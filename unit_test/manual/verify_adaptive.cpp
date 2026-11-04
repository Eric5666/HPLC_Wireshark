// verify_adaptive.cpp — GW_2026 版本自适应委托端到端验证(不启动 GUI)
// 同一 HDC 1.0 抓包 bin 分别喂 GW_2022 直连解析器与 GW_2026 解析器(内部按
// FCH 版本号=0 委托 GW_2022),逐帧比对协议身份/帧型/TEI/NID/PB/MSDU 一致性。
#include <QCoreApplication>
#include <QFile>
#include <QByteArray>
#include <QDebug>

#include "bplcframe.h"
#include "gw_2022_parser.h"
#include "gw_2026_parser.h"

#include <cstdio>

static bool extract_frame(QByteArray& buf, BplcFrame& out) {
    while (!buf.isEmpty()) {
        int idx = buf.indexOf(char(0x3C));
        if (idx < 0) { buf.clear(); return false; }
        buf.remove(0, idx + 1);
        idx = buf.indexOf(char(0x3E));
        if (idx < 0) return false;
        QByteArray esc = buf.left(idx);
        buf.remove(0, idx + 1);
        QByteArray unesc;
        for (int i = 0; i < esc.size(); ++i) {
            quint8 b = static_cast<quint8>(esc[i]);
            if (b == 0x3D && i + 1 < esc.size()) {
                ++i;
                unesc.append(static_cast<char>(0xFF ^ static_cast<quint8>(esc[i])));
            } else {
                unesc.append(static_cast<char>(b));
            }
        }
        out.data = unesc;
        out.meta.has_time_tag = false;
        return true;
    }
    return false;
}

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    const QString path = (argc > 1) ? QString::fromLocal8Bit(argv[1])
        : QStringLiteral("D:\\code\\gitlab\\HPLC_HRF_GW\\monitor\\BPLC_STA_QtMonitor\\samples\\replay_test.bin");
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) { qCritical() << "open failed:" << path; return 1; }
    QByteArray raw = f.readAll();
    f.close();
    std::printf("Loaded %lld bytes\n", (long long)raw.size());

    GW_2022_Parser p22;
    GW_2026_Parser p26;
    GW_2022_Parser::Filter f0;   // Result/Filter 为协议无关别名
    f0.allow_beacon = f0.allow_sof = f0.allow_ack = f0.allow_coord = true;
    f0.link_hplc = f0.link_hrf = true;

    int frames = 0, mismatch = 0;
    int v26_native = 0, v26_delegated = 0, v26_dropped = 0;
    qint64 msdu_mismatch = 0;

    QByteArray b1 = raw, b2 = raw;
    BplcFrame fr1, fr2;
    while (extract_frame(b1, fr1)) {
        bool ok2 = extract_frame(b2, fr2);
        if (!ok2) break;
        ++frames;
        MsduState m1, m2;   // 独立重组状态(逐帧比对,不含跨帧重组顺序差)
        auto r1 = p22.parse(fr1, m1, f0);
        auto r2 = p26.parse(fr2, m2, f0);
        if (r2.protocol == ProtocolVariant::GW_2026) ++v26_native;
        else ++v26_delegated;   // 委托 GW_2022 后 protocol 被标记为 GW_2022
        if (!r1.accept && !r2.accept) continue;
        if (r1.accept != r2.accept) { ++mismatch;
            std::printf("#%d accept differ: 22=%d 26=%d (%s / %s)\n", frames,
                        r1.accept, r2.accept, qPrintable(r1.reject_reason),
                        qPrintable(r2.reject_reason)); continue; }
        if (!r1.accept) { ++v26_dropped; continue; }
        const bool same =
            r1.protocol == r2.protocol &&
            r1.mpdu.frame_type == r2.mpdu.frame_type &&
            r1.mpdu.net_id == r2.mpdu.net_id &&
            r1.mpdu.version == r2.mpdu.version &&
            r1.mpdu.src_tei == r2.mpdu.src_tei &&
            r1.mpdu.dst_tei == r2.mpdu.dst_tei &&
            r1.mpdu.pb_num == r2.mpdu.pb_num &&
            r1.mpdu.pb_size == r2.mpdu.pb_size &&
            r1.mpdu.fch_crc_ok == r2.mpdu.fch_crc_ok &&
            r1.msdu.present == r2.msdu.present &&
            r1.msdu_body == r2.msdu_body;
        if (!same) {
            ++mismatch;
            std::printf("#%d MISMATCH proto=%d/%d ft=%d/%d nid=%x/%x tei=%d/%d-%d/%d pb=%d/%d-%d/%d msdu=%d/%d\n",
                        frames, int(r1.protocol), int(r2.protocol),
                        r1.mpdu.frame_type, r2.mpdu.frame_type,
                        r1.mpdu.net_id, r2.mpdu.net_id,
                        r1.mpdu.src_tei, r2.mpdu.src_tei,
                        r1.mpdu.dst_tei, r2.mpdu.dst_tei,
                        r1.mpdu.pb_num, r2.mpdu.pb_num,
                        r1.mpdu.pb_size, r2.mpdu.pb_size,
                        r1.msdu.present, r2.msdu.present);
        }
    }
    std::printf("\n===== 自适应验证结果 =====\n");
    std::printf("总帧数        : %d\n", frames);
    std::printf("GW_2026 原生  : %d (HDC 2.0 版本号帧/保留值帧)\n", v26_native);
    std::printf("委托 GW_2022  : %d (版本=0,HDC 1.0 帧)\n", v26_delegated);
    std::printf("双方均拒收    : %d\n", v26_dropped);
    std::printf("逐帧不一致    : %d\n", mismatch);
    std::printf(mismatch == 0 ? "PASS: HDC 1.0 帧经 GW_2026 解析与直连 GW_2022 完全一致\n"
                              : "FAIL: 存在解析差异\n");
    return mismatch == 0 ? 0 : 2;
}
