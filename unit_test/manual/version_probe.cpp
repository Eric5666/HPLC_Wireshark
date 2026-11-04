/// @file version_probe.cpp
/// @brief GW_2026 版本自适应委托探针:验证 FCH 版本号驱动的新旧协议分派
/// @details 用真实 HDC 1.0 回放帧(replay_test.bin,GW_2022 可成功解析):
///          ① 原帧 → GW_2026_Parser 应委托 GW_2022(r.protocol=GW_2022 且接受)
///          ② 版本位翻转为 1 → FCH CRC24 失败拒收(版本位受 CRC 保护,
///             篡改版本必然被拦,自适应不会被脏帧误触发——预期行为)
#include "bplcframe.h"
#include "gw_protocol/gw_2026/gw_2026_parser.h"
#include <QCoreApplication>
#include <QFile>
#include <QDebug>
#include <cstdio>

static int ver_of(const QByteArray& mpdu) {
    if (mpdu.size() < 13) return -1;
    return int((quint8(mpdu[12]) >> 4) & 0x0F);
}

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    const QString bin = (argc > 1)
        ? QString::fromLocal8Bit(argv[1])
        : QStringLiteral("replay_test.bin");
    QFile f(bin);
    if (!f.open(QIODevice::ReadOnly)) { qWarning() << "cannot open" << bin; return 2; }
    const QByteArray raw = f.readAll();
    f.close();

    // 哨兵切帧 + 0x3D 反转义(与 headless_test 一致)
    QList<QByteArray> frames;
    int i = 0;
    const int n = raw.size();
    while (i < n) {
        if (quint8(raw[i]) != 0x3C) { ++i; continue; }
        int j = i + 1;
        QByteArray body;
        bool esc = false, done = false;
        while (j < n) {
            quint8 b = quint8(raw[j]);
            if (esc) { body.append(char(b)); esc = false; ++j; continue; }
            if (b == 0x3D) { esc = true; ++j; continue; }
            if (b == 0x3E) { done = true; ++j; break; }
            body.append(char(b));
            ++j;
        }
        if (done && body.size() >= 16) frames.append(body);
        i = j;
    }
    printf("frames: %d\n", frames.size());
    if (frames.isEmpty()) return 3;

    GW_2026_Parser parser;
    int n_gw2022 = 0, n_gw2026 = 0, n_reject = 0;
    QString first_legacy;
    for (int k = 0; k < frames.size(); ++k) {
        BplcFrame in;
        in.data = frames[k];
        in.meta.has_time_tag = false;
        in.meta.frame_time = QDateTime::currentDateTime();
        in.arrival_us = k;
        MsduState msdu;
        GW_2026_Parser::Filter f0;   // 全放行
        auto r = parser.parse(in, msdu, f0);
        if (!r.accept) { ++n_reject; continue; }
        if (r.protocol == ProtocolVariant::GW_2022) {
            ++n_gw2022;
            if (n_gw2022 == 1)
                first_legacy = QStringLiteral("type=%1 nid=0x%2 ver=%3 fch_ok=%4")
                    .arg(r.mpdu.frame_type)
                    .arg(r.mpdu.net_id, 6, 16, QChar('0'))
                    .arg(r.mpdu.version).arg(r.mpdu.fch_crc_ok);
        } else if (r.protocol == ProtocolVariant::GW_2026) {
            ++n_gw2026;
        }
    }
    printf("RESULT: delegated_gw2022=%d kept_gw2026=%d rejected=%d\n",
           n_gw2022, n_gw2026, n_reject);
    printf("first legacy: %s\n", first_legacy.toLocal8Bit().constData());

    // 版本位翻转实验(帧头 2B len + 4B ts + 4B media,MPDU 自偏移 10)
    {
        QByteArray d = frames[0];
        const int mpdu_off = 10;
        if (d.size() > mpdu_off + 13) {
            const int v0 = ver_of(d.mid(mpdu_off));
            d[mpdu_off + 12] = char(quint8(d[mpdu_off + 12]) | 0x10);  // ver |= 1
            BplcFrame in;
            in.data = d;
            in.meta.has_time_tag = false;
            in.meta.frame_time = QDateTime::currentDateTime();
            MsduState msdu;
            GW_2026_Parser::Filter f0;
            auto r = parser.parse(in, msdu, f0);
            printf("ver-flip: ver %d->%d protocol=%s accept=%d reason=%s\n",
                   v0, ver_of(d.mid(mpdu_off)),
                   r.protocol == ProtocolVariant::GW_2026 ? "GW_2026" :
                   (r.protocol == ProtocolVariant::GW_2022 ? "GW_2022" : "?"),
                   int(r.accept), r.reject_reason.toLocal8Bit().constData());
        }
    }
    printf("DONE\n");
    return 0;
}
