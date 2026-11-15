// GW OFDMA/TDA 多站逐站 CRC 进 mpdu.pb_crc_oks 回归用例。
// 对应用户 2026-10-30 定:逐站 CRC 进 mpdu.pb_crc_oks,且该字段只针对 PB 块 CRC。
// 直接调用 gw_2026_sof::assemble():载波 SOF(表7 帧子类型 2=OFDMA / 3=TDA),
// 2 站,每站 1 块 136B(分集拷贝模式 2,HDC2.0 4-1 物理层 表18),GW 布局头 1B + 体 + CRC24 3B。
// 站点 0 TEI = FCH 目的 TEI(表10 (5,4,12));站点 1 TEI 在 eFC(表11/13)。
// 断言:OFDMA 全好 [true,true];翻转站 0/站 1/双站对应位 false;
//      TDA 全好 [true,true]、翻转站 1 [true,false];多站汇总 pb_num 为 0。
#include <QCoreApplication>
#include <cstdio>
#include "gw_2026_sof_parser.h"
#include "fieldtools.h"
#include "crc.h"

static void put_crc24(quint8* blk, int len) {
    const quint32 calc = crc24_lsb(blk, len);
    blk[len - 3] = calc & 0xFF;
    blk[len - 2] = (calc >> 8) & 0xFF;
    blk[len - 1] = (calc >> 16) & 0xFF;
}

// GW 单块 136B:头 1B(START+END) + 体 132B + CRC24 3B。
static QByteArray build_gw_block(bool flip_crc) {
    QByteArray blk(136, 0);
    quint8* p = reinterpret_cast<quint8*>(blk.data());
    p[0] = 0xC0;                     // START + END 单块
    put_crc24(p, 136);
    if (flip_crc) p[135] ^= 0xFF;    // 末 CRC 字节翻转
    return blk;
}

// GW 多站帧 304B:FCH 16B + eFC 16B + 站点 0 块 136B + 站点 1 块 136B。
static QByteArray build_gw_multi(bool is_tda, bool flip0, bool flip1) {
    QByteArray f(304, 0);
    quint8* p = reinterpret_cast<quint8*>(f.data());
    p[0] = 0x01;                     // SOF
    set_bits(p, 4, 0, 12, 1);        // 源 TEI = 1 (CCO)
    set_bits(p, 5, 4, 12, 27);       // 目的 TEI = 站点 0 TEI
    set_bits(p, 8, 0, 12, 100);      // 帧长(显示用)
    p[7] = is_tda ? 0x0B : 0x0A;     // 帧子类型 3/2 + 站点数码 1(2 站,表10/表12 (7,3,2))
    set_bits(p, 11, 3, 5, 2);        // 站点 0 分集拷贝模式 2 -> 136B(表10 (11,3,5))
    // 站点 0 PB 数码 (11,2,1)=0 -> 1 块(留 0);TDA 恒 1 块
    quint8* e = p + 16;              // eFC
    set_bits(e, 0, 0, 12, 42);       // 站点 1 TEI(表11/13 (b,0,12),b=16)
    if (is_tda)
        set_bits(e, 3, 0, 5, 2);     // TDA 分集拷贝模式(表13 (b+3,0,5))
    else
        set_bits(e, 2, 0, 5, 2);     // OFDMA 分集拷贝模式(表11 (b+2,0,5))
    // OFDMA 站点 1 PB 数码 (18,5,1)=0 -> 1 块(留 0)
    put_crc24(e, 16);                // eFC FCS -> bytes 29..31(上游 877f838 起 eFC CRC24 错整帧拒收)
    f.replace(32, 136, build_gw_block(flip0));
    f.replace(168, 136, build_gw_block(flip1));
    return f;
}

static bool oks_eq(const QVector<bool>& v, std::initializer_list<bool> want) {
    if (v.size() != (int)want.size()) return false;
    int i = 0;
    for (bool b : want) if (v[i++] != b) return false;
    return true;
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    int fails = 0;
    auto check = [&](const char* name, bool ok) {
        std::printf("%s: %s\n", name, ok ? "PASS" : "FAIL");
        if (!ok) ++fails;
    };
    auto run = [&](const char* name, bool is_tda, bool flip0, bool flip1,
                   std::initializer_list<bool> want) {
        MpduInfo info;
        MsduState msdu;
        QByteArray complete;
        const QString err = gw_2026_sof::assemble(build_gw_multi(is_tda, flip0, flip1),
                                                  info, msdu, complete, 0xFF, false);
        check(name, err.isEmpty());
        if (!err.isEmpty()) {
            std::printf("  assemble err: %s\n", qPrintable(err));
            return;
        }
        check("stations", info.sof_stations.size() == 2);
        if (info.sof_stations.size() == 2) {
            check("sta0 tei", info.sof_stations[0].tei == 27);
            check("sta1 tei", info.sof_stations[1].tei == 42);
            check("sta0 size", info.sof_stations[0].pb_size == 136);
            check("sta1 size", info.sof_stations[1].pb_size == 136);
        }
        check("frame oks", oks_eq(info.pb_crc_oks, want));
        check("pb_num 0", info.pb_num == 0);
    };

    run("ofdma-ok", false, false, false, {true, true});
    run("ofdma-flip0", false, true, false, {false, true});
    run("ofdma-flip1", false, false, true, {true, false});
    run("ofdma-flipboth", false, true, true, {false, false});
    run("tda-ok", true, false, false, {true, true});
    run("tda-flip1", true, false, true, {true, false});

    // eFC FCS 坏 ⇒ 整帧拒收(与 FC CRC 坏同口径),不出站点
    for (bool is_tda : {false, true}) {
        QByteArray f = build_gw_multi(is_tda, false, false);
        f[29] = char(quint8(f[29]) ^ 0x01);
        MpduInfo info; MsduState msdu; QByteArray complete;
        const QString err = gw_2026_sof::assemble(f, info, msdu, complete, 0xFF, false);
        check(is_tda ? "tda-bad-efc rejected" : "ofdma-bad-efc rejected",
              err.contains(QStringLiteral("CRC24")) && info.sof_stations.isEmpty());
    }

    std::printf("RESULT: %s\n", fails == 0 ? "ALL PASS" : "FAILURES");
    return fails == 0 ? 0 : 1;
}
