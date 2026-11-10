// NW UL-OFDMA 类型1 逐站 CRC 进 mpdu.pb_crc_oks 回归用例。
// 对应用户 2026-10-30 定:逐站 CRC 进 mpdu.pb_crc_oks,且该字段只针对 PB 块 CRC。
// 构帧:载波 SOF version=2、多站。
//   trigger(类型2)32B:FCH + eFC(SPLC 第4部分 表28),2 站(TEI 27/42,各 1 块 264B,TMI 9);
//   UL 数据(类型1)544B:FCH + 站点 0 块 264B + 站点 1 块 264B(无 eFC,载荷自 byte16 起);
//   DL-SACK(类型1)32B:FCH + 单 16B PB(CRC 通过,体首 nibble MsgID=0)。
// 断言:
//   无 trigger 时 UL 帧:无站点、pb_crc_oks 为空(不凭空造项);
//   trigger 后 UL 全好:pb_crc_oks == [true,true](站序即块序);
//   UL 站点 0/1/双站翻转:对应位 false,其余 true;
//   UL 站点 1 聚合块翻转:同样 [true,false](聚合路径亦进帧级表);
//   DL-SACK:单站 TEI 33、pb_crc_oks == [true]。
// 类型3(UL-SACK)不在此:其无站点条目,无 PB 块 CRC 可进表(另案)。
#include <QCoreApplication>
#include <cstdio>
#include "nw_2026_parser.h"
#include "fieldtools.h"
#include "crc.h"

static quint64 mac6(quint8 a, quint8 b, quint8 c, quint8 d, quint8 e, quint8 f) {
    return (quint64)a | ((quint64)b << 8) | ((quint64)c << 16)
         | ((quint64)d << 24) | ((quint64)e << 32) | ((quint64)f << 40);
}
static void put_mac(quint8* p, quint64 mac) {
    for (int i = 0; i < 6; ++i) p[i] = (quint8)((mac >> (8 * i)) & 0xFF);
}
static void put_crc24(quint8* blk, int len) {
    const quint32 calc = crc24_lsb(blk, len);
    blk[len - 3] = calc & 0xFF;
    blk[len - 2] = (calc >> 8) & 0xFF;
    blk[len - 1] = (calc >> 16) & 0xFF;
}

// 与 nw-dlofdma-crc-probe 的 build_nw_assoc 同构:NW AssocReq MAC 帧 134B。
static QByteArray build_nw_assoc(int dst_tei, quint64 dst_mac, int src_tei,
                                 quint64 src_mac, int restart) {
    QByteArray mme(80, 0);
    quint8* m = reinterpret_cast<quint8*>(mme.data());
    m[0] = 0x01;
    m[1] = 0x30; m[2] = 0x00;        // MMType 0x0030 ASSOCREQ (LE)
    put_mac(m + 6, src_mac);         // STAMAC at mme offset 6
    const int msdu_len = 18 + (int)mme.size();
    QByteArray f(32 + msdu_len + 4, 0);
    quint8* p = reinterpret_cast<quint8*>(f.data());
    p[0] = 0x02;                     // version 1, long head
    p[2] = quint8(msdu_len & 0xFF); p[3] = quint8((msdu_len >> 8) & 0xFF);
    p[4] = quint8(dst_tei & 0xFF);
    p[5] = quint8(((dst_tei >> 8) & 0x0F) | ((src_tei & 0x0F) << 4));
    p[6] = quint8((src_tei >> 4) & 0xFF);
    p[7] = quint8((restart & 0x0F) << 4);
    p[10] = 0xEE; p[11] = 0x64;
    put_mac(p + 12, dst_mac);
    put_mac(p + 32, dst_mac);
    put_mac(p + 38, src_mac);
    p[44] = 0x00; p[45] = 0x81; p[46] = 0x00; p[47] = 0x00;  // VLAN 0x8100
    p[48] = 0xE1; p[49] = 0x88;                              // type 0x88E1
    memcpy(p + 50, mme.constData(), mme.size());
    // MSDU 帧尾 4B CRC32:与 append_msdu_crc 同语义(crc32_le 遍历 len-4 字节,
    // 存储在 payload_start(32, 长头)+payload_len 起的 4B,小端)。合成帧必须是"好载荷",
    // 否则新口径(MSDU CRC 正确才采信)会正确判坏载荷并清空 learning。
    const quint32 crc = crc32_le(p + 32, msdu_len + 4);
    p[32 + msdu_len + 0] = quint8(crc & 0xFF);
    p[32 + msdu_len + 1] = quint8((crc >> 8) & 0xFF);
    p[32 + msdu_len + 2] = quint8((crc >> 16) & 0xFF);
    p[32 + msdu_len + 3] = quint8((crc >> 24) & 0xFF);
    return f;
}

// 单站 PB:264B = 头 4B(agg=0 非聚合)+ 体 256B + 保留 1B + CRC24 3B。
static QByteArray build_station_block(const QByteArray& msdu, int seq, bool flip_crc) {
    QByteArray blk(264, 0);
    quint8* p = reinterpret_cast<quint8*>(blk.data());
    p[0] = quint8(seq & 0xFF); p[1] = quint8((seq >> 8) & 0xFF);
    p[2] = 0x00;                     // agg bit0 = 0:非聚合分支
    memcpy(p + 4, msdu.constData(), msdu.size());
    put_crc24(p, 264);
    if (flip_crc) p[263] ^= 0xFF;    // 末 CRC 字节翻转
    return blk;
}

// 聚合站块:264B = 头 4B(agg=1 聚合)+ 体 256B(级联记录流)+ 保留 1B + CRC24 3B。
static QByteArray build_agg_station_block(const QByteArray& msdu, int seq, bool flip_crc) {
    QByteArray blk(264, 0);
    quint8* p = reinterpret_cast<quint8*>(blk.data());
    p[0] = quint8(seq & 0xFF); p[1] = quint8((seq >> 8) & 0xFF);
    p[2] = 0x01;                     // agg bit0 = 1:聚合分支
    const int clen = msdu.size();    // 134
    p[4] = quint8(clen & 0xFF);
    p[5] = quint8(((clen >> 8) & 0x0F) | 0x10 | 0x20);   // 高 4b + Start + End
    memcpy(p + 6, msdu.constData(), msdu.size());
    put_crc24(p, 264);
    if (flip_crc) p[263] ^= 0xFF;
    return blk;
}

static void build_fch(quint8* p, quint8 byte4) {
    p[0] = 0x01;                     // SOF, SNID 0
    set_bits(p, 1, 0, 12, 1);        // FCH 源 TEI = 1 (CCO)
    set_bits(p, 2, 4, 12, 0xFFF);    // FCH 目的 TEI = 广播
    p[4] = byte4;
    set_bits(p, 8, 0, 12, 100);      // 帧长(显示用)
    p[12] = 0x20;                    // version 2
    put_crc24(p, 16);                // FCH CRC24
}

// trigger(类型2)32B:FCH + eFC(SPLC 第4部分 表28)。
// eFC 站条目 25b 步进,与 DL-OFDMA eFC 同布局:PBNum 1b + TEI 12b + TMI 5b + RU 4b + Tx回退 3b。
static QByteArray build_trigger() {
    QByteArray f(32, 0);
    quint8* p = reinterpret_cast<quint8*>(f.data());
    build_fch(p, 0x45);              // multi=1, 类型 2, 站点数码 1 -> 2 站
    quint8* e = p + 16;
    set_bits(e, 0, 2, 1, 0);         // 站点 0: PBNum 码 0 -> 1 块
    set_bits(e, 0, 3, 12, 27);       // 站点 0 TEI
    set_bits(e, 1, 7, 5, 9);         // 站点 0 TMI 9 -> 264B
    set_bits(e, 3, 3, 1, 0);         // 站点 1: PBNum 码 0 -> 1 块(bit27)
    set_bits(e, 3, 4, 12, 42);       // 站点 1 TEI (bits 28..39)
    set_bits(e, 5, 0, 5, 9);         // 站点 1 TMI 9 -> 264B (bits 40..44)
    put_crc24(e, 16);                // eFC CRC24
    return f;
}

// UL 数据(类型1)544B:FCH + 站点 0 块 + 站点 1 块(无 eFC,载荷自 byte16 起)。
static QByteArray build_uldata(bool flip0, bool flip1, bool agg1,
                               quint64 cco, quint64 sta27, quint64 sta42) {
    QByteArray f(544, 0);
    quint8* p = reinterpret_cast<quint8*>(f.data());
    build_fch(p, 0x43);              // multi=1, 类型 1, 站点数码 1 -> 2 站
    f.replace(16, 264, build_station_block(build_nw_assoc(1, cco, 27, sta27, 5), 0, flip0));
    if (agg1)
        f.replace(280, 264, build_agg_station_block(build_nw_assoc(1, cco, 42, sta42, 5), 0, flip1));
    else
        f.replace(280, 264, build_station_block(build_nw_assoc(1, cco, 42, sta42, 5), 0, flip1));
    return f;
}

// DL-SACK(类型1)32B:FCH + 单 16B PB(CRC 通过,体首 nibble MsgID=0,源 TEI 33)。
static QByteArray build_dlsack() {
    QByteArray f(32, 0);
    quint8* p = reinterpret_cast<quint8*>(f.data());
    build_fch(p, 0x03);              // multi=1, 类型 1, 站点数码 0
    quint8* blk = p + 16;
    blk[0] = 0x00;                   // PB 头首字节
    blk[4] = 0x10;                   // 体首:高 nibble 1(源 TEI 低 4b),低 nibble 0(MsgID=0)
    blk[5] = 0x02;                   // 源 TEI 高 8b -> TEI = 0x21 = 33
    put_crc24(blk, 16);              // PB CRC24 at blk[13..15]
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
    const quint64 cco   = mac6(0x02, 0, 0, 0, 0, 0x01);
    const quint64 sta27 = mac6(0x02, 0, 0, 0, 0, 0x27);
    const quint64 sta42 = mac6(0x02, 0, 0, 0, 0, 0x42);
    int fails = 0;
    auto check = [&](const char* name, bool ok) {
        std::printf("%s: %s\n", name, ok ? "PASS" : "FAIL");
        if (!ok) ++fails;
    };

    NW_2026_Parser parser;
    ParseFilter filt;                // 默认全放行
    auto parse = [&](const QByteArray& frame) {
        BplcFrame fr;
        fr.meta.from_raw = true;
        fr.data = QByteArray(1, char(0)) + frame;
        MsduState msdu;
        return parser.parse(fr, msdu, filt);
    };

    {   // 无 trigger:UL 帧无站点、帧级表为空
        const ParseResult r = parse(build_uldata(false, false, false, cco, sta27, sta42));
        check("no-trigger stations empty", r.mpdu.sof_stations.isEmpty());
        check("no-trigger pb_crc_oks empty", r.mpdu.pb_crc_oks.isEmpty());
    }
    {   // trigger 本帧 accept,上下文建立
        const ParseResult r = parse(build_trigger());
        check("trigger accept", r.accept);
    }
    {   // UL 全好
        const ParseResult r = parse(build_uldata(false, false, false, cco, sta27, sta42));
        check("ul-ok stations", r.mpdu.sof_stations.size() == 2);
        check("ul-ok sta0", oks_eq(r.mpdu.sof_stations[0].pb_crc_oks, {true}));
        check("ul-ok sta1", oks_eq(r.mpdu.sof_stations[1].pb_crc_oks, {true}));
        check("ul-ok frame oks", oks_eq(r.mpdu.pb_crc_oks, {true, true}));
        check("ul-ok pb_num 0", r.mpdu.pb_num == 0);
    }
    {   // UL 站点 0 翻转
        const ParseResult r = parse(build_uldata(true, false, false, cco, sta27, sta42));
        check("ul-flip0 frame oks", oks_eq(r.mpdu.pb_crc_oks, {false, true}));
    }
    {   // UL 站点 1 翻转
        const ParseResult r = parse(build_uldata(false, true, false, cco, sta27, sta42));
        check("ul-flip1 frame oks", oks_eq(r.mpdu.pb_crc_oks, {true, false}));
    }
    {   // UL 双站翻转
        const ParseResult r = parse(build_uldata(true, true, false, cco, sta27, sta42));
        check("ul-flipboth frame oks", oks_eq(r.mpdu.pb_crc_oks, {false, false}));
    }
    {   // UL 站点 1 聚合块翻转
        const ParseResult r = parse(build_uldata(false, true, true, cco, sta27, sta42));
        check("ul-agg-flip1 frame oks", oks_eq(r.mpdu.pb_crc_oks, {true, false}));
    }
    {   // DL-SACK
        const ParseResult r = parse(build_dlsack());
        check("dlsack stations", r.mpdu.sof_stations.size() == 1);
        check("dlsack tei", !r.mpdu.sof_stations.isEmpty() && r.mpdu.sof_stations[0].tei == 33);
        check("dlsack frame oks", oks_eq(r.mpdu.pb_crc_oks, {true}));
    }

    std::printf("RESULT: %s\n", fails == 0 ? "ALL PASS" : "FAILURES");
    return fails == 0 ? 0 : 1;
}
