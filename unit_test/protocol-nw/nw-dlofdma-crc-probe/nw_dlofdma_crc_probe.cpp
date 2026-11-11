// NW DL-OFDMA 站点1+ 非聚合分支 PB CRC 门回归用例。
// 对应修复:fix/nw-dlofdma-pbcrc(9832d1b),合入 fix/remove-parse-filter(11afa31)。
// 原探针 ~/workspace/nw-crc-probe/nw_crc_probe.cpp 逻辑原样迁移,仅改名。
// 构帧:载波 SOF version=2,DL-OFDMA(类型0)2 站点,每站 1 块 264B(TMI 9),
// 站点 PB 体 = NW AssocReq MSDU(32B MAC 头 + 98B MSDU + 4B,同 sender-mac 探针)。
// 断言(期望行为):
//   好 CRC:站点 0 对(27)与站点 1 对(42)都学到;
//   站点 1 块 CRC 翻转但 MSDU CRC32 有效:仍允许站点 1 对学习(CRC32 优先)。
//   MSDU CRC32 失败即使 PB CRC 通过:站点 1 对不得学习。
#include <QCoreApplication>
#include <QDebug>
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

// 与 sender-mac 探针 build_nw_assoc 同构:NW AssocReq MAC 帧 134B。
static QByteArray build_nw_assoc(int dst_tei, quint64 dst_mac, int src_tei,
                                 quint64 src_mac, int restart, bool bad_msdu_crc = false) {
    QByteArray mme(80, 0);
    quint8* m = reinterpret_cast<quint8*>(mme.data());
    m[0] = 0x01;                     // MMe version
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
    put_mac(p + 12, dst_mac);        // SPLC-4 表7 目的 MAC bytes 12-17
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
    if (bad_msdu_crc) p[32 + msdu_len + 3] ^= 0xFF;
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
// 级联记录 = 级联头 2B(级联数据块长度 12b LSB-first + Start/End 标识)+ 独立 MAC 帧。
// 此处单条记录:MAC 帧 = NW AssocReq 134B,clen=134,头 [0x86,0x30](Start=1,End=1),
// 体剩余 120B 为 0 填充(clen=0 触发级联 while 停止)。
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

// DL-OFDMA 2 站点帧:32B(FCH+eFC) + 站点 0 块 + 站点 1 块 = 560B。
static QByteArray build_dlofdma(bool flip_sta1, quint64 cco, quint64 sta27, quint64 sta42,
                                bool bad_msdu_crc_sta1 = false) {
    QByteArray f(560, 0);
    quint8* p = reinterpret_cast<quint8*>(f.data());
    p[0] = 0x01;                     // SOF, SNID 0
    set_bits(p, 1, 0, 12, 1);        // FCH 源 TEI = 1 (CCO)
    set_bits(p, 2, 4, 12, 0xFFF);    // FCH 目的 TEI = 广播
    p[4] = 0x41;                     // multi=1, OFDMA 类型 0, 站点数码 1 -> 2 站
    set_bits(p, 8, 0, 12, 100);      // 帧长(显示用)
    p[12] = 0x20;                    // version 2
    put_crc24(p, 16);                // FCH CRC24
    quint8* e = p + 16;              // eFC, SPLC 第4部分 表27
    set_bits(e, 0, 2, 1, 0);         // 站点 0: PBNum 码 0 -> 1 块
    set_bits(e, 0, 3, 12, 27);       // 站点 0 TEI
    set_bits(e, 1, 7, 5, 9);         // 站点 0 TMI 9 -> 264B
    set_bits(e, 3, 3, 1, 0);         // 站点 1: PBNum 码 0 -> 1 块(bit27)
    set_bits(e, 3, 4, 12, 42);       // 站点 1 TEI (bits 28..39)
    set_bits(e, 5, 0, 5, 9);         // 站点 1 TMI 9 -> 264B (bits 40..44)
    put_crc24(e, 16);                // eFC CRC24
    f.replace(32, 264, build_station_block(build_nw_assoc(1, cco, 27, sta27, 5), 0, false));
    f.replace(296, 264, build_station_block(build_nw_assoc(1, cco, 42, sta42, 5, bad_msdu_crc_sta1), 0, flip_sta1));
    return f;
}

// DL-OFDMA 2 站点聚合帧:站点 0 非聚合 + 站点 1 聚合(级联记录流)。
// 布局与 build_dlofdma 相同,仅站点 1 块换成聚合块。
static QByteArray build_dlofdma_agg(bool flip_sta1, quint64 cco, quint64 sta27, quint64 sta42,
                                    bool bad_msdu_crc_sta1 = false) {
    QByteArray f(560, 0);
    quint8* p = reinterpret_cast<quint8*>(f.data());
    p[0] = 0x01;                     // SOF, SNID 0
    set_bits(p, 1, 0, 12, 1);        // FCH 源 TEI = 1 (CCO)
    set_bits(p, 2, 4, 12, 0xFFF);    // FCH 目的 TEI = 广播
    p[4] = 0x41;                     // multi=1, OFDMA 类型 0, 站点数码 1 -> 2 站
    set_bits(p, 8, 0, 12, 100);      // 帧长(显示用)
    p[12] = 0x20;                    // version 2
    put_crc24(p, 16);                // FCH CRC24
    quint8* e = p + 16;              // eFC, SPLC 第4部分 表27
    set_bits(e, 0, 2, 1, 0);         // 站点 0: PBNum 码 0 -> 1 块
    set_bits(e, 0, 3, 12, 27);       // 站点 0 TEI
    set_bits(e, 1, 7, 5, 9);         // 站点 0 TMI 9 -> 264B
    set_bits(e, 3, 3, 1, 0);         // 站点 1: PBNum 码 0 -> 1 块(bit27)
    set_bits(e, 3, 4, 12, 42);       // 站点 1 TEI (bits 28..39)
    set_bits(e, 5, 0, 5, 9);         // 站点 1 TMI 9 -> 264B (bits 40..44)
    put_crc24(e, 16);                // eFC CRC24
    f.replace(32, 264, build_station_block(build_nw_assoc(1, cco, 27, sta27, 5), 0, false));
    f.replace(296, 264, build_agg_station_block(build_nw_assoc(1, cco, 42, sta42, 5, bad_msdu_crc_sta1), 0, flip_sta1));
    return f;
}

static bool has_pair(const ParseResult& r, quint16 tei, quint64 mac) {
    for (const TeiMacPair& p : r.msdu.tei_mac_pairs)
        if (p.tei == tei && p.mac == mac) return true;
    return false;
}
static void dump_pairs(const char* tag, const ParseResult& r) {
    std::printf("%s pairs:", tag);
    for (const TeiMacPair& p : r.msdu.tei_mac_pairs)
        std::printf(" [TEI %u mac %02x:%02x:%02x:%02x:%02x:%02x]",
                    p.tei, (unsigned)(p.mac & 0xFF), (unsigned)((p.mac >> 8) & 0xFF),
                    (unsigned)((p.mac >> 16) & 0xFF), (unsigned)((p.mac >> 24) & 0xFF),
                    (unsigned)((p.mac >> 32) & 0xFF), (unsigned)((p.mac >> 40) & 0xFF));
    std::printf("\n");
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
    for (int tc = 0; tc < 2; ++tc) {
        const bool flip = (tc == 1);
        BplcFrame fr;
        fr.meta.from_raw = true;
        fr.data = QByteArray(1, char(0)) + build_dlofdma(flip, cco, sta27, sta42);
        MsduState msdu;
        const ParseResult r = parser.parse(fr, msdu, filt);
        const char* tag = flip ? "flipped" : "control";
        dump_pairs(tag, r);
        std::printf("%s frame msdu src: TEI %d mac %llx dst: TEI %d mac %llx\n",
                    tag, r.msdu.msdu_src_tei, (unsigned long long)r.msdu.msdu_src_mac,
                    r.msdu.msdu_dst_tei, (unsigned long long)r.msdu.msdu_dst_mac);
        check(flip ? "flipped: accept" : "control: accept", r.accept);
        // 站点 0 的对走帧级字段 (通用路径直接赋值 r.msdu,不进 tei_mac_pairs)。
        check(flip ? "flipped: sta0 pair kept" : "control: sta0 pair",
              r.msdu.msdu_src_tei == 27 && r.msdu.msdu_src_mac == sta27);
        check(flip ? "flipped: valid MSDU CRC overrides PB CRC FAIL; sta1 learned" : "control: sta1 pair",
              has_pair(r, 42, sta42));
        if (flip) {
            check("flipped: STA1 AssocReq topo event retained",
                  r.msdu.topo_extra_events.size() == 1
                  && r.msdu.topo_extra_events[0].kind == TopoEventKind::AssocReq
                  && r.msdu.topo_extra_events[0].nodes.size() == 1
                  && r.msdu.topo_extra_events[0].nodes[0].tei == 0
                  && r.msdu.topo_extra_events[0].nodes[0].mac == sta42);
        }
        // 新增: CRC 状态检查
        bool has_crc_fail = std::any_of(r.mpdu.pb_crc_oks.begin(), r.mpdu.pb_crc_oks.end(),
                                        [](bool ok) { return !ok; });
        check(flip ? "flipped: pb_crc_oks has failure" : "control: pb_crc_oks all pass",
              flip ? has_crc_fail : !has_crc_fail);
    }
    // 聚合分支:站点 1 为聚合 PB(级联记录流),即使站点 1 块 CRC24 翻转,
    // 只要 MSDU CRC32 有效,仍应学习站点 1 对及其拓扑事件(CRC32 优先);
    // 站点 0(好块,帧级通用路径)不受影响;帧本身仍 accept(CRC 错靠 pb_crc_oks 标红)。
    {
        BplcFrame fr;
        fr.meta.from_raw = true;
        fr.data = QByteArray(1, char(0)) + build_dlofdma_agg(true, cco, sta27, sta42);
        MsduState msdu;
        const ParseResult r = parser.parse(fr, msdu, filt);
        dump_pairs("agg-flipped", r);
        check("agg-flipped: accept", r.accept);
        check("agg-flipped: sta0 pair kept",
              r.msdu.msdu_src_tei == 27 && r.msdu.msdu_src_mac == sta27);
        check("agg-flipped: valid MSDU CRC overrides PB CRC FAIL; sta1 learned",
              has_pair(r, 42, sta42));
        // 新增:CRC 状态检查
        bool has_crc_fail = std::any_of(r.mpdu.pb_crc_oks.begin(), r.mpdu.pb_crc_oks.end(),
                                        [](bool ok) { return !ok; });
        check("agg-flipped: pb_crc_oks has failure", has_crc_fail);
    }
    {
        BplcFrame fr;
        fr.meta.from_raw = true;
        fr.data = QByteArray(1, char(0)) + build_dlofdma_agg(false, cco, sta27, sta42);
        MsduState msdu;
        const ParseResult r = parser.parse(fr, msdu, filt);
        dump_pairs("agg-control", r);
        check("agg-control: accept", r.accept);
        check("agg-control: sta0 pair kept",
              r.msdu.msdu_src_tei == 27 && r.msdu.msdu_src_mac == sta27);
        check("agg-control: sta1 pair learned", has_pair(r, 42, sta42));
        // 新增:CRC 状态检查
        bool has_crc_fail = std::any_of(r.mpdu.pb_crc_oks.begin(), r.mpdu.pb_crc_oks.end(),
                                        [](bool ok) { return !ok; });
        check("agg-control: pb_crc_oks all pass", !has_crc_fail);
    }
    // CRC32 FAIL must independently block learning even when the containing PB CRC24 is valid.
    {
        BplcFrame fr;
        fr.meta.from_raw = true;
        fr.data = QByteArray(1, char(0)) + build_dlofdma(false, cco, sta27, sta42, true);
        MsduState msdu;
        const ParseResult r = parser.parse(fr, msdu, filt);
        dump_pairs("msdu-crc-fail", r);
        const bool pb_all_ok = std::all_of(r.mpdu.pb_crc_oks.begin(), r.mpdu.pb_crc_oks.end(),
                                           [](bool ok) { return ok; });
        check("msdu-crc-fail: frame accepted", r.accept);
        check("msdu-crc-fail: PB CRCs all pass", pb_all_ok);
        check("msdu-crc-fail: station 0 valid pair retained",
              r.msdu.msdu_src_tei == 27 && r.msdu.msdu_src_mac == sta27);
        check("msdu-crc-fail: station 1 pair blocked", !has_pair(r, 42, sta42));
    }
    {
        BplcFrame fr;
        fr.meta.from_raw = true;
        fr.data = QByteArray(1, char(0)) + build_dlofdma_agg(false, cco, sta27, sta42, true);
        MsduState msdu;
        const ParseResult r = parser.parse(fr, msdu, filt);
        dump_pairs("agg-msdu-crc-fail", r);
        const bool pb_all_ok = std::all_of(r.mpdu.pb_crc_oks.begin(), r.mpdu.pb_crc_oks.end(),
                                           [](bool ok) { return ok; });
        check("agg-msdu-crc-fail: frame accepted", r.accept);
        check("agg-msdu-crc-fail: PB CRCs all pass", pb_all_ok);
        check("agg-msdu-crc-fail: station 0 valid pair retained",
              r.msdu.msdu_src_tei == 27 && r.msdu.msdu_src_mac == sta27);
        check("agg-msdu-crc-fail: station 1 pair blocked", !has_pair(r, 42, sta42));
    }
    std::printf(fails ? "RESULT: %d FAILURES\n" : "RESULT: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
