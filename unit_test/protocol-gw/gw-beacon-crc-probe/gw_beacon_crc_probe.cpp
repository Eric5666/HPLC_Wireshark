// gw_beacon_crc_probe.cpp
// 信标载荷 CRC32(BPCS)与 PB CRC24 三态:解析 → 标红 → 学习阻断(表驱动)。
// GW2022/GW2026 走完整解析器(GW_2022_Parser/GW_2026_Parser,载波信标 TMI=2,
// PB 136B,STA Cap 条目 TEI 5/MAC aa:bb:cc:dd:ee:05,CCO MAC aa:bb:cc:dd:ee:01);
// NW2026/NW2021 直测 parse_beacon(南网完整 MPDU 另需 FCH 规约,信标解析器
// 入口等价;NW 不设 mpdu.beacon_cco_mac,故只断言条目对)。
// 口径(用户 2026-11 裁决:信标也要验证载荷 CRC):正确 ⇒ Ok(学)、篡改 ⇒ Fail
// (标红、不学,摘要仍保留"信标载荷 CRC32:失败"以明示原因)、PB CRC 坏 ⇒
// 只标红、仍可学(与 MSDU CRC 覆盖 PB CRC 同口径)。有 FAIL 即 exit 1。
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <QCoreApplication>
#include <QByteArray>
#include <QString>
#include "bplcframe.h"
#include "fieldtools.h"
#include "crc.h"
#include "common/msdu_crc_state.h"
#include "gw_protocol/gw_2026/gw_2026_parser.h"
#include "gw_protocol/gw_2022/gw_2022_parser.h"
#include "nw_protocol/nw_2026/nw_2026_beacon_parser.h"
#include "nw_protocol/nw_2021/nw_2021_beacon_parser.h"
#include "ui/packetlistmodel.h"

static int g_fails = 0;
// 学习断言走公开路径 make_export_snapshot().tei_mac(lookup_mac 是私有的)。
static quint64 learned_mac(const PacketListModel& model, quint32 nid, quint16 tei) {
    const auto snap = model.make_export_snapshot();
    const auto it = snap.tei_mac.constFind(nid);
    if (it == snap.tei_mac.constEnd()) return 0;
    return it.value().value(tei, 0);
}

static void check(const char* name, bool ok) {
    std::printf("%-72s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) ++g_fails;
}

static void put_u48le(quint8* p, quint64 mac) {
    for (int i = 0; i < 6; ++i) p[i] = quint8((mac >> (8 * i)) & 0xFF);
}
static void put_u32le(quint8* p, quint32 v) {
    for (int i = 0; i < 4; ++i) p[i] = quint8((v >> (8 * i)) & 0xFF);
}
static void fix_fch_crc(quint8* p) {
    p[13] = p[14] = p[15] = 0;
    const quint32 c = crc24_lsb(p, 16);
    p[13] = quint8(c & 0xFF); p[14] = quint8((c >> 8) & 0xFF); p[15] = quint8((c >> 16) & 0xFF);
}

// variant: 0=Ok(全正确) 1=Fail(载荷 CRC32 篡改 1 bit,PB CRC 仍有效)
//          2=PB 坏(载荷 CRC32 正确,PB CRC24 篡改 1 bit)
static QByteArray gw_beacon_mpdu(int version, int variant) {
    QByteArray mpdu(16 + 136, 0);
    quint8* p = reinterpret_cast<quint8*>(mpdu.data());
    p[0] = 0x00;                                    // BEACON
    set_bits(p, 1, 0, 24, 0x1234);                  // NID
    set_bits(p, 8, 0, 12, 1);                       // src TEI = CCO
    set_bits(p, 9, 4, 4, 2);                        // TMI = 2 -> PB 136
    set_bits(p, 10, 0, 9, 300);                     // symbol num
    set_bits(p, 11, 1, 2, 2);                       // beacon line
    set_bits(p, 12, 4, 4, version);                 // 0=HDC 1.0 / 1=HDC 2.0
    fix_fch_crc(p);
    // gb(133B):固定头 20B + ItemNum + STA Cap 条目 + 零填充 + 载荷 CRC32
    quint8* gb = p + 16;
    gb[1] = 1;                                      // NetSN
    put_u48le(gb + 2, 0xAABBCCDDEE01ULL);            // CCO MAC
    put_u32le(gb + 8, 1);                           // period count
    gb[20] = 1;                                     // ItemNum = 1
    gb[21] = 0x00;                                  // head: STA_CAPABILITY
    gb[22] = 15;                                    // len_raw = 内容 13B + 2
    quint8* it = gb + 23;
    set_bits(it, 0, 0, 12, 5);                      // TEI 5
    set_bits(it, 1, 4, 12, 2);                      // PCOTEI 2
    it[3] = 100;                                    // LinkMinCommSuccessRate
    put_u48le(it + 4, 0xAABBCCDDEE05ULL);            // SourceMAC
    it[10] = 0x11;                                  // Role 1 (STA) | NetLevel 1
    put_u32le(gb + 129, crc32_le(gb, 133));         // 载荷 CRC32(覆盖前 129B)
    quint8* blk = p + 16;
    put_u32le(blk + 133, 0);                        // 先清零再算 PB CRC24
    const quint32 pb = crc24_lsb(blk, 136);
    blk[133] = quint8(pb & 0xFF); blk[134] = quint8((pb >> 8) & 0xFF);
    blk[135] = quint8((pb >> 16) & 0xFF);
    if (variant == 1) gb[129] = quint8(gb[129] ^ 0x01);   // 只坏载荷 CRC32
    else if (variant == 2) blk[133] = quint8(blk[133] ^ 0x01);  // 只坏 PB CRC24
    return mpdu;
}

// 南网信标载荷直测:16B 占位 FCH + PB 136B;固定头 6B,ItemNum 在 gb[6],
// STA Cap 条目 head=0x01,TEI 在内容 byte1(12b),MAC 在 byte4(48b)。
// BPCS 在 gb 倒数第 5..2 字节(覆盖前 gb.size()-5 字节),末字节保留。
static QByteArray nw_beacon_payload(int variant) {
    QByteArray payload(16 + 136, 0);
    quint8* gb = reinterpret_cast<quint8*>(payload.data()) + 16;
    gb[6] = 1;                                      // ItemNum = 1
    gb[7] = 0x01;                                   // head: STA_CAPABILITY
    gb[8] = 15;                                     // len_raw = 内容 13B + 2
    quint8* it = gb + 9;
    set_bits(it, 1, 0, 12, 5);                      // TEI 5
    put_u48le(it + 4, 0xAABBCCDDEE05ULL);            // SourceMAC
    put_u32le(gb + 128, crc32_le(gb, 132));         // BPCS(覆盖前 128B)
    gb[132] = 0;                                    // 保留字节
    quint8* blk = reinterpret_cast<quint8*>(payload.data()) + 16;
    const quint32 pb = crc24_lsb(blk, 136);
    blk[133] = quint8(pb & 0xFF); blk[134] = quint8((pb >> 8) & 0xFF);
    blk[135] = quint8((pb >> 16) & 0xFF);
    if (variant == 1) gb[128] = quint8(gb[128] ^ 0x01);  // 只坏 BPCS
    else if (variant == 2) blk[133] = quint8(blk[133] ^ 0x01);  // 只坏 PB CRC24
    return payload;
}

// 逐用例断言:期望 state/red/学习口径。want: 0=Ok,1=Fail,2=PB 坏(Ok 但红)。
static void assert_case(const char* tag, const PacketEntry& e, int want,
                        bool check_learn, bool check_cco) {
    char buf[160];
    const MsduCrcState got = msdu_crc_state(e.beacon);
    std::snprintf(buf, sizeof buf, "%s: present", tag);
    check(buf, e.beacon.present);
    std::snprintf(buf, sizeof buf, "%s: crc_state", tag);
    check(buf, (want == 0 && got == MsduCrcState::Ok)
              || (want == 1 && got == MsduCrcState::Fail)
              || (want == 2 && got == MsduCrcState::Ok));
    std::snprintf(buf, sizeof buf, "%s: frame_crc_red==%d", tag, want == 0 ? 0 : 1);
    check(buf, frame_crc_red(e) == (want != 0));
    if (want == 1) {
        // Fail:摘要保留失败通知(与 MSDU FAIL 清空不同,见 packetlistmodel 注释)
        std::snprintf(buf, sizeof buf, "%s: summary keeps FAIL notice", tag);
        check(buf, !e.beacon.summary.isEmpty()
                  && e.beacon.summary.contains(QStringLiteral("失败")));
    }
    if (check_learn) {
        PacketListModel model;
        const quint32 nid = e.mpdu.net_id;
        // 学习走公开路径 append_packet -> update_tei_mac(后者是私有的)。
        model.append_packet(e);
        std::snprintf(buf, sizeof buf, "%s: TEI5 learned==%d", tag, want != 1 ? 1 : 0);
        check(buf, (learned_mac(model, nid, 5) == 0xAABBCCDDEE05ULL) == (want != 1));
        if (check_cco) {
            std::snprintf(buf, sizeof buf, "%s: CCO(TEI1) learned==%d", tag, want != 1 ? 1 : 0);
            check(buf, (learned_mac(model, nid, 1) == 0xAABBCCDDEE01ULL) == (want != 1));
        }
    }
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    // GW:完整解析器(载波信标)。version 0 走 GW2022,version 1 走 GW2026。
    for (int variant = 0; variant <= 2; ++variant) {
        const char* vname = (variant == 0) ? "ok" : (variant == 1) ? "fail" : "pb-bad";
        char tag[96];
        {
            GW_2022_Parser parser;
            BplcFrame in; in.meta.from_raw = true;
            in.data = QByteArray(1, char(0)) + gw_beacon_mpdu(0, variant);
            MsduState st; ParseFilter f;
            const ParseResult r = parser.parse(in, st, f);
            PacketEntry e; e.meta = r.meta; e.mpdu = r.mpdu; e.beacon = r.beacon;
            e.accepted = r.accept; e.mpdu.net_id = 0x1234;
            std::snprintf(tag, sizeof tag, "T gw2022 %s", vname);
            assert_case(tag, e, variant, true, true);
        }
        {
            GW_2026_Parser parser;
            BplcFrame in; in.meta.from_raw = true;
            in.data = QByteArray(1, char(0)) + gw_beacon_mpdu(1, variant);
            MsduState st; ParseFilter f;
            const ParseResult r = parser.parse(in, st, f);
            PacketEntry e; e.meta = r.meta; e.mpdu = r.mpdu; e.beacon = r.beacon;
            e.accepted = r.accept; e.mpdu.net_id = 0x1234;
            std::snprintf(tag, sizeof tag, "T gw2026 %s", vname);
            assert_case(tag, e, variant, true, true);
        }
    }
    // NW:直测 parse_beacon(南网不设 beacon_cco_mac,只断言条目对;NW2021 无对)。
    for (int variant = 0; variant <= 2; ++variant) {
        const char* vname = (variant == 0) ? "ok" : (variant == 1) ? "fail" : "pb-bad";
        char tag[96];
        {
            const QByteArray payload = nw_beacon_payload(variant);
            PacketEntry e; e.accepted = true;
            e.mpdu.net_id = 99; e.mpdu.frame_type = 0;
            e.mpdu.fch_crc_checked = true; e.mpdu.fch_crc_ok = true;
            e.beacon = NW_2026_BeaconParser::parse_beacon(payload, 136, false);
            std::snprintf(tag, sizeof tag, "T nw2026 %s", vname);
            assert_case(tag, e, variant, true, false);
        }
        {
            const QByteArray payload = nw_beacon_payload(variant);
            PacketEntry e; e.accepted = true;
            e.mpdu.net_id = 99; e.mpdu.frame_type = 0;
            e.mpdu.fch_crc_checked = true; e.mpdu.fch_crc_ok = true;
            e.beacon = NW_2021_BeaconParser::parse_beacon(payload, 136, false);
            std::snprintf(tag, sizeof tag, "T nw2021 %s", vname);
            assert_case(tag, e, variant, false, false);
            std::snprintf(tag, sizeof tag, "T nw2021 %s: no pairs", vname);
            check(tag, e.beacon.tei_mac_pairs.isEmpty());
        }
    }

    std::printf(g_fails ? "RESULT: %d FAIL\n" : "RESULT: ALL PASS\n", g_fails);
    return g_fails ? 1 : 0;
}
