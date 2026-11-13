// gw_icv_probe.cpp
// 单跳 4B 简头(MSDU_BASE_S)尾部 32 位 ICV 校验三态 + 标准 16B 头对照(表驱动,4 个 variant:0=Ok、1=Fail、2/3=N/A 截断)。
// 直接测 GW_2026_MsduParser::parse / GW_2022_MsduParser::parse 的 MSDU body。
// 用户 2026-11 裁决:简头也要验证 ICV(HDC2.0 §5.1.1.6/§5.2.5.2、HDC1.0 均无单跳例外)。
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
#include "gw_protocol/gw_2026/gw_2026_msdu_parser.h"
#include "gw_protocol/gw_2022/gw_2022_msdu_parser.h"

static int g_fails = 0;
static void check(const char* name, bool ok) {
    std::printf("%-72s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) ++g_fails;
}

static QByteArray u32le(quint32 v) {
    QByteArray b(4, 0);
    b[0] = char(v & 0xFF);
    b[1] = char((v >> 8) & 0xFF);
    b[2] = char((v >> 16) & 0xFF);
    b[3] = char((v >> 24) & 0xFF);
    return b;
}

// variant: 0=Ok(正确 ICV) 1=Fail(篡改 1 bit) 2=N/A(截断 1B) 3=N/A(截断 3B)
static QByteArray simple_msdu(quint8 type, const QByteArray& payload, int variant) {
    QByteArray hdr(4, 0);
    hdr[0] = char(0x01);  // version=1 (单跳), byte0 低 4b
    hdr[1] = char(type);
    quint8* h = reinterpret_cast<quint8*>(hdr.data());
    set_bits(h, 2, 0, 11, payload.size());
    quint32 crc = crc32_le(reinterpret_cast<const quint8*>(payload.constData()),
                           payload.size() + 4);
    QByteArray icv = u32le(crc);
    if (variant == 1) icv[0] = char(icv[0] ^ 0x01);
    else if (variant == 2) icv.truncate(3);
    else if (variant == 3) icv.truncate(1);
    return hdr + payload + icv;
}

static QByteArray std_msdu(quint8 type, const QByteArray& payload, int variant) {
    QByteArray hdr(16, 0);
    quint8* h = reinterpret_cast<quint8*>(hdr.data());
    set_bits(h, 0, 4, 12, 1);  // src_tei=1 (CCO), byte0 低 4b=0 (标准)
    set_bits(h, 2, 0, 12, 5);  // dst_tei=5
    set_bits(h, 5, 0, 16, 1);  // seq=1
    h[7] = char(type);
    set_bits(h, 8, 0, 11, payload.size());
    quint32 crc = crc32_le(reinterpret_cast<const quint8*>(payload.constData()),
                           payload.size() + 4);
    QByteArray icv = u32le(crc);
    if (variant == 1) icv[0] = char(icv[0] ^ 0x01);
    else if (variant == 2) icv.truncate(3);
    else if (variant == 3) icv.truncate(1);
    return hdr + payload + icv;
}

// 逐用例断言:期望 Ok/Fail/N-A 三态对应的 crc_state/summary/tree/red/learning 口径。
static void assert_case(const char* tag, const MsduInfo& m, int want_state /*0=Ok,1=Fail,2=N-A*/) {
    char buf[160];
    const MsduCrcState got = msdu_crc_state(m);
    std::snprintf(buf, sizeof buf, "%s: crc_state", tag);
    check(buf, (want_state == 0 && got == MsduCrcState::Ok)
              || (want_state == 1 && got == MsduCrcState::Fail)
              || (want_state == 2 && got == MsduCrcState::NotAvailable));

    PacketEntry pe;
    pe.accepted = true;
    pe.msdu = m;
    pe.mpdu.fch_crc_checked = true;
    pe.mpdu.fch_crc_ok = true;
    const bool red = frame_crc_red(pe);
    std::snprintf(buf, sizeof buf, "%s: frame_crc_red==%d", tag, want_state == 1 ? 1 : 0);
    check(buf, red == (want_state == 1));

    const bool learn_ok = msdu_crc_allows_learning(m, /*pb_fallback_ok=*/true);
    std::snprintf(buf, sizeof buf, "%s: allows_learning", tag);
    check(buf, (want_state == 0 && learn_ok) || (want_state == 1 && !learn_ok)
              || (want_state == 2 && learn_ok));  // N/A + pb_fallback_ok=true 仍可学

    if (want_state == 1) {
        // Fail:摘要清空、树只留 MSDU CRC32 … FAIL 证据、学习字段被清
        std::snprintf(buf, sizeof buf, "%s: summary empty (Fail)", tag);
        check(buf, m.summary.isEmpty());
        std::snprintf(buf, sizeof buf, "%s: tree only CRC FAIL evidence", tag);
        check(buf, m.tree.size() == 1
                  && m.tree.first().name == QStringLiteral("MSDU CRC32")
                  && m.tree.first().value.contains(QStringLiteral("FAIL")));
        std::snprintf(buf, sizeof buf, "%s: tei_mac_pairs cleared", tag);
        check(buf, m.tei_mac_pairs.isEmpty());
        std::snprintf(buf, sizeof buf, "%s: topo_event cleared", tag);
        check(buf, m.topo_event.kind == TopoEventKind::Other);
        std::snprintf(buf, sizeof buf, "%s: src/dst tei/mac cleared", tag);
        check(buf, m.msdu_src_tei == -1 && m.msdu_dst_tei == -1
                  && m.msdu_src_mac == 0 && m.msdu_dst_mac == 0);
    } else if (want_state == 0) {
        // Ok:摘要保留(非空)
        std::snprintf(buf, sizeof buf, "%s: summary kept (Ok)", tag);
        check(buf, !m.summary.isEmpty());
    }
    // N-A:不标红(上面已断言 red==false)、树无 FAIL 证据(由 crc_state 已保证)
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QByteArray payload(20, char(0xAA));  // 载荷内容不参与 CRC 判态,任意 20B

    struct Case { const char* tag; QByteArray body; };
    // 表驱动:两种头 × 三态,各协议一套
    for (int variant = 0; variant <= 3; ++variant) {
        const int want = (variant == 0) ? 0 : (variant == 1) ? 1 : 2;
        const char* vname = (variant == 0) ? "ok" : (variant == 1) ? "fail" : "na";

        char tag[96];
        std::snprintf(tag, sizeof tag, "T gw2026 simple %s", vname);
        assert_case(tag, GW_2026_MsduParser::parse(simple_msdu(2, payload, variant)), want);
        std::snprintf(tag, sizeof tag, "T gw2026 std   %s", vname);
        assert_case(tag, GW_2026_MsduParser::parse(std_msdu(2, payload, variant)), want);
        std::snprintf(tag, sizeof tag, "T gw2022 simple %s", vname);
        assert_case(tag, GW_2022_MsduParser::parse(simple_msdu(0, payload, variant)), want);
        std::snprintf(tag, sizeof tag, "T gw2022 std   %s", vname);
        assert_case(tag, GW_2022_MsduParser::parse(std_msdu(0, payload, variant)), want);
    }

    std::printf(g_fails ? "RESULT: %d FAIL\n" : "RESULT: ALL PASS\n", g_fails);
    return g_fails ? 1 : 0;
}
