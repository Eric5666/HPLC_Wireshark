// H1 探针:get_bits 边界检查 + GW2026 OFDMA/TDA eFC 门/CRC24 整帧拒收。
// ASan 下喂截断帧,验证:(a)16-31B 截断 OFDMA/TDA 帧被 assemble() 以
// "eFC 截断"拒收;(b)32B 但 eFC CRC 错以 CRC 原因拒收;(c)32B 且 eFC CRC
// 对照常接受,完整 304B 帧接受且 PB CRC 全过;(d)14 处引用点中有代表性
// 的 5 处截断输入(GW2022 信标 STA Cap 5B、GW2022/GW2026 MSDU RFDL
// elen=8、GW2022 MSDU AssocReq b=5B、NW2026 信标 STA Cap 5B)不崩,
// 且越界读按新语义返回 0(sta_mac/tei_mac_pairs 为空)。
// H1 后续修复(问题 1/2/3/4/6):(e)d2/d4 的 IE 头位置修正到 body[11..12]
// (原写 body[4..5] 落在 MAC 里,实际只测了 elen=0 空 IE),elen=8 截断 IE
// 须跳过拓扑采集(proxy_tei/成功率留默认值);(f)d6 载波版 elen=8 同上,
// 且 TEI→MAC 学习一并跳过;(g)d7/d8 12B AssocCnf 不生成事件、不更新 CCO;
// (h)d9 宽字段(len>64)显覆盖字节十六进制,不再恒 0;(i)d10 get_bits 守卫
// 用 qint64 算 last_byte,超大偏移不再 int 溢出绕过检查。
// 另渲染一帧截断 OFDMA 帧的字段树,验证 gw_2026_tree.cpp 的 eFC 循环
// 在 rsz<32 时被跳过(纵深防御)。
// 用法:./build.sh (构建 + 运行;构建时 qmake 传 SANITIZERS=address)。
#include <QApplication>
#include <QTreeWidgetItem>
#include <climits>
#include <cstdio>
#include <cstring>
#include "bplcframe.h"
#include "fieldspec.h"
#include "fieldtools.h"
#include "gw_2026_parser.h"
#include "gw_2022_beacon_parser.h"
#include "gw_2022_msdu_parser.h"
#include "gw_2026_msdu_parser.h"
#include "nw_2026_beacon_parser.h"
#include "protocoltree.h"
#include "crc.h"

static int g_passes = 0;
static int g_fails = 0;

static void check(const char* name, bool ok, const QString& detail = QString()) {
    if (ok) {
        ++g_passes;
        std::printf("[%-26s] PASS %s\n", name, qPrintable(detail));
    } else {
        ++g_fails;
        std::printf("[%-26s] FAIL %s\n", name, qPrintable(detail));
    }
    // 逐行刷盘:ASan abort 时不走正常退出,缓冲的输出会丢。
    std::fflush(stdout);
}

static void fix_fch_crc(quint8* p) {
    p[13] = p[14] = p[15] = 0;
    const quint32 c = crc24_lsb(p, 16);
    p[13] = (quint8)(c & 0xFF);
    p[14] = (quint8)((c >> 8) & 0xFF);
    p[15] = (quint8)((c >> 16) & 0xFF);
}

// eFC 在 MPDU p[16..31]:CRC24 算前 13B,存 p[29..31](小端)。
static void fix_efc_crc(quint8* p) {
    const quint32 c = crc24_lsb(p + 16, 16);
    p[29] = (quint8)(c & 0xFF);
    p[30] = (quint8)((c >> 8) & 0xFF);
    p[31] = (quint8)((c >> 16) & 0xFF);
}

// PB 块 CRC24:算块前 sz-3B,存末 3B(小端)。
static void fix_pb_crc(quint8* blk, int sz) {
    const quint32 c = crc24_lsb(blk, sz);
    blk[sz - 3] = (quint8)(c & 0xFF);
    blk[sz - 2] = (quint8)((c >> 8) & 0xFF);
    blk[sz - 1] = (quint8)((c >> 16) & 0xFF);
}

// 合成 GW2026 OFDMA/TDA MPDU。
// total:总长(16/24/31=截断,32=仅 FCH+eFC,304=完整 2 站×136B);
// sof_dt:2=OFDMA,3=TDA;efc_crc_ok:false 时故意写错 eFC CRC。
static QByteArray make_ofdma_mpdu(int total, int sof_dt, bool efc_crc_ok) {
    QByteArray mpdu(total, 0);
    quint8* p = reinterpret_cast<quint8*>(mpdu.data());
    p[0] = 0x01;                       // frame_type=SOF(0,0,3),net_type=0
    p[1] = 0x01; p[2] = 0x00;          // net_id=1
    p[7] = (quint8)(sof_dt | (1 << 3));  // sof_dt(7,0,3)+sn_code=1(7,3,2)→2 站
    p[11] = 0x10;                      // 站点0 copy_mode=2(11,3,5)→136B;块数1(11,2,1)=0
    p[12] = 0x10;                      // version=1 HDC 2.0(12,4,4)
    if (total >= 32) {
        if (sof_dt == 2) {             // OFDMA 站点1:b=16,TEI(16,0,12)=2,copy(18,0,5)=2
            p[16] = 0x02; p[17] = 0x00; p[18] = 0x02;
        } else {                       // TDA 站点1:b=16,TEI(16,0,12)=2,copy(19,0,5)=2
            p[16] = 0x02; p[17] = 0x00; p[19] = 0x02;
        }
        if (efc_crc_ok)
            fix_efc_crc(p);
        else {
            p[29] = 0xAA; p[30] = 0xBB; p[31] = 0xCC;
        }
    }
    // PB 块(站点0 @32,站点1 @168;单块 136B:头 0xC0 + 132B 零体 + CRC24)。
    for (int base : {32, 168}) {
        if (total < base + 136)
            break;
        quint8* blk = p + base;
        blk[0] = 0xC0;                 // START|END,seq 0
        fix_pb_crc(blk, 136);
    }
    fix_fch_crc(p);
    return mpdu;
}

static GW_2026_Parser::Result parse_gw2026(const QByteArray& mpdu) {
    BplcFrame in;
    in.data = QByteArray(1, char(0)) + mpdu;  // 载波
    in.meta.from_raw = true;
    in.meta.has_time_tag = false;
    in.meta.frame_time = QDateTime::currentDateTime();
    GW_2026_Parser parser;
    MsduState st;
    ParseFilter f;
    return parser.parse(in, st, f);
}

static void dump_item(QTreeWidgetItem* it, int depth) {
    std::printf("%*s%s = %s\n", depth * 2, "",
                qPrintable(it->text(0)), qPrintable(it->text(1)));
    for (int i = 0; i < it->childCount(); ++i)
        dump_item(it->child(i), depth + 1);
}

// 在 MsduInfo.tree 里递归找名字含 needle 的节点。
static bool tree_has(const QVector<MsduFieldNode>& nodes, const QString& needle) {
    for (const auto& n : nodes) {
        if (n.name.contains(needle))
            return true;
        if (tree_has(n.children, needle))
            return true;
    }
    return false;
}

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    // --- (a) 16-31B 截断 OFDMA 帧(FCH CRC 有效)→ eFC 截断拒收 ---
    for (int len : {16, 24, 31}) {
        auto r = parse_gw2026(make_ofdma_mpdu(len, 2, true));
        char name[32];
        std::snprintf(name, sizeof name, "ofdma-trunc-%dB", len);
        check(name, !r.accept && r.reject_reason.contains(QStringLiteral("eFC 截断")),
              QStringLiteral("accept=%1 reason=%2").arg(r.accept).arg(r.reject_reason));
    }

    // --- (b) 32B 但 eFC CRC 错 → CRC 原因拒收 ---
    {
        auto r = parse_gw2026(make_ofdma_mpdu(32, 2, false));
        check("ofdma-32B-bad-efc-crc", !r.accept && r.reject_reason.contains(QStringLiteral("eFC CRC24 错")),
              QStringLiteral("accept=%1 reason=%2").arg(r.accept).arg(r.reject_reason));
    }

    // --- (c1) 32B 且 eFC CRC 对(无 PB)→ 照常接受 ---
    {
        auto r = parse_gw2026(make_ofdma_mpdu(32, 2, true));
        check("ofdma-32B-good-efc-crc", r.accept,
              QStringLiteral("accept=%1 reason=%2 stations=%3")
                  .arg(r.accept).arg(r.reject_reason).arg(r.mpdu.sof_stations.size()));
    }

    // --- (c2) 完整 304B OFDMA 帧 → 接受,PB CRC 全过,2 站 ---
    {
        auto r = parse_gw2026(make_ofdma_mpdu(304, 2, true));
        check("ofdma-304B-full", r.accept && r.mpdu.pb_crc_ok && r.mpdu.sof_stations.size() == 2,
              QStringLiteral("accept=%1 pb_crc_ok=%2 stations=%3")
                  .arg(r.accept).arg(r.mpdu.pb_crc_ok).arg(r.mpdu.sof_stations.size()));
    }

    // --- (c3) 完整 304B TDA 帧 → 接受 ---
    {
        auto r = parse_gw2026(make_ofdma_mpdu(304, 3, true));
        check("tda-304B-full", r.accept && r.mpdu.sof_stations.size() == 2,
              QStringLiteral("accept=%1 reason=%2 stations=%3")
                  .arg(r.accept).arg(r.reject_reason).arg(r.mpdu.sof_stations.size()));
    }

    // --- (d0) 截断 OFDMA 帧的字段树:rsz<32 时 eFC 循环被跳过,不崩 ---
    {
        auto r = parse_gw2026(make_ofdma_mpdu(20, 2, true));
        PacketEntry e;
        e.index = 1;
        e.accepted = r.accept;
        e.reason = r.reject_reason;
        e.raw_bytes = r.payload_for_log;
        e.meta = r.meta;
        e.mpdu = r.mpdu;
        e.msdu_body = r.msdu_body;
        e.msdu = r.msdu;
        e.msdu_raw_base = r.msdu_raw_base;
        e.protocol = kProtocolGw2026;
        ProtocolTree tree;
        tree.show_packet(e);
        std::printf("--- truncated OFDMA field tree (rsz=20) ---\n");
        for (int i = 0; i < tree.topLevelItemCount(); ++i)
            dump_item(tree.topLevelItem(i), 0);
        check("tree-trunc-ofdma-20B", !r.accept && tree.topLevelItemCount() > 0,
              QStringLiteral("accept=%1 reason=%2 top_items=%3")
                  .arg(r.accept).arg(r.reject_reason).arg(tree.topLevelItemCount()));
    }

    // --- (d1) GW2022 信标 STA Cap 条目截到 5B (beacon:349-350) ---
    {
        QByteArray payload(16 + 136, 0);
        quint8* p = reinterpret_cast<quint8*>(payload.data());
        p[0] = 0x00;                   // BEACON
        p[8] = 0x01;                   // 源 TEI=1 (8,0,12)
        p[9] = 0x30;                   // TMI=3 (9,4,4) → PB 136B
        p[10] = 0xF3;
        p[12] = 0x15;                  // 版本=1
        fix_fch_crc(p);
        quint8* g = p + 16;            // gb:标准信标,item_num 在 gb[20]
        g[20] = 1;                     // item_num=1
        g[21] = 0x00;                  // STA_CAPABILITY
        g[22] = 7;                     // len_raw=7 → 内容 5B
        g[23] = 0x01; g[24] = 0x00;    // TEI=1 (it[0] 12b)
        g[25] = 0xAA; g[26] = 0xBB; g[27] = 0xCC;  // it[2..4];it[4..9] 的 48b MAC 被截掉
        auto info = GW_2022_BeaconParser::parse_beacon(payload);
        check("gw2022-beacon-stacap-5B",
              info.present && info.tei_mac_pairs.isEmpty(),
              QStringLiteral("present=%1 tei_mac_pairs=%2")
                  .arg(info.present).arg(info.tei_mac_pairs.size()));
    }

    // --- (d2) GW2022 MSDU RFDL IE elen=8 (msdu:843-856) ---
    // IE 头在 msdu_body[7..8]=body[11..12]:RFDL 载荷开头 7B(STA MAC 6B + 序号 1B),
    // TLV 循环从 pos=7 开始;原探针写 p[4..5] 落在 MAC 里,实际只测了 elen=0 空 IE。
    // elen=8<12 为截断 IE:proxy TEI=5 为陷阱值,门应跳过拓扑采集(只留字段树渲染)。
    {
        QByteArray body(21, 0);
        quint8* p = reinterpret_cast<quint8*>(body.data());
        p[0] = 0x01;                   // 简头(版本低 4 位=1)
        p[1] = 0x00;                   // DISCOVERY_LIST
        p[2] = 0x11; p[3] = 0x00;      // msdu_len=17 (2,0,11);载荷=7+2+8
        // msdu_body=body[4..20]:STA MAC body[4..9],序号 body[10]
        p[11] = 0x00;                  // IE type 0 = 站点属性(表126,14B 定长)
        p[12] = 0x08;                  // elen=8 (<12,内容只给 8B)
        p[19] = 0x05;                  // content[6]=proxy TEI 陷阱值 5
        auto info = GW_2022_MsduParser::parse(body);
        check("gw2022-msdu-rfdl-elen8",
              info.present && info.summary.contains(QStringLiteral("发现列表"))
                  && info.summary.contains(QStringLiteral(" (站点属性截断)"))
                  && tree_has(info.tree, QStringLiteral("Station Attribute"))
                  && info.topo_event.proxy_tei == kTeiInvalid
                  && info.topo_event.proxy_up_rate == -1
                  && info.topo_event.proxy_down_rate == -1
                  && info.topo_event.min_link_rate == -1,
              QStringLiteral("present=%1 proxy_tei=0x%2 up=%3 summary=%4")
                  .arg(info.present).arg(info.topo_event.proxy_tei, 0, 16)
                  .arg(info.topo_event.proxy_up_rate).arg(info.summary));
    }

    // --- (d3) GW2022 MSDU AssocReq b=5B (msdu:1166) ---
    {
        QByteArray body(25, 0);
        quint8* p = reinterpret_cast<quint8*>(body.data());
        p[7] = 0x00;                   // msdu_type = NET_MANAGEMENT
        p[8] = 0x09; p[9] = 0x00;      // msdu_len=9 (8,0,11);restart_count=0
        // msdu_body=body[16..24]:MMType=0x0000(MME_ASSOC_REQ),RSV=0,b=5B
        p[20] = 0x11; p[21] = 0x22; p[22] = 0x33; p[23] = 0x44; p[24] = 0x55;
        auto info = GW_2022_MsduParser::parse(body);
        check("gw2022-msdu-assocreq-5B",
              info.present && info.sta_mac == 0,
              QStringLiteral("present=%1 sta_mac=0x%2")
                  .arg(info.present).arg(info.sta_mac, 0, 16));
    }

    // --- (d4) GW2026 MSDU RFDL IE elen=8 (msdu:836-856,同 d2 形状) ---
    // IE 头位置同 d2;elen=8<12 截断,proxy TEI=5 为陷阱值,门应跳过拓扑采集。
    {
        QByteArray body(21, 0);
        quint8* p = reinterpret_cast<quint8*>(body.data());
        p[0] = 0x01;
        p[1] = 0x00;
        p[2] = 0x11; p[3] = 0x00;      // msdu_len=17 (2,0,11);载荷=7+2+8
        p[11] = 0x00;                  // IE type 0 = 站点属性(表92,14B 定长)
        p[12] = 0x08;                  // elen=8 (<12)
        p[19] = 0x05;                  // content[6]=proxy TEI 陷阱值 5
        auto info = GW_2026_MsduParser::parse(body);
        check("gw2026-msdu-rfdl-elen8",
              info.present && info.summary.contains(QStringLiteral("发现列表"))
                  && info.summary.contains(QStringLiteral(" (站点属性截断)"))
                  && tree_has(info.tree, QStringLiteral("Station Attribute"))
                  && info.topo_event.proxy_tei == kTeiInvalid
                  && info.topo_event.proxy_up_rate == -1
                  && info.topo_event.proxy_down_rate == -1
                  && info.topo_event.min_link_rate == -1,
              QStringLiteral("present=%1 proxy_tei=0x%2 up=%3 summary=%4")
                  .arg(info.present).arg(info.topo_event.proxy_tei, 0, 16)
                  .arg(info.topo_event.proxy_up_rate).arg(info.summary));
    }

    // --- (d5) NW2026 信标 STA Cap 条目截到 5B (beacon:382) ---
    {
        QByteArray payload(16 + 136, 0);
        quint8* p = reinterpret_cast<quint8*>(payload.data());
        quint8* g = p + 16;            // gb:非精简信标(gb[0] bit4=0),mgmt_start=6
        g[6] = 1;                      // item_num=1
        g[7] = 0x01;                   // STA_CAPABILITY
        g[8] = 7;                      // len_raw=7 → 内容 5B
        g[9] = 0x01; g[10] = 0x00;     // it[1] 12b TEI 所在字节
        g[11] = 0xAA; g[12] = 0xBB; g[13] = 0xCC;  // it[2..4];it[4..9] 的 48b MAC 被截掉
        auto info = NW_2026_BeaconParser::parse_beacon(payload, 136, false);
        check("nw2026-beacon-stacap-5B",
              info.present && info.tei_mac_pairs.isEmpty(),
              QStringLiteral("present=%1 tei_mac_pairs=%2")
                  .arg(info.present).arg(info.tei_mac_pairs.size()));
    }

    // --- (d6) GW2026 载波发现列表 RFDL IE elen=8 (msdu:826-870) ---
    // msg_type 2 = CARRIER_DISCOVERY;IE 头同样在 body[11..12];elen=8<17 截断:
    // sender TEI=5 与 proxy TEI=5 均为陷阱值,门应跳过 TEI→MAC 学习与拓扑采集。
    {
        QByteArray body(21, 0);
        quint8* p = reinterpret_cast<quint8*>(body.data());
        p[0] = 0x01;
        p[1] = 0x02;                   // CARRIER_DISCOVERY
        p[2] = 0x11; p[3] = 0x00;      // msdu_len=17 (2,0,11);载荷=7+2+8
        // 头 MAC body[4..9] = 发送节点 MAC(陷阱),序号 body[10]
        p[4] = 0x00; p[5] = 0x11; p[6] = 0x22; p[7] = 0x33; p[8] = 0x44; p[9] = 0x55;
        p[11] = 0x00;                  // IE type 0 = 站点属性(表63,23B 定长)
        p[12] = 0x08;                  // elen=8 (<17)
        p[13] = 0x05;                  // content[0]=sender TEI 陷阱值 5
        p[14] = 0x50;                  // content[1] bit4..=proxy TEI 陷阱值 5
        auto info = GW_2026_MsduParser::parse(body);
        check("gw2026-carrier-rfdl-elen8",
              info.present && info.summary.contains(QStringLiteral("载波发现列表"))
                  && info.summary.contains(QStringLiteral(" (站点属性截断)"))
                  && tree_has(info.tree, QStringLiteral("Station Attribute"))
                  && info.tei_mac_pairs.isEmpty()
                  && info.topo_event.proxy_tei == kTeiInvalid
                  && info.topo_event.proxy_comm_rate == -1
                  && info.topo_event.proxy_down_comm_rate == -1
                  && info.topo_event.min_comm_rate == -1,
              QStringLiteral("present=%1 pairs=%2 proxy_tei=0x%3 comm=%4 summary=%5")
                  .arg(info.present).arg(info.tei_mac_pairs.size())
                  .arg(info.topo_event.proxy_tei, 0, 16)
                  .arg(info.topo_event.proxy_comm_rate).arg(info.summary));
    }

    // --- (d7) GW2022 MSDU AssocCnf b=12B (msdu:1232-1255) ---
    // b=12B<18B:assoc_res@12 越界读 0 会被当成入网成功;门应跳过事件与 CCO 更新。
    // sta_mac/cco_mac 均给非零陷阱值,验证 CCO 不更新、节点不建。
    {
        QByteArray body(32, 0);
        quint8* p = reinterpret_cast<quint8*>(body.data());
        p[7] = 0x00;                   // msdu_type = NET_MANAGEMENT
        p[8] = 0x10; p[9] = 0x00;      // msdu_len=16 (8,0,11);MMe_BASE 4B + b 12B
        // msdu_body=body[16..31]:MMType=0x0001(MME_ASSOC_CNF),RSV=0,b=body[20..31]
        p[16] = 0x01;                  // MMType 低字节=0x01
        p[20] = 0x00; p[21] = 0x11; p[22] = 0x22; p[23] = 0x33; p[24] = 0x44; p[25] = 0x55;
        p[26] = 0x66; p[27] = 0x77; p[28] = 0x88; p[29] = 0x99; p[30] = 0xAA; p[31] = 0xBB;
        auto info = GW_2022_MsduParser::parse(body);
        check("gw2022-msdu-assoccnf-12B",
              info.present && info.summary.contains(QStringLiteral("关联确认"))
                  && info.summary.contains(QStringLiteral(" (关联确认截断)"))
                  && info.topo_event.kind == TopoEventKind::Other
                  && info.topo_event.cco_mac == 0
                  && !info.topo_event.is_rf_known
                  && info.topo_event.nodes.isEmpty()
                  && info.topo_event.routes.isEmpty(),
              QStringLiteral("present=%1 kind=%2 cco=0x%3 summary=%4")
                  .arg(info.present).arg((int)info.topo_event.kind)
                  .arg(info.topo_event.cco_mac, 0, 16).arg(info.summary));
    }

    // --- (d8) GW2026 MSDU AssocCnf b=12B (msdu:1370-1395,同 d7 形状) ---
    // b=12B<18B:门应跳过事件、CCO 更新与 tei_mac_pairs 学习。
    {
        QByteArray body(32, 0);
        quint8* p = reinterpret_cast<quint8*>(body.data());
        p[7] = 0x00;                   // msdu_type = NET_MANAGEMENT
        p[8] = 0x10; p[9] = 0x00;      // msdu_len=16 (8,0,11);MMe_BASE 4B + b 12B
        p[16] = 0x01;                  // MMType 低字节=0x01 (MME_ASSOC_CNF)
        p[20] = 0x00; p[21] = 0x11; p[22] = 0x22; p[23] = 0x33; p[24] = 0x44; p[25] = 0x55;
        p[26] = 0x66; p[27] = 0x77; p[28] = 0x88; p[29] = 0x99; p[30] = 0xAA; p[31] = 0xBB;
        auto info = GW_2026_MsduParser::parse(body);
        check("gw2026-msdu-assoccnf-12B",
              info.present && info.summary.contains(QStringLiteral("关联确认"))
                  && info.summary.contains(QStringLiteral(" (关联确认截断)"))
                  && info.topo_event.kind == TopoEventKind::Other
                  && info.topo_event.cco_mac == 0
                  && !info.topo_event.is_rf_known
                  && info.topo_event.nodes.isEmpty()
                  && info.topo_event.routes.isEmpty()
                  && info.tei_mac_pairs.isEmpty(),
              QStringLiteral("present=%1 kind=%2 cco=0x%3 pairs=%4 summary=%5")
                  .arg(info.present).arg((int)info.topo_event.kind)
                  .arg(info.topo_event.cco_mac, 0, 16)
                  .arg(info.tei_mac_pairs.size()).arg(info.summary));
    }

    // --- (d9) >64 位保留字段不走 get_bits,显覆盖字节十六进制 (fieldspec:48) ---
    // 80 位 DEC 旧语义恒显 0;125 位 bit=3 的字段首尾邻位混入,RSV 显示可接受。
    {
        QByteArray d(26, 0);
        for (int i = 0; i < d.size(); ++i) d[i] = (char)i;   // 0x00..0x19
        static const FieldSpec kWideSpec[] = {
            {"RSV", 0, 0, 80, Fmt::DEC},
            {"RSV2", 10, 3, 125, Fmt::HEX4},
        };
        QVector<MsduFieldNode> nodes;
        add_fields(nodes, d, 0, kWideSpec, 2);
        check("wide-field-hex-dump",
              nodes.size() == 2
                  && nodes[0].value == QStringLiteral("00 01 02 03 04 05 06 07 08 09")
                  && nodes[1].value == QStringLiteral("0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19"),
              QStringLiteral("n=%1 v0=%2 v1=%3").arg(nodes.size())
                  .arg(nodes.size() > 0 ? nodes[0].value : QStringLiteral("-"))
                  .arg(nodes.size() > 1 ? nodes[1].value : QStringLiteral("-")));
    }

    // --- (d10) get_bits 守卫 qint64:超大偏移不再 int 溢出绕过检查 (fieldtools:29-31) ---
    // start_byte=INT_MAX-2、bit_len=64 时旧守卫和为 INT_MAX+5 回绕成负,绕过检查后
    // 循环读 d[INT_MAX-2...] 直接崩;新守卫 last_byte(INT64) 直接返 0。
    {
        const QByteArray d("ABCD", 4);
        const quint64 v1 = get_bits(d, INT_MAX - 2, 0, 64);
        const quint64 v2 = get_bits(d, 0, INT_MAX, 64);
        const quint64 v3 = get_bits(d, 0, 0, 65);   // bit_len>64 仍返 0
        check("getbits-qint64-guard",
              v1 == 0 && v2 == 0 && v3 == 0,
              QStringLiteral("v1=%1 v2=%2 v3=%3").arg(v1).arg(v2).arg(v3));
    }

    std::printf("RESULT: %d PASS, %d FAIL\n", g_passes, g_fails);
    return g_fails ? 1 : 0;
}
