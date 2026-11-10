/// 探针:MSDU CRC32 三态门控(用户 2026-11 裁决)
/// 口径(逐层三态,DROP 只在 FC 阶段):
///   FCH CRC FAIL                      ⇒ DROP(唯一 DROP 条件)
///   FCH OK + PB FAIL + MSDU OK        ⇒ 必须解析(原摘要),Info 列仍显 CRC FAIL,行红
///   FCH OK + PB ANY  + MSDU FAIL      ⇒ present=1、摘要空、字段树只留 `MSDU CRC32 … FAIL`、行红
///   FCH OK + PB ANY  + MSDU N-A       ⇒ 维持现状(摘要保留 "(CRC 缺失)" 提示,不因缺失标红)
/// 用例来源:用户线上帧(0x3C@0 … 0x3E@764,766 字节;帧后紧跟模块调试日志被同一 3C/3E 吞入)
///   fixture: unit_test/frames/frame-probe/nw_log_tail_pb_crc_fail.bin(原样入库,期望写死)
/// 用法:./msdu_crc_gate_probe ; exit 0 = 全部断言通过
#include <QCoreApplication>
#include <QFile>
#include <QByteArray>
#include <cstdio>
#include "bplcframe.h"
#include "crc.h"
#include "msdu_crc_state.h"
#include "nw_2021_parser.h"
#include "gw_2026_parser.h"
#include "packetlistmodel.h"   // UI 层逐字断言(Info / MSDU Type / ForegroundRole)
#include "playbackwriter.h"    // 反转义路径(W 用例)
#include <QColor>

static int g_block_start = -1;   ///< PB 块起点(相对反转义后的帧);由 A 用例解析结果反推
static int g_pb_size = 0;        ///< PB 块长(FCH 声明)

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { std::printf("FAIL: %s\n", msg); ++failures; } \
    else { std::printf("ok: %s\n", msg); } } while (0)

/// @brief 3C/3E 定界 + 反转义(直接调生产函数 playback::unescape_frame_data,方案 A)
/// @details 探针与生产共用同一反转义实现,不做第二套手写反转义(否则线缆字节解出结果不同)。
static bool extract_frame(QByteArray& buf, QByteArray& out) {
    int idx = buf.indexOf(char(0x3C));
    if (idx < 0) return false;
    buf.remove(0, idx + 1);
    idx = buf.indexOf(char(0x3E));
    if (idx < 0) return false;
    const QByteArray esc = buf.left(idx);
    buf.remove(0, idx + 1);
    int n = 0;
    playback::unescape_frame_data(esc, out, &n);
    return true;
}

/// @brief 重算最后一块 PB 块尾 CRC24(块 = 末尾 pb_size 字节,CRC24 存末 3B,LSB 先行)
/// @details 生成/修复样本用:只改 CRC 自身,不动块内容 —— 用于造 "PB OK" 的变体。
static void fix_pb_crc24(QByteArray& inner, int block_start, int pb_size) {
    if (block_start < 0 || inner.size() < block_start + pb_size) return;
    quint8* p = reinterpret_cast<quint8*>(inner.data()) + block_start;
    const quint32 c = crc24_lsb(p, pb_size);   // crc24_lsb 遍历前 len-3 字节
    p[pb_size - 3] = (quint8)(c & 0xFF);
    p[pb_size - 2] = (quint8)((c >> 8) & 0xFF);
    p[pb_size - 1] = (quint8)((c >> 16) & 0xFF);
}

static QString node_value(const QVector<MsduFieldNode>& nodes, const QString& name) {
    for (const MsduFieldNode& n : nodes) {
        if (n.name == name) return n.value;
        const QString sub = node_value(n.children, name);
        if (!sub.isEmpty()) return sub;
    }
    return QString();
}

static int count_nodes(const QVector<MsduFieldNode>& nodes, const QString& name) {
    int c = 0;
    for (const MsduFieldNode& n : nodes) {
        if (n.name == name) ++c;
        c += count_nodes(n.children, name);
    }
    return c;
}

static PacketEntry make_entry(const ParseResult& r) {
    PacketEntry e;
    e.accepted = r.accept;
    e.mpdu = r.mpdu;
    e.msdu = r.msdu;
    return e;
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);

    // ---- fixture:用户线上帧(入库原样,期望写死)----
    QFile f(QStringLiteral(FIXTURE_PATH));
    if (!f.open(QIODevice::ReadOnly)) { std::printf("FAIL: cannot open fixture\n"); return 1; }
    QByteArray buf = f.readAll();
    QByteArray inner;
    if (!extract_frame(buf, inner)) { std::printf("FAIL: no frame in fixture\n"); return 1; }
    std::printf("fixture: %d bytes -> unescaped %d bytes\n", (int)buf.size(), (int)inner.size());

    // ===== A:原始帧 —— FCH CRC OK + PB 块 CRC FAIL + MSDU CRC32 OK ⇒ 必须解析 =====
    {
        BplcFrame in;
        in.data = inner;
        NW_2021_Parser parser;
        MsduState st;
        ParseFilter flt;
        const ParseResult r = parser.parse(in, st, flt);
        std::printf("[A] accept=%d fch_checked=%d fch_ok=%d pb_num=%d pb_oks=%d msdu_present=%d summary=%s\n",
                    (int)r.accept, (int)r.mpdu.fch_crc_checked, (int)r.mpdu.fch_crc_ok,
                    r.mpdu.pb_num, (int)r.mpdu.pb_crc_oks.size(), (int)r.msdu.present,
                    qPrintable(r.msdu.summary));
        CHECK(r.accept, "A1 帧被接受(FC CRC 通过 ⇒ 不 DROP)");
        CHECK(r.mpdu.fch_crc_checked && r.mpdu.fch_crc_ok, "A2 FCH CRC24 校验通过");
        CHECK(r.mpdu.pb_crc_oks.size() == 1 && !r.mpdu.pb_crc_oks.at(0),
              "A3 PB 块 CRC24 FAIL(块体跨进模块调试日志)");
        CHECK(r.msdu.present, "A4 PB 块 CRC 失败不再阻断:MSDU 仍解析(present=1)");
        CHECK(r.msdu.summary.contains(QStringLiteral("应用层报文")),
              "A5 摘要为原摘要(应用层报文…)");
        CHECK(r.msdu.summary.contains(QStringLiteral("BID=0x03")), "A6 摘要含 BID=0x03");
        CHECK(r.msdu.summary.contains(QStringLiteral("站点间通信")), "A7 摘要含业务名 站点间通信");
        std::printf("[A] bid=0x%02x app_type=0x%02x trans_dir=%d;",
                    r.msdu.business_id, r.msdu.app_packet_type,
                    (int)r.msdu.trans_direction_flag);
        std::puts("");
        const QString crc = node_value(r.msdu.tree, QStringLiteral("MSDU CRC32"));
        std::printf("[A] MSDU CRC32 = %s\n", qPrintable(crc));
        CHECK(crc == QStringLiteral("0x5d813887 OK"), "A8 字段树 MSDU CRC32 = 0x5d813887 OK");
        CHECK(msdu_crc_state(r.msdu) == MsduCrcState::Ok, "A9 三态 = Ok");
        CHECK(frame_crc_red(make_entry(r)), "A10 行判红(PB 块 CRC 失败)");
        // 块位置:单块帧 msdu_raw_base = 块体偏移 ⇒ 块起点 = 块体偏移 - (PB 头 4B + 保留 1B)
        g_pb_size = r.mpdu.pb_size;
        // msdu_raw_base 是相对 payload_for_log 的块体偏移 ⇒ 换算到反转义后的帧坐标
        // (payload_for_log 通常从物理头之后开始,需加上物理头长度)
        const int pl_off = inner.indexOf(r.payload_for_log);
        // 块布局(南网表47):块头 4B + 块体 128B + 尾保留 1B + CRC24 3B
        // ⇒ 块起点 = 块体偏移 - 块头长度(4)
        g_block_start = (r.msdu_raw_base > 0)
                            ? (pl_off < 0 ? 0 : pl_off) + r.msdu_raw_base - 4 : -1;
        std::printf("[A] block_start=%d pb_size=%d msdu_raw_base=%d\n",
                    g_block_start, g_pb_size, r.msdu_raw_base);
        CHECK(g_block_start > 0 && g_pb_size > 8, "A11 已定位 PB 块(供 D/C 变体重算块 CRC24)");
    }

    // ===== D:好帧回归 —— 只重算 PB 块 CRC24(PB OK + MSDU OK)⇒ 摘要/字段树与改前一致 =====
    {
        QByteArray good = inner;
        fix_pb_crc24(good, g_block_start, g_pb_size);   // 只重算块尾 CRC24 ⇒ PB OK
        BplcFrame in;
        in.data = good;
        NW_2021_Parser parser;
        MsduState st;
        ParseFilter flt;
        const ParseResult r = parser.parse(in, st, flt);
        std::printf("[D] accept=%d pb_oks=%d msdu_present=%d summary=%s\n",
                    (int)r.accept, (int)r.mpdu.pb_crc_oks.size(), (int)r.msdu.present,
                    qPrintable(r.msdu.summary));
        CHECK(r.accept && r.mpdu.fch_crc_ok, "D1 好帧:FCH OK");
        CHECK(r.mpdu.pb_crc_oks.size() == 1 && r.mpdu.pb_crc_oks.at(0), "D2 好帧:PB 块 CRC OK");
        CHECK(r.msdu.present && r.msdu.summary.contains(QStringLiteral("应用层报文")),
              "D3 好帧:摘要与改前一致");
        CHECK(msdu_crc_state(r.msdu) == MsduCrcState::Ok, "D4 好帧:MSDU CRC OK");
        CHECK(!frame_crc_red(make_entry(r)), "D5 好帧:不标红");
    }

    // ===== C:PB OK + MSDU CRC FAIL ⇒ present=1、摘要空、只留 CRC 证据节点、标红 =====
    {
        QByteArray bad = inner;
        // 改 MSDU 数据区一个字节(避开帧尾 4B CRC32 自身),再重算 PB 块 CRC24
        // ⇒ PB OK + MSDU CRC FAIL(隔离出 MSDU 变量)
        const int body_off = g_block_start + 4;      // 块体起点 = 块起点 + 块头 4B
        bad[body_off + 80] = char(quint8(bad.at(body_off + 80)) ^ 0x5A);
        fix_pb_crc24(bad, g_block_start, g_pb_size);
        BplcFrame in;
        in.data = bad;
        NW_2021_Parser parser;
        MsduState st;
        ParseFilter flt;
        const ParseResult r = parser.parse(in, st, flt);
        std::printf("[C] pb_oks=%d msdu_present=%d summary='%s' tree_crc_nodes=%d\n",
                    (int)r.mpdu.pb_crc_oks.size(), (int)r.msdu.present,
                    qPrintable(r.msdu.summary), count_nodes(r.msdu.tree, QStringLiteral("MSDU CRC32")));
        CHECK(r.mpdu.pb_crc_oks.size() == 1 && r.mpdu.pb_crc_oks.at(0), "C1 PB 块 CRC OK(只为隔离 MSDU 变量)");
        CHECK(msdu_crc_state(r.msdu) == MsduCrcState::Fail, "C2 MSDU CRC32 FAIL");
        CHECK(r.msdu.present, "C3 present=1(有 MSDU,内容不可采信)");
        CHECK(r.msdu.summary.isEmpty(), "C4 摘要为空");
        CHECK(count_nodes(r.msdu.tree, QStringLiteral("MSDU CRC32")) == 1,
              "C5 字段树只留 MSDU CRC32 证据节点(1 个)");
        CHECK(node_value(r.msdu.tree, QStringLiteral("MSDU CRC32")).contains(QStringLiteral("FAIL")),
              "C6 证据节点值为 FAIL");
        CHECK(r.msdu.tree.size() == 1, "C7 字段树无其它节点");
        CHECK(frame_crc_red(make_entry(r)), "C8 行判红");
        CHECK(r.msdu.topo_event.kind == TopoEventKind::Other, "C9 坏载荷不产出拓扑事件");
    }

    // ===== E:FC(FCH)CRC FAIL ⇒ 仍然 DROP =====
    {
        QByteArray bad = inner;
        bad[g_block_start - 2] = char(quint8(bad.at(g_block_start - 2)) ^ 0xFF);   // 改 FCH 区(块前一字节)
        BplcFrame in;
        in.data = bad;
        NW_2021_Parser parser;
        MsduState st;
        ParseFilter flt;
        const ParseResult r = parser.parse(in, st, flt);
        std::printf("[E] accept=%d fch_checked=%d fch_ok=%d\n",
                    (int)r.accept, (int)r.mpdu.fch_crc_checked, (int)r.mpdu.fch_crc_ok);
        CHECK(!r.accept, "E1 FCH CRC FAIL ⇒ DROP(accept=0)");
        CHECK(!r.msdu.present && r.msdu.summary.isEmpty(), "E2 DROP 帧不解析 MSDU");
    }

    // ===== F:MSDU CRC 缺失(N-A)⇒ 维持现状解析、摘要照旧、不因缺失标红 =====
    {
        MsduInfo no_crc;
        no_crc.present = true;
        no_crc.summary = QStringLiteral("应用层报文 (BID=0x00 数据透传至设备 ↓)");
        MsduFieldNode n;
        n.name = QStringLiteral("APP Data");
        n.value = QStringLiteral("00 01 02");
        no_crc.tree.append(n);
        CHECK(msdu_crc_state(no_crc) == MsduCrcState::NotAvailable, "F1 无 CRC 节点 ⇒ 三态 N-A");
        const MsduInfo kept = msdu_crc_gate(no_crc);
        CHECK(!kept.summary.isEmpty() && kept.tree.size() == 1, "F2 N-A 原样返回(摘要/字段树不动)");

        MsduInfo missing;
        missing.present = true;
        missing.summary = QStringLiteral("应用层报文 (CRC 缺失)");
        MsduFieldNode m;
        m.name = QStringLiteral("MSDU CRC32");
        m.value = QStringLiteral("校验数据缺失（已有1/4字节）");
        missing.tree.append(m);
        CHECK(msdu_crc_state(missing) == MsduCrcState::NotAvailable, "F3 字节不足 ⇒ N-A");
        PacketEntry e;
        e.accepted = true;
        e.msdu = missing;
        e.mpdu.fch_crc_checked = true;
        e.mpdu.fch_crc_ok = true;
        CHECK(!frame_crc_red(e), "F4 N-A 不因 CRC 缺失标红");
    }

    // ===== G:国网侧(HDC2.0 表7 数据帧尾 4B CRC32)同款 C 场景 =====
    // 国网两条 MSDU 解析路径(gw_2022_msdu_parser / gw_2026_msdu_parser)末尾统一
    // `return msdu_crc_gate(out);`,与南网共用同一实现,故该场景与协议无关;
    // 这里用"国网形态字段树(节点名/值格式与 gw parser 输出一致)"断言收敛结果。
    // (仓库内 gw2026_ofdma_sim.bin 是 OFDMA/TDA 多站帧,帧级 msdu_body 为空,
    //  不适合做本断言,故不引入该 fixture。)
    {
        MsduInfo gw;
        gw.present = true;
        gw.summary = QStringLiteral("MMeDiscoverNodeList");
        gw.business_id = 0x02;
        gw.mme_type = 0x0001;
        MsduFieldNode head;
        head.name = QStringLiteral("MSDU Type");
        head.value = QStringLiteral("0x0001");
        MsduFieldNode crc;
        crc.name = QStringLiteral("MSDU CRC32");
        crc.value = QStringLiteral("0x12345678 FAIL");
        gw.tree.append(head);
        gw.tree.append(crc);
        const MsduInfo g2 = msdu_crc_gate(gw);
        std::printf("[G] gw-style: state=%d summary_empty=%d nodes=%d;",
                    (int)msdu_crc_state(gw), (int)g2.summary.isEmpty(), (int)g2.tree.size());
        std::puts("");
        CHECK(msdu_crc_state(gw) == MsduCrcState::Fail, "G1 国网:MSDU CRC32 FAIL 三态");
        CHECK(g2.summary.isEmpty(), "G2 国网:摘要为空");
        CHECK(g2.tree.size() == 1 && g2.tree.first().name == QStringLiteral("MSDU CRC32"),
              "G3 国网:字段树只留 CRC 证据节点");
        PacketEntry e;
        e.accepted = true;
        e.msdu = g2;
        e.mpdu.fch_crc_checked = true;
        e.mpdu.fch_crc_ok = true;
        CHECK(frame_crc_red(e), "G4 国网:行判红");
    }

    // ===== H:UI 层逐字断言(PacketListModel,基准 = 用户 v2.0.1 实拍 Info 行) =====
    {
        BplcFrame in;
        in.data = inner;
        NW_2021_Parser parser;
        MsduState st;
        ParseFilter flt;
        const ParseResult r = parser.parse(in, st, flt);

        PacketEntry e = make_entry(r);
        e.protocol  = kProtocolNw2021;
        e.meta      = r.meta;
        e.msdu_body = r.msdu_body;
        e.index     = 1;

        PacketListModel model;
        model.append_packet(e);

        const auto col_of = [&model](const QString& title) {
            for (int c = 0; c < model.columnCount(); ++c)
                if (model.headerData(c, Qt::Horizontal, Qt::DisplayRole).toString() == title)
                    return c;
            return -1;
        };
        const int c_info = col_of(QStringLiteral("Info"));
        const int c_msdu = col_of(QStringLiteral("MSDU Type"));
        CHECK(c_info >= 0 && c_msdu >= 0, "H1 找到 Info / MSDU Type 列");

        const QString info  = model.data(model.index(0, c_info)).toString();
        const QString msdu  = model.data(model.index(0, c_msdu)).toString();
        std::printf("[H] info=%s\n", qPrintable(info));
        std::printf("[H] msdu_type=%s\n", qPrintable(msdu));

        CHECK(info == QStringLiteral(
                  "NetID=0x00000F src=6 dst=10 MCS=2 PBNum=1 CRC FAIL(1/1) MSDU[128B]"),
              "H2 Info 列与用户 v2.0.1 实拍逐字一致");
        CHECK(r.msdu_body.size() == 128, "H3 msdu_body = 128B(Info 里 MSDU[128B] 的唯一来源)");
        // 方向位实测 = 1(表8 D15=1 上行)⇒ ↑;派单期望的 ↓ 与本帧方向位不符,已在报告中列出证据
        CHECK(msdu == QStringLiteral("应用层报文 (BID=0x03 站点间通信 ↑)"),
              "H4 MSDU Type 列 = 原摘要(方向按帧内 TransDirectionFlag 判定)");
        CHECK(!msdu.contains(QStringLiteral("STA-")) && !msdu.contains(QStringLiteral("[MAC")),
              "H5 MSDU Type 无多余主体后缀(未触发代理转发附加段)");
        const QVariant fg = model.data(model.index(0, c_info), Qt::ForegroundRole);
        CHECK(fg.value<QColor>() == QColor(224, 64, 64), "H6 ForegroundRole = QColor(224,64,64) 红行");
        CHECK(node_value(r.msdu.tree, QStringLiteral("MSDU CRC32")) == QStringLiteral("0x5d813887 OK"),
              "H7 字段树 MSDU CRC32 = 0x5d813887 OK");
        CHECK(msdu_crc_state(r.msdu) == MsduCrcState::Ok && frame_crc_red(e),
              "H8 行红来自 PB 块 CRC(MSDU CRC 本体 OK)");
    }

    // ===== W:反转义宽松(方案 A,用户 2026-11)reader 路径 =====
    {
        // W1:线上 wire 帧(766B,含 8 处非法 0x3D)⇒ 返回 true、还原 755B、n==8
        QFile wf(QStringLiteral(WIRE_FIXTURE));
        if (!wf.open(QIODevice::ReadOnly)) { CHECK(false, "W0 wire fixture 缺失"); }
        else {
            const QByteArray wire = wf.readAll();
            // 0x3E 定界在 wire[764];帧体 = [1, 764) 共 763B(去首尾哨兵)
            const QByteArray body = wire.mid(1, wire.size() - 3);
            QByteArray out;
            int n = -1;
            const bool ok = playback::unescape_frame_data(body, out, &n);
            std::printf("[W1] wire=%d esc=%d unesc=%d ok=%d n=%d\n",
                        (int)wire.size(), (int)body.size(), (int)out.size(), (int)ok, n);
            CHECK(ok, "W1a 返回 true(不再因非法 0x3D 判失败)");
            // 宽松语义:8 处非法 0x3D 保留为字面 '=',不缩长度 ⇒ 输出长度 = 帧体 763B
            CHECK(out.size() == 763, "W1b 宽松输出 763B(8 处非法 0x3D 保留为 '=')");
            CHECK(n == 8, "W1c 8 处非法 0x3D 全部计入 lenient_fixes");

            // W5:该 wire 走「反转义 → 真实 parser」后仍可解析出原摘要
            BplcFrame in;
            in.data = out;
            NW_2021_Parser parser;
            MsduState st;
            ParseFilter flt;
            const ParseResult r = parser.parse(in, st, flt);
            CHECK(r.accept && r.mpdu.fch_crc_checked && r.mpdu.fch_crc_ok, "W5a accept 且 FCH OK");
            CHECK(r.mpdu.pb_crc_oks.size() == 1 && !r.mpdu.pb_crc_oks.at(0), "W5b PB 块 CRC FAIL");
            CHECK(r.msdu.present && r.msdu.summary.contains(QStringLiteral("BID=0x03")),
                  "W5c MSDU 解析出原摘要");
            CHECK(node_value(r.msdu.tree, QStringLiteral("MSDU CRC32")) == QStringLiteral("0x5d813887 OK"),
                  "W5d 树 MSDU CRC32 = 0x5d813887 OK");
            PacketEntry e = make_entry(r);
            e.protocol  = kProtocolNw2021;
            e.meta      = r.meta;
            e.msdu_body = r.msdu_body;
            e.index     = 1;
            PacketListModel model;
            model.append_packet(e);
            const auto col_of = [&model](const QString& title) {
                for (int c = 0; c < model.columnCount(); ++c)
                    if (model.headerData(c, Qt::Horizontal, Qt::DisplayRole).toString() == title)
                        return c;
                return -1;
            };
            const int c_info = col_of(QStringLiteral("Info"));
            const QString info = c_info >= 0 ? model.data(model.index(0, c_info)).toString() : QString();
            std::printf("[W5] info=%s\n", qPrintable(info));
            CHECK(info == QStringLiteral(
                      "NetID=0x00000F src=6 dst=10 MCS=2 PBNum=1 CRC FAIL(1/1) MSDU[128B]"),
                  "W5e Info 列逐字一致");
            CHECK(frame_crc_red(e), "W5f 行红(PB 块 CRC 失败)");
            CHECK(n == 8 && r.accept, "W6 非法转义帧不再 DROP(进入解析且 accept=1)");

            // 交叉断言(缺陷2):探针 extract_frame 与生产 unescape 走同一实现,解出结果一致
            QByteArray buf2 = wire;
            QByteArray via_extract;
            extract_frame(buf2, via_extract);
            CHECK(via_extract == out, "R5 探针 extract_frame 与生产 unescape 结果一致(同一实现)");
        }

        // W2:合法转义不变(3D C1/C2/C3 → 3E/3D/3C,n==0)
        {
            const QByteArray esc = QByteArray::fromHex("3dc13dc23dc3");
            QByteArray out;
            int n = -1;
            const bool ok = playback::unescape_frame_data(esc, out, &n);
            CHECK(ok && n == 0 && out == QByteArray::fromHex("3e3d3c"),
                  "W2 合法转义 3D C1/C2/C3 还原为 3E/3D/3C 且 n==0");
        }
        // W3:悬空 0x3D 在末尾 ⇒ true、末尾为 0x3D、n==1
        {
            const QByteArray esc(1, char(0x3D));
            QByteArray out;
            int n = -1;
            const bool ok = playback::unescape_frame_data(esc, out, &n);
            CHECK(ok && n == 1 && out.size() == 1 && (quint8)out.at(0) == 0x3D,
                  "W3 悬空 0x3D 当普通数据、n==1");
        }
        // W4:无非法转义的普通帧 ⇒ 输出逐字节一致、n==0
        {
            const QByteArray esc = QByteArray::fromHex("0102033c3e5a");
            QByteArray out;
            int n = -1;
            const bool ok = playback::unescape_frame_data(esc, out, &n);
            CHECK(ok && n == 0 && out == esc, "W4 无 0x3D 帧逐字节一致、n==0");
        }
    }

    // ===== R:递归三态/裁剪(缺陷 1:嵌套 CRC 节点漏判) =====
    {
        const auto mk_crc = [](const char* val) {
            MsduFieldNode n;
            n.name = QStringLiteral("MSDU CRC32");
            n.value = QString::fromUtf8(val);
            n.rel_start = 100;
            n.rel_len = 4;
            return n;
        };
        // R1: 聚合帧分组下嵌套 FAIL
        {
            MsduInfo m;
            m.present = true;
            m.cascade = true;
            m.summary = QStringLiteral("聚合帧(1 帧: …)");
            MsduFieldNode grp;
            grp.name = QStringLiteral("Cascade MAC Frame[0]");
            grp.rel_start = 0;
            grp.rel_len = 200;
            grp.children.append(mk_crc("0xdeadbeef FAIL"));
            MsduFieldNode other;
            other.name = QStringLiteral("APP Data");
            other.value = QStringLiteral("…");
            grp.children.append(other);
            m.tree.append(grp);
            CHECK(msdu_crc_state(m) == MsduCrcState::Fail, "R1a 嵌套 FAIL ⇒ 三态 Fail");
            const MsduInfo ev = msdu_crc_fail_evidence(m);
            CHECK(ev.summary.isEmpty(), "R1b 摘要清空");
            CHECK(ev.tree.size() == 1 && ev.tree[0].name == QStringLiteral("Cascade MAC Frame[0]"),
                  "R1c 保留祖先分组");
            CHECK(ev.tree[0].children.size() == 1
                      && ev.tree[0].children[0].name == QStringLiteral("MSDU CRC32"),
                  "R1d 组下只有 CRC 节点");
            CHECK(ev.tree[0].children[0].rel_start == 100 && ev.tree[0].children[0].rel_len == 4,
                  "R1e rel_start/rel_len 原样保留");
            PacketEntry pe;
            pe.accepted = true;
            pe.msdu = m;
            pe.mpdu.fch_crc_checked = true;
            pe.mpdu.fch_crc_ok = true;
            CHECK(frame_crc_red(pe), "R1f 嵌套 FAIL 标红");
        }
        // R2: 嵌套 OK ⇒ Ok、不标红、不裁剪
        {
            MsduInfo m;
            m.present = true;
            m.summary = QStringLiteral("聚合帧(1 帧: …)");
            MsduFieldNode grp;
            grp.name = QStringLiteral("Cascade MAC Frame[0]");
            grp.children.append(mk_crc("0x5d813887 OK"));
            m.tree.append(grp);
            CHECK(msdu_crc_state(m) == MsduCrcState::Ok, "R2a 嵌套 OK ⇒ Ok");
            const MsduInfo g = msdu_crc_gate(m);
            CHECK(g.tree.size() == 1 && g.summary == m.summary, "R2b OK 不裁剪、摘要保留");
            PacketEntry pe;
            pe.accepted = true;
            pe.msdu = m;
            pe.mpdu.fch_crc_checked = true;
            pe.mpdu.fch_crc_ok = true;
            CHECK(!frame_crc_red(pe), "R2c OK 不标红");
        }
        // R3: 两层以上嵌套(分组里再套分组)
        {
            MsduInfo m;
            m.present = true;
            MsduFieldNode outer;
            outer.name = QStringLiteral("Cascade MAC Frame[1]");
            MsduFieldNode inner;
            inner.name = QStringLiteral("Inner Group");
            inner.children.append(mk_crc("0x00000000 FAIL"));
            outer.children.append(inner);
            m.tree.append(outer);
            CHECK(msdu_crc_state(m) == MsduCrcState::Fail, "R3a 两层嵌套 FAIL ⇒ Fail");
            const MsduInfo ev = msdu_crc_fail_evidence(m);
            CHECK(ev.tree.size() == 1 && ev.tree[0].children.size() == 1
                      && ev.tree[0].children[0].children.size() == 1,
                  "R3b 两层祖先分组均保留、组下仅 CRC 叶");
        }
        // R4: 无 CRC 节点 ⇒ N/A、不裁剪、不红
        {
            MsduInfo m;
            m.present = true;
            m.summary = QStringLiteral("MMeX");
            MsduFieldNode n;
            n.name = QStringLiteral("APP Data");
            n.value = QStringLiteral("01 02");
            m.tree.append(n);
            CHECK(msdu_crc_state(m) == MsduCrcState::NotAvailable, "R4a 无 CRC ⇒ N/A");
            const MsduInfo g = msdu_crc_gate(m);
            CHECK(g.tree.size() == 1 && g.summary == m.summary, "R4b N/A 不裁剪");
            PacketEntry pe;
            pe.accepted = true;
            pe.msdu = m;
            pe.mpdu.fch_crc_checked = true;
            pe.mpdu.fch_crc_ok = true;
            CHECK(!frame_crc_red(pe), "R4c N/A 不红");
        }
        // R6: 聚合帧两个级联分组,[0] 无 CRC 后代、[1] 挂 FAIL ⇒ gate 丢弃 [0]、[1] 只留 CRC
        {
            MsduInfo m;
            m.present = true;
            m.cascade = true;
            m.summary = QStringLiteral("聚合帧(2 帧: A, B)");
            MsduFieldNode g0;
            g0.name = QStringLiteral("Cascade MAC Frame[0]");
            g0.rel_start = 0;
            g0.rel_len = 50;
            MsduFieldNode plain;
            plain.name = QStringLiteral("APP Data");
            plain.value = QStringLiteral("aa bb");
            g0.children.append(plain);
            m.tree.append(g0);
            MsduFieldNode g1;
            g1.name = QStringLiteral("Cascade MAC Frame[1]");
            g1.rel_start = 52;
            g1.rel_len = 60;
            g1.children.append(mk_crc("0xdeadbeef FAIL"));
            m.tree.append(g1);
            CHECK(msdu_crc_state(m) == MsduCrcState::Fail, "R6a 聚合两级联[1] FAIL ⇒ Fail");
            const MsduInfo ev = msdu_crc_gate(m);
            CHECK(ev.summary.isEmpty(), "R6b 聚合摘要清空");
            CHECK(ev.tree.size() == 1
                      && ev.tree[0].name == QStringLiteral("Cascade MAC Frame[1]"),
                  "R6c 无 CRC 后代的 [0] 被丢弃、保留 [1]");
            CHECK(ev.tree[0].children.size() == 1
                      && ev.tree[0].children[0].name == QStringLiteral("MSDU CRC32"),
                  "R6d [1] 下只剩 CRC 证据节点");
            CHECK(ev.tree[0].children[0].rel_start == 100
                      && ev.tree[0].children[0].rel_len == 4,
                  "R6e rel_start/rel_len 未改动");
            PacketEntry pe;
            pe.accepted = true;
            pe.msdu = m;
            pe.mpdu.fch_crc_checked = true;
            pe.mpdu.fch_crc_ok = true;
            CHECK(frame_crc_red(pe), "R6f 聚合 FAIL 标红");
        }
        // R7: 聚合帧两个级联都 OK ⇒ Ok、摘要保留、树不裁剪
        {
            MsduInfo m;
            m.present = true;
            m.cascade = true;
            m.summary = QStringLiteral("聚合帧(2 帧: A, B)");
            MsduFieldNode g0;
            g0.name = QStringLiteral("Cascade MAC Frame[0]");
            g0.children.append(mk_crc("0x11111111 OK"));
            m.tree.append(g0);
            MsduFieldNode g1;
            g1.name = QStringLiteral("Cascade MAC Frame[1]");
            g1.children.append(mk_crc("0x22222222 OK"));
            m.tree.append(g1);
            CHECK(msdu_crc_state(m) == MsduCrcState::Ok, "R7a 聚合两级联都 OK ⇒ Ok");
            const MsduInfo g = msdu_crc_gate(m);
            CHECK(g.summary == m.summary && g.tree.size() == 2, "R7b 摘要保留、树不裁剪");
        }
    }

    std::printf(failures ? "RESULT: %d FAILURES\n" : "RESULT: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
