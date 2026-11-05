#include <QCoreApplication>
#include <QTextStream>
#include <cstdlib>
#include "nw_2021_msdu_parser.h"
#include "common/fieldtools.h"
#include "common/crc.h"
#include "i18n.h"
#include "protocol_tree_builder.h"

static int checks = 0;

static void check(bool ok, const QString& context) {
    ++checks;
    if (!ok) {
        QTextStream(stderr) << "FAIL: " << context << Qt::endl;
        std::exit(1);
    }
}

static void put(QByteArray& data, int offset, int bits, quint64 value) {
    check(offset >= 0 && offset + (bits + 7) / 8 <= data.size(), "fixture write bounds");
    set_bits(reinterpret_cast<quint8*>(data.data()), offset, 0, bits, value);
}

static QByteArray mme(quint16 type, int length) {
    QByteArray data(length, char(0));
    if (length > 0) data[0] = 1;
    if (length > 1) data[1] = char(type & 0xff);
    if (length > 2) data[2] = char(type >> 8);
    if (length > 3) data[3] = char(0xa1);
    if (length > 4) data[4] = char(0xb2);
    if (length > 5) data[5] = char(0xc3);
    return data;
}

static QByteArray frame(const QByteArray& mme_data) {
    QByteArray payload(18, char(0));
    payload.replace(0, 6, QByteArray::fromHex("102030405060"));
    payload.replace(6, 6, QByteArray::fromHex("aabbccddeeff"));
    put(payload, 12, 32, 0x8100);
    put(payload, 16, 16, 0x88e1);
    payload += mme_data;
    QByteArray header(32, char(0));
    header[0] = 2; // 标准帧、长 MAC 头
    put(header, 2, 16, quint64(payload.size()));
    QByteArray crc(4, char(0));
    put(crc, 0, 32, crc32_le(reinterpret_cast<const quint8*>(payload.constData()),
                            int(payload.size()) + 4));
    return header + payload + crc;
}

static const MsduFieldNode* node(const MsduInfo& info, const QString& name) {
    for (const auto& field : info.tree)
        if (field.name == name) return &field;
    return nullptr;
}

static void header_mappings(const MsduInfo& info, const QByteArray& raw) {
    for (const auto& field : info.tree) {
        if (!field.name.startsWith("Original ") && !field.name.startsWith("VLAN Tag")
            && !field.name.startsWith("MSDU Type") && !field.name.startsWith("MMe Version")
            && !field.name.startsWith("MMe Type") && field.name != "RSV [24b]"
            && field.name != "MSDU CRC32") continue;
        check(field.rel_len == 0 ? field.rel_start == -1
                                : field.rel_start >= 0 && field.rel_len > 0
                                  && field.rel_start + field.rel_len <= raw.size(),
              "header mapping never exceeds available bytes");
        for (int pb_size : {0, 136, 520}) {
            const MsduRawMap map{pb_size ? -1 : 100, 4, pb_size, 16, 4, pb_size - 8, {}};
            QTreeWidgetItem root;
            tree_render_msdu(&root, {field}, map, raw);
            const auto* item = root.child(0);
            check(item && item->text(0) == field.name && item->text(1) == field.value,
                  "rendered field retains its name/value");
            check(item->data(0, kRoleBytes).toByteArray() == raw.mid(field.rel_start, field.rel_len),
                  "rendered field copies only its actual bytes");
            const auto ranges = tree_msdu_raw_ranges(map, field.rel_start, field.rel_len);
            if (field.rel_len == 0) {
                check(!item->data(0, kRoleStart).isValid() && item->data(0, kRoleRanges).toList().isEmpty(),
                      "absent CRC has no highlight");
            } else {
                check(item->data(0, kRoleRanges).toList().size() == ranges.size(), "all PB highlight fragments retained");
                check(item->data(0, kRoleStart).toInt() == (pb_size ? 20 : 100) + field.rel_start,
                      "header first-byte raw mapping correct");
                int covered = 0;
                for (const auto& range : ranges) covered += range.second;
                check(covered == field.rel_len, "PB fragments cover exactly the available field");
            }
        }
    }
}

static void check_header(const MsduInfo& info, const QByteArray& data) {
    const auto* version = node(info, "MMe Version [8b]");
    const auto* type = node(info, "MMe Type [16b]");
    const auto* reserved = node(info, "RSV [24b]");
    const quint16 mm_type = quint16(get_bits(data, 1, 0, 16));
    check(info.mme_type == mm_type && version && type && reserved,
          "complete common header retained");
    check(version->rel_start == 50 && version->rel_len == 1 && version->value == "1"
          && type->rel_start == 51 && type->rel_len == 2
          && reserved->rel_start == 53 && reserved->rel_len == 3
          && reserved->value == "0xA1B2C3", "common header value/range unchanged");
}

static MsduInfo parse(const QByteArray& data) {
    const MsduInfo info = NW_2021_MsduParser::parse(frame(data));
    check(info.present, "outer MSDU declaration is complete");
    const auto* crc = node(info, "MSDU CRC32");
    check(crc && crc->value.endsWith("OK"), "CRC retained even for truncated MMe");
    if (data.size() >= 6) check_header(info, data);
    return info;
}

static void no_topology(const MsduInfo& info, const QString& context) {
    const auto& event = info.topo_event;
    check(event.kind == TopoEventKind::Other && event.nodes.isEmpty()
          && event.routes.isEmpty() && event.up_routes.isEmpty()
          && event.leaves.isEmpty() && event.comm_rates.isEmpty()
          && event.neighbor_teis.isEmpty() && event.discover_src_tei == 0
          && event.cco_mac == 0 && event.restart_count == -1
          && event.desc.isEmpty() && info.tei_mac_pairs.isEmpty(),
          "no partial topology or TEI/MAC learning: " + context);
}

static void truncated(const QByteArray& data) {
    const auto info = parse(data);
    const QString context = QString("type=0x%1 length=%2")
        .arg(data.size() >= 3 ? get_bits(data, 1, 0, 16) : 0, 4, 16, QChar('0'))
        .arg(data.size());
    check(info.summary.endsWith(" (截断)"), "truncation marked: " + context);
    no_topology(info, context);
}

static void unsupported_version(const QByteArray& data) {
    const auto info = NW_2021_MsduParser::parse(frame(data));
    const auto* version = node(info, "MMe Version [8b]");
    check(info.present && version && version->rel_start == 50 && version->rel_len == 1
          && version->value.startsWith(QString::number(quint8(data[0])) + " - "),
          "unsupported MMe version displayed as unsigned with original range");
    // 合并 MAC 头分支后树多出 "MAC Header" 段根节点(其字段为子节点),总数 8 -> 9;
    // 断言意图不变:不支持版本时仅保留公共头与 CRC,不解释报文体
    check(info.summary.contains("不支持的 MMe 版本") && info.tree.size() == 9,
          "unsupported version retains common header and CRC only");
    no_topology(info, "unsupported MMe version");
}

static MsduInfo complete(const QByteArray& data) {
    const auto info = parse(data);
    check(!info.summary.contains("截断"), "complete MMe accepted");
    return info;
}

static void all_prefixes(const QByteArray& data) {
    for (int length = 0; length < data.size(); ++length)
        truncated(data.left(length));
    complete(data);
}

static QByteArray vlan_frame(bool short_head, quint32 vlan, quint16 type,
                             const QByteArray& data = QByteArray(12, char(0))) {
    QByteArray payload(short_head ? 2 : 18, char(0));
    put(payload, short_head ? 0 : 12, short_head ? 8 : 32, vlan);
    put(payload, short_head ? 1 : 16, short_head ? 8 : 16, type);
    payload += data;
    QByteArray header(short_head ? 12 : 32, char(0));
    header[0] = short_head ? 3 : 2;
    put(header, 2, 16, quint64(payload.size()));
    QByteArray crc(4, char(0));
    put(crc, 0, 32, crc32_le(reinterpret_cast<const quint8*>(payload.constData()),
                            int(payload.size()) + 4));
    return header + payload + crc;
}

static void check_vlan(bool short_head, quint32 vlan, quint16 type, bool english) {
    const auto info = NW_2021_MsduParser::parse(vlan_frame(short_head, vlan, type));
    const auto* field = node(info, short_head ? "VLAN Tag [8b]" : "VLAN Tag [32b]");
    check(info.present && field && info.vlan_tag == vlan && info.msdu_type == type,
          "VLAN and MSDU Type retained for long/short header");
    QString meaning;
    if (type == 1 && vlan <= 3) {
        meaning = english
            ? QString("Meter reading/data subscription application, LID (priority)=%1").arg(vlan)
            : QString("抄表/数据订阅应用，LID（优先级）=%1").arg(vlan);
    } else if (type == 0x88e1 && vlan == 0x8100) {
        meaning = english
            ? "Network management packet, LID (priority)=0-255 (implementation-defined)"
            : "网络管理报文，LID（优先级）=0-255（实现自定义）";
    } else {
        meaning = english ? "Undefined VLAN/MSDU Type combination" : "未定义的VLAN/MSDU Type组合";
    }
    check(field->value == QString("0x%1 - %2").arg(vlan, short_head ? 2 : 8, 16, QChar('0')).arg(meaning),
          "VLAN meaning follows table 98 in both languages");
    check(field->rel_start == (short_head ? 12 : 44) && field->rel_len == (short_head ? 1 : 4),
          "VLAN highlight range covers only its raw bytes");
    const auto* type_field = node(info, short_head ? "MSDU Type [8b]" : "MSDU Type [16b]");
    check(type_field && type_field->rel_start == (short_head ? 13 : 48)
          && type_field->rel_len == (short_head ? 1 : 2), "MSDU Type highlight unchanged");
    const auto* crc = node(info, "MSDU CRC32");
    check(crc && crc->value.endsWith("OK"), "VLAN display preserves CRC parsing");
    // 分发用 VLAN+MSDU类型 双条件(表98/8.2.13):仅 VLAN=0x8100 且 类型=0x88E1 走 MMe
    const bool is_mme = !short_head && vlan == 0x8100 && type == 0x88e1;
    // 摘要是双语的:en "MMe ..." / "APP ..." 现改为 "Application Layer Packet ...";
    // zh "MMe ..." / "应用报文 ..." 现改为 "应用层报文 ..."(表9 批次统一了应用层文案)。
    // 本断言只关心"分发到 APP 而不是 MMe",文案前缀不是被测契约 ⇒ 新旧前缀都接受。
    const bool app_sum = english
        ? (info.summary.startsWith("APP") || info.summary.startsWith("Application Layer Packet"))
        : (info.summary.startsWith("应用报文") || info.summary.startsWith("应用层报文"));
    const bool ok_sum = is_mme ? info.summary.startsWith("MMe") : app_sum;
    check(ok_sum, "VLAN+type double condition controls payload dispatch (表98)");
}

static void vlan_tests() {
    for (bool english : {false, true}) {
        trl::set_enabled(english);
        for (quint32 vlan : {0u, 1u, 2u, 3u, 4u, 0x8100u, 0x10000u, 0x81000000u, 0xffffffffu})
            for (quint16 type : {1, 0x88e1, 0x1234})
                check_vlan(false, vlan, type, english);
        for (quint32 vlan = 0; vlan <= 255; ++vlan)
            for (quint16 type : {0, 1, 2, 255})
                check_vlan(true, vlan, type, english);
    }
    trl::set_enabled(false);
    const auto management = NW_2021_MsduParser::parse(vlan_frame(false, 0x8100, 0x88e1, mme(0x0031, 50)));
    check(management.topo_event.kind == TopoEventKind::AssocCnf, "VLAN meaning preserves complete MMe topology");
    const auto minimal = NW_2021_MsduParser::parse(vlan_frame(true, 3, 1, QByteArray()));
    check(node(minimal, "VLAN Tag [8b]") && minimal.summary.endsWith("(截断)"),
          "complete short VLAN shown even when APP is truncated");
    QByteArray partial(13, char(0));
    partial[0] = 3;
    put(partial, 2, 16, 1);
    const auto missing_type = NW_2021_MsduParser::parse(partial);
    check(!node(missing_type, "VLAN Tag [8b]"), "incomplete short header does not invent a VLAN meaning");
    QByteArray single_hop(4, char(0));
    single_hop[0] = 4;  // Version(bit1-2)=2:南网单跳帧协议(第2部分 §8.1.2.4 表113,4B 帧头)
    const auto simple = NW_2021_MsduParser::parse(single_hop);
    check(simple.present && simple.simple_head,
          "version 2 = NW single-hop protocol (表113): stub parsed as single-hop (MSDU absent)");
    QByteArray app(12, char(0));
    app[0] = 0x11;
    put(app, 1, 16, 0x0101);
    for (bool short_head : {false, true}) {
        const auto raw = vlan_frame(short_head, 3, 1, app);
        const auto info = NW_2021_MsduParser::parse(raw);
        const auto* cci = node(info, "Channel Control Info [4B]");
        check(cci && cci->children.size() >= 2 && cci->children[0].value.startsWith("0x11 - ")
              && cci->children[1].value.startsWith("0x0101 - "), "APP group annotations survive tree growth");
        header_mappings(info, raw);
    }
}

static void diagnostic_tests() {
    for (int version : {0, 1, 2, 255}) {
        for (int length = 0; length <= 6; ++length) {
            auto data = mme(0x0031, length);
            if (length) data[0] = char(version);
            const auto raw = frame(data);
            const auto info = NW_2021_MsduParser::parse(raw);
            const auto* mv = node(info, "MMe Version [8b]");
            const auto* mt = node(info, "MMe Type [16b]");
            const auto* rsv = node(info, "RSV [24b]");
            check(bool(mv) == (length >= 1) && bool(mt) == (length >= 2)
                  && bool(rsv) == (length >= 4), "only available common header bytes displayed");
            if (mv) check(mv->value.startsWith(QString::number(version)), "available version byte stays unsigned");
            if (mt) check(mt->rel_len == qMin(2, length - 1)
                          && (length >= 3 ? mt->value == "0x0031 - 关联确认" : mt->value == "0x??31 (truncated)"),
                          "partial type does not invent its missing high byte");
            if (rsv) check(rsv->rel_len == qMin(3, length - 3)
                           && rsv->value.contains("truncated") == (length < 6), "partial RSV explicitly marked");
            if (length < 6) check(info.summary.endsWith(" (截断)"), "incomplete common header marked truncated");
            no_topology(info, "incomplete/unsupported common header");
            header_mappings(info, raw);
        }
    }
    auto unknown_version = mme(0x9999, 6);
    unknown_version[0] = char(255);
    unsupported_version(unknown_version);
    trl::set_enabled(true);
    const auto english = NW_2021_MsduParser::parse(frame(unknown_version));
    check(node(english, "MMe Version [8b]")->value.contains("Unsupported"), "unsupported version translated");
    trl::set_enabled(false);

    const auto full = frame(mme(0x0031, 50));
    // 第三种帧形取长头应用帧(原单跳 Version=2 帧形已摘除:单跳简头是国网帧型,南网不解析)
    for (const auto& raw : {full, vlan_frame(true, 3, 1), vlan_frame(false, 3, 1)}) {
        for (int available = 0; available <= 4; ++available) {
            const auto partial = raw.left(raw.size() - 4 + available);
            const auto info = NW_2021_MsduParser::parse(partial);
            const auto* crc = node(info, "MSDU CRC32");
            check(info.present && crc && crc->rel_start == (available ? raw.size() - 4 : -1) && crc->rel_len == available,
                  "CRC presence/absence retains parsed MSDU with exact byte range");
            check(info.summary.contains("CRC 缺失") == (available < 4), "missing CRC explicit in summary");
            check(available == 4 ? crc->value.endsWith("OK")
                                : crc->value == QString("校验数据缺失（已有%1/4字节）").arg(available),
                  "CRC missing never appears as OK/FAIL");
            header_mappings(info, partial);
        }
        auto corrupt = raw;
        corrupt[corrupt.size() - 1] = char(quint8(corrupt.back()) ^ 0x01);
        const auto info = NW_2021_MsduParser::parse(corrupt);
        check(node(info, "MSDU CRC32")->value.endsWith("FAIL") && !info.summary.contains("CRC 缺失"),
              "bad complete CRC remains distinct from missing CRC");
    }
    trl::set_enabled(true);
    const auto no_crc = NW_2021_MsduParser::parse(full.left(full.size() - 4));
    check(node(no_crc, "MSDU CRC32")->value == "CRC data missing (0/4 bytes available)", "missing CRC translated");
    trl::set_enabled(false);
    const auto crossing = frame(mme(0x0031, 76));
    const auto crossing_info = NW_2021_MsduParser::parse(crossing);
    QTreeWidgetItem root;
    const MsduRawMap map{-1, 2, 136, 16, 4, 128, {}};
    tree_render_msdu(&root, {*node(crossing_info, "MSDU CRC32")}, map, crossing);
    const auto fragments = root.child(0)->data(0, kRoleRanges).toList();
    check(fragments.size() == 2 && fragments[0].toList() == QVariantList({146, 2})
          && fragments[1].toList() == QVariantList({156, 2})
          && root.child(0)->data(0, kRoleBytes).toByteArray() == crossing.mid(126, 4),
          "CRC across PB boundary has two exact highlight/copy fragments");
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    struct FixedCase { quint16 type; int minimum; TopoEventKind kind; };
    const FixedCase fixed[] = {
        {0x0030, 74, TopoEventKind::AssocReq},
        {0x0031, 50, TopoEventKind::AssocCnf},
        {0x0032, 46, TopoEventKind::Other},
        {0x0034, 78, TopoEventKind::AssocInd},
        {0x0037, 38, TopoEventKind::ChangeProxyCnf},
        {0x003a, 34, TopoEventKind::AssocGatherInd},
        {0x003b, 145, TopoEventKind::ChangeProxyCnf},
        {0x0049, 26, TopoEventKind::LeaveInd},
        {0x0051, 145, TopoEventKind::Other},
        {0x0055, 176, TopoEventKind::DiscoverList},
        {0x005d, 22, TopoEventKind::LeaveInd},
        {0x005e, 10, TopoEventKind::SuccessRate},
        {0x0062, 11, TopoEventKind::Other},
        {0x0063, 14, TopoEventKind::Other},
        {0x0064, 8, TopoEventKind::Other},
    };
    for (const auto& test : fixed) {
        for (int version : {0, 2, 255}) {
            for (int length : {6, test.minimum}) {
                auto data = mme(test.type, length);
                data[0] = char(version);
                unsupported_version(data);
            }
        }
        all_prefixes(mme(test.type, test.minimum));
        const auto info = complete(mme(test.type, test.minimum));
        check(info.topo_event.kind == test.kind, "valid topology classification unchanged");
        complete(mme(test.type, test.minimum + 1));
    }

    struct ListCase { quint16 type; int base; int count_offset; int count_bits; int item_size; };
    const ListCase lists[] = {
        {0x0031, 50, 42, 16, 2},
        {0x0034, 78, 70, 16, 2},
        {0x0037, 38, 16, 16, 2},
        {0x003a, 34, 17, 8, 8},
        {0x0055, 176, 30, 16, 1},
        {0x005d, 22, 8, 16, 6},
        {0x005e, 10, 8, 16, 4},
    };
    for (const auto& test : lists) {
        auto data = mme(test.type, test.base + 2 * test.item_size);
        put(data, test.count_offset, test.count_bits, 2);
        all_prefixes(data);
        put(data, test.count_offset, test.count_bits, 3);
        truncated(data); // 已存在完整条目也不得部分更新拓扑
        put(data, test.count_offset, test.count_bits, test.count_bits == 8 ? 255 : 65535);
        truncated(data);
    }

    // 两个 PCO 的嵌套路由:第二个子列表不足时,不得保留第一个事件。
    auto routes = mme(0x0031, 64);
    put(routes, 42, 16, 1);
    put(routes, 44, 16, 2);
    put(routes, 50, 16, 7);
    put(routes, 52, 16, 8);
    put(routes, 54, 16, 2);
    put(routes, 56, 16, 9);
    put(routes, 58, 16, 10);
    put(routes, 60, 16, 11);
    put(routes, 62, 16, 0);
    all_prefixes(routes);
    put(routes, 62, 16, 1);
    truncated(routes);
    routes.append(QByteArray(2, char(0)));
    put(routes, 64, 16, 12);
    all_prefixes(routes);
    put(routes, 62, 16, 65535);
    truncated(routes);
    auto missing_pco = mme(0x0031, 50);
    put(missing_pco, 44, 16, 65535);
    truncated(missing_pco);

    // 关联指示的嵌套路由与关联确认同构(计数在 70/72,条目自 78 起):
    // 第二个 PCO 的子列表不足时,同样不得保留部分拓扑。
    auto ind_routes = mme(0x0034, 92);
    put(ind_routes, 70, 16, 1);
    put(ind_routes, 72, 16, 2);
    put(ind_routes, 78, 16, 7);
    put(ind_routes, 80, 16, 8);
    put(ind_routes, 82, 16, 2);
    put(ind_routes, 84, 16, 9);
    put(ind_routes, 86, 16, 10);
    put(ind_routes, 88, 16, 11);
    put(ind_routes, 90, 16, 0);
    all_prefixes(ind_routes);
    put(ind_routes, 90, 16, 1);
    truncated(ind_routes);
    ind_routes.append(QByteArray(2, char(0)));
    put(ind_routes, 92, 16, 12);
    all_prefixes(ind_routes);
    put(ind_routes, 90, 16, 65535);
    truncated(ind_routes);
    auto ind_missing_pco = mme(0x0034, 78);
    put(ind_missing_pco, 72, 16, 65535);
    truncated(ind_missing_pco);

    // 位图版代理变更确认:本体 145B(位图完整)即可解析,尾部字段
    // (保留/端到端/路径序列号,至 154B)缺失时警告而非按截断处理。
    for (int len = 145; len < 154; ++len) {
        const auto info = parse(mme(0x003b, len));
        check(info.summary.contains("字段缺失") && !info.summary.contains("截断"),
              "bitmap body complete but tail fields missing warns");
        check(info.topo_event.kind == TopoEventKind::ChangeProxyCnf,
              "bitmap topo retained when tail fields missing");
    }
    check(!complete(mme(0x003b, 154)).summary.contains("字段缺失"),
          "full bitmap frame has no missing-field warning");

    auto gather = mme(0x003a, 50);
    put(gather, 14, 16, 3);
    put(gather, 17, 8, 2);
    put(gather, 34, 48, 0x112233445566);
    put(gather, 40, 12, 5);
    put(gather, 42, 48, 0x223344556677);
    put(gather, 48, 12, 6);
    all_prefixes(gather);
    const auto gathered = complete(gather);
    check(gathered.topo_event.nodes.size() == 2 && gathered.topo_event.routes.size() == 2,
          "complete association list keeps both nodes/routes");
    put(gather, 17, 8, 3);
    truncated(gather);

    auto discover = mme(0x0055, 185);
    put(discover, 6, 16, 5);
    put(discover, 10, 48, 0x112233445566);
    put(discover, 30, 16, 3);
    put(discover, 34, 16, 2);
    put(discover, 48, 12, 1);
    put(discover, 50, 8, 3);
    put(discover, 51, 12, 2);
    put(discover, 53, 8, 3);
    put(discover, 54, 8, 0x0e);
    all_prefixes(discover);
    const auto discovered = complete(discover);
    check(discovered.topo_event.up_routes.size() == 2
          && discovered.topo_event.neighbor_teis.size() == 3
          && discovered.tei_mac_pairs.size() == 1,
          "complete discovery retains routes/neighbors/TEI-MAC learning");
    put(discover, 34, 16, 65535);
    truncated(discover);

    // 过零上报(表87/88):上报数量在 mme 字节 8(含基准 NTB),差值自字节 14 起 12 位紧凑打包
    auto zc = mme(0x0063, 19);
    put(zc, 8, 8, 4);  // 数量 4 = 基准 + 3 个差值,需 14 + ceil(3*12/8) = 19 字节
    all_prefixes(zc);
    auto zc_cut = mme(0x0063, 18);
    put(zc_cut, 8, 8, 4);
    truncated(zc_cut);
    auto zc_big = mme(0x0063, 19);
    put(zc_big, 8, 8, 255);
    truncated(zc_big);

    for (int length = 0; length < 6; ++length) truncated(mme(0x9999, length));
    const auto unknown = complete(mme(0x9999, 6));
    check(unknown.topo_event.kind == TopoEventKind::Other, "unknown MMe stays non-topological");
    complete(mme(0x9999, 7));
    const auto full_frame = frame(mme(0x0031, 50));
    for (int length = 0; length < full_frame.size() - 4; ++length) {
        const auto info = NW_2021_MsduParser::parse(full_frame.left(length));
        check(!info.present && info.topo_event.kind == TopoEventKind::Other,
              "physically truncated outer MSDU rejected");
    }
    vlan_tests();
    diagnostic_tests();
    QTextStream(stdout) << "PASS: " << checks << " NW MMe/VLAN checks" << Qt::endl;
    return 0;
}
