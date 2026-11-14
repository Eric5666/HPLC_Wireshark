/// @file plugin_serialization.cpp
/// @brief 插件 IPC 用 QDataStream 序列化实现
#include "plugin_serialization.h"
#include "packetentry_serialize.h"   // pser::kMaxFieldDepth(盘块字段树同一深度语义)

#include <QBuffer>
#include <QIODevice>
#include <QImage>
#include <utility>

// ---- 反序列化防护(载荷来自插件宿主进程,不可信) ----
// Qt 默认的容器 operator>>(readArrayBasedContainer)对流里读出的计数直接 reserve(n),
// 只拒负数/溢出:恶意插件在 1 MiB 帧里声明 0xFFFFFFFD 个元素即可让主程序
// bad_alloc / 数 GB 分配。字段树递归无深度上限,深层嵌套帧可致栈溢出。
// 这里所有容器改为自读:先读计数,按剩余字节 × 每元素最小线上字节校验,
// 小步 reserve 后逐个 append;任何超限置 ReadCorruptData,调用方据 status() 判协议错误。
// 线上布局与 Qt 默认写出的完全一致(quint32 计数 + 元素),写端不变。
namespace {

/// 字段树单次读取(一棵顶层树/一个字段列表)的节点总数上限
constexpr int kMaxTreeNodes = 10000;
/// 逐个 append 前最多预留的元素数(计数已按剩余字节校验,仍不按大值预分配)
constexpr quint32 kReserveStep = 1024;

/// 流中剩余可读字节(IPC 帧为 QBuffer;顺序设备退回 bytesAvailable)
quint64 remaining_bytes(QDataStream& in) {
    QIODevice* d = in.device();
    if (!d) return 0;
    const qint64 left = d->isSequential() ? d->bytesAvailable() : d->size() - d->pos();
    return left > 0 ? quint64(left) : 0;
}

/// 读容器计数并校验:Qt_6_5 布局下计数恒 < 0xFFFFFFFE(NullCode/ExtendedSize 不会出现),
/// 且 n 个元素至少要 n × min_elem 字节;否则置 ReadCorruptData、返回 false
bool read_count(QDataStream& in, quint32& n, quint32 min_elem) {
    n = 0;
    if (in.status() != QDataStream::Ok) return false;
    in >> n;
    if (in.status() != QDataStream::Ok) { n = 0; return false; }
    if (n >= 0xFFFFFFFEu || quint64(n) * qMax<quint32>(min_elem, 1) > remaining_bytes(in)) {
        n = 0;
        in.setStatus(QDataStream::ReadCorruptData);
        return false;
    }
    return true;
}

/// 通用顺序容器读取:read_one 读单个元素;流出错即清空容器返回(不接受半个容器)
template <typename C, typename F>
void read_seq(QDataStream& in, C& c, quint32 min_elem, F&& read_one) {
    c.clear();
    quint32 n = 0;
    if (!read_count(in, n, min_elem)) return;
    c.reserve(qsizetype(qMin(n, kReserveStep)));
    for (quint32 i = 0; i < n; ++i) {
        typename C::value_type v{};
        read_one(in, v);
        if (in.status() != QDataStream::Ok) { c.clear(); return; }
        c.append(std::move(v));
    }
}

/// 定长标量元素(线上字节 = sizeof:quint8/bool/quint16/quint32/quint64)
template <typename C>
void read_scalar_seq(QDataStream& in, C& c) {
    using T = typename C::value_type;
    static_assert(sizeof(T) <= 8, "scalar only");
    read_seq(in, c, quint32(sizeof(T)), [](QDataStream& s, T& v) { s >> v; });
}

/// QPair<quint16, quint16> 列表(路由/上行路由,4 字节/项)
void read_u16_pairs(QDataStream& in, QVector<QPair<quint16, quint16>>& c) {
    read_seq(in, c, 4, [](QDataStream& s, QPair<quint16, quint16>& v) { s >> v.first >> v.second; });
}

// 字段树单元素最小线上字节:name(4) + value(4) + 子节点计数(4) + 其余定长字段
constexpr quint32 kMinFieldNodeBytes = 4 + 4 + 4 + 4 + 4;           // + rel_start + rel_len
constexpr quint32 kMinDissectFieldBytes = 4 + 4 + 4 + 4 + 1 + 4;    // + start + len + severity

struct TreeBudget { int nodes = 0; };

/// 进入一个节点:深度达 pser::kMaxFieldDepth(64 层)或节点数超 kMaxTreeNodes ⇒ 损坏
bool enter_node(QDataStream& in, int depth, TreeBudget& b) {
    if (in.status() != QDataStream::Ok) return false;
    if (depth >= pser::kMaxFieldDepth || ++b.nodes > kMaxTreeNodes) {
        in.setStatus(QDataStream::ReadCorruptData);
        return false;
    }
    return true;
}

void read_field_node(QDataStream& in, MsduFieldNode& n, int depth, TreeBudget& b) {
    if (!enter_node(in, depth, b)) return;
    in >> n.name >> n.value;
    read_seq(in, n.children, kMinFieldNodeBytes,
             [&](QDataStream& s, MsduFieldNode& c) { read_field_node(s, c, depth + 1, b); });
    in >> n.rel_start >> n.rel_len;
}

void read_field_tree(QDataStream& in, QVector<MsduFieldNode>& tree) {
    TreeBudget b;
    read_seq(in, tree, kMinFieldNodeBytes,
             [&](QDataStream& s, MsduFieldNode& c) { read_field_node(s, c, 0, b); });
}

void read_dissect_field(QDataStream& in, DissectField& f, int depth, TreeBudget& b) {
    if (!enter_node(in, depth, b)) return;
    in >> f.name >> f.value >> f.start >> f.len >> f.severity;
    read_seq(in, f.children, kMinDissectFieldBytes,
             [&](QDataStream& s, DissectField& c) { read_dissect_field(s, c, depth + 1, b); });
}

void read_dissect_list(QDataStream& in, QVector<DissectField>& list) {
    TreeBudget b;
    read_seq(in, list, kMinDissectFieldBytes,
             [&](QDataStream& s, DissectField& c) { read_dissect_field(s, c, 0, b); });
}

void read_tei_mac_pairs(QDataStream& in, QVector<TeiMacPair>& c) {
    read_seq(in, c, 2 + 8, [](QDataStream& s, TeiMacPair& p) { s >> p.tei >> p.mac; });
}

}  // namespace

// ---- PhysicalMeta ----
QDataStream& operator<<(QDataStream& out, const PhysicalMeta& m) {
    out << m.timestamp << m.phr_mcs << m.option << m.channel << m.is_rf;
    return out;
}
QDataStream& operator>>(QDataStream& in, PhysicalMeta& m) {
    in >> m.timestamp >> m.phr_mcs >> m.option >> m.channel >> m.is_rf;
    return in;
}

// ---- BplcFrame ----
QDataStream& operator<<(QDataStream& out, const BplcFrame& f) {
    out << f.meta << f.data << f.error_reason
        << f.arrival_us << f.raw_wire
        << f.decoded_index << f.decoded_epoch_ms << f.topo_event
        << f.accepted << f.mpdu << f.msdu_summary << f.msdu_present;
    return out;
}
QDataStream& operator>>(QDataStream& in, BplcFrame& f) {
    in >> f.meta >> f.data >> f.error_reason
       >> f.arrival_us >> f.raw_wire
       >> f.decoded_index >> f.decoded_epoch_ms >> f.topo_event
       >> f.accepted >> f.mpdu >> f.msdu_summary >> f.msdu_present;
    return in;
}

// ---- MsduState ----
QDataStream& operator<<(QDataStream& out, const MsduState& s) {
    out << s.buffer << s.received_count << s.expected_len << s.complete;
    return out;
}
QDataStream& operator>>(QDataStream& in, MsduState& s) {
    in >> s.buffer >> s.received_count >> s.expected_len >> s.complete;
    return in;
}

// ---- ParseFilter ----
QDataStream& operator<<(QDataStream& out, const ParseFilter& f) {
    out << f.enable_type_filter << f.allow_beacon << f.allow_sof << f.allow_ack
        << f.allow_coord << f.link_hplc << f.link_hrf
        << f.nid_filter << f.nid_mask << f.nid_list
        << f.tei_filter << f.tei_list;
    return out;
}
QDataStream& operator>>(QDataStream& in, ParseFilter& f) {
    in >> f.enable_type_filter >> f.allow_beacon >> f.allow_sof >> f.allow_ack
       >> f.allow_coord >> f.link_hplc >> f.link_hrf
       >> f.nid_filter >> f.nid_mask;
    read_scalar_seq(in, f.nid_list);
    in >> f.tei_filter;
    read_scalar_seq(in, f.tei_list);
    return in;
}

// ---- MpduInfo ----
QDataStream& operator<<(QDataStream& out, const MpduInfo& m) {
    out << m.frame_type << m.net_type << m.net_id << m.version
        << m.src_tei << m.dst_tei << m.link_id << m.frame_len
        << m.pb_num << m.symbol_num
        << m.bc_flag << m.re_send_flag << m.encryp_flag
        << m.tmi << m.tmi_ext << m.pb_size
        << m.fch_crc_ok << m.pb_crc_ok << m.pb_head
        << m.pb_heads << m.pb_crc_oks
        << m.beacon_timestamp << m.beacon_line
        << m.beacon_type << m.beacon_netsn << m.beacon_cco_mac
        << m.beacon_period_cnt << m.beacon_rf_channel << m.beacon_rf_option
        << m.beacon_item_num
        << m.coord_duration << m.coord_shift << m.coord_neighbour_nid
        << m.coord_rf_channel << m.coord_rsv0 << m.coord_rsv1
        << m.coord_rsv2 << m.coord_rsv3
        << m.coord_band_end_flag
        << m.coord_band_end_offset << m.coord_band_start_offset
        << m.ack_ext_type << m.ack_rx_res << m.ack_rx_status << m.ack_rx_pb_num
        << m.ack_rsv0 << m.ack_channel_quality << m.ack_sta_load << m.ack_rsv1
        << m.ack_dst_addr
        << m.ack_search_tei
        << m.ack_sync_timestamp << m.ack_sync_tei
        << m.pb_num_field    // v3 新增字段(追加末尾,见 plugin_ipc::kWireFormatVersion)
        << m.beacon_rsv      // v4 新增字段(信标保留原始值,见 plugin_ipc::kWireFormatVersion)
        << m.pblen           // v5 新增字段(南网无线载荷PB大小索引,见 plugin_ipc::kWireFormatVersion)
        << m.mcs;            // v6 新增字段(无线 MCS,见 plugin_ipc::kWireFormatVersion)
    return out;
}
QDataStream& operator>>(QDataStream& in, MpduInfo& m) {
    in >> m.frame_type >> m.net_type >> m.net_id >> m.version
       >> m.src_tei >> m.dst_tei >> m.link_id >> m.frame_len
       >> m.pb_num >> m.symbol_num
       >> m.bc_flag >> m.re_send_flag >> m.encryp_flag
       >> m.tmi >> m.tmi_ext >> m.pb_size
       >> m.fch_crc_ok >> m.pb_crc_ok >> m.pb_head;
    read_scalar_seq(in, m.pb_heads);
    read_scalar_seq(in, m.pb_crc_oks);
    in >> m.beacon_timestamp >> m.beacon_line
       >> m.beacon_type >> m.beacon_netsn >> m.beacon_cco_mac
       >> m.beacon_period_cnt >> m.beacon_rf_channel >> m.beacon_rf_option
       >> m.beacon_item_num
       >> m.coord_duration >> m.coord_shift >> m.coord_neighbour_nid
       >> m.coord_rf_channel >> m.coord_rsv0 >> m.coord_rsv1
       >> m.coord_rsv2 >> m.coord_rsv3
       >> m.coord_band_end_flag
       >> m.coord_band_end_offset >> m.coord_band_start_offset
       >> m.ack_ext_type >> m.ack_rx_res >> m.ack_rx_status >> m.ack_rx_pb_num
       >> m.ack_rsv0 >> m.ack_channel_quality >> m.ack_sta_load >> m.ack_rsv1
       >> m.ack_dst_addr
       >> m.ack_search_tei
       >> m.ack_sync_timestamp >> m.ack_sync_tei
       >> m.pb_num_field
       >> m.beacon_rsv
       >> m.pblen
       >> m.mcs;
    return in;
}

// ---- MsduFieldNode (递归) ----
QDataStream& operator<<(QDataStream& out, const MsduFieldNode& n) {
    out << n.name << n.value << n.children << n.rel_start << n.rel_len;
    return out;
}
QDataStream& operator>>(QDataStream& in, MsduFieldNode& n) {
    TreeBudget b;   // 单独读一个节点:深度/节点数上限同顶层树
    read_field_node(in, n, 0, b);
    return in;
}

// ---- TeiMacPair ----
QDataStream& operator<<(QDataStream& out, const TeiMacPair& p) {
    out << p.tei << p.mac;
    return out;
}
QDataStream& operator>>(QDataStream& in, TeiMacPair& p) {
    in >> p.tei >> p.mac;
    return in;
}

// ---- CommRateInfo ----
QDataStream& operator<<(QDataStream& out, const CommRateInfo& c) {
    out << c.tei << c.down << c.up;
    return out;
}
QDataStream& operator>>(QDataStream& in, CommRateInfo& c) {
    in >> c.tei >> c.down >> c.up;
    return in;
}

// ---- TopoEvent ----
QDataStream& operator<<(QDataStream& out, const TopoEvent& e) {
    out << static_cast<quint8>(e.kind)
        << e.nid << e.cco_mac << e.nodes << e.routes << e.up_routes
        << e.discover_src_tei << e.neighbor_teis << e.leaves << e.comm_rates
        << e.is_rf << e.restart_count << e.desc << e.epoch_ms << e.frame_index;
    return out;
}
QDataStream& operator>>(QDataStream& in, TopoEvent& e) {
    quint8 k = 0;
    in >> k >> e.nid >> e.cco_mac;
    read_tei_mac_pairs(in, e.nodes);
    read_u16_pairs(in, e.routes);
    read_u16_pairs(in, e.up_routes);
    in >> e.discover_src_tei;
    read_scalar_seq(in, e.neighbor_teis);
    read_scalar_seq(in, e.leaves);
    read_seq(in, e.comm_rates, 2 + 1 + 1,
             [](QDataStream& s, CommRateInfo& c) { s >> c.tei >> c.down >> c.up; });
    in >> e.is_rf >> e.restart_count >> e.desc >> e.epoch_ms >> e.frame_index;
    e.kind = static_cast<TopoEventKind>(k);
    return in;
}

// ---- MsduInfo ----
QDataStream& operator<<(QDataStream& out, const MsduInfo& m) {
    out << m.present << m.simple_head << m.msdu_seq
        << m.msdu_src_tei << m.msdu_dst_tei << m.msdu_send_type
        << m.msdu_src_mac << m.msdu_dst_mac << m.sta_mac
        << m.vlan_tag << m.msdu_type << m.restart_count
        << m.broadcast_direction << m.business_id << m.app_packet_type
        << m.mme_type << m.total_len << m.summary << m.tree
        << m.tei_mac_pairs << m.topo_event
        << m.route_hops_left;   // v2 新增字段(格式版本见 plugin_ipc::kWireFormatVersion)
    return out;
}
QDataStream& operator>>(QDataStream& in, MsduInfo& m) {
    in >> m.present >> m.simple_head >> m.msdu_seq
       >> m.msdu_src_tei >> m.msdu_dst_tei >> m.msdu_send_type
       >> m.msdu_src_mac >> m.msdu_dst_mac >> m.sta_mac
       >> m.vlan_tag >> m.msdu_type >> m.restart_count
       >> m.broadcast_direction >> m.business_id >> m.app_packet_type
       >> m.mme_type >> m.total_len >> m.summary;
    read_field_tree(in, m.tree);
    read_tei_mac_pairs(in, m.tei_mac_pairs);
    in >> m.topo_event
       >> m.route_hops_left;
    return in;
}

// ---- DissectField (递归;插件通用字段树) ----
QDataStream& operator<<(QDataStream& out, const DissectField& f) {
    out << f.name << f.value << f.start << f.len << f.severity << f.children;
    return out;
}
QDataStream& operator>>(QDataStream& in, DissectField& f) {
    TreeBudget b;
    read_dissect_field(in, f, 0, b);
    return in;
}

// ---- ParseResult ----
QDataStream& operator<<(QDataStream& out, const ParseResult& r) {
    out << r.meta << r.mpdu << r.msdu_body << r.msdu
        << r.msdu_raw_base << r.beacon << r.arrival_us
        << r.raw_wire << r.accept << r.reject_reason << r.payload_for_log
        << static_cast<quint8>(r.protocol)    // v2 新增字段(格式版本见 plugin_ipc::kWireFormatVersion)
        << r.dissect_fields;                  // v7:插件通用字段树(内置解析器恒为空)
    return out;
}
QDataStream& operator>>(QDataStream& in, ParseResult& r) {
    in >> r.meta >> r.mpdu >> r.msdu_body >> r.msdu
       >> r.msdu_raw_base >> r.beacon >> r.arrival_us
       >> r.raw_wire >> r.accept >> r.reject_reason >> r.payload_for_log;
    quint8 proto = 0;
    in >> proto;
    // 插件结果成型点(IPC 反序列化后、交给上层前):置插件位(高位=插件解析),
    // 低 7 位保留插件声明的内置协议编号供着色/过滤回退;此处唯一置位,不重复
    r.protocol = static_cast<ProtocolVariant>(proto | kProtocolPluginBit);
    read_dissect_list(in, r.dissect_fields);  // v7
    return in;
}

// ---- GraphicsEvent (Phase3) ----
QDataStream& operator<<(QDataStream& out, const GraphicsEvent& e) {
    out << static_cast<quint8>(e.type) << e.x << e.y << e.button
        << e.modifiers << e.delta_y << e.width << e.height;
    return out;
}
QDataStream& operator>>(QDataStream& in, GraphicsEvent& e) {
    quint8 t = 0;
    in >> t >> e.x >> e.y >> e.button >> e.modifiers >> e.delta_y
       >> e.width >> e.height;
    e.type = static_cast<GraphicsEventType>(t);
    return in;
}
// (QImage 的 QDataStream 序列化已由 Qt 内置提供,见 QtGui/qimage.h,此处不再重复定义)
