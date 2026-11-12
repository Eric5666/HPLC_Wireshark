/// @file packetentry_serialize.h
/// @brief PacketEntry 的磁盘序列化(供换页临时文件存储)
/// @details 手动逐字段序列化,避免 QDateTime / QVector<bool> 的流操作
///          版本/字节序不确定性;序列化文件仅在同一进程会话内往返
///          (换页临时文件,不跨版本/跨平台持久化)。
///          读写字段顺序必须严格一致,改动结构体后同步更新本文件。
#ifndef BPLC_PACKETENTRY_SERIALIZE_H
#define BPLC_PACKETENTRY_SERIALIZE_H

#include "bplcframe.h"
#include <QDataStream>
#include <QFile>
#include <QHash>
#include <QVector>

namespace pser {

/// @brief 编码侧块内字符串池:千条目间字段名/值海量重复,存索引代替存字符串
/// @details 块内唯一字符串一般仅数千个;池本身随块一起被 qCompress 压缩。
struct StrPool {
    QHash<QString, quint32> idx;
    QVector<QString>       list;
    quint32 intern(const QString& s) {
        auto it = idx.find(s);
        if (it != idx.end()) return it.value();
        const quint32 id = quint32(list.size());
        idx.insert(s, id);
        list.append(s);
        return id;
    }
};

inline void write_u32(QDataStream& s, quint32 v) { s << v; }
inline void write_u16(QDataStream& s, quint16 v) { s << v; }
inline void write_u8(QDataStream& s, quint8 v)  { s << v; }
inline void write_i32(QDataStream& s, qint32 v) { s << v; }
inline void write_i64(QDataStream& s, qint64 v) { s << v; }
inline void write_bool(QDataStream& s, bool v)   { s << v; }
inline void write_bytes(QDataStream& s, const QByteArray& b) { s << b; }
inline void write_str(QDataStream& s, const QString& v, StrPool& pool) { s << pool.intern(v); }

inline void read_u32(QDataStream& s, quint32& v) { s >> v; }
inline void read_u16(QDataStream& s, quint16& v) { s >> v; }
inline void read_u8(QDataStream& s, quint8& v)   { s >> v; }
inline void read_i32(QDataStream& s, qint32& v)  { s >> v; }
inline void read_i64(QDataStream& s, qint64& v)  { s >> v; }
inline void read_bool(QDataStream& s, bool& v)   { s >> v; }
inline void read_bytes(QDataStream& s, QByteArray& b) { s >> b; }
/// @brief 按索引从字符串表取回;索引越界(损坏)时置空并标记流错误
inline void read_str(QDataStream& s, QString& v, const QVector<QString>& table) {
    quint32 id = 0;
    s >> id;
    if (id < quint32(table.size())) {
        v = table[int(id)];
    } else {
        v.clear();
        s.setStatus(QDataStream::ReadCorruptData);
    }
}

/// @brief 读计数字段并按剩余字节校验(L8)
/// @details 计数来自文件:每个元素至少占 min_elem_bytes 字节,剩余字节容不下
///          n 个元素即为损坏——置 ReadCorruptData、n=0,调用方的循环/reserve
///          随之为空,不再按损坏的计数做数 GB 的分配。流已出错时同样返回 0。
inline quint32 remaining_bytes(QDataStream& s) {
    QIODevice* d = s.device();
    if (!d) return 0;
    const qint64 left = d->size() - d->pos();
    return left > 0 ? quint32(qMin<qint64>(left, 0xFFFFFFFFll)) : 0;
}
inline void read_count(QDataStream& s, quint32& n, quint32 min_elem_bytes) {
    n = 0;
    s >> n;
    if (s.status() != QDataStream::Ok) { n = 0; return; }
    if (min_elem_bytes == 0) min_elem_bytes = 1;
    if (quint64(n) * min_elem_bytes > remaining_bytes(s)) {
        n = 0;
        s.setStatus(QDataStream::ReadCorruptData);
    }
}
/// @brief 字段树最大嵌套深度(read_field_node 递归上限,防栈溢出)
inline constexpr int kMaxFieldDepth = 64;
/// @brief 循环条件:未读完且流仍正常(损坏后立即停,不空转到 n)
inline bool more(QDataStream& s, quint32 i, quint32 n) {
    return i < n && s.status() == QDataStream::Ok;
}

inline void write_meta(QDataStream& s, const PhysicalMeta& m) {
    write_u32(s, m.timestamp);
    write_u8(s, m.phr_mcs);
    write_u8(s, m.option);
    write_u16(s, m.channel);
    write_bool(s, m.is_rf);
    write_bool(s, m.has_time_tag);
    // QDateTime 存 valid + epoch ms
    write_bool(s, m.frame_time.isValid());
    write_i64(s, m.frame_time.isValid() ? m.frame_time.toMSecsSinceEpoch() : 0);
    write_bool(s, m.from_raw);
    write_bool(s, m.frame_ts_is_ntb);
    write_bool(s, m.seg_start);
    write_bool(s, m.replay_time_tag);
}

inline void read_meta(QDataStream& s, PhysicalMeta& m) {
    read_u32(s, m.timestamp);
    read_u8(s, m.phr_mcs);
    read_u8(s, m.option);
    read_u16(s, m.channel);
    read_bool(s, m.is_rf);
    read_bool(s, m.has_time_tag);
    bool valid = false; qint64 ms = 0;
    read_bool(s, valid);
    read_i64(s, ms);
    m.frame_time = valid ? QDateTime::fromMSecsSinceEpoch(ms) : QDateTime();
    read_bool(s, m.from_raw);
    read_bool(s, m.frame_ts_is_ntb);
    read_bool(s, m.seg_start);
    read_bool(s, m.replay_time_tag);
}

inline void write_mpdu(QDataStream& s, const MpduInfo& m) {
    write_u8(s, m.frame_type);
    write_u8(s, m.net_type);
    write_u32(s, m.net_id);
    write_u8(s, m.version);
    write_u16(s, m.src_tei);
    write_u16(s, m.dst_tei);
    write_u8(s, m.link_id);
    write_u16(s, m.frame_len);
    write_u8(s, m.pb_num);
    write_u16(s, m.symbol_num);
    write_bool(s, m.bc_flag);
    write_bool(s, m.re_send_flag);
    write_bool(s, m.encryp_flag);
    write_u8(s, m.tmi);
    write_u8(s, m.tmi_ext);
    write_u16(s, m.pb_size);
    write_bool(s, m.fch_crc_ok);
    write_bool(s, m.pb_crc_ok);
    write_u8(s, m.pb_head);
    // QVector<quint8>
    write_u32(s, quint32(m.pb_heads.size()));
    for (quint8 v : m.pb_heads) write_u8(s, v);
    // QVector<bool> → 逐字节
    write_u32(s, quint32(m.pb_crc_oks.size()));
    for (bool v : m.pb_crc_oks) write_bool(s, v);
    // BEACON
    write_u32(s, m.beacon_timestamp);
    write_u8(s, m.beacon_line);
    write_u8(s, m.beacon_type);
    write_u8(s, m.beacon_netsn);
    s << m.beacon_cco_mac;           // quint64
    write_u32(s, m.beacon_period_cnt);
    write_u8(s, m.beacon_rf_channel);
    write_u8(s, m.beacon_rf_option);
    write_i32(s, m.beacon_item_num);
    // COORD
    write_u16(s, m.coord_duration);
    write_u16(s, m.coord_shift);
    write_u32(s, m.coord_neighbour_nid);
    write_u8(s, m.coord_rf_channel);
    write_u8(s, m.coord_rsv0);
    write_u16(s, m.coord_rsv1);      // v10 补写:树渲染依赖(nw_2021_tree.cpp:428)
    write_u8(s, m.coord_rsv2);       // v10 补写:树渲染依赖(nw_2021_tree.cpp:430)
    write_u8(s, m.coord_rsv3);       // v10 补写:树渲染依赖(nw_2021_tree.cpp:440/442/446)
    write_u8(s, m.coord_band_end_flag);
    write_u16(s, m.coord_band_end_offset);
    write_u16(s, m.coord_band_start_offset);
    // ACK
    write_u8(s, m.ack_ext_type);
    write_u8(s, m.ack_rx_res);
    write_u8(s, m.ack_rx_status);
    write_u8(s, m.ack_rx_pb_num);
    write_u8(s, m.ack_rsv0);
    write_u8(s, m.ack_channel_quality);
    write_u8(s, m.ack_sta_load);
    write_u8(s, m.ack_rsv1);
    s << m.ack_dst_addr;             // quint64
    write_u16(s, m.ack_search_tei);
    write_u32(s, m.ack_sync_timestamp);
    write_u16(s, m.ack_sync_tei);
    write_u8(s, m.pb_num_field);   // 追加末尾(统一追加式布局)
    write_u16(s, m.beacon_rsv);    // 追加末尾(信标保留原始值)
    write_u8(s, m.pblen);          // 追加末尾(南网无线载荷PB大小索引)
    write_u8(s, m.mcs);            // 追加末尾(无线 MCS)
    // v11 补: SOF/信标/ACK 物理层参数(换页后不丢,13 个 quint8)
    write_u8(s, m.sof_data_type);
    write_u8(s, m.sof_tf_symbol_pos);
    write_u8(s, m.sof_tf_symbol_num);
    write_u8(s, m.sof_fch_sym_num);
    write_u8(s, m.sof_mod_mode);
    write_u8(s, m.sof_mod_param);
    write_u8(s, m.sof_band);
    write_u8(s, m.sof_gain);
    write_u8(s, m.sof_load_table_id);
    write_u8(s, m.beacon_fch_sym);
    write_u8(s, m.ack_bru_snr_flag);
    write_u8(s, m.ack_sat_id_flag);
    write_u8(s, m.ack_remain_sta_num);
    write_bool(s, m.fch_crc_checked);  // v12 补: FCH CRC 三态(未校验/通过/失败)
    // v13 补: 多站点 PB 分组(OFDMA 表10/11、TDA 表12/13 逐站点)
    write_u32(s, (quint32)m.sof_stations.size());
    for (const auto& st : m.sof_stations) {
        write_u16(s, st.tei);
        write_u8 (s, st.copy_mode);
        write_u8 (s, st.pb_num);
        write_u16(s, st.pb_size);
        write_i32(s, st.block_base);
        write_u32(s, (quint32)st.pb_heads.size());
        for (quint8 h : st.pb_heads) write_u8(s, h);
        write_u32(s, (quint32)st.pb_crc_oks.size());
        for (bool b : st.pb_crc_oks) write_bool(s, b);
        write_bytes(s, st.msdu);
    }
}

inline void read_mpdu(QDataStream& s, MpduInfo& m) {
    read_u8(s, m.frame_type);
    read_u8(s, m.net_type);
    read_u32(s, m.net_id);
    read_u8(s, m.version);
    read_u16(s, m.src_tei);
    read_u16(s, m.dst_tei);
    read_u8(s, m.link_id);
    read_u16(s, m.frame_len);
    read_u8(s, m.pb_num);
    read_u16(s, m.symbol_num);
    read_bool(s, m.bc_flag);
    read_bool(s, m.re_send_flag);
    read_bool(s, m.encryp_flag);
    read_u8(s, m.tmi);
    read_u8(s, m.tmi_ext);
    read_u16(s, m.pb_size);
    read_bool(s, m.fch_crc_ok);
    read_bool(s, m.pb_crc_ok);
    read_u8(s, m.pb_head);
    quint32 n = 0; read_count(s, n, 1);
    m.pb_heads.clear(); m.pb_heads.reserve(int(n));
    for (quint32 i = 0; more(s, i, n); ++i) { quint8 v; read_u8(s, v); m.pb_heads.append(v); }
    read_count(s, n, 1);
    m.pb_crc_oks.clear(); m.pb_crc_oks.reserve(int(n));
    for (quint32 i = 0; more(s, i, n); ++i) { bool v; read_bool(s, v); m.pb_crc_oks.append(v); }
    read_u32(s, m.beacon_timestamp);
    read_u8(s, m.beacon_line);
    read_u8(s, m.beacon_type);
    read_u8(s, m.beacon_netsn);
    s >> m.beacon_cco_mac;
    read_u32(s, m.beacon_period_cnt);
    read_u8(s, m.beacon_rf_channel);
    read_u8(s, m.beacon_rf_option);
    read_i32(s, m.beacon_item_num);
    read_u16(s, m.coord_duration);
    read_u16(s, m.coord_shift);
    read_u32(s, m.coord_neighbour_nid);
    read_u8(s, m.coord_rf_channel);
    read_u8(s, m.coord_rsv0);
    read_u16(s, m.coord_rsv1);       // v10 补读(与 write 镜像)
    read_u8(s, m.coord_rsv2);
    read_u8(s, m.coord_rsv3);
    read_u8(s, m.coord_band_end_flag);
    read_u16(s, m.coord_band_end_offset);
    read_u16(s, m.coord_band_start_offset);
    read_u8(s, m.ack_ext_type);
    read_u8(s, m.ack_rx_res);
    read_u8(s, m.ack_rx_status);
    read_u8(s, m.ack_rx_pb_num);
    read_u8(s, m.ack_rsv0);
    read_u8(s, m.ack_channel_quality);
    read_u8(s, m.ack_sta_load);
    read_u8(s, m.ack_rsv1);
    s >> m.ack_dst_addr;
    read_u16(s, m.ack_search_tei);
    read_u32(s, m.ack_sync_timestamp);
    read_u16(s, m.ack_sync_tei);
    read_u8(s, m.pb_num_field);   // 追加末尾(统一追加式布局)
    read_u16(s, m.beacon_rsv);    // 追加末尾(信标保留原始值)
    read_u8(s, m.pblen);          // 追加末尾(南网无线载荷PB大小索引)
    read_u8(s, m.mcs);            // 追加末尾(无线 MCS)
    // v11 补: SOF/信标/ACK 物理层参数(换页后不丢,13 个 quint8)
    read_u8(s, m.sof_data_type);
    read_u8(s, m.sof_tf_symbol_pos);
    read_u8(s, m.sof_tf_symbol_num);
    read_u8(s, m.sof_fch_sym_num);
    read_u8(s, m.sof_mod_mode);
    read_u8(s, m.sof_mod_param);
    read_u8(s, m.sof_band);
    read_u8(s, m.sof_gain);
    read_u8(s, m.sof_load_table_id);
    read_u8(s, m.beacon_fch_sym);
    read_u8(s, m.ack_bru_snr_flag);
    read_u8(s, m.ack_sat_id_flag);
    read_u8(s, m.ack_remain_sta_num);
    read_bool(s, m.fch_crc_checked);   // v12 补: FCH CRC 三态(未校验/通过/失败)
    // v13 补: 多站点 PB 分组 + 待真实帧验证标志
    quint32 n_st = 0; read_count(s, n_st, 22);  // tei2+mode1+num1+size2+base4+3 个 u32 计数/长度
    m.sof_stations.clear(); m.sof_stations.reserve(int(n_st));
    for (quint32 i = 0; more(s, i, n_st); ++i) {
        SofStationPb st;
        read_u16(s, st.tei);
        read_u8 (s, st.copy_mode);
        read_u8 (s, st.pb_num);
        read_u16(s, st.pb_size);
        read_i32(s, st.block_base);
        quint32 nh = 0; read_count(s, nh, 1);
        st.pb_heads.reserve(int(nh));
        for (quint32 j = 0; more(s, j, nh); ++j) { quint8 h; read_u8(s, h); st.pb_heads.append(h); }
        quint32 nc = 0; read_count(s, nc, 1);
        st.pb_crc_oks.reserve(int(nc));
        for (quint32 j = 0; more(s, j, nc); ++j) { bool b; read_bool(s, b); st.pb_crc_oks.append(b); }
        read_bytes(s, st.msdu);
        m.sof_stations.append(st);
    }
}

inline void write_field_node(QDataStream& s, const MsduFieldNode& n, StrPool& pool) {
    write_str(s, n.name, pool);
    write_str(s, n.value, pool);
    write_i32(s, n.rel_start);
    write_i32(s, n.rel_len);
    write_u32(s, quint32(n.children.size()));
    for (const MsduFieldNode& c : n.children) write_field_node(s, c, pool);
}

inline void read_field_node(QDataStream& s, MsduFieldNode& n,
                            const QVector<QString>& table, int depth = 0) {
    if (depth >= kMaxFieldDepth) {   // 嵌套过深 = 损坏,不再递归
        s.setStatus(QDataStream::ReadCorruptData);
        return;
    }
    read_str(s, n.name, table);
    read_str(s, n.value, table);
    read_i32(s, n.rel_start);
    read_i32(s, n.rel_len);
    quint32 cnt = 0; read_count(s, cnt, 20);  // name4+value4+start4+len4+count4
    n.children.clear(); n.children.reserve(int(cnt));
    for (quint32 i = 0; more(s, i, cnt); ++i) {
        MsduFieldNode c; read_field_node(s, c, table, depth + 1); n.children.append(c);
    }
}

inline void write_topo_event(QDataStream& s, const TopoEvent& t, StrPool& pool) {
    write_u8(s, static_cast<quint8>(t.kind));
    write_u32(s, t.nid);
    s << t.cco_mac;
    write_u32(s, quint32(t.nodes.size()));
    for (const TeiMacPair& p : t.nodes) { write_u16(s, p.tei); s << p.mac; }
    write_u32(s, quint32(t.routes.size()));
    for (const auto& r : t.routes) { write_u16(s, r.first); write_u16(s, r.second); }
    write_u32(s, quint32(t.leaves.size()));
    for (quint64 mac : t.leaves) s << mac;
    write_u32(s, quint32(t.comm_rates.size()));
    for (const CommRateInfo& c : t.comm_rates) { write_u16(s, c.tei); write_u8(s, c.down); write_u8(s, c.up); }
    write_str(s, t.desc, pool);
    write_i64(s, t.epoch_ms);
    // v11 补: 换页后不丢的 23 个拓扑字段(与 read_topo_event 逐行对应)
    write_u32(s, quint32(t.up_routes.size()));
    for (const auto& r : t.up_routes) { write_u16(s, r.first); write_u16(s, r.second); }
    write_u16(s, t.discover_src_tei);
    write_u32(s, quint32(t.neighbor_teis.size()));
    for (quint16 tei : t.neighbor_teis) write_u16(s, tei);
    write_bool(s, t.neighbor_teis_present);
    write_bool(s, t.is_rf);
    write_bool(s, t.is_rf_known);
    write_u32(s, quint32(t.rssi_entries.size()));
    for (const auto& p : t.rssi_entries) { write_u16(s, p.first); write_i32(s, p.second); }
    write_u32(s, quint32(t.neighbor_rates.size()));
    for (const auto& p : t.neighbor_rates) { write_u16(s, p.first); write_u8(s, p.second); }
    write_u32(s, quint32(t.neighbor_snrs.size()));
    for (const auto& p : t.neighbor_snrs) { write_u16(s, p.first); write_u16(s, static_cast<quint16>(p.second)); }
    write_u16(s, t.proxy_tei);
    write_u16(s, static_cast<quint16>(t.proxy_up_rate));
    write_u16(s, static_cast<quint16>(t.proxy_down_rate));
    write_u16(s, static_cast<quint16>(t.min_link_rate));
    write_u8(s, t.rf_hop);
    write_u8(s, t.rf_role);
    write_i32(s, t.link_type);
    write_u32(s, quint32(t.node_link_types.size()));
    for (const auto& p : t.node_link_types) { write_u16(s, p.first); write_u8(s, p.second); }
    write_i32(s, t.proxy_comm_rate);
    write_i32(s, t.proxy_down_comm_rate);
    write_u16(s, static_cast<quint16>(t.min_comm_rate));
    write_u32(s, quint32(t.child_teis.size()));
    for (quint16 tei : t.child_teis) write_u16(s, tei);
    write_i32(s, t.restart_count);
    write_i64(s, t.frame_index);
    s << t.sender_mac;   // v15: 本跳发送方 MAC(STA 重启按发送方建基线)
}

inline void read_topo_event(QDataStream& s, TopoEvent& t,
                            const QVector<QString>& table) {
    quint8 k = 0; read_u8(s, k); t.kind = static_cast<TopoEventKind>(k);
    read_u32(s, t.nid);
    s >> t.cco_mac;
    quint32 nc = 0; read_count(s, nc, 10);
    t.nodes.clear(); t.nodes.reserve(int(nc));
    for (quint32 i = 0; more(s, i, nc); ++i) { TeiMacPair p; read_u16(s, p.tei); s >> p.mac; t.nodes.append(p); }
    quint32 rc = 0; read_count(s, rc, 4);
    t.routes.clear(); t.routes.reserve(int(rc));
    for (quint32 i = 0; more(s, i, rc); ++i) { quint16 a = 0, b = 0; read_u16(s, a); read_u16(s, b); t.routes.append({a, b}); }
    quint32 lc = 0; read_count(s, lc, 8);
    t.leaves.clear(); t.leaves.reserve(int(lc));
    for (quint32 i = 0; more(s, i, lc); ++i) { quint64 mac = 0; s >> mac; t.leaves.append(mac); }
    quint32 cc = 0; read_count(s, cc, 4);
    t.comm_rates.clear(); t.comm_rates.reserve(int(cc));
    for (quint32 i = 0; more(s, i, cc); ++i) {
        CommRateInfo c; read_u16(s, c.tei); read_u8(s, c.down); read_u8(s, c.up);
        t.comm_rates.append(c);
    }
    read_str(s, t.desc, table);
    read_i64(s, t.epoch_ms);
    // v11 补: 换页后不丢的 23 个拓扑字段(与 write_topo_event 逐行对应)
    quint32 urc = 0; read_count(s, urc, 4);
    t.up_routes.clear(); t.up_routes.reserve(int(urc));
    for (quint32 i = 0; more(s, i, urc); ++i) { quint16 a = 0, b = 0; read_u16(s, a); read_u16(s, b); t.up_routes.append({a, b}); }
    read_u16(s, t.discover_src_tei);
    quint32 ntc = 0; read_count(s, ntc, 2);
    t.neighbor_teis.clear(); t.neighbor_teis.reserve(int(ntc));
    for (quint32 i = 0; more(s, i, ntc); ++i) { quint16 tei = 0; read_u16(s, tei); t.neighbor_teis.append(tei); }
    read_bool(s, t.neighbor_teis_present);
    read_bool(s, t.is_rf);
    read_bool(s, t.is_rf_known);
    quint32 rsc = 0; read_count(s, rsc, 6);
    t.rssi_entries.clear(); t.rssi_entries.reserve(int(rsc));
    for (quint32 i = 0; more(s, i, rsc); ++i) { quint16 a = 0; qint32 b = 0; read_u16(s, a); read_i32(s, b); t.rssi_entries.append({a, b}); }
    quint32 nrc = 0; read_count(s, nrc, 3);
    t.neighbor_rates.clear(); t.neighbor_rates.reserve(int(nrc));
    for (quint32 i = 0; more(s, i, nrc); ++i) { quint16 a = 0; quint8 b = 0; read_u16(s, a); read_u8(s, b); t.neighbor_rates.append({a, b}); }
    quint32 nsc = 0; read_count(s, nsc, 4);
    t.neighbor_snrs.clear(); t.neighbor_snrs.reserve(int(nsc));
    for (quint32 i = 0; more(s, i, nsc); ++i) { quint16 a = 0; quint16 b = 0; read_u16(s, a); read_u16(s, b); t.neighbor_snrs.append({a, static_cast<qint16>(b)}); }
    read_u16(s, t.proxy_tei);
    quint16 pur = 0; read_u16(s, pur); t.proxy_up_rate = static_cast<qint16>(pur);
    quint16 pdr = 0; read_u16(s, pdr); t.proxy_down_rate = static_cast<qint16>(pdr);
    quint16 mlr = 0; read_u16(s, mlr); t.min_link_rate = static_cast<qint16>(mlr);
    read_u8(s, t.rf_hop);
    read_u8(s, t.rf_role);
    read_i32(s, t.link_type);
    quint32 nltc = 0; read_count(s, nltc, 3);
    t.node_link_types.clear(); t.node_link_types.reserve(int(nltc));
    for (quint32 i = 0; more(s, i, nltc); ++i) { quint16 a = 0; quint8 b = 0; read_u16(s, a); read_u8(s, b); t.node_link_types.append({a, b}); }
    read_i32(s, t.proxy_comm_rate);
    read_i32(s, t.proxy_down_comm_rate);
    quint16 mcr = 0; read_u16(s, mcr); t.min_comm_rate = static_cast<qint16>(mcr);
    quint32 ctc = 0; read_count(s, ctc, 2);
    t.child_teis.clear(); t.child_teis.reserve(int(ctc));
    for (quint32 i = 0; more(s, i, ctc); ++i) { quint16 tei = 0; read_u16(s, tei); t.child_teis.append(tei); }
    read_i32(s, t.restart_count);
    read_i64(s, t.frame_index);
    s >> t.sender_mac;   // v15: 本跳发送方 MAC(STA 重启按发送方建基线)
}

inline void write_msdu_info(QDataStream& s, const MsduInfo& m, StrPool& pool) {
    write_bool(s, m.present);
    write_bool(s, m.simple_head);
    write_bool(s, m.cascade);          // 聚合帧级联标记(SPLC 表47/48)
    write_u16(s, m.msdu_seq);
    write_i32(s, m.msdu_src_tei);
    write_i32(s, m.msdu_dst_tei);
    write_i32(s, m.msdu_send_type);
    s << m.msdu_src_mac;   // quint64(48-bit MAC)
    s << m.msdu_dst_mac;
    s << m.sta_mac;
    write_u32(s, m.vlan_tag);
    write_u16(s, m.msdu_type);
    write_u8(s, m.restart_count);
    write_u8(s, m.broadcast_direction);
    write_u8(s, m.route_hops_left);
    write_u8(s, m.business_id);
    write_u8(s, m.app_packet_type);
    write_u16(s, m.mme_type);
    write_u8(s, m.trans_direction_flag);
    write_i32(s, m.total_len);
    write_str(s, m.summary, pool);
    write_u32(s, quint32(m.tree.size()));
    for (const MsduFieldNode& n : m.tree) write_field_node(s, n, pool);
    write_u32(s, quint32(m.tei_mac_pairs.size()));
    for (const TeiMacPair& p : m.tei_mac_pairs) { write_u16(s, p.tei); s << p.mac; }
    write_topo_event(s, m.topo_event, pool);
    write_u32(s, quint32(m.topo_extra_events.size()));
    for (const TopoEvent& t : m.topo_extra_events) write_topo_event(s, t, pool);
    write_u32(s, quint32(m.orig_srcs.size()));
    for (const TeiMacPair& p : m.orig_srcs) { write_u16(s, p.tei); s << p.mac; }
    write_u32(s, quint32(m.orig_dsts.size()));
    for (const TeiMacPair& p : m.orig_dsts) { write_u16(s, p.tei); s << p.mac; }
}

inline void read_msdu_info(QDataStream& s, MsduInfo& m,
                           const QVector<QString>& table) {
    read_bool(s, m.present);
    read_bool(s, m.simple_head);
    read_bool(s, m.cascade);           // 聚合帧级联标记(SPLC 表47/48)
    read_u16(s, m.msdu_seq);
    read_i32(s, m.msdu_src_tei);
    read_i32(s, m.msdu_dst_tei);
    read_i32(s, m.msdu_send_type);
    s >> m.msdu_src_mac;
    s >> m.msdu_dst_mac;
    s >> m.sta_mac;
    read_u32(s, m.vlan_tag);
    read_u16(s, m.msdu_type);
    read_u8(s, m.restart_count);
    read_u8(s, m.broadcast_direction);
    read_u8(s, m.route_hops_left);
    read_u8(s, m.business_id);
    read_u8(s, m.app_packet_type);
    read_u16(s, m.mme_type);
    read_u8(s, m.trans_direction_flag);
    read_i32(s, m.total_len);
    read_str(s, m.summary, table);
    quint32 cnt = 0; read_count(s, cnt, 20);
    m.tree.clear(); m.tree.reserve(int(cnt));
    for (quint32 i = 0; more(s, i, cnt); ++i) {
        MsduFieldNode n; read_field_node(s, n, table); m.tree.append(n);
    }
    quint32 pc = 0; read_count(s, pc, 10);
    m.tei_mac_pairs.clear(); m.tei_mac_pairs.reserve(int(pc));
    for (quint32 i = 0; more(s, i, pc); ++i) {
        TeiMacPair p; read_u16(s, p.tei); s >> p.mac; m.tei_mac_pairs.append(p);
    }
    read_topo_event(s, m.topo_event, table);
    { quint32 n = 0; read_count(s, n, 32); m.topo_extra_events.clear();
      for (quint32 i = 0; more(s, i, n); ++i) { TopoEvent t; read_topo_event(s, t, table); m.topo_extra_events.append(t); } }
    { quint32 n = 0; read_count(s, n, 10); m.orig_srcs.clear();
      for (quint32 i = 0; more(s, i, n); ++i) { TeiMacPair p; read_u16(s, p.tei); s >> p.mac; m.orig_srcs.append(p); } }
    { quint32 n = 0; read_count(s, n, 10); m.orig_dsts.clear();
      for (quint32 i = 0; more(s, i, n); ++i) { TeiMacPair p; read_u16(s, p.tei); s >> p.mac; m.orig_dsts.append(p); } }
}

/// @brief 序列化一个 PacketEntry 到字节流(不含长度前缀)
/// @details search_text 不在本载荷内:单条往返时由 deserialize_entry 按派生
///          规则重建;块文件 v3 则把它存进块索引,BlockReader 解码时回填。
///          字符串经 pool 去重,调用方(encode_block)负责先写字符串表。
inline QByteArray serialize_entry(const PacketEntry& e, StrPool& pool) {
    QByteArray buf;
    QDataStream s(&buf, QIODevice::WriteOnly);
    write_i32(s, e.index);
    write_i64(s, e.epoch_ms);
    write_i64(s, e.delta_us);
    write_bool(s, e.accepted);
    write_str(s, e.reason, pool);
    write_bytes(s, e.raw_wire);
    write_meta(s, e.meta);
    write_mpdu(s, e.mpdu);
    write_u8(s, e.protocol);
    write_bytes(s, e.msdu_body);
    write_msdu_info(s, e.msdu, pool);
    write_msdu_info(s, e.beacon, pool);
    write_i32(s, e.msdu_raw_base);
    write_bytes(s, e.raw_bytes);
    return buf;
}

/// @brief 反序列化一个 PacketEntry(与 serialize_entry 严格互逆)
/// @param rebuild_search true=按派生规则重建 search_text(单条往返/旧路径);
///        false=不重建,由调用方从块索引回填 v3 落盘值(BlockReader 用)
inline bool deserialize_entry(const QByteArray& buf, PacketEntry& e,
                              const QVector<QString>& table,
                              bool rebuild_search = true) {
    QDataStream s(buf);
    read_i32(s, e.index);
    read_i64(s, e.epoch_ms);
    read_i64(s, e.delta_us);
    read_bool(s, e.accepted);
    read_str(s, e.reason, table);
    read_bytes(s, e.raw_wire);
    read_meta(s, e.meta);
    read_mpdu(s, e.mpdu);
    read_u8(s, e.protocol);
    read_bytes(s, e.msdu_body);
    read_msdu_info(s, e.msdu, table);
    read_msdu_info(s, e.beacon, table);
    read_i32(s, e.msdu_raw_base);
    read_bytes(s, e.raw_bytes);
    if (s.status() != QDataStream::Ok)
        return false;
    if (rebuild_search)
        e.search_text = make_search_text(e);  // 派生字段:加载时重建
    return true;
}

// ---------------------------------------------------------------------------
// 块文件格式 v3(字符串池 + 轻量索引 + 条目分块独立压缩)
// 文件布局(定长部分以 Wire* 结构体表达,sizeof 即磁盘字节数;变长段为
// quint32 长度前缀 + 内容,QDataStream 大端序顺序写入,偏移为文件绝对字节):
//   [WireBlockHead][pool_blob]         blob = qCompress(pool_raw) 或 pool_raw
//     pool_raw = [str_count u32][str...]        (块内字符串去重表)
//   [index_raw]                         WireIndexEntry × count(QByteArray
//                                       形式承载,自带 u32 长度前缀)
//   [nchunks u32][WireChunkEntry × nchunks]
//   [chunk_blob × nchunks]              每块 ≤ kBlockChunkEntries 条:
//                                       chunk_raw = [len u32][payload] × n,
//                                       blob = qCompress(chunk_raw) 或 chunk_raw;
//                                       payload 与 v2 相同(serialize_entry,
//                                       字符串以池索引引用)
// 设计目标(2026-10 实测驱动):滚动只解一屏需要的条目(按条随机解码,不再整块
// 解压+逐条反序列化+重建 search_text);筛选只读池+索引(search_text 已落盘),
// 不碰条目正文。search_text 存索引区(池索引),反序列化后由 BlockReader 回填。
// 换页临时文件仅同一进程会话内往返,不做跨版本兼容;魔数/条数/偏移/解压校验
// 用于识别截断文件(磁盘满等),解码失败时调用方不得使用残缺数据。
// ---------------------------------------------------------------------------

inline quint32 block_magic()   { return 0x50424C4Bu; }  // "PBLK"
inline quint32 block_version() { return 20u; }  // v20: 轻量索引补 orig_src_teis/orig_dst_teis(TEI-only 段亦含,过滤 sta- 条件纯 TEI 比对,不扫 search_text); v19: MsduInfo 补 orig_dsts(聚合/多站点原始目的,与 orig_srcs 镜像); v18: MsduInfo 补 orig_srcs(聚合/多站点原始源); v17: MsduInfo 补 topo_extra_events(多站点后续拓扑事件); v16: 补 MsduInfo::trans_direction_flag(APP 传输方向,P2P Dir 列); v15: TopoEvent 补 sender_mac(STA 重启按发送方建基线); v14: 删 MpduInfo::sof_multi_site_verified(死字段,UI 零读取); v13: 补 MpduInfo::sof_stations(多站点 PB 分组 OFDMA/TDA) + sof_multi_site_verified; v12: 补 fch_crc_checked(FCH CRC 三态);v11: 补 MsduInfo::cascade + TopoEvent 23 字段 + MpduInfo 13 字段;v10: 删死字段 pb_index/coord_option/ack_search_freq;补写 coord_rsv1/2/3(树渲染依赖,原先漏写导致换页后恒 0);v9 增 mcs;v8 增 pblen;v7 增 beacon_rsv;v6 三线合流并集
/// @brief 独立压缩分块的条目数(随机解码粒度:解一条最多解压一个分块)
inline constexpr int kBlockChunkEntries = 50;

// ---- v4 磁盘布局结构体 -----------------------------------------------------
// 1 字节对齐的定长布局定义:字段顺序与 QDataStream 的写入顺序一一对应,
// sizeof 即磁盘字节数。所有段长/偏移/条目步长一律由 sizeof 推导(禁止再
// 手算数字);改字段必须同步改结构体,static_assert 与 round-trip 测试兜底。
#pragma pack(push, 1)
/// @brief 文件头定长部分:[magic][version][count][pool_zipped]
struct WireBlockHead {
    quint32 magic;
    quint32 version;
    quint32 count;
    quint8  pool_zipped;
};
/// @brief 轻量索引条目:[frame_type][src_tei][dst_tei][search_text 池索引]
struct WireIndexEntry {
    quint8  frame_type;
    quint16 src_tei;
    quint16 dst_tei;
    quint32 search_idx;
};
/// @brief 分块表条目:[文件绝对偏移][分块字节数][是否压缩]
struct WireChunkEntry {
    quint32 offset;
    quint32 length;
    quint8  zipped;
};
#pragma pack(pop)
static_assert(sizeof(WireBlockHead)  == 13, "WireBlockHead disk size drifted");
static_assert(sizeof(WireIndexEntry) == 9,  "WireIndexEntry disk size drifted");
static_assert(sizeof(WireChunkEntry) == 9,  "WireChunkEntry disk size drifted");
/// @brief 变长段(QByteArray/QVector 计数等)的长度前缀字节数
inline constexpr qint64 kLenPrefixBytes = qint64(sizeof(quint32));

namespace detail {
/// @brief 大端 u32 读取(与 QDataStream 默认字节序一致,供分块内偏移步进)
inline quint32 read_be32(const char* p) {
    return (quint32(quint8(p[0])) << 24) | (quint32(quint8(p[1])) << 16)
         | (quint32(quint8(p[2])) << 8)  |  quint32(quint8(p[3]));
}
/// @brief 压缩(1 档速度优先);压不动/失败则原样返回并置 zipped=false
inline QByteArray compress_or_raw(const QByteArray& raw, bool& zipped) {
    const QByteArray comp = qCompress(raw, 1);
    if (!comp.isEmpty() && comp.size() < raw.size()) {
        zipped = true;
        return comp;
    }
    zipped = false;
    return raw;
}
}  // namespace detail

/// @brief 把一整块条目编码为待写入文件的内容(v3 布局)
inline QByteArray encode_block(const QVector<PacketEntry>& entries) {
    if (entries.isEmpty()) return {};
    StrPool pool;
    QVector<QByteArray> payloads;
    QVector<quint32>    search_idx;
    payloads.reserve(entries.size());
    search_idx.reserve(entries.size());
    for (const PacketEntry& e : entries) {
        payloads.append(serialize_entry(e, pool));
        // search_text 落盘:空时按派生规则补算(模型路径恒已填充)
        search_idx.append(pool.intern(e.search_text.isEmpty()
                                          ? make_search_text(e)
                                          : e.search_text));
    }
    // 字符串池段
    QByteArray pool_raw;
    {
        QDataStream s(&pool_raw, QIODevice::WriteOnly);
        s << quint32(pool.list.size());
        for (const QString& str : pool.list) s << str;
    }
    bool pool_zipped = false;
    const QByteArray pool_blob = detail::compress_or_raw(pool_raw, pool_zipped);
    // 轻量索引段(帧型/TEI/search_text 索引,筛选专用,不解码正文)
    QByteArray index_raw;
    {
        QDataStream s(&index_raw, QIODevice::WriteOnly);
        for (int i = 0; i < entries.size(); ++i) {
            s << quint8(entries[i].mpdu.frame_type)
              << quint16(entries[i].mpdu.src_tei)
              << quint16(entries[i].mpdu.dst_tei)
              << search_idx[i];
        }
    }
    // Orig TEI 索引段(v20,筛选专用):每行依次 [qint32 msdu_src_tei]
    // [qint32 msdu_dst_tei][u16 n_src][u16 src_teis...][u16 n_dst]
    // [u16 dst_teis...];orig TEI 去重保序(TEI-only 段亦含,仅 TEI 值,
    // 不含 MAC)。sta- 条件据此纯 TEI 比对,不再扫 search_text:
    // 命中集 = 轻量索引段的 hop 源/目的 TEI ∪ (msdu 帧级 TEI>0 时取
    // 其值,否则取 orig 两列),与 make_search_text 的 sta- 词集合
    // 完全一致(含帧级有源时 orig 词缺席的前提条件)。
    QByteArray orig_raw;
    {
        QDataStream s(&orig_raw, QIODevice::WriteOnly);
        auto write_teis = [&s](const QVector<TeiMacPair>& pairs) {
            QVector<quint16> teis;
            for (const auto& p : pairs) {
                if (p.tei != 0 && !teis.contains(p.tei)) teis.append(p.tei);
            }
            s << quint16(teis.size());
            for (const quint16 t : teis) s << t;
        };
        for (const PacketEntry& e : entries) {
            s << qint32(e.msdu.msdu_src_tei) << qint32(e.msdu.msdu_dst_tei);
            write_teis(e.msdu.orig_srcs);
            write_teis(e.msdu.orig_dsts);
        }
    }
    // 条目分块段(每分块独立压缩,支撑按条随机解码)
    const int nchunks = (entries.size() + kBlockChunkEntries - 1)
                        / kBlockChunkEntries;
    QVector<QByteArray> chunk_blobs;
    QVector<bool>       chunk_zipped;
    chunk_blobs.reserve(nchunks);
    for (int c = 0; c < nchunks; ++c) {
        QByteArray raw;
        QDataStream s(&raw, QIODevice::WriteOnly);
        const int end = qMin(entries.size(), (c + 1) * kBlockChunkEntries);
        for (int i = c * kBlockChunkEntries; i < end; ++i) {
            s << quint32(payloads[i].size());
            s.writeRawData(payloads[i].constData(), payloads[i].size());
        }
        bool z = false;
        chunk_blobs.append(detail::compress_or_raw(raw, z));
        chunk_zipped.append(z);
    }
    // 文件头总长(分块表偏移为绝对文件偏移):全部由布局结构体的 sizeof
    // 推导,与下方 QDataStream 实际写出的字节数逐字节对应——定长头
    // WireBlockHead、三个 QByteArray 变长段(长度前缀+内容:池/轻量索引/
    // Orig TEI 索引)、nchunks 计数、分块表 WireChunkEntry × nchunks。
    const qint64 header_len = qint64(sizeof(WireBlockHead))
                            + (kLenPrefixBytes + pool_blob.size())
                            + (kLenPrefixBytes + index_raw.size())
                            + (kLenPrefixBytes + orig_raw.size())
                            + qint64(sizeof(quint32))
                            + qint64(nchunks) * qint64(sizeof(WireChunkEntry));
    QByteArray out;
    QDataStream s(&out, QIODevice::WriteOnly);
    s << block_magic() << block_version() << quint32(entries.size());
    s << quint8(pool_zipped ? 1 : 0) << pool_blob;
    s << index_raw;
    s << orig_raw;
    s << quint32(nchunks);
    qint64 off = header_len;
    for (int c = 0; c < nchunks; ++c) {
        s << quint32(off) << quint32(chunk_blobs[c].size())
          << quint8(chunk_zipped[c] ? 1 : 0);
        off += chunk_blobs[c].size();
    }
    for (const QByteArray& b : chunk_blobs)
        s.writeRawData(b.constData(), b.size());
    return out;
}

/// @brief v3 块文件随机访问读取器:打开只解析头/池/索引,条目按需解码
/// @details 同一时刻只缓存最近一个分块的解压结果与一条条目(滚动/绘制的
///          实际访问模式);read_all 顺序遍历时分块只解压一次。
class BlockReader {
public:
    bool open(const QString& path) {
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) return false;
        const QByteArray data = f.readAll();
        f.close();
        if (data.isEmpty()) return false;
        return open_data(data);
    }

    bool open_data(const QByteArray& data) {
        m_data = data;
        m_table.clear();
        m_index.clear();
        m_msdu_src.clear();
        m_msdu_dst.clear();
        m_orig_src.clear();
        m_orig_dst.clear();
        m_chunks.clear();
        m_chunk_no = -1;
        m_chunk_raw.clear();
        m_chunk_pay.clear();
        m_ref_idx = -1;
        QDataStream s(m_data);
        quint32 magic = 0, ver = 0, count = 0;
        quint8 pool_zipped = 0;
        QByteArray pool_blob, index_raw, orig_raw;
        s >> magic >> ver >> count >> pool_zipped >> pool_blob >> index_raw
          >> orig_raw;
        if (s.status() != QDataStream::Ok || magic != block_magic()
            || ver != block_version() || count == 0 || count > 100000)
            return false;
        const QByteArray pool_raw = pool_zipped ? qUncompress(pool_blob)
                                                : pool_blob;
        if (pool_raw.isEmpty()) return false;
        {
            QDataStream ps(pool_raw);
            quint32 str_count = 0;
            ps >> str_count;
            // 每个字符串至少 4 字节长度前缀:计数超出池字节数即损坏(L8)
            if (ps.status() != QDataStream::Ok || str_count > 1000000
                || quint64(str_count) * 4 > quint64(pool_raw.size()))
                return false;
            m_table.reserve(int(str_count));
            for (quint32 i = 0; i < str_count; ++i) {
                QString str;
                ps >> str;
                if (ps.status() != QDataStream::Ok) return false;
                m_table.append(str);
            }
        }
        if (qint64(index_raw.size())
                != qint64(count) * qint64(sizeof(WireIndexEntry)))
            return false;   // 索引段字节数必须恰为 count 条定长条目
        {
            QDataStream is(index_raw);
            m_index.reserve(int(count));
            for (quint32 i = 0; i < count; ++i) {
                IndexEntry ix;
                is >> ix.frame_type >> ix.src_tei >> ix.dst_tei >> ix.search_idx;
                if (is.status() != QDataStream::Ok) return false;
                if (ix.search_idx >= quint32(m_table.size())) return false;
                m_index.append(ix);
            }
        }
        {
            // Orig TEI 索引段(v20):每行 [qint32 msdu_src][qint32 msdu_dst]
            // [u16 n_src][u16 src...][u16 n_dst][u16 dst...],必须恰好解析
            // 出 count 行且用尽整段,否则拒收(与轻量索引段同等严格)。
            QDataStream os(orig_raw);
            m_msdu_src.clear();
            m_msdu_dst.clear();
            m_orig_src.clear();
            m_orig_dst.clear();
            m_msdu_src.reserve(int(count));
            m_msdu_dst.reserve(int(count));
            m_orig_src.reserve(int(count));
            m_orig_dst.reserve(int(count));
            for (quint32 i = 0; i < count; ++i) {
                qint32 msdu_src = 0, msdu_dst = 0;
                quint16 n_src = 0, n_dst = 0;
                os >> msdu_src >> msdu_dst >> n_src;
                if (os.status() != QDataStream::Ok) return false;
                QVector<quint16> src_teis;
                src_teis.reserve(int(n_src));
                for (quint16 j = 0; j < n_src; ++j) {
                    quint16 t = 0;
                    os >> t;
                    if (os.status() != QDataStream::Ok) return false;
                    src_teis.append(t);
                }
                os >> n_dst;
                if (os.status() != QDataStream::Ok) return false;
                QVector<quint16> dst_teis;
                dst_teis.reserve(int(n_dst));
                for (quint16 j = 0; j < n_dst; ++j) {
                    quint16 t = 0;
                    os >> t;
                    if (os.status() != QDataStream::Ok) return false;
                    dst_teis.append(t);
                }
                m_msdu_src.append(msdu_src);
                m_msdu_dst.append(msdu_dst);
                m_orig_src.append(std::move(src_teis));
                m_orig_dst.append(std::move(dst_teis));
            }
            if (!os.atEnd()) return false;
        }
        quint32 nchunks = 0;
        s >> nchunks;
        if (s.status() != QDataStream::Ok
            || nchunks != quint32((count + kBlockChunkEntries - 1)
                                  / kBlockChunkEntries))
            return false;
        m_chunks.reserve(int(nchunks));
        for (quint32 c = 0; c < nchunks; ++c) {
            Chunk ch;
            quint8 z = 0;
            s >> ch.off >> ch.len >> z;
            ch.zipped = (z != 0);
            if (s.status() != QDataStream::Ok) return false;
            if (qint64(ch.off) + ch.len > m_data.size()) return false;
            m_chunks.append(ch);
        }
        m_count = int(count);
        return true;
    }

    int count() const { return m_count; }

    // ---- 轻量索引访问(筛选扫描用,不解码条目正文) ----
    quint8  frame_type(int i) const { return m_index[i].frame_type; }
    quint16 src_tei(int i) const    { return m_index[i].src_tei; }
    quint16 dst_tei(int i) const    { return m_index[i].dst_tei; }
    const QString& search_text(int i) const {
        return m_table[int(m_index[i].search_idx)];
    }
    // Orig TEI 索引(v20,筛选专用):仅 TEI 值,去重保序;hop TEI 见 src_tei/dst_tei
    int msdu_src_tei(int i) const { return m_msdu_src[i]; }
    int msdu_dst_tei(int i) const { return m_msdu_dst[i]; }
    const QVector<quint16>& orig_src_teis(int i) const { return m_orig_src[i]; }
    const QVector<quint16>& orig_dst_teis(int i) const { return m_orig_dst[i]; }

    /// @brief 按条随机解码(只解压所在分块,只反序列化目标条)
    bool entry_at(int i, PacketEntry& out) const {
        if (i < 0 || i >= m_count) return false;
        const int c = i / kBlockChunkEntries;
        if (c != m_chunk_no && !load_chunk(c)) return false;
        const int j = i - c * kBlockChunkEntries;
        if (j >= m_chunk_pay.size()) return false;
        const PayRec& rec = m_chunk_pay[j];
        // 零拷贝视图(不深拷贝 payload):deserialize 期间分块缓存不被触碰,
        // m_chunk_raw 始终有效,视图在其内部消费完毕。
        const QByteArray payload = QByteArray::fromRawData(
            m_chunk_raw.constData() + rec.off, rec.len);
        if (!deserialize_entry(payload, out, m_table, /*rebuild_search=*/false))
            return false;
        out.search_text = search_text(i);   // 回填落盘值,不重建
        return true;
    }

    /// @brief entry_at 的引用版(单条缓存,供模型 locate 的瞬时使用场景)
    /// @warning 返回的引用指向单槽缓存 m_ref_entry:本读取器后续任何一次
    ///          entry_ref、或触发 load_chunk 的 entry_at/read_all 调用都会
    ///          覆盖它。调用方必须在下一次调用前立即消费(读字段或深拷贝),
    ///          严禁跨调用持有该引用——这是与 v2「整块 QVector 引用在块
    ///          淘汰前一直有效」相比收紧的语义,新增调用点务必注意。
    const PacketEntry& entry_ref(int i, bool& ok) const {
        if (i == m_ref_idx) { ok = true; return m_ref_entry; }
        ok = entry_at(i, m_ref_entry);
        if (ok) m_ref_idx = i;
        return m_ref_entry;
    }

    /// @brief 顺序解出整块(导出/for_each/测试用;分块各只解压一次)
    bool read_all(QVector<PacketEntry>& entries) const {
        entries.clear();
        entries.reserve(m_count);
        for (int i = 0; i < m_count; ++i) {
            PacketEntry e;
            if (!entry_at(i, e)) { entries.clear(); return false; }
            entries.append(std::move(e));
        }
        return entries.size() == m_count;
    }

private:
    struct IndexEntry {
        quint8  frame_type = 0;
        quint16 src_tei = 0;
        quint16 dst_tei = 0;
        quint32 search_idx = 0;
    };
    struct Chunk {
        quint32 off = 0;
        quint32 len = 0;
        bool    zipped = false;
    };
    struct PayRec { int off = 0; int len = 0; };

    bool load_chunk(int c) const {
        const Chunk& ch = m_chunks[c];
        const QByteArray slice = m_data.mid(int(ch.off), int(ch.len));
        const QByteArray raw = ch.zipped ? qUncompress(slice) : slice;
        if (raw.isEmpty()) return false;
        const int expect = qMin(kBlockChunkEntries,
                                m_count - c * kBlockChunkEntries);
        QVector<PayRec> pays;
        pays.reserve(expect);
        constexpr int kLenBytes = int(sizeof(quint32));  // [len u32][payload]
        int pos = 0;
        for (int j = 0; j < expect; ++j) {
            if (pos + kLenBytes > raw.size()) return false;
            const quint32 len = detail::read_be32(raw.constData() + pos);
            pos += kLenBytes;
            if (len == 0 || pos + int(len) > raw.size()) return false;
            pays.append({pos, int(len)});
            pos += int(len);
        }
        if (pos != raw.size()) return false;   // 分块内容必须恰好用尽
        m_chunk_raw = raw;
        m_chunk_pay = pays;
        m_chunk_no = c;
        m_ref_idx = -1;   // 分块换出,单条缓存随之失效
        return true;
    }

    QByteArray          m_data;
    int                 m_count = 0;
    QVector<QString>    m_table;
    QVector<IndexEntry> m_index;
    QVector<int> m_msdu_src;  // v20 MSDU 帧级源 TEI(与 m_index 等长,-1=无)
    QVector<int> m_msdu_dst;  // v20 MSDU 帧级目的 TEI(与 m_index 等长,-1=无)
    QVector<QVector<quint16>> m_orig_src;  // v20 Orig TEI 索引(与 m_index 等长)
    QVector<QVector<quint16>> m_orig_dst;
    QVector<Chunk>      m_chunks;
    mutable int         m_chunk_no = -1;
    mutable QByteArray  m_chunk_raw;
    mutable QVector<PayRec> m_chunk_pay;
    mutable int         m_ref_idx = -1;
    mutable PacketEntry m_ref_entry;
};

/// @brief 解码块文件内容;任一步校验失败返回 false 并清空 entries
inline bool decode_block(const QByteArray& data, QVector<PacketEntry>& entries) {
    BlockReader r;
    if (!r.open_data(data)) { entries.clear(); return false; }
    return r.read_all(entries);
}

/// @brief 从块文件路径直接读出一整块条目,失败返回 false
inline bool read_block_file(const QString& path, QVector<PacketEntry>& entries) {
    BlockReader r;
    if (!r.open(path)) { entries.clear(); return false; }
    return r.read_all(entries);
}

}  // namespace pser

#endif  // BPLC_PACKETENTRY_SERIALIZE_H
