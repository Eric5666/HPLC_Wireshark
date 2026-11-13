/// @file msdu_crc_state.h
/// @brief MSDU CRC32 三态判定(header-only):parser 与 UI 共用同一实现
/// @details 依据:各协议 MSDU 解析器在字段树尾部追加名为 `MSDU CRC32` 的节点,
///          值形如 `0x5D813887 OK` / `0x5D813887 FAIL`(MSDU 帧尾 4B CRC32;
///          国网 HDC2.0 表7 数据帧可变区域后的 4B、南网 SPLC 第4部分同款)。
/// @note 为什么不加字段:`MsduInfo` 全字段都进盘块序列化(write_msdu_info),
///       新增字段等于改块格式,违反「块版本严格相等、不迁移」铁律;
///       故三态一律从**已序列化**的字段树派生。
/// @note header-only:全仓 30+ 探针构建文件直接编译各 parser,引入 .cpp 会 undefined reference
///       (与 nw_app_bid.h 同一约定)。
#ifndef MSDU_CRC_STATE_H
#define MSDU_CRC_STATE_H

#include "bplcframe.h"

/// @brief MSDU CRC32 三态
enum class MsduCrcState {
    NotAvailable, ///< 无 CRC 节点/字节不足 4B(如单跳简头、截断):维持现状解析,不因缺失标红
    Ok,           ///< 校验通过
    Fail,         ///< 校验失败:摘要清空,字段树只留证据节点,整行标红
};

/// @brief 递归扫描字段树(含所有层级 children),统计 MSDU CRC32 节点的 OK/FAIL
inline void msdu_crc_scan(const QVector<MsduFieldNode>& nodes, bool& seen_ok, bool& seen_fail) {
    for (const MsduFieldNode& n : nodes) {
        if (n.name == QLatin1String("MSDU CRC32")) {
            if (n.value.contains(QLatin1String("FAIL"))) seen_fail = true;
            else if (n.value.contains(QLatin1String("OK"))) seen_ok = true;
        }
        msdu_crc_scan(n.children, seen_ok, seen_fail);
    }
}

/// @brief 从字段树派生 MSDU CRC32 三态(递归遍历整棵树)
/// @details 聚合/多站帧树里 `MSDU CRC32` 节点可能挂在 `Cascade MAC Frame[N]` 等分组下,
///          不能只扫顶层(否则嵌套 FAIL 被判成 N/A ⇒ 不标红/不降级)。任一 FAIL ⇒ Fail;
///          否则任一 OK ⇒ Ok;都没有 ⇒ NotAvailable。
inline MsduCrcState msdu_crc_state(const MsduInfo& msdu) {
    bool seen_ok = false;
    bool seen_fail = false;
    msdu_crc_scan(msdu.tree, seen_ok, seen_fail);
    if (seen_fail) return MsduCrcState::Fail;
    if (seen_ok) return MsduCrcState::Ok;
    return MsduCrcState::NotAvailable;
}

/// @brief 递归裁剪:只保留 MSDU CRC32 证据节点及其祖先分组(父链),rel_start/rel_len 原样
/// @details 分组节点下若已无任何 CRC 后代(含更深层),则该分组整体丢弃。
///          保留分组节点自身(名字/rel 区间)是为了让高亮映射与证据仍可定位。
inline void msdu_crc_prune(const QVector<MsduFieldNode>& in, QVector<MsduFieldNode>& out) {
    for (const MsduFieldNode& n : in) {
        if (n.name == QLatin1String("MSDU CRC32")) {
            out.append(n);                       // 证据叶节点,原样保留(含 rel_start/rel_len)
            continue;
        }
        QVector<MsduFieldNode> kids;
        msdu_crc_prune(n.children, kids);
        if (!kids.isEmpty()) {
            MsduFieldNode copy = n;              // 保留祖先分组(名字/rel 原样)
            copy.children = kids;
            out.append(copy);
        }
    }
}

/// @brief 只保留 MSDU CRC32 证据节点(及其祖先分组)的降级结果(MSDU CRC32 FAIL 时采用)
/// @details 用户 2026-11 裁决:MSDU CRC32 FAIL ⇒ 摘要为空、字段树只保留
///          `MSDU CRC32 … FAIL` 证据节点(递归裁剪,保留其祖先分组)、整行标红
///          (与 PB 块 CRC 同等待遇)。载荷本身就不可信,故一并清掉由载荷派生的
///          展示/拓扑信息(主体 MAC、拓扑事件、TEI↔MAC 学习对、业务/管理类型),
///          避免把坏载荷当成实证写进拓扑与着色。
inline MsduInfo msdu_crc_fail_evidence(const MsduInfo& in) {
    MsduInfo out = in;
    out.present = true;          ///< 仍是"有 MSDU",只是内容不可采信
    out.summary.clear();
    QVector<MsduFieldNode> kept;
    msdu_crc_prune(in.tree, kept);
    out.tree = kept;
    out.sta_mac = 0;
    // CRC32 FAIL makes every payload-derived scalar unusable too. In particular,
    // topo_input consumes these fields independently of the field tree.
    out.simple_head = false;
    out.msdu_seq = 0;
    out.msdu_src_tei = -1;
    out.msdu_dst_tei = -1;
    out.msdu_send_type = -1;
    out.msdu_src_mac = 0;
    out.msdu_dst_mac = 0;
    out.vlan_tag = 0;
    out.msdu_type = 0;
    out.restart_count = kRestartCountInvalid;
    out.broadcast_direction = 0xFF;
    out.route_hops_left = 0xFF;
    out.total_len = -1;
    out.tei_mac_pairs.clear();
    out.orig_srcs.clear();
    out.orig_dsts.clear();
    out.topo_event = TopoEvent();
    out.topo_extra_events.clear();
    out.mme_type = kMMeTypeNone;
    out.business_id = 0xFF;
    out.app_packet_type = 0xFF;
    out.trans_direction_flag = 0xFF;
    return out;
}

/// @brief 剥离拓扑学习用字段(MSDU CRC32 不可用且 PB 回退也不成立时采用)。
/// @details 保留解析与展示(present/summary/字段树/显示用标量原样),只清掉
///          会进拓扑学习的数据:拓扑事件(首事件与后续事件)、TEI↔MAC 学习对、
///          原始源/目的、发送方 TEI/MAC(TopoState 按发送方建身份基线、判重启、
///          复活离线节点)与重启次数(TopoState 按帧 restart_count 采样)。
///          与多站路径 msdu_crc_allows_learning 返回 false 时"不 merge 学习"
///          语义对齐。MSDU CRC32 FAIL 仍走 msdu_crc_gate 降级,不走这里;
///          Ok 时原样保留,学习不受影响。
inline MsduInfo msdu_crc_strip_learning(const MsduInfo& in) {
    MsduInfo out = in;
    out.topo_event = TopoEvent();
    out.topo_extra_events.clear();
    out.tei_mac_pairs.clear();
    out.orig_srcs.clear();
    out.orig_dsts.clear();
    out.msdu_src_tei = -1;
    out.msdu_src_mac = 0;
    out.restart_count = kRestartCountInvalid;
    return out;
}

/// @brief 解析结果统一收敛:MSDU CRC32 FAIL ⇒ 降级为证据节点,其余原样返回
inline MsduInfo msdu_crc_gate(const MsduInfo& in) {
    return msdu_crc_state(in) == MsduCrcState::Fail ? msdu_crc_fail_evidence(in) : in;
}

/// @brief MSDU CRC32 outranks PB-block CRC for topology learning.
/// @param pb_fallback_ok Legacy structural/PB check, used only when this MSDU has
///        no available CRC32 evidence. A valid MSDU CRC permits learning even if
///        one or more PB CRCs failed; a failed MSDU CRC never permits it.
inline bool msdu_crc_allows_learning(const MsduInfo& msdu, bool pb_fallback_ok) {
    const MsduCrcState state = msdu_crc_state(msdu);
    return state == MsduCrcState::Ok
        || (state == MsduCrcState::NotAvailable && pb_fallback_ok);
}

/// @brief 整行"CRC 失败标红"判据(UI 与探针共用,避免判据漂移)
/// @details 用户 2026-11 裁决:「DROP 只有在 fc crc 就失败时标记,否则应先解析,存在 CRC
///          失败即标记红色」「MSDU CRC32 FAIL 也标红(与 PB 同等待遇)」。
///          任一成立即红:
///           1. FCH(FC) CRC24 校验过且失败;
///           2. 任一 PB 块 CRC24 失败;
///           3. 已尝试组装且帧级未通过(含截断;合法 0 块帧 pb_size=0 不进此条);
///           4. MSDU 帧尾 CRC32 失败。
inline bool frame_crc_red(const PacketEntry& e) {
    if (e.mpdu.fch_crc_checked && !e.mpdu.fch_crc_ok) return true;
    for (bool ok : e.mpdu.pb_crc_oks)
        if (!ok) return true;
    if (e.mpdu.pb_size > 8 && e.mpdu.pb_num > 0 && !e.mpdu.pb_crc_ok) return true;
    if (e.msdu.present && msdu_crc_state(e.msdu) == MsduCrcState::Fail) return true;
    return false;
}

#endif // MSDU_CRC_STATE_H
