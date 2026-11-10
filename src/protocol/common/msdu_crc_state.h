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

/// @brief 从字段树派生 MSDU CRC32 三态
/// @details 聚合/多站帧树里可能有多个 `MSDU CRC32` 节点:任一 FAIL ⇒ Fail;
///          否则任一 OK ⇒ Ok;都没有 ⇒ NotAvailable。
inline MsduCrcState msdu_crc_state(const MsduInfo& msdu) {
    bool seen_ok = false;
    bool seen_fail = false;
    for (const MsduFieldNode& n : msdu.tree) {
        if (n.name != QLatin1String("MSDU CRC32")) continue;
        if (n.value.contains(QLatin1String("FAIL"))) seen_fail = true;
        else if (n.value.contains(QLatin1String("OK"))) seen_ok = true;
    }
    if (seen_fail) return MsduCrcState::Fail;
    if (seen_ok) return MsduCrcState::Ok;
    return MsduCrcState::NotAvailable;
}

/// @brief 只保留 MSDU CRC32 证据节点的降级结果(MSDU CRC32 FAIL 时采用)
/// @details 用户 2026-11 裁决:MSDU CRC32 FAIL ⇒ 摘要为空、字段树只保留
///          `MSDU CRC32 … FAIL` 证据节点、整行标红(与 PB 块 CRC 同等待遇)。
///          载荷本身就不可信,故一并清掉由载荷派生的展示/拓扑信息
///          (主体 MAC、拓扑事件、TEI↔MAC 学习对、业务/管理类型),避免
///          把坏载荷当成实证写进拓扑与着色。
inline MsduInfo msdu_crc_fail_evidence(const MsduInfo& in) {
    MsduInfo out = in;
    out.present = true;          ///< 仍是"有 MSDU",只是内容不可采信
    out.summary.clear();
    QVector<MsduFieldNode> kept;
    for (const MsduFieldNode& n : in.tree)
        if (n.name == QLatin1String("MSDU CRC32")) kept.append(n);
    out.tree = kept;
    out.sta_mac = 0;
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

/// @brief 解析结果统一收敛:MSDU CRC32 FAIL ⇒ 降级为证据节点,其余原样返回
inline MsduInfo msdu_crc_gate(const MsduInfo& in) {
    return msdu_crc_state(in) == MsduCrcState::Fail ? msdu_crc_fail_evidence(in) : in;
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
