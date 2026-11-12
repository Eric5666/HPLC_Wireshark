/// @file sofparser.h
/// @brief SOF 帧解析模块声明(51242 SOF:FCH 字段 + PB 块/MSDU 重组)
/// @details 负责 SOF 帧 FCH 内业务字段(源/目的 TEI、LinkID、PBNum、TMI…)
///          与多 PB 块的 MSDU 跨帧重组(与 Python MPDU_Class 重组逻辑一致)。
///          重组状态 MsduState 定义于 bplcframe.h(由调用方持有,跨帧保活)。
#ifndef GW_2022_SOFPARSER_H
#define GW_2022_SOFPARSER_H

#include "bplcframe.h"

namespace gw_2022_sof {

/// @brief SOF FCH 字段解析 + 多 PB 重组
/// @param body      payload_for_log(自 FrameType 起,含 16B FCH)
/// @param info      [out] 填充 src/dst TEI、pb_size、pb_heads/pb_crc_oks 等
/// @param msdu      跨帧重组状态(多帧分段时由调用方在帧间保留)
/// @param complete_msdu_body [out] 重组完成的 MSDU body(未完成则为空)
/// @param band      PLC 频段号(0-3),用于查 gw_2022_pb_num_table 校验 PB 块数;
///                  0xFF(默认)= 非 PLC(HRF 等)
/// @param is_rf     是否无线信道帧:无线 SOF 走表30 字段格式——固定 1 个 PB 块,
///                  字节9 bit4-7 为载荷PB大小(表29)定 PB 大小、字节11 bit4-7 为 MCS,
///                  字节10-11 bit0/字节12 bit0-3 为保留;载波走表19(物理块个数/TMI)
/// @param crc_candidate_body [out,可选] 单站点帧重组后的完整体流,**不论 PB 块 CRC**
///                  (用户 2026-11 裁决,与南网同口径:「PB 块 CRC 失败但 MSDU CRC32 正确,
///                  MSDU 也要解析」)。仅当其 MSDU CRC32 三态不是 N-A 时调用方才可采用
///                  (OK ⇒ 原样解析;FAIL ⇒ msdu_crc_gate 只留证据);N-A 时必须回退
///                  `complete_msdu_body` 的保守门。多站点(OFDMA/TDA)帧不填。
/// @return 空字符串 = 成功;非空 = 错误文案(调用方拒收该帧)
QString assemble(const QByteArray& body, MpduInfo& info, MsduState& msdu,
                 QByteArray& complete_msdu_body, quint8 band = 0xFF,
                 bool is_rf = false, QByteArray* crc_candidate_body = nullptr);

}  // namespace gw_2022_sof

#endif // GW_2022_SOFPARSER_H
