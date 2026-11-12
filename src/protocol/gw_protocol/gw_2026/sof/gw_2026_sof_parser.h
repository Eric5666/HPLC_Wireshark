/// @file sofparser.h
/// @brief SOF 帧解析模块声明(HDC 2.0 SOF:FCH 字段 + PB 块/MSDU 重组)
/// @details 负责 SOF 帧 FCH 内业务字段(源/目的 TEI、帧长、载波表7 帧子类型/
///          TF/调制方式…、无线表19 载荷PB大小/MCS…)与多 PB 块的 MSDU 跨帧
///          重组(与 Python MPDU_Class 重组逻辑一致)。
///          重组状态 MsduState 定义于 bplcframe.h(由调用方持有,跨帧保活)。
#ifndef BPLC_GW_2026_SOF_PARSER_H
#define BPLC_GW_2026_SOF_PARSER_H

#include "bplcframe.h"
#include "pb_assembler.h"   // pb_asm::SpanLayout / msdu_span_avoids_bad_blocks

namespace gw_2026_sof {

/// @brief SOF FCH 字段解析 + 多 PB 重组
/// @param body      payload_for_log(自 FrameType 起,含 16B FCH)
/// @param info      [out] 填充 src/dst TEI、pb_size、pb_heads/pb_crc_oks 等
/// @param msdu      跨帧重组状态(多帧分段时由调用方在帧间保留)
/// @param complete_msdu_body [out] 重组完成的 MSDU body(未完成则为空)
/// @param band      PLC 频段号(0-3),用于查 gw_2026_pb_num_table 校验 PB 块数;
///                  0xFF(默认)= 非 PLC(HRF 等)
/// @param is_rf     是否无线信道帧:无线 SOF 走 HDC2.0 4-2 表19 字段格式——固定 1 个 PB 块,
///                  字节9 bit4-7 为载荷PB大小(表19)定 PB 大小、字节11 bit4-7 为 MCS,
///                  字节10-11 bit0/字节12 bit0-3 为保留;载波走表7(帧子类型/TF/调制
///                  方式与参数,链路标识符在 MAC 帧头 byte15)
/// @param crc_candidate_body [out,可选] 单站点帧重组后的完整体流,**不论 PB 块 CRC**
///                  (用户 2026-11 裁决,与南网同口径:「PB 块 CRC 失败但 MSDU CRC32 正确,
///                  MSDU 也要解析」)。仅当其 MSDU CRC32 三态不是 N-A 时调用方才可采用
///                  (OK ⇒ 原样解析;FAIL ⇒ msdu_crc_gate 只留证据);N-A 时必须回退
///                  `complete_msdu_body` 的保守门。多站点(OFDMA/TDA)帧不填。
/// @return 空字符串 = 成功;非空 = 错误文案(调用方拒收该帧)
QString assemble(const QByteArray& body, MpduInfo& info, MsduState& msdu,
                 QByteArray& complete_msdu_body, quint8 band = 0xFF,
                 bool is_rf = false, QByteArray* crc_candidate_body = nullptr);

/// @brief 本站 MSDU span 是否避开全部 CRC 失败块(用户 2026-10-29 定,NW 同款
/// 多块补定在 GW 的落点:多站点 OFDMA/TDA 逐站判定;单站点已由 assemble 的
/// seq 链等价覆盖,此处不另设门)。
/// @details span 口径与 GW MSDU 解析器一致(gw_2026_msdu_parser.cpp):
/// 简头(体[0]低 nibble==0x01):span=4+len+4,len 为体[2..3]低 11bit;
/// 标准头:头 16B,MACAddrFlag(体[11] bit3)置位时 28B,len 为体[8..9]低 11bit,
/// span=头+len+4。站体流为各块体依序拼接,坏块 j 区间为
/// [j*(pb_size-4),(j+1)*(pb_size-4));span 自 0 起,相交当且仅当
/// span > j*(pb_size-4)。体 <4B 或 pb_size<=4 时无法判定,返回 false。
/// ⚠ `crc_oks` 必须与 `body` **同序**(即 seq 序)。多站帧里 `st.pb_crc_oks` 是到达序,
///    必须先经 `station_msdu_parseable` 按 seq 归位再调本函数,否则坏块位置与体流
///    偏移错位(乱序时两向都可能判错)。
/// @details span 口径 = **国网**口径(`pb_asm::SpanLayout::Gw`),实现在
/// `pb_assembler.h::msdu_span_avoids_bad_blocks`——国网/南网头部布局不同,
/// 曾因复用南网公式导致两向误判(简头帧误拒、标准头帧误放行),勿再各自实现。
inline bool msdu_span_avoids_bad_blocks(const QByteArray& body,
                                        const QVector<bool>& crc_oks,
                                        int pb_size) {
    const int body_len = pb_size - 4;  // PB 头 1B + CRC24 3B
    return pb_asm::msdu_span_avoids_bad_blocks(body, crc_oks, body_len,
                                               pb_asm::SpanLayout::Gw);
}

/// @brief 本站 MSDU 是否可安全交给解析器(多站学习门)。
/// @details `st.pb_heads` / `st.pb_crc_oks` 是**到达序(线序)**——UI 的
///          `analyze_pb_seq_heads` 与逐块 CRC 成对显示都依赖它;而 `st.msdu` 是
///          **序列号重排后的 seq 序**体流(见 assemble 里的 `pb_asm::body_parseable`
///          → `res.msdu_body`)。两者序不同:直接拿到达序 CRC 的下标去跟 seq 序体流的
///          偏移比较,站内乱序时两向都会错——坏块在 seq 前段会**误放行**(坏块字节经
///          `merge_msdu_learn` 进 tei_mac_pairs/orig/topology),坏块在 seq 后段会**误拒**。
///          故判定前先按序列号把 CRC 归位成 seq 序数组,再用**国网口径**算 span。
/// @param seq_mask PB 头序列号掩码(国网 PB 头 1B:bit7=END / bit6=START / 低 6 位 = seq)
/// @return true = 本站全好,或首个 MSDU 的 span 完全避开 seq 序上的坏块
inline bool station_msdu_parseable(const SofStationPb& st, quint8 seq_mask = 0x3F) {
    if (st.msdu.isEmpty() || int(st.pb_size) <= 4) return false;
    const int n = st.pb_heads.size();
    if (n <= 0 || st.pb_crc_oks.size() != n) return false;
    // 全好 → 与块序无关,直接放行
    bool all_ok = true;
    for (bool ok : st.pb_crc_oks) all_ok = all_ok && ok;
    if (all_ok) return true;
    // 序列号全同 = 设备未填序列号,assemble 走 pb_asm 的 `seq_uniform_fallback`
    // 按到达位置拼接 → 此时体流序 == 到达序,CRC 直接按到达序用(不能按 seq 归位,
    // 否则会把 1..n-1 号槽当坏块,反而把正常帧判死)。
    bool uniform = true;
    for (int i = 1; i < n; ++i) {
        if ((quint8(st.pb_heads[i]) & seq_mask)
            != (quint8(st.pb_heads[0]) & seq_mask)) { uniform = false; break; }
    }
    if (uniform) {
        // 体流序 == 到达序 → CRC 直接按到达序用
        return msdu_span_avoids_bad_blocks(st.msdu, st.pb_crc_oks, int(st.pb_size));
    }
    // 按序列号归位:seq_crcs[seq] = 该 seq 块的 CRC。越界/缺失槽位保守记为 false
    // (不可信 → 按坏块处理,宁可少学习也不让坏块字节进拓扑)。
    QVector<bool> seq_crcs(n > int(st.pb_num) ? n : int(st.pb_num), false);
    for (int i = 0; i < n; ++i) {
        const int seq = int(quint8(st.pb_heads[i]) & seq_mask);
        if (seq < 0 || seq >= seq_crcs.size()) continue;
        seq_crcs[seq] = st.pb_crc_oks[i];
    }
    // 归位后 CRC 与体流同为 seq 序 → 交给国网口径的 span 判定
    return msdu_span_avoids_bad_blocks(st.msdu, seq_crcs, int(st.pb_size));
}

}  // namespace gw_2026_sof

#endif  // BPLC_GW_2026_SOF_PARSER_H
