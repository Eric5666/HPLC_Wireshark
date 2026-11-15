/// @file gw_2022_mcs.h
/// @brief 国网 GW_2022 协议参数:MCS 取值释义(表28:分集次数/调制方式/码率)
/// @details MCS 取值 0-6 为有效组合,7 以上保留。信标(表27)与 SOF(表30)字段树共用,
///          避免两处各自复制释义数组导致静默发散。
/// @note 与南网第2部分表129 逐值相同;但按协议独立维护(同南网 NW_2021 的
///       nw_mcs_text 一样各自持表,不跨协议共享)。
#ifndef BPLC_GW_2022_MCS_H
#define BPLC_GW_2022_MCS_H

#include <QtGlobal>

/// 国网 MCS 取值中文释义(表28:分集次数/调制方式/码率)。
/// 索引 0-6 有效;7+ 返回 nullptr(调用方以「保留」兜底)。
inline const char* gw_2022_mcs_desc(quint8 mcs) {
    static const char* const kDesc[] = {
        "分集4次 BPSK 码率1/2", "分集2次 BPSK 码率1/2",
        "分集2次 QPSK 码率1/2", "分集1次 QPSK 码率1/2",
        "分集1次 QPSK 码率4/5", "分集1次 16QAM 码率1/2",
        "分集1次 16QAM 码率4/5",
    };
    return (mcs <= 6) ? kDesc[mcs] : nullptr;
}

#endif  // BPLC_GW_2022_MCS_H
