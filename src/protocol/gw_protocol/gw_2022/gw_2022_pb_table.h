/// @file gw_2022_pb_table.h
/// @brief 国网 GW_2022 协议参数:TMI → PB 块大小查表
/// @details 国网 HPLC TMI(分级拷贝基本模式)决定物理块大小,取值 0-14:
///   TMI 0-1 → 520;2-6 → 136;7-10 → 520;11-12 → 264;13-14 → 72。
///   信标/单块帧同样按 FCH TMI 查表;-1 = TMI 无效。
/// @note 南网 NW_2021 的 PB 大小定义不同(见 nw_protocol/nw_2021/nw_2021_pb_table.h),
///       故本表按协议+版本独立,不与其他协议共享。
#ifndef BPLC_GW_2022_PB_TABLE_H
#define BPLC_GW_2022_PB_TABLE_H

#include <QtGlobal>

/// 国网无线载荷 PB 大小码 → PB 块大小(字节)(表29:0-5 = 16/40/72/136/264/520)。-1 = 保留值
inline int gw_2022_rf_pb_size(quint8 code) {
    static const quint16 table[] = {16, 40, 72, 136, 264, 520};
    return (code <= 5) ? int(table[code]) : -1;
}

/// 国网 TMI → PB 块大小(字节)。-1 = TMI 无效
inline int gw_2022_pb_size(quint8 tmi) {
    if (tmi == 0 || tmi == 1)       return 520;
    if (tmi >= 2 && tmi <= 6)       return 136;
    if (tmi >= 7 && tmi <= 10)      return 520;
    if (tmi == 11 || tmi == 12)     return 264;
    if (tmi == 13 || tmi == 14)     return 72;
    return -1;
}

/// 国网各频段(PL band 0-3)× TMI/TMI_EXT 支持的最大 PB 块数量。
/// 列索引 0-15 = TMI 0x0-0xF;列 16-29 = TMI_EXT 1-14(TMI=0xF 时用扩展)。
inline constexpr quint8 gw_2022_pb_num_table[4][30] = {
    //  tmi: 0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f | 1  2  3  4  5  6  7  8  9  a  b  c  d  e
    { 4, 4, 4, 4, 4, 4, 4, 3, 4, 4, 4, 4, 4, 4, 4, 0,   4, 4, 4, 4, 4, 4, 0, 0, 0, 4, 4, 4, 4, 4 },  // PL band0
    { 3, 4, 4, 2, 4, 4, 4, 1, 1, 2, 3, 4, 2, 4, 4, 0,   4, 4, 4, 4, 4, 4, 0, 0, 0, 4, 4, 4, 4, 4 },  // PL band1
    { 2, 4, 4, 1, 2, 3, 4, 0, 1, 1, 2, 2, 1, 4, 4, 0,   4, 4, 4, 4, 4, 4, 0, 0, 0, 4, 4, 4, 4, 4 },  // PL band2
    { 1, 2, 3, 0, 1, 1, 2, 0, 0, 0, 1, 1, 0, 4, 2, 0,   4, 4, 4, 4, 2, 4, 0, 0, 0, 4, 4, 4, 4, 4 },  // PL band3
};

/// 查国网某频段 + TMI/TMI_EXT 支持的最大 PB 块数量。返回 -1 = 配置无效。
inline int gw_2022_max_pb_num(quint8 band, quint8 tmi, quint8 tmi_ext) {
    constexpr int kRows = sizeof(gw_2022_pb_num_table) / sizeof(gw_2022_pb_num_table[0]);
    if (band >= kRows) return -1;                   // 频段越界(表行数即有效频段数)
    int col;
    if (tmi <= 14) {
        col = tmi;                                  // TMI 主表(0x0-0xE)
    } else if (tmi_ext >= 1 && tmi_ext <= 14) {
        col = 16 + (tmi_ext - 1);                   // TMI=0xF → TMI_EXT 扩展(1-14)
    } else {
        return -1;                                  // TMI=0xF 且无有效 TMI_EXT
    }
    return gw_2022_pb_num_table[band][col];
}

#endif  // BPLC_GW_2022_PB_TABLE_H
