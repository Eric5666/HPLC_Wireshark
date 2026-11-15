/// @file nw_2026_pb_table.h
/// @brief 南网 NW_2026 协议参数:PB 块大小查表(载波 TMI / SPLC TMI编号 / 无线载荷 PB 大小)
/// @details SPLC 第3部分(物理层,试行)表13「SPLC 载荷数据的 ROBO 模式」+ 第4部分(数据链路层)表23:
///   (表13 于 2026-10-30 以 docs/protocol_doc/nw/SPLC/ 第3部分物理层文档逐项复核,28 项 TMI→PB 全一致)
///   - BPLC 版本(标准版本号=1)载波路径:TMI(载波映射表索引)→ PB size,取值 0-14;
///     TMI 13-14 转查 TMI_EXT
///   - SPLC 版本(标准版本号=2)载波路径:TMI编号(表23 byte6 bit1-5)→ PB size,
///     Bitloading标识=0 用 nw_2026_splc_pb_size,=1 用 nw_2026_splc_bitload_pb_size
///   - 无线路径:载荷 PB 大小(PBLen,表130)→ PB size,0-5 → 16/40/72/136/264/520
/// @note PB 大小映射见协议表(SPLC 第3部分物理层表13 / 第4部分数据链路层表23 / 无线表130)。与国网独立,勿共享。
#ifndef BPLC_NW_2026_PB_TABLE_H
#define BPLC_NW_2026_PB_TABLE_H

#include <QtGlobal>

/// 南网 BPLC 版载波路径 TMI → PB 块大小(字节)。-1 = TMI/TMI_EXT 无效
inline int nw_2026_pb_size(quint8 tmi, quint8 tmi_ext) {
    if (tmi == 0 || tmi == 1)                          return 520;
    if (tmi >= 2 && tmi <= 6)                          return 136;
    if (tmi >= 7 && tmi <= 10)                         return 520;
    if (tmi == 11 || tmi == 12)                        return 264;
    // TMI=0xD(13):转查扩展 TMI_EXT(BPLC-2 表121 j)节;14 无扩展定义 → -1
    if (tmi == 13) {
        if (tmi_ext >= 1 && tmi_ext <= 6)              return 520;
        if (tmi_ext >= 10 && tmi_ext <= 14)            return 136;
        return -1;
    }
    return -1;
}

/// 南网无线路径「载荷 PB 大小」(表130)→ PB 块大小(字节)。-1 = 无效
inline int nw_2026_rf_pb_size(quint8 pblen) {
    switch (pblen) {
        case 0: return 16;
        case 1: return 40;
        case 2: return 72;
        case 3: return 136;
        case 4: return 264;
        case 5: return 520;
        default: return -1;
    }
}

/// 南网 SPLC 版(标准版本号=2)载波 TMI编号 → PB 块大小(字节,第4部分表23/第3部分物理层表13):
/// 0-8→520 / 9-15→264 / 16-20→136 / 21-25→72 / 26-27→16。Bitloading标识=0 时使用。
inline int nw_2026_splc_pb_size(quint8 tmi_idx) {
    if (tmi_idx <= 8)  return 520;
    if (tmi_idx <= 15) return 264;
    if (tmi_idx <= 20) return 136;
    if (tmi_idx <= 25) return 72;
    if (tmi_idx <= 27) return 16;
    return -1;
}

/// 南网 SPLC 版 Bitloading标识=1 时 TMI编号 → 物理块大小(表23:0→136/1→520/2→72/3→264)。
inline int nw_2026_splc_bitload_pb_size(quint8 idx) {
    switch (idx) {
        case 0: return 136;
        case 1: return 520;
        case 2: return 72;
        case 3: return 264;
        default: return -1;
    }
}

/// 南网 SPLC 各频段(PL band 0-4,物理层表17 通信频段;5/6 保留)×
/// SPLC TMI 编号(0-27,物理层表13)支持的最大 PB 块数量。
/// 0 = 该组合不支持(拒收)。频段索引取 SPLC 单站点帧(SPLC-4 表23)
/// 「PL频段标识」(5,3,3)。
inline constexpr quint8 nw_2026_pb_num_table[5][28] = {
    // TMI:0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27
    { 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 },  // PL band0
    { 1, 1, 3, 4, 4, 4, 4, 4, 4, 2, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 },  // PL band1
    { 0, 1, 2, 4, 4, 4, 4, 4, 4, 1, 2, 4, 4, 4, 4, 4, 2, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 },  // PL band2
    { 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 },  // PL band3
    { 1, 3, 4, 4, 4, 4, 4, 4, 4, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 },  // PL band4
};

/// 查南网 SPLC 某频段 + TMI 编号支持的最大 PB 块数量。返回 -1 = 配置无效。
/// 0 = 该频段+TMI 组合不支持(调用方按非法拒收)。
inline int nw_2026_max_pb_num(quint8 band, quint8 tmi_idx) {
    constexpr int kRows = sizeof(nw_2026_pb_num_table) / sizeof(nw_2026_pb_num_table[0]);
    if (band >= kRows) return -1;                    // 频段越界(表行数即有效频段数)
    if (tmi_idx >= 28) return -1;                    // TMI 编号越界(表13 28 项)
    return nw_2026_pb_num_table[band][tmi_idx];
}

#endif  // BPLC_NW_2026_PB_TABLE_H
