/// @file nw_2021_beacon_parser.h
/// @brief 南网 NW_2021 信标帧载荷区解析器
/// @details 输入整帧 MPDU(自 FrameType 起含 16B FCH),输出信标帧载荷区字段树:
///          固定头(信标类型/标志位/组网序列号/短网络标识) + 信标管理信息 +
///          帧载荷校验序列(BPCS,32-bit CRC32) + 保留字节 + 物理块检查序列(24-bit)。
///          字段坐标对照数据链路层报批稿表24/表29 及 Python 参考 MPDU_BEACON_LOAD。
#ifndef BPLC_NW_2021_BEACON_PARSER_H
#define BPLC_NW_2021_BEACON_PARSER_H

#include "bplcframe.h"

/// 南网 NW_2021 信标类型(表25:0 发现/1 代理/2 中央)
enum class NW_2021_BeaconType : quint8 {
    DISCOVERY = 0,  ///< 发现信标
    PROXY     = 1,  ///< 代理信标
    CENTRAL   = 2,  ///< 中央信标
};

/// 南网 NW_2021 相线(表33站点相线:0 全相线/1 A/2 B/3 C;表15信标相线中 0=未知)
enum class NW_2021_PhaseLine : quint8 {
    ALL_LINES = 0,  ///< 全相线
    LINE_A    = 1,  ///< A 相线
    LINE_B    = 2,  ///< B 相线
    LINE_C    = 3,  ///< C 相线
};

/// 南网 NW_2021 站点角色(表33:0 未知/1 STA/2 PCO/4 CCO)
enum class NW_2021_StationType : quint8 {
    UNKNOWN = 0,  ///< 未知
    STA     = 1,  ///< STA 站点
    PCO     = 2,  ///< PCO 站点
    CCO     = 4,  ///< CCO 站点
};

/// 南网 NW_2021 信标条目类型(表31)
enum class NW_2021_BeaconItemType : quint8 {
    STA_CAPABILITY = 0x01,  ///< 站点能力条目
    TIME_SLOT_ALLOC = 0x02, ///< 时隙分配条目
    ROUTE_PARAM     = 0x06, ///< 路由参数条目
    BAND_CHANGE     = 0x07, ///< 频段变更条目
    BAND_PROBE      = 0x0A, ///< 频段探测条目
    CALENDAR_SYNC   = 0x0B, ///< 万年历同步条目
    RF_ROUTE_PARAM  = 0x0C, ///< 无线路由参数条目(表142;表152 头列 0x09 为旧编号残留)
    RF_CHANNEL_CHANGE = 0x0D, ///< 无线信道变更条目(表142;表153 头列 0x0A 为旧编号残留)
    LITE_STA_SLOT   = 0x0E, ///< 精简信标站点信息及时隙条目(表142/表155)
};

namespace NW_2021_BeaconParser {

/// @brief 解析南网信标帧载荷区
/// @param payload 整帧 MPDU(payload_for_log,自 FrameType 起含 16B FCH)
/// @param pbsize  信标物理块大小(由 FCH TMI 决定,如 136/520)
/// @param is_rf   无线介质时固定头按第2部分表134(含精简信标标志/本网络无线
///                option/信道编号),载波按数据链路层表24
/// @return MsduInfo.tree 为字段树(相对载荷区起点,即 payload 偏移 16);
///         present=false 表示载荷不可解析
MsduInfo parse_beacon(const QByteArray& payload, int pbsize, bool is_rf);

}  // namespace NW_2021_BeaconParser

#endif  // BPLC_NW_2021_BEACON_PARSER_H
