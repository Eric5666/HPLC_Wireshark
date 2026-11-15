/// @file beaconparser.h
/// @brief BEACON 帧载荷区解析器(移植自 BPLCMonitor/MPDU_Class.py)
/// @details 输入 MPDU(payload_for_log,自 FrameType 起),输出载荷区字段树:
///          载荷固定头(BeaconType/标志位/NetSN/CCO MAC/周期计数/RF 参数)
///          + BeaconMgrInfo 管理条目(STA Cap / Route Param / TSA 等)。
///          字段树复用 MsduFieldNode/MsduInfo(定义在 bplcframe.h)。
#ifndef BPLC_GW_2022_BEACON_PARSER_H
#define BPLC_GW_2022_BEACON_PARSER_H

#include "bplcframe.h"

// ================= 语义枚举(51242/51243 信标字段) =================

/// @brief 信标类型(51242 表39)
enum class GW_2022_BeaconType : quint8 {
    DISCOVERY = 0,  ///< 发现信标
    PROXY     = 1,  ///< 代理信标
    CENTRAL   = 2,  ///< 中央信标
};

/// @brief 相线(51242 表47/52/53)
enum class GW_2022_PhaseLine : quint8 {
    ALL_LINES = 0,  ///< 全相线
    LINE_A    = 1,  ///< A 相线
    LINE_B    = 2,  ///< B 相线
    LINE_C    = 3,  ///< C 相线
};

/// @brief 信标管理条目类型(51242 表46)
enum class GW_2022_BeaconItemType : quint8 {
    STA_CAPABILITY       = 0x00,  ///< 站点能力条目
    ROUTE_PARAMETER      = 0x01,  ///< 路由参数条目
    BAND_CHANGE          = 0x02,  ///< 频段变更条目
    RF_ROUTE_PARAMETER   = 0x03,  ///< 无线路由参数条目
    RF_CHANNEL_CHANGE    = 0x04,  ///< 无线信道变更条目
    LITE_STA_INFO_SLOT   = 0x05,  ///< 精简信标站点信息及时隙条目
    TIME_SLOT_ALLOCATION = 0xC0,  ///< 时隙分配条目(TSA)
};

/// @brief 无线信标发送模式(51242 表51):载波信标与无线信标的发送组合方式
enum class GW_2022_BeaconSendMode : quint8 {
    CARRIER_ONLY             = 0,  ///< 仅发送高速载波信标
    RF_STANDARD_ONLY         = 1,  ///< 仅发送无线标准信标
    CARRIER_THEN_RF_STANDARD = 2,  ///< 载波信标后发无线标准信标
    CARRIER_THEN_RF_LITE     = 3,  ///< 载波信标后发无线精简信标
    CARRIER_CSMA_RF_LITE     = 4,  ///< 载波信标+CSMA时隙发无线精简信标
};

/// @brief BEACON 载荷解析器(纯静态,无状态)
class GW_2022_BeaconParser {
public:
    /// @brief 解析 BEACON 帧载荷区
    /// @param payload_for_log 整帧 MPDU(payload_for_log,自 FrameType 起含 16B FCH)
    /// @return MsduInfo.tree 为字段树;present=false 表示载荷不可解析
    static MsduInfo parse_beacon(const QByteArray& payload_for_log);
};

#endif  // BPLC_GW_2022_BEACON_PARSER_H
