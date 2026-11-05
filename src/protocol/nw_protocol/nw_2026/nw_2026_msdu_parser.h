/// @file nw_2026_msdu_parser.h
/// @brief 南网 NW_2026 MSDU/MAC 层解析器(头解析,管理消息后续补)
/// @details 输入 SOF 重组出的 MAC 帧(MAC 帧头 + MSDU + CRC32),解析:
///          - MAC 帧头(MSDU_BASE 32B 长/12B 短):TEI/SNID/重启次数/广播方向/目的 MAC
///          - MSDU 帧头(MSDU_LONGHEAD 18B / SHORTHEAD 2B):MAC 48b + VLAN + MSDU 类型
///          字段坐标移植自 MSDU_Class.py(MSDU_BASE/MSDU_LONGHEAD/MSDU_SHORTHEAD)。
#ifndef NW_2026_MSDU_PARSER_H
#define NW_2026_MSDU_PARSER_H

#include "bplcframe.h"

/// @brief 南网 NW_2026 应用层帧类型域(业务报文头控制域 bit0-3,表4)
enum class NW_2026_PacketType : quint8 {
    AckNack       = 0x0,  ///< 确认/否认
    DataForward   = 0x1,  ///< 数据转发帧
    Command       = 0x2,  ///< 命令帧
    EventReport   = 0x3,  ///< 主动上报帧
    ReaderFrame   = 0x4,  ///< 抄控器相关协议
    BroadcastCmd  = 0x5,  ///< 广播命令帧
    DataSubscribe = 0x6,  ///< 数据订阅路由帧
    Test          = 0xE,  ///< 厂家调试帧
    FactoryFrame  = 0xF,  ///< 厂测帧
};

/// @brief 确认/否认帧业务标识(表9,报文端口 0x11)
enum class NW_2026_AckNackBid : quint8 {
    Confirm = 0x00,  ///< 确认
    Deny    = 0x01,  ///< 否认
};

/// @brief 数据转发帧业务标识(表9,必须按 (报文端口号, 业务标识) 联合判定)
/// @note  释义统一由 src/protocol/common/nw_app_bid.cpp 提供(2021/2026 共用):
///        应用层 6.3.2 表9(2021/2026 共用;2026 为超集)。
enum class NW_2026_DataForwardBid : quint8 {
    ToDevice               = 0x00,  ///< 数据透传至设备(端口 0x11,表9)
    ToModule               = 0x01,  ///< 数据透传至模块(端口 0x13,表9)
    ConcurrentMeterReading = 0x02,  ///< 并发抄读端设备(端口 0x11,表9)
    InterStationComm       = 0x03,  ///< 站点间通信(端口 0x13,表9)
};

/// @brief 命令帧业务标识(表9)
enum class NW_2026_CommandBid : quint8 {
    QuerySearchResult    = 0x00,  ///< 查询终端搜索结果(0x11)
    IssueSearchList      = 0x01,  ///< 下发搜索终端列表(0x11)
    FileTransfer         = 0x02,  ///< 文件传输(0x11)
    EnableDisableNodeEv  = 0x03,  ///< 允许/禁止从节点事件(0x11)
    NodeRestart          = 0x04,  ///< 从节点重启(0x11)
    NodeInfoQuery        = 0x05,  ///< 从节点信息查询(0x11)
    IssueCommAddrMap     = 0x06,  ///< 下发通信地址映射表列表(0x11)
    QueryNodeRunStatus   = 0x07,  ///< 查询从节点运行状态信息(0x13)
    QueryNodeChannelInfo = 0x08,  ///< 查询从节点信道信息(0x13)
    QueryModuleRunParam  = 0x09,  ///< 查询模块运行参数(0x13)
    PhaseIdent           = 0x10,  ///< 台区户变关系/相位识别(0x11)
    TestFrame            = 0xF0,  ///< 测试帧(0x11)
};

/// @brief 主动上报帧业务标识(表9)
enum class NW_2026_EventReportBid : quint8 {
    MeterEvent  = 0x00,  ///< 电表事件主动上报(0x11)
    PowerOnOff  = 0x01,  ///< 停上电事件上报(0x13)
    DeviceEvent = 0x02,  ///< 设备事件主动上报(0x11)/通信模块事件上报(0x13)
};

/// @brief 抄控器协议帧业务标识(表9,报文端口 0x11)
enum class NW_2026_ReaderFrameBid : quint8 {
    CcoProtocol   = 0x00,  ///< 抄控器-CCO 协议
    SerialForward = 0x01,  ///< 数据透传串口转发
};

/// @brief 广播命令帧业务标识(表9)
enum class NW_2026_BroadcastCmdBid : quint8 {
    NodeRestart          = 0x04,  ///< 从节点重启(0x11)
    NodeInfoQuery        = 0x05,  ///< 从节点信息查询(0x11)
    QueryNodeRunStatus   = 0x07,  ///< 查询从节点运行状态信息(0x13)
    QueryNodeChannelInfo = 0x08,  ///< 查询从节点信道信息(0x13)
};

/// @brief 南网 MMe 管理消息类型(MMType 16-bit,MMe_BASE 字节1-2)
enum class NW_2026_MMeType : quint16 {
    MME_ASSOCREQ            = 0x0030,
    MME_ASSOCCNF            = 0x0031,
    MME_CHANGEPROXYREQ      = 0x0032,
    MME_ASSOCIND            = 0x0034,
    MME_CHANGEPROXYCNF      = 0x0037,
    MME_ASSOCGATHERIND      = 0x003A,
    MME_CHANGEPROXYBITMAPCNF = 0x003B,
    MME_LEAVEIND            = 0x0049,
    MME_HEARTBEATCHECK      = 0x0051,
    MME_DISCOVERNODELIST    = 0x0055,
    MME_DELAYLEAVEIND       = 0x005D,
    MME_SUCCESSRATEREPORT   = 0x005E,
    MME_NETWORKCONFLICTREPORT = 0x005F,  ///< 网络冲突上报(第2部分无线表158)
    MME_ZEROCROSSNTBCOLLECTIND = 0x0062,
    MME_ZEROCROSSNTBREPORT  = 0x0063,
    MME_NETDIAGNOSE         = 0x0064,
    MME_RFCHANNELCONFLICTREPORT = 0x0070,  ///< 无线信道冲突上报(第2部分无线表158)
    // ---- SPLC 新增管理消息(SPLC 数据链路层 §5.1.4.19-5.1.4.24,表153-164) ----
    MME_BITLOAD_UPDATE_REQ   = 0x0080,  ///< Bitloading训练结果更新请求
    MME_BITLOAD_UPDATE_CNF   = 0x0081,  ///< Bitloading训练结果更新确认
    MME_RUSNR_INFO_IND       = 0x0082,  ///< RU_SNR信息告知
    MME_TEI_LIST_REQ         = 0x0083,  ///< 站点TEI列表请求
    MME_TEI_LIST_CNF         = 0x0084,  ///< 站点TEI列表回复
    MME_EXT_NETWORK_CONFLICT_RPT = 0x0085,  ///< 扩展网络冲突上报报文
    // ---- SPLC 物联终端接入系列(SPLC 数据链路层 §6.2.3.2,表243-247) ----
    MME_IOT_ASSOC_REQ   = 0x00A0,  ///< 物联终端接入请求(表243)
    MME_IOT_ASSOC_IND   = 0x00A1,  ///< 物联终端接入确认(表244)
    MME_IOT_LEAVE_IND   = 0x00A2,  ///< 物联终端离线指示(表246)
};

/// @brief 报文端口号(6.1:0x11 业务报文 0x13 管理报文)
enum class NW_2026_PortNum : quint8 {
    BUSINESS_PORT = 0x11,  ///< 业务报文
    MGMT_PORT     = 0x13,  ///< 管理报文
};

/// @brief 报文标识符(6.2:应用层报文固定 0x0101)
enum class NW_2026_PacketId : quint16 {
    APP_PACKET = 0x0101,  ///< CCO-STA 应用层报文
};

/// @brief MSDU 类型(表1:0x88E1 管理消息报文 0x01 应用层报文)
enum class NW_2026_MsduType : quint16 {
    MANAGEMENT_MESSAGE = 0x88E1,  ///< 管理消息报文
    APPLICATION_PACKET = 0x0001,  ///< 应用层报文
};

/// @brief VLAN 标签(0x8100 = 长帧头管理消息)
enum class NW_2026_VlanTag : quint32 {
    MANAGEMENT = 0x8100,  ///< 管理消息 VLAN 标签
};

/// @brief MAC 帧版本(帧头 bit1-2,表6:0 保留 1 本标准协议 2-3 保留)
enum class NW_2026_MacVersion : quint8 {
    STANDARD   = 0x1,  ///< 标准帧(MSDU_BASE)
};

/// @brief MAC 帧头标志(0 长帧头 32B,1 短帧头 12B)
enum class NW_2026_MacHeadFlag : quint8 {
    LONG_HEAD  = 0x0,  ///< 长帧头(32B)
    SHORT_HEAD = 0x1,  ///< 短帧头(12B)
};

/// @brief 南网 MSDU 解析器(纯静态,无状态)
class NW_2026_MsduParser {
public:
    /// @brief 解析完整 MAC 帧(MAC 帧头起,含尾 CRC32)
    /// @param body  重组后的完整 MAC 帧(MSDU_BASE 起)
    static MsduInfo parse(const QByteArray& body);
};

#endif // NW_2026_MSDU_PARSER_H
