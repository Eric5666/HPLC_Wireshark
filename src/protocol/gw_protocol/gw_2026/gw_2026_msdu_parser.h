/// @file msduparser.h
/// @brief MSDU/MAC 层完整字段解析器(移植自 BPLCMonitor/MSDU_Class.py)
/// @details 输入 SOF 重组出的完整 MSDU 载荷(含 MSDU_BASE 头 + 体 + CRC32),
///          输出结构化的 MsduInfo 字段树(节点定义在 bplcframe.h)。
///          覆盖回放数据实际出现的类型:
///            MSDUType 0(网管):AssocReq/AssocCnf/ChangeProxyReq/
///                              ChangeProxyBitMapCnf/HeartBeatCheck/
///                              DiscoverNodeList/SuccessRateReport
///            MSDUType 48(应用):APP_BASE + PacketID 0x0008 EventPacket
#ifndef BPLC_GW_2026_MSDU_PARSER_H
#define BPLC_GW_2026_MSDU_PARSER_H

#include "bplcframe.h"

/// @brief 网络管理消息类型(MMe_BASE.MMType,HDC 2.0 表43,16bit 值取低 8bit)
/// @note HDC 2.0 变更:0x0008 发现列表改保留(发现列表改经信标条目 0xC2/单跳帧
///       无线发现列表承载);0x0050-0x007F 整段保留(旧路由修复族 0x50-0x55 废弃);
///       新增 0x0011/0x0012 Bitloading 训练请求/拒绝、0x0013/0x0014 分组请求/确认。
enum class GW_2026_MMeType : quint8 {
    MME_ASSOC_REQ                   = 0x00,
    MME_ASSOC_CNF                   = 0x01,
    MME_ASSOC_GATHER_IND            = 0x02,
    MME_CHANGE_PROXY_REQ            = 0x03,
    MME_CHANGE_PROXY_CNF            = 0x04,
    MME_CHANGE_PROXY_BITMAP_CNF     = 0x05,
    MME_LEAVE_IND                   = 0x06,
    MME_HEARTBEAT_CHECK             = 0x07,
    MME_RESERVED_08                 = 0x08,  ///< 保留(表43;旧版发现列表)
    MME_SUCCESS_RATE_REPORT         = 0x09,
    MME_NETWORK_CONFLICT_REPORT     = 0x0A,
    MME_ZERO_CROSS_NTB_COLLECT_IND  = 0x0B,
    MME_ZERO_CROSS_NTB_REPORT       = 0x0C,
    MME_BITLOADING_TRAIN_REQ        = 0x11,  ///< Bitloading 训练请求(表104)
    MME_BITLOADING_TRAIN_REQ_REJECT = 0x12,  ///< Bitloading 训练请求拒绝(表105)
    MME_GROUP_REQ                   = 0x13,  ///< 分组请求报文(表109/110)
    MME_GROUP_CNF                   = 0x14,  ///< 分组确认报文(表111/112)
    MME_DIAGNOSE                    = 0x4F,
    MME_RF_CHANNEL_CONFLICT_REPORT  = 0x80,
};

/// @brief 应用层业务标识(APP_BASE.PacketID,表2 报文ID,16bit)
enum class GW_2026_AppBid : quint16 {
    TERMINAL_METER_READING               = 0x0001,  // 终端主动抄表
    ROUTER_METER_READING                 = 0x0002,  // 路由主动抄表
    TERMINAL_CONCURRENT_METER_READING    = 0x0003,  // 终端主动并发抄表
    TIME_SYNC                            = 0x0004,  // 校时
    COMM_TEST                            = 0x0006,  // 通信测试
    EVENT_REPORT                         = 0x0008,  // 事件上报
    QUERY_SLAVE_REGISTRATION             = 0x0011,  // 查询从节点主动注册
    START_SLAVE_REGISTRATION             = 0x0012,  // 启动从节点主动注册
    STOP_SLAVE_REGISTRATION              = 0x0013,  // 停止从节点主动注册
    CONFIRM_DENY                         = 0x0020,  // 确认/否认
    START_UPGRADE                        = 0x0030,  // 开始升级
    STOP_UPGRADE                         = 0x0031,  // 停止升级
    TRANSFER_FILE_DATA                   = 0x0032,  // 传输文件数据
    TRANSFER_FILE_DATA_UNICAST_TO_LOCAL_BROADCAST = 0x0033,  // 传输文件数据(单播转本地广播)
    QUERY_NODE_UPGRADE_STATUS            = 0x0034,  // 查询站点升级状态
    EXECUTE_UPGRADE                      = 0x0035,  // 执行升级
    QUERY_NODE_INFO                      = 0x0036,  // 查询站点信息
    METER_CONTROLLER_CCO                 = 0x0040,  // 抄控器 CCO
    METER_CONTROLLER_SERIAL_FORWARDING   = 0x0041,  // 抄控器数据透传串口转发
    AUTH_SECURITY                        = 0x00A0,  // 鉴权安全
    TRANSFORMER_AREA_RELATION            = 0x00A1,  // 台区户变关系识别
    QUERY_ID_INFO                        = 0x00A2,  // 查询ID信息
    PRECISE_TIME_SYNC                    = 0x00A3,  // 精准校时
    DISTRIBUTION_INFO_REPORT             = 0x00A4,  // 配电信息上报
    STORAGE_COLLECT_EXT_CONFIG           = 0x00B0,  // 存储采集扩展配置
    STORAGE_DATA_BROADCAST_SCHEDULE      = 0x00B1,  // 存储数据广播时规
    STORAGE_DATA_SYNC_CONFIG             = 0x00B2,  // 存储数据同步配置
    TERMINAL_CONCURRENT_METER_READING_EXT = 0x00B3,  // 终端主动并发抄表(扩展)
    AUTHENTICATION                       = 0x00C1,  // 认证
    STORE_HRF_RELAY_HEARTBEAT            = 0x00CC,  // 存储 HRF 中继心跳
};

/// @brief 应用层报文端口号(APP_BASE.PortNum,表2 报文端口号,8bit)
enum class GW_2026_PortNum : quint8 {
    MANAGEMENT_METER_READING = 0x11,  // 管理/抄表端口
    UPGRADE                   = 0x12,  // 升级端口
    SECURITY                  = 0x1A,  // 安全端口
};

/// @brief 标准头 MSDUType 取值(MSDU_BASE.MSDUType,8bit)
enum class GW_2026_MsduType : quint8 {
    NET_MANAGEMENT = 0x00,  // 网络管理消息
    APPLICATION    = 0x30,  // 应用层消息 (48)
    IP             = 0x31,  // IP 消息 (49)
};

/// @brief 简头消息类型取值(MSDU_BASE_S.消息类型,8bit,表3/5.1.1.4)
enum class GW_2026_MsduSType : quint8 {
    DISCOVERY_LIST    = 0x00,  // 无线发现列表消息(表3;载荷=表91 无线发现列表报文)
    CHANNEL_EVAL      = 0x01,  // 信道评估参数更新报文(表3;载荷=表106-108)
    CARRIER_DISCOVERY = 0x02,  // 载波发现列表消息(表3;载荷=表62 载波发现列表报文,表68/77 含 BRU 变体)
    APPLICATION       = 0x80,  // 应用层消息 (128)
    IPV4              = 0x81,  // IPv4 消息 (129)
};

/// @brief MSDU 解析器(纯静态,无状态)
class GW_2026_MsduParser {
public:
    /// @brief 解析完整 MSDU
    /// @param body  重组后的完整 MSDU(MSDU_BASE 起,含尾 CRC32)
    static MsduInfo parse(const QByteArray& body);
};

#endif  // BPLC_GW_2026_MSDU_PARSER_H
