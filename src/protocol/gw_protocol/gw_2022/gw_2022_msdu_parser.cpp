/// @file msduparser.cpp
/// @brief MSDU 解析器实现
/// @details 字段位域坐标与 Python MSDU_Class.py 的 BitDefine 定义一一对应。
///          解析 = 公共头(MSDU_BASE/MSDU_BASE_S) + 类型分支(MMe / APP)。
#include "gw_2022_msdu_parser.h"
#include "common/fieldspec.h"
#include "crc.h"
#include "i18n.h"
#include "parse_anomaly.h"
#include <QtEndian>
#include <cstdint>

// ---------- 工具:取位域(与 bplcparser 同算法,本地独立实现) ----------
// ================= 公共头字段表(Python MSDU_BASE) =================
static const FieldSpec kMsduBaseSpec[] = {
    {"Version",             0, 0, 4,  Fmt::DEC},
    {"SourceTEI",           0, 4, 12, Fmt::DEC},
    {"DestinationTEI",      2, 0, 12, Fmt::DEC},
    {"SendType",            3, 4, 4,  Fmt::DEC},
    {"MaxSendCountLimit",   4, 0, 5,  Fmt::DEC},
    {"RSV0",                4, 5, 3,  Fmt::DEC},
    {"MSDU Seq",            5, 0, 16, Fmt::DEC},
    {"MSDUType",            7, 0, 8,  Fmt::DEC},
    {"MSDULen",             8, 0, 11, Fmt::DEC},
    {"RestartCount",        9, 3, 4,  Fmt::DEC},
    {"MainProxyFlag",       9, 7, 1,  Fmt::DEC},
    {"RouteHopsTotalNum",  10, 0, 4,  Fmt::DEC},
    {"RouteHopsLeftNum",   10, 4, 4,  Fmt::DEC},
    {"BroadcastDirection", 11, 0, 2,  Fmt::DEC},
    {"PathRepairFlag",     11, 2, 1,  Fmt::DEC},
    {"MACAddrFlag",        11, 3, 1,  Fmt::DEC},
    {"RSV1",               11, 4, 12, Fmt::DEC},
    {"NetSN",              13, 0, 8,  Fmt::DEC},
    {"RSV2",               14, 0, 8,  Fmt::DEC},
    {"RSV3",               15, 0, 8,  Fmt::DEC},
};
static const int kMsduBaseSpecN = int(sizeof(kMsduBaseSpec) / sizeof(kMsduBaseSpec[0]));

// 扩展 MAC 地址字段(仅在 MACAddrFlag=1 时追加)
static const FieldSpec kMsduMacSpec[] = {
    {"SourceMACAddr",      16, 0, 48, Fmt::MAC},
    {"DestinationMACAddr", 22, 0, 48, Fmt::MAC},
};

// ================= MMe 公共头(MMe_BASE):MMType(0,0,8) RSV(2,0,8) =================
static QString mme_type_name(quint8 t) {
    switch (static_cast<GW_2022_MMeType>(t)) {
        case GW_2022_MMeType::MME_ASSOC_REQ: return trl::L("关联请求");
        case GW_2022_MMeType::MME_ASSOC_CNF: return trl::L("关联确认");
        case GW_2022_MMeType::MME_ASSOC_GATHER_IND: return trl::L("关联汇总指示");
        case GW_2022_MMeType::MME_CHANGE_PROXY_REQ: return trl::L("代理变更请求");
        case GW_2022_MMeType::MME_CHANGE_PROXY_CNF: return trl::L("代理变更确认");
        case GW_2022_MMeType::MME_CHANGE_PROXY_BITMAP_CNF: return trl::L("代理变更确认位图版");
        case GW_2022_MMeType::MME_LEAVE_IND: return trl::L("离线指示");
        case GW_2022_MMeType::MME_HEARTBEAT_CHECK: return trl::L("心跳检测");
        case GW_2022_MMeType::MME_DISCOVER_NODE_LIST: return trl::L("发现列表");
        case GW_2022_MMeType::MME_SUCCESS_RATE_REPORT: return trl::L("通信成功率上报");
        case GW_2022_MMeType::MME_NETWORK_CONFLICT_REPORT: return trl::L("网络冲突上报");
        case GW_2022_MMeType::MME_ZERO_CROSS_NTB_COLLECT_IND: return trl::L("过零NTB采集指示");
        case GW_2022_MMeType::MME_ZERO_CROSS_NTB_REPORT: return trl::L("过零NTB上报");
        case GW_2022_MMeType::MME_DIAGNOSE: return trl::L("网络诊断");
        case GW_2022_MMeType::MME_ROUTE_REQUEST: return trl::L("路由请求");
        case GW_2022_MMeType::MME_ROUTE_REPLY: return trl::L("路由应答");
        case GW_2022_MMeType::MME_ROUTE_ERROR: return trl::L("路由错误");
        case GW_2022_MMeType::MME_ROUTE_ACK: return trl::L("路由确认");
        case GW_2022_MMeType::MME_LINK_CONFIRM_REQUEST: return trl::L("链路确认请求");
        case GW_2022_MMeType::MME_LINK_CONFIRM_RESPONSE: return trl::L("链路确认响应");
        case GW_2022_MMeType::MME_RF_CHANNEL_CONFLICT_REPORT: return trl::L("无线信道冲突上报");
        default:   return QStringLiteral("Unknown(0x%1)").arg(t, 2, 16, QChar('0'));
    }
}

static QString assoc_result_str(quint8 v) {
    static const char* names[] = {
        "Request Succeeded", "STA not in Whitelist", "STA in blacklist",
        "STA number exceeded limit", "Whitelist not configured",
        "PCO number exceeded limit", "Child STA number exceeded limit",
        "Reserved", "Duplicate MAC", "Topology levels exceeded",
        "Re-Association Succeeded", "Use subordinate as proxy",
        "Loops in topology", "Unknown CCO error", "RF PCO exceeded limit"};
    if (v <= 0x0e) return QStringLiteral("%1 - %2").arg(v).arg(QLatin1String(names[v]));
    return QString::number(v);
}

/// 枚举字典翻译:name 命中则替换 value 为 "值 - 含义"
static void translate_enum(QVector<MsduFieldNode>& nodes, const char* field,
                           const char* const* dict, int dict_size) {
    for (auto& n : nodes) {
        if (n.name.startsWith(QLatin1String(field))) {
            bool ok = false;
            int v = n.value.toInt(&ok);
            if (ok && v >= 0 && v < dict_size && dict[v])
                n.value = QStringLiteral("%1 - %2").arg(v).arg(QLatin1String(dict[v]));
        }
    }
}

/// 稀疏数值字典翻译(值→含义):value 改为 "值 - 含义"
static void translate_enum_sparse(QVector<MsduFieldNode>& nodes, const char* field,
                                  const QVector<QPair<int, QString>>& dict) {
    for (auto& n : nodes) {
        if (!n.name.startsWith(QLatin1String(field))) continue;
        bool ok = false;
        int v = n.value.toInt(&ok);
        if (!ok) continue;
        for (const auto& kv : dict) {
            if (kv.first == v) {
                n.value = QStringLiteral("%1 - %2").arg(v).arg(kv.second);
                break;
            }
        }
    }
}

/// APP PacketID → 报文类型注释
/// 依据协议"表 2 报文 ID"(含义/报文端口号),与 Python MPDU_Process 分发补充。
static QString packet_id_name(quint16 id) {
    switch (static_cast<GW_2022_AppBid>(id)) {
        case GW_2022_AppBid::TERMINAL_METER_READING: return trl::L("终端主动抄表");
        case GW_2022_AppBid::ROUTER_METER_READING: return trl::L("路由主动抄表");
        case GW_2022_AppBid::TERMINAL_CONCURRENT_METER_READING:
        case GW_2022_AppBid::TERMINAL_CONCURRENT_METER_READING_EXT: return trl::L("终端主动并发抄表");
        case GW_2022_AppBid::TIME_SYNC: return trl::L("校时");
        case GW_2022_AppBid::COMM_TEST: return trl::L("通信测试");
        case GW_2022_AppBid::EVENT_REPORT: return trl::L("事件上报");
        case GW_2022_AppBid::QUERY_SLAVE_REGISTRATION: return trl::L("查询从节点主动注册");
        case GW_2022_AppBid::START_SLAVE_REGISTRATION: return trl::L("启动从节点主动注册");
        case GW_2022_AppBid::STOP_SLAVE_REGISTRATION: return trl::L("停止从节点主动注册");
        case GW_2022_AppBid::CONFIRM_DENY: return trl::L("确认/否认");
        case GW_2022_AppBid::START_UPGRADE: return trl::L("开始升级");
        case GW_2022_AppBid::STOP_UPGRADE: return trl::L("停止升级");
        case GW_2022_AppBid::TRANSFER_FILE_DATA: return trl::L("传输文件数据");
        case GW_2022_AppBid::TRANSFER_FILE_DATA_UNICAST_TO_LOCAL_BROADCAST: return trl::L("传输文件数据(单播转本地广播)");
        case GW_2022_AppBid::QUERY_NODE_UPGRADE_STATUS: return trl::L("查询站点升级状态");
        case GW_2022_AppBid::EXECUTE_UPGRADE: return trl::L("执行升级");
        case GW_2022_AppBid::QUERY_NODE_INFO: return trl::L("查询站点信息");
        case GW_2022_AppBid::METER_CONTROLLER_CCO: return trl::L("抄控器 CCO");
        case GW_2022_AppBid::METER_CONTROLLER_SERIAL_FORWARDING: return trl::L("抄控器数据透传串口转发");
        case GW_2022_AppBid::AUTH_SECURITY: return trl::L("鉴权安全");
        case GW_2022_AppBid::TRANSFORMER_AREA_RELATION: return trl::L("台区户变关系识别");
        case GW_2022_AppBid::QUERY_ID_INFO: return trl::L("查询ID信息");
        case GW_2022_AppBid::PRECISE_TIME_SYNC: return trl::L("精准校时");
        case GW_2022_AppBid::DISTRIBUTION_INFO_REPORT: return trl::L("配电信息上报");
        // 以下为 Python 已实现但"表 2"未单列的应用报文(扩展补充)
        case GW_2022_AppBid::STORAGE_COLLECT_EXT_CONFIG: return trl::L("存储采集扩展配置");
        case GW_2022_AppBid::STORAGE_DATA_BROADCAST_SCHEDULE: return trl::L("存储数据广播时规");
        case GW_2022_AppBid::STORAGE_DATA_SYNC_CONFIG: return trl::L("存储数据同步配置");
        case GW_2022_AppBid::AUTHENTICATION: return trl::L("认证");
        case GW_2022_AppBid::STORE_HRF_RELAY_HEARTBEAT: return trl::L("存储 HRF 中继心跳");
        default:     return trl::L("(未实现)");
    }
}

/// APP PortNum → 端口注释(表 2 报文端口号列)
static QString app_port_name(quint8 port) {
    switch (static_cast<GW_2022_PortNum>(port)) {
        case GW_2022_PortNum::MANAGEMENT_METER_READING: return trl::L("管理/抄表端口");
        case GW_2022_PortNum::UPGRADE: return trl::L("升级端口");
        case GW_2022_PortNum::SECURITY: return trl::L("安全端口");
        default:   return QString();
    }
}

/// 2 值标志字段:value 改为 "0 (0: 含义A, 1: 含义B)"
static void annotate_flag(QVector<MsduFieldNode>& nodes, const char* field,
                          const char* desc0, const char* desc1) {
    for (auto& n : nodes) {
        if (n.name.startsWith(QLatin1String(field))) {
            bool ok = false;
            int v = n.value.toInt(&ok);
            if (ok)
                n.value = QStringLiteral("%1 (0: %2, 1: %3)")
                              .arg(v).arg(QLatin1String(desc0))
                                     .arg(QLatin1String(desc1));
        }
    }
}

/// MSDU_BASE 顶层字段解释(与 Python MSDU_BASE display 一致)
static void annotate_msdu_base(QVector<MsduFieldNode>& nodes) {
    // 稀疏字典避免大数组错位:0=网管 48=应用 49=IP
    translate_enum_sparse(nodes, "SendType", {
        {0, QStringLiteral("Unicast")},
        {1, QStringLiteral("Global Broadcast")},
        {2, QStringLiteral("Local Broadcast")},
        {3, QStringLiteral("Proxy Broadcast")},
    });
    translate_enum_sparse(nodes, "MSDUType", {
        {0, QStringLiteral("Net Management Message")},
        {48, QStringLiteral("Application Level Message")},
        {49, QStringLiteral("IP Message")},
    });
    translate_enum_sparse(nodes, "BroadcastDirection", {
        {0, QStringLiteral("Bi-direction Broadcast")},
        {1, QStringLiteral("Downstream Broadcast")},
        {2, QStringLiteral("Upstream Broadcast")},
        {3, QStringLiteral("UNKNOWN")},
    });
    annotate_flag(nodes, "MainProxyFlag",
                  "Disable Main Proxy Path Mode", "Enable Proxy Main Path Mode");
    annotate_flag(nodes, "PathRepairFlag",
                  "Not Repaired Path", "Repaired Path");
    annotate_flag(nodes, "MACAddrFlag", "No MAC Addr", "Have MAC Addr");
}

static const char* kDeviceType[] = {
    nullptr, "Central Controller", "Concentrator Comm Module",
    "Meter Comm Module", "Repeater", "TypeII Data Collector",
    "TypeI Data Collector", "3 Phase Meter Comm Module"};
static const char* kMacAddrType[] = {
    "Use Meter MAC Address", "Use Comm Module MAC Address"};
static const char* kModuleType[] = {
    "HPLC Module", "HPLC+HRF Module", "HRF Module"};
static const char* kLinePhase[] = {
    "Unknown", "LineA", "LineB", "LineC"};
static const char* kLinkType[] = {
    "HPLC Link", "HRF Link"};
static const char* kBootReason[] = {
    "Normal Boot", "PowerOff Boot", "WatchDog Boot", "PC exception Boot"};
static const char* kReason[] = {
    "Unknown", "Periodically Proxy Change"};
static const char* kRole[] = {
    nullptr, "STA", "PCO", nullptr, "CCO"};
static const char* kCarrierFreq[] = {
    "1.953-11.96MHz", "2.441-5.615MHz", "0.781-2.930MHz", "1.758-2.930MHz"};

/// 把组内翻译应用到一组已 add_fields 的兄弟字段
static void apply_dicts(QVector<MsduFieldNode>& nodes) {
    translate_enum(nodes, "DeviceType", kDeviceType, 8);
    translate_enum(nodes, "MACAddrType", kMacAddrType, 2);
    translate_enum(nodes, "ModuleType", kModuleType, 3);
    translate_enum(nodes, "CandidateLinePhase0", kLinePhase, 4);
    translate_enum(nodes, "CandidateLinePhase1", kLinePhase, 4);
    translate_enum(nodes, "CandidateLinePhase2", kLinePhase, 4);
    translate_enum(nodes, "LinkType", kLinkType, 2);
    translate_enum(nodes, "BootReason", kBootReason, 4);
    translate_enum(nodes, "Reason", kReason, 2);
    translate_enum(nodes, "Role", kRole, 5);
    translate_enum(nodes, "CarrierFreq", kCarrierFreq, 4);
    // LinkType0..4(AssocReq/ChangeProxyReq)
    for (int i = 0; i <= 4; ++i) {
        QString fn = QStringLiteral("LinkType%1").arg(i);
        translate_enum(nodes, qPrintable(fn), kLinkType, 2);
    }
}

// ================= MMe 子类型字段表(偏移均为 MMeHeadSize=4 + 相对偏移) =================
// ---- MMeAssocReq (0x00) ----
// 固定头 b[0..24):STAMACAddr(0,0,48) 5×(TEI(2B)+LinkType(1b)+RSV(3b)) LinePhase
static const FieldSpec kAssocReqSpec[] = {
    {"STAMACAddr",       0, 0, 48, Fmt::MAC},
    {"CandidateTEI0",    6, 0, 12, Fmt::DEC},
    {"LinkType0",        7, 4, 1,  Fmt::DEC},
    {"RSV0",             7, 5, 3,  Fmt::DEC},
    {"CandidateTEI1",    8, 0, 12, Fmt::DEC},
    {"LinkType1",        9, 4, 1,  Fmt::DEC},
    {"RSV1",             9, 5, 3,  Fmt::DEC},
    {"CandidateTEI2",   10, 0, 12, Fmt::DEC},
    {"LinkType2",       11, 4, 1,  Fmt::DEC},
    {"RSV2",            11, 5, 3,  Fmt::DEC},
    {"CandidateTEI3",   12, 0, 12, Fmt::DEC},
    {"LinkType3",       13, 4, 1,  Fmt::DEC},
    {"RSV3",            13, 5, 3,  Fmt::DEC},
    {"CandidateTEI4",   14, 0, 12, Fmt::DEC},
    {"LinkType4",       15, 4, 1,  Fmt::DEC},
    {"RSV4",            15, 5, 3,  Fmt::DEC},
    {"CandidateLinePhase0",      16, 0, 2,  Fmt::DEC},
    {"CandidateLinePhase1", 16, 2, 2, Fmt::DEC},
    {"CandidateLinePhase2", 16, 4, 2,  Fmt::DEC},
    {"RSV5",            16, 6, 2,  Fmt::DEC},
    {"DeviceType",      17, 0, 8,  Fmt::DEC},
    {"MACAddrType",     18, 0, 8,  Fmt::DEC},
    {"ModuleType",      19, 0, 2,  Fmt::DEC},
    {"RSV6",            19, 2, 6,  Fmt::DEC},
    {"STAAssocRandomData", 20, 0, 32, Fmt::HEX8},
};
static const int kAssocReqSpecN = int(sizeof(kAssocReqSpec) / sizeof(kAssocReqSpec[0]));

// 站点版本信息(513211 表66,相对 42:10B):
// 系统启动原因/BOOT版本号/软件版本号(BCD)/版本时间(年7+月4+日5)/
// 厂商代码(ASCII)/芯片代码
static const FieldSpec kStaVerSpec[] = {
    {"BootReason",        0, 0, 8,  Fmt::DEC},
    {"BootVersion",       1, 0, 8,  Fmt::DEC},
    {"SoftwareVersion",   2, 0, 16, Fmt::HEX4},
    {"VersionDataYear",   4, 0, 7,  Fmt::DEC},
    {"VersionDataMonth",  4, 7, 4,  Fmt::DEC},
    {"VersionDataDay",    5, 3, 5,  Fmt::DEC},
    {"ManufacturerID",    6, 0, 16, Fmt::HEX4},
    {"ChipID",            8, 0, 16, Fmt::HEX4},
};
static const int kStaVerSpecN = int(sizeof(kStaVerSpec) / sizeof(kStaVerSpec[0]));

// AssocReq 版本信息之后(52..60):硬/软复位累积次数、代理类型、保留、端到端序号
static const FieldSpec kAssocReqTailSpec[] = {
    {"HardRstCount",      52, 0, 16, Fmt::DEC},
    {"SoftRstCount",      54, 0, 16, Fmt::DEC},
    {"ProxyType",         56, 0, 8,  Fmt::DEC},
    {"RSV7",              57, 0, 24, Fmt::DEC},
    {"EndSequence",       60, 0, 32, Fmt::HEX8},
};
static const int kAssocReqTailSpecN =
    int(sizeof(kAssocReqTailSpec) / sizeof(kAssocReqTailSpec[0]));

// 变长尾随字节区(AssocReq 24..42 ManufacturerInfo 18B;64..88 ManagementID 24B)
static QString bytes_hex(const QByteArray& d, int from, int len) {
    // 越界保护:数据不足时返回空,避免 mid 越界断言
    if (from < 0) { len += from; from = 0; }
    if (from >= d.size() || len <= 0) return QString();
    if (from + len > d.size()) len = d.size() - from;
    QByteArray s = d.mid(from, len).toHex(' ');
    return QString::fromLatin1(s).toUpper();
}

// ---- MMeAssocCnf (0x01) ----
static const FieldSpec kAssocCnfSpec[] = {
    {"STAMACAddr",       0, 0, 48, Fmt::MAC},
    {"CCOMACAddr",       6, 0, 48, Fmt::MAC},
    {"AssocResult",     12, 0, 8,  Fmt::DEC},
    {"STALevel",        13, 0, 8,  Fmt::DEC},
    {"STATEI",          14, 0, 12, Fmt::DEC},
    {"LinkType",        15, 4, 1,  Fmt::DEC},
    {"CarrierFreq",     15, 5, 2,  Fmt::DEC},
    {"RSV0",            15, 7, 1,  Fmt::DEC},
    {"ProxyTEI",        16, 0, 12, Fmt::DEC},
    {"RSV1",            17, 4, 4,  Fmt::DEC},
    {"TotalPacketNum",  18, 0, 8,  Fmt::DEC},
    {"PacketIndex",     19, 0, 8,  Fmt::DEC},
    {"STAAssocRandomData", 20, 0, 32, Fmt::HEX8},
    {"STAReAssocTime",  24, 0, 32, Fmt::DEC},
    {"EndSequence",     28, 0, 32, Fmt::HEX8},
    {"PathSequence",    32, 0, 32, Fmt::HEX8},
    {"RSV2",            36, 0, 32, Fmt::DEC},
};
static const int kAssocCnfSpecN = int(sizeof(kAssocCnfSpec) / sizeof(kAssocCnfSpec[0]));
static const FieldSpec kAssocGatherIndSpec[] = {
    // 关联汇总指示(5134 表76,相对 b=MMeHeadSize 起)
    {"AssocResult",      0, 0, 8,  Fmt::DEC},
    {"STALevel",         1, 0, 8,  Fmt::DEC},
    {"CCOMACAddr",       2, 0, 48, Fmt::MAC},
    {"ProxyTEI",         8, 0, 12, Fmt::DEC},
    {"CarrierFreq",      9, 4, 2,  Fmt::DEC},
    {"RSV0",             9, 6, 2,  Fmt::DEC},
    {"RSV1",            10, 0, 8,  Fmt::DEC},
    {"NewSTANumber",    11, 0, 8,  Fmt::DEC},
    {"RSV2",            12, 0, 32, Fmt::DEC},
};
static const int kAssocGatherIndSpecN = int(sizeof(kAssocGatherIndSpec) / sizeof(kAssocGatherIndSpec[0]));

// ---- MMeChangeProxyReq (0x03) ----
static const FieldSpec kChangeProxyReqSpec[] = {
    {"STATEI",         0, 0, 12, Fmt::DEC},
    {"RSV0",           1, 4, 4,  Fmt::DEC},
    {"NewProxyTEI0",   2, 0, 12, Fmt::DEC},
    {"LinkType0",      3, 4, 1,  Fmt::DEC},
    {"RSV1",           3, 5, 3,  Fmt::DEC},
    {"NewProxyTEI1",   4, 0, 12, Fmt::DEC},
    {"LinkType1",      5, 4, 1,  Fmt::DEC},
    {"RSV2",           5, 5, 3,  Fmt::DEC},
    {"NewProxyTEI2",   6, 0, 12, Fmt::DEC},
    {"LinkType2",      7, 4, 1,  Fmt::DEC},
    {"RSV3",           7, 5, 3,  Fmt::DEC},
    {"NewProxyTEI3",   8, 0, 12, Fmt::DEC},
    {"LinkType3",      9, 4, 1,  Fmt::DEC},
    {"RSV4",           9, 5, 3,  Fmt::DEC},
    {"NewProxyTEI4",  10, 0, 12, Fmt::DEC},
    {"LinkType4",     11, 4, 1,  Fmt::DEC},
    {"RSV5",          11, 5, 3,  Fmt::DEC},
    {"OldProxyTEI",   12, 0, 12, Fmt::DEC},
    {"RSV6",          13, 4, 4,  Fmt::DEC},
    {"ProxyType",     14, 0, 8,  Fmt::DEC},
    {"Reason",        15, 0, 8,  Fmt::DEC},
    {"EndSequence",   16, 0, 32, Fmt::HEX8},
    {"CandidateLinePhase0",    20, 0, 2,  Fmt::DEC},
    {"CandidateLinePhase1", 20, 2, 2, Fmt::DEC},
    {"CandidateLinePhase2", 20, 4, 2, Fmt::DEC},
    {"RSV7",          20, 6, 2,  Fmt::DEC},
    {"Reserved",      21, 0, 24, Fmt::DEC},
};
static const int kChangeProxyReqSpecN = int(sizeof(kChangeProxyReqSpec) / sizeof(kChangeProxyReqSpec[0]));

// ---- MMeChangeProxyBitMapCnf (0x05) ----
static const FieldSpec kChangeProxyBitMapCnfSpec[] = {
    {"Result",        0, 0, 8,  Fmt::DEC},
    {"RSV0",          1, 0, 8,  Fmt::DEC},
    {"BitMapSize",    2, 0, 16, Fmt::DEC},
    {"STATEI",        4, 0, 12, Fmt::DEC},
    {"LinkType",      5, 4, 1,  Fmt::DEC},
    {"RSV1",          5, 5, 3,  Fmt::DEC},
    {"ProxyTEI",      6, 0, 12, Fmt::DEC},
    {"RSV2",          7, 4, 4,  Fmt::DEC},
    {"EndSequence",   8, 0, 32, Fmt::HEX8},
    {"PathSequence", 12, 0, 32, Fmt::HEX8},
    {"RSV3",         16, 0, 32, Fmt::DEC},
};
static const int kChangeProxyBitMapCnfSpecN = int(sizeof(kChangeProxyBitMapCnfSpec) / sizeof(kChangeProxyBitMapCnfSpec[0]));

// ---- MMeHeartBeatCheck (0x07) ----
static const FieldSpec kHeartBeatSpec[] = {
    {"OriginalSourceTEI", 0, 0, 12, Fmt::DEC},
    {"RSV0",              1, 4, 4,  Fmt::DEC},
    {"DiscoverCountTEI",  2, 0, 12, Fmt::DEC},
    {"RSV1",              3, 4, 4,  Fmt::DEC},
    {"DiscoverCount",     4, 0, 16, Fmt::DEC},
    {"BitMapSize",        6, 0, 16, Fmt::DEC},
};
static const int kHeartBeatSpecN = int(sizeof(kHeartBeatSpec) / sizeof(kHeartBeatSpec[0]));

// ---- MMeDiscoverNodeList (0x08) ----
static const FieldSpec kDiscoverNodeListSpec[] = {
    {"STATEI",             0, 0, 12, Fmt::DEC},
    {"ProxyTEI",           1, 4, 12, Fmt::DEC},
    {"Role",               3, 0, 4,  Fmt::DEC},
    {"Level",              3, 4, 4,  Fmt::DEC},
    {"MACAddr",            4, 0, 48, Fmt::MAC},
    {"CCOMACAddr",        10, 0, 48, Fmt::MAC},
    {"CandidateLinePhase0",        16, 0, 2,  Fmt::DEC},
    {"CandidateLinePhase1", 16, 2, 2, Fmt::DEC},
    {"CandidateLinePhase2", 16, 4, 2, Fmt::DEC},
    {"RSV0",              16, 6, 2,  Fmt::DEC},
    {"ProxyChannelQuality", 17, 0, 8, Fmt::DEC},
    {"ProxyCommRate",     18, 0, 8,  Fmt::DEC},
    {"ProxyDownCommRate", 19, 0, 8,  Fmt::DEC},
    {"DiscoverNodeNum",   20, 0, 16, Fmt::DEC},
    {"SendDiscoveryPacketCount", 22, 0, 8, Fmt::DEC},
    {"UpRouteEntryNum",   23, 0, 8,  Fmt::DEC},
    {"EvaluateBeginTimeout", 24, 0, 16, Fmt::DEC},
    {"DiscoverySTABitMapSize", 26, 0, 16, Fmt::DEC},
    {"MinCommRate",       28, 0, 8,  Fmt::DEC},
    {"RSV1",              29, 0, 24, Fmt::DEC},
};
static const int kDiscoverNodeListSpecN = int(sizeof(kDiscoverNodeListSpec) / sizeof(kDiscoverNodeListSpec[0]));

// ---- MMeChangeProxyCnf (0x04):固定 20B + 子站点 2B×N ----
static const FieldSpec kChangeProxyCnfSpec[] = {
    {"Result",            0, 0, 8,  Fmt::DEC},
    {"TotalPacketNum",    1, 0, 8,  Fmt::DEC},
    {"PacketIndex",       2, 0, 8,  Fmt::DEC},
    {"RSV0",              3, 0, 8,  Fmt::DEC},
    {"STATEI",            4, 0, 12, Fmt::DEC},
    {"LinkType",          5, 4, 1,  Fmt::DEC},
    {"RSV1",              5, 5, 3,  Fmt::DEC},
    {"ProxyTEI",          6, 0, 12, Fmt::DEC},
    {"RSV2",              7, 4, 4,  Fmt::DEC},
    {"EndSequence",       8, 0, 32, Fmt::HEX8},
    {"PathSequence",     12, 0, 32, Fmt::HEX8},
    {"ChildSum",         16, 0, 16, Fmt::DEC},
    {"RSV3",             18, 0, 16, Fmt::DEC},
};
static const int kChangeProxyCnfSpecN = int(sizeof(kChangeProxyCnfSpec) / sizeof(kChangeProxyCnfSpec[0]));

// ---- MMeLeaveInd (0x06):固定 16B + 离线站点 MAC 6B×N ----
static const FieldSpec kLeaveIndSpec[] = {
    {"Reason",            0, 0, 16, Fmt::DEC},
    {"LeaveSTANum",       2, 0, 16, Fmt::DEC},
    {"LeaveDelayTime",    4, 0, 16, Fmt::DEC},
    {"RSV0",              6, 0, 80, Fmt::DEC},
};
static const int kLeaveIndSpecN = int(sizeof(kLeaveIndSpec) / sizeof(kLeaveIndSpec[0]));

// ---- MMeNetworkConflictReport (0x0A):固定 8B + NIDSize×N 邻居网络号 ----
static const FieldSpec kNetworkConflictSpec[] = {
    {"CCOMACAddr",        0, 0, 48, Fmt::MAC},
    {"NeighbourNetWorkCount", 6, 0, 8, Fmt::DEC},
    {"NIDSize",           7, 0, 8,  Fmt::DEC},
};
static const int kNetworkConflictSpecN = int(sizeof(kNetworkConflictSpec) / sizeof(kNetworkConflictSpec[0]));

// ---- MMeRFChannelConflictReport (0x80):固定 7B + channel/option 各 Count 字节 ----
static const FieldSpec kRFChannelConflictSpec[] = {
    {"CCOMACAddr",        0, 0, 48, Fmt::MAC},
    {"NeighbourNetWorkCount", 6, 0, 8, Fmt::DEC},
};
static const int kRFChannelConflictSpecN = int(sizeof(kRFChannelConflictSpec) / sizeof(kRFChannelConflictSpec[0]));

// ---- 路由/链路类(0x50-0x55,公共头版本 0x00) ----
static const FieldSpec kRouteReqReplyHeadSpec[] = {   // RouteRequest/RouteReply 前 7B
    {"RouteVersion",      0, 0, 8,  Fmt::DEC},
    {"RouterReqSN",       1, 0, 32, Fmt::HEX8},
};
static const int kRouteReqReplyHeadSpecN = int(sizeof(kRouteReqReplyHeadSpec) / sizeof(kRouteReqReplyHeadSpec[0]));
static const FieldSpec kRouteRequestTailSpec[] = {    // 字节5-6(RouteRequest)
    {"RSV0",              5, 0, 3,  Fmt::DEC},
    {"RoutePriorFlag",    5, 3, 1,  Fmt::DEC},
    {"LoadDataType",      5, 4, 4,  Fmt::DEC},
    {"LoadDataLength",    6, 0, 8,  Fmt::DEC},
};
static const int kRouteRequestTailSpecN = int(sizeof(kRouteRequestTailSpec) / sizeof(kRouteRequestTailSpec[0]));
static const FieldSpec kRouteReplyTailSpec[] = {       // 字节5-6(RouteReply)
    {"RSV0",              5, 0, 4,  Fmt::DEC},
    {"LoadDataType",      5, 4, 4,  Fmt::DEC},
    {"LoadDataLength",    6, 0, 8,  Fmt::DEC},
};
static const int kRouteReplyTailSpecN = int(sizeof(kRouteReplyTailSpec) / sizeof(kRouteReplyTailSpec[0]));
static const FieldSpec kRouteAckSpec[] = {            // RouteAck 8B
    {"RouteVersion",      0, 0, 8,  Fmt::DEC},
    {"RSV0",              1, 0, 24, Fmt::DEC},
    {"RouterReqSN",       4, 0, 32, Fmt::HEX8},
};
static const int kRouteAckSpecN = int(sizeof(kRouteAckSpec) / sizeof(kRouteAckSpec[0]));
static const FieldSpec kRouteErrorSpec[] = {          // RouteError 前 7B
    {"Version",           0, 0, 8,  Fmt::DEC},
    {"RouterReqSN",       1, 0, 32, Fmt::HEX8},
    {"RSV0",              5, 0, 8,  Fmt::DEC},
    {"UnReachableSTANum", 6, 0, 8,  Fmt::DEC},
};
static const int kRouteErrorSpecN = int(sizeof(kRouteErrorSpec) / sizeof(kRouteErrorSpec[0]));
static const FieldSpec kLinkConfirmRequestSpec[] = {  // 链路确认请求前 7B
    {"Version",           0, 0, 8,  Fmt::DEC},
    {"RouterReqSN",       1, 0, 32, Fmt::HEX8},
    {"RSV0",              5, 0, 8,  Fmt::DEC},
    {"AckStaNum",         6, 0, 8,  Fmt::DEC},
};
static const int kLinkConfirmRequestSpecN = int(sizeof(kLinkConfirmRequestSpec) / sizeof(kLinkConfirmRequestSpec[0]));
static const FieldSpec kLinkConfirmResponseSpec[] = { // 链路确认回应 8B
    {"Version",           0, 0, 8,  Fmt::DEC},
    {"Level",             1, 0, 8,  Fmt::DEC},
    {"ChannelQuality",    2, 0, 8,  Fmt::DEC},
    {"RoutePriorityFlag", 3, 0, 1,  Fmt::DEC},
    {"RSV0",              3, 1, 7,  Fmt::DEC},
    {"RouterReqSN",       4, 0, 32, Fmt::HEX8},
};
static const int kLinkConfirmResponseSpecN = int(sizeof(kLinkConfirmResponseSpec) / sizeof(kLinkConfirmResponseSpec[0]));

// ---- MMeDiagnose (0x4F):芯片厂商 ID ----
static const FieldSpec kDiagnoseSpec[] = {
    {"ChipManufacID",     0, 0, 16, Fmt::DEC},
};
static const int kDiagnoseSpecN = int(sizeof(kDiagnoseSpec) / sizeof(kDiagnoseSpec[0]));

// ---- MMeZeroCrossNTBCollectInd (0x0B):固定 8B ----
// 协议 L1533 表104: TEI=12bit(字节0 bit0-7 + 字节1 bit0-3), RSV=4bit(字节1 bit4-7)
static const FieldSpec kZeroCrossCollectSpec[] = {
    {"STATEI",            0, 0, 12, Fmt::DEC},
    {"RSV0",              1, 4, 4,  Fmt::DEC},
    {"NTBCollectionMode", 2, 0, 8,  Fmt::DEC},
    {"NTBCollectionPeriod", 3, 0, 8, Fmt::DEC},
    {"NTBCollectionQuantity", 4, 0, 8, Fmt::DEC},
    {"RSV1",              5, 0, 24, Fmt::DEC},
};
static const int kZeroCrossCollectSpecN = int(sizeof(kZeroCrossCollectSpec) / sizeof(kZeroCrossCollectSpec[0]));

// ---- MMeZeroCrossNTBReport (0x0C):固定 10B + 12bit 差分 NTB 打包流 ----
static const FieldSpec kZeroCrossReportSpec[] = {
    {"STATEI",            0, 0, 12, Fmt::DEC},
    {"RSV0",              1, 4, 4,  Fmt::DEC},
    {"TotalCount",        2, 0, 8,  Fmt::DEC},
    {"LineATotalCount",   3, 0, 8,  Fmt::DEC},
    {"LineBTotalCount",   4, 0, 8,  Fmt::DEC},
    {"LineCTotalCount",   5, 0, 8,  Fmt::DEC},
    {"NTBBase",           6, 0, 32, Fmt::DEC},
};
static const int kZeroCrossReportSpecN = int(sizeof(kZeroCrossReportSpec) / sizeof(kZeroCrossReportSpec[0]));

/// @brief 渲染 RouteRequest/RouteReply 的 LoadData 段(MMe_RoutePathList,4B×N):
///        每 4B = TEI(12b)+RSV0(4b)+CommSuccRate(1B,%)+ChannelQuality(1B,dB)
static void annotate_route_loaddata(QVector<MsduFieldNode>& nodes,
                                    const QByteArray& b, int rel_base) {
    for (auto& n : nodes) {
        if (!n.name.startsWith(QStringLiteral("LoadDataType"))) continue;
        const int v = n.value.toInt();
        // 负载数据类型(表112):0=未携带负载数据 1=传播路径列表 其他=保留 / 0=none,1=propagation path list,else reserved
        n.value = QStringLiteral("%1 - %2").arg(v).arg(
            v == 0 ? QStringLiteral("No load data")
          : v == 1 ? QStringLiteral("Propagation path list")
                   : QStringLiteral("Reserved"));
    }
    if (b.size() < 8) { pa::warn("gw_2022:content_short", QStringLiteral("block %1B<8B").arg(b.size())); return; }
    const int len = (int)get_bits(b, 6, 0, 8);   // LoadDataLength
    const int cnt = len / 4;
    if (cnt <= 0) return;
    auto& pg = group(nodes, QStringLiteral("RoutePathList [%1]").arg(cnt));
    for (int i = 0; i < cnt && 7 + 4 * i + 4 <= b.size(); ++i) {
        const int off = 7 + 4 * i;
        const int rel0 = rel_base + off;
        auto& rp = group(pg.children, QStringLiteral("RoutePath[%1]").arg(i));
        MsduFieldNode t;
        t.name  = QStringLiteral("TEI [12b]");
        t.value = QString::number((quint16)get_bits(b, off, 0, 12));
        t.rel_start = rel0; t.rel_len = 2;
        rp.children.append(t);
        MsduFieldNode rv;
        rv.name  = QStringLiteral("RSV0 [4b]");
        rv.value = QString::number((quint8)get_bits(b, off + 1, 4, 4));
        rv.rel_start = rel0 + 1; rv.rel_len = 1;
        rp.children.append(rv);
        MsduFieldNode cr;
        cr.name  = QStringLiteral("CommSuccRate");
        cr.value = QStringLiteral("%1%").arg((quint8)b[off + 2]);
        cr.rel_start = rel0 + 2; cr.rel_len = 1;
        rp.children.append(cr);
        MsduFieldNode cq;
        cq.name  = QStringLiteral("ChannelQuality");
        cq.value = QStringLiteral("%1 dB").arg((quint8)b[off + 3]);
        cq.rel_start = rel0 + 3; cq.rel_len = 1;
        rp.children.append(cq);
    }
}

// ---- MMeSuccessRateReport (0x09) ----
static const FieldSpec kSuccessRateSpec[] = {
    {"ProxySTATEI", 0, 0, 12, Fmt::DEC},
    {"RSV0",        1, 4, 4,  Fmt::DEC},
    {"STANumber",   2, 0, 16, Fmt::DEC},
};
static const int kSuccessRateSpecN = int(sizeof(kSuccessRateSpec) / sizeof(kSuccessRateSpec[0]));

// ================= APP 公共头(APP_BASE) =================
static const FieldSpec kAppBaseSpec[] = {
    {"PortNum",      0, 0, 8,  Fmt::HEX4},
    {"PacketID",     1, 0, 16, Fmt::HEX4},
    {"PacketCtrWord", 3, 0, 8, Fmt::HEX4},
};
static const int kAppBaseSpecN = int(sizeof(kAppBaseSpec) / sizeof(kAppBaseSpec[0]));

// ================= MSDU_BASE_S 简头 =================
static const FieldSpec kMsduBaseSSpec[] = {
    {"Version",   0, 0, 4,  Fmt::DEC},
    {"RSV0",      0, 4, 4,  Fmt::DEC},
    {"MSDUType",  1, 0, 8,  Fmt::DEC},
    {"MSDULen",   2, 0, 11, Fmt::DEC},
    {"RSV1",      3, 3, 5,  Fmt::DEC},
};
static const int kMsduBaseSSpecN = int(sizeof(kMsduBaseSSpec) / sizeof(kMsduBaseSSpec[0]));

// ================= 无线发现列表(RFDL, 表123-137) =================
// 单跳帧(MSDU_BASE_S)消息类型0 = 无线发现列表(表123),TLV 结构。
// 参考:§5.1.1.4 单跳MAC帧头(表11) / §5.13.23 无线发现列表报文(表123-137)。

/// 邻居节点信道信息组合类型字段位宽(表129 非位图版 / 表137 位图版)
struct RfdlChCombo {
    quint8 rcv;   ///< 接收率位宽(0/6/8)
    quint8 snr;   ///< 平均信噪比位宽(0/4/6)
    quint8 rssi;  ///< 信号强度位宽(0/4/6/8)
};

// 表129:非位图版(每条固定含 TEI 12b)
static const RfdlChCombo kRfdlNonBitmap[] = {
    {8,0,0}, {0,4,0}, {0,0,8}, {0,0,4}, {8,4,0},
    {6,0,6}, {0,6,6}, {8,6,6}, {0,4,4}, {8,0,4},
};
// 表137:位图版(无 TEI,由位图索引定位)
static const RfdlChCombo kRfdlBitmap[] = {
    {8,0,0}, {0,4,0}, {0,0,8}, {0,0,4}, {8,4,0},
    {8,0,8}, {0,6,6}, {8,6,6}, {8,4,4}, {0,4,4}, {8,0,4},
};

/// 信息单元类型名(表124)
static QString rfdl_ie_name(quint8 t) {
    switch (t) {
    case 0: return QStringLiteral("Station Attribute");
    case 1: return QStringLiteral("Station Route");
    case 2: return QStringLiteral("Neighbor Ch Info (non-bitmap)");
    case 3: return QStringLiteral("Neighbor Ch Info (bitmap)");
    default: return QStringLiteral("Reserved");
    }
}

/// 路由类型(表98):0 错误 1 同级 2 上级 3 代理主路径 4 上上级
/// 经 trl::L 走 i18n(中/英),避免 QLatin1String 对 UTF-8 中文的误解码。
static const char* kRfdlRouteType[] = {
    "错误路由类型", "同级路由类型", "上级路由类型",
    "代理主路径路由类型", "上上级路由类型"};

// 站点属性信息(表126):14B 定长,字节对齐
static const FieldSpec kRfdlAttrSpec[] = {
    {"CCOMACAddr",       0, 0, 48, Fmt::MAC},
    {"ProxyTEI",         6, 0, 12, Fmt::DEC},
    {"Role",             7, 4, 4,  Fmt::DEC},
    {"Level",            8, 0, 4,  Fmt::DEC},
    {"RFHop",            8, 4, 4,  Fmt::DEC},
    {"ProxyUpRcvRate",   9, 0, 8,  Fmt::DEC},
    {"ProxyDownRcvRate", 10, 0, 8, Fmt::DEC},
    {"MinRcvRate",       11, 0, 8, Fmt::DEC},
    {"RFDLPeriod",       12, 0, 8, Fmt::DEC},
    {"RcvAgingCycles",   13, 0, 8, Fmt::DEC},
};
static const int kRfdlAttrSpecN = int(sizeof(kRfdlAttrSpec)/sizeof(kRfdlAttrSpec[0]));

/// 追加一个位域节点(c 内 bitpos 起的 bits 位;cbase_abs=c[0] 在 body 的绝对偏移)
static void rfdl_bit_field(MsduFieldNode& parent, const char* name,
                           const QByteArray& c, int bitpos, int bits,
                           int cbase_abs, const QString& val) {
    Q_UNUSED(c)   // 位置取值用 cbase_abs(调用方已换算),c 仅为签名对称保留
    MsduFieldNode n;
    n.name = QStringLiteral("%1 [%2b]").arg(QLatin1String(name)).arg(bits);
    n.value = val;
    n.rel_start = cbase_abs + bitpos / 8;
    n.rel_len   = (bitpos % 8 + bits + 7) / 8;
    parent.children.append(n);
}

/// 渲染一条邻居信道信息(位流内,自 bitpos 起),返回下一条起始位
static int rfdl_neighbour_bits(MsduFieldNode& parent, const QByteArray& c,
                               int bitpos, const RfdlChCombo& cb,
                               int cbase_abs, bool has_tei,
                               quint16 tei = 0,
                               QVector<QPair<quint16, int>>* rssi_out = nullptr,
                               QVector<QPair<quint16, quint8>>* rates_out = nullptr,
                               QVector<QPair<quint16, qint16>>* snrs_out = nullptr) {
    int bp = bitpos;
    if (has_tei) {
        tei = (quint16)get_bits(c, bp / 8, bp % 8, 12);   // 非位图:TEI 在条目内,覆盖调用方传入值
        rfdl_bit_field(parent, "TEI", c, bp, 12, cbase_abs, QString::number(tei));
        bp += 12;
    }
    if (cb.rcv) {
        const quint64 v = get_bits(c, bp / 8, bp % 8, cb.rcv);
        // 表130:6b=实际/2, 8b=实际(单位 %)
        const quint64 pct = (cb.rcv == 6) ? v * 2 : v;
        rfdl_bit_field(parent, "RcvRate", c, bp, cb.rcv, cbase_abs,
                       QStringLiteral("%1 (%2%)").arg(v).arg(pct));
        // 拓扑采集:该邻居上行成功率%(方向=邻居→我;6b=量化/2,8b=实际);>100 为非法值,跳过追加
        if (rates_out && tei && pct <= 100)
            rates_out->append({tei, (quint8)pct});
        bp += cb.rcv;
    }
    if (cb.snr) {
        // 表131(6bit): 量化值=SNR+6 → SNR=v-6(v=0 表示 ≤-6dB);表132(4bit): 非均匀 -6 起
        // 2dB/3dB 步进至 >25(与 2.0 表98 逐行一致;1.0 原文负号被 MinerU 吞掉,如"SNR≤6"实为"SNR≤-6")
        const quint64 v = get_bits(c, bp / 8, bp % 8, cb.snr);
        QString sv;
        if (v == 0) {
            sv = QStringLiteral("%1 (SNR≤-6dB)").arg(v);
        } else if (cb.snr == 6) {
            sv = QStringLiteral("%1 (SNR=%2dB)").arg(v).arg(int(v) - 6);
        } else {
            static const int hi[14] = { -4, -2, 0, 2, 4, 6, 8, 10, 12, 14, 16, 19, 22, 25 };
            const int lo = (v == 1) ? -6 : hi[v - 2];
            sv = (v == 15) ? QStringLiteral("%1 (SNR>25dB)").arg(v)
                           : QStringLiteral("%1 (SNR %2~%3dB)").arg(v).arg(lo).arg(hi[v - 1]);
        }
        rfdl_bit_field(parent, "SNR", c, bp, cb.snr, cbase_abs, sv);
        // 拓扑采集:该邻居 SNR(dB,区间下限;1.0 无线单簇映射与文案一致)
        if (snrs_out && tei) {
            int snr_db = 0;
            if (cb.snr == 6) {
                snr_db = (v == 0) ? -6 : int(v) - 6;
            } else {
                static const int hi[14] = { -4, -2, 0, 2, 4, 6, 8, 10, 12, 14, 16, 19, 22, 25 };
                snr_db = (v == 0) ? -6 : (v >= 15 ? 25 : ((v == 1) ? -6 : hi[v - 2]));
            }
            snrs_out->append({tei, (qint16)snr_db});
        }
        bp += cb.snr;
    }
    if (cb.rssi) {
        // 表133:8bit 量化值=RSSI+110(dBm) → RSSI=v-110(v=0 表示 ≤-110dBm);
        // 表135:6bit 2dB 步进,量化值 v → RSSI∈[2v-110, 2v-108](与 2.0 表101 同);
        // 表134(1.0,无线,与 2.0 表100 逐档一致):4bit 非均匀区间硬编码
        const quint64 v = get_bits(c, bp / 8, bp % 8, cb.rssi);
        QString rv;
        if (cb.rssi == 8) {
            rv = QStringLiteral("%1 (RSSI=%2dBm)").arg(v).arg(int(v) - 110);
        } else if (cb.rssi == 6) {
            rv = (v == 0) ? QStringLiteral("%1 (RSSI≤-110dBm)").arg(v)
                          : QStringLiteral("%1 (RSSI %2~%3dBm)").arg(v).arg(int(v) * 2 - 110).arg(int(v) * 2 - 108);
        } else {
            // 表134 4bit:0=RSSI≤-105;1:-105~-95;2:-95~-86;3:-86~-80;4:-80~-74;5:-74~-68;
            //   6:-68~-62;7:-62~-56;8:-56~-48;9:-48~-42;10:-42~-36;11:-36~-30;12:-30~-20;
            //   13:-20~-10;14:-10~0;15=RSSI>0 (dBm)
            static const int kLo[14] = {-105, -95, -86, -80, -74, -68, -62,
                                        -56, -48, -42, -36, -30, -20, -10};
            static const int kHi[14] = {-95, -86, -80, -74, -68, -62, -56,
                                        -48, -42, -36, -30, -20, -10, 0};
            if (v == 0)       rv = QStringLiteral("%1 (RSSI≤-105dBm)").arg(v);
            else if (v == 15) rv = QStringLiteral("%1 (RSSI>0dBm)").arg(v);
            else              rv = QStringLiteral("%1 (RSSI=%2~%3dBm)").arg(v).arg(kLo[v - 1]).arg(kHi[v - 1]);
        }
        // 拓扑采集:该邻居信号强度 dBm(档位下限;gw_2022 单簇映射与文案一致)
        if (rssi_out && tei) {
            int dbm = 0;
            if (cb.rssi == 8)      dbm = int(v) - 110;
            else if (cb.rssi == 6) dbm = (v == 0) ? -110 : int(v) * 2 - 110;
            else {                 // 表134(4bit)档位下限
                static const int kLo[14] = {-105, -95, -86, -80, -74, -68, -62,
                                            -56, -48, -42, -36, -30, -20, -10};
                dbm = (v == 0) ? -105 : (v >= 15 ? 0 : kLo[v - 1]);
            }
            rssi_out->append({tei, dbm});
        }
        rfdl_bit_field(parent, "RSSI", c, bp, cb.rssi, cbase_abs, rv);
        bp += cb.rssi;
    }
    return bp;
}

/// 解析无线发现列表(RFDL)载荷,挂到 out.tree;rfdl=载荷本身,rel_base=其在 body 中的偏移
static void parse_rfdl(MsduInfo& out, const QByteArray& rfdl, int rel_base) {
    const QByteArray d = rfdl;
    if (d.size() < 7) { pa::warn("gw_2022:truncated", QStringLiteral("RFDL %1B<7B").arg(d.size())); append_summary(out, trl::L(" (RFDL 截断)")); return; }

    // 表123 头:站点MAC 6B + 统计序号 1B
    {
        MsduFieldNode mac;
        mac.name = QStringLiteral("STA MAC [48b]");
        mac.value = mac_str(get_bits(d, 0, 0, 48));
        mac.rel_start = rel_base; mac.rel_len = 6;
        out.tree.append(mac);
        MsduFieldNode seq;
        seq.name = QStringLiteral("Seq [8b]");
        seq.value = QString::number((quint8)d[6]);
        seq.rel_start = rel_base + 6; seq.rel_len = 1;
        out.tree.append(seq);
    }

    // TLV 循环:信息单元类型(7b)+长度类型(1b)+长度(1/2B)+内容
    int pos = 7;
    int ie_idx = 0;
    while (pos + 1 < d.size()) {
        const quint8 hdr = (quint8)d[pos];
        const quint8 ie_type = hdr & 0x7F;         // 信息单元类型(bit0-6)
        const bool  long_len = (hdr & 0x80) != 0;  // 长度类型(bit7,表125:0=1B 1=2B)
        {
            MsduFieldNode t;
            t.name = QStringLiteral("IE[%1] Type [7b]").arg(ie_idx);
            t.value = QStringLiteral("%1 - %2").arg(ie_type).arg(rfdl_ie_name(ie_type));
            t.rel_start = rel_base + pos; t.rel_len = 1;
            out.tree.append(t);
        }
        ++pos;
        if (pos >= d.size()) break;
        const int len_bytes = long_len ? 2 : 1;
        if (pos + len_bytes > d.size()) { pa::warn("gw_2022:ie_overflow", QStringLiteral("IE len hdr @%1 exceeds %2").arg(pos).arg(d.size())); break; }
        quint32 elen = (quint8)d[pos];
        if (len_bytes == 2) elen = ((quint32)(quint8)d[pos] << 8) | (quint8)d[pos + 1];
        {
            MsduFieldNode l;
            l.name = QStringLiteral("IE[%1] Len [%2b]").arg(ie_idx).arg(len_bytes * 8);
            l.value = QString::number(elen);
            l.rel_start = rel_base + pos; l.rel_len = len_bytes;
            out.tree.append(l);
        }
        pos += len_bytes;
        if (pos + elen > d.size()) { pa::warn("gw_2022:ie_overflow", QStringLiteral("IE type=%1 len=%2 exceeds remaining %3").arg(ie_type).arg(elen).arg(d.size()-pos)); break; }
        const QByteArray content = d.mid(pos, elen);
        const int content_abs = rel_base + pos;

        // 按信息单元类型解析内容(表124)
        switch (ie_type) {
        case 0: {  // 站点属性信息(表126,14B 定长)
            auto& g = group(out.tree, QStringLiteral("IE[%1] Station Attribute [%2B]").arg(ie_idx).arg(elen));
            g.rel_start = content_abs; g.rel_len = elen;
            add_fields(g.children, content, 0, kRfdlAttrSpec, kRfdlAttrSpecN, content_abs);
            // 拓扑采集(表126 站点属性,不改渲染):代理 TEI/上下行接收率/最小接收率/RF 跳数/角色
            out.topo_event.proxy_tei = (quint16)get_bits(content, 6, 0, 12);
            out.topo_event.rf_role = (quint8)get_bits(content, 7, 4, 4);
            out.topo_event.rf_hop = (quint8)get_bits(content, 8, 4, 4);
            const quint8 up_v   = (quint8)get_bits(content, 9, 0, 8);
            const quint8 down_v = (quint8)get_bits(content, 10, 0, 8);
            const quint8 min_v  = (quint8)get_bits(content, 11, 0, 8);
            out.topo_event.proxy_up_rate   = (up_v   <= 100) ? (qint16)up_v   : -1;
            out.topo_event.proxy_down_rate = (down_v <= 100) ? (qint16)down_v : -1;
            out.topo_event.min_link_rate   = (min_v  <= 100) ? (qint16)min_v  : -1;
            translate_enum(g.children, "Role", kRole, 5);
            annotate_unit(g.children, "ProxyUpRcvRate", QStringLiteral("%"));
            annotate_unit(g.children, "ProxyDownRcvRate", QStringLiteral("%"));
            annotate_unit(g.children, "MinRcvRate", QStringLiteral("%"));
            annotate_unit(g.children, "RFDLPeriod", QStringLiteral("s"));
            break;
        }
        case 1: {  // 站点路由信息(表127):每条 16b = TEI 12b + 路由类型 4b
            auto& g = group(out.tree, QStringLiteral("IE[%1] Station Route [%2B]").arg(ie_idx).arg(elen));
            g.rel_start = content_abs; g.rel_len = elen;
            const int n = elen / 2;
            for (int i = 0; i < n; ++i) {
                const quint16 v = (quint16)get_bits(content, i * 2, 0, 16);
                const quint16 tei = v & 0x0FFF;
                const quint8  rt  = (quint8)((v >> 12) & 0x0F);
                auto& e = group(g.children, QStringLiteral("Route[%1]").arg(i));
                e.rel_start = content_abs + i * 2; e.rel_len = 2;
                MsduFieldNode tn;
                tn.name = QStringLiteral("TEI [12b]");
                tn.value = QString::number(tei);
                tn.rel_start = content_abs + i * 2; tn.rel_len = 2;
                e.children.append(tn);
                MsduFieldNode rn;
                rn.name = QStringLiteral("RouteType [4b]");
                rn.value = (rt < 5) ? QStringLiteral("%1 - %2").arg(rt).arg(trl::L(kRfdlRouteType[rt]))
                                    : QStringLiteral("%1 - %2").arg(rt).arg(trl::L("保留"));
                rn.rel_start = content_abs + i * 2 + 1; rn.rel_len = 1;
                e.children.append(rn);
            }
            break;
        }
        case 2: {  // 邻居信道信息非位图版(表128/129)
            auto& g = group(out.tree, QStringLiteral("IE[%1] Neighbor Ch Info [%2B]").arg(ie_idx).arg(elen));
            g.rel_start = content_abs; g.rel_len = elen;
            if (content.size() < 1) { pa::warn("gw_2022:content_short", QStringLiteral("neighbor ch info <1B")); break; }
            const quint8 combo = (quint8)get_bits(content, 0, 0, 4);
            if (combo > 9) {  // 组合类型越界(表129 仅 0-9):内容 hex 兜底,避免静默丢弃
                pa::warn("gw_2022:combo_unsupported", QStringLiteral("non-bitmap combo=%1>9").arg(combo));
                g.value = QString(content.toHex(' '));
                break;
            }
            const RfdlChCombo& cb = kRfdlNonBitmap[combo];
            const int entry_bits = 12 + cb.rcv + cb.snr + cb.rssi;
            // 表128/129 头:信道信息组合类型(0,0-3,4b)+保留(0,4-7,4b)——此前整字节跳过未渲染
            {
                QStringList sem;
                sem << QStringLiteral("TEI");
                if (cb.rcv) sem << QStringLiteral("Rcv%1b").arg(cb.rcv);
                if (cb.snr) sem << QStringLiteral("SNR%1b").arg(cb.snr);
                if (cb.rssi) sem << QStringLiteral("RSSI%1b").arg(cb.rssi);
                MsduFieldNode& hd = group(g.children, QStringLiteral("ChannelInfoHead"));
                hd.rel_start = content_abs; hd.rel_len = 1;
                MsduFieldNode& ct = group(hd.children, QStringLiteral("ComboType"),
                    trl::L("%1 - %2 (%3b/邻居)").arg(combo)
                        .arg(sem.join(QLatin1Char('+'))).arg(entry_bits));
                ct.rel_start = content_abs; ct.rel_len = 1;
                MsduFieldNode& cr = group(hd.children, QStringLiteral("RSV [4b]"),
                    QString::number(get_bits(content, 0, 4, 4)));
                cr.rel_start = content_abs; cr.rel_len = 1;
            }
            const int total_bits = content.size() * 8;  // 内容绝对末位(邻居自 bit8 起)
            int bitpos = 8;   // 跳过组合类型字节
            int i = 0;
            while (bitpos + entry_bits <= total_bits) {
                auto& e = group(g.children, QStringLiteral("Neighbor[%1]").arg(i));
                bitpos = rfdl_neighbour_bits(e, content, bitpos, cb, content_abs, /*has_tei=*/true,
                                     0, &out.topo_event.rssi_entries,
                                     &out.topo_event.neighbor_rates, &out.topo_event.neighbor_snrs);
                ++i;
            }
            break;
        }
        case 3: {  // 邻居信道信息位图版(表136/137)
            auto& g = group(out.tree, QStringLiteral("IE[%1] Neighbor Ch Bitmap [%2B]").arg(ie_idx).arg(elen));
            g.rel_start = content_abs; g.rel_len = elen;
            if (content.size() < 2) { pa::warn("gw_2022:content_short", QStringLiteral("neighbor ch bitmap %1B<2B").arg(content.size())); break; }
            const quint8 combo = (quint8)get_bits(content, 0, 0, 4);
            if (combo > 10) {  // 组合类型越界(表137 仅 0-10):内容 hex 兜底,避免静默丢弃
                pa::warn("gw_2022:combo_unsupported", QStringLiteral("bitmap combo=%1>10").arg(combo));
                g.value = QString(content.toHex(' '));
                break;
            }
            const RfdlChCombo& cb = kRfdlBitmap[combo];
            const int entry_bits = cb.rcv + cb.snr + cb.rssi;
            const int total_bits = content.size() * 8;  // 越界防护基准(与 gw_2026 P1 同)
            // 表136/137 头:信道信息组合类型(0,0-3,4b)+保留(0,4-7,4b)——此前整字节跳过未渲染
            {
                QStringList sem;
                if (cb.rcv) sem << QStringLiteral("Rcv%1b").arg(cb.rcv);
                if (cb.snr) sem << QStringLiteral("SNR%1b").arg(cb.snr);
                if (cb.rssi) sem << QStringLiteral("RSSI%1b").arg(cb.rssi);
                MsduFieldNode& hd = group(g.children, QStringLiteral("ChannelInfoHead"));
                hd.rel_start = content_abs; hd.rel_len = 1;
                MsduFieldNode& ct = group(hd.children, QStringLiteral("ComboType"),
                    trl::L("%1 - %2 (%3b/邻居)").arg(combo)
                        .arg(sem.join(QLatin1Char('+'))).arg(entry_bits));
                ct.rel_start = content_abs; ct.rel_len = 1;
                MsduFieldNode& cr = group(hd.children, QStringLiteral("RSV [4b]"),
                    QString::number(get_bits(content, 0, 4, 4)));
                cr.rel_start = content_abs; cr.rel_len = 1;
            }
            int off = 1;   // 跳过组合类型字节
            int k = 0;
            while (off + 4 <= content.size()) {
                const quint16 start_tei = (quint16)get_bits(content, off, 0, 12);
                const quint8  bmp_size  = (quint8)content[off + 2];
                if (off + 3 + bmp_size > content.size()) { pa::warn("gw_2022:bitmap_overflow", QStringLiteral("bmp_size=%1 exceeds remaining %2").arg(bmp_size).arg(content.size()-off-3)); break; }
                const QByteArray bmp = content.mid(off + 3, bmp_size);
                int nk = 0;
                for (int i = 0; i < bmp.size(); ++i)
                    for (int j = 0; j < 8; ++j)
                        if (bmp[i] & (1u << j)) ++nk;
                auto& kg = group(g.children, QStringLiteral("Group[%1] StartTEI=%2").arg(k).arg(start_tei));
                kg.rel_start = content_abs + off; kg.rel_len = 3 + bmp_size + (nk * entry_bits + 7) / 8;
                // 表136/137 组内:起始TEI 12b(off+0 起)+保留 4b(off+1 bit4-7)+位图大小 1B(off+2)
                MsduFieldNode& st = group(kg.children, QStringLiteral("StartTEI"), QString::number(start_tei));
                st.rel_start = content_abs + off; st.rel_len = 2;
                MsduFieldNode& gr = group(kg.children, QStringLiteral("RSV [4b]"),
                    QString::number(get_bits(content, off + 1, 4, 4)));
                gr.rel_start = content_abs + off + 1; gr.rel_len = 1;
                MsduFieldNode& bl = group(kg.children, QStringLiteral("BitmapSize [8b]"), QString::number(bmp_size));
                bl.rel_start = content_abs + off + 2; bl.rel_len = 1;
                QVector<QPair<int,int>> bm_pos;   // 置位位(位图内字节,位)
                // 位图组(表136/137):hex + 置位 TEI 推导(bit i = StartTEI+i,LSB 在前)
                // + 逐位子节点(仅 bit=1,值标注该 bit 所在的字节号,与下方条目一一对应)
                {
                    QStringList teis;
                    for (int i = 0; i < bmp.size() * 8; ++i)
                        if (bmp[i / 8] & (1u << (i % 8))) {
                            teis << QString::number(start_tei + i);
                            bm_pos.append({i / 8, i % 8});
                        }
                    MsduFieldNode bn;
                    bn.name = QStringLiteral("Bitmap [%1b]").arg(bmp.size() * 8);
                    bn.value = QStringLiteral("0x%1 (TEI: %2)")
                                   .arg(QString(bmp.toHex()))
                                   .arg(teis.isEmpty() ? QStringLiteral("-")
                                                       : teis.join(QLatin1String(",")));
                    bn.rel_start = content_abs + off + 3;
                    bn.rel_len   = bmp.size();
                    for (int i = 0; i < bmp.size() * 8; ++i)
                        if (bmp[i / 8] & (1u << (i % 8))) {
                            MsduFieldNode bp = group(bn.children,
                                QStringLiteral("Neighbor[%1] TEI=%2").arg(i).arg(start_tei + i),
                                trl::L("在位图(第%1字节)").arg(i / 8));
                            bp.rel_start = content_abs + off + 3 + (i / 8);
                            bp.rel_len = 1;
                        }
                    kg.children.append(bn);
                }
                int bitpos = (off + 3 + bmp_size) * 8;  // 邻居信道信息起始位
                for (int i = 0; i < nk; ++i) {
                    // P1 同款越界防护(与 gw_2026 对齐):位图置位数 nk 是发端声明,截断帧可虚大
                    if (bitpos + entry_bits > total_bits) { pa::warn("gw_2022:entry_overflow", QStringLiteral("entry %1bit @%2 exceeds %3").arg(entry_bits).arg(bitpos).arg(total_bits)); break; }
                    auto& e = group(kg.children, trl::L("Neighbor[%1] (位图 byte %2 bit %3)")
                        .arg(i).arg(bm_pos[i].first).arg(bm_pos[i].second));
                    const quint16 ntei = (quint16)(start_tei + bm_pos[i].first * 8 + bm_pos[i].second);
                    bitpos = rfdl_neighbour_bits(e, content, bitpos, cb, content_abs, /*has_tei=*/false,
                                                 ntei, &out.topo_event.rssi_entries,
                                                 &out.topo_event.neighbor_rates, &out.topo_event.neighbor_snrs);
                }
                off = (bitpos + 7) / 8;   // 下一组自本组实际消费末尾起(截断时按已解析推进)
                ++k;
            }
            break;
        }
        default: {  // 保留/未知类型:整段 hex
            pa::warn("gw_2022:unknown_ie", QStringLiteral("IE type=%1 len=%2 (hex fallback)").arg(ie_type).arg(elen));
            auto& g = group(out.tree, QStringLiteral("IE[%1] Reserved [%2B]").arg(ie_idx).arg(elen),
                            QString(content.toHex(' ')));
            g.rel_start = content_abs; g.rel_len = elen;
            break;
        }
        }
        pos += elen;
        ++ie_idx;
    }
}

// 系统启动原因(HDC2.0 表45/表66)后缀:只在版本信息字节实际存在时追加。
// 0=正常启动 1=断电重启 2=看门狗复位 3=程序指针异常;4 及以上保留,不追加。
// 版本信息在 MMe 体 b 偏移 42 起,BootReason = b[42]。
static QString boot_reason_suffix(const QByteArray& b) {
    if (b.size() <= 42) return QString();
    switch (static_cast<quint8>(b[42])) {
    case 0: return trl::L("正常启动");
    case 1: return trl::L("断电重启");
    case 2: return trl::L("看门狗复位");
    case 3: return trl::L("程序指针异常");
    default: return QString();
    }
}

// ================= 主解析 =================
MsduInfo GW_2022_MsduParser::parse(const QByteArray& body) {
    MsduInfo out;
    out.present = false;
    out.simple_head = false;
    if (body.size() < 8) { pa::warn("gw_2022:content_short", QStringLiteral("body %1B<8B").arg(body.size())); return out; }

    const quint8* p = reinterpret_cast<const quint8*>(body.constData());
    // 单跳帧判定:版本字段(字节0 低4位)==1 为单跳帧协议(表2/5.1.1.4.2);
    // 0 为标准帧协议,其余为保留(旧实现只判 bit0,保留奇数值会误判)
    bool simple = (p[0] & 0x0F) == 0x01;

    if (simple) {
        out.simple_head = true;
        add_fields(out.tree, body, 0, kMsduBaseSSpec, kMsduBaseSSpecN);
        // MSDUType 简头字典(表12):0 发现列表消息 128 应用层报文 129 IPv4 报文
        translate_enum_sparse(out.tree, "MSDUType", {
            {0, QStringLiteral("Discovery List Message")},
            {128, QStringLiteral("Application Level Message")},
            {129, QStringLiteral("IPv4 Message")},
        });
        quint8 msdu_type = (quint8)get_bits(p, 1, 0, 8);
        int   msdu_len   = (int)get_bits(p, 2, 0, 11);
        if (msdu_len > body.size() - 4) msdu_len = body.size() - 4;  // 防声明长度越界
        QByteArray msdu_body = body.mid(4, msdu_len);
        if (static_cast<GW_2022_MsduSType>(msdu_type) == GW_2022_MsduSType::DISCOVERY_LIST) {
            // 消息类型0 = 无线发现列表(表123),按 TLV 逐字段解析
            out.summary = trl::L("发现列表消息");
            parse_rfdl(out, msdu_body, 4);   // RFDL 载荷自单跳头(4B)之后
        } else {
            out.summary = trl::L("单跳 MSDU 类型 %1").arg(msdu_type);
        }
        out.present = true;
        return out;
    }

    // ---- 标准 MSDU_BASE(16B 头, MACAddrFlag=1 时 28B)----
    if (body.size() < 16) { pa::warn("gw_2022:content_short", QStringLiteral("body %1B<16B").arg(body.size())); return out; }
    add_fields(out.tree, body, 0, kMsduBaseSpec, kMsduBaseSpecN);
    annotate_msdu_base(out.tree);   // 标志/枚举字段加数值解释
    out.msdu_seq = (quint16)get_bits(p, 5, 0, 16);   // MSDU Seq(MSDUIndex)
    // 原始发起/终点 TEI(长头 MSDU_BASE;供列表 Orig 列与方向判定)
    out.msdu_src_tei  = (int)get_bits(p, 0, 4, 12);
    out.msdu_dst_tei  = (int)get_bits(p, 2, 0, 12);
    out.msdu_send_type = (int)get_bits(p, 3, 4, 4);   // 广播类型判定
    out.route_hops_left     = (quint8)get_bits(p, 10, 4, 4); // 路由剩余跳数(表4 byte10 bit4-7)
    out.broadcast_direction = (quint8)get_bits(p, 11, 0, 2); // 广播方向(国网表7:0双向/1下行/2上行)
    out.restart_count  = (quint8)get_bits(p, 9, 3, 4); // RestartCount(国网 MSDU 头 byte9 bits3-6,发送方重启次数)
    quint8 msdu_type   = (quint8)get_bits(p, 7, 0, 8);
    int    msdu_len    = (int)get_bits(p, 8, 0, 11);
    bool   mac_flag    = get_bits(p, 11, 3, 1) != 0;
    int    head_size   = mac_flag ? 28 : 16;

    if (mac_flag && body.size() >= 28) {
        add_fields(out.tree, body, 0, kMsduMacSpec, 2);
        // 提取源/目的 MAC(48-bit),供 TEI→MAC 映射表与列表地址显示
        out.msdu_src_mac = get_bits(p, 16, 0, 48);
        out.msdu_dst_mac = get_bits(p, 22, 0, 48);
    }

    // MSDU 数据区从 head_size 起;头不完整(mac_flag 但 body<28)时无法解析,直接放弃
    if (body.size() < head_size) {
        pa::warn("gw_2022:truncated", QStringLiteral("body %1B < head_size %2").arg(body.size()).arg(head_size));
        out.present = false;
        return out;
    }
    if (msdu_len > body.size() - head_size) {
        pa::warn("gw_2022:truncated", QStringLiteral("msdu_len %1 > avail %2").arg(msdu_len).arg(body.size()-head_size));
        // 声明长度超出实际帧长:异常帧,标记但跳过深解析(避免 MMe/APP 子字段越界)
        out.present = true;
        out.summary = trl::L("MSDU 截断(长度 %1 > 可用 %2)")
                          .arg(msdu_len).arg(body.size() - head_size);
        return out;
    }
    QByteArray msdu_body = body.mid(head_size, msdu_len);
    out.present = true;

    if (static_cast<GW_2022_MsduType>(msdu_type) == GW_2022_MsduType::NET_MANAGEMENT) {
        // ---- 网络管理消息:MMe_BASE(4B) ----
        if (msdu_body.size() < 4) {
            pa::warn("gw_2022:truncated", QStringLiteral("MMe body %1B<4B").arg(msdu_body.size()));
            out.summary = trl::L("MMe (截断)");
            return out;
        }
        quint8 mm_type = (quint8)get_bits(msdu_body, 0, 0, 8);
        out.mme_type = mm_type;
        out.summary = mme_type_name(mm_type);
        auto& root = group(out.tree, QStringLiteral("MMe: %1").arg(out.summary));

        // MMe_BASE 头 4B = [MMType 2B(小端)][RSV 2B];真实帧如 08 00 00 00。
        // MMType 字段行(数值 + 类型名,高亮指向 MMe_BASE 前 2 字节)
        {
            MsduFieldNode mt;
            mt.name = QStringLiteral("MMType [16b]");
            quint16 mmv = (quint16)get_bits(msdu_body, 0, 0, 16);
            mt.value = QStringLiteral("%1 - %2").arg(mmv).arg(out.summary);
            mt.rel_start = head_size;   // MMe_BASE 位于 msdu_body[0],相对 body 起点
            mt.rel_len   = 2;           // MMType 占 2 字节
            root.children.append(mt);
        }
        // RSV 16bit(byte2-3)
        MsduFieldNode rsv;
        rsv.name  = QStringLiteral("RSV [16b]");
        rsv.value = QString::number(get_bits(msdu_body, 2, 0, 16));
        rsv.rel_start = head_size + 2;
        rsv.rel_len   = 2;
        root.children.append(rsv);

        // body 从 MMeHeadSize=4 起
        QByteArray b = msdu_body.mid(4);
        switch (static_cast<GW_2022_MMeType>(mm_type)) {
            case GW_2022_MMeType::MME_ASSOC_REQ: {
                // MMeAssocReq(关联请求),字段按 51321/表60 结构:
                // 固定区(0..23)→ 厂家自定义信息(24-41)→ 站点版本信息
                // (42-51,组)→ 复位计数/代理类型/端到端序号(52..60)→ 管理ID
                add_fields(root.children, b, 0, kAssocReqSpec, kAssocReqSpecN, head_size + 4);
                // STAMACAddr(0,0,48):关联请求源 TEI 未知(0)时,供 Source 列显示 STA-X [MAC]
                out.sta_mac = get_bits(b, 0, 0, 48);
                // 拓扑事件:关联请求(STA 正在入网;TEI 未分配,用 tei=0 承载 MAC)
                out.topo_event.kind = TopoEventKind::AssocReq;
                out.topo_event.nodes.append({0, out.sta_mac});
                // STA 重启检测用:关联请求由 STA 本人发出,MSDU 头 RestartCount 即该 STA 的;
                // 0xFF=无此字段不检测
                if (out.restart_count != kRestartCountInvalid)
                    out.topo_event.restart_count = (int)out.restart_count;
                out.topo_event.desc = trl::L("关联请求: STA %1 正在入网")
                    .arg(mac_str(out.sta_mac));
                if (const QString reason = boot_reason_suffix(b); !reason.isEmpty())
                    out.topo_event.desc = trl::L("关联请求: STA %1 正在入网（%2）")
                        .arg(mac_str(out.sta_mac)).arg(reason);
                MsduFieldNode mn;
                mn.name  = QStringLiteral("ManufacturerInfo [144b]");
                mn.value = bytes_hex(b, 24, 18);
                mn.rel_start = head_size + 4 + 24;
                mn.rel_len   = 18;
                root.children.append(mn);
                // 站点版本信息(513211 表66)
                auto& ver = group(root.children, trl::L("站点版本信息"));
                add_fields(ver.children, b, 42, kStaVerSpec, kStaVerSpecN, head_size + 4);
                for (auto& v : ver.children) {
                    // 软件版本号:BCD(与本地通信模块接口协议一致)
                    if (v.name.startsWith(QStringLiteral("SoftwareVersion")))
                        v.value += QStringLiteral(" (BCD)");
                    // 厂商代码:ASCII(表66;值为 2 字节 ASCII)
                    else if (v.name.startsWith(QStringLiteral("ManufacturerID"))) {
                        const QByteArray as = b.mid(48, 2);
                        QString a;
                        for (char c : as) a += c >= 0x20 && c < 0x7F ? c : '.';
                        v.value = QStringLiteral("\"%1\" (0x%2)")
                                      .arg(a).arg(quint16(v.value.toUInt(nullptr, 16)),
                                                  4, 16, QChar('0'));
                    }
                }
                apply_dicts(ver.children);   // 系统启动原因字典(表67)
                add_fields(root.children, b, 0, kAssocReqTailSpec, kAssocReqTailSpecN,
                           head_size + 4);
                apply_dicts(root.children);
                // 相线可信程度说明(参考南网6.8.14):第一/第二/第三相线依次高/中/低可信
                for (auto& ch : root.children) {
                    if (ch.name.startsWith(QStringLiteral("CandidateLinePhase0")))
                        ch.value += trl::L(" (高可信)");
                    else if (ch.name.startsWith(QStringLiteral("CandidateLinePhase1")))
                        ch.value += trl::L(" (中可信)");
                    else if (ch.name.startsWith(QStringLiteral("CandidateLinePhase2")))
                        ch.value += trl::L(" (低可信)");
                }
                // 代理类型(表69):0=站点动态选择的代理,其它保留
                for (auto& ch : root.children) {
                    if (ch.name.startsWith(QStringLiteral("ProxyType"))) {
                        quint8 pt = (quint8)get_bits(b, 56, 0, 8);
                        ch.value = QStringLiteral("%1 - %2").arg(pt).arg(
                            pt == 0 ? trl::L("站点动态选择的代理")
                                    : trl::L("保留"));
                    }
                }
                MsduFieldNode mid;
                mid.name  = QStringLiteral("ManagementID [192b]");
                mid.value = bytes_hex(b, 64, 24);
                mid.rel_start = head_size + 4 + 64;
                mid.rel_len   = 24;
                root.children.append(mid);
                break;
            }
            case GW_2022_MMeType::MME_ASSOC_CNF: {
                // MMeAssocCnf(关联确认):固定头到 b[40],RouteInfo 从 b[40] 起
                add_fields(root.children, b, 0, kAssocCnfSpec, kAssocCnfSpecN, head_size + 4);
                // 拓扑事件:关联确认(STA 入网 + 代理 + CCO MAC);仅成功(0=成功,0x0A=再次入网成功)时更新拓扑
                {
                    const quint8 assoc_res = (quint8)get_bits(b, 12, 0, 8);
                    const quint64 sta_mac = get_bits(b, 0, 0, 48);
                    const quint64 cco_mac = get_bits(b, 6, 0, 48);
                    const quint16 sta_tei = (quint16)get_bits(b, 14, 0, 12);
                    const quint16 proxy_tei = (quint16)get_bits(b, 16, 0, 12);
                    if (assoc_res != 0 && assoc_res != 0x0A) {
                        // 关联失败:不更新拓扑(但保留字段解析)
                    } else {
                    out.topo_event.kind = TopoEventKind::AssocCnf;
                    // 链路类型(关联确认 kAssocCnfSpec byte15 bit4):0=HPLC载波/1=HRF无线,确认 STA 接入方式
                    out.topo_event.link_type = (int)get_bits(b, 15, 4, 1);
                    out.topo_event.is_rf = (get_bits(b, 15, 4, 1) != 0);
                    out.topo_event.is_rf_known = true;
                    if (cco_mac) out.topo_event.cco_mac = cco_mac;
                    if (sta_tei && sta_mac) out.topo_event.nodes.append({sta_tei, sta_mac});
                    if (sta_tei && proxy_tei) out.topo_event.routes.append({sta_tei, proxy_tei});
                    out.topo_event.desc = trl::L("关联确认: STA TEI=%1 入网 代理=%2")
                        .arg(sta_tei)
                        .arg(proxy_tei ? QString::number(proxy_tei) : QStringLiteral("-"));
                    }
                }
                apply_dicts(root.children);
                annotate_unit(root.children, "STAReAssocTime", QStringLiteral("ms"));
                // 修正 AssocResult 可读文本
                for (auto& ch : root.children) {
                    if (ch.name.startsWith(QStringLiteral("AssocResult")))
                        ch.value = assoc_result_str((quint8)get_bits(b, 12, 0, 8));
                }
                int off = 40;  // 路由表信息起点(表74;MMeHeadSize 4 + 固定 36)
                if (b.size() >= off + 8) {
                    const int rel0 = head_size + 4 + 40;
                    quint16 sta_sum  = (quint16)get_bits(b, off + 0, 0, 16);
                    quint16 pco_sum  = (quint16)get_bits(b, off + 2, 0, 16);
                    quint16 route_sz = (quint16)get_bits(b, off + 4, 0, 16);
                    quint16 rsv3     = (quint16)get_bits(b, off + 6, 0, 16);
                    // 路由信息头(表74):直连站点数/直连代理数/路由表大小/保留
                    auto& route = group(root.children, QStringLiteral("RouteInfo"),
                                        QStringLiteral("%1 B").arg(route_sz));
                    MsduFieldNode r1;
                    r1.name  = QStringLiteral("StraightSTASum [16b]");
                    r1.value = QString::number(sta_sum);
                    r1.rel_start = rel0 + 0; r1.rel_len = 2;
                    route.children.append(r1);
                    MsduFieldNode r2;
                    r2.name  = QStringLiteral("StraightPCOSum [16b]");
                    r2.value = QString::number(pco_sum);
                    r2.rel_start = rel0 + 2; r2.rel_len = 2;
                    route.children.append(r2);
                    MsduFieldNode r3;
                    r3.name  = QStringLiteral("RouteInfoTableSize [16b]");
                    r3.value = QStringLiteral("%1 B").arg(route_sz);
                    r3.rel_start = rel0 + 4; r3.rel_len = 2;
                    route.children.append(r3);
                    MsduFieldNode r4;
                    r4.name  = QStringLiteral("RSV3 [16b]");
                    r4.value = QString::number(rsv3);
                    r4.rel_start = rel0 + 6; r4.rel_len = 2;
                    route.children.append(r4);
                    off += 8;
                    // 直连站点表(表75 前半):2B/条 = TEI(12b)+链路类型(1b)+保留(3b)
                    for (int i = 0; i < sta_sum && off + 2 <= b.size(); ++i) {
                        quint16 e = (quint16)get_bits(b, off, 0, 16);
                        off += 2;
                        MsduFieldNode sn;
                        sn.name = QStringLiteral("STA[%1]").arg(i);
                        sn.value = QStringLiteral("TEI=%1 LinkType=%2")
                                       .arg(e & 0x0FFF).arg((e >> 12) & 0x01);
                        sn.rel_start = rel0 + 8 + 2 * i;
                        sn.rel_len   = 2;
                        route.children.append(sn);
                    }
                    // 直连代理表(表75 后半):代理 2B(TEI12+链路1+保留3)+子站点数
                    // 2B + 子站点 2B/条(TEI12+保留4b)
                    for (int i = 0; i < pco_sum && off + 4 <= b.size(); ++i) {
                        quint16 tei    = (quint16)get_bits(b, off + 0, 0, 12);
                        quint8  plink  = (quint8)get_bits(b, off + 1, 4, 1);
                        quint16 child  = (quint16)get_bits(b, off + 2, 0, 16);
                        MsduFieldNode pn;
                        pn.name = QStringLiteral("PCO[%1]").arg(tei);
                        pn.value = QStringLiteral("LinkType=%1 childSum=%2")
                                       .arg(plink).arg(child);
                        pn.rel_start = rel0 + 8 + 2 * sta_sum + i * 4;
                        pn.rel_len   = 4;
                        route.children.append(pn);
                        off += 4;
                        for (int j = 0; j < child && off + 2 <= b.size(); ++j) {
                            quint16 ctei = (quint16)get_bits(b, off, 0, 16);
                            off += 2;
                            MsduFieldNode cn;
                            cn.name = QStringLiteral("Child[%1]").arg(j);
                            cn.value = QStringLiteral("TEI=%1").arg(ctei & 0x0FFF);
                            cn.rel_start = pn.rel_start + 4 + 2 * j;
                            cn.rel_len   = 2;
                            pn.children.append(cn);
                        }
                    }
                }
                break;
            }
            case GW_2022_MMeType::MME_ASSOC_GATHER_IND: {
                // MMeAssocGatherInd(关联汇总指示,5134):固定头 16B(表76)
                // + 站点信息表(表78,每条 8B=MAC6+TEI12b+保留4b,16 起)
                add_fields(root.children, b, 0, kAssocGatherIndSpec,
                           kAssocGatherIndSpecN, head_size + 4);
                apply_dicts(root.children);
                // 结果(51342):固定 0=允许加入网络,其它无效
                for (auto& ch : root.children) {
                    if (!ch.name.startsWith(QStringLiteral("AssocResult"))) continue;
                    quint8 ar = (quint8)get_bits(b, 0, 0, 8);
                    ch.value = QStringLiteral("%1 - %2").arg(ar).arg(
                        ar == 0 ? QStringLiteral("Allowed to join network")
                                : QStringLiteral("Invalid"));
                }
                int sta_num = (int)get_bits(b, 11, 0, 8);  // 汇总站点数(51347)
                int off = 16;                              // 站点信息起点
                // 拓扑事件:关联汇总(批量站点入网 + 代理);仅 AssocResult=0(允许加入网络)时更新拓扑
                const quint8 gar = (quint8)get_bits(b, 0, 0, 8);
                const quint16 gproxy_tei = (quint16)get_bits(b, 8, 0, 12);
                const bool g_ok = (gar == 0);
                if (g_ok) {
                    const quint64 gcco_mac = (quint64)get_bits(b, 2, 0, 48);
                    out.topo_event.kind = TopoEventKind::AssocGatherInd;
                    if (gcco_mac) out.topo_event.cco_mac = gcco_mac;
                    out.topo_event.desc = trl::L("关联汇总: %1 个站点入网 代理=%2")
                        .arg(sta_num)
                        .arg(gproxy_tei ? QString::number(gproxy_tei) : QStringLiteral("-"));
                }
                if (sta_num > 0 && off + 8 <= b.size()) {
                    auto& sgi = group(root.children,
                                      QStringLiteral("STAInfo [%1]").arg(sta_num));
                    for (int i = 0; i < sta_num && off + 8 <= b.size(); ++i) {
                        const int rel0 = head_size + 4 + off;
                        const quint64 gsta_mac = (quint64)get_bits(b, off, 0, 48);
                        const quint16 gsta_tei = (quint16)get_bits(b, off + 6, 0, 12);
                        if (g_ok) {
                            if (gsta_tei && gsta_mac) out.topo_event.nodes.append({gsta_tei, gsta_mac});
                            if (gsta_tei && gproxy_tei) out.topo_event.routes.append({gsta_tei, gproxy_tei});
                        }
                        auto& ns = group(sgi.children,
                                         QStringLiteral("NewSTA[%1]").arg(i));
                        MsduFieldNode mac;
                        mac.name  = QStringLiteral("STAMACAddr [48b]");
                        mac.value = mac_str(gsta_mac);
                        mac.rel_start = rel0; mac.rel_len = 6;
                        ns.children.append(mac);
                        MsduFieldNode tei;
                        tei.name  = QStringLiteral("STATEI [12b]");
                        tei.value = QString::number(gsta_tei);
                        tei.rel_start = rel0 + 6; tei.rel_len = 2;
                        ns.children.append(tei);
                        MsduFieldNode rv;
                        rv.name  = QStringLiteral("RSV0 [4b]");
                        rv.value = QString::number((quint8)get_bits(b, off + 7, 4, 4));
                        rv.rel_start = rel0 + 7; rv.rel_len = 1;
                        ns.children.append(rv);
                        off += 8;
                    }
                }
                break;
            }
            case GW_2022_MMeType::MME_CHANGE_PROXY_REQ:
                add_fields(root.children, b, 0, kChangeProxyReqSpec, kChangeProxyReqSpecN, head_size + 4);
                // 拓扑事件:代理变更请求(仅记录入表,不更新拓扑;待确认后更新)
                {
                    const quint16 sta_tei = (quint16)get_bits(b, 0, 0, 12);
                    const quint16 new_proxy = (quint16)get_bits(b, 2, 0, 12);
                    const quint16 old_proxy = (quint16)get_bits(b, 12, 0, 12);
                    if (sta_tei) {
                        out.topo_event.kind = TopoEventKind::ChangeProxyReq;
                        out.topo_event.desc = trl::L("代理变更请求: STA TEI=%1 %2→%3")
                            .arg(sta_tei)
                            .arg(old_proxy ? QString::number(old_proxy) : QStringLiteral("-"))
                            .arg(new_proxy ? QString::number(new_proxy) : QStringLiteral("-"));
                    }
                }
                apply_dicts(root.children);
                // 代理类型(表81):0=站点动态选择的代理,其他保留 / 0=station-dynamic proxy, else reserved
                for (auto& ch : root.children) {
                    if (ch.name.startsWith(QStringLiteral("ProxyType"))) {
                        quint8 pt = (quint8)get_bits(b, 14, 0, 8);
                        ch.value = QStringLiteral("%1 - %2").arg(pt).arg(
                            pt == 0 ? trl::L("站点动态选择的代理") : trl::L("保留"));
                    }
                }
                break;
            case GW_2022_MMeType::MME_CHANGE_PROXY_BITMAP_CNF: {
                // MMeChangeProxyBitMapCnf:固定头到 b[20],随后 BitMap(BitMapSize 字节)
                add_fields(root.children, b, 0, kChangeProxyBitMapCnfSpec, kChangeProxyBitMapCnfSpecN, head_size + 4);
                apply_dicts(root.children);
                int bm_size = (int)get_bits(b, 2, 0, 16);
                if (bm_size > 0 && b.size() >= 20 + bm_size) {
                    auto& bmg = group(root.children, QStringLiteral("ProxyChildSTA BitMap [%1B]").arg(bm_size));
                    QByteArray bm = b.mid(20, bm_size);
                    // 拓扑事件:批量代理变更确认;仅 Result=0(成功)时更新拓扑
                    const quint8 bmres = (quint8)get_bits(b, 0, 0, 8);
                    const quint16 bmproxy_tei = (quint16)get_bits(b, 6, 0, 12);
                    const bool bm_ok = (bmres == 0);
                    int bm_cnt = 0;
                    if (bm_ok) {
                        out.topo_event.kind = TopoEventKind::ChangeProxyCnf;
                        // 链路类型(位图确认 kChangeProxyBitMapCnfSpec):0=HPLC载波/1=HRF无线
                        out.topo_event.is_rf = (get_bits(b, 5, 4, 1) != 0);
                        out.topo_event.is_rf_known = true;
                        out.topo_event.link_type = (int)get_bits(b, 5, 4, 1);
                    }
                    QString teis;
                    for (int i = 0; i < bm.size(); ++i) {
                        quint8 byte = (quint8)bm[i];
                        for (int j = 0; j < 8; ++j) {
                            if (byte & (1u << j)) {
                                const quint16 ctei = (quint16)(8 * i + j);
                                teis += QString("%1, ").arg(ctei);
                                if (bm_ok && ctei && bmproxy_tei) {
                                    out.topo_event.routes.append({ctei, bmproxy_tei});
                                    ++bm_cnt;
                                }
                            }
                        }
                    }
                    if (bm_ok) {
                        out.topo_event.desc = trl::L("代理变更(批量): %1 个站点代理→%2")
                            .arg(bm_cnt)
                            .arg(bmproxy_tei ? QString::number(bmproxy_tei) : QStringLiteral("-"));
                    }
                    MsduFieldNode bl;
                    bl.name  = QStringLiteral("ChildSTATEI");
                    bl.value = teis.isEmpty() ? QStringLiteral("(none)") : teis;
                    bmg.children.append(bl);
                }
                break;
            }
            case GW_2022_MMeType::MME_HEARTBEAT_CHECK: {
                // MMeHeartBeatCheck:bitmap → TEI 列表
                add_fields(root.children, b, 0, kHeartBeatSpec, kHeartBeatSpecN, head_size + 4);
                apply_dicts(root.children);
                int bm_size = (int)get_bits(b, 6, 0, 16);
                if (bm_size > 0 && b.size() >= 8 + bm_size) {
                    QByteArray bm = b.mid(8, bm_size);
                    const int rel0 = head_size + 4 + 8;  // bitmap 相对 body 起点
                    auto& hlg = group(root.children, QStringLiteral("DiscoverSTAList"));
                    int order = 0;
                    for (int i = 0; i < bm.size(); ++i) {
                        quint8 byte = (quint8)bm[i];
                        QString teis;
                        for (int j = 0; j < 8; ++j) {
                            if (!(byte & (1u << j))) continue;
                            if (!teis.isEmpty()) teis += QStringLiteral(", ");
                            teis += QString::number(8 * i + j);
                            ++order;
                        }
                        if (teis.isEmpty()) continue;   // 该字节无置位
                        MsduFieldNode dl;
                        dl.name  = QStringLiteral("DiscoverSTATEI[%1]").arg(i);
                        dl.value = teis;
                        dl.rel_start = rel0 + i;   // 该字节
                        dl.rel_len   = 1;
                        hlg.children.append(dl);
                    }
                    if (order == 0) {
                        MsduFieldNode dl;
                        dl.name  = QStringLiteral("DiscoverSTATEI");
                        dl.value = QStringLiteral("(none)");
                        hlg.children.append(dl);
                    }
                }
                break;
            }
            case GW_2022_MMeType::MME_DISCOVER_NODE_LIST: {
                // MMeDiscoverNodeList
                add_fields(root.children, b, 0, kDiscoverNodeListSpec, kDiscoverNodeListSpecN, head_size + 4);
                // 学习 TEI→MAC:STATEI→MACAddr、CCOMACAddr(TEI=1)
                if (b.size() >= 16) {
                    const quint16 sta_tei = (quint16)get_bits(b, 0, 0, 12);
                    const quint64 sta_mac = get_bits(b, 4, 0, 48);
                    const quint64 cco_mac = get_bits(b, 10, 0, 48);
                    const quint16 proxy_tei = (quint16)get_bits(b, 1, 4, 12);
                    if (sta_tei != 0 && sta_mac)
                        out.tei_mac_pairs.append({sta_tei, sta_mac});
                    if (cco_mac)
                        out.tei_mac_pairs.append({1, cco_mac});
                    // 拓扑事件:发现列表(节点 + 代理关系 + CCO MAC)
                    out.topo_event.kind = TopoEventKind::DiscoverList;
                    out.topo_event.cco_mac = cco_mac;
                    // CCO 重启检测用:MSDU 头 RestartCount(发送方重启次数);
                    // 只有 CCO 本人发出(src_tei == kTeiCco)的发现列表才采用,STA 中继转发的
                    // 发现列表其 RestartCount 是中继 STA 的,不能用于 CCO 重启判断;
                    // 0xFF=无此字段不检测
                    if (out.restart_count != kRestartCountInvalid && out.msdu_src_tei == kTeiCco)
                        out.topo_event.restart_count = (int)out.restart_count;
                    if (sta_tei && sta_mac) out.topo_event.nodes.append({sta_tei, sta_mac});
                    if (sta_tei && proxy_tei) out.topo_event.routes.append({sta_tei, proxy_tei});
                    // 成功率:ProxyCommRate(上行)/ProxyDownCommRate(下行)为百分比,
                    // 填入 comm_rates 供 TopoState 更新通讯成功率状态(对齐南网)
                    {
                        const quint8 up_rate = (quint8)get_bits(b, 18, 0, 8);
                        const quint8 down_rate = (quint8)get_bits(b, 19, 0, 8);
                        if (sta_tei && (up_rate <= 100 || down_rate <= 100)) {
                            CommRateInfo cr;
                            cr.tei = sta_tei;
                            cr.up = (quint8)qMin<quint8>(up_rate, 100);
                            cr.down = (quint8)qMin<quint8>(down_rate, 100);
                            out.topo_event.comm_rates.append(cr);
                        }
                    }
                    out.topo_event.desc = trl::L("发现列表: STA TEI=%1 代理=%2")
                        .arg(sta_tei)
                        .arg(proxy_tei ? QString::number(proxy_tei) : QStringLiteral("-"));
                    // 载波组(表95 byte18/19/28):与代理站点通信成功率/下行/最小 → proxy_comm_rate/down/min_comm_rate
                    // (独立于 RFDL proxy_* 与 0x005E comm_rates;值 0-100,超出无效=-1)
                    {
                        const quint8 up_v  = (quint8)get_bits(b, 18, 0, 8);
                        const quint8 dwn_v = (quint8)get_bits(b, 19, 0, 8);
                        const quint8 min_v = (quint8)get_bits(b, 28, 0, 8);
                        out.topo_event.proxy_comm_rate      = (up_v  <= 100) ? (qint32)up_v  : -1;
                        out.topo_event.proxy_down_comm_rate = (dwn_v <= 100) ? (qint32)dwn_v : -1;
                        out.topo_event.min_comm_rate        = (min_v <= 100) ? (qint16)min_v : -1;
                    }
                }
                apply_dicts(root.children);
                // 成功率字段带 %(与 Python log "ProxyCommRate: 85%" 一致)
                annotate_unit(root.children, "ProxyCommRate", QStringLiteral("%"));
                annotate_unit(root.children, "MinCommRate", QStringLiteral("%"));
                annotate_unit(root.children, "ProxyDownCommRate", QStringLiteral("%"));
                annotate_unit(root.children, "EvaluateBeginTimeout", QStringLiteral("s"));
                annotate_unit(root.children, "ProxyChannelQuality", QStringLiteral("dB"));
                int up_route_num = (int)get_bits(b, 23, 0, 8);
                int bitmap_size  = (int)get_bits(b, 26, 0, 16);
                int node_num     = (int)get_bits(b, 20, 0, 16);
                int off = 32;  // 固定头 32B(MMeHead 4 + DiscoverNodeList 28)
                // UpRoute 条目:2B/条 NextHopTEI(0,0,12) + RouteType(1,4,4)
                // 与 Python MMe_UpRouteInfo 一致;RouteTypeDict 含义翻译
                // 同步提取 NextHopTEI 入 topo_event.up_routes,供 TopoState 识别
                // 上行路径变化(对齐南网)
                if (up_route_num > 0 && off + up_route_num * 2 <= b.size()) {
                    const quint16 ur_sta_tei = (quint16)get_bits(b, 0, 0, 12);
                    auto& upg = group(root.children, QStringLiteral("UpRouteEntryList [%1]").arg(up_route_num));
                    for (int i = 0; i < up_route_num; ++i) {
                        quint16 tei = (quint16)get_bits(b, off, 0, 12);
                        quint8  rtype = (quint8)get_bits(b, off + 1, 4, 4);
                        // 仅代理主路径(RouteType=3)为该 STA 父节点,其余路由类型忽略
                        if (ur_sta_tei && tei && rtype == 3)
                            out.topo_event.up_routes.append({ur_sta_tei, tei});
                        int abs0 = head_size + 4 + off;   // 条目相对 body 起点
                        off += 2;
                        // 每条目分组
                        auto& ug = group(upg.children,
                                         QStringLiteral("UpRoute[%1]").arg(i));
                        MsduFieldNode nh;
                        nh.name  = QStringLiteral("NextHopTEI [12b]");
                        nh.value = QString::number(tei);
                        nh.rel_start = abs0;      // bit0-11 跨 2B
                        nh.rel_len   = 2;
                        ug.children.append(nh);
                        MsduFieldNode rt;
                        rt.name = QStringLiteral("RouteType [4b]");
                        // 表98 路由类型(中文 key,随界面语言;勿用 QLatin1String 直出中文)
                        static const char* rtd[] = {
                            "错误路由类型", "同级路由类型", "上级路由类型",
                            "代理主路径路由类型", "上上级路由类型"};
                        rt.value = (rtype <= 4)
                            ? QStringLiteral("%1 - %2").arg(rtype)
                                .arg(trl::L(QString::fromUtf8(rtd[rtype])))
                            : QString::number(rtype);
                        rt.rel_start = abs0 + 1;  // byte1 高 4bit
                        rt.rel_len   = 1;
                        ug.children.append(rt);
                    }
                }
                // ---- 发现站点列表位图(按字节分字段解析,勿与接收信息合并) ----
                QByteArray bm;
                int bm_base = -1;   // bitmap 相对 body 起点(供高亮)
                if (bitmap_size > 0 && off + bitmap_size <= b.size()) {
                    bm_base = head_size + 4 + off;
                    bm = b.mid(off, bitmap_size);
                    off += bitmap_size;
                }
                bool bm_any = false;
                int  nset = 0;
                QVector<QStringList> per_byte(bm.size());
                for (int i = 0; i < bm.size(); ++i) {
                    quint8 byte = (quint8)bm[i];
                    for (int j = 0; j < 8; ++j) {
                        if (!(byte & (1u << j))) continue;
                        per_byte[i] << QStringLiteral("TEI%1").arg(8 * i + j);
                        ++nset;
                    }
                    if (!per_byte[i].isEmpty()) bm_any = true;
                }
                // 邻居表:位图置位 TEI 即该 STA 发现的邻居,供 TopoState 按 STA 更新邻居表
                // 全 0 位图(nset==0)也要上报(空 neighbor_teis),以清空该 STA 的旧邻居
                {
                    const quint16 bm_sta_tei = (quint16)get_bits(b, 0, 0, 12);
                    if (bm_sta_tei) {
                        out.topo_event.discover_src_tei = bm_sta_tei;
                        out.topo_event.neighbor_teis.reserve(nset);
                        for (int i = 0; i < bm.size(); ++i) {
                            const quint8 byte = (quint8)bm[i];
                            for (int j = 0; j < 8; ++j) {
                                if (byte & (1u << j))
                                    out.topo_event.neighbor_teis.append((quint16)(8 * i + j));
                            }
                        }
                    }
                }
                if (!bm_any) {
                    // 全 0(如 bitmap size=1 且 bitmap[0]=0)→ NULL
                    MsduFieldNode bl;
                    bl.name = QStringLiteral("DiscoverySTAList BitMap [%1B]")
                                  .arg(bm.size());
                    bl.value = QStringLiteral("NULL");
                    if (bm_base >= 0) { bl.rel_start = bm_base; bl.rel_len = bm.size(); }
                    root.children.append(bl);
                } else {
                    // 逐字节一行:DiscoverySTABitMap[i] [8b] = TEI0, TEI7 …
                    auto& bmg = group(root.children,
                                      QStringLiteral("DiscoverySTAList BitMap [%1B]")
                                          .arg(bm.size()));
                    for (int i = 0; i < bm.size(); ++i) {
                        if (per_byte[i].isEmpty()) continue;   // 空字节跳过
                        MsduFieldNode bl;
                        bl.name = QStringLiteral("DiscoverySTABitMap[%1] [8b]").arg(i);
                        bl.value = per_byte[i].join(QStringLiteral(", "));
                        if (bm_base >= 0) { bl.rel_start = bm_base + i; bl.rel_len = 1; }
                        bmg.children.append(bl);
                    }
                }

                // ---- 接收发现列表信息(表99:置位 TEI 各一条,1B 计数) ----
                QByteArray cnts;
                int cnts_base = -1;  // 计数区相对 body 起点(供高亮)
                if (node_num > 0 && off + node_num <= b.size()) {
                    cnts_base = head_size + 4 + off;
                    cnts = b.mid(off, node_num);
                }
                int order = 0;
                if (bm_any && nset > 0) {
                    auto& rgi = group(root.children,
                                      QStringLiteral("ReceivedDiscoveryInfo [%1]")
                                          .arg(nset));
                    for (int i = 0; i < bm.size(); ++i) {
                        quint8 byte = (quint8)bm[i];
                        for (int j = 0; j < 8; ++j) {
                            if (!(byte & (1u << j))) continue;
                            const int tei = 8 * i + j;
                            MsduFieldNode rc;
                            // 每条含义:数量 - TEx
                            rc.name = QStringLiteral("ReceivedDiscoverCount[%1]")
                                          .arg(order);
                            if (order < cnts.size()) {
                                rc.value = QStringLiteral("%1 - TEI%2")
                                               .arg((quint8)cnts[order]).arg(tei);
                                if (cnts_base >= 0) {
                                    rc.rel_start = cnts_base + order;
                                    rc.rel_len   = 1;
                                }
                            } else {
                                rc.value = QStringLiteral("? - TEI%1").arg(tei);
                            }
                            rgi.children.append(rc);
                            ++order;
                        }
                    }
                }
                break;
            }
            case GW_2022_MMeType::MME_SUCCESS_RATE_REPORT: {
                add_fields(root.children, b, 0, kSuccessRateSpec, kSuccessRateSpecN, head_size + 4);
                apply_dicts(root.children);
                int sta_num = (int)get_bits(b, 2, 0, 16);
                int off = 4;
                // 拓扑事件:成功率上报(STA 与上级的上下行成功率)
                out.topo_event.kind = TopoEventKind::SuccessRate;
                if (sta_num > 0) {
                    auto& crg = group(root.children, QStringLiteral("CommRateInfoList [%1]").arg(sta_num));
                    for (int i = 0; i < sta_num && off + 4 <= b.size(); ++i) {
                        quint16 tei = (quint16)get_bits(b, off + 0, 0, 12);
                        quint8  rsv = (quint8)get_bits(b, off + 1, 4, 4);
                        quint8  down = (quint8)b[off + 2];
                        quint8  up   = (quint8)b[off + 3];
                        out.topo_event.comm_rates.append({tei, down, up});
                        int abs0 = head_size + 4 + off;   // 条目相对 body 起点
                        off += 4;
                        // 对齐 Python log 权威形态:
                        //   MMe_CommRateInfo STATEI: 2 DownCommRate: 100% UpCommRate: 100%
                        auto& en = group(crg.children,
                                         QStringLiteral("STA[%1]").arg(tei));
                        MsduFieldNode st;
                        st.name  = QStringLiteral("STATEI [12b]");
                        st.value = QString::number(tei);
                        st.rel_start = abs0;
                        st.rel_len   = 2;      // bit0-11 跨 2B
                        en.children.append(st);
                        MsduFieldNode rv;
                        rv.name  = QStringLiteral("RSV0 [4b]");
                        rv.value = QString::number(rsv);
                        rv.rel_start = abs0 + 1;   // 条目 byte1 高 4bit
                        rv.rel_len   = 1;
                        en.children.append(rv);
                        MsduFieldNode dl;
                        dl.name  = QStringLiteral("DownCommRate");
                        dl.value = QStringLiteral("%1%").arg(down);
                        dl.rel_start = abs0 + 2;   // 条目 byte2:下行成功率
                        dl.rel_len   = 1;
                        en.children.append(dl);
                        MsduFieldNode ul;
                        ul.name  = QStringLiteral("UpCommRate");
                        ul.value = QStringLiteral("%1%").arg(up);
                        ul.rel_start = abs0 + 3;   // 条目 byte3:上行成功率
                        ul.rel_len   = 1;
                        en.children.append(ul);
                    }
                }
                break;
            }
            case GW_2022_MMeType::MME_CHANGE_PROXY_CNF: {
                // MMeChangeProxyCnf(代理变更确认):固定 20B + 子站点 2B×ChildSum
                add_fields(root.children, b, 0, kChangeProxyCnfSpec,
                           kChangeProxyCnfSpecN, head_size + 4);
                // 拓扑事件:代理变更确认(STA 换代理);仅 Result=0(成功)时更新拓扑
                {
                    const quint8 pres = (quint8)get_bits(b, 0, 0, 8);
                    const quint16 sta_tei = (quint16)get_bits(b, 4, 0, 12);
                    const quint16 proxy_tei = (quint16)get_bits(b, 6, 0, 12);
                    if (pres != 0) {
                        // 变更失败:不更新拓扑(但保留字段解析)
                    } else {
                    out.topo_event.kind = TopoEventKind::ChangeProxyCnf;
                    // 链路类型(代理变更确认 kChangeProxyCnfSpec):0=HPLC载波/1=HRF无线
                    out.topo_event.is_rf = (get_bits(b, 5, 4, 1) != 0);
                    out.topo_event.is_rf_known = true;
                    out.topo_event.link_type = (int)get_bits(b, 5, 4, 1);
                    if (sta_tei && proxy_tei) out.topo_event.routes.append({sta_tei, proxy_tei});
                    out.topo_event.desc = trl::L("代理变更: STA TEI=%1 代理→%2")
                        .arg(sta_tei)
                        .arg(proxy_tei ? QString::number(proxy_tei) : QStringLiteral("-"));
                    }
                }
                apply_dicts(root.children);
                for (auto& ch : root.children) {
                    if (!ch.name.startsWith(QStringLiteral("Result"))) continue;
                    quint8 res = (quint8)get_bits(b, 0, 0, 8);
                    ch.value = QStringLiteral("%1 - %2").arg(res).arg(
                        res == 0 ? QStringLiteral("Success")
                                 : QStringLiteral("Fail"));
                }
                int child_sum = (int)get_bits(b, 16, 0, 16);
                int off = 20;   // 子站点表起点
                if (child_sum > 0 && off + 2 <= b.size()) {
                    auto& cg = group(root.children,
                                     QStringLiteral("ProxyChildSTA [%1]").arg(child_sum));
                    for (int i = 0; i < child_sum && off + 2 <= b.size(); ++i) {
                        quint16 e = (quint16)get_bits(b, off, 0, 16);
                        MsduFieldNode cn;
                        cn.name = QStringLiteral("Child[%1]").arg(i);
                        cn.value = QStringLiteral("TEI=%1").arg(e & 0x0FFF);  // 表87:子站点=TEI12b+保留4b,无链路类型
                        cn.rel_start = head_size + 4 + off;
                        cn.rel_len   = 2;
                        cg.children.append(cn);
                        off += 2;
                    }
                }
                break;
            }
            case GW_2022_MMeType::MME_LEAVE_IND: {
                // MMeLeaveInd(离线指示):固定 16B + 离线站点 MAC 6B×N
                add_fields(root.children, b, 0, kLeaveIndSpec, kLeaveIndSpecN,
                           head_size + 4);
                annotate_unit(root.children, "LeaveDelayTime", QStringLiteral("s"));  // 表91:延迟时间,单位秒 / seconds
                for (auto& ch : root.children) {
                    if (!ch.name.startsWith(QStringLiteral("Reason"))) continue;
                    quint16 r = (quint16)get_bits(b, 0, 0, 16);
                    static const char* rsn[] = {
                        "CCO decides STA offline",
                        "Network layers exceeded upper limit",
                        "STA not in whitelist"};
                    ch.value = (r <= 2)
                        ? QStringLiteral("%1 - %2").arg(r).arg(QLatin1String(rsn[r]))
                        : QString::number(r);
                }
                int n = (int)get_bits(b, 2, 0, 16);
                int off = 16;
                // 拓扑事件:离网指示(按 MAC 标记离网)
                out.topo_event.kind = TopoEventKind::LeaveInd;
                if (n > 0 && off + 6 <= b.size()) {
                    auto& lg = group(root.children,
                                     QStringLiteral("LeaveSTAMACList [%1]").arg(n));
                    for (int i = 0; i < n && off + 6 <= b.size(); ++i) {
                        const quint64 lmac = (quint64)get_bits(b, off, 0, 48);
                        out.topo_event.leaves.append(lmac);
                        MsduFieldNode mac;
                        mac.name  = QStringLiteral("LeaveSTAMAC [48b]");
                        mac.value = mac_str(lmac);
                        mac.rel_start = head_size + 4 + off;
                        mac.rel_len   = 6;
                        lg.children.append(mac);
                        off += 6;
                    }
                    out.topo_event.desc = trl::L("离线指示: %1 个站点离线").arg(n);
                }
                break;
            }
            case GW_2022_MMeType::MME_NETWORK_CONFLICT_REPORT: {
                // MMeNetworkConflictReport(网络冲突上报):固定 8B + 邻居网络号
                // NIDSize(规范=3)×NeighbourNetWorkCount
                add_fields(root.children, b, 0, kNetworkConflictSpec,
                           kNetworkConflictSpecN, head_size + 4);
                int cnt = (int)get_bits(b, 6, 0, 8);
                int nid_sz = (int)get_bits(b, 7, 0, 8);
                int off = 8;
                if (nid_sz > 0 && cnt > 0 && off + nid_sz <= b.size()) {
                    auto& ng = group(root.children,
                                     QStringLiteral("NeighbourNetworkNIDList [%1]")
                                         .arg(cnt));
                    for (int i = 0; i < cnt && off + nid_sz <= b.size(); ++i) {
                        quint32 nid = (quint32)get_bits(b, off, 0, nid_sz * 8);
                        MsduFieldNode nd;
                        nd.name  = QStringLiteral("NeighbourNID[%1]").arg(i);
                        nd.value = QStringLiteral("0x%1")
                                       .arg(nid, nid_sz * 2, 16, QChar('0'));
                        nd.rel_start = head_size + 4 + off;
                        nd.rel_len   = nid_sz;
                        ng.children.append(nd);
                        off += nid_sz;
                    }
                }
                break;
            }
            case GW_2022_MMeType::MME_RF_CHANNEL_CONFLICT_REPORT: {
                // MMeRFChannelConflictReport(无线信道冲突上报,表121/122):CCO MAC + 邻居数;
                // 邻居网络条目 = 每邻居 1 字节(该邻居无线信道号)
                add_fields(root.children, b, 0, kRFChannelConflictSpec,
                           kRFChannelConflictSpecN, head_size + 4);
                int cnt = (int)get_bits(b, 6, 0, 8);
                int ch_off = 7;
                if (cnt > 0 && ch_off + cnt <= b.size()) {
                    auto& rg = group(root.children,
                                     QStringLiteral("NeighbourRFNetworkList [%1]")
                                         .arg(cnt));
                    for (int i = 0; i < cnt; ++i) {
                        quint8 ch = (quint8)b[ch_off + i];
                        MsduFieldNode nd;
                        nd.name  = QStringLiteral("Neighbour[%1]").arg(i);
                        nd.value = QStringLiteral("ch=%1").arg(ch);
                        nd.rel_start = head_size + 4 + ch_off + i;
                        nd.rel_len   = 1;
                        rg.children.append(nd);
                    }
                }
                break;
            }
            case GW_2022_MMeType::MME_ROUTE_REQUEST: {
                // MMeRouteRequest(路由请求):头 7B + LoadData(4B×N RoutePath)
                add_fields(root.children, b, 0, kRouteReqReplyHeadSpec,
                           kRouteReqReplyHeadSpecN, head_size + 4);
                add_fields(root.children, b, 0, kRouteRequestTailSpec,
                           kRouteRequestTailSpecN, head_size + 4);
                apply_dicts(root.children);
                annotate_route_loaddata(root.children, b, head_size + 4);
                break;
            }
            case GW_2022_MMeType::MME_ROUTE_REPLY: {
                // MMeRouteReply(路由回复):头 7B + LoadData(4B×N RoutePath)
                add_fields(root.children, b, 0, kRouteReqReplyHeadSpec,
                           kRouteReqReplyHeadSpecN, head_size + 4);
                add_fields(root.children, b, 0, kRouteReplyTailSpec,
                           kRouteReplyTailSpecN, head_size + 4);
                apply_dicts(root.children);
                annotate_route_loaddata(root.children, b, head_size + 4);
                break;
            }
            case GW_2022_MMeType::MME_ROUTE_ERROR: {
                // MMeRouteError(路由错误):固定 7B + 不可达站点 2B×N
                add_fields(root.children, b, 0, kRouteErrorSpec,
                           kRouteErrorSpecN, head_size + 4);
                int n = (int)get_bits(b, 6, 0, 8);
                int off = 7;
                if (n > 0 && off + 2 <= b.size()) {
                    auto& ug = group(root.children,
                                     QStringLiteral("UnReachableSTAList [%1]").arg(n));
                    for (int i = 0; i < n && off + 2 <= b.size(); ++i) {
                        quint16 e = (quint16)get_bits(b, off, 0, 16);
                        MsduFieldNode sn;
                        sn.name  = QStringLiteral("UnReachableSTA[%1]").arg(i);
                        sn.value = QStringLiteral("TEI=%1").arg(e & 0x0FFF);  // 表117:不可达站点=2B TEI,无链路类型
                        sn.rel_start = head_size + 4 + off;
                        sn.rel_len   = 2;
                        ug.children.append(sn);
                        off += 2;
                    }
                }
                break;
            }
            case GW_2022_MMeType::MME_ROUTE_ACK: {
                // MMeRouteAck(路由应答):固定 8B
                add_fields(root.children, b, 0, kRouteAckSpec, kRouteAckSpecN,
                           head_size + 4);
                break;
            }
            case GW_2022_MMeType::MME_LINK_CONFIRM_REQUEST: {
                // MMeLinkConfirmRequest(链路确认请求):固定 7B + 应答站点 2B×N
                add_fields(root.children, b, 0, kLinkConfirmRequestSpec,
                           kLinkConfirmRequestSpecN, head_size + 4);
                int n = (int)get_bits(b, 6, 0, 8);
                int off = 7;
                if (n > 0 && off + 2 <= b.size()) {
                    auto& ag = group(root.children,
                                     QStringLiteral("AckSTAList [%1]").arg(n));
                    for (int i = 0; i < n && off + 2 <= b.size(); ++i) {
                        quint16 e = (quint16)get_bits(b, off, 0, 16);
                        MsduFieldNode sn;
                        sn.name  = QStringLiteral("AckSTA[%1]").arg(i);
                        sn.value = QStringLiteral("TEI=%1").arg(e & 0x0FFF);  // 表119:确认站点=2B TEI,无链路类型
                        sn.rel_start = head_size + 4 + off;
                        sn.rel_len   = 2;
                        ag.children.append(sn);
                        off += 2;
                    }
                }
                break;
            }
            case GW_2022_MMeType::MME_LINK_CONFIRM_RESPONSE: {
                // MMeLinkConfirmResponse(链路确认回应):固定 8B
                add_fields(root.children, b, 0, kLinkConfirmResponseSpec,
                           kLinkConfirmResponseSpecN, head_size + 4);
                for (auto& ch : root.children) {
                    if (!ch.name.startsWith(QStringLiteral("RoutePriorityFlag")))
                        continue;
                    quint8 f = (quint8)get_bits(b, 3, 0, 1);
                    ch.value = QStringLiteral("%1 - %2").arg(f).arg(
                        f == 1 ? QStringLiteral("Have high priority")
                               : QStringLiteral("Normal priority"));
                }
                break;
            }
            case GW_2022_MMeType::MME_DIAGNOSE: {
                // MMeDiagnose(网络诊断,表109):芯片厂商 ID(表110,0x00-0x14)+ 厂家自定义(可变长)
                add_fields(root.children, b, 0, kDiagnoseSpec, kDiagnoseSpecN,
                           head_size + 4);
                for (auto& ch : root.children) {
                    if (!ch.name.startsWith(QStringLiteral("ChipManufacID")))
                        continue;
                    quint16 v = (quint16)get_bits(b, 0, 0, 16);
                    // 表110 芯片厂商 ID:0x06 与 0x13 均为 "RS"(规约原文如此,非笔误)
                    static const char* mf[] = {
                        "Reserved", "HS", "ES", "TC", "LH", "HT", "RS", "SW", "SC",
                        "YM", "QJ", "HZ", "ZC", "SP", "PE", "NR", "SL", "MT", "SI", "RS", "XY"};
                    ch.value = (v <= 0x14)
                        ? QStringLiteral("%1 - %2").arg(v).arg(QLatin1String(mf[v]))
                        : QStringLiteral("%1 - Reserved").arg(v);
                }
                // 厂家自定义区(表109:byte2 起,可变长)——此前不可见,现以 hex 呈现
                if (b.size() > 2) {
                    MsduFieldNode d;
                    d.name = QStringLiteral("Vendor Data [%1B]").arg(b.size() - 2);
                    d.value = QString(b.mid(2).toHex(' '));
                    d.rel_start = head_size + 4 + 2;
                    d.rel_len   = b.size() - 2;
                    root.children.append(d);
                }
                break;
            }
            case GW_2022_MMeType::MME_ZERO_CROSS_NTB_COLLECT_IND: {
                // MMeZeroCrossNTBCollectInd(过零NTB采集指示):固定 8B
                add_fields(root.children, b, 0, kZeroCrossCollectSpec,
                           kZeroCrossCollectSpecN, head_size + 4);
                for (auto& ch : root.children) {
                    if (ch.name.startsWith(QStringLiteral("NTBCollectionMode"))) {
                        // 采集站点(表105):0=指定单站点 1=指定全网站点 其他=保留 / 0=single,1=all,else reserved
                        quint8 m = (quint8)get_bits(b, 2, 0, 8);
                        ch.value = QStringLiteral("%1 - %2").arg(m).arg(
                            m == 0 ? QStringLiteral("Appointed single STA")
                          : m == 1 ? QStringLiteral("All STAs collect zero-cross NTB")
                                   : QStringLiteral("Reserved"));
                    } else if (ch.name.startsWith(
                                   QStringLiteral("NTBCollectionPeriod"))) {
                        // 采集周期(表106):0=二分之一电力线周期 1=一个电力线周期 其他=保留 / 0=half cycle,1=one cycle,else reserved
                        quint8 p = (quint8)get_bits(b, 3, 0, 8);
                        ch.value = QStringLiteral("%1 - %2").arg(p).arg(
                            p == 0 ? QStringLiteral("Half power line cycle")
                          : p == 1 ? QStringLiteral("One power line cycle")
                                   : QStringLiteral("Reserved"));
                    }
                }
                break;
            }
            case GW_2022_MMeType::MME_ZERO_CROSS_NTB_REPORT: {
                // MMeZeroCrossNTBReport(过零NTB上报):固定 10B + 差分 NTB
                // (12bit 打包:偶序号 = b0|(b1&0F)<<8 吃1B;奇序号=(b0>>4)|(b1<<4)
                // 吃2B;LineA/B/C 依次各消费各自计数)
                add_fields(root.children, b, 0, kZeroCrossReportSpec,
                           kZeroCrossReportSpecN, head_size + 4);
                const int la = (int)get_bits(b, 3, 0, 8);
                const int lb = (int)get_bits(b, 4, 0, 8);
                const int lc = (int)get_bits(b, 5, 0, 8);
                const int total = (int)get_bits(b, 2, 0, 8);
                int la_show = (la == total && total > 0) ? la - 1 : la;  // 与 Python 一致
                QByteArray tab = b.mid(10);
                int cur = 0;
                // 12bit 差分 NTB 按"条目序号"奇偶交替解码:偶序号吃 1B(低 8bit +
                // 下一字节低 4bit),奇序号吃 2B(高 4bit + 下一字节)。分支依据必须是
                // 条目序号奇偶,而非当前字节位置 cur 的奇偶(LineA/B/C 连续解码,
                // 跨行起始奇偶按上一行累计计数翻转,与 Python 完全一致);否则
                // 消费字节数错位会越过 tab 末尾触发 qbytearray.h:594 断言。
                auto read12 = [&tab, &cur](bool even) -> quint16 {
                    if (cur + 1 >= tab.size()) return 0;  // 越界保护:需 cur、cur+1 两字节
                    quint16 v;
                    if (even) {
                        v = (quint16)(quint8)tab[cur]
                          | (quint16)(((quint8)tab[cur + 1] & 0x0F) << 8);
                        cur += 1;
                    } else {
                        v = (quint16)((quint8)tab[cur] >> 4)
                          | (quint16)((quint8)tab[cur + 1] << 4);
                        cur += 2;
                    }
                    return v;
                };
                auto diff_group = [&](QVector<MsduFieldNode>& out, const char* nm,
                                      int cnt, bool start_even) {
                    if (cnt <= 0) return;
                    auto& g = group(out, QStringLiteral("%1 Diff NTB List [%2]")
                                             .arg(QLatin1String(nm)).arg(cnt));
                    for (int i = 0; i < cnt; ++i) {
                        MsduFieldNode d;
                        d.name  = QStringLiteral("DiffNTB[%1]").arg(i);
                        const bool even = start_even ? (i % 2 == 0) : (i % 2 == 1);
                        d.value = QString::number(read12(even));
                        g.children.append(d);
                    }
                };
                diff_group(root.children, "LineA", la_show, /*start_even=*/true);
                diff_group(root.children, "LineB", lb, /*start_even=*/(la % 2) == 0);
                diff_group(root.children, "LineC", lc, /*start_even=*/((la + lb) % 2) == 0);
                break;
            }
            default: {
                MsduFieldNode un;
                un.name = trl::L("(未实现子类型)");
                un.value = QString(b.toHex(' '));
                root.children.append(un);
                break;
            }
        }
    } else if (static_cast<GW_2022_MsduType>(msdu_type) == GW_2022_MsduType::APPLICATION) {
        // ---- 应用层报文:APP_BASE(4B) ----
        quint16 packet_id = (quint16)get_bits(msdu_body, 1, 0, 16);
        out.summary = trl::L("应用报文 %1 (0x%2)")
                          .arg(packet_id_name(packet_id))
                          .arg(packet_id, 4, 16, QChar('0'));
        auto& root = group(out.tree, QStringLiteral("APP"));
        add_fields(root.children, msdu_body, 0, kAppBaseSpec, kAppBaseSpecN, head_size);
        // PacketID / PortNum 字段行加注释(表 2 报文 ID 含义、报文端口号)
        for (auto& c : root.children) {
            if (c.name.startsWith(QStringLiteral("PacketID")))
                c.value += QStringLiteral(" - %1").arg(packet_id_name(packet_id));
            else if (c.name.startsWith(QStringLiteral("PortNum"))) {
                QString pn = app_port_name((quint8)get_bits(msdu_body, 0, 0, 8));
                if (!pn.isEmpty())
                    c.value += QStringLiteral(" - %1").arg(pn);
            }
        }
        {
            // APP 载荷统一 hex 原文(0x0008 事件上报保留专属名,便于日后专用解析)
            MsduFieldNode raw;
            raw.name = (static_cast<GW_2022_AppBid>(packet_id) == GW_2022_AppBid::EVENT_REPORT)
                ? QStringLiteral("EventPacket Payload")
                : QStringLiteral("Payload");
            raw.value = QString(msdu_body.mid(4).toHex(' '));
            raw.rel_start = head_size + 4;   // msdu_body 在 body 起点 head_size + APP 头 4B
            raw.rel_len   = msdu_body.size() - 4;
            root.children.append(raw);
        }
    } else if (static_cast<GW_2022_MsduType>(msdu_type) == GW_2022_MsduType::IP) {
        // ---- IP 报文(表10:49):独立于应用层报文(48),内部格式见应用层分册,此处仅呈现 hex ----
        out.summary = trl::L("IP 报文");
        auto& ipg = group(out.tree, QStringLiteral("IP"));
        MsduFieldNode raw;
        raw.name = QStringLiteral("IP Payload");
        raw.value = QString(msdu_body.toHex(' '));
        raw.rel_start = head_size;
        raw.rel_len   = msdu_body.size();
        ipg.children.append(raw);
    } else {
        out.summary = trl::L("MSDU 类型 %1").arg(msdu_type);
    }

    // ---- MSDU 帧尾 4B CRC32 ----
    // 位置:MSDU 数据区(MSDULen)之后紧接 4B;计算范围 = MSDU 数据区 msdu_len 字节
    // (与 Python MSDU_BASE 校验一致:cal_crc32(MSDU_Body, MSDULen+4),
    //  即遍历 MSDULen 字节, poly=0xEDB88320, init=0xFFFFFFFF, 末取反)
    if (msdu_len > 0) {
        const int crc_off = head_size + msdu_len;
        // MSDU 帧总长 = 头 + 数据区 + CRC 4B(不含 PB 填充);供整体高亮
        out.total_len = crc_off + 4;
        if (crc_off + 4 <= body.size()) {
            quint32 stored = (quint8)body[crc_off]
                | ((quint32)(quint8)body[crc_off + 1] << 8)
                | ((quint32)(quint8)body[crc_off + 2] << 16)
                | ((quint32)(quint8)body[crc_off + 3] << 24);
// crc32_le 内部遍历 len-4 字节;此处传 载荷+4(全长)即校验载荷区,
// 末 4B 为本 CRC 自身(crc.h 约定,勿传 payload_len/msdu_len 否则少算 4B)
            quint32 calc = crc32_le(
                reinterpret_cast<const quint8*>(msdu_body.constData()),
                msdu_len + 4);
            MsduFieldNode crc;
            crc.name = QStringLiteral("MSDU CRC32");
            crc.value = QStringLiteral("0x%1 %2")
                .arg(stored, 8, 16, QChar('0'))
                .arg(stored == calc ? QStringLiteral("OK")
                                    : QStringLiteral("FAIL"));
            if (stored != calc)
                pa::warn("gw_2022:crc_fail", QStringLiteral("MSDU CRC32 stored=0x%1 calc=0x%2").arg(stored,8,16,QChar('0')).arg(calc,8,16,QChar('0')));
            crc.rel_start = crc_off;
            crc.rel_len   = 4;
            out.tree.append(crc);
        }
    }
    // 逐事件发送方 MAC:与重启次数同源(MSDU 头源 MAC);短头无 MAC 时留 0,
    // TopoState 回落到事件 nodes 首条;多站/级联每段/每站解析各填各的,
    // 合并时随 TopoEvent 对象整体拷贝,不混、不丢。
    if (out.topo_event.kind != TopoEventKind::Other && out.msdu_src_mac)
        out.topo_event.sender_mac = out.msdu_src_mac;
    return out;
}

// ===== i18n:文件级 中→英 显示词典(仅显示翻译;未命中回退中文) =====
namespace {

struct I18nReg {
    I18nReg() {
        trl::register_en("网络诊断", "MMeDiagnose");
        trl::register_en("在位图(第%1字节)", "In Bitmap (Byte %1)");
        trl::register_en("Neighbor[%1] (位图 byte %2 bit %3)", "Neighbor[%1] (bitmap byte %2 bit %3)");
        trl::register_en("关联确认", "MMeAssocCnf");
        trl::register_en("关联汇总指示", "MMeAssocGatherInd");
        trl::register_en("关联请求", "MMeAssocReq");
        trl::register_en("代理变更确认位图版", "MMeChangeProxyBitMapCnf");
        trl::register_en("代理变更确认", "MMeChangeProxyCnf");
        trl::register_en("代理变更请求", "MMeChangeProxyReq");
        trl::register_en("发现列表", "MMeDiscoveryNodeList");
        trl::register_en("心跳检测", "MMeHeartBeatCheck");
        trl::register_en("离线指示", "MMeLeaveInd");
        trl::register_en("链路确认请求", "MMeLinkConfirmRequest");
        trl::register_en("链路确认响应", "MMeLinkConfirmResponse");
        trl::register_en("网络冲突上报", "MMeNetworkConflictReport");
        trl::register_en("无线信道冲突上报", "MMeRFChannelConflictReport");
        trl::register_en("路由确认", "MMeRouteAck");
        trl::register_en("路由错误", "MMeRouteError");
        trl::register_en("路由应答", "MMeRouteReply");
        trl::register_en("路由请求", "MMeRouteRequest");
        trl::register_en("通信成功率上报", "MMeSuccessRateReport");
        trl::register_en("过零NTB采集指示", "MMeZeroCrossNTBCollectInd");
        trl::register_en("过零NTB上报", "MMeZeroCrossNTBReport");
        trl::register_en(" (RFDL 截断)", " (RFDL truncated)");
        trl::register_en("发现列表消息", "Discovery List Message");
        trl::register_en("单跳 MSDU 类型 %1", "Simple MSDU type %1");
        trl::register_en("MSDU 截断(长度 %1 > 可用 %2)", "MSDU truncated (len %1 > avail %2)");
        trl::register_en("MMe (截断)", "MMe (truncated)");
        trl::register_en("应用报文 %1 (0x%2)", "APP %1 (0x%2)");
        trl::register_en("IP 报文", "IP Packet");
        trl::register_en("MSDU 类型 %1", "MSDUType %1");
        trl::register_en("终端主动抄表", "Terminal meter reading");
        trl::register_en("路由主动抄表", "Router meter reading");
        trl::register_en("终端主动并发抄表", "Terminal concurrent meter reading");
        trl::register_en("校时", "Time sync");
        trl::register_en("站点版本信息", "STA Version Info");
        trl::register_en("错误路由类型", "Incorrect Route");
        trl::register_en("同级路由类型", "Same-level route");
        trl::register_en("上级路由类型", "Upper-level route");
        trl::register_en("代理主路径路由类型", "Proxy main-path route");
        trl::register_en("上上级路由类型", "Upper of upper-level route");
        trl::register_en("站点动态选择的代理", "Proxy chosen by the STA");
        trl::register_en("通信测试", "Comm test");
        trl::register_en("事件上报", "Event report");
        trl::register_en("查询从节点主动注册", "Query slave node registration");
        trl::register_en("启动从节点主动注册", "Start slave node registration");
        trl::register_en("停止从节点主动注册", "Stop slave node registration");
        trl::register_en("确认/否认", "Confirm / Deny");
        trl::register_en("开始升级", "Start upgrade");
        trl::register_en("停止升级", "Stop upgrade");
        trl::register_en("传输文件数据", "Transfer file data");
        trl::register_en("传输文件数据(单播转本地广播)", "Transfer file data (unicast to local broadcast)");
        trl::register_en("查询站点升级状态", "Query node upgrade status");
        trl::register_en("执行升级", "Execute upgrade");
        trl::register_en("查询站点信息", "Query node info");
        trl::register_en("抄控器 CCO", "Meter-reading controller CCO");
        trl::register_en("抄控器数据透传串口转发", "Meter-reading controller transparent serial forwarding");
        trl::register_en("鉴权安全", "Authentication security");
        trl::register_en("台区户变关系识别", "Transformer-area relation detection");
        trl::register_en("查询ID信息", "Query ID info");
        trl::register_en("精准校时", "Precise time sync");
        trl::register_en("配电信息上报", "Distribution info report");
        trl::register_en("存储采集扩展配置", "Storage collection extended configuration");
        trl::register_en("存储数据广播时规", "Storage data broadcast schedule");
        trl::register_en("存储数据同步配置", "Storage data sync configuration");
        trl::register_en("认证", "Authentication");
        trl::register_en("存储 HRF 中继心跳", "Store HRF relay heartbeat");
        trl::register_en("(未实现)", "(Not implemented)");
        trl::register_en("管理/抄表端口", "Management / meter-reading port");
        trl::register_en("升级端口", "Upgrade port");
        trl::register_en("安全端口", "Security port");
        trl::register_en("(未实现子类型)", "(Not implemented subtype)");
        trl::register_en(" (高可信)", " (high confidence)");
        trl::register_en(" (中可信)", " (medium confidence)");
        trl::register_en(" (低可信)", " (low confidence)");
        // 拓扑事件变更说明(TOPO 路由变更表 desc)
        trl::register_en("关联请求: STA %1 正在入网", "Assoc request: STA %1 joining");
        trl::register_en("关联请求: STA %1 正在入网（%2）", "Assoc request: STA %1 joining (%2)");
        trl::register_en("正常启动", "Normal Boot");
        trl::register_en("断电重启", "PowerOff Boot");
        trl::register_en("看门狗复位", "WatchDog Boot");
        trl::register_en("程序指针异常", "PC exception Boot");
        trl::register_en("关联确认: STA TEI=%1 入网 代理=%2", "Assoc confirm: STA TEI=%1 joined, proxy=%2");
        trl::register_en("关联汇总: %1 个站点入网 代理=%2", "Assoc gather: %1 stations joined, proxy=%2");
        trl::register_en("发现列表: STA TEI=%1 代理=%2", "Discover list: STA TEI=%1 proxy=%2");
        trl::register_en("代理变更: STA TEI=%1 代理→%2", "Proxy change: STA TEI=%1 proxy→%2");
        trl::register_en("代理变更请求: STA TEI=%1 %2→%3", "Proxy change request: STA TEI=%1 %2→%3");
        trl::register_en("代理变更(批量): %1 个站点代理→%2", "Proxy change (batch): %1 stations proxy→%2");
        trl::register_en("离线指示: %1 个站点离线", "Leave indication: %1 stations left");
        trl::register_en("%1 - %2 (%3b/邻居)", "%1 - %2 (%3b/neighbor)");
    }
};
const I18nReg g_i18n_reg_msdu;

}  // namespace
