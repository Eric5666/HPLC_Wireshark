/// @file nw_2026_msdu_parser.cpp
/// @brief 南网 NW_2026 MSDU/MAC 层解析实现(头解析 + MMe 管理消息字段)
/// @details MSDU 处理流程(帧类型判定 / MAC 帧头 / MSDU 帧头 / MMe 分支):
///           1. 判帧类型:Version(bit1-2)=1 标准(MSDU_BASE);0/2/3 保留(表6),不解释
///           2. MAC 帧头(MSDU_BASE 32B 长/12B 短):TEI/SNID/重启次数/广播方向
///           3. MSDU 帧头(长 18B / 短 2B,由 MACHeadFlag 决定):MAC 48b + VLAN + 类型
///           4. VLAN==0x8100 → MMe 管理消息(MMType 16b 分支,字段树)
#include "nw_2026_msdu_parser.h"
#include "common/fieldtools.h"
#include "common/fieldspec.h"
#include "common/crc.h"
#include "i18n.h"
#include "parse_anomaly.h"
#include "../../common/nw_app_bid.h"   // 表9/表8 释义(相对包含:消费者 INCLUDEPATH 未必含 common/)

namespace {

// 口径：名称表无对应项的未分配类型值统一带“保留”后缀；已分配类型名不动。
inline QString mme_type_name(quint16 t) {
    switch (static_cast<NW_2026_MMeType>(t)) {
        case NW_2026_MMeType::MME_ASSOCREQ: return trl::L("关联请求");
        case NW_2026_MMeType::MME_ASSOCCNF: return trl::L("关联确认");
        case NW_2026_MMeType::MME_CHANGEPROXYREQ: return trl::L("代理变更请求");
        case NW_2026_MMeType::MME_ASSOCIND: return trl::L("关联指示");
        case NW_2026_MMeType::MME_CHANGEPROXYCNF: return trl::L("代理变更确认");
        case NW_2026_MMeType::MME_ASSOCGATHERIND: return trl::L("关联汇总指示");
        case NW_2026_MMeType::MME_CHANGEPROXYBITMAPCNF: return trl::L("代理变更确认位图版");
        case NW_2026_MMeType::MME_LEAVEIND: return trl::L("离线指示");
        case NW_2026_MMeType::MME_HEARTBEATCHECK: return trl::L("心跳检测");
        case NW_2026_MMeType::MME_DISCOVERNODELIST: return trl::L("发现列表");
        case NW_2026_MMeType::MME_DELAYLEAVEIND: return trl::L("延迟离线指示");
        case NW_2026_MMeType::MME_SUCCESSRATEREPORT: return trl::L("通信成功率上报");
        case NW_2026_MMeType::MME_ZEROCROSSNTBCOLLECTIND: return trl::L("过零NTB采集指示");
        case NW_2026_MMeType::MME_ZEROCROSSNTBREPORT: return trl::L("过零NTB上报");
        case NW_2026_MMeType::MME_NETDIAGNOSE: return trl::L("网络诊断");
        case NW_2026_MMeType::MME_NETWORKCONFLICTREPORT: return trl::L("网络冲突上报");
        case NW_2026_MMeType::MME_RFCHANNELCONFLICTREPORT: return trl::L("无线信道冲突上报");
        case NW_2026_MMeType::MME_BITLOAD_UPDATE_REQ: return trl::L("Bitloading训练结果更新请求");
        case NW_2026_MMeType::MME_BITLOAD_UPDATE_CNF: return trl::L("Bitloading训练结果更新确认");
        case NW_2026_MMeType::MME_RUSNR_INFO_IND: return trl::L("RU_SNR信息告知");
        case NW_2026_MMeType::MME_TEI_LIST_REQ: return trl::L("站点TEI列表请求");
        case NW_2026_MMeType::MME_TEI_LIST_CNF: return trl::L("站点TEI列表回复");
        case NW_2026_MMeType::MME_EXT_NETWORK_CONFLICT_RPT: return trl::L("扩展网络冲突上报");
        case NW_2026_MMeType::MME_IOT_ASSOC_REQ: return trl::L("物联终端接入请求");
        case NW_2026_MMeType::MME_IOT_ASSOC_IND: return trl::L("物联终端接入确认");
        case NW_2026_MMeType::MME_IOT_LEAVE_IND: return trl::L("物联终端离线指示");
        default: return QStringLiteral("MMe 0x%1 (%2)").arg(t, 4, 16, QChar('0')).arg(trl::L("保留"));
    }
}

// ── 枚举值解释(中文 key,经 trl 注册英文;与国网 apply_dicts 对齐) ──

/// 按名查找首个同名字段节点(递归;节点名带 " [Nb]" 后缀,按前缀匹配),未找到返回 nullptr
static MsduFieldNode* find_field_node(QVector<MsduFieldNode>& nodes, const char* name) {
    for (auto& n : nodes) {
        if (n.name.startsWith(QLatin1String(name))) return &n;
        if (MsduFieldNode* hit = find_field_node(n.children, name)) return hit;
    }
    return nullptr;
}

/// 枚举字典翻译:name 命中则 value 改为 "值 - 释义"
static void translate_enum_i18n(QVector<MsduFieldNode>& nodes, const char* field,
                                const char* const* zh_dict, int dict_size) {
    for (auto& n : nodes) {
        if (!n.name.startsWith(QLatin1String(field))) continue;
        bool ok = false;
        const int v = n.value.toInt(&ok);
        if (!ok) continue;
        if (v >= 0 && v < dict_size && zh_dict[v])
            n.value = QStringLiteral("%1 - %2").arg(v).arg(trl::L(zh_dict[v]));
        else
            n.value = QStringLiteral("%1 - %2").arg(v).arg(trl::L("保留"));  // 字典内 nullptr 或越界值显式标注"保留"
    }
}

/// 相线(表15:0 未知 1 A 2 B 3 C)
static const char* kLinePhaseZh[] = { "未知", "A相线", "B相线", "C相线" };
/// 角色(0 未知 1 站点 2 代理站点 4 中央协调器,索引 3 保留无释义)
static const char* kRoleZh[] = { "未知", "站点", "代理站点", nullptr, "中央协调器" };
/// 通信成功率计算完成标志(0 未完成 1 已完成)
static const char* kCommRateCalcZh[] = { "未完成", "已完成" };
/// 上行路由类型(表:0 错误 1 同级 2 上级 3 代理主路径 4 上上级)
static const char* kRouteTypeZh[] = {
    "错误路由类型", "同级路由类型", "上级路由类型", "代理主路径路由类型", "上上级路由类型" };
/// 设备类型(表45:0x01 抄控器 ... 0x07 三相表通信模块,0x00/0x08+ 保留)
static const char* kDeviceTypeZh[] = {
    nullptr, "抄控器", "集中器通信模块", "单相电表通信模块", "中继器",
    "II型采集器", "I型采集器", "三相表通信模块" };
/// MAC 地址类型(表46:0 电能表地址 1 模块本身MAC 2 采集器地址)
static const char* kMACAddrTypeZh[] = { "电能表地址", "模块本身MAC地址", "采集器地址" };
// 链路类型(表79:0 高速载波链路 1 无线链路)
static const char* kLinkTypeZh[] = { "高速载波链路", "无线链路" };
// PLC 能力指示(0 支持BPLC版本 1 支持BPLC和SPLC版本)
static const char* kPLCCapZh[] = { "支持BPLC版本", "支持BPLC和SPLC版本" };
// 模块类型(0 HPLC 单模模块 1 双模 HPLC 和 RF 模块 2 无线单模模块)
static const char* kModuleTypeZh[] = { "HPLC 单模模块", "双模 HPLC 和 RF 模块", "无线单模模块" };
// 通道数(0 单通道 1 多通道)
static const char* kChannelNumZh[] = { "单通道", "多通道" };
// 载波频段(表95:0-4 频段定义,5-7 保留;ASCII 频段值,无需英译)
static const char* kCarrierFreqZh[] = {
    "1.953~11.96MHz", "2.441~5.615MHz", "0.781~2.930MHz",
    "0.781~11.963MHz", "0.781~5.615MHz", nullptr, nullptr, nullptr };
// 扩展特性标识(byte21 bit0:1=支持应用层多帧抄读)
static const char* kExtFeatureZh[] = { "不支持应用层多帧抄读", "支持应用层多帧抄读" };
/// 代理类型(表50/63:0x1 保留 0x2 动态代理)
static const char* kProxyTypeZh[] = { nullptr, nullptr, "动态代理" };
/// 支持频段标识(表51:0x0 频段0和1 0x1 频段0/1/2)
static const char* kBandSupportZh[] = { "频段0和频段1", "频段0/1/2" };
/// 系统启动原因(表48:0x0 正常重启)
static const char* kBootReasonZh[] = { "正常重启" };
/// 关联确认结果(表53:0x07 保留)
static const char* kAssocCnfResultZh[] = {
    "关联请求成功", "站点不在白名单中", nullptr, "加入站点个数超过上限",
    "没有设置白名单列表", "代理站点个数超过上限", "子站点个数超过上限",
    nullptr, "重复的MAC地址", "超过拓扑层级", "站点再次关联请求入网成功",
    "新站点试图以自己的子站点为代理入网", "组网拓扑中存在环路", "CCO端未知原因出错" };
/// 关联指示结果(表58:0x07 没有回复,0x0A 再次入网)
static const char* kAssocIndResultZh[] = {
    "关联请求成功", "站点不在白名单中", nullptr, "加入站点个数超过上限",
    "没有设置白名单列表", "代理站点个数超过上限", "子站点个数超过上限",
    "没有回复", "重复的MAC地址", "超过拓扑层级", "曾经入网的站点再次入网",
    "新站点试图以自己的子站点为代理入网", "组网拓扑中存在环路", "CCO端未知原因出错" };
/// 最后一个分包标识(表54/59:0 不是 1 是)
static const char* kLastPacketFlagZh[] = { "不是最后一个分包", "是最后一个分包" };
// 探测频段标识符值释义(6.4.2.15):0=关联指示在工作频段上发送 1=在探测频段上发送
static const char* kDetectBandFlagZh[] = { "在工作频段上发送", "在探测频段上发送" };
// 过零 NTB 采集站点类型值释义(表85):0=单站点 1=全网站点 其他=保留
static const char* kZCStationTypeZh[] = { "单站点", "全网站点" };
// 过零 NTB 采集周期值释义(表86):0=半个电力线周期 1=一个电力线周期 其他=保留
static const char* kZCCollectPeriodZh[] = { "半个电力线周期", "一个电力线周期" };
/// 代理变更原因(表64:0x1 周期 0x2 快速)
static const char* kProxyChangeReasonZh[] = { nullptr, "周期代理变更", "快速代理变更" };
/// 代理变更结果(表67/70:0x0 变更成功)
static const char* kProxyChangeResultZh[] = { "变更成功" };
/// 关联汇总结果(6.4.4.1:固定值 0 允许加入网络)
static const char* kAssocGatherResultZh[] = { "允许加入网络" };
/// 离线原因(表114:0x0 未入网却发报文 0x2 拓扑超限 0x4 立即离线 0x5 第三方设备认证失败 0x6 认证超时)
static const char* kLeaveReasonZh[] = {
    "站点未入网却收到其报文", nullptr, "拓扑层级超过上限", nullptr, "立即离线",
    "第三方设备认证失败", "第三方设备认证超时" };
/// 延迟离线原因(表74:0x3 不在最新白名单)
static const char* kDelayLeaveReasonZh[] = { nullptr, nullptr, nullptr, "站点不在最新白名单中" };
/// 芯片厂商ID(表90:0x0000 保留 0x0001 HS ... 0x0008 SC)
static const char* kChipIDZh[] = { "保留", "HS", "ES", "TC", "LH", "HT", "RS", "SW", "SC" };
/// 帧类型域(表4:0 确认/否认 1 数据转发 2 命令 3 主动上报 4 抄控器 5 广播 6 数据订阅 14 厂家调试 15 厂测帧)
static const char* kPacketTypeZh[] = {
    "确认/否认", "数据转发帧", "命令帧", "主动上报帧",
    "抄控器相关协议", "广播命令帧", "数据订阅路由帧",
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    "厂家调试", "厂测帧" };
/// 业务扩展域标识位(表5:0 无扩展域 1 有扩展域)
static const char* kExtBusinessFlagZh[] = { "无业务扩展域", "有业务扩展域" };
/// 响应标识位(表6:0 不需要应答 1 需要应答)
static const char* kRespondFlagZh[] = { "不需要应答", "需要应答" };
/// 启动标志位(表7:0 从动站 1 启动站)
static const char* kStartFlagZh[] = { "从动站", "启动站" };
/// 传输方向位(表8:0 下行方向 1 上行方向)
static const char* kTransDirectionFlagZh[] = { "下行方向", "上行方向" };

/// 文件级中→英翻译注册(匿名命名空间一次性)
struct MMeI18nReg {
    MMeI18nReg() {
        trl::register_en("关联请求", "MMeAssocReq");
        trl::register_en("关联确认", "MMeAssocCnf");
        trl::register_en("代理变更请求", "MMeChangeProxyReq");
        trl::register_en("关联指示", "MMeAssocInd");
        trl::register_en("代理变更确认", "MMeChangeProxyCnf");
        trl::register_en("关联汇总指示", "MMeAssocGatherInd");
        trl::register_en("代理变更确认位图版", "MMeChangeProxyBitMapCnf");
        trl::register_en("离线指示", "MMeLeaveInd");
        trl::register_en("心跳检测", "MMeHeartBeatCheck");
        trl::register_en("发现列表", "MMeDiscoverNodeList");
        trl::register_en("延迟离线指示", "MMeDelayLeaveInd");
        trl::register_en("通信成功率上报", "MMeSuccessRateReport");
        trl::register_en("过零NTB采集指示", "MMeZeroCrossNTBCollectInd");
        trl::register_en("过零NTB上报", "MMeZeroCrossNTBReport");
        trl::register_en("网络诊断", "MMeNetDiagnose");
        trl::register_en("网络冲突上报", "MMeNetworkConflictReport");
        trl::register_en("无线信道冲突上报", "MMeRFChannelConflictReport");
        trl::register_en("物联终端接入请求", "MMeIoTAssocReq");
        trl::register_en("物联终端接入确认", "MMeIoTAssocInd");
        trl::register_en("物联终端离线指示", "MMeIoTLeaveInd");
        trl::register_en("Bitloading训练结果更新请求", "MMeBitLoadUpdateReq");
        trl::register_en("Bitloading训练结果更新确认", "MMeBitLoadUpdateCnf");
        trl::register_en("RU_SNR信息告知", "MMeRUSNRInfoInd");
        trl::register_en("站点TEI列表请求", "MMeTEIListReq");
        trl::register_en("站点TEI列表回复", "MMeTEIListCnf");
        trl::register_en("扩展网络冲突上报", "MMeExtNetworkConflictReport");
        trl::register_en("MMe", "MMe");
        trl::register_en("应用报文(截断)", "APP (truncated)");
        trl::register_en("应用层报文 (%1)", "Application Layer Packet (%1)");
        trl::register_en(" (CRC 缺失)", " (CRC missing)");
        trl::register_en(" (无线发现节点列表截断)", " (RF DiscoverNodeList truncated)");
        trl::register_en("无线发现节点列表 (%1 个信息单元)", "RF DiscoverNodeList (%1 info units)");
        trl::register_en(" (截断)", " (truncated)");
        trl::register_en("IPv4", "IPv4");
        trl::register_en(" (不支持的 MMe 版本 %1)", " (unsupported MMe version %1)");
        trl::register_en(" (字段缺失)", " (fields missing)");
        trl::register_en("在工作频段上发送", "Sent on the Working Band");
        trl::register_en("在探测频段上发送", "Sent on the Detection Band");
        trl::register_en("单站点", "Single Station");
        trl::register_en("全网站点", "All Stations");
        trl::register_en("半个电力线周期", "Half Power-Line Cycle");
        trl::register_en("一个电力线周期", "One Power-Line Cycle");
        trl::register_en("未知", "Unknown");
        trl::register_en("A相线", "LineA");
        trl::register_en("B相线", "LineB");
        trl::register_en("C相线", "LineC");
        trl::register_en("站点", "STA");
        trl::register_en("代理站点", "PCO");
        trl::register_en("中央协调器", "CCO");
        trl::register_en("未完成", "Not Finished");
        trl::register_en("已完成", "Finished");
        trl::register_en("错误路由类型", "Incorrect Route");
        trl::register_en("同级路由类型", "Same-level Backup Route");
        trl::register_en("上级路由类型", "Upper-level Backup Route");
        trl::register_en("代理主路径路由类型", "Proxy Main Path Route");
        trl::register_en("上上级路由类型", "Upper-of-upper Backup Route");
        trl::register_en(" (高可信)", " (high confidence)");
        trl::register_en(" (中可信)", " (medium confidence)");
        trl::register_en(" (低可信)", " (low confidence)");
        trl::register_en("保留", "Reserved");
        // 单跳帧协议(第2部分无线 §8.1.2.4 表113/114/214/215)
        trl::register_en("单跳帧协议", "Single-Hop Frame Protocol");
        trl::register_en("无线发现列表消息", "RF Discover List message");
        trl::register_en("IPv4报文", "IPv4 packet");
        trl::register_en("站点属性信息", "Station Attribute Info");
        trl::register_en("站点路由信息", "Station Route Info");
        trl::register_en("邻居节点信道信息非位图版", "Neighbor Channel Info (Non-Bitmap)");
        trl::register_en("邻居节点信道信息位图版", "Neighbor Channel Info (Bitmap)");
        trl::register_en("1字节长度", "1-byte length");
        trl::register_en("2字节长度", "2-byte length");
        trl::register_en("保留(管理消息扩展)", "Reserved (Mgmt-Message Extension)");
        // 无线发现列表信息单元路由类型(表218 后文)
        trl::register_en("错误的路由类型", "Invalid Route Type");
        trl::register_en("同级备份路由类型", "Peer Backup Route");
        trl::register_en("上级备份路由类型", "Upper Backup Route");
        trl::register_en("代理主路径路由类型", "Proxy Primary Route");
        trl::register_en("上上级路由类型", "Upper-Upper Route");
        trl::register_en("抄控器", "Central Controller");
        trl::register_en("集中器通信模块", "Concentrator Comm Module");
        trl::register_en("单相电表通信模块", "Meter Comm Module");
        trl::register_en("中继器", "Repeater");
        trl::register_en("II型采集器", "TypeII Data Collector");
        trl::register_en("I型采集器", "TypeI Data Collector");
        trl::register_en("三相表通信模块", "3-Phase Meter Comm Module");
        trl::register_en("电能表地址", "Meter MAC Address");
        trl::register_en("模块本身MAC地址", "Module MAC Address");
        trl::register_en("采集器地址", "Collector MAC Address");
        trl::register_en("动态代理", "Dynamic Proxy");
        trl::register_en("频段0和频段1", "Band0 & Band1");
        trl::register_en("频段0/1/2", "Band0/1/2");
        // 新一代字段释义(SPLC 数据链路层:模块类型/链路类型/PLC能力/通道数/扩展特性)
        trl::register_en("高速载波链路", "HPLC Link");
        trl::register_en("无线链路", "HRF Link");
        trl::register_en("支持BPLC版本", "BPLC supported");
        trl::register_en("支持BPLC和SPLC版本", "BPLC & SPLC supported");
        trl::register_en("HPLC 单模模块", "HPLC Single Mode Module");
        trl::register_en("双模 HPLC 和 RF 模块", "Dual-mode HPLC and RF Module");
        trl::register_en("无线单模模块", "Wireless Single Mode Module");
        trl::register_en("单通道", "Single Channel");
        trl::register_en("多通道", "Multi Channels");
        trl::register_en("不支持应用层多帧抄读", "No App Multi-Frame Reading");
        trl::register_en("支持应用层多帧抄读", "App Multi-Frame Reading Supported");
        trl::register_en("第三方设备认证失败", "3rd-party device auth failed");
        trl::register_en("第三方设备认证超时", "3rd-party device auth timeout");
        // SPLC 新增管理消息值释义(表153-164)
        trl::register_en("单流", "Single Stream");
        trl::register_en("双流", "Dual Stream");
        trl::register_en("更新成功", "Update OK");
        trl::register_en("更新失败", "Update Failed");
        trl::register_en("RU分组ID0信息", "RU group ID0 info");
        trl::register_en("不承载数据", "No Data");
        trl::register_en("BPSK(1比特)", "BPSK (1 bit)");
        trl::register_en("QPSK(2比特)", "QPSK (2 bits)");
        trl::register_en("16QAM(4比特)", "16QAM (4 bits)");
        trl::register_en("64QAM(6比特)", "64QAM (6 bits)");
        trl::register_en("正常重启", "Normal Boot");
        trl::register_en("关联请求成功", "Association Success");
        trl::register_en("站点不在白名单中", "STA Not in Whitelist");
        trl::register_en("加入站点个数超过上限", "STA Count Exceeds Limit");
        trl::register_en("没有设置白名单列表", "No Whitelist Configured");
        trl::register_en("代理站点个数超过上限", "PCO Count Exceeds Limit");
        trl::register_en("子站点个数超过上限", "Child STA Count Exceeds Limit");
        trl::register_en("没有回复", "No Reply");
        trl::register_en("重复的MAC地址", "Duplicate MAC Address");
        trl::register_en("超过拓扑层级", "Topology Level Exceeded");
        trl::register_en("站点再次关联请求入网成功", "STA Re-association Success");
        trl::register_en("曾经入网的站点再次入网", "Former STA Rejoined");
        trl::register_en("新站点试图以自己的子站点为代理入网", "STA Uses Own Child as Proxy");
        trl::register_en("组网拓扑中存在环路", "Loop in Network Topology");
        trl::register_en("CCO端未知原因出错", "CCO Unknown Error");
        trl::register_en("不是最后一个分包", "Not Last Fragment");
        trl::register_en("是最后一个分包", "Last Fragment");
        trl::register_en("周期代理变更", "Periodic Proxy Change");
        trl::register_en("快速代理变更", "Fast Proxy Change");
        trl::register_en("变更成功", "Change Success");
        trl::register_en("允许加入网络", "Allow Join");
        trl::register_en("站点未入网却收到其报文", "STA Not Joined but Packet Received");
        trl::register_en("拓扑层级超过上限", "Topology Level Exceeds Limit");
        trl::register_en("立即离线", "Leave Immediately");
        trl::register_en("站点不在最新白名单中", "STA Not in Latest Whitelist");
        trl::register_en("下降沿采集", "Falling Edge");
        trl::register_en("上升沿采集", "Rising Edge");
        trl::register_en("确认/否认", "ACK/NACK");
        trl::register_en("数据转发帧", "Data Forward Frame");
        trl::register_en("命令帧", "Command Frame");
        trl::register_en("主动上报帧", "Event Report Frame");
        trl::register_en("抄控器相关协议", "Reader Protocol");
        trl::register_en("广播命令帧", "Broadcast Command Frame");
        trl::register_en("数据订阅路由帧", "Data Subscription Route Frame");
        trl::register_en("厂家调试", "Vendor Debug");
        trl::register_en("厂测帧", "Factory Test Frame");
        trl::register_en("确认", "ACK");
        trl::register_en("否认", "NACK");
        trl::register_en("数据透传至设备", "Data Forward to Device");
        trl::register_en("数据透传至模块", "Data Forward to Module");
        trl::register_en("并发抄读端设备", "Concurrent Meter Reading");
        trl::register_en("站点间通信", "Inter-Station Communication");
        trl::register_en("查询模块运行参数", "Query Module Running Parameters");
        trl::register_en("查询终端搜索结果", "Query Meter Search Result");
        trl::register_en("下发搜索终端列表", "Distribute Meter Search List");
        trl::register_en("文件传输", "File Transmission");
        trl::register_en("允许/禁止从节点事件", "Enable/Disable Node Event");
        trl::register_en("从节点重启", "Reboot Node");
        trl::register_en("从节点信息查询", "Query Node Info");
        trl::register_en("下发通信地址映射表列表", "Distribute Address Map");
        trl::register_en("查询从节点运行状态信息", "Query Node Running Status");
        trl::register_en("查询从节点信道信息", "Query Node Channel Info");
        trl::register_en("台区户变关系/相位识别", "Station/Phase Identification");
        trl::register_en("测试帧", "Test Frame");
        trl::register_en("电表事件主动上报", "Meter Event Report");
        trl::register_en("停上电事件上报", "Power On/Off Event Report");
        trl::register_en("设备事件主动上报", "Device Event Report");
        trl::register_en("通信模块事件上报", "Comm Module Event Report");
        trl::register_en("抄控器-CCO协议", "Reader-CCO Protocol");
        trl::register_en("数据透传串口转发", "Data Forward via UART");
        trl::register_en("无业务扩展域", "No Extended Field");
        trl::register_en("有业务扩展域", "Has Extended Field");
        trl::register_en("不需要应答", "No Response Required");
        trl::register_en("需要应答", "Response Required");
        trl::register_en("从动站", "From Slave STA");
        trl::register_en("启动站", "From Initiating STA");
        trl::register_en("下行方向", "Downlink Direction");
        trl::register_en("上行方向", "Uplink Direction");
        trl::register_en("业务报文", "Service Packet");
        trl::register_en("管理报文", "Management Packet");
        trl::register_en("CCO-STA 应用层报文", "CCO-STA APP Packet");
        trl::register_en("应用层报文", "Application Layer Packet");
        trl::register_en("管理消息报文", "Management Message Packet");
        trl::register_en("抄表/数据订阅应用，LID（优先级）=%1",
                         "Meter reading/data subscription application, LID (priority)=%1");
        trl::register_en("网络管理报文，LID（优先级）=0-255（实现自定义）",
                         "Network management packet, LID (priority)=0-255 (implementation-defined)");
        trl::register_en("未定义的VLAN/MSDU Type组合", "Undefined VLAN/MSDU Type combination");
        trl::register_en("不支持的MMe版本（仅支持1）", "Unsupported MMe version (only 1 supported)");
        trl::register_en("校验数据缺失（已有%1/4字节）", "CRC data missing (%1/4 bytes available)");
        // 拓扑事件变更说明(TOPO 路由变更表 desc)
        trl::register_en("关联请求: STA %1 正在入网", "Assoc request: STA %1 joining");
        trl::register_en("关联确认: STA TEI=%1 入网 代理=%2", "Assoc confirm: STA TEI=%1 joined, proxy=%2");
        trl::register_en("关联指示: STA TEI=%1 入网 代理=%2", "Assoc indication: STA TEI=%1 joined, proxy=%2");
        trl::register_en("关联汇总: %1 个站点入网 代理=%2", "Assoc gather: %1 stations joined, proxy=%2");
        trl::register_en("发现列表: STA TEI=%1 代理=%2", "Discover list: STA TEI=%1 proxy=%2");
        trl::register_en("代理变更: STA TEI=%1 代理→%2", "Proxy change: STA TEI=%1 proxy→%2");
        trl::register_en("代理变更请求: STA TEI=%1 %2→%3", "Proxy change request: STA TEI=%1 %2→%3");
        trl::register_en("代理变更(批量): %1 个站点代理→%2", "Proxy change (batch): %1 stations proxy→%2");
        trl::register_en("离线指示: STA TEI=%1 离线", "Leave indication: STA TEI=%1 left");
        trl::register_en("延迟离线指示: %1 个站点离线", "Delayed leave indication: %1 stations left");
        // MAC 帧头字段释义(6.2.1 表3/表5/表6/表8)
        trl::register_en("长帧头(32B)", "Long header (32B)");
        trl::register_en("短帧头(12B)", "Short header (12B)");
        trl::register_en("标准帧协议", "Standard Frame Protocol");
        trl::register_en("单跳帧协议", "Single-hop Frame Protocol");
        trl::register_en("单播,需要确认回应", "Unicast, ACK required");
        trl::register_en("全网广播,不需要回应", "Network broadcast, no ACK");
        trl::register_en("本地广播,不需要回应", "Local broadcast, no ACK");
        trl::register_en("全网广播,需要确认回应", "Network broadcast, ACK required");
        trl::register_en("本地广播,需要确认回应", "Local broadcast, ACK required");
        trl::register_en("下行广播", "Downlink broadcast");
        trl::register_en("上行广播", "Uplink broadcast");
        trl::register_en("允许接入网络", "Allow Network Access");
        trl::register_en("认证失败", "Authentication Failed");
        trl::register_en("在位图(第%1字节)", "In Bitmap (Byte %1)");
        trl::register_en("SNID[%1]", "SNID[%1]");
        trl::register_en("子站点 TEI=%1", "SubSTA TEI=%1");
        trl::register_en("可发现站点 TEI=%1", "DiscoverableSTA TEI=%1");
        trl::register_en("发现站点 TEI=%1", "DiscoverySTA TEI=%1");
        trl::register_en(" (载波 %1-%2)", " (carrier %1-%2)");
        trl::register_en("Neighbor[%1] TEI=%2 (位图 byte %3 bit %4)", "Neighbor[%1] TEI=%2 (bitmap byte %3 bit %4)");
        trl::register_en("未接入网络,需要重新接入网络", "Not Joined, Rejoin Required");
        trl::register_en("不在认证名单中", "Not in Authentication List");
        trl::register_en(" 级", " level(s)");
        trl::register_en("%1 - %2 (%3b/邻居)", "%1 - %2 (%3b/neighbor)");
    }
} mme_i18n_reg;

// 表98：应用 VLAN 直接对应 LID；管理报文的 LID 由实现自定义。
static QString vlan_tag_value(quint32 vlan, quint16 msdu_type, int hex_width) {
    QString meaning;
    if (msdu_type == static_cast<quint16>(NW_2026_MsduType::APPLICATION_PACKET) && vlan <= 3) {
        meaning = trl::L("抄表/数据订阅应用，LID（优先级）=%1").arg(vlan);
    } else if (msdu_type == static_cast<quint16>(NW_2026_MsduType::MANAGEMENT_MESSAGE)
               && vlan == static_cast<quint32>(NW_2026_VlanTag::MANAGEMENT)) {
        meaning = trl::L("网络管理报文，LID（优先级）=0-255（实现自定义）");
    } else {
        meaning = trl::L("未定义的VLAN/MSDU Type组合");
    }
    return QStringLiteral("0x%1 - %2").arg(vlan, hex_width, 16, QChar('0')).arg(meaning);
}

static void append_mme_header(MsduInfo& out, const QByteArray& mme, int rel_base) {
    out.summary = trl::L("MMe");
    if (mme.size() >= 3) {
        out.mme_type = (quint16)get_bits(mme, 1, 0, 16);
        out.summary = mme_type_name(out.mme_type);
    }
    if (!mme.isEmpty()) {
        const quint8 version = (quint8)mme[0];
        MsduFieldNode mv;
        mv.name = QStringLiteral("MMe Version [8b]");
        mv.value = QStringLiteral("%1").arg(version);
        if (version != 1)
            mv.value += QStringLiteral(" - %1").arg(trl::L("不支持的MMe版本（仅支持1）"));
        mv.rel_start = rel_base;
        mv.rel_len   = 1;
        out.tree.append(mv);
    }
    if (mme.size() >= 2) {
        MsduFieldNode mt;
        mt.name = QStringLiteral("MMe Type [16b]");
        mt.value = mme.size() >= 3
            ? QStringLiteral("0x%1 - %2").arg(out.mme_type, 4, 16, QChar('0')).arg(out.summary)
            : QStringLiteral("0x??%1 (truncated)").arg((quint8)mme[1], 2, 16, QChar('0'));
        mt.rel_start = rel_base + 1;
        mt.rel_len   = qMin(2, int(mme.size()) - 1);
        out.tree.append(mt);
    }
    if (mme.size() >= 4) {
        MsduFieldNode rv;
        rv.name = QStringLiteral("RSV [24b]");
        rv.value = QStringLiteral("0x%1").arg(QString::fromLatin1(mme.mid(3, 3).toHex().toUpper()));
        if (mme.size() < 6) rv.value += QStringLiteral(" (truncated)");
        rv.rel_start = rel_base + 3;
        rv.rel_len   = qMin(3, int(mme.size()) - 3);
        out.tree.append(rv);
    }
}

static void append_msdu_crc(MsduInfo& out, const QByteArray& body, int payload_start, int payload_len) {
    const int crc_off = payload_start + payload_len;
    const int available = qBound(0, int(body.size()) - crc_off, 4);
    MsduFieldNode crc;
    crc.name = QStringLiteral("MSDU CRC32");
    crc.rel_start = available > 0 ? crc_off : -1;
    crc.rel_len   = available;
    if (available == 4) {
        const quint32 stored = (quint32)get_bits(body, crc_off, 0, 32);
// crc32_le 内部遍历 len-4 字节;此处传 载荷+4(全长)即校验载荷区,
// 末 4B 为本 CRC 自身(crc.h 约定,勿传 payload_len/msdu_len 否则少算 4B)
        const quint32 calc = crc32_le(reinterpret_cast<const quint8*>(body.constData()) + payload_start,
                                     payload_len + 4);
        crc.value = QStringLiteral("0x%1 %2").arg(stored, 8, 16, QChar('0'))
            .arg(stored == calc ? QStringLiteral("OK") : QStringLiteral("FAIL"));
        if (stored != calc)
            pa::warn("nw_2026:crc_fail", QStringLiteral("MSDU CRC32 stored=0x%1 calc=0x%2").arg(stored,8,16,QChar('0')).arg(calc,8,16,QChar('0')));
    } else {
        crc.value = trl::L("校验数据缺失（已有%1/4字节）").arg(available);
        pa::warn("nw_2026:crc_missing", QStringLiteral("CRC data %1/4 bytes").arg(available));
        append_summary(out, trl::L(" (CRC 缺失)"));
    }
    out.tree.append(crc);
}

/// 关联请求报文体(SPLC-4 表78;体偏移,字节号不含 MMe 头 6B):
/// MAC@0-5 / 候选代理TEI0-4@6-15 / 相线@16-18 / 设备类型@19(表81) /
/// 保留@20 / 扩展特性标识@21 bit0(表78 段) / MAC地址类型@22(表78 段) /
/// 模块类型@23 bit0-1(表84) + 候选代理0-4链路类型@23 bit2-6(表79) + 保留 bit7 / 随机数@24-27
static const FieldSpec kMMeAssocReqSpec[] = {
    { "STAMACAddr", 0, 0, 48, Fmt::MAC },
    { "CandidateTEI0", 6, 0, 16, Fmt::DEC },
    { "CandidateTEI1", 8, 0, 16, Fmt::DEC },
    { "CandidateTEI2", 10, 0, 16, Fmt::DEC },
    { "CandidateTEI3", 12, 0, 16, Fmt::DEC },
    { "CandidateTEI4", 14, 0, 16, Fmt::DEC },
    { "LinePhase0", 16, 0, 8, Fmt::DEC },
    { "CandidateLinePhase1", 17, 0, 8, Fmt::DEC },
    { "CandidateLinePhase2", 18, 0, 8, Fmt::DEC },
    { "DeviceType", 19, 0, 8, Fmt::DEC },
    { "MMeAssocReqRSV5", 20, 0, 8, Fmt::HEX4 },
    // 扩展特性标识(表78,报文体 byte21):bit0 置1=支持应用层多帧抄读,bit1-7 保留
    { "ExtFeatureFlag", 21, 0, 1, Fmt::DEC },
    { "MMeAssocReqRSV6", 21, 1, 7, Fmt::HEX4 },
    { "MACAddrType", 22, 0, 8, Fmt::DEC },
    // 模块类型(bit0-1)+候选代理0-4链路类型(bit2-6)+保留(bit7),规格§5.1.4.1(byte23 未标注比特位,按序打包)
    { "ModuleType", 23, 0, 2, Fmt::DEC },
    { "LinkType0", 23, 2, 1, Fmt::DEC },
    { "LinkType1", 23, 3, 1, Fmt::DEC },
    { "LinkType2", 23, 4, 1, Fmt::DEC },
    { "LinkType3", 23, 5, 1, Fmt::DEC },
    { "LinkType4", 23, 6, 1, Fmt::DEC },
    { "RSV2", 23, 7, 1, Fmt::HEX4 },
    { "STAAssocRandomData", 24, 0, 32, Fmt::DEC },
};
static const int kMMeAssocReqSpecN = int(sizeof(kMMeAssocReqSpec)/sizeof(kMMeAssocReqSpec[0]));

/// 关联请求尾段(SPLC-4 表78 byte56-67):硬/软复位@56-59 / 代理类型@60(表88) /
/// 组网序列号@61 / PLC能力指示+通道数+保留@62 / 频段标识@63 bit0-1 / 端到端序列号@64-67;
/// 排在厂家附加数据(28-45)与版本信息(46-55)之后渲染,字段树顺序与报文布局一致
static const FieldSpec kMMeAssocReqTailSpec[] = {
    { "HardRstCount", 56, 0, 16, Fmt::DEC },
    { "SoftRstCount", 58, 0, 16, Fmt::DEC },
    { "ProxyType", 60, 0, 8, Fmt::DEC },
    { "NetSN", 61, 0, 8, Fmt::DEC },
    { "RSV3", 62, 0, 1, Fmt::HEX4 },
    { "MMeVersion", 62, 1, 4, Fmt::DEC },
    { "PLCCapInd", 62, 5, 2, Fmt::DEC },   // PLC能力指示:0=支持BPLC 1=支持BPLC+SPLC
    { "ChannelNum", 62, 7, 1, Fmt::DEC },  // 通道数:0=单通道 1=多通道
    { "BandSupport", 63, 0, 2, Fmt::DEC },
    { "RSV5", 63, 2, 6, Fmt::HEX4 },
    { "EndSequence", 64, 0, 32, Fmt::DEC },
};
static const int kMMeAssocReqTailSpecN = int(sizeof(kMMeAssocReqTailSpec)/sizeof(kMMeAssocReqTailSpec[0]));

static const FieldSpec kMMeAssocCnfSpec[] = {
    { "STAMACAddr", 0, 0, 48, Fmt::MAC },
    { "AssocResult", 6, 0, 8, Fmt::DEC },
    { "STALevel", 7, 0, 8, Fmt::DEC },
    { "STATEI", 8, 0, 16, Fmt::DEC },
    { "ProxyTEI", 10, 0, 16, Fmt::DEC },
    { "TotalPacketNum", 12, 0, 8, Fmt::DEC },
    { "PacketIndex", 13, 0, 8, Fmt::DEC },
    { "LastPacketFlag", 14, 0, 8, Fmt::DEC },
    // 链路类型(表79:byte15 1bit,0=高速载波链路 1=无线链路)+载波频段(表92:byte15 3bit,取值见表95)+保留 4bit
    { "LinkType", 15, 0, 1, Fmt::DEC },
    { "CarrierFreq", 15, 1, 3, Fmt::DEC },
    { "RSV1", 15, 4, 4, Fmt::HEX4 },
    { "STAAssocRandomData", 16, 0, 32, Fmt::DEC },
    { "STAReAssocTime", 20, 0, 32, Fmt::DEC },
    { "EndSequence", 24, 0, 32, Fmt::DEC },
    { "PathSequence", 28, 0, 32, Fmt::DEC },
    { "NetSN", 32, 0, 8, Fmt::DEC },
    { "MMeVersion", 33, 0, 4, Fmt::DEC },
    { "DetectBandFlag", 33, 4, 1, Fmt::DEC },
    { "RSV2", 33, 5, 19, Fmt::HEX4 },
};
static const int kMMeAssocCnfSpecN = int(sizeof(kMMeAssocCnfSpec)/sizeof(kMMeAssocCnfSpec[0]));

static const FieldSpec kMMeChangeProxyReqSpec[] = {
    { "STATEI", 0, 0, 16, Fmt::DEC },
    { "NewProxyTEI0", 2, 0, 16, Fmt::DEC },
    { "NewProxyTEI1", 4, 0, 16, Fmt::DEC },
    { "NewProxyTEI2", 6, 0, 16, Fmt::DEC },
    { "NewProxyTEI3", 8, 0, 16, Fmt::DEC },
    { "NewProxyTEI4", 10, 0, 16, Fmt::DEC },
    { "OldProxyTEI", 12, 0, 16, Fmt::DEC },
    { "ProxyType", 14, 0, 8, Fmt::DEC },
    { "Reason", 15, 0, 8, Fmt::DEC },
    { "LinePhase0", 16, 0, 8, Fmt::DEC },
    { "CandidateLinePhase1", 17, 0, 8, Fmt::DEC },
    { "CandidateLinePhase2", 18, 0, 8, Fmt::DEC },
    { "RSV0", 19, 0, 8, Fmt::HEX4 },
    { "EndSequence", 20, 0, 32, Fmt::DEC },
    { "NetSN", 24, 0, 8, Fmt::DEC },
    { "RSV1", 25, 0, 120, Fmt::HEX4 },
};
static const int kMMeChangeProxyReqSpecN = int(sizeof(kMMeChangeProxyReqSpec)/sizeof(kMMeChangeProxyReqSpec[0]));

static const FieldSpec kMMeAssocIndSpec[] = {
    { "AssocResult", 0, 0, 8, Fmt::DEC },
    { "STALevel", 1, 0, 8, Fmt::DEC },
    { "STAMACAddr", 2, 0, 48, Fmt::MAC },
    { "CCOMACAddr", 8, 0, 48, Fmt::MAC },
    { "STATEI", 14, 0, 16, Fmt::DEC },
    { "ProxyTEI", 16, 0, 16, Fmt::DEC },
    // 链路类型(表79:byte18 1bit)+载波频段(表99:byte18 3bit,取值见表95)+保留 20bit
    { "LinkType", 18, 0, 1, Fmt::DEC },
    { "CarrierFreq", 18, 1, 3, Fmt::DEC },
    { "RSV1", 18, 4, 20, Fmt::HEX4 },
    { "PacketIndex", 21, 0, 8, Fmt::DEC },
    { "TotalPacketNum", 22, 0, 8, Fmt::DEC },
    { "LastPacketFlag", 23, 0, 8, Fmt::DEC },
    { "STAAssocRandomData", 24, 0, 32, Fmt::DEC },
    { "RSV2", 28, 0, 136, Fmt::HEX4 },
    { "NetSN", 45, 0, 8, Fmt::DEC },
    { "RSV3", 46, 0, 16, Fmt::HEX4 },
    { "STAReAssocTime", 48, 0, 32, Fmt::DEC },
    { "EndSequence", 52, 0, 32, Fmt::DEC },
    { "RSV4", 56, 0, 64, Fmt::HEX4 },
};
static const int kMMeAssocIndSpecN = int(sizeof(kMMeAssocIndSpec)/sizeof(kMMeAssocIndSpec[0]));

static const FieldSpec kMMeChangeProxyCnfSpec[] = {
    { "Result", 0, 0, 32, Fmt::DEC },
    { "TotalPacketNum", 4, 0, 8, Fmt::DEC },
    { "PacketIndex", 5, 0, 8, Fmt::DEC },
    { "STATEI", 6, 0, 16, Fmt::DEC },
    { "ProxyTEI", 8, 0, 16, Fmt::DEC },
    { "ChildSum", 10, 0, 16, Fmt::DEC },
    { "RSV", 12, 0, 8, Fmt::HEX4 },
    { "NetSN", 13, 0, 8, Fmt::DEC },
    { "LinkType", 14, 0, 1, Fmt::DEC },
    { "RSV0", 14, 1, 7, Fmt::HEX4 },
    { "RSV1", 15, 0, 8, Fmt::HEX4 },
    { "EndSequence", 16, 0, 32, Fmt::DEC },
    { "PathSequence", 20, 0, 32, Fmt::DEC },
    { "RSV2", 24, 0, 64, Fmt::HEX4 },
};
static const int kMMeChangeProxyCnfSpecN = int(sizeof(kMMeChangeProxyCnfSpec)/sizeof(kMMeChangeProxyCnfSpec[0]));

static const FieldSpec kMMeAssocGatherIndSpec[] = {
    { "AssocResult", 0, 0, 8, Fmt::DEC },
    { "STALevel", 1, 0, 8, Fmt::DEC },
    { "CCOMACAddr", 2, 0, 48, Fmt::MAC },
    { "ProxyTEI", 8, 0, 16, Fmt::DEC },
    { "NetSN", 10, 0, 8, Fmt::DEC },
    { "NewSTANumber", 11, 0, 8, Fmt::DEC },
    // 载波频段(SPLC 第4部分 表102:byte12 bit0-2 3bit,取值见 SPLC 第4部分 表95)+保留(bit3-7 5bit + byte13-27 15字节)=125bit
    // 注意: SPLC 第4部分 表102 关联汇总指示无「链路类型」字段(与 SPLC 第4部分 表92/99 不同)
    { "CarrierFreq", 12, 0, 3, Fmt::DEC },
    { "RSV3", 12, 3, 125, Fmt::HEX4 },
};
static const int kMMeAssocGatherIndSpecN = int(sizeof(kMMeAssocGatherIndSpec)/sizeof(kMMeAssocGatherIndSpec[0]));

// 位图版代理变更确认:分头/尾两段渲染,中间夹位图块(byte 9-138),使树序与字节序一致
static const FieldSpec kMMeChangeProxyBitMapCnfSpec[] = {
    { "Result", 0, 0, 32, Fmt::DEC },
    { "STATEI", 4, 0, 16, Fmt::DEC },
    { "ProxyTEI", 6, 0, 16, Fmt::DEC },
    { "NetSN", 8, 0, 8, Fmt::DEC },
};
static const int kMMeChangeProxyBitMapCnfSpecN = int(sizeof(kMMeChangeProxyBitMapCnfSpec)/sizeof(kMMeChangeProxyBitMapCnfSpec[0]));
static const FieldSpec kMMeChangeProxyBitMapCnfTailSpec[] = {
    // 链路类型(SPLC 表111:byte139 bit0,0=高速载波链路 1=无线链路)+保留 7bit
    { "LinkType", 139, 0, 1, Fmt::DEC },
    { "RSV0", 139, 1, 7, Fmt::HEX4 },
    { "EndSequence", 140, 0, 32, Fmt::DEC },
    { "PathSequence", 144, 0, 32, Fmt::DEC },
};
static const int kMMeChangeProxyBitMapCnfTailSpecN = int(sizeof(kMMeChangeProxyBitMapCnfTailSpec)/sizeof(kMMeChangeProxyBitMapCnfTailSpec[0]));

static const FieldSpec kMMeLeaveIndSpec[] = {
    { "LeaveSTATEI", 0, 0, 16, Fmt::DEC },
    { "Reason", 2, 0, 16, Fmt::DEC },
    { "LeaveSTAMAC", 4, 0, 48, Fmt::MAC },
    { "ProxyTEI", 10, 0, 16, Fmt::DEC },
    { "RSV0", 12, 0, 64, Fmt::HEX4 },
};
static const int kMMeLeaveIndSpecN = int(sizeof(kMMeLeaveIndSpec)/sizeof(kMMeLeaveIndSpec[0]));

static const FieldSpec kMMeHeartBeatCheckSpec[] = {
    { "OriginalSourceTEI", 0, 0, 16, Fmt::DEC },
    { "DiscoverCountTEI", 2, 0, 16, Fmt::DEC },
    { "DiscoverCount", 4, 0, 32, Fmt::DEC },
};
static const int kMMeHeartBeatCheckSpecN = int(sizeof(kMMeHeartBeatCheckSpec)/sizeof(kMMeHeartBeatCheckSpec[0]));

static const FieldSpec kMMeDiscoverNodeListSpec[] = {
    { "STATEI", 0, 0, 16, Fmt::DEC },
    { "Role", 2, 0, 8, Fmt::DEC },
    { "Level", 3, 0, 8, Fmt::DEC },
    { "MACAddr", 4, 0, 48, Fmt::MAC },
    { "ProxyTEI", 10, 0, 16, Fmt::DEC },
    // PLC能力指示(12,0,2)+通道数(12,2,1),规格发现列表(byte12);其余 12-15 保留
    { "PLCCapInd", 12, 0, 2, Fmt::DEC },
    { "ChannelNum", 12, 2, 1, Fmt::DEC },
    { "RSV0", 12, 3, 28, Fmt::HEX8 },
    { "CommRateCalculateFinish", 15, 7, 1, Fmt::DEC },
    { "ProxyCommRate", 16, 0, 32, Fmt::DEC },
    { "ProxyDownCommRate", 20, 0, 32, Fmt::DEC },
    { "DiscoverNodeNum", 24, 0, 16, Fmt::DEC },
    { "SendDiscoveryPacketCount", 26, 0, 16, Fmt::DEC },
    { "UpRouteEntryNum", 28, 0, 16, Fmt::DEC },
    { "ReceivedInfoEntryLen", 30, 0, 8, Fmt::DEC },
    { "RSV1", 31, 0, 16, Fmt::HEX4 },
    { "RoutePeriodLeftTime", 33, 0, 16, Fmt::DEC },
    { "CandidateLinePhase2", 35, 0, 2, Fmt::DEC },
    { "CandidateLinePhase1", 35, 2, 2, Fmt::DEC },
    { "CandidateLinePhase0", 35, 4, 2, Fmt::DEC },
    { "RSV2", 35, 6, 2, Fmt::HEX4 },
    { "MinCommRate", 36, 0, 8, Fmt::DEC },
    // 与代理的RU_SNR评估信息(37-40,32b)+保留(41),规格发现列表
    { "ProxyRUSNR", 37, 0, 32, Fmt::DEC },
    { "RSV3", 41, 0, 8, Fmt::HEX4 },
};
static const int kMMeDiscoverNodeListSpecN = int(sizeof(kMMeDiscoverNodeListSpec)/sizeof(kMMeDiscoverNodeListSpec[0]));

static const FieldSpec kMMeDelayLeaveIndSpec[] = {
    { "Reason", 0, 0, 16, Fmt::DEC },
    { "LeaveSTANum", 2, 0, 16, Fmt::DEC },
    { "LeaveDelayTime", 4, 0, 16, Fmt::DEC },
    { "RSV0", 6, 0, 80, Fmt::HEX4 },
};
static const int kMMeDelayLeaveIndSpecN = int(sizeof(kMMeDelayLeaveIndSpec)/sizeof(kMMeDelayLeaveIndSpec[0]));

static const FieldSpec kMMeSuccessRateReportSpec[] = {
    { "ProxySTATEI", 0, 0, 16, Fmt::DEC },
    { "STANumber", 2, 0, 16, Fmt::DEC },
};
static const int kMMeSuccessRateReportSpecN = int(sizeof(kMMeSuccessRateReportSpec)/sizeof(kMMeSuccessRateReportSpec[0]));

// 过零 NTB 采集指示(表84):站点 TEI + 站点类型 + 采集周期 + 采集数量
static const FieldSpec kMMeZeroCrossNTBCollectIndSpec[] = {
    { "STATEI",          0, 0, 16, Fmt::DEC },
    { "StationType",     2, 0, 8,  Fmt::DEC },
    { "CollectPeriod",   3, 0, 8,  Fmt::DEC },
    { "CollectQuantity", 4, 0, 8,  Fmt::DEC },
};
static const int kMMeZeroCrossNTBCollectIndSpecN = int(sizeof(kMMeZeroCrossNTBCollectIndSpec)/sizeof(kMMeZeroCrossNTBCollectIndSpec[0]));

// 过零 NTB 上报报文(表87):站点 TEI + 上报数量 + 保留 + 基准 NTB 值;
// 差值列表(表88:12bit/项紧凑排列)自消息体 byte 8 起,在 case 里动态解析
static const FieldSpec kMMeZeroCrossNTBReportSpec[] = {
    { "TEI",         0, 0, 16, Fmt::DEC },
    { "ReportCount", 2, 0, 8,  Fmt::DEC },
    { "RSV0",        3, 0, 8,  Fmt::HEX4 },
    { "NTBBase",     4, 0, 32, Fmt::DEC },
};
static const int kMMeZeroCrossNTBReportSpecN = int(sizeof(kMMeZeroCrossNTBReportSpec)/sizeof(kMMeZeroCrossNTBReportSpec[0]));

static const FieldSpec kMMeNetDiagnoseSpec[] = {
    { "ChipID", 0, 0, 16, Fmt::DEC },
};
static const int kMMeNetDiagnoseSpecN = int(sizeof(kMMeNetDiagnoseSpec)/sizeof(kMMeNetDiagnoseSpec[0]));

// 网络冲突上报 0x005F(第2部分无线表204,固定体 9B)
static const FieldSpec kMMeNetworkConflictReportSpec[] = {
    { "ConflictCCOMACAddr", 0, 0, 48, Fmt::MAC },   // 冲突网络 CCO MAC 地址(6B)
    { "NeighborNetNum",     6, 0, 8,  Fmt::DEC },   // 邻居网络个数(1B)
    { "NeighborSNIDBitmap", 7, 0, 16, Fmt::HEX4 },  // 邻居网络 SNID 位图(2B)
};
static const int kMMeNetworkConflictReportSpecN = int(sizeof(kMMeNetworkConflictReportSpec)/sizeof(kMMeNetworkConflictReportSpec[0]));

// 无线信道冲突上报 0x0070(第2部分无线表212,固定头 7B + 变长条目)
static const FieldSpec kMMeRFChannelConflictReportSpec[] = {
    { "ConflictCCOMACAddr", 0, 0, 48, Fmt::MAC },   // 冲突网络 CCO MAC 地址(6B)
    { "NeighborNetNum",     6, 0, 8,  Fmt::DEC },   // 邻居网络个数(1B)
};
static const int kMMeRFChannelConflictReportSpecN = int(sizeof(kMMeRFChannelConflictReportSpec)/sizeof(kMMeRFChannelConflictReportSpec[0]));

// 邻居网络条目(第2部分无线表213,每条 2B):无线信道号 1B + option 2bit + 保留 6bit
static const FieldSpec kRFChannelNeighborSpec[] = {
    { "RFChannel", 0, 0, 8, Fmt::DEC },   // 无线信道号
    { "RFOption",  1, 0, 2, Fmt::DEC },   // 无线 option
    { "RSV",       1, 2, 6, Fmt::HEX4 },  // 保留 6bit
};
static const int kRFChannelNeighborSpecN = int(sizeof(kRFChannelNeighborSpec)/sizeof(kRFChannelNeighborSpec[0]));

// ── SPLC 新增管理消息(SPLC 数据链路层 §5.1.4.19-5.1.4.24,表153-164) ──
// Bitloading训练结果更新请求 0x0080(表153,固定头 8B + 可变比特加载表)
// 表153(PDF 第62页原文,DstTEI 字节号经 PDF 核实——源TEI 12b 占 byte0+byte1低4,
// 目的TEI 12b 占 byte1高4+byte2,与表157 同布局;流数起 byte3 与位流连续推演一致)
static const FieldSpec kMMeBitLoadUpdateReqSpec[] = {
    { "SrcTEI",          0, 0, 12, Fmt::DEC },
    { "DstTEI",          1, 4, 12, Fmt::DEC },
    { "StreamNum",       3, 0, 1,  Fmt::DEC },   // 0单流 1双流
    { "CutOffCarrier",   3, 1, 9,  Fmt::DEC },   // 截止载波(全带宽可用填490)
    { "RSV0",            4, 2, 6,  Fmt::HEX4 },
    { "RSV1",            5, 0, 8,  Fmt::HEX4 },
    { "BitLoadTableLen", 6, 0, 16, Fmt::DEC },   // 比特加载表长度(字节)
};
static const int kMMeBitLoadUpdateReqSpecN = int(sizeof(kMMeBitLoadUpdateReqSpec)/sizeof(kMMeBitLoadUpdateReqSpec[0]));
// Bitloading训练结果更新确认 0x0081(表157,固定头 5B)
// 表157(PDF 第63页原文,字节号经 PDF 核实——MinerU .md 曾丢该列致 5B 误实现):
// 源TEI 12b(0,0) + 目的TEI 12b(1,4,跨字节) + 更新结果 1b(3,0) + 保留 7b(3,1-7) = 4B
static const FieldSpec kMMeBitLoadUpdateCnfSpec[] = {
    { "SrcTEI",       0, 0, 12, Fmt::DEC },
    { "DstTEI",       1, 4, 12, Fmt::DEC },
    { "UpdateResult", 3, 0, 1,  Fmt::DEC },   // 0更新成功 1更新失败
    { "RSV",          3, 1, 7,  Fmt::HEX4 },
};
static const int kMMeBitLoadUpdateCnfSpecN = int(sizeof(kMMeBitLoadUpdateCnfSpec)/sizeof(kMMeBitLoadUpdateCnfSpec[0]));
// RU_SNR信息告知 0x0082(表158,固定头 8B + 位图 + 邻居RU_SNR)
static const FieldSpec kMMeRUSNRInfoIndSpec[] = {
    { "SrcTEI",           0, 0, 12, Fmt::DEC },
    { "NeighborStartTEI", 1, 4, 12, Fmt::DEC },
    { "RUGroupId",        3, 0, 8,  Fmt::DEC },   // 0=RU分组ID0信息(表159)
    { "NeighborNum",      4, 0, 16, Fmt::DEC },   // 告知的邻居站点总数
    { "BitmapLen",        6, 0, 16, Fmt::DEC },   // 邻居站点位图长度(字节)
};
static const int kMMeRUSNRInfoIndSpecN = int(sizeof(kMMeRUSNRInfoIndSpec)/sizeof(kMMeRUSNRInfoIndSpec[0]));
// RU 分组 ID0 信息(表159,每邻居 4B):RU0-RU5 各 5bit SNR + 保留 2bit
static const FieldSpec kRUSNRGroup0Spec[] = {
    { "RU0_SNR", 0, 0, 5, Fmt::DEC },
    { "RU1_SNR", 0, 5, 5, Fmt::DEC },
    { "RU2_SNR", 1, 2, 5, Fmt::DEC },
    { "RU3_SNR", 1, 7, 5, Fmt::DEC },
    { "RU4_SNR", 2, 4, 5, Fmt::DEC },
    { "RU5_SNR", 3, 1, 5, Fmt::DEC },
    { "RSV",     3, 6, 2, Fmt::HEX4 },
};
static const int kRUSNRGroup0SpecN = int(sizeof(kRUSNRGroup0Spec)/sizeof(kRUSNRGroup0Spec[0]));
// 站点TEI列表请求 0x0083(表160,固定头 8B + MAC 列表 6B/条)
static const FieldSpec kMMeTEIListReqSpec[] = {
    { "RequestSeq",  0, 0, 8,  Fmt::DEC },
    { "SrcMAC",      1, 0, 48, Fmt::MAC },
    { "StationNum",  7, 0, 8,  Fmt::DEC },   // ≤20
};
static const int kMMeTEIListReqSpecN = int(sizeof(kMMeTEIListReqSpec)/sizeof(kMMeTEIListReqSpec[0]));
// 站点TEI列表回复 0x0084(SPLC 第4部分 表161/162,固定头 8B + TEI 列表 8B/条)
static const FieldSpec kMMeTEIListCnfSpec[] = {
    { "RequestSeq",  0, 0, 8,  Fmt::DEC },
    { "SrcMAC",      1, 0, 48, Fmt::MAC },
    { "StationNum",  7, 0, 8,  Fmt::DEC },
};
static const int kMMeTEIListCnfSpecN = int(sizeof(kMMeTEIListCnfSpec)/sizeof(kMMeTEIListCnfSpec[0]));
// 站点TEI列表条目(SPLC 第4部分 表162:MAC 48b + TEI 12b + 保留 4b)
static const FieldSpec kTEIListEntrySpec[] = {
    { "StationMAC", 0, 0, 48, Fmt::MAC },
    { "StationTEI", 6, 0, 12, Fmt::DEC },
    { "RSV",        7, 4, 4,  Fmt::HEX4 },
};
static const int kTEIListEntrySpecN = int(sizeof(kTEIListEntrySpec)/sizeof(kTEIListEntrySpec[0]));
// 扩展网络冲突上报 0x0085(表163,固定头 7B + 邻居网络条目 1B/条)
static const FieldSpec kMMeExtNetConflictSpec[] = {
    { "ConflictCCOMAC",   0, 0, 48, Fmt::MAC },
    { "NeighborNetNum",   6, 0, 8,  Fmt::DEC },
};
static const int kMMeExtNetConflictSpecN = int(sizeof(kMMeExtNetConflictSpec)/sizeof(kMMeExtNetConflictSpec[0]));
// 扩展网络冲突上报邻居条目(表164:每条 1B = SNID 5bit + 保留 3bit)
static const FieldSpec kExtNetConflictNeighborSpec[] = {
    { "NeighborSNID", 0, 0, 5, Fmt::DEC },
    { "RSV",          0, 5, 3, Fmt::HEX4 },
};
static const int kExtNetConflictNeighborSpecN = int(sizeof(kExtNetConflictNeighborSpec)/sizeof(kExtNetConflictNeighborSpec[0]));

// 物联终端接入请求 0x00A0(表243,固定体 10B)
static const FieldSpec kMMeIoTAssocReqSpec[] = {
    { "IoTDeviceAddr", 0, 0, 48, Fmt::MAC },  // 物联终端设备地址(物理地址)
    { "GatewayTEI",    6, 0, 12, Fmt::DEC },  // 物联网关设备地址(TEI,12bit)
    { "RSV",           7, 4, 4,  Fmt::HEX4 },
    { "DeviceType",    8, 0, 8,  Fmt::DEC },  // 物联终端设备类型
    { "PowerType",     9, 0, 4,  Fmt::DEC },  // 功耗类型
    { "RSV2",          9, 4, 4,  Fmt::HEX4 },
};
static const int kMMeIoTAssocReqSpecN = int(sizeof(kMMeIoTAssocReqSpec)/sizeof(kMMeIoTAssocReqSpec[0]));
// 物联终端接入确认 0x00A1(表244,固定体 7B;接入结果 表245)
static const FieldSpec kMMeIoTAssocIndSpec[] = {
    { "IoTDeviceAddr", 0, 0, 48, Fmt::MAC },
    { "AccessResult",  6, 0, 8,  Fmt::DEC },
};
static const int kMMeIoTAssocIndSpecN = int(sizeof(kMMeIoTAssocIndSpec)/sizeof(kMMeIoTAssocIndSpec[0]));
// 物联终端离线指示 0x00A2(表246,固定体 7B;离线原因 表247)
static const FieldSpec kMMeIoTLeaveIndSpec[] = {
    { "IoTDeviceAddr", 0, 0, 48, Fmt::MAC },
    { "LeaveReason",   6, 0, 8,  Fmt::DEC },
};
static const int kMMeIoTLeaveIndSpecN = int(sizeof(kMMeIoTLeaveIndSpec)/sizeof(kMMeIoTLeaveIndSpec[0]));
// 接入结果(表245:0 允许接入网络 / 1 认证失败)
static const char* kIoTAccessResultZh[] = { "允许接入网络", "认证失败" };
// 离线原因(表247:0 未接入需重新接入 / 1 不在认证名单 / 其他保留)
// 注:文档正文(第2部分 L1294 / SPLC L4911)写"0.表示不在认证档案中",与各自表格矛盾,以表格为准。
static const char* kIoTLeaveReasonZh[] = { "未接入网络,需要重新接入网络", "不在认证名单中" };



// ── 南网 MMe 变长区字段表 ─────────────────────────────
// MMeAssocReq:STAVersionInfo 10B(相对 MMe 数据起点 byte 52 = MMeHeadSize+46);
// 版本信息(SPLC-4 表85):BOOT/软件版本 BCD,厂商/芯片 ASCII;系统启动原因=表86,版本时间=表87
static const FieldSpec kAssocReqSTAVerSpec[] = {
    { "BootReason",       0, 0, 8,  Fmt::DEC },
    { "BootVersion",      1, 0, 8,  Fmt::DEC },
    { "SoftwareVersion",  2, 0, 16, Fmt::DEC },
    { "VersionDataYear",  4, 0, 7,  Fmt::DEC },
    { "VersionDataMonth", 4, 7, 4,  Fmt::DEC },
    { "VersionDataDay",   5, 3, 5,  Fmt::DEC },
    { "ManufacturerID",   6, 0, 16, Fmt::HEX4 },
    { "ChipID",           8, 0, 16, Fmt::HEX4 },
};
static const int kAssocReqSTAVerSpecN = int(sizeof(kAssocReqSTAVerSpec)/sizeof(kAssocReqSTAVerSpec[0]));
// MMeAssocCnf/Ind:RouteInfo 汇总头(相对 RouteInfo 起点,各消息 base 不同)
static const FieldSpec kRouteInfoHeadSpec[] = {
    { "StraightSTASum",     0, 0, 16, Fmt::DEC },
    { "StraightPCOSum",     2, 0, 16, Fmt::DEC },
    { "RouteInfoTableSize", 4, 0, 16, Fmt::DEC },
    { "RSV3",               6, 0, 16, Fmt::HEX4 },
};
static const int kRouteInfoHeadSpecN = int(sizeof(kRouteInfoHeadSpec)/sizeof(kRouteInfoHeadSpec[0]));

// ── 南网 APP 应用层头(APP_BASE, 12B) ──────────────────
// 通道控制信息(表1:报文端口号 1B + 报文标识符 2B + 保留 1B)
static const FieldSpec kChannelCtrlInfoSpec[] = {
    { "PortNum",       0, 0, 8,  Fmt::HEX4 },
    { "PacketID",      1, 0, 16, Fmt::HEX4 },
    { "RSVBits0",      3, 0, 8,  Fmt::HEX4 },
};
static const int kChannelCtrlInfoSpecN = int(sizeof(kChannelCtrlInfoSpec)/sizeof(kChannelCtrlInfoSpec[0]));

// 业务报文头(表2:控制域 2B + 业务标识 1B + 应用版本号 1B + 帧序号 2B + 帧长 2B)
static const FieldSpec kBusinessHeaderSpec[] = {
    { "PacketType",    0, 0, 4,  Fmt::DEC },
    { "RSVBits1",      0, 4, 8,  Fmt::HEX4 },
    { "ExtBusinessFlag", 1, 4, 1, Fmt::DEC },
    { "RespondFlag",     1, 5, 1, Fmt::DEC },
    { "StartFlag",       1, 6, 1, Fmt::DEC },
    { "TransDirectionFlag", 1, 7, 1, Fmt::DEC },
    { "BusinessID",    2, 0, 8,  Fmt::HEX4 },
    { "AppVersion",    3, 0, 8,  Fmt::DEC },
    { "PacketSN",      4, 0, 16, Fmt::DEC },
    { "PacketLen",     6, 0, 16, Fmt::DEC },
};
static const int kBusinessHeaderSpecN = int(sizeof(kBusinessHeaderSpec)/sizeof(kBusinessHeaderSpec[0]));



static void append_payload_hex(MsduInfo& out, const QByteArray& app, int offset,
                               int max_len, const QString& label, int rel_base = 0) {
    if (app.size() <= offset) return;
    int avail = app.size() - offset;
    if (max_len >= 0 && avail > max_len) avail = max_len;
    if (avail <= 0) return;
    MsduFieldNode& n = group(out.tree, QStringLiteral("%1 [%2 B]").arg(label).arg(avail),
        QString::fromLatin1(app.mid(offset, avail).toHex(' ').toUpper()));
    n.rel_start = rel_base + offset; n.rel_len = avail;
}


// ── 报文端口号(6.1):0x11 业务报文 0x13 管理报文 ──
static QString port_num_name(quint8 port) {
    switch (static_cast<NW_2026_PortNum>(port)) {
    case NW_2026_PortNum::BUSINESS_PORT: return trl::L("业务报文");
    case NW_2026_PortNum::MGMT_PORT:     return trl::L("管理报文");
    default:   return QString();
    }
}

// ── 报文标识符(6.2):应用层报文固定 0x0101 ──
static QString packet_id_name(quint16 id) {
    if (id == static_cast<quint16>(NW_2026_PacketId::APP_PACKET)) return trl::L("CCO-STA 应用层报文");
    return QString();
}


/// @brief 递归给 "MSDU Type" 字段填释义
/// @note  标准 MAC 头的 MSDU Type 在 out.tree 顶层,而单跳帧(表113)的 MSDU Type 在
///        "MAC Header [4B]" 子节点里 ⇒ 必须递归,只扫顶层会漏掉单跳应用帧。
static void set_msdu_type_text(QVector<MsduFieldNode>& nodes, const QString& text) {
    for (MsduFieldNode& n : nodes) {
        if (n.name.startsWith(QLatin1String("MSDU Type"))) n.value = text;
        set_msdu_type_text(n.children, text);
    }
}


static void parse_app(MsduInfo& out, const QByteArray& app, int rel_base, quint16 msdu_type) {
    if (app.size() < 12) { out.summary = trl::L("应用报文(截断)"); return; }
    // 通道控制信息(表1,4B):报文端口号 + 报文标识符 + 保留
    MsduFieldNode& cci = group(out.tree, QStringLiteral("Channel Control Info [4B]"));
    cci.rel_start = rel_base; cci.rel_len = 4;
    add_fields(cci.children, app, 0, kChannelCtrlInfoSpec, kChannelCtrlInfoSpecN, rel_base);
    const quint8  port_num    = (quint8)get_bits(app, 0, 0, 8);
    const quint16 packet_id   = (quint16)get_bits(app, 1, 0, 16);
    const NW_2026_PacketType packet_type = static_cast<NW_2026_PacketType>(get_bits(app, 4, 0, 4));
    const quint8  business_id = (quint8)get_bits(app, 6, 0, 8);
    // 报文端口号 + 报文标识符值解释(6.1/6.2)
    const QString port_name = port_num_name(port_num);
    const QString pid_name  = packet_id_name(packet_id);
    for (auto& n : cci.children) {
        if (n.name.startsWith(QLatin1String("PortNum")) && !port_name.isEmpty())
            n.value = QStringLiteral("0x%1 - %2").arg(port_num, 2, 16, QChar('0')).arg(port_name);
        else if (n.name.startsWith(QLatin1String("PacketID")) && !pid_name.isEmpty())
            n.value = QStringLiteral("0x%1 - %2").arg(packet_id, 4, 16, QChar('0')).arg(pid_name);
    }
    // 业务报文头(表2,8B):控制域 + 业务标识 + 应用版本号 + 帧序号 + 帧长
    MsduFieldNode& bh = group(out.tree, QStringLiteral("Business Header [8B]"));
    bh.rel_start = rel_base + 4; bh.rel_len = 8;
    add_fields(bh.children, app, 4, kBusinessHeaderSpec, kBusinessHeaderSpecN, rel_base);
    // 帧类型域 + 控制域标志位 + 业务标识值解释(表4/5/6/7/8/9)
    translate_enum_i18n(bh.children, "PacketType", kPacketTypeZh, 16);
    translate_enum_i18n(bh.children, "ExtBusinessFlag", kExtBusinessFlagZh, 2);
    translate_enum_i18n(bh.children, "RespondFlag", kRespondFlagZh, 2);
    translate_enum_i18n(bh.children, "StartFlag", kStartFlagZh, 2);
    translate_enum_i18n(bh.children, "TransDirectionFlag", kTransDirectionFlagZh, 2);
    out.trans_direction_flag = (quint8)get_bits(app, 5, 7, 1);  // 表8 byte1 bit7(业务报文头自 app[4],P2P Dir 列)
    annotate_unit(bh.children, "PacketLen", QStringLiteral(" B"));
    const QString bid_name = nw_app_bid_name(port_num, static_cast<quint8>(packet_type), business_id);
    // 括号内统一文案:有业务名 → "BID=0x03 站点间通信 ↓";保留组合 → 只留 "BID=0x02"(不带方向/尾部空白)
    const QString bid_disp = bid_name.isEmpty()
        ? QStringLiteral("BID=0x%1").arg(business_id, 2, 16, QChar('0'))
        : QStringLiteral("BID=0x%1 %2 %3")
              .arg(business_id, 2, 16, QChar('0'))
              .arg(bid_name)
              .arg(nw_app_dir_symbol(out.trans_direction_flag));
    if (!bid_name.isEmpty()) {
        for (auto& n : bh.children) {
            if (n.name.startsWith(QLatin1String("BusinessID")))
                n.value = QStringLiteral("0x%1 - %2 %3")
                              .arg(business_id, 2, 16, QChar('0'))
                              .arg(bid_name)
                              .arg(nw_app_dir_symbol(out.trans_direction_flag));
        }
    }
    // MSDU Type 字段附带 BID + 业务名 + 方向(应用层报文:一眼看出业务类型与上下行)
    // 单跳帧的 MSDU Type 在 MAC Header 子节点里 ⇒ 用递归填充(只扫顶层会漏)
    set_msdu_type_text(out.tree, QStringLiteral("0x%1 - %2 (%3)")
                                   .arg(msdu_type, 4, 16, QChar('0'))
                                   .arg(trl::L("应用层报文"))
                                   .arg(bid_disp));
    out.business_id = business_id;
    out.app_packet_type = static_cast<quint8>(packet_type);
    // MSDU Type 列 / Info 列来源:保留帧类型名,括号内补业务名 + 方向(表9/表8)
    out.summary = trl::L("应用层报文 (%1)").arg(bid_disp);
    // 业务数据单元(业务报文头之后,含业务扩展域)统一以"APP Data"字段展示
    append_payload_hex(out, app, 12, -1, QStringLiteral("APP Data"), rel_base);
}



// ── 南网 MMe 循环结构条目表 ──────────────────────────
static const FieldSpec kSTATEISpec[] = {
    { "STATEI", 0, 0, 16, Fmt::DEC },
};
static const int kSTATEISpecN = int(sizeof(kSTATEISpec)/sizeof(kSTATEISpec[0]));
static const FieldSpec kStraightPCOSpec[] = {
    { "PCOTEI", 0, 0, 16, Fmt::DEC },
    { "PCOChildSum", 2, 0, 16, Fmt::DEC },
};
static const int kStraightPCOSpecN = int(sizeof(kStraightPCOSpec)/sizeof(kStraightPCOSpec[0]));
static const FieldSpec kSTAInfoSpec[] = {
    { "STAMACAddr", 0, 0, 48, Fmt::MAC },
    { "STATEI", 6, 0, 16, Fmt::DEC },
};
static const int kSTAInfoSpecN = int(sizeof(kSTAInfoSpec)/sizeof(kSTAInfoSpec[0]));
static const FieldSpec kUpRouteInfoSpec[] = {
    { "NextHopTEI", 0, 0, 16, Fmt::DEC },
    { "RouteType", 2, 0, 8, Fmt::DEC },
};
static const int kUpRouteInfoSpecN = int(sizeof(kUpRouteInfoSpec)/sizeof(kUpRouteInfoSpec[0]));
static const FieldSpec kCommRateInfoSpec[] = {
    { "STATEI", 0, 0, 16, Fmt::DEC },
    { "DownCommRate", 2, 0, 8, Fmt::DEC },
    { "UpCommRate", 3, 0, 8, Fmt::DEC },
};
static const int kCommRateInfoSpecN = int(sizeof(kCommRateInfoSpec)/sizeof(kCommRateInfoSpec[0]));
template <size_t N>
static int mme_fixed_length(const FieldSpec (&spec)[N]) {
    int length = 6;
    for (const auto& field : spec)
        length = qMax(length, 6 + field.byte + (field.bit + field.len + 7) / 8);
    return length;
}

static int mme_fixed_length(NW_2026_MMeType type) {
    switch (type) {
    case NW_2026_MMeType::MME_ASSOCREQ: // 规约表分头(0-27)/尾(56-67)两段,取整体末端
        return qMax(mme_fixed_length(kMMeAssocReqSpec), mme_fixed_length(kMMeAssocReqTailSpec));
    case NW_2026_MMeType::MME_ASSOCCNF: return 50; // 固定体36B + 路由信息头8B + MMe头6B
    case NW_2026_MMeType::MME_CHANGEPROXYREQ: return mme_fixed_length(kMMeChangeProxyReqSpec);
    case NW_2026_MMeType::MME_ASSOCIND: return 78; // 固定体64B + 路由信息头8B + MMe头6B(与关联确认同构)
    case NW_2026_MMeType::MME_CHANGEPROXYCNF: return mme_fixed_length(kMMeChangeProxyCnfSpec);
    case NW_2026_MMeType::MME_ASSOCGATHERIND: return mme_fixed_length(kMMeAssocGatherIndSpec);
    case NW_2026_MMeType::MME_CHANGEPROXYBITMAPCNF: return 145; // 本体最小长度:MMe头6B + 前段9B + 位图130B(尾部字段缺失仅警告,见 parse)
    case NW_2026_MMeType::MME_LEAVEIND: return mme_fixed_length(kMMeLeaveIndSpec);
    case NW_2026_MMeType::MME_HEARTBEATCHECK: return 145; // 固定体8B + 位图130B + 保留1B + MMe头6B
    case NW_2026_MMeType::MME_DISCOVERNODELIST: return mme_fixed_length(kMMeDiscoverNodeListSpec);
    case NW_2026_MMeType::MME_DELAYLEAVEIND: return mme_fixed_length(kMMeDelayLeaveIndSpec);
    case NW_2026_MMeType::MME_SUCCESSRATEREPORT: return mme_fixed_length(kMMeSuccessRateReportSpec);
    case NW_2026_MMeType::MME_ZEROCROSSNTBCOLLECTIND: return mme_fixed_length(kMMeZeroCrossNTBCollectIndSpec);
    case NW_2026_MMeType::MME_ZEROCROSSNTBREPORT: return mme_fixed_length(kMMeZeroCrossNTBReportSpec);
    case NW_2026_MMeType::MME_NETDIAGNOSE: return mme_fixed_length(kMMeNetDiagnoseSpec);
    case NW_2026_MMeType::MME_NETWORKCONFLICTREPORT: return mme_fixed_length(kMMeNetworkConflictReportSpec);
    case NW_2026_MMeType::MME_RFCHANNELCONFLICTREPORT: return mme_fixed_length(kMMeRFChannelConflictReportSpec);
    // SPLC 新增管理消息(表153-164)
    case NW_2026_MMeType::MME_BITLOAD_UPDATE_REQ: return mme_fixed_length(kMMeBitLoadUpdateReqSpec);
    case NW_2026_MMeType::MME_BITLOAD_UPDATE_CNF: return mme_fixed_length(kMMeBitLoadUpdateCnfSpec);
    case NW_2026_MMeType::MME_RUSNR_INFO_IND: return mme_fixed_length(kMMeRUSNRInfoIndSpec);
    case NW_2026_MMeType::MME_TEI_LIST_REQ: return mme_fixed_length(kMMeTEIListReqSpec);
    case NW_2026_MMeType::MME_TEI_LIST_CNF: return mme_fixed_length(kMMeTEIListCnfSpec);
    case NW_2026_MMeType::MME_EXT_NETWORK_CONFLICT_RPT: return mme_fixed_length(kMMeExtNetConflictSpec);
    case NW_2026_MMeType::MME_IOT_ASSOC_REQ: return mme_fixed_length(kMMeIoTAssocReqSpec);
    case NW_2026_MMeType::MME_IOT_ASSOC_IND: return mme_fixed_length(kMMeIoTAssocIndSpec);
    case NW_2026_MMeType::MME_IOT_LEAVE_IND: return mme_fixed_length(kMMeIoTLeaveIndSpec);
    default: return 6;
    }
}

static bool mme_body_complete(const QByteArray& mme, NW_2026_MMeType type) {
    if (mme.size() < mme_fixed_length(type)) return false;
    const auto has_items = [&mme](int offset, int count, int item_size) {
        return offset <= mme.size() && count <= (mme.size() - offset) / item_size;
    };
    switch (type) {
    case NW_2026_MMeType::MME_ASSOCCNF:
    case NW_2026_MMeType::MME_ASSOCIND: {
        // 路由信息结构两类消息同构,仅起始偏移不同(确认 rb=42 / 指示 rb=70)
        const int rb = type == NW_2026_MMeType::MME_ASSOCCNF ? 42 : 70;
        const int sta_sum = int(get_bits(mme, rb, 0, 16));
        const int pco_sum = int(get_bits(mme, rb + 2, 0, 16));
        int offset = rb + 8;
        if (!has_items(offset, sta_sum, 2)) return false;
        offset += sta_sum * 2;
        for (int i = 0; i < pco_sum; ++i) {
            if (!has_items(offset, 1, 4)) return false;
            const int child_sum = int(get_bits(mme, offset + 2, 0, 16));
            offset += 4;
            if (!has_items(offset, child_sum, 2)) return false;
            offset += child_sum * 2;
        }
        return true;
    }
    case NW_2026_MMeType::MME_CHANGEPROXYCNF:
        return has_items(38, int(get_bits(mme, 16, 0, 16)), 2);
    case NW_2026_MMeType::MME_ASSOCGATHERIND:
        return has_items(34, int(get_bits(mme, 17, 0, 8)), 8);
    case NW_2026_MMeType::MME_DISCOVERNODELIST: {
        const int route_num = int(get_bits(mme, 34, 0, 16));
        const int node_num = int(get_bits(mme, 30, 0, 16));
        if (!has_items(48, route_num, 3)) return false;
        const int bitmap_end = 48 + route_num * 3 + 128;
        return has_items(bitmap_end, node_num, 1);
    }
    case NW_2026_MMeType::MME_DELAYLEAVEIND:
        return has_items(22, int(get_bits(mme, 8, 0, 16)), 6);
    case NW_2026_MMeType::MME_SUCCESSRATEREPORT:
        return has_items(10, int(get_bits(mme, 8, 0, 16)), 4);
    case NW_2026_MMeType::MME_ZEROCROSSNTBREPORT: {
        // 表87/88 布局:上报数量(mme 字节 8,含基准 NTB)在固定体(14B)之后,
        // 差值数量为数量-1,自 mme 字节 14 起按 12 位紧凑打包
        const int count = int(get_bits(mme, 8, 0, 8));
        const int diffs = count > 0 ? count - 1 : 0;
        return mme.size() >= 14 + (diffs * 12 + 7) / 8;
    }
    case NW_2026_MMeType::MME_RFCHANNELCONFLICTREPORT:
        // 邻居网络条目(表213,每条 2B)完整性:固定头 7B 之后自 mme[13] 起 nb_num 条
        return has_items(13, int(get_bits(mme, 12, 0, 8)), 2);
    // SPLC 新增管理消息完整性(表153-164);偏移为 mme 含 6B 头(报文体 byteN = mme[6+N])
    case NW_2026_MMeType::MME_BITLOAD_UPDATE_REQ:
        // 固定头 8B 后按 比特加载表长度(报文体 byte6 = mme[12]) 校验可变区(自 mme[14])
        return has_items(14, int(get_bits(mme, 12, 0, 16)), 1);
    case NW_2026_MMeType::MME_RUSNR_INFO_IND:
        // 仅 RU分组 id=0(报文体 byte3 = mme[9]) 结构已定义(表159,每邻居 4B);
        // 其它 id 为保留,可变区无法校验,不判截断。
        if (get_bits(mme, 9, 0, 8) != 0)
            return true;
        // 位图(自 mme[14],位图长度=报文体 byte6 = mme[12])后每邻居 4B
        return has_items(14 + int(get_bits(mme, 12, 0, 16)),
                         int(get_bits(mme, 10, 0, 16)), 4);
    case NW_2026_MMeType::MME_TEI_LIST_REQ:
        // MAC 列表(表160):固定头 8B(至报文体 byte7 = mme[13])后每站点 6B(自 mme[14])
        return has_items(14, int(get_bits(mme, 13, 0, 8)), 6);
    case NW_2026_MMeType::MME_TEI_LIST_CNF:
        // TEI 列表(SPLC 第4部分 表161/162):固定头 8B(至报文体 byte7 = mme[13])后每站点 8B(自 mme[14])
        return has_items(14, int(get_bits(mme, 13, 0, 8)), 8);
    case NW_2026_MMeType::MME_EXT_NETWORK_CONFLICT_RPT:
        // 邻居网络条目(表163/164):固定头 7B(至报文体 byte6 = mme[12])后每条 1B(自 mme[13])
        return has_items(13, int(get_bits(mme, 12, 0, 8)), 1);
    default: return true;
    }
}

// ── MAC 帧头字段表(6.2.1 表3 长帧头 32B / 6.2.2 表9 短帧头 12B) ──
// 帧头类型(表5:0 长帧头 32B / 1 短帧头 12B)
static const char* kHeaderTypeZh[] = { "长帧头(32B)", "短帧头(12B)" };
// 版本(表5:0 保留 / 1 标准帧协议 / 2 单跳帧协议 / 3 保留)
static const char* kMacVersionZh[] = { nullptr, "标准帧协议", "单跳帧协议", nullptr };
// 发送类型(南网 §6.2.1.10 表8:0 单播需确认 / 1 全网广播不需 / 2 本地广播不需 / 3 全网广播需确认 / 4 本地广播需确认)
// 注:国网 GW_2022 表5 是 0单播/1全网/2本地/3代理广播,与本表不同,勿混用。
static const char* kSendTypeZh[] = { "单播,需要确认回应", "全网广播,不需要回应", "本地广播,不需要回应", "全网广播,需要确认回应", "本地广播,需要确认回应" };
// 广播方向(§6.2.1.9 表7:0x0 保留 / 0x1 下行广播 / 0x2 上行广播 / 其他 保留)
static const char* kBroadcastDirZh[] = { nullptr, "下行广播", "上行广播", nullptr };

/// 公共字段(byte 0-11,长/短头共有)
static const FieldSpec kMacHeaderSpec[] = {
    { "HeaderType",     0, 0, 1,  Fmt::DEC },   // 帧头类型
    { "Version",        0, 1, 2,  Fmt::DEC },   // 版本
    { "SNIDHigh",       0, 3, 1,  Fmt::DEC },   // 短网络标识高位(SNID 5bit 的高1bit)
    { "SendSeq",        0, 4, 12, Fmt::DEC },   // 发送序号(byte0 bit4-7 + byte1,12bit)
    { "MSDULength",     2, 0, 16, Fmt::DEC },   // MSDU 长度
    { "DstTEI",         4, 0, 12, Fmt::DEC },   // 原始目的 TEI
    { "SrcTEI",         5, 4, 12, Fmt::DEC },   // 原始源 TEI
    { "SNIDLow",        7, 0, 4,  Fmt::DEC },   // 短网络标识低位(4bit)
    { "RestartCount",   7, 4, 4,  Fmt::DEC },   // 重启次数
    { "RouteHop",       8, 0, 4,  Fmt::DEC },   // 路由跳数
    { "BroadcastDir",   8, 4, 4,  Fmt::DEC },   // 广播方向
    { "SendType",       9, 0, 3,  Fmt::DEC },   // 发送类型
    { "SendCountLimit", 9, 3, 5,  Fmt::DEC },   // 发送次数限值
    { "MSDUSeq",        10, 0, 16, Fmt::DEC },  // MSDU 序列号
};
static const int kMacHeaderSpecN = int(sizeof(kMacHeaderSpec)/sizeof(kMacHeaderSpec[0]));

/// 长帧头独有字段(相对短头多出的 byte 12-31;RSV2 22-31 在下方单独 hex 处理)
static const FieldSpec kMacLongHeaderSpec[] = {
    { "DstMAC", 12, 0, 48, Fmt::MAC },   // 目的 MAC 地址
    { "RSV1",   18, 0, 32, Fmt::HEX8 },  // 保留
};
static const int kMacLongHeaderSpecN = int(sizeof(kMacLongHeaderSpec)/sizeof(kMacLongHeaderSpec[0]));

// ── SPLC 新增管理消息值释义(表153-164) ──
// 流数(表153:0 单流 1 双流)
static const char* kStreamNumZh[] = { "单流", "双流" };
// 更新结果(表157:0 更新成功 1 更新失败)
static const char* kUpdateResultZh[] = { "更新成功", "更新失败" };
// RU 分组 id(表158:0=RU分组ID0信息,其他保留)
static const char* kRUGroupIdZh[] = { "RU分组ID0信息", "保留" };
// 比特承载信息(表156:0/1/2/4/6 = 不承载/BPSK/QPSK/16QAM/64QAM)
static QString bitload_value_str(quint8 v) {
    switch (v) {
        case 0: return trl::L("不承载数据");
        case 1: return trl::L("BPSK(1比特)");
        case 2: return trl::L("QPSK(2比特)");
        case 4: return trl::L("16QAM(4比特)");
        case 6: return trl::L("64QAM(6比特)");
        default: return trl::L("保留");
    }
}

// ── 单跳帧协议(第2部分无线 §8.1.2.4 表113,版本==2,仅无线信道) ──
// 单跳 MAC 帧头仅 4B:帧头类型(单跳无意义)/版本/保留5b + MSDU 类型 + MSDU 长度;
// 无 TEI/SNID/重启/序号等路由字段(单跳无路由,直连 CCO/STA)。
static const FieldSpec kSingleHopHeaderSpec[] = {
    { "HeaderType",  0, 0, 1,  Fmt::DEC },   // 单跳帧协议下无意义
    { "Version",     0, 1, 2,  Fmt::DEC },   // 2=单跳帧协议
    { "RSV0",        0, 3, 5,  Fmt::HEX4 },  // 保留 5b
    { "MSDU Type",   1, 0, 8,  Fmt::DEC },   // MSDU 类型(表114)
    { "MSDULength",  2, 0, 16, Fmt::DEC },   // MSDU 长度
};
static const int kSingleHopHeaderSpecN = int(sizeof(kSingleHopHeaderSpec)/sizeof(kSingleHopHeaderSpec[0]));

// ── 无线发现列表信息单元内部字段(表215 类型 0-3) ──
// 站点属性信息(表217,固定 14B):CCO MAC/代理TEI/角色/层级/RF跳数/上下行接收率/最小接收率/发现周期/老化周期
static const FieldSpec kRfStaAttrSpec[] = {
    { "CCOMACAddr",     0, 0, 48, Fmt::MAC },
    { "ProxyTEI",       6, 0, 12, Fmt::DEC },
    { "Role",           7, 4, 4,  Fmt::DEC },   // 0未知/1站点/2代理站点/4中央协调器
    { "Level",          8, 0, 4,  Fmt::DEC },
    { "RFLinkHop",      8, 4, 4,  Fmt::DEC },
    { "ProxyUpRate",    9, 0, 8,  Fmt::DEC },   // %
    { "ProxyDownRate", 10, 0, 8,  Fmt::DEC },   // %
    { "MinLinkRate",   11, 0, 8,  Fmt::DEC },   // %
    { "RFDiscoverPeriod", 12, 0, 8, Fmt::DEC }, // 秒
    { "RateAgingNum",  13, 0, 8,  Fmt::DEC },
};
static const int kRfStaAttrSpecN = int(sizeof(kRfStaAttrSpec)/sizeof(kRfStaAttrSpec[0]));
// 路由类型(表218 后文):0x00 错误 / 0x01 同级备份 / 0x02 上级备份 / 0x03 代理主路径 / 0x04 上上级
// (与上行路由 kRouteTypeZh 的表措辞不同:南网单跳帧用"备份路由"术语,故独立成表)
static const char* kSingleHopRouteTypeZh[] = { "错误的路由类型", "同级备份路由类型", "上级备份路由类型",
                                               "代理主路径路由类型", "上上级路由类型" };
// 非位图版组合类型(表220):每邻居 TEI12b + 接收率8b + [SNR] + [信号强度]
static const int kChNonBitmapSnrBits[4] = { 0, 4, 6, 0 };
static const int kChNonBitmapRssiBits[4] = { 0, 0, 6, 4 };
// 位图版组合类型(表227):每邻居 接收率8b + [SNR] + [信号强度](TEI 由位图位置确定)
static const int kChBitmapSnrBits[6] = { 0, 4, 0, 6, 4, 0 };
static const int kChBitmapRssiBits[6] = { 0, 0, 8, 6, 4, 4 };

// 站点属性信息(表217)
static void parse_sta_attr_info(QVector<MsduFieldNode>& nodes, const QByteArray& c, int rel_base,
                                TopoEvent* ev = nullptr) {
    if (c.size() < 14) { pa::warn("nw_2026:content_short", QStringLiteral("site attr %1B<14B").arg(c.size())); return; }
    add_fields(nodes, c, 0, kRfStaAttrSpec, kRfStaAttrSpecN, rel_base);
    // 拓扑采集(表217 站点属性,不改渲染):代理 TEI/上下行接收率/最小接收率/RF 跳数/角色
    if (ev) {
        ev->proxy_tei = (quint16)get_bits(c, 6, 0, 12);
        ev->rf_role = (quint8)get_bits(c, 7, 4, 4);
        ev->rf_hop = (quint8)get_bits(c, 8, 4, 4);
        ev->proxy_up_rate = (qint16)get_bits(c, 9, 0, 8);
        ev->proxy_down_rate = (qint16)get_bits(c, 10, 0, 8);
        ev->min_link_rate = (qint16)get_bits(c, 11, 0, 8);
    }
    translate_enum_i18n(nodes, "Role", kRoleZh, 5);
    annotate_unit(nodes, "ProxyUpRate", QStringLiteral("%"));
    annotate_unit(nodes, "ProxyDownRate", QStringLiteral("%"));
    annotate_unit(nodes, "MinLinkRate", QStringLiteral("%"));
    annotate_unit(nodes, "RFDiscoverPeriod", QStringLiteral("s"));
    // 表217 释义:Level=网络层级 / RFLinkHop=路径上无线跳数 / RateAgingNum=老化周期个数
    annotate_unit(nodes, "Level", trl::L(" 级"));
    annotate_unit(nodes, "RFLinkHop", QStringLiteral(" hop"));
    annotate_unit(nodes, "RateAgingNum", trl::L(" 周期"));
}

// 站点路由信息(表218,每条 2B):下一跳 TEI 12b + 路由类型 4b
static void parse_sta_route_info(QVector<MsduFieldNode>& nodes, const QByteArray& c, int rel_base) {
    for (int i = 0, off = 0; off + 2 <= c.size(); ++i, off += 2) {
        const quint16 tei = (quint16)get_bits(c, off, 0, 12);
        const quint8  rtype = (quint8)get_bits(c, off + 1, 4, 4);
        auto& g = group(nodes, QStringLiteral("NextHop[%1]").arg(i));
        g.rel_start = rel_base + off; g.rel_len = 2;
        MsduFieldNode& t = group(g.children, QStringLiteral("NextTEI"), QString::number(tei));
        t.rel_start = rel_base + off; t.rel_len = 2;
        MsduFieldNode& r = group(g.children, QStringLiteral("RouteType"),
            QStringLiteral("%1 - %2").arg(rtype).arg(
                rtype < 5 ? trl::L(kSingleHopRouteTypeZh[rtype]) : trl::L("保留")));
        r.rel_start = rel_base + off + 1; r.rel_len = 1;
    }
}

// 信号强度量化值 → RSSI 含义(硬编码区间查表;8bit 为公式 v-111,不在本函数)
// 表149(SPLC,4bit,16 档,与第2部分表224 逐档一致):0=RSSI<-105;1=-105~-95;2:-95~-86;3:-86~-80;
//   4:-80~-74;5:-74~-68;6:-68~-62;7:-62~-56;8:-56~-48;9:-48~-42;10:-42~-36;11:-36~-30;
//   12:-30~-20;13:-20~-10;14:-10~0;15=RSSI≥0 (dBm)
// 表150(SPLC,6bit,64 档,原文完整无错位):0=RSSI<-110;档 n(1..62) 每 2dB 一档,
//   覆盖 [-110+2(n-1),-110+2n)dBm;63=RSSI≥14dBm(与第2部分表225 重建公式逐档一致)
static QString rssi_meaning(quint32 bits, quint64 v) {
    if (bits == 4) {
        static const int kLo[14] = {-105, -95, -86, -80, -74, -68, -62,
                                    -56, -48, -42, -36, -30, -20, -10};
        static const int kHi[14] = {-95, -86, -80, -74, -68, -62, -56,
                                    -48, -42, -36, -30, -20, -10, 0};
        if (v == 0)  return QStringLiteral("(RSSI<-105dBm)");
        if (v == 15) return QStringLiteral("(RSSI≥0dBm)");
        return QStringLiteral("(RSSI=%1~%2dBm)").arg(kLo[v - 1]).arg(kHi[v - 1]);
    }
    // 6bit(表225)
    if (v == 0)  return QStringLiteral("(RSSI<-110dBm)");
    if (v == 63) return QStringLiteral("(RSSI≥14dBm)");
    return QStringLiteral("(RSSI=%1~%2dBm)").arg(-110 + 2 * int(v) - 2)
                                           .arg(-110 + 2 * int(v));
}

// 渲染一个邻居信道条目(前导 TEI 可选 + 接收率[位宽可变] + [SNR] + [信号强度]);返回占用比特数
static int render_ch_entry(QVector<MsduFieldNode>& nodes, const QByteArray& c, int bitpos,
                           const QString& label, int rel_base,
                           int tei_bits, quint16 tei, int snr_bits, int rssi_bits,
                           int rcv_bits = 8, QVector<QPair<quint16, int>>* rssi_out = nullptr,
                           QVector<QPair<quint16, quint8>>* rates_out = nullptr,
                           QVector<QPair<quint16, qint16>>* snrs_out = nullptr) {
    const int total = tei_bits + rcv_bits + snr_bits + rssi_bits;
    if (bitpos + total > c.size() * 8) return 0;
    const int b0 = bitpos / 8, bi = bitpos % 8;
    auto& g = group(nodes, label);
    g.rel_start = rel_base + b0; g.rel_len = (bi + total + 7) / 8;
    int o = 0;
    if (tei_bits > 0) {
        MsduFieldNode& t = group(g.children, QStringLiteral("TEI"), QString::number(tei));
        t.rel_start = rel_base + b0; t.rel_len = (bi + tei_bits + 7) / 8;
        o += tei_bits;
    }
    if (rcv_bits > 0) {
        // 接收率位宽由组合表给定(南网表220/227 恒 8b;国网表68/77 才可变,勿混)
        const quint64 rv = get_bits(c, b0, bi + o, rcv_bits);
        MsduFieldNode& r = group(g.children, QStringLiteral("UpRate"),
            QStringLiteral("%1%").arg(rv));
        o += rcv_bits;
        r.rel_start = rel_base + b0; r.rel_len = (bi + o + 7) / 8;
        // 拓扑采集:该邻居上行成功率%(方向=邻居→我;南网接收率恒 8b=实际%)
        if (rates_out && tei)
            rates_out->append({tei, (quint8)rv});
    }
    if (snr_bits) {
        // 表222:6bit 量化值=SNR+7(dB) → SNR=v-7;4bit 映射表文档引用缺失,仅展示量化值
        const quint64 v = get_bits(c, b0, bi + o, snr_bits);
        MsduFieldNode& snr = group(g.children, QStringLiteral("AvgSNR"),
            (snr_bits == 6) ? QStringLiteral("%1 (SNR=%2dB)").arg(v).arg(int(v) - 7)
                            : QStringLiteral("%1 dB").arg(v));
        o += snr_bits;
        snr.rel_start = rel_base + b0; snr.rel_len = (bi + o + 7) / 8;
        // 拓扑采集:该邻居 SNR(dB;6bit=量化值-7,4bit 映射缺失取量化值)
        if (snrs_out && tei)
            snrs_out->append({tei, (snr_bits == 6) ? (qint16)(int(v) - 7) : (qint16)v});
    }
    if (rssi_bits) {
        // 表148(SPLC):8bit 量化值=RSSI+111(dBm) → RSSI=v-111;4/6bit 走表149/150(SPLC) 硬编码区间查表
        // (第2部分同内容表号为 表223/224/225, 勿混引)
        const quint64 v = get_bits(c, b0, bi + o, rssi_bits);
        MsduFieldNode& s = group(g.children, QStringLiteral("SignalStrength"),
            (rssi_bits == 8) ? QStringLiteral("%1 (RSSI=%2dBm)").arg(v).arg(int(v) - 111)
                             : QStringLiteral("%1 %2").arg(v).arg(rssi_meaning(rssi_bits, v)));
        o += rssi_bits;
        s.rel_start = rel_base + b0; s.rel_len = (bi + o + 7) / 8;
        // 拓扑采集:该邻居信号强度(dBm 档位下限估计;RF 发现列表上下文由调用方传入);未知 width 不追加
        if (rssi_out && tei) {
            const int dbm = rssi_bits_to_dbm(rssi_bits, v);
            if (dbm != INT_MIN) rssi_out->append({tei, dbm});
        }
    }
    return total;
}

// 邻居节点信道信息非位图版(表219/220):组合类型(0,0,4)+保留(0,4,4) + 每邻居 TEI12b+接收率8b+[SNR]+[强度]
static void parse_channel_non_bitmap(QVector<MsduFieldNode>& nodes, const QByteArray& c, int rel_base,
                                  QVector<QPair<quint16, int>>* rssi_out = nullptr,
                                  QVector<QPair<quint16, quint8>>* rates_out = nullptr,
                                  QVector<QPair<quint16, qint16>>* snrs_out = nullptr) {
    if (c.size() < 1) { pa::warn("nw_2026:content_short", QStringLiteral("channel non-bitmap <1B")); return; }
    const quint8 combo = (quint8)get_bits(c, 0, 0, 4);
    if (combo > 3) { pa::warn("nw_2026:combo_unsupported", QStringLiteral("non-bitmap combo=%1>3").arg(combo)); return; }
    MsduFieldNode& head = group(nodes, QStringLiteral("ChannelInfoHead"));
    head.rel_start = rel_base + 0; head.rel_len = 1;
    // 表220 语义:TEI 12b + 接收率 8b 恒有,SNR/RSSI 按组合类型附加
    QStringList sem;
    sem << QStringLiteral("TEI") << QStringLiteral("Rcv8b");
    if (kChNonBitmapSnrBits[combo]) sem << QStringLiteral("SNR%1b").arg(kChNonBitmapSnrBits[combo]);
    if (kChNonBitmapRssiBits[combo]) sem << QStringLiteral("RSSI%1b").arg(kChNonBitmapRssiBits[combo]);
    MsduFieldNode& ct = group(head.children, QStringLiteral("ComboType"),
        trl::L("%1 - %2 (%3b/邻居)")
            .arg(combo).arg(sem.join(QLatin1Char('+')))
            .arg(20 + kChNonBitmapSnrBits[combo] + kChNonBitmapRssiBits[combo]));
    ct.rel_start = rel_base + 0; ct.rel_len = 1;
    // 表219:保留(0,4,4)
    MsduFieldNode& cr = group(head.children, QStringLiteral("RSV [4b]"),
        QString::number(get_bits(c, 0, 4, 4)));
    cr.rel_start = rel_base + 0; cr.rel_len = 1;
    const int snr_bits = kChNonBitmapSnrBits[combo], rssi_bits = kChNonBitmapRssiBits[combo];
    int bitpos = 8;
    for (int idx = 0; ; ++idx) {
        const int b0 = bitpos / 8, bi = bitpos % 8;
        if (bitpos + 12 + 8 + snr_bits + rssi_bits > c.size() * 8) break;
        const quint16 tei = (quint16)get_bits(c, b0, bi, 12);
        const int used = render_ch_entry(nodes, c, bitpos + 12,
            QStringLiteral("Neighbor[%1] TEI=%2").arg(idx).arg(tei),
            rel_base, 0, tei, snr_bits, rssi_bits, 8, rssi_out, rates_out, snrs_out);
        if (used <= 0) break;
        bitpos += 12 + used;
    }
}

// 邻居节点信道信息位图版(表226/227):组合类型+保留 + 一组或多组 [起始TEI12b+保留4b+位图大小1B+位图+条目]
// 表227 接收率恒 8bit(0-5 全 8);可变接收率是国网表77 的语义,勿混入南网
static const int kChBitmapRcvBits[6] = { 8, 8, 8, 8, 8, 8 };
static void parse_channel_bitmap(QVector<MsduFieldNode>& nodes, const QByteArray& c, int rel_base,
                                QVector<QPair<quint16, int>>* rssi_out = nullptr,
                                QVector<QPair<quint16, quint8>>* rates_out = nullptr,
                                QVector<QPair<quint16, qint16>>* snrs_out = nullptr) {
    if (c.size() < 4) { pa::warn("nw_2026:content_short", QStringLiteral("channel bitmap %1B<4B").arg(c.size())); return; }
    const quint8 combo = (quint8)get_bits(c, 0, 0, 4);
    if (combo > 5) { pa::warn("nw_2026:combo_unsupported", QStringLiteral("bitmap combo=%1>5").arg(combo)); return; }
    MsduFieldNode& head = group(nodes, QStringLiteral("ChannelInfoHead"));
    head.rel_start = rel_base + 0; head.rel_len = 1;
    // 表227 语义:接收率 0/8b + SNR/RSSI 按组合类型附加(组合 1/2/3 无接收率)
    {
        QStringList sem;
        if (kChBitmapRcvBits[combo]) sem << QStringLiteral("Rcv%1b").arg(kChBitmapRcvBits[combo]);
        if (kChBitmapSnrBits[combo]) sem << QStringLiteral("SNR%1b").arg(kChBitmapSnrBits[combo]);
        if (kChBitmapRssiBits[combo]) sem << QStringLiteral("RSSI%1b").arg(kChBitmapRssiBits[combo]);
        MsduFieldNode& ct = group(head.children, QStringLiteral("ComboType"),
            trl::L("%1 - %2 (%3b/邻居)")
                .arg(combo).arg(sem.join(QLatin1Char('+')))
                .arg(kChBitmapRcvBits[combo] + kChBitmapSnrBits[combo] + kChBitmapRssiBits[combo]));
        ct.rel_start = rel_base + 0; ct.rel_len = 1;
        // 表226:保留(0,4,4)
        MsduFieldNode& cr = group(head.children, QStringLiteral("RSV [4b]"),
            QString::number(get_bits(c, 0, 4, 4)));
        cr.rel_start = rel_base + 0; cr.rel_len = 1;
    }
    const int snr_bits = kChBitmapSnrBits[combo], rssi_bits = kChBitmapRssiBits[combo];
    const int rcv_bits = kChBitmapRcvBits[combo];
    const int entry_bits = rcv_bits + snr_bits + rssi_bits;
    int off = 1;   // 组合类型+保留 仅 1B,首位图组自 byte1 起(表226)
    int set_idx = 0;
    while (off + 3 <= c.size()) {
        const quint16 start_tei = (quint16)get_bits(c, off, 0, 12);
        const int bm_len = (quint8)c[off + 2];   // 位图大小(组内 byte2,表226)
        if (off + 3 + bm_len > c.size()) break;
        auto& g = group(nodes, QStringLiteral("BitmapSet[%1]").arg(set_idx));
        g.rel_start = rel_base + off; g.rel_len = 3 + bm_len;
        MsduFieldNode& st = group(g.children, QStringLiteral("StartTEI"), QString::number(start_tei));
        st.rel_start = rel_base + off; st.rel_len = 2;
        // 表226:组保留(起始TEI 高 4bit,off+1 bit4-7)
        MsduFieldNode& gr = group(g.children, QStringLiteral("RSV [4b]"),
            QString::number(get_bits(c, off + 1, 4, 4)));
        gr.rel_start = rel_base + off + 1; gr.rel_len = 1;
        const QByteArray bm = c.mid(off + 3, bm_len);
        MsduFieldNode& bmn = group(g.children, QStringLiteral("Bitmap [%1 B]").arg(bm_len),
            QString::fromLatin1(bm.toHex(' ').toUpper()));
        bmn.rel_start = rel_base + off + 3; bmn.rel_len = bm_len;
        // 位图逐位(仅 bit=1,与下方条目一一对应):值标注该 bit 所在的字节号(位图内
        // 第 k/8 字节);TEI = 起始TEI + k(位序与表158 一致:byte k/8 的 bit k%8,LSB 在前)
        for (int k = 0; k < bm_len * 8; ++k) {
            if (!((bm[k >> 3] >> (k & 7)) & 1)) continue;
            MsduFieldNode& bn = group(bmn.children,
                QStringLiteral("Neighbor[%1] TEI=%2").arg(k).arg(start_tei + k),
                trl::L("在位图(第%1字节)").arg(k >> 3));
            bn.rel_start = rel_base + off + 3 + (k >> 3);
            bn.rel_len = 1;
        }
        // 位图 1 位对应 TEI=起始TEI+k,条目按位图顺序排列
        int bitpos = (off + 3 + bm_len) * 8;
        int entry_idx = 0;
        for (int k = 0; k < bm_len * 8 && bitpos + entry_bits <= c.size() * 8; ++k) {
            if (!((bm[k >> 3] >> (k & 7)) & 1)) continue;
            const int used = render_ch_entry(g.children, c, bitpos,
                trl::L("Neighbor[%1] TEI=%2 (位图 byte %3 bit %4)")
                    .arg(entry_idx).arg(start_tei + k).arg(k >> 3).arg(k & 7),
                rel_base, 0, start_tei + k, snr_bits, rssi_bits, rcv_bits, rssi_out, rates_out, snrs_out);
            if (used <= 0) break;
            bitpos += used;
            ++entry_idx;
        }
        off = (bitpos + 7) / 8;   // 下一组自本组条目末尾起
        ++set_idx;
    }
}



// 追加变长 hex 载荷节点(offset 起;max_len<0 到末尾,否则按 max_len 截断)
// MSDU 类型(表114):0 保留 / 1 应用层报文 / 2 无线发现列表消息 / 3-127 保留(管理消息扩展) / 128 IPv4
static QString singlehop_msdu_type_name(quint8 t) {
    switch (t) {
        case 1:   return trl::L("应用层报文");
        case 2:   return trl::L("无线发现列表消息");
        case 128: return trl::L("IPv4报文");
        default:
            // 表114:3-127 标注为"保留(用于管理消息类型扩展)",与 0/129+ 纯保留区分
            return (t >= 3 && t <= 127) ? trl::L("保留(管理消息扩展)") : trl::L("保留");
    }
}

// 信息单元类型(表215):0 站点属性信息 / 1 站点路由信息 / 2 邻居节点信道信息非位图版 / 3 邻居节点信道信息位图版
static QString rf_info_unit_type_name(quint8 t) {
    switch (t) {
        case 0: return trl::L("站点属性信息");
        case 1: return trl::L("站点路由信息");
        case 2: return trl::L("邻居节点信道信息非位图版");
        case 3: return trl::L("邻居节点信道信息位图版");
        default: return trl::L("保留");
    }
}

// 无线发现列表报文(表214):站点MAC(0,0,48) + 统计序号(6,0,8) + 信息单元序列
// 信息单元:类型 7b + 长度类型 1b(0=长度1B/1=长度2B) + 长度 + 内容(可变)
static void parse_rf_discover_list(MsduInfo& out, const QByteArray& msdu, int rel_base) {
    if (msdu.size() < 7) {
        pa::warn("nw_2026:truncated", QStringLiteral("RF discover list %1B<7B").arg(msdu.size()));
        append_summary(out, trl::L(" (无线发现节点列表截断)"));
        return;
    }
    MsduFieldNode& dl = group(out.tree, QStringLiteral("RF DiscoverNodeList"));
    dl.rel_start = rel_base; dl.rel_len = msdu.size();
    {
        const quint64 mac = get_bits(msdu, 0, 0, 48);
        MsduFieldNode& m = group(dl.children, QStringLiteral("StationMAC"), mac_str(mac));
        m.rel_start = rel_base + 0; m.rel_len = 6;
        MsduFieldNode& sq = group(dl.children, QStringLiteral("SeqNum"),
            QString::number(get_bits(msdu, 6, 0, 8)));
        sq.rel_start = rel_base + 6; sq.rel_len = 1;
    }
    int off = 7;
    int idx = 0;
    while (off < msdu.size()) {
        const quint8 type7   = (quint8)get_bits(msdu, off, 0, 7);
        const bool  len2     = (get_bits(msdu, off, 7, 1) != 0);
        int len = 0, content_start = off + 1;
        if (!len2) {
            if (off + 2 > msdu.size()) { pa::warn("nw_2026:ie_overflow", QStringLiteral("IE hdr @%1 exceeds %2").arg(off).arg(msdu.size())); break; }
            len = (quint8)msdu[off + 1];
            content_start = off + 2;
        } else {
            if (off + 3 > msdu.size()) { pa::warn("nw_2026:ie_overflow", QStringLiteral("IE hdr(2B) @%1 exceeds %2").arg(off).arg(msdu.size())); break; }
            len = (int)((quint16)(quint8)msdu[off + 1] | ((quint16)(quint8)msdu[off + 2] << 8));
            content_start = off + 3;
        }
        if (content_start + len > msdu.size()) { pa::warn("nw_2026:ie_overflow", QStringLiteral("IE type=%1 len=%2 exceeds remaining %3").arg(type7).arg(len).arg(msdu.size()-content_start)); break; }
        auto& g = group(dl.children,
            QStringLiteral("InfoUnit[%1] (%2 - %3)")
                .arg(idx).arg(type7).arg(rf_info_unit_type_name(type7)));
        g.rel_start = rel_base + off; g.rel_len = (content_start + len) - off;
        MsduFieldNode& lt = group(g.children, QStringLiteral("LengthType"),
            len2 ? QStringLiteral("1 - %1").arg(trl::L("2字节长度"))
                 : QStringLiteral("0 - %1").arg(trl::L("1字节长度")));
        lt.rel_start = rel_base + off; lt.rel_len = 1;
        MsduFieldNode& ld = group(g.children, QStringLiteral("Length"), QString::number(len));
        ld.rel_start = rel_base + off + 1; ld.rel_len = len2 ? 2 : 1;
        // 信息单元内容按类型(表215)结构化解析;未知类型保留 hex
        const QByteArray content = msdu.mid(content_start, len);
        switch (type7) {
            case 0:  parse_sta_attr_info(g.children, content, rel_base + content_start,
                                          &out.topo_event); break;
            case 1:  parse_sta_route_info(g.children, content, rel_base + content_start); break;
            case 2:  parse_channel_non_bitmap(g.children, content, rel_base + content_start,
                                              &out.topo_event.rssi_entries,
                                              &out.topo_event.neighbor_rates,
                                              &out.topo_event.neighbor_snrs); break;
            case 3:  parse_channel_bitmap(g.children, content, rel_base + content_start,
                                          &out.topo_event.rssi_entries,
                                          &out.topo_event.neighbor_rates,
                                          &out.topo_event.neighbor_snrs); break;
            default: {
                pa::warn("nw_2026:unknown_ie", QStringLiteral("IE type=%1 len=%2 (hex fallback)").arg(type7).arg(len));
                MsduFieldNode& ct = group(g.children, QStringLiteral("Content [%1 B]").arg(len),
                    QString::fromLatin1(content.toHex(' ').toUpper()));
                ct.rel_start = rel_base + content_start; ct.rel_len = len;
                break;
            }
        }
        off = content_start + len;
        ++idx;
    }
    append_summary(out, trl::L("无线发现节点列表 (%1 个信息单元)").arg(idx));
}

// 单跳帧协议(版本==2)整帧解析:4B 帧头 + MSDU(按表114 类型分派) + 帧尾 CRC32
static void parse_single_hop(MsduInfo& out, const QByteArray& body) {
    out.simple_head = true;   // 单跳帧标志(GW 同语义):供帧列表 Orig 列等 UI 跳过 TEI 语义
    const quint8* p = reinterpret_cast<const quint8*>(body.constData());
    const quint8  msdu_type = (quint8)get_bits(p, 1, 0, 8);
    const quint16 msdu_len  = (quint16)get_bits(p, 2, 0, 16);
    out.msdu_type = msdu_type;
    // 单跳 MAC 帧头(表113,4B)
    MsduFieldNode& mh = group(out.tree, QStringLiteral("MAC Header [4B]"));
    mh.rel_start = 0; mh.rel_len = 4;
    add_fields(mh.children, body, 0, kSingleHopHeaderSpec, kSingleHopHeaderSpecN, 0);
    translate_enum_i18n(mh.children, "Version", kMacVersionZh, 4);
    // MSDU 类型(表114)释义:值含 128(IPv4),不适合字典索引,手动替换
    for (auto& n : mh.children) {
        if (n.name.startsWith(QLatin1String("MSDU Type")))
            n.value = QStringLiteral("%1 - %2").arg(msdu_type).arg(singlehop_msdu_type_name(msdu_type));
    }
    annotate_unit(mh.children, "MSDULength", QStringLiteral(" B"));

    if (body.size() < 4 + msdu_len) {
        pa::warn("nw_2026:truncated", QStringLiteral("single-hop body %1B < 4+len %2").arg(body.size()).arg(4+msdu_len));
        append_summary(out, trl::L(" (截断)"));
        append_msdu_crc(out, body, 4, msdu_len);
        out.present = true;
        return;
    }
    const QByteArray msdu_body = body.mid(4, msdu_len);
    out.total_len = 4 + msdu_len + 4;
    switch (msdu_type) {
        case 1:    // 应用层报文:载荷即业务报文(APP_BASE 4B + 业务报文头 8B)
            parse_app(out, msdu_body, 4, msdu_type);
            break;
        case 2:    // 无线发现列表消息(表214)
            parse_rf_discover_list(out, msdu_body, 4);
            break;
        case 128:  // IPv4 报文
            append_summary(out, trl::L("IPv4"));
            append_payload_hex(out, msdu_body, 0, -1, QStringLiteral("IPv4 Payload"), 4);
            break;
        default:   // 保留/管理消息扩展:原始 hex 展示
            append_summary(out, QStringLiteral(" (%1)").arg(singlehop_msdu_type_name(msdu_type)));
            append_payload_hex(out, msdu_body, 0, -1, QStringLiteral("MSDU Payload"), 4);
            break;
    }
    append_msdu_crc(out, body, 4, msdu_len);
    out.present = true;
}

}  // namespace

MsduInfo NW_2026_MsduParser::parse(const QByteArray& body) {
    MsduInfo out;
    if (body.size() < 4) { pa::warn("nw_2026:content_short", QStringLiteral("body %1B<4B").arg(body.size())); return out; }
    const quint8* p = reinterpret_cast<const quint8*>(body.constData());

    // 帧类型:Version 字段(bit1-2)。表6:1=本标准协议,0/3 保留,2=单跳帧协议。
    // 单跳帧协议(第2部分无线 §8.1.2.4 表113,仅无线信道)使用专用 4B 帧头,
    // 无 TEI/SNID/路由字段;此前按"保留版本回退标准头"会错位 8B 误解析,现独立处理。
    // 版本 0/3(保留)仍回退按标准头解析(表6 未定义其布局,按用户决策保持)。
    if ((quint8)get_bits(p, 0, 1, 2) == 2) {
        parse_single_hop(out, body);
        return out;
    }

    // 标准 MAC 帧头 MSDU_BASE:MACHeadFlag(0,0,1) 决定长(32B)/短(12B)
    // 短头至少 12 字节(读到 msdu_seq 在 byte 10-11),不足则无法解析。
    if (body.size() < 12) { pa::warn("nw_2026:content_short", QStringLiteral("body %1B<12B (short MAC hdr)").arg(body.size())); return out; }
    const quint8 mac_head_flag = (quint8)get_bits(p, 0, 0, 1);
    const quint16 msdu_len     = (quint16)get_bits(p, 2, 0, 16);

    out.msdu_dst_tei        = (int)get_bits(p, 4, 0, 12);
    out.msdu_src_tei        = (int)get_bits(p, 5, 4, 12);
    out.restart_count       = (quint8)get_bits(p, 7, 4, 4);
    out.route_hops_left     = (quint8)get_bits(p, 8, 0, 4);   // 路由跳数(表3 byte8 bit0-3)
    out.broadcast_direction = (quint8)get_bits(p, 8, 4, 4);
    out.msdu_send_type      = (int)get_bits(p, 9, 0, 3);
    out.msdu_seq            = (quint16)get_bits(p, 10, 0, 16);

    const int mac_hdr_len = (mac_head_flag == static_cast<quint8>(NW_2026_MacHeadFlag::LONG_HEAD)) ? 32 : 12;

    // MAC 帧头字段树(byte 0..mac_hdr_len-1):公共字段 + 长头目的 MAC/保留。
    // 此前 HeaderType/Version/SNID/路由跳数/发送次数限值/目的 MAC/保留均未
    // 进字段树(只作列表标量或分支判断),现补齐,保留位按 RSV 展示。
    {
        MsduFieldNode& mh = group(out.tree,
            QStringLiteral("MAC Header [%1B]").arg(mac_hdr_len));
        mh.rel_start = 0;
        mh.rel_len = mac_hdr_len;
        add_fields(mh.children, body, 0, kMacHeaderSpec, kMacHeaderSpecN, 0);
        translate_enum_i18n(mh.children, "HeaderType", kHeaderTypeZh, 2);
        translate_enum_i18n(mh.children, "Version", kMacVersionZh, 4);
        translate_enum_i18n(mh.children, "SendType", kSendTypeZh, 5);
        translate_enum_i18n(mh.children, "BroadcastDir", kBroadcastDirZh, 4);
        annotate_unit(mh.children, "MSDULength", QStringLiteral(" B"));
        if (mac_head_flag == static_cast<quint8>(NW_2026_MacHeadFlag::LONG_HEAD)) {
            add_fields(mh.children, body, 0, kMacLongHeaderSpec, kMacLongHeaderSpecN, 0);
            // 80-bit 保留(byte 22-31):get_bits 仅支持 ≤64bit,hex dump 展示
            if (body.size() >= 32) {
                MsduFieldNode& rsv2 = group(mh.children, QStringLiteral("RSV2 [80b]"),
                    QString::fromLatin1(body.mid(22, 10).toHex(' ').toUpper()));
                rsv2.rel_start = 22; rsv2.rel_len = 10;
            }
        }
    }

    if (body.size() < mac_hdr_len + msdu_len) { pa::warn("nw_2026:truncated", QStringLiteral("body %1B < hdr %2+len %3").arg(body.size()).arg(mac_hdr_len).arg(msdu_len)); return out; }
    const QByteArray msdu_body = body.mid(mac_hdr_len, msdu_len);
    out.total_len = mac_hdr_len + msdu_len + 4;

    // MSDU 帧头(长 18B / 短 2B,由 MACHeadFlag 决定)
    if (mac_head_flag == static_cast<quint8>(NW_2026_MacHeadFlag::LONG_HEAD)) {
        // MSDU_LONGHEAD(18B):原始目的/源 MAC 48b + VLAN 32b + MSDU 类型 16b
        if (msdu_body.size() >= 18) {
            const quint8* q = reinterpret_cast<const quint8*>(msdu_body.constData());
            out.msdu_dst_mac = get_bits(q, 0, 0, 48);
            out.msdu_src_mac = get_bits(q, 6, 0, 48);
            out.vlan_tag     = (quint32)get_bits(q, 12, 0, 32);
            out.msdu_type    = (quint16)get_bits(q, 16, 0, 16);
            // MSDU 长帧头前段字段(表1/表41:原始目的/源地址 + VLAN 标签;此前仅入标量、树上缺失)
            {
                MsduFieldNode dm;
                dm.name = QStringLiteral("Original Dst MAC [48b]");
                dm.value = mac_str(out.msdu_dst_mac);
                dm.rel_start = mac_hdr_len + 0;   // 原始目的地址在 msdu_body[0..5]
                dm.rel_len   = 6;
                out.tree.append(dm);
                MsduFieldNode sm;
                sm.name = QStringLiteral("Original Src MAC [48b]");
                sm.value = mac_str(out.msdu_src_mac);
                sm.rel_start = mac_hdr_len + 6;   // 原始源地址在 msdu_body[6..11]
                sm.rel_len   = 6;
                out.tree.append(sm);
                MsduFieldNode vt;
                vt.name = QStringLiteral("VLAN Tag [32b]");
                vt.value = vlan_tag_value(out.vlan_tag, out.msdu_type, 8);
                vt.rel_start = mac_hdr_len + 12;  // VLAN 标签在 msdu_body[12..15]
                vt.rel_len   = 4;
                out.tree.append(vt);
            }
            // MSDU 类型字段(表1:0x01 应用层报文 / 0x88E1 管理消息)
            {
                MsduFieldNode mt;
                mt.name = QStringLiteral("MSDU Type [16b]");
                const QString tn = (out.msdu_type == static_cast<quint16>(NW_2026_MsduType::MANAGEMENT_MESSAGE)) ? trl::L("管理消息报文")
                                 : (out.msdu_type == static_cast<quint16>(NW_2026_MsduType::APPLICATION_PACKET)) ? trl::L("应用层报文")
                                 : trl::L("保留");
                mt.value = QStringLiteral("0x%1 - %2")
                               .arg(out.msdu_type, 4, 16, QChar('0')).arg(tn);
                mt.rel_start = mac_hdr_len + 16;   // MSDU 类型在 msdu_body[16..17]
                mt.rel_len   = 2;
                out.tree.append(mt);
            }
            // VLAN 0x8100 + MSDU类型 0x88E1 = 长帧头管理消息(MMe,表98/8.2.13 双条件);否则抄表业务(APP)
            if (out.vlan_tag == static_cast<quint32>(NW_2026_VlanTag::MANAGEMENT)
                && out.msdu_type == static_cast<quint16>(NW_2026_MsduType::MANAGEMENT_MESSAGE)) {
                const QByteArray mme = msdu_body.mid(18);   // MMe 数据(帧头 18B 之后)
                // MMe 头相对重组块体(msdu_body[0])的字节偏移:MAC 帧头 mac_hdr_len + MSDU 帧头 18
                // (add_fields 的 rel_start 基准须对齐 tree_msdu_raw_of 的重组块体起点)
                const int mme_rel_base = mac_hdr_len + 18;
                append_mme_header(out, mme, mme_rel_base);
                const quint16 mm_type = out.mme_type;
                const quint8 mme_version = mme.isEmpty() ? 0 : (quint8)mme[0];
                if (!mme.isEmpty() && mme_version != 1)
                    append_summary(out, trl::L(" (不支持的 MMe 版本 %1)").arg(mme_version));
                if (mme.size() < 6) {
                    append_summary(out, trl::L(" (截断)"));
                } else if (mme_version == 1) {
                    if (!mme_body_complete(mme, static_cast<NW_2026_MMeType>(mm_type))) {
                        append_summary(out, trl::L(" (截断)"));
                    } else {
                    // 位图版代理变更确认:本体(至位图末尾,共 145B)完整即可解析;
                    // 尾部保留/端到端/路径序列号(至 154B)缺失时警告,不按截断处理
                    if (mm_type == static_cast<quint16>(NW_2026_MMeType::MME_CHANGEPROXYBITMAPCNF)
                        && mme.size() < 154)
                        append_summary(out, trl::L(" (字段缺失)"));
                    switch (static_cast<NW_2026_MMeType>(mm_type)) {
        case NW_2026_MMeType::MME_ASSOCREQ: {
            add_fields(out.tree, mme, 6, kMMeAssocReqSpec, kMMeAssocReqSpecN, mme_rel_base);
            // 拓扑事件:关联请求(STA 正在入网;TEI 未分配,用 tei=0 承载 MAC)
            {
                const quint64 sta_mac = get_bits(mme, 6, 0, 48);
                out.sta_mac = sta_mac;   // 报文体主体 STA MAC(STAMACAddr;MSDU Type 列展示)
                out.topo_event.kind = TopoEventKind::AssocReq;
                out.topo_event.nodes.append({0, sta_mac});
                out.topo_event.module_type = (quint8)get_bits(mme, 29, 0, 2);   // 表84 模块类型(体 byte23 bit0-1→mme 偏移29)
                // 关联请求由 STA 本人发出:MSDU 头重启次数即该 STA 的,
                // TopoState 据此检测 STA 重启(单跳帧无此字段,0xFF 不填)
                if (out.restart_count != kRestartCountInvalid)
                    out.topo_event.restart_count = (int)out.restart_count;
                out.topo_event.desc = trl::L("关联请求: STA %1 正在入网")
                    .arg(mac_str(sta_mac));
            }
            // 厂家附加数据(报文体 byte 28-45)与版本信息(46-55)按布局顺序渲染,
            // 尾段(56-67)排在其后,字段树顺序与报文字节序一致
            if (mme.size() >= 52) {
                MsduFieldNode& info = group(out.tree, QStringLiteral("ManufacturerInfo [144b]"),
                    QString::fromLatin1(mme.mid(34, 18).toHex(' ').toUpper()));
                info.rel_start = mme_rel_base + (34); info.rel_len = 18;
            }
            if (mme.size() >= 62) {
                add_fields(out.tree, mme, 52, kAssocReqSTAVerSpec, kAssocReqSTAVerSpecN, mme_rel_base);
                // 版本区表示法(表47):BOOT/软件版本号为 BCD 码,厂商/芯片代码为 ASCII 码;
                // 仅当数据符合对应编码时才换算呈现,否则保留原始数值
                if (MsduFieldNode* n = find_field_node(out.tree, "BootVersion")) {
                    const quint8 v = (quint8)mme[53];
                    if ((v >> 4) <= 9 && (v & 0x0F) <= 9)
                        n->value = QStringLiteral("%1%2").arg(v >> 4).arg(v & 0x0F);
                }
                if (MsduFieldNode* n = find_field_node(out.tree, "SoftwareVersion")) {
                    const quint8 hi = (quint8)mme[54], lo = (quint8)mme[55];
                    if ((hi >> 4) <= 9 && (hi & 0x0F) <= 9 && (lo >> 4) <= 9 && (lo & 0x0F) <= 9)
                        n->value = QStringLiteral("%1%2%3%4")
                            .arg(hi >> 4).arg(hi & 0x0F).arg(lo >> 4).arg(lo & 0x0F);
                }
                const auto ascii_code = [&](const char* name, int abs) {
                    const quint8 c0 = (quint8)mme[abs], c1 = (quint8)mme[abs + 1];
                    if (c0 >= 0x20 && c0 < 0x7F && c1 >= 0x20 && c1 < 0x7F) {
                        if (MsduFieldNode* n = find_field_node(out.tree, name))
                            n->value = QString::fromLatin1(mme.constData() + abs, 2);
                    }
                };
                ascii_code("ManufacturerID", 58);
                ascii_code("ChipID", 60);
                translate_enum_i18n(out.tree, "BootReason", kBootReasonZh, 1);
            }
            add_fields(out.tree, mme, 6, kMMeAssocReqTailSpec, kMMeAssocReqTailSpecN, mme_rel_base);
            translate_enum_i18n(out.tree, "LinePhase0", kLinePhaseZh, 4);
            translate_enum_i18n(out.tree, "CandidateLinePhase1", kLinePhaseZh, 4);
            translate_enum_i18n(out.tree, "CandidateLinePhase2", kLinePhaseZh, 4);
            translate_enum_i18n(out.tree, "DeviceType", kDeviceTypeZh, 8);
            translate_enum_i18n(out.tree, "MACAddrType", kMACAddrTypeZh, 3);
            translate_enum_i18n(out.tree, "ProxyType", kProxyTypeZh, 3);
            translate_enum_i18n(out.tree, "BandSupport", kBandSupportZh, 2);
            // 新一代字段释义(SPLC 数据链路层:模块类型/候选代理链路类型/PLC能力/通道数/扩展特性)
            translate_enum_i18n(out.tree, "ModuleType", kModuleTypeZh, 3);
            translate_enum_i18n(out.tree, "LinkType0", kLinkTypeZh, 2);
            translate_enum_i18n(out.tree, "LinkType1", kLinkTypeZh, 2);
            translate_enum_i18n(out.tree, "LinkType2", kLinkTypeZh, 2);
            translate_enum_i18n(out.tree, "LinkType3", kLinkTypeZh, 2);
            translate_enum_i18n(out.tree, "LinkType4", kLinkTypeZh, 2);
            translate_enum_i18n(out.tree, "PLCCapInd", kPLCCapZh, 2);
            translate_enum_i18n(out.tree, "ChannelNum", kChannelNumZh, 2);
            translate_enum_i18n(out.tree, "ExtFeatureFlag", kExtFeatureZh, 2);
            break;
        }
        case NW_2026_MMeType::MME_ASSOCCNF: {
            add_fields(out.tree, mme, 6, kMMeAssocCnfSpec, kMMeAssocCnfSpecN, mme_rel_base);
            // 拓扑:帧内链路类型(表79:0=高速载波链路 1=无线链路)——接入方式判定用
            out.topo_event.link_type = (int)get_bits(mme, 21, 0, 1);   // spec byte15 为相对 MMe 体,含 6B 头 → mme[21]
            translate_enum_i18n(out.tree, "LinkType", kLinkTypeZh, 2);
            // 拓扑事件:关联确认(STA 入网 + 代理);仅成功(0=成功,0x0A=再次入网成功)时更新拓扑
            {
                const quint8 assoc_res = (quint8)get_bits(mme, 12, 0, 8);
                const quint64 sta_mac = get_bits(mme, 6, 0, 48);
                out.sta_mac = sta_mac;   // 报文体主体 STA MAC(STAMACAddr)
                const quint16 sta_tei = (quint16)get_bits(mme, 14, 0, 12);
                const quint16 proxy_tei = (quint16)get_bits(mme, 16, 0, 16);
                if (assoc_res == 0 || assoc_res == 0x0A) {
                out.topo_event.kind = TopoEventKind::AssocCnf;
                if (sta_tei && sta_mac) out.topo_event.nodes.append({sta_tei, sta_mac});
                if (sta_tei && proxy_tei) out.topo_event.routes.append({sta_tei, proxy_tei});
                out.topo_event.desc = trl::L("关联确认: STA TEI=%1 入网 代理=%2")
                    .arg(sta_tei)
                    .arg(proxy_tei ? QString::number(proxy_tei) : QStringLiteral("-"));
                }
            }
            translate_enum_i18n(out.tree, "AssocResult", kAssocCnfResultZh, 14);
            translate_enum_i18n(out.tree, "LastPacketFlag", kLastPacketFlagZh, 2);
            translate_enum_i18n(out.tree, "DetectBandFlag", kDetectBandFlagZh, 2);
            translate_enum_i18n(out.tree, "CarrierFreq", kCarrierFreqZh, 8);
            annotate_unit(out.tree, "STAReAssocTime", QStringLiteral("ms"));
            const int rb = 42;
            if (mme.size() >= rb + 8) {
                // 路由表信息(表55/56)整体为一个字段:头部计数与条目同组呈现
                MsduFieldNode& rg = group(out.tree, QStringLiteral("RouteInfoTable"));
                rg.rel_start = mme_rel_base + rb;
                add_fields(rg.children, mme, rb, kRouteInfoHeadSpec, kRouteInfoHeadSpecN, mme_rel_base);
                const quint16 sta_sum = (quint16)get_bits(mme, rb, 0, 16);
                const quint16 pco_sum = (quint16)get_bits(mme, rb + 2, 0, 16);
                int off = rb + 8;
                for (int i = 0; i < sta_sum && off + 2 <= mme.size(); ++i) {
                    const quint16 sta_tei = (quint16)get_bits(mme, off, 0, 12);
                    out.topo_event.node_link_types.append({sta_tei, (quint8)get_bits(mme, off + 1, 4, 1)});
                    MsduFieldNode& n = group(rg.children, QStringLiteral("StraightSTA[%1]").arg(i));
                    n.rel_start = mme_rel_base + (off); n.rel_len = 2;
                    add_fields(n.children, mme, off, kSTATEISpec, kSTATEISpecN, mme_rel_base);
                    off += 2;
                }
                for (int i = 0; i < pco_sum && off + 4 <= mme.size(); ++i) {
                    const quint16 pco_tei = (quint16)get_bits(mme, off, 0, 12);
                    out.topo_event.node_link_types.append({pco_tei, (quint8)get_bits(mme, off + 1, 4, 1)});
                    MsduFieldNode& n = group(rg.children, QStringLiteral("StraightPCO[%1]").arg(i));
                    n.rel_start = mme_rel_base + (off); n.rel_len = 4;
                    add_fields(n.children, mme, off, kStraightPCOSpec, kStraightPCOSpecN, mme_rel_base);
                    const quint16 child_sum = (quint16)get_bits(mme, off + 2, 0, 16);
                    int coff = off + 4;
                    for (int c = 0; c < child_sum && coff + 2 <= mme.size(); ++c) {
                        MsduFieldNode& cn = group(n.children, QStringLiteral("Child[%1]").arg(c));
                        cn.rel_start = mme_rel_base + (coff); cn.rel_len = 2;
                        add_fields(cn.children, mme, coff, kSTATEISpec, kSTATEISpecN, mme_rel_base);
                        coff += 2;
                    }
                    off = coff;
                }
                rg.rel_len = off - rb;
            }
            break;
        }
        case NW_2026_MMeType::MME_CHANGEPROXYREQ: {
            add_fields(out.tree, mme, 6, kMMeChangeProxyReqSpec, kMMeChangeProxyReqSpecN, mme_rel_base);
            // 拓扑事件:代理变更请求(仅记录入表,不更新拓扑;待确认后更新)
            {
                const quint16 sta_tei = (quint16)get_bits(mme, 6, 0, 16);
                const quint16 new_proxy = (quint16)get_bits(mme, 8, 0, 12);
                const quint16 old_proxy = (quint16)get_bits(mme, 18, 0, 16);
                if (sta_tei) {
                    out.topo_event.kind = TopoEventKind::ChangeProxyReq;
                    // 报文体仅携带主体 TEI(STATEI)无 MAC:填 nodes{TEI,0},
                    // 渲染层按 TEI≠本跳源 TEI 判代理转发,并自 TEI→MAC 映射表补 MAC
                    out.topo_event.nodes.append({sta_tei, 0});
                    out.topo_event.desc = trl::L("代理变更请求: STA TEI=%1 %2→%3")
                        .arg(sta_tei)
                        .arg(old_proxy ? QString::number(old_proxy) : QStringLiteral("-"))
                        .arg(new_proxy ? QString::number(new_proxy) : QStringLiteral("-"));
                }
            }
            translate_enum_i18n(out.tree, "ProxyType", kProxyTypeZh, 3);
            translate_enum_i18n(out.tree, "Reason", kProxyChangeReasonZh, 3);
            translate_enum_i18n(out.tree, "LinePhase0", kLinePhaseZh, 4);
            translate_enum_i18n(out.tree, "CandidateLinePhase1", kLinePhaseZh, 4);
            translate_enum_i18n(out.tree, "CandidateLinePhase2", kLinePhaseZh, 4);
            break;
        }
        case NW_2026_MMeType::MME_ASSOCIND: {
            add_fields(out.tree, mme, 6, kMMeAssocIndSpec, kMMeAssocIndSpecN, mme_rel_base);
            // 拓扑:帧内链路类型(表79:0=高速载波链路 1=无线链路)——接入方式判定用
            out.topo_event.link_type = (int)get_bits(mme, 24, 0, 1);   // spec byte18 为相对 MMe 体,含 6B 头 → mme[24]
            translate_enum_i18n(out.tree, "LinkType", kLinkTypeZh, 2);
            // 拓扑事件:关联指示(语义等同关联确认);仅成功(0=成功,0x0A=再次入网)时更新拓扑
            {
                const quint8 assoc_res = (quint8)get_bits(mme, 6, 0, 8);
                const quint64 sta_mac = get_bits(mme, 8, 0, 48);
                out.sta_mac = sta_mac;   // 报文体主体 STA MAC(STAMACAddr;不分成败)
                if (assoc_res == 0 || assoc_res == 0x0A) {
                    const quint64 cco_mac = get_bits(mme, 14, 0, 48);
                    const quint16 sta_tei = (quint16)get_bits(mme, 20, 0, 12);
                    const quint16 proxy_tei = (quint16)get_bits(mme, 22, 0, 16);
                    out.topo_event.kind = TopoEventKind::AssocInd;
                    if (cco_mac) out.topo_event.cco_mac = cco_mac;
                    if (sta_tei && sta_mac) out.topo_event.nodes.append({sta_tei, sta_mac});
                    if (sta_tei && proxy_tei) out.topo_event.routes.append({sta_tei, proxy_tei});
                    out.topo_event.desc = trl::L("关联指示: STA TEI=%1 入网 代理=%2")
                        .arg(sta_tei)
                        .arg(proxy_tei ? QString::number(proxy_tei) : QStringLiteral("-"));
                }
            }
            translate_enum_i18n(out.tree, "AssocResult", kAssocIndResultZh, 14);
            translate_enum_i18n(out.tree, "LastPacketFlag", kLastPacketFlagZh, 2);
            translate_enum_i18n(out.tree, "CarrierFreq", kCarrierFreqZh, 8);
            annotate_unit(out.tree, "STAReAssocTime", QStringLiteral("ms"));
            const int rb = 70;
            if (mme.size() >= rb + 8) {
                // 路由表信息整体为一个字段:头部计数与条目同组呈现(与 AssocCnf 一致)
                MsduFieldNode& rg = group(out.tree, QStringLiteral("RouteInfoTable"));
                rg.rel_start = mme_rel_base + rb;
                add_fields(rg.children, mme, rb, kRouteInfoHeadSpec, kRouteInfoHeadSpecN, mme_rel_base);
                const quint16 sta_sum = (quint16)get_bits(mme, rb, 0, 16);
                const quint16 pco_sum = (quint16)get_bits(mme, rb + 2, 0, 16);
                int off = rb + 8;
                for (int i = 0; i < sta_sum && off + 2 <= mme.size(); ++i) {
                    const quint16 sta_tei = (quint16)get_bits(mme, off, 0, 12);
                    out.topo_event.node_link_types.append({sta_tei, (quint8)get_bits(mme, off + 1, 4, 1)});
                    MsduFieldNode& n = group(rg.children, QStringLiteral("StraightSTA[%1]").arg(i));
                    n.rel_start = mme_rel_base + (off); n.rel_len = 2;
                    add_fields(n.children, mme, off, kSTATEISpec, kSTATEISpecN, mme_rel_base);
                    off += 2;
                }
                for (int i = 0; i < pco_sum && off + 4 <= mme.size(); ++i) {
                    const quint16 pco_tei = (quint16)get_bits(mme, off, 0, 12);
                    out.topo_event.node_link_types.append({pco_tei, (quint8)get_bits(mme, off + 1, 4, 1)});
                    MsduFieldNode& n = group(rg.children, QStringLiteral("StraightPCO[%1]").arg(i));
                    n.rel_start = mme_rel_base + (off); n.rel_len = 4;
                    add_fields(n.children, mme, off, kStraightPCOSpec, kStraightPCOSpecN, mme_rel_base);
                    const quint16 child_sum = (quint16)get_bits(mme, off + 2, 0, 16);
                    int coff = off + 4;
                    for (int c = 0; c < child_sum && coff + 2 <= mme.size(); ++c) {
                        MsduFieldNode& cn = group(n.children, QStringLiteral("Child[%1]").arg(c));
                        cn.rel_start = mme_rel_base + (coff); cn.rel_len = 2;
                        add_fields(cn.children, mme, coff, kSTATEISpec, kSTATEISpecN, mme_rel_base);
                        coff += 2;
                    }
                    off = coff;
                }
                rg.rel_len = off - rb;
            }
            break;
        }
        case NW_2026_MMeType::MME_CHANGEPROXYCNF: {
            add_fields(out.tree, mme, 6, kMMeChangeProxyCnfSpec, kMMeChangeProxyCnfSpecN, mme_rel_base);
            // 拓扑事件:代理变更确认(STA 换代理);仅 Result=0(变更成功)时更新拓扑
            {
                const quint32 pres = (quint32)get_bits(mme, 6, 0, 32);
                const quint16 sta_tei = (quint16)get_bits(mme, 12, 0, 16);
                const quint16 proxy_tei = (quint16)get_bits(mme, 14, 0, 16);
                if (pres == 0) {
                out.topo_event.kind = TopoEventKind::ChangeProxyCnf;
                if (mme.size() > 20)
                    out.topo_event.link_type = (int)get_bits(mme, 20, 0, 1);  // SPLC 表108 byte14 bit0(0-based)
                if (sta_tei) out.topo_event.nodes.append({sta_tei, 0});   // 主体 TEI(STATEI)无 MAC
                if (sta_tei && proxy_tei) out.topo_event.routes.append({sta_tei, proxy_tei});
                out.topo_event.desc = trl::L("代理变更: STA TEI=%1 代理→%2")
                    .arg(sta_tei)
                    .arg(proxy_tei ? QString::number(proxy_tei) : QStringLiteral("-"));
                }
            }
            translate_enum_i18n(out.tree, "LinkType", kLinkTypeZh, 2);
            translate_enum_i18n(out.tree, "Result", kProxyChangeResultZh, 1);
            const quint16 child_sum = (quint16)get_bits(mme, 16, 0, 16);
            int off = 38;
            for (int i = 0; i < child_sum && off + 2 <= mme.size(); ++i) {
                MsduFieldNode& n = group(out.tree, QStringLiteral("ChildSTA[%1]").arg(i));
                n.rel_start = mme_rel_base + (off); n.rel_len = 2;
                add_fields(n.children, mme, off, kSTATEISpec, kSTATEISpecN, mme_rel_base);
                off += 2;
            }
            break;
        }
        case NW_2026_MMeType::MME_ASSOCGATHERIND: {
            add_fields(out.tree, mme, 6, kMMeAssocGatherIndSpec, kMMeAssocGatherIndSpecN, mme_rel_base);
            // 拓扑:帧内链路类型(表79:0=高速载波链路 1=无线链路)——接入方式判定用
            out.topo_event.link_type = (int)get_bits(mme, 18, 0, 1);   // spec byte12 为相对 MMe 体,含 6B 头 → mme[18]
            translate_enum_i18n(out.tree, "LinkType", kLinkTypeZh, 2);
            translate_enum_i18n(out.tree, "AssocResult", kAssocGatherResultZh, 1);
            translate_enum_i18n(out.tree, "CarrierFreq", kCarrierFreqZh, 8);
            const quint8 sta_num = (quint8)get_bits(mme, 17, 0, 8);
            int off = 34;  // 消息体 byte 28(MMeHeadSize 6 + 28),RSV0(15B) 之后
            // 拓扑事件:关联汇总(批量站点入网 + 代理);仅 AssocResult=0(允许加入网络)时更新拓扑
            const quint8 gar = (quint8)get_bits(mme, 6, 0, 8);
            const quint16 gproxy_tei = (quint16)get_bits(mme, 14, 0, 12);
            const bool g_ok = (gar == 0);
            if (g_ok) {
                const quint64 gcco_mac = get_bits(mme, 8, 0, 48);
                out.topo_event.kind = TopoEventKind::AssocGatherInd;
                if (gcco_mac) out.topo_event.cco_mac = gcco_mac;
                out.topo_event.desc = trl::L("关联汇总: %1 个站点入网 代理=%2")
                    .arg(sta_num)
                    .arg(gproxy_tei ? QString::number(gproxy_tei) : QStringLiteral("-"));
            }
            for (int i = 0; i < sta_num && off + 8 <= mme.size(); ++i) {
                if (g_ok) {
                    const quint64 gsta_mac = get_bits(mme, off, 0, 48);
                    const quint16 gsta_tei = (quint16)get_bits(mme, off + 6, 0, 12);
                    if (gsta_tei && gsta_mac) {
                        out.topo_event.nodes.append({gsta_tei, gsta_mac});
                        // 学习 TEI→MAC(SPLC 第4部分 表102/表103:条目 MAC 6B + TEI 12b;仅 g_ok 时学)
                        out.tei_mac_pairs.append({gsta_tei, gsta_mac});
                    }
                    if (gsta_tei && gproxy_tei) out.topo_event.routes.append({gsta_tei, gproxy_tei});
                }
                MsduFieldNode& n = group(out.tree, QStringLiteral("NewSTA[%1]").arg(i));
                n.rel_start = mme_rel_base + (off); n.rel_len = 8;
                add_fields(n.children, mme, off, kSTAInfoSpec, kSTAInfoSpecN, mme_rel_base);
                off += 8;
            }
            break;
        }
        case NW_2026_MMeType::MME_CHANGEPROXYBITMAPCNF: {
            add_fields(out.tree, mme, 6, kMMeChangeProxyBitMapCnfSpec, kMMeChangeProxyBitMapCnfSpecN, mme_rel_base);
            translate_enum_i18n(out.tree, "Result", kProxyChangeResultZh, 1);
            // 子站点位图(byte 9-138,130 字节):空字节不显示,非空字节按 bitmap[索引][8b] 显示
            if (mme.size() >= 145) {
                auto& bmg = group(out.tree, QStringLiteral("ChildSTA BitMap [130B]"));
                const int bm_base = 15;  // mme[15] = MMe头6B + 固定头9B(Result4+STATEI2+ProxyTEI2+NetSN1)
                // 组节点覆盖整个 bitmap 区域,点击高亮全部所属字节
                bmg.rel_start = mme_rel_base + bm_base; bmg.rel_len = 130;
                // 拓扑事件:批量代理变更确认;仅 Result=0(变更成功)时更新拓扑
                const quint32 bmres = (quint32)get_bits(mme, 6, 0, 32);
                const quint16 bmproxy_tei = (quint16)get_bits(mme, 12, 0, 16);
                const bool bm_ok = (bmres == 0);
                int bm_cnt = 0;
                if (bm_ok) out.topo_event.kind = TopoEventKind::ChangeProxyCnf;
                // 子站点位图逐位(仅 bit=1):绝对 TEI 位图,起始 TEI=0(文档:
                // "第0字节第1比特=1 表示 TEI 1;第1字节第0比特=1 表示 TEI 8"),
                // TEI = 字节号*8 + 位号,LSB 在前;值标注该 bit 所在的字节号
                for (int i = 0; i < 130; ++i) {
                    const quint8 byte = (quint8)mme[bm_base + i];
                    if (byte == 0) continue;   // 空字节不显示
                    for (int j = 0; j < 8; ++j) {
                        if (!(byte & (1u << j))) continue;
                        const quint16 ctei = (quint16)(8 * i + j);
                        if (bm_ok) out.topo_event.child_teis.append(ctei);   // 绝对 TEI 位图 bit0=TEI 0 合法,不跳过;仅成功才进子站点表   // 子站点表(TopoState 按链路类型更新接入方式)
                        if (bm_ok && ctei && bmproxy_tei) {
                            out.topo_event.routes.append({ctei, bmproxy_tei});
                            ++bm_cnt;
                        }
                        MsduFieldNode bn;
                        bn.name = trl::L("子站点 TEI=%1").arg(ctei);
                        bn.value = trl::L("在位图(第%1字节)").arg(i);
                        bn.rel_start = mme_rel_base + (bm_base + i); bn.rel_len = 1;
                        bmg.children.append(bn);
                    }
                }
                if (bm_ok) {
                    out.topo_event.desc = trl::L("代理变更(批量): %1 个站点代理→%2")
                        .arg(bm_cnt)
                        .arg(bmproxy_tei ? QString::number(bmproxy_tei) : QStringLiteral("-"));
                }
                // 帧内链路类型(SPLC 表111:byte139 bit0):仅 Result=0(成功)时用;尾段需存在才可读(get_bits 无越界检查)
                if (bm_ok && mme.size() > 145)
                    out.topo_event.link_type = (int)get_bits(mme, 145, 0, 1);   // spec byte139 为相对 MMe 体,含 6B 头 → mme[145]
            }
            // 尾段(保留 byte 139 + 端到端/路径序列号)排在位图块之后,与字节序一致
            add_fields(out.tree, mme, 6, kMMeChangeProxyBitMapCnfTailSpec, kMMeChangeProxyBitMapCnfTailSpecN, mme_rel_base);
            translate_enum_i18n(out.tree, "LinkType", kLinkTypeZh, 2);
            break;
        }
        case NW_2026_MMeType::MME_LEAVEIND: {
            add_fields(out.tree, mme, 6, kMMeLeaveIndSpec, kMMeLeaveIndSpecN, mme_rel_base);
            // 拓扑事件:离网指示(单 STA,按 TEI+MAC)
            {
                const quint16 leave_tei = (quint16)get_bits(mme, 6, 0, 16);
                const quint64 leave_mac = get_bits(mme, 10, 0, 48);
                out.sta_mac = leave_mac;   // 报文体主体 STA MAC(离网单 STA)
                out.topo_event.kind = TopoEventKind::LeaveInd;
                if (leave_tei && leave_mac) out.topo_event.nodes.append({leave_tei, leave_mac});
                if (leave_mac) out.topo_event.leaves.append(leave_mac);
                out.topo_event.desc = trl::L("离线指示: STA TEI=%1 离线").arg(leave_tei);
            }
            translate_enum_i18n(out.tree, "Reason", kLeaveReasonZh, 7);
            break;
        }
        case NW_2026_MMeType::MME_HEARTBEATCHECK: {
            add_fields(out.tree, mme, 6, kMMeHeartBeatCheckSpec, kMMeHeartBeatCheckSpecN, mme_rel_base);
            // 可发现站点 TEI 位图(byte 8-137,130B):空字节不显示,非空字节按 bitmap[索引][8b] 显示
            if (mme.size() >= 145) {
                auto& bmg = group(out.tree, QStringLiteral("DiscoverableSTA BitMap [130B]"));
                const int bm_base = 14;  // mme[14] = MMe头6B + 固定头8B(OSTEI2+DCTEI2+DCount4)
                bmg.rel_start = mme_rel_base + bm_base; bmg.rel_len = 130;
                // 可发现站点位图逐位(仅 bit=1):绝对 TEI 位图,起始 TEI=0,
                // TEI = 字节号*8 + 位号,LSB 在前;值标注该 bit 所在的字节号
                for (int i = 0; i < 130; ++i) {
                    const quint8 byte = (quint8)mme[bm_base + i];
                    if (byte == 0) continue;   // 空字节不显示
                    for (int j = 0; j < 8; ++j) {
                        if (!(byte & (1u << j))) continue;
                        MsduFieldNode bn;
                        bn.name = trl::L("可发现站点 TEI=%1").arg(8 * i + j);
                        bn.value = trl::L("在位图(第%1字节)").arg(i);
                        bn.rel_start = mme_rel_base + (bm_base + i); bn.rel_len = 1;
                        bmg.children.append(bn);
                    }
                }
                // 保留(byte 138,1B)
                MsduFieldNode rsv;
                rsv.name = QStringLiteral("RSV [8b]");
                rsv.value = QStringLiteral("0x%1").arg((quint8)mme[bm_base + 130], 2, 16, QChar('0'));
                rsv.rel_start = mme_rel_base + (bm_base + 130); rsv.rel_len = 1;
                out.tree.append(rsv);
            }
            break;
        }
        case NW_2026_MMeType::MME_DISCOVERNODELIST: {
            add_fields(out.tree, mme, 6, kMMeDiscoverNodeListSpec, kMMeDiscoverNodeListSpecN, mme_rel_base);
            // 拓扑事件:发现列表(STATEI/MAC/代理/层级) + TEI→MAC 学习对
            {
                const quint16 sta_tei = (quint16)get_bits(mme, 6, 0, 16);
                const quint64 sta_mac = get_bits(mme, 10, 0, 48);
                out.sta_mac = sta_mac;   // 报文体节点主体 MAC(MACAddr)
                const quint16 proxy_tei = (quint16)get_bits(mme, 16, 0, 16);
                if (sta_tei && sta_mac) {
                    out.tei_mac_pairs.append({sta_tei, sta_mac});
                    out.topo_event.nodes.append({sta_tei, sta_mac});
                }
                out.topo_event.kind = TopoEventKind::DiscoverList;
                // 南网 MAC 帧头重启次数(4-bit):TopoState 据此检测 CCO 重启;
                // 只有 CCO 本人发出(src_tei == kTeiCco)才采用,防 STA 中继转发误报;
                // 重启次数为哨兵 0xFF(未填)时不采用(保持 -1 未知)
                if (out.restart_count != kRestartCountInvalid && out.msdu_src_tei == kTeiCco)
                    out.topo_event.restart_count = (int)out.restart_count;
                // 发现列表由 CCO 广播:发送方即 CCO,填 cco_mac 保证拓扑图根节点
                // 创建(对齐国网 DiscoverList 填 cco_mac 的行为);中继转发的帧
                // 源 TEI 不是 1,不填,防误认
                if (out.msdu_src_tei == kTeiCco && out.msdu_src_mac)
                    out.topo_event.cco_mac = out.msdu_src_mac;
                if (sta_tei && proxy_tei) out.topo_event.routes.append({sta_tei, proxy_tei});
                // 发现列表携带该 STA 经代理的上下行成功率(表77 byte16-19/20-23,32bit,取值0-100,超出无效):
                // 填 proxy_comm_rate/proxy_down_comm_rate/min_comm_rate(独立于 0x005E comm_rates)。
                // 偏移:spec 相对 mme+6,ProxyCommRate@16/ProxyDownCommRate@20/MinCommRate@36 → mme 22/26/42
                {
                    const quint32 up_rate = (quint32)get_bits(mme, 22, 0, 32);
                    const quint32 down_rate = (quint32)get_bits(mme, 26, 0, 32);
                    const quint8  min_rate = (quint8)get_bits(mme, 42, 0, 8);
                    if (sta_tei) {
                        out.topo_event.proxy_comm_rate = (up_rate <= 100) ? (qint32)up_rate : -1;
                        out.topo_event.proxy_down_comm_rate = (down_rate <= 100) ? (qint32)down_rate : -1;
                        out.topo_event.min_comm_rate = (min_rate <= 100) ? (qint16)min_rate : -1;
                    }
                }
                out.topo_event.desc = trl::L("发现列表: STA TEI=%1 代理=%2")
                    .arg(sta_tei)
                    .arg(proxy_tei ? QString::number(proxy_tei) : QStringLiteral("-"));
            }
            // 值解释(对齐国网:Role/LinePhase/CommRateCalculateFinish 双语,成功率带 %)
            translate_enum_i18n(out.tree, "Role", kRoleZh, 5);
            translate_enum_i18n(out.tree, "CandidateLinePhase0", kLinePhaseZh, 4);
            translate_enum_i18n(out.tree, "CandidateLinePhase1", kLinePhaseZh, 4);
            translate_enum_i18n(out.tree, "CandidateLinePhase2", kLinePhaseZh, 4);
            translate_enum_i18n(out.tree, "CommRateCalculateFinish", kCommRateCalcZh, 2);
            // 新一代字段释义:PLC能力指示/通道数(byte12)
            translate_enum_i18n(out.tree, "PLCCapInd", kPLCCapZh, 2);
            translate_enum_i18n(out.tree, "ChannelNum", kChannelNumZh, 2);
            // 相线可信程度说明(6.8.14):高可信/中可信/低可信依次递减
            for (auto& n : out.tree) {
                if (n.name.startsWith(QLatin1String("CandidateLinePhase0")))
                    n.value += trl::L(" (高可信)");
                else if (n.name.startsWith(QLatin1String("CandidateLinePhase1")))
                    n.value += trl::L(" (中可信)");
                else if (n.name.startsWith(QLatin1String("CandidateLinePhase2")))
                    n.value += trl::L(" (低可信)");
            }
            annotate_unit(out.tree, "ProxyCommRate", QStringLiteral("%"));
            annotate_unit(out.tree, "ProxyDownCommRate", QStringLiteral("%"));
            annotate_unit(out.tree, "MinCommRate", QStringLiteral("%"));
            annotate_unit(out.tree, "RoutePeriodLeftTime", QStringLiteral("s"));
            annotate_unit(out.tree, "ReceivedInfoEntryLen", QStringLiteral("bit"));
            const quint16 route_num = (quint16)get_bits(mme, 34, 0, 16);  // UpRouteEntryNum
            const quint16 node_num  = (quint16)get_bits(mme, 30, 0, 16);  // DiscoverNodeNum
            int off = 48;  // 固定头 42B(MMeHead 6 + 消息体 42)
            // 上行路由条目(3B/条:NextHopTEI 12b + RSV 4b + RouteType 8b)
            // 同步提取 NextHopTEI 入 topo_event.up_routes,供 TopoState 识别上行路径变化
            const quint16 ur_sta_tei = (quint16)get_bits(mme, 6, 0, 16);
            for (int i = 0; i < route_num && off + 3 <= mme.size(); ++i) {
                const quint16 nexthop = (quint16)get_bits(mme, off, 0, 12);
                const quint8 route_type = (quint8)get_bits(mme, off + 2, 0, 8);
                // 仅代理主路径(RouteType=3)为该 STA 父节点,其余路由类型忽略
                if (ur_sta_tei && nexthop && route_type == 3)
                    out.topo_event.up_routes.append({ur_sta_tei, nexthop});
                MsduFieldNode& n = group(out.tree, QStringLiteral("UpRoute[%1]").arg(i));
                n.rel_start = mme_rel_base + (off); n.rel_len = 3;
                add_fields(n.children, mme, off, kUpRouteInfoSpec, kUpRouteInfoSpecN, mme_rel_base);
                translate_enum_i18n(n.children, "RouteType", kRouteTypeZh, 5);
                off += 3;
            }
            // 发现站点列表位图(128B 按位解析,bit 位置 = TEI)
            QByteArray bm;
            int bm_base = -1;
            if (off + 128 <= mme.size()) {
                bm_base = off;
                bm = mme.mid(off, 128);
                off += 128;
            }
            bool bm_any = false;
            int nset = 0;
            QVector<QStringList> per_byte(bm.size());
            for (int i = 0; i < bm.size(); ++i) {
                const quint8 byte = (quint8)bm[i];
                for (int j = 0; j < 8; ++j) {
                    if (!(byte & (1u << j))) continue;
                    per_byte[i] << QStringLiteral("TEI%1").arg(8 * i + j);
                    ++nset;
                }
                if (!per_byte[i].isEmpty()) bm_any = true;
            }
            // 邻居表:位图置位 TEI 即该 STA 发现的邻居,供 TopoState 按 STA 更新邻居表
            // 全 0 位图(nset==0)也要上报(空 neighbor_teis),以清空该 STA 的旧邻居
            if (ur_sta_tei) {
                out.topo_event.discover_src_tei = ur_sta_tei;
                out.topo_event.neighbor_teis.reserve(nset);
                for (int i = 0; i < bm.size(); ++i) {
                    const quint8 byte = (quint8)bm[i];
                    for (int j = 0; j < 8; ++j) {
                        if (byte & (1u << j))
                            out.topo_event.neighbor_teis.append((quint16)(8 * i + j));
                    }
                }
            }
            // 逐字节显示(空字节不显示,非空字节按 bitmap[索引][8b] 显示,对应 hex 高亮)
            auto& bmg = group(out.tree,
                QStringLiteral("DiscoverySTAList BitMap [%1B]").arg(bm.size()));
            // 组节点覆盖整个 bitmap 区域,点击高亮全部所属字节
            if (bm_base >= 0) { bmg.rel_start = mme_rel_base + bm_base; bmg.rel_len = bm.size(); }
            // 发现站点列表位图逐位(仅 bit=1):绝对 TEI 位图,起始 TEI=0(文档:
            // "从0字节开始第一个有效 TEI"),TEI = 字节号*8 + 位号,LSB 在前;
            // 值标注该 bit 所在的字节号;配套 ReceivedDiscoveryInfo 为逐置位 TEI 计数表
            for (int i = 0; i < bm.size(); ++i) {
                if (per_byte[i].isEmpty()) continue;   // 空字节不显示
                for (int j = 0; j < 8; ++j) {
                    if (!((quint8)bm[i] & (1u << j))) continue;
                    MsduFieldNode bn;
                    bn.name = trl::L("发现站点 TEI=%1").arg(8 * i + j);
                    bn.value = trl::L("在位图(第%1字节)").arg(i);
                    if (bm_base >= 0) { bn.rel_start = mme_rel_base + (bm_base + i); bn.rel_len = 1; }
                    bmg.children.append(bn);
                }
            }
            // 收到发现列表信息(置位 TEI 各一条,1B 计数)
            QByteArray cnts;
            int cnts_base = -1;
            if (node_num > 0 && off + node_num <= mme.size()) {
                cnts_base = off;
                cnts = mme.mid(off, node_num);
            }
            if (bm_any && nset > 0) {
                auto& rgi = group(out.tree,
                    QStringLiteral("ReceivedDiscoveryInfo [%1]").arg(nset));
                int order = 0;
                for (int i = 0; i < bm.size(); ++i) {
                    const quint8 byte = (quint8)bm[i];
                    for (int j = 0; j < 8; ++j) {
                        if (!(byte & (1u << j))) continue;
                        const int tei = 8 * i + j;
                        MsduFieldNode rc;
                        rc.name = QStringLiteral("ReceivedDiscoverCount[%1]").arg(order);
                        if (order < cnts.size()) {
                            rc.value = QStringLiteral("%1 - TEI%2")
                                           .arg((quint8)cnts[order]).arg(tei);
                            if (cnts_base >= 0) { rc.rel_start = mme_rel_base + (cnts_base + order); rc.rel_len = 1; }
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
        case NW_2026_MMeType::MME_DELAYLEAVEIND: {
            add_fields(out.tree, mme, 6, kMMeDelayLeaveIndSpec, kMMeDelayLeaveIndSpecN, mme_rel_base);
            translate_enum_i18n(out.tree, "Reason", kDelayLeaveReasonZh, 4);
            annotate_unit(out.tree, "LeaveDelayTime", QStringLiteral("s"));
            const quint16 sta_num = (quint16)get_bits(mme, 8, 0, 16);
            int off = 22;  // 消息体 byte 16(MMeHeadSize 6 + 16),RSV0(10B) 之后
            // 拓扑事件:延迟离线指示(直接按离线标,按 MAC 匹配)
            out.topo_event.kind = TopoEventKind::LeaveInd;
            for (int i = 0; i < sta_num && off + 6 <= mme.size(); ++i) {
                const quint64 lmac = get_bits(mme, off, 0, 48);
                if (lmac) out.topo_event.leaves.append(lmac);
                MsduFieldNode& n = group(out.tree, QStringLiteral("LeaveSTA[%1]").arg(i),
                    mac_str(lmac));
                n.rel_start = mme_rel_base + (off); n.rel_len = 6;
                off += 6;
            }
            out.topo_event.desc = trl::L("延迟离线指示: %1 个站点离线").arg(sta_num);
            break;
        }
        case NW_2026_MMeType::MME_SUCCESSRATEREPORT: {
            add_fields(out.tree, mme, 6, kMMeSuccessRateReportSpec, kMMeSuccessRateReportSpecN, mme_rel_base);
            const quint16 sta_num = (quint16)get_bits(mme, 8, 0, 16);
            int off = 10;
            // 拓扑事件:成功率上报(STA 与上级的上下行成功率)
            out.topo_event.kind = TopoEventKind::SuccessRate;
            for (int i = 0; i < sta_num && off + 4 <= mme.size(); ++i) {
                const quint16 tei = (quint16)get_bits(mme, off, 0, 16);
                const quint8 down = (quint8)get_bits(mme, off + 2, 0, 8);
                const quint8 up   = (quint8)get_bits(mme, off + 3, 0, 8);
                out.topo_event.comm_rates.append({tei, down, up});
                MsduFieldNode& n = group(out.tree, QStringLiteral("CommRate[%1]").arg(i));
                n.rel_start = mme_rel_base + (off); n.rel_len = 4;
                add_fields(n.children, mme, off, kCommRateInfoSpec, kCommRateInfoSpecN, mme_rel_base);
                annotate_unit(n.children, "DownCommRate", QStringLiteral("%"));
                annotate_unit(n.children, "UpCommRate", QStringLiteral("%"));
                off += 4;
            }
            break;
        }
        case NW_2026_MMeType::MME_ZEROCROSSNTBCOLLECTIND: {
            add_fields(out.tree, mme, 6, kMMeZeroCrossNTBCollectIndSpec, kMMeZeroCrossNTBCollectIndSpecN, mme_rel_base);
            translate_enum_i18n(out.tree, "StationType", kZCStationTypeZh, 2);
            translate_enum_i18n(out.tree, "CollectPeriod", kZCCollectPeriodZh, 2);
            break;
        }
        case NW_2026_MMeType::MME_ZEROCROSSNTBREPORT: {
            add_fields(out.tree, mme, 6, kMMeZeroCrossNTBReportSpec, kMMeZeroCrossNTBReportSpecN, mme_rel_base);
            // 过零 NTB 差值列表(表88:自消息体 byte 8 起按 12bit 紧凑排列;
            // 上报数量含基准 NTB 在内,差值个数 = 上报数量 - 1)
            if (mme.size() >= 14) {
                const int total = (int)get_bits(mme, 8, 0, 8);
                const int cnt = total > 0 ? total - 1 : 0;
                const int shown = qMin(cnt, (mme.size() - 14) * 8 / 12);
                if (shown > 0) {
                    auto& g = group(out.tree, QStringLiteral("NTB Diff List [%1]").arg(shown));
                    for (int i = 0; i < shown; ++i) {
                        const int bitpos = i * 12;
                        MsduFieldNode d;
                        d.name = QStringLiteral("NTBDiff[%1]").arg(i);
                        d.value = QString::number(get_bits(mme, 14 + bitpos / 8, bitpos % 8, 12));
                        d.rel_start = mme_rel_base + 8 + bitpos / 8;
                        d.rel_len = (bitpos % 8 + 12 + 7) / 8;
                        g.children.append(d);
                    }
                    g.rel_start = mme_rel_base + 8;
                    g.rel_len = (shown * 12 + 7) / 8;
                }
            }
            break;
        }
        case NW_2026_MMeType::MME_NETDIAGNOSE: {
            add_fields(out.tree, mme, 6, kMMeNetDiagnoseSpec, kMMeNetDiagnoseSpecN, mme_rel_base);
            translate_enum_i18n(out.tree, "ChipID", kChipIDZh, 9);
            // DiagInfo 变长诊断数据(mme byte 8 起 = 消息体 byte 2)
            if (mme.size() > 8) {
                MsduFieldNode& d = group(out.tree, QStringLiteral("DiagInfo [%1 B]").arg(mme.size() - 8),
                    QString::fromLatin1(mme.mid(8).toHex(' ').toUpper()));
                d.rel_start = mme_rel_base + (8); d.rel_len = mme.size() - 8;
            }
            break;
        }
        case NW_2026_MMeType::MME_NETWORKCONFLICTREPORT: {
            // 网络冲突上报(第2部分无线表204,固定体 9B):冲突网络 CCO MAC + 邻居网络个数 + SNID 位图
            add_fields(out.tree, mme, 6, kMMeNetworkConflictReportSpec, kMMeNetworkConflictReportSpecN, mme_rel_base);
            // NeighborSNIDBitmap 逐位(仅 bit=1):每位对应一个 SNID(绝对,起始 0,
            // 文档"1bit 置位表明可探测到周边 SNID 为 1 的网络"),SNID = 字节号*8+位号,
            // LSB 在前;值标注该 bit 所在的字节号
            // NeighborSNIDBitmap 逐位(仅 bit=1):每位对应一个 SNID(绝对,起始 0,
            // 文档"1bit 置位表明可探测到周边 SNID 为 1 的网络"),SNID = 字节号*8+位号,
            // LSB 在前;值标注该 bit 所在的字节号。固定体最后一项即 SNID 位图,
            // 直接取 out.tree.last() 引用回填(勿按名匹配 add_fields 产物,其名含 [16b] 后缀)
            {
                const int nb_off = 6 + 7;   // mme[13] = MMe 头 6B + 固定体 MAC6+Num1 之后
                if (mme.size() >= nb_off + 2 && !out.tree.isEmpty()) {
                    const quint16 bm16 = (quint16)get_bits(mme, nb_off, 0, 16);
                    MsduFieldNode& snid_node = out.tree.last();
                    if (snid_node.name.startsWith(QLatin1String("NeighborSNIDBitmap"))) {
                        for (int k = 0; k < 16; ++k) {
                            if (!((bm16 >> k) & 1)) continue;
                            MsduFieldNode sn;
                            sn.name = trl::L("SNID[%1]").arg(k);
                            sn.value = trl::L("在位图(第%1字节)").arg(k / 8);
                            sn.rel_start = mme_rel_base + nb_off + (k / 8);
                            sn.rel_len = 1;
                            snid_node.children.append(sn);
                        }
                    }
                }
            }

            break;
        }
        case NW_2026_MMeType::MME_RFCHANNELCONFLICTREPORT: {
            // 无线信道冲突上报(第2部分无线表212):固定头 7B + 变长邻居网络条目(表213,每条 2B)
            add_fields(out.tree, mme, 6, kMMeRFChannelConflictReportSpec, kMMeRFChannelConflictReportSpecN, mme_rel_base);
            const quint8 nb_num = (quint8)get_bits(mme, 12, 0, 8);  // 邻居网络个数(mme byte 12 = 6 头 + 报文体 byte 6)
            int off = 13;  // 条目起点(mme byte 13 = 6 头 + 7 固定头)
            for (int i = 0; i < nb_num && off + 2 <= mme.size(); ++i) {
                auto& g = group(out.tree, QStringLiteral("Neighbor[%1] (2B)").arg(i));
                g.rel_start = mme_rel_base + off; g.rel_len = 2;
                add_fields(g.children, mme, off, kRFChannelNeighborSpec, kRFChannelNeighborSpecN, mme_rel_base);
                off += 2;
            }
            break;
        }
        // ---- SPLC 新增管理消息(SPLC 数据链路层 §5.1.4.19-5.1.4.24,表153-164) ----
        case NW_2026_MMeType::MME_BITLOAD_UPDATE_REQ: {
            // Bitloading训练结果更新请求(表153):固定头 8B + 可变比特加载表
            add_fields(out.tree, mme, 6, kMMeBitLoadUpdateReqSpec, kMMeBitLoadUpdateReqSpecN, mme_rel_base);
            translate_enum_i18n(out.tree, "StreamNum", kStreamNumZh, 2);
            const int table_len = (int)get_bits(mme, 12, 0, 16);   // 比特加载表长度(表153,报文体 byte6)
            if (table_len > 0 && mme.size() >= 14 + table_len) {   // 表自报文体 byte8(mme 偏移 14) 起
                MsduFieldNode& g = group(out.tree, QStringLiteral("BitLoadTable [%1 B]").arg(table_len),
                    QString::fromLatin1(mme.mid(14, table_len).toHex(' ').toUpper()));
                g.rel_start = mme_rel_base + 14; g.rel_len = table_len;
                // 表154/155:每 3bit 一组,表156 释义;仅渲染前 32 组避免字段树过大
                const int groups = qMin(table_len * 8 / 3, 32);
                for (int i = 0; i < groups; ++i) {
                    const quint8 v = (quint8)get_bits(mme, 14 + (i * 3) / 8, (i * 3) % 8, 3);
                    MsduFieldNode leaf;
                    leaf.name = QStringLiteral("Group%1").arg(i);
                    leaf.value = QStringLiteral("%1 - %2").arg(v).arg(bitload_value_str(v));
                    leaf.rel_start = mme_rel_base + 14 + (i * 3) / 8;
                    leaf.rel_len = ((i * 3) % 8 + 3 + 7) / 8;
                    g.children.append(leaf);
                }
            }
            break;
        }
        case NW_2026_MMeType::MME_BITLOAD_UPDATE_CNF: {
            // Bitloading训练结果更新确认(表157):固定头 5B
            add_fields(out.tree, mme, 6, kMMeBitLoadUpdateCnfSpec, kMMeBitLoadUpdateCnfSpecN, mme_rel_base);
            translate_enum_i18n(out.tree, "UpdateResult", kUpdateResultZh, 2);
            break;
        }
        case NW_2026_MMeType::MME_RUSNR_INFO_IND: {
            // RU_SNR信息告知(表158):固定头 8B + 邻居站点位图 + 邻居RU_SNR(表159,每 4B)
            add_fields(out.tree, mme, 6, kMMeRUSNRInfoIndSpec, kMMeRUSNRInfoIndSpecN, mme_rel_base);
            translate_enum_i18n(out.tree, "RUGroupId", kRUGroupIdZh, 2);
            const quint8 ru_group = (quint8)get_bits(mme, 9, 0, 8);   // 报文体 byte3
            const int nb_num  = (int)get_bits(mme, 10, 0, 16);        // 报文体 byte4
            const int bm_len  = (int)get_bits(mme, 12, 0, 16);        // 报文体 byte6
            const int bm_start = 14;                                   // 位图自报文体 byte8(mme 偏移 14)
            if (bm_len > 0 && mme.size() >= bm_start + bm_len) {
                MsduFieldNode& bm = group(out.tree, QStringLiteral("NeighborBitmap [%1 B]").arg(bm_len),
                    QString::fromLatin1(mme.mid(bm_start, bm_len).toHex(' ').toUpper()));
                bm.rel_start = mme_rel_base + bm_start; bm.rel_len = bm_len;
                // 位图逐位展开(位序与表226 一致:byte k/8 的 bit k%8,LSB 在前):
                // bit=1 的邻居 TEI = NeighborStartTEI + k(表158 语义:1 位对应一个
                // 告知的邻居),值标注该 bit 所在的字节号(k>>3);bit=0 的位不列
                const quint16 nb_start_tei = (quint16)get_bits(mme, 7, 4, 12);
                for (int k = 0; k < bm_len * 8; ++k) {
                    if (!((mme[bm_start + (k >> 3)] >> (k & 7)) & 1)) continue;
                    MsduFieldNode& bn = group(bm.children,
                        QStringLiteral("Neighbor[%1] TEI=%2").arg(k).arg(nb_start_tei + k),
                        trl::L("在位图(第%1字节)").arg(k >> 3));
                    bn.rel_start = mme_rel_base + bm_start + (k >> 3);
                    bn.rel_len = 1;
                }
            }
            // 仅 RU分组 id=0(表159,每邻居 4B)渲染;其它 id 为保留,结构未定义
            const int nb_start = bm_start + bm_len;
            // 表159 各 RU 5bit SNR 的载波范围(仅 RU分组 ID0 有定义;gid≠0 结构保留)
            static const struct { const char* name; int lo, hi; } kRuCarrier[6] = {
                {"RU0_SNR", 32, 101}, {"RU1_SNR", 109, 178}, {"RU2_SNR", 186, 255},
                {"RU3_SNR", 263, 332}, {"RU4_SNR", 340, 409}, {"RU5_SNR", 417, 490},
            };
            for (int i = 0; i < nb_num && ru_group == 0 && nb_start + (i + 1) * 4 <= mme.size(); ++i) {
                auto& g = group(out.tree, QStringLiteral("NeighborRU_SNR[%1]").arg(i));
                g.rel_start = mme_rel_base + nb_start + i * 4; g.rel_len = 4;
                add_fields(g.children, mme, nb_start + i * 4, kRUSNRGroup0Spec, kRUSNRGroup0SpecN, mme_rel_base);
                for (auto& n : g.children)
                    // add_fields 的节点名带 " [Nbit]" 后缀,按前缀匹配 RU 名
                    for (const auto& rc : kRuCarrier)
                        if (n.name.startsWith(QLatin1String(rc.name)))
                            n.value += trl::L(" (载波 %1-%2)").arg(rc.lo).arg(rc.hi);
            }
            break;
        }
        case NW_2026_MMeType::MME_TEI_LIST_REQ: {
            // 站点TEI列表请求(表160):固定头 8B + MAC 列表 6B/条
            add_fields(out.tree, mme, 6, kMMeTEIListReqSpec, kMMeTEIListReqSpecN, mme_rel_base);
            const quint8 sta_num = (quint8)get_bits(mme, 13, 0, 8);   // 报文体 byte7(站点数量)
            for (int i = 0; i < sta_num && 14 + (i + 1) * 6 <= mme.size(); ++i) {
                const quint64 mac = get_bits(mme, 14 + i * 6, 0, 48); // MAC 列表自报文体 byte8(mme 偏移 14)
                MsduFieldNode& n = group(out.tree, QStringLiteral("Station[%1] MAC").arg(i), mac_str(mac));
                n.rel_start = mme_rel_base + 14 + i * 6; n.rel_len = 6;
            }
            break;
        }
        case NW_2026_MMeType::MME_TEI_LIST_CNF: {
            // 站点TEI列表回复(表161/162):固定头 8B + TEI 列表 8B/条
            add_fields(out.tree, mme, 6, kMMeTEIListCnfSpec, kMMeTEIListCnfSpecN, mme_rel_base);
            const quint8 sta_num = (quint8)get_bits(mme, 13, 0, 8);   // 报文体 byte7(站点数量)
            for (int i = 0; i < sta_num && 14 + (i + 1) * 8 <= mme.size(); ++i) {
                auto& g = group(out.tree, QStringLiteral("TEIEntry[%1]").arg(i));
                g.rel_start = mme_rel_base + 14 + i * 8; g.rel_len = 8;
                add_fields(g.children, mme, 14 + i * 8, kTEIListEntrySpec, kTEIListEntrySpecN, mme_rel_base);
                // 学习 TEI→MAC(SPLC 第4部分 表161/162 条目:StationMAC 6B + StationTEI 12b;仅发对,不动 topo)
                {
                    const quint64 mac = get_bits(mme, 14 + i * 8, 0, 48);
                    const quint16 tei = (quint16)get_bits(mme, 14 + i * 8 + 6, 0, 12);
                    if (tei != 0 && mac)
                        out.tei_mac_pairs.append({tei, mac});
                }
            }
            break;
        }
        case NW_2026_MMeType::MME_EXT_NETWORK_CONFLICT_RPT: {
            // 扩展网络冲突上报(表163/164):固定头 7B + 邻居网络条目 1B/条(SNID 5bit)
            add_fields(out.tree, mme, 6, kMMeExtNetConflictSpec, kMMeExtNetConflictSpecN, mme_rel_base);
            const quint8 nb_num = (quint8)get_bits(mme, 12, 0, 8);    // 报文体 byte6(邻居网络个数)
            for (int i = 0; i < nb_num && 13 + i < mme.size(); ++i) { // 条目自报文体 byte7(mme 偏移 13)
                auto& g = group(out.tree, QStringLiteral("NeighborNet[%1] (1B)").arg(i));
                g.rel_start = mme_rel_base + 13 + i; g.rel_len = 1;
                add_fields(g.children, mme, 13 + i, kExtNetConflictNeighborSpec, kExtNetConflictNeighborSpecN, mme_rel_base);
            }
            break;
        }
        case NW_2026_MMeType::MME_IOT_ASSOC_REQ: {
            // 物联终端接入请求(表243,固定体 10B)
            add_fields(out.tree, mme, 6, kMMeIoTAssocReqSpec, kMMeIoTAssocReqSpecN, mme_rel_base);
            break;
        }
        case NW_2026_MMeType::MME_IOT_ASSOC_IND: {
            // 物联终端接入确认(表244,固定体 7B;接入结果 表245)
            add_fields(out.tree, mme, 6, kMMeIoTAssocIndSpec, kMMeIoTAssocIndSpecN, mme_rel_base);
            translate_enum_i18n(out.tree, "AccessResult", kIoTAccessResultZh, 2);
            break;
        }
        case NW_2026_MMeType::MME_IOT_LEAVE_IND: {
            // 物联终端离线指示(表246,固定体 7B;离线原因 表247)
            add_fields(out.tree, mme, 6, kMMeIoTLeaveIndSpec, kMMeIoTLeaveIndSpecN, mme_rel_base);
            translate_enum_i18n(out.tree, "LeaveReason", kIoTLeaveReasonZh, 2);
            break;
        }
                        default:
                            // 未知管理消息类型(如新规约扩展类型):报文体以原始 hex 呈现,避免整段不可见
                            append_payload_hex(out, mme, 6, -1, QStringLiteral("MMe Data"), mme_rel_base);
                            break;
                    }
                    }
                }
            } else {
                parse_app(out, msdu_body.mid(18), mac_hdr_len + 18, out.msdu_type);   // 长帧头 APP 数据(帧头 18B 之后)
            }
        }
    } else {
        // MSDU_SHORTHEAD(2B):VLAN 8b + MSDU 类型 8b(短帧头只携带应用层报文)
        if (msdu_body.size() >= 2) {
            const quint8* q = reinterpret_cast<const quint8*>(msdu_body.constData());
            out.vlan_tag  = (quint32)get_bits(q, 0, 0, 8);
            out.msdu_type = (quint16)get_bits(q, 1, 0, 8);
            {
                MsduFieldNode vt;
                vt.name = QStringLiteral("VLAN Tag [8b]");
                vt.value = vlan_tag_value(out.vlan_tag, out.msdu_type, 2);
                vt.rel_start = mac_hdr_len;
                vt.rel_len   = 1;
                out.tree.append(vt);
            }
            // MSDU 类型字段(表2:8b)
            {
                MsduFieldNode mt;
                mt.name = QStringLiteral("MSDU Type [8b]");
                mt.value = QStringLiteral("0x%1 - %2")
                               .arg(out.msdu_type, 2, 16, QChar('0')).arg(trl::L("应用层报文"));
                mt.rel_start = mac_hdr_len + 1;   // 短帧头 MSDU 类型在 msdu_body[1]
                mt.rel_len   = 1;
                out.tree.append(mt);
            }
            parse_app(out, msdu_body.mid(2), mac_hdr_len + 2, out.msdu_type);   // 短帧头 APP 数据(帧头 2B 之后)
        }
    }
    // ---- MSDU 帧尾 4B CRC32 ----
    // 位置:MSDU 载荷(MAC 帧头 mac_hdr_len 之后 msdu_len 字节)之后紧接 4B;
    // 计算覆盖 MSDU 载荷(不含 MAC 帧头),poly=0xEDB88320
    append_msdu_crc(out, body, mac_hdr_len, msdu_len);
    out.present = true;
    // 逐事件发送方 MAC:与重启次数同源(MAC 帧头源 MAC);短头无 MAC 时留 0,
    // TopoState 回落到事件 nodes 首条;多站/级联每段/每站解析各填各的,
    // 合并时随 TopoEvent 对象整体拷贝,不混、不丢。
    if (out.topo_event.kind != TopoEventKind::Other && out.msdu_src_mac)
        out.topo_event.sender_mac = out.msdu_src_mac;
    return out;
}
