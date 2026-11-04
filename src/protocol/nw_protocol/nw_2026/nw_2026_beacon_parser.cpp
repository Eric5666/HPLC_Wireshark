/// @file nw_2026_beacon_parser.cpp
/// @brief 南网 NW_2026 信标帧载荷区解析实现
/// @details 对照数据链路层报批稿表24(信标帧载荷字段)/表25-28(信标类型/组网/
///          多网络优选/开始关联)/表29-31(信标管理信息)及 Python 参考
///          MPDU_BEACON_LOAD。信标物理块 = 固定头 + 管理信息 + BPCS(CRC32)
///          + 保留字节 + 物理块检查序列(CRC24)。
#include "nw_2026_beacon_parser.h"
#include "common/fieldspec.h"
#include "common/fieldtools.h"
#include "crc.h"
#include "i18n.h"

namespace {

// 信标类型名称(表25:0 发现/1 代理/2 中央/其它保留)
static QString beacon_type_name(quint8 t) {
    switch (static_cast<NW_2026_BeaconType>(t)) {
        case NW_2026_BeaconType::DISCOVERY: return trl::L("发现信标");
        case NW_2026_BeaconType::PROXY:     return trl::L("代理信标");
        case NW_2026_BeaconType::CENTRAL:   return trl::L("中央信标");
        default: return trl::L("保留");
    }
}

// 相线名称(SPLC 第4部分 表61:0 全相线 1 A 2 B 3 C)
static QString line_name(quint8 l) {
    switch (static_cast<NW_2026_PhaseLine>(l)) {
        case NW_2026_PhaseLine::ALL_LINES: return trl::L("全相线");
        case NW_2026_PhaseLine::LINE_A:    return trl::L("A相线");
        case NW_2026_PhaseLine::LINE_B:    return trl::L("B相线");
        case NW_2026_PhaseLine::LINE_C:    return trl::L("C相线");
        default: return trl::L("保留");
    }
}

// 站点角色(SPLC 第4部分 表61:0 未知 1 STA 2 PCO 4 CCO 其它保留)
static QString role_name(quint8 r) {
    switch (static_cast<NW_2026_StationType>(r)) {
        case NW_2026_StationType::UNKNOWN: return trl::L("未知");
        case NW_2026_StationType::STA:     return QStringLiteral("STA");
        case NW_2026_StationType::PCO:     return QStringLiteral("PCO");
        case NW_2026_StationType::CCO:     return QStringLiteral("CCO");
        default: return trl::L("保留");
    }
}

// 信标条目头名称(表59:信标条目头取值,试行版编号;旧报批稿为表31)
static QString beacon_item_head_name(quint8 h) {
    switch (static_cast<NW_2026_BeaconItemType>(h)) {
        case NW_2026_BeaconItemType::STA_CAPABILITY:  return trl::L("站点能力条目");
        case NW_2026_BeaconItemType::TIME_SLOT_ALLOC: return trl::L("时隙分配条目");
        case NW_2026_BeaconItemType::ROUTE_PARAM:     return trl::L("路由参数条目");
        case NW_2026_BeaconItemType::BAND_CHANGE:     return trl::L("频段变更条目");
        case NW_2026_BeaconItemType::BAND_PROBE:      return trl::L("频段探测条目");
        case NW_2026_BeaconItemType::CALENDAR_SYNC:   return trl::L("万年历同步条目");
        case NW_2026_BeaconItemType::ROUTE_PARAM_RF:  return trl::L("无线路由参数条目");
        case NW_2026_BeaconItemType::RF_CHANNEL_CHANGE: return trl::L("无线信道变更条目");
        case NW_2026_BeaconItemType::SIMPLE_STA_SLOT: return trl::L("精简信标站点信息及时隙条目");
        case NW_2026_BeaconItemType::BEACON_MECH_SWITCH: return trl::L("信标机制切换条目");
        case NW_2026_BeaconItemType::PROXY_ROLE:      return trl::L("代理角色条目");
        default:
            return (h >= 0x80 && h <= 0xEF) ? trl::L("厂家自定义条目")
                                            : trl::L("保留条目");
    }
}

// 信标帧载荷固定头(表51,统一载波/无线):信标类型/组网标志/精简信标/多网络优选/
// 开始关联/短网络标识高位/组网序列号/短网络标识低位/无线option/PLC能力指示/
// 无线信道/通道数/网络版本号/信标机制状态/发现信标使能/保留
static const FieldSpec kBeaconLoadSpec[] = {
    {"BeaconType",             0, 0, 3,  Fmt::DEC},
    {"NetWorkingFlag",         0, 3, 1,  Fmt::DEC},
    {"ReduceBeaconFlag",       0, 4, 1,  Fmt::DEC},   // 精简信标标志
    {"MultiNetChooseFuncFlag", 0, 5, 1,  Fmt::DEC},
    {"AssociationFlag",        0, 6, 1,  Fmt::DEC},
    {"SNIDHigh",               0, 7, 1,  Fmt::DEC},   // 短网络标识高位
    {"NetSN",                  1, 0, 8,  Fmt::DEC},
    {"SNIDLow",                2, 0, 4,  Fmt::DEC},   // 短网络标识低位
    {"RFOption",               2, 4, 2,  Fmt::DEC},   // 本网络无线 option
    {"PLCCapInd",              2, 6, 2,  Fmt::DEC},   // PLC能力指示
    {"RFChannel",              3, 0, 8,  Fmt::DEC},   // 本网络无线信道编号
    {"ChannelNum",             4, 0, 1,  Fmt::DEC},   // 通道数
    {"NetVersion",             4, 1, 3,  Fmt::DEC},   // 网络版本号
    {"BeaconMechStatus",       4, 4, 1,  Fmt::DEC},   // 信标机制状态
    {"DiscoverBeaconEnable",   4, 5, 1,  Fmt::DEC},   // 发现信标发送使能标志
    {"RSV2",                   4, 6, 2,  Fmt::DEC},   // 保留(4 bit6-7)
    {"RSV3",                   5, 0, 8,  Fmt::DEC},   // 保留(byte5)
};
static const int kBeaconLoadSpecN = int(sizeof(kBeaconLoadSpec) / sizeof(kBeaconLoadSpec[0]));

// ── 信标条目字段表(相对条目内容 it,即条目头/长度之后) ──

// 站点能力条目 0x01(SPLC 第4部分 表61,内容 20B;旧报批稿编号为表33)
static const FieldSpec kStaCapSpec[] = {
    {"NetLevel",               0, 0, 6,  Fmt::DEC},   // 层级数
    {"STALine",                0, 6, 2,  Fmt::DEC},   // 相线
    {"TEI",                    1, 0, 12, Fmt::DEC},   // 站点 TEI
    {"Role",                   2, 4, 4,  Fmt::DEC},   // 角色
    {"BeaconUsageFlag",        3, 0, 8,  Fmt::DEC},   // 信标使用标志
    {"SourceMAC",              4, 0, 48, Fmt::MAC},   // 发送信标站点 MAC
    {"PCOTEI",                10, 0, 12, Fmt::DEC},   // 代理站点 TEI
    {"RSV0",                  11, 4, 4,  Fmt::DEC},   // 保留
    {"LinkMinCommSuccessRate", 12, 0, 32, Fmt::DEC},  // 路径最低通信成功率
    {"RSV1",                  16, 0, 32, Fmt::DEC},   // 保留
};
static const int kStaCapSpecN = int(sizeof(kStaCapSpec) / sizeof(kStaCapSpec[0]));

// 时隙分配条目 0x02 固定头(表62,内容头 24B,可变长区随后;旧报批稿编号为表34)
static const FieldSpec kTsaHeadSpec[] = {
    {"NonCCOBeaconSlotNum",  0, 0, 8,  Fmt::DEC},   // 非中央信标时隙总数
    {"CCOBeaconSlotNum",     1, 0, 8,  Fmt::DEC},   // 中央信标时隙总数
    {"CSMALineNum",          2, 0, 8,  Fmt::DEC},   // CSMA 时隙相线个数
    {"PCOBeaconSlotNum",     3, 0, 8,  Fmt::DEC},   // 代理信标时隙总数
    {"BeaconSlotLen",        4, 0, 16, Fmt::DEC},   // 信标时隙长度(100us)
    {"CSMASlotSize",         6, 0, 8,  Fmt::DEC},   // CSMA 时隙大小(10ms)
    {"BindingCSMALineNum",   7, 0, 8,  Fmt::DEC},   // 绑定 CSMA 相线个数
    {"BindingCSMALinkID",    8, 0, 8,  Fmt::DEC},   // 绑定 CSMA 链路标识符
    {"TDMASlotLen",          9, 0, 16, Fmt::DEC},   // TDMA 时隙长度(100us)
    {"TDMALinkID",          11, 0, 8,  Fmt::DEC},   // TDMA 链路标识符
    { "BeaconPeriodStartNTB", 12, 0, 32, Fmt::HEX8}, // 信标周期起始 NTB
    { "BeaconPeriodLen",     16, 0, 32, Fmt::DEC},   // 信标周期长度(100us)
    // RF信标时隙长度(表62:规格 byte22-23 bit0-1,10bit,单位1ms;旧报批稿为 byte23)
    { "RFBeaconSlotLen",     19, 0, 10, Fmt::DEC},   // RF信标时隙长度(1ms)
    { "RSV",                 20, 2, 30, Fmt::HEX8},  // 保留(内容 byte20 bit2-7 + byte21-23)
};
static const int kTsaHeadSpecN = int(sizeof(kTsaHeadSpec) / sizeof(kTsaHeadSpec[0]));

// 路由参数条目 0x06(表66,内容 32B;旧报批稿编号为表38)
static const FieldSpec kRouteParamSpec[] = {
    {"RoutePeriod",       0, 0, 16,  Fmt::DEC},   // 路由周期(s)
    {"RSV0",              2, 0, 16,  Fmt::DEC},   // 保留
    {"NextRouteEstTime",  4, 0, 16,  Fmt::DEC},   // 路由评估剩余时间(s)
    {"RSV1",              6, 0, 160, Fmt::DEC},   // 保留
    {"CCOMACAddr",       26, 0, 48,  Fmt::MAC},   // CCO MAC 地址
};
static const int kRouteParamSpecN = int(sizeof(kRouteParamSpec) / sizeof(kRouteParamSpec[0]));

// 频段变更条目 0x07(表67,内容 5B;旧报批稿编号为表39)
static const FieldSpec kBandChangeSpec[] = {
    {"TargetBand",       0, 0, 8,  Fmt::DEC},   // 目标频段
    {"SwitchRemainTime", 1, 0, 32, Fmt::DEC},   // 频段切换剩余时间(ms)
};
static const int kBandChangeSpecN = int(sizeof(kBandChangeSpec) / sizeof(kBandChangeSpec[0]));

// 频段探测条目 0x0A(附录B 表B-1,内容 2B)
static const FieldSpec kBandProbeSpec[] = {
    {"ProbeBand",       0, 0, 8,  Fmt::DEC},   // 探测频段
    {"BindCSMASlotLID", 1, 0, 8,  Fmt::DEC},   // 对应的绑定CSMA时隙LID(固定77)
};
static const int kBandProbeSpecN = int(sizeof(kBandProbeSpec) / sizeof(kBandProbeSpec[0]));

// 万年历同步条目 0x0B(表68,内容 8B;旧报批稿编号为表40)
static const FieldSpec kCalendarSyncSpec[] = {
    {"CCOCalendarTime", 0, 0, 32, Fmt::DEC},   // CCO 万年历(秒)
    {"CCOCalendarNTB",  4, 0, 32, Fmt::DEC},   // CCO 万年历 NTB
};
static const int kCalendarSyncSpecN = int(sizeof(kCalendarSyncSpec) / sizeof(kCalendarSyncSpec[0]));

// 信标机制切换条目 0x0F(表71,内容 5B)
static const FieldSpec kBeaconMechSwitchSpec[] = {
    {"MechID",    0, 0, 8,  Fmt::DEC},   // 切换目标机制 ID(0 集中/1 分散/其他保留)
    {"SwitchNTB", 1, 0, 32, Fmt::HEX8},  // 预定切换的 NTB 时刻
};
static const int kBeaconMechSwitchSpecN = int(sizeof(kBeaconMechSwitchSpec) / sizeof(kBeaconMechSwitchSpec[0]));

// 无线路由参数条目 0x0C(坐标同第2部分表152,内容 2B;表142 分配 0x0C,表152 头列 0x09 为旧编号残留)
static const FieldSpec kRfRouteParamSpec[] = {
    {"RFDiscoverPeriod", 0, 0, 8, Fmt::DEC},   // 无线发现列表周期(秒)
    {"RFAgingCycles",    1, 0, 8, Fmt::DEC},   // 无线接收率老化周期个数(单位:无线发现列表周期)
};
static const int kRfRouteParamSpecN = int(sizeof(kRfRouteParamSpec) / sizeof(kRfRouteParamSpec[0]));

// 无线信道变更条目 0x0D(坐标同第2部分表153,内容 6B;表142 分配 0x0D,表153 头列 0x0A 为旧编号残留)
static const FieldSpec kRfChannelChangeSpec[] = {
    {"TargetChannel",    0, 0, 8,  Fmt::DEC},   // 目标信道编号
    {"TargetOption",     1, 0, 2,  Fmt::DEC},   // 目标信道 option
    {"RSV0",             1, 2, 6,  Fmt::DEC},   // 保留(表153 byte3 bit2-7)
    {"SwitchRemainTime", 2, 0, 32, Fmt::DEC},   // 信道切换剩余时间(毫秒)
};
static const int kRfChannelChangeSpecN = int(sizeof(kRfChannelChangeSpec) / sizeof(kRfChannelChangeSpec[0]));

// 精简信标站点信息及时隙条目 0x0E(坐标同 BPLC 第2部分 表155,内容 17B;BPLC 第2部分 表142 分配 0x0E)
static const FieldSpec kLiteStaSlotSpec[] = {
    {"TEI",              0, 0, 12, Fmt::DEC},   // 发送信标站点 TEI
    {"PCOTEI",           1, 4, 12, Fmt::DEC},   // 代理站点 TEI
    {"Role",             3, 0, 4,  Fmt::DEC},   // 角色(0x0 未知/0x1 STA/0x2 PCO/0x4 CCO)
    {"Level",            3, 4, 4,  Fmt::DEC},   // 层级数
    {"BeaconSTAMAC",     4, 0, 48, Fmt::MAC},   // 发送信标站点 MAC
    {"RFLinkHop",        8, 0, 4,  Fmt::DEC},   // 链路上 RF 跳数
    {"CarrierBand",      8, 4, 2,  Fmt::DEC},   // 载波频段(第2部分表156)
    {"RSV0",             8, 6, 2,  Fmt::DEC},   // 保留
    {"CSMASlotStartNTB", 9, 0, 32, Fmt::HEX8},  // CSMA 时隙开始时间(NTB)
    {"CSMASlotLen",     13, 0, 16, Fmt::DEC},   // CSMA 时隙长度(毫秒)
};
static const int kLiteStaSlotSpecN = int(sizeof(kLiteStaSlotSpec) / sizeof(kLiteStaSlotSpec[0]));

// 载波频段(第2部分表156,精简信标 0x0E 条目用)
static QString lite_band_name(quint8 b) {
    switch (b) {
        case 0: return QStringLiteral("1.953~11.96MHz");
        case 1: return QStringLiteral("2.441~5.615MHz");
        case 2: return QStringLiteral("0.781~2.930MHz");
        default: return trl::L("保留");
    }
}

// 精简信标帧载荷固定头(坐标同第2部分表154,12B):字节0 bit5 为保留(标准信标此处为
// 多网络优选)、bit7 为信标使用标志;组网序列号后为 CCO MAC 48b + 信标周期计数 32b,
// 管理区自 byte12 起,仅含 0x0E 精简信标站点信息及时隙条目
// (SPLC 未单独定义精简信标载荷格式,按第2部分表154 解析——表51 注明"信标管理信息与第2部分一致")
static const FieldSpec kLiteBeaconLoadSpec[] = {
    {"BeaconType",        0, 0, 3,  Fmt::DEC},
    {"NetWorkingFlag",    0, 3, 1,  Fmt::DEC},
    {"ReduceBeaconFlag",  0, 4, 1,  Fmt::DEC},   // 精简信标标志(恒 1)
    {"RSV0",              0, 5, 1,  Fmt::DEC},
    {"AssociationFlag",   0, 6, 1,  Fmt::DEC},
    {"BeaconUsageFlag",   0, 7, 1,  Fmt::DEC},   // 信标使用标志(表154 未定义值域,展示原始值)
    {"NetSN",             1, 0, 8,  Fmt::DEC},
    {"CCOMAC",            2, 0, 48, Fmt::MAC},
    {"BeaconPeriodCount", 8, 0, 32, Fmt::DEC},   // 信标周期计数
};
static const int kLiteBeaconLoadSpecN = int(sizeof(kLiteBeaconLoadSpec) / sizeof(kLiteBeaconLoadSpec[0]));

// 槽信息叶子节点(可变长区字段展示辅助)
static void slot_leaf(QVector<MsduFieldNode>& out, const QString& name,
                      const QString& value, int rel_abs, int rel_len) {
    MsduFieldNode n;
    n.name      = name;
    n.value     = value;
    n.rel_start = rel_abs;
    n.rel_len   = rel_len;
    out.append(n);
}

}  // namespace

MsduInfo NW_2026_BeaconParser::parse_beacon(const QByteArray& payload, int pbsize, bool is_rf) {
    Q_UNUSED(is_rf);  // 表51 固定头已统一载波/无线,is_rf 暂不参与载荷固定头解析
    MsduInfo out;
    out.present = false;
    if (pbsize < 16 || payload.size() < 16 + pbsize) return out;

    // 信标载荷区 = payload[16 : 16+pbsize-3](固定头 + 管理信息 + BPCS + 保留字节),
    // 不含块尾 3B 物理块检查序列。
    QByteArray gb = payload.mid(16, pbsize - 3);
    if (gb.size() < 8) return out;
    out.present = true;

    // BPCS(帧载荷校验序列,32-bit):gb 倒数第 5..2 字节(小端);
    // 覆盖前 gb.size()-5 字节(固定头 + 管理信息,不含 BPCS 与保留字节)。
    quint32 bpcs = 0;
    bool bpcs_ok = false;
    if (gb.size() >= 5) {
        bpcs = (quint8)gb[gb.size() - 5]
             | ((quint32)(quint8)gb[gb.size() - 4] << 8)
             | ((quint32)(quint8)gb[gb.size() - 3] << 16)
             | ((quint32)(quint8)gb[gb.size() - 2] << 24);
        quint32 calc = crc32_le(
            reinterpret_cast<const quint8*>(gb.constData()), gb.size() - 1);
        bpcs_ok = (bpcs == calc);
    }
    out.summary = trl::L("信标 BPCS CRC32:%1")
                      .arg(bpcs_ok ? trl::L("成功") : trl::L("失败"));

    auto& root = group(out.tree, QStringLiteral("Beacon Load [%1B]").arg(gb.size()));

    // 固定头(表51,统一载波/无线;精简信标为表154 专用 12B 头,按精简信标标志分派)
    const bool reduce_beacon = ((quint8)get_bits(gb, 0, 4, 1) != 0);
    if (reduce_beacon)
        add_fields(root.children, gb, 0, kLiteBeaconLoadSpec, kLiteBeaconLoadSpecN);
    else
        add_fields(root.children, gb, 0, kBeaconLoadSpec, kBeaconLoadSpecN);

    // 值解释:信标类型(表25)/组网标志(表26)/多网络优选(表27)/开始关联(表28)/
    //         精简信标标志(表137,仅无线)
    const quint8 beacon_type = (quint8)get_bits(gb, 0, 0, 3);
    for (auto& ch : root.children) {
        if (ch.name.startsWith(QStringLiteral("BeaconType"))) {
            ch.value = QStringLiteral("%1 - %2").arg(ch.value, beacon_type_name(beacon_type));
        } else if (ch.name.startsWith(QStringLiteral("NetWorkingFlag"))) {
            const quint8 v = (quint8)get_bits(gb, 0, 3, 1);
            ch.value = QStringLiteral("%1 - %2").arg(v).arg(
                v ? trl::L("组网完成") : trl::L("组网未完成"));
        } else if (ch.name.startsWith(QStringLiteral("MultiNetChooseFuncFlag"))) {
            const quint8 v = (quint8)get_bits(gb, 0, 5, 1);
            ch.value = QStringLiteral("%1 - %2").arg(v).arg(
                v ? trl::L("使能网络评估") : trl::L("未使能网络评估"));
        } else if (ch.name.startsWith(QStringLiteral("AssociationFlag"))) {
            const quint8 v = (quint8)get_bits(gb, 0, 6, 1);
            ch.value = QStringLiteral("%1 - %2").arg(v).arg(
                v ? trl::L("允许站点发起关联请求")
                  : trl::L("不允许站点发起关联请求"));
        } else if (ch.name.startsWith(QStringLiteral("ReduceBeaconFlag"))) {
            const quint8 v = (quint8)get_bits(gb, 0, 4, 1);
            ch.value = QStringLiteral("%1 - %2").arg(v).arg(
                v ? trl::L("精简信标帧") : trl::L("标准信标帧"));
        } else if (ch.name.startsWith(QStringLiteral("PLCCapInd"))) {
            // PLC能力指示(表51):0支持BPLC / 1支持BPLC和SPLC / 其他保留
            const quint8 v = (quint8)get_bits(gb, 2, 6, 2);
            ch.value = QStringLiteral("%1 - %2").arg(v).arg(
                v == 0 ? trl::L("支持BPLC") : v == 1 ? trl::L("支持BPLC和SPLC") : trl::L("保留"));
        } else if (ch.name.startsWith(QStringLiteral("ChannelNum"))) {
            const quint8 v = (quint8)get_bits(gb, 4, 0, 1);
            ch.value = QStringLiteral("%1 - %2").arg(v).arg(
                v ? trl::L("多通道通信模块") : trl::L("单通道模块"));
        } else if (ch.name.startsWith(QStringLiteral("NetVersion"))) {
            // 网络版本号(表51):0 BPLC版本 / 1 SPLC版本 / 其他保留
            const quint8 v = (quint8)get_bits(gb, 4, 1, 3);
            ch.value = QStringLiteral("%1 - %2").arg(v).arg(
                v == 0 ? trl::L("BPLC版本") : v == 1 ? trl::L("SPLC版本") : trl::L("保留"));
        } else if (ch.name.startsWith(QStringLiteral("BeaconMechStatus"))) {
            const quint8 v = (quint8)get_bits(gb, 4, 4, 1);
            ch.value = QStringLiteral("%1 - %2").arg(v).arg(
                v ? trl::L("分散信标机制") : trl::L("集中信标机制"));
        } else if (ch.name.startsWith(QStringLiteral("DiscoverBeaconEnable"))) {
            const quint8 v = (quint8)get_bits(gb, 4, 5, 1);
            ch.value = QStringLiteral("%1 - %2").arg(v).arg(
                v ? trl::L("允许发送发现信标") : trl::L("不允许发送发现信标"));
        }
    }

    // 信标管理信息(表29):标准信标 gb[6 : gb.size()-5],精简信标(表154)固定头 12B,
    // 管理区自 byte12 起(仅含 0x0E 条目);首字节条目数,随后 头+长度+内容
    const int mgmt_start = reduce_beacon ? 12 : 6;
    const int mgmt_end   = gb.size() - 5;  // BPCS 起点
    if (mgmt_end > mgmt_start + 1) {
        const quint8 item_num = (quint8)gb[mgmt_start];
        auto& mg = group(root.children, QStringLiteral("Beacon Mgmt Info"));
        MsduFieldNode in;
        in.name      = QStringLiteral("ItemNum [8b]");
        in.value     = QString::number(item_num);
        in.rel_start = mgmt_start;
        in.rel_len   = 1;
        mg.children.append(in);

        int pos = mgmt_start + 1;
        for (int n = 0; n < item_num && pos < mgmt_end; ++n) {
            const int head_abs = pos;
            const quint8 head = (quint8)gb[pos++];
            const NW_2026_BeaconItemType head_type =
                static_cast<NW_2026_BeaconItemType>(head);
            // 长度字段大小:时隙分配(0x02)用 2B,其余 1B(表31)
            const int len_bytes =
                (head_type == NW_2026_BeaconItemType::TIME_SLOT_ALLOC
                 || head_type == NW_2026_BeaconItemType::PROXY_ROLE) ? 2 : 1;
            if (pos + len_bytes > mgmt_end) break;
            quint32 len_raw = 0;
            for (int k = 0; k < len_bytes; ++k)
                len_raw |= (quint32)(quint8)gb[pos + k] << (8 * k);
            pos += len_bytes;
            // 条目内容长:时隙分配 len-3(头1+长度2),其余 len-2(头1+长度1)
            const int item_len = (head_type == NW_2026_BeaconItemType::TIME_SLOT_ALLOC)
                                     ? int(len_raw) - 3 : int(len_raw) - 2;
            if (item_len < 0 || pos + item_len > mgmt_end) break;
            const QByteArray it = gb.mid(pos, item_len);
            const int abs0 = pos;
            pos += item_len;

            auto& grp = group(mg.children,
                trl::L("Item[%1] %2 (%3B)").arg(n).arg(beacon_item_head_name(head)).arg(item_len));
            MsduFieldNode hd;
            hd.name      = QStringLiteral("ItemHead [8b]");
            hd.value     = QStringLiteral("0x%1 - %2").arg(head, 2, 16, QChar('0'))
                               .arg(beacon_item_head_name(head));
            hd.rel_start = head_abs;
            hd.rel_len   = 1;
            grp.children.append(hd);
            MsduFieldNode ln;
            ln.name      = (len_bytes == 2) ? QStringLiteral("ItemLen [16b]")
                                            : QStringLiteral("ItemLen [8b]");
            ln.value     = QString::number(len_raw);
            ln.rel_start = head_abs + 1;
            ln.rel_len   = len_bytes;
            grp.children.append(ln);

            switch (head_type) {
            case NW_2026_BeaconItemType::STA_CAPABILITY: {  // 站点能力条目(SPLC 第4部分 表61)
                add_fields(grp.children, it, 0, kStaCapSpec, kStaCapSpecN, abs0);
                // 学习 TEI→SourceMAC(SPLC 第4部分 表61:TEI byte1 12b + SourceMAC byte4 48b;GW_2026 信标同型已学)
                {
                    const quint16 tei = (quint16)get_bits(it, 1, 0, 12);
                    const quint64 mac = get_bits(it, 4, 0, 48);
                    if (tei != 0 && mac)
                        out.tei_mac_pairs.append({tei, mac});
                }
                annotate_unit(grp.children, "LinkMinCommSuccessRate", QStringLiteral("%"));
                for (auto& ch : grp.children) {
                    if (ch.name.startsWith(QStringLiteral("STALine"))) {
                        const quint8 l = (quint8)get_bits(it, 0, 6, 2);
                        ch.value = QStringLiteral("%1 - %2").arg(l).arg(line_name(l));
                    } else if (ch.name.startsWith(QStringLiteral("Role"))) {
                        const quint8 r = (quint8)get_bits(it, 2, 4, 4);
                        ch.value = QStringLiteral("%1 - %2").arg(r).arg(role_name(r));
                    } else if (ch.name.startsWith(QStringLiteral("BeaconUsageFlag"))) {
                        const quint8 v = (quint8)get_bits(it, 3, 0, 8);
                        ch.value = QStringLiteral("%1 - %2").arg(v).arg(
                            v ? trl::L("使用信标评估信道") : trl::L("不使用信标评估信道"));
                    }
                }
                break;
            }
            case NW_2026_BeaconItemType::TIME_SLOT_ALLOC: {  // 时隙分配条目(表34 + 表35/36/37)
                add_fields(grp.children, it, 0, kTsaHeadSpec, kTsaHeadSpecN, abs0);
                annotate_unit(grp.children, "BeaconSlotLen", QStringLiteral("00us"));
                annotate_unit(grp.children, "CSMASlotSize", QStringLiteral("0ms"));
                annotate_unit(grp.children, "TDMASlotLen", QStringLiteral("00us"));
                annotate_unit(grp.children, "BeaconPeriodLen", QStringLiteral("00us"));
                const int noncco = (int)get_bits(it, 0, 0, 8);
                const int csma   = (int)get_bits(it, 2, 0, 8);
                const int bind   = (int)get_bits(it, 7, 0, 8);
                int o = 24;  // 固定头 24B(byte0-23),可变长区从 byte24 起
                // 非中央信标信息(2B/条,表35):TEI 12b + 信标类型 1b + 保留 3b
                if (noncco > 0) {
                    auto& ng = group(grp.children, QStringLiteral("NonCCOBeaconInfo [%1]").arg(noncco));
                    for (int i = 0; i < noncco && o + 2 <= it.size(); ++i) {
                        auto& sg = group(ng.children, QStringLiteral("NonCCO[%1] (2B)").arg(i), QString());
                        const quint16 tei = (quint16)get_bits(it, o, 0, 12);
                        const quint8 bt  = (quint8)get_bits(it, o + 1, 4, 1);
                        slot_leaf(sg.children, QStringLiteral("TEI [12b]"),
                                  QString::number(tei), abs0 + o, 2);
                        QString bt_desc;
                        switch (bt) {
                            case 0: bt_desc = trl::L("发现信标"); break;
                            case 1: bt_desc = trl::L("代理信标"); break;
                            default: break;  // 信标类型为 1 位字段,仅 0/1,default 不可达
                        }
                        slot_leaf(sg.children, QStringLiteral("Beacon Type [1b]"),
                                  QStringLiteral("%1 - %2").arg(bt).arg(bt_desc),
                                  abs0 + o + 1, 1);
                        slot_leaf(sg.children, QStringLiteral("RSV [3b]"),
                                  QString::number((quint8)get_bits(it, o + 1, 5, 3)),
                                  abs0 + o + 1, 1);
                        o += 2;
                    }
                }
                // CSMA 时隙信息(4B/条,表36):CSMA 时隙长度 24b + 相线 8b
                if (csma > 0) {
                    auto& cg = group(grp.children, QStringLiteral("CSMASlotInfo [%1]").arg(csma));
                    for (int i = 0; i < csma && o + 4 <= it.size(); ++i) {
                        auto& sg = group(cg.children, QStringLiteral("CSMA[%1] (4B)").arg(i), QString());
                        const quint32 len = (quint32)get_bits(it, o, 0, 24);
                        const quint8 ln  = (quint8)get_bits(it, o + 3, 0, 8);
                        slot_leaf(sg.children, QStringLiteral("CSMA Slot Len [24b]"),
                                  QStringLiteral("%1 x100us").arg(len), abs0 + o, 3);
                        slot_leaf(sg.children, QStringLiteral("Line [8b]"),
                                  QStringLiteral("%1 - %2").arg(ln).arg(line_name(ln)),
                                  abs0 + o + 3, 1);
                        o += 4;
                    }
                }
                // 绑定 CSMA 时隙信息(4B/条,表37):绑定长度 24b + 相线 8b
                if (bind > 0) {
                    auto& bg = group(grp.children, QStringLiteral("BindingCSMASlotInfo [%1]").arg(bind));
                    for (int i = 0; i < bind && o + 4 <= it.size(); ++i) {
                        auto& sg = group(bg.children, QStringLiteral("Binding[%1] (4B)").arg(i), QString());
                        const quint32 len = (quint32)get_bits(it, o, 0, 24);
                        const quint8 ln  = (quint8)get_bits(it, o + 3, 0, 8);
                        slot_leaf(sg.children, QStringLiteral("Binding Slot Len [24b]"),
                                  QStringLiteral("%1 x100us").arg(len), abs0 + o, 3);
                        slot_leaf(sg.children, QStringLiteral("Line [8b]"),
                                  QStringLiteral("%1 - %2").arg(ln).arg(line_name(ln)),
                                  abs0 + o + 3, 1);
                        o += 4;
                    }
                }
                break;
            }
            case NW_2026_BeaconItemType::ROUTE_PARAM: {  // 路由参数条目(表38)
                add_fields(grp.children, it, 0, kRouteParamSpec, kRouteParamSpecN, abs0);
                annotate_unit(grp.children, "RoutePeriod", QStringLiteral("s"));
                annotate_unit(grp.children, "NextRouteEstTime", QStringLiteral("s"));
                break;
            }
            case NW_2026_BeaconItemType::BAND_CHANGE: {  // 频段变更条目(表39)
                add_fields(grp.children, it, 0, kBandChangeSpec, kBandChangeSpecN, abs0);
                annotate_unit(grp.children, "SwitchRemainTime", QStringLiteral("ms"));
                for (auto& ch : grp.children) {
                    if (ch.name.startsWith(QStringLiteral("TargetBand"))) {
                        const quint8 b = (quint8)get_bits(it, 0, 0, 8);
                        ch.value = QStringLiteral("%1 - %2").arg(b).arg(
                            b <= 2 ? QStringLiteral("Band %1").arg(b) : trl::L("保留"));
                    }
                }
                break;
            }
            case NW_2026_BeaconItemType::CALENDAR_SYNC: {  // 万年历同步条目(表40)
                add_fields(grp.children, it, 0, kCalendarSyncSpec, kCalendarSyncSpecN, abs0);
                for (auto& ch : grp.children) {
                    if (ch.name.startsWith(QStringLiteral("CCOCalendarTime"))) {
                        ch.value += trl::L(" s (自 2000-01-01 00:00:00 起)");
                    } else if (ch.name.startsWith(QStringLiteral("CCOCalendarNTB"))) {
                        ch.value += trl::L(" (40ns/tick)");
                    }
                }
                break;
            }
            case NW_2026_BeaconItemType::BAND_PROBE: {  // 频段探测条目(附录B 表B-1)
                add_fields(grp.children, it, 0, kBandProbeSpec, kBandProbeSpecN, abs0);
                for (auto& ch : grp.children) {
                    if (ch.name.startsWith(QStringLiteral("ProbeBand"))) {
                        const quint8 b = (quint8)get_bits(it, 0, 0, 8);
                        ch.value = QStringLiteral("%1 - %2").arg(b).arg(
                            b == 1 ? QStringLiteral("Band 1") : trl::L("保留"));
                    } else if (ch.name.startsWith(QStringLiteral("BindCSMASlotLID"))) {
                        ch.value += trl::L(" (固定77)");
                    }
                }
                break;
            }
            case NW_2026_BeaconItemType::ROUTE_PARAM_RF: {  // 无线路由参数条目(坐标同第2部分表152)
                add_fields(grp.children, it, 0, kRfRouteParamSpec, kRfRouteParamSpecN, abs0);
                annotate_unit(grp.children, "RFDiscoverPeriod", QStringLiteral("s"));
                annotate_unit(grp.children, "RFAgingCycles", trl::L(" 周期"));
                break;
            }
            case NW_2026_BeaconItemType::RF_CHANNEL_CHANGE: {  // 无线信道变更条目(坐标同第2部分表153)
                add_fields(grp.children, it, 0, kRfChannelChangeSpec, kRfChannelChangeSpecN, abs0);
                annotate_unit(grp.children, "SwitchRemainTime", QStringLiteral("ms"));
                break;
            }
            case NW_2026_BeaconItemType::SIMPLE_STA_SLOT: {  // 精简信标站点信息及时隙条目(坐标同 BPLC 第2部分 表155)
                add_fields(grp.children, it, 0, kLiteStaSlotSpec, kLiteStaSlotSpecN, abs0);
                // 学习 TEI→BeaconSTAMAC(BPLC 第2部分 表155:TEI byte0 12b + BeaconSTAMAC byte4 48b;GW_2026 信标同型已学)
                {
                    const quint16 tei = (quint16)get_bits(it, 0, 0, 12);
                    const quint64 mac = get_bits(it, 4, 0, 48);
                    if (tei != 0 && mac)
                        out.tei_mac_pairs.append({tei, mac});
                }
                annotate_unit(grp.children, "CSMASlotLen", QStringLiteral("ms"));
                for (auto& ch : grp.children) {
                    if (ch.name.startsWith(QStringLiteral("Role"))) {
                        const quint8 r = (quint8)get_bits(it, 3, 0, 4);
                        ch.value = QStringLiteral("%1 - %2").arg(r).arg(role_name(r));
                    } else if (ch.name.startsWith(QStringLiteral("CarrierBand"))) {
                        const quint8 b = (quint8)get_bits(it, 8, 4, 2);
                        ch.value = QStringLiteral("%1 - %2").arg(b).arg(lite_band_name(b));
                    }
                }
                break;
            }
            case NW_2026_BeaconItemType::BEACON_MECH_SWITCH: {  // 信标机制切换条目(表71,内容 5B)
                add_fields(grp.children, it, 0, kBeaconMechSwitchSpec, kBeaconMechSwitchSpecN, abs0);
                for (auto& ch : grp.children) {
                    if (ch.name.startsWith(QStringLiteral("MechID"))) {
                        const quint8 m = (quint8)it[0];
                        ch.value = (m == 0) ? QStringLiteral("0 - %1").arg(trl::L("集中信标机制"))
                                 : (m == 1) ? QStringLiteral("1 - %1").arg(trl::L("分散信标机制"))
                                            : QStringLiteral("%1 - %2").arg(m).arg(trl::L("保留"));
                    } else if (ch.name.startsWith(QStringLiteral("SwitchNTB"))) {
                        ch.value += QStringLiteral(" (NTB)");
                    }
                }
                break;
            }
            case NW_2026_BeaconItemType::PROXY_ROLE: {  // 代理角色条目(表72,长度字段 2B,可变长)
                // 内容:N×12b 代理节点 TEI 连续位流;代理站点个数为奇数时末尾 4b 保留对齐
                const int content_bits = it.size() * 8;
                int n = content_bits / 12;
                const bool odd_pad = (content_bits % 12) != 0;
                if (odd_pad) n = (content_bits - 4) / 12;
                for (int i = 0; i < n; ++i) {
                    auto& pg = group(grp.children, QStringLiteral("ProxyTEI[%1]").arg(i));
                    MsduFieldNode t;
                    t.name  = QStringLiteral("TEI [12b]");
                    // get_bits 签名 (data, byte_off, bit_off, bits):12b 跨 nibble 须换算字节/位偏移
                    t.value = QString::number((quint16)get_bits(it, (i * 12) / 8, (i * 12) % 8, 12));
                    t.rel_start = abs0 + (i * 12) / 8;
                    t.rel_len   = ((i * 12) % 8 + 12 + 7) / 8;
                    pg.children.append(t);
                    pg.rel_start = t.rel_start;
                    pg.rel_len   = t.rel_len;
                }
                if (odd_pad) {
                    MsduFieldNode r;
                    r.name  = QStringLiteral("RSV [4b]");
                    r.value = QString::number((quint8)get_bits(it, (n * 12) / 8, (n * 12) % 8, 4));
                    r.rel_start = abs0 + (n * 12) / 8;
                    r.rel_len   = 1;
                    grp.children.append(r);
                }
                break;
            }
            default: {  // 厂家自定义/保留:内容 hex
                MsduFieldNode body;
                body.name      = QStringLiteral("Content [%1B]").arg(item_len);
                body.value     = QString::fromLatin1(it.toHex(' ').toUpper());
                body.rel_start = abs0;
                body.rel_len   = item_len;
                grp.children.append(body);
                break;
            }
            }
        }

        // 管理条目之后的填充区(条目消费终点 pos 到 BPCS 前):正常全 0x00,
        // 非零时展示前 8B 便于发现未识别条目/异常。
        if (pos < mgmt_end) {
            const int pad_len = mgmt_end - pos;
            bool all_zero = true;
            for (int k = pos; k < mgmt_end && all_zero; ++k)
                all_zero = (gb[k] == 0);
            MsduFieldNode pad;
            pad.name = QStringLiteral("PB Padding");
            pad.value = all_zero
                ? QStringLiteral("%1 B (0x00 fill)").arg(pad_len)
                : trl::L("%1 B (含非 0x00: %2 ...)")
                      .arg(pad_len)
                      .arg(QString::fromLatin1(gb.mid(pos, qMin(pad_len, 8)).toHex(' ')));
            pad.rel_start = pos;
            pad.rel_len   = pad_len;
            root.children.append(pad);
        }
    }

    // BPCS(帧载荷校验序列,32-bit)
    {
        MsduFieldNode crc;
        crc.name      = QStringLiteral("BPCS [32b]");
        crc.value     = QStringLiteral("0x%1 %2")
                            .arg(bpcs, 8, 16, QChar('0'))
                            .arg(bpcs_ok ? QStringLiteral("OK") : QStringLiteral("FAIL"));
        crc.rel_start = gb.size() - 5;
        crc.rel_len   = 4;
        root.children.append(crc);
    }
    // 保留字节(1B)
    {
        MsduFieldNode rsv;
        rsv.name      = QStringLiteral("RSV [8b]");
        rsv.value     = QStringLiteral("0x%1").arg((quint8)gb[gb.size() - 1], 2, 16, QChar('0'));
        rsv.rel_start = gb.size() - 1;
        rsv.rel_len   = 1;
        root.children.append(rsv);
    }

    // 物理块检查序列(24-bit,块尾 3B;覆盖 PB 头+块体+保留,表7)
    if (payload.size() >= 16 + pbsize) {
        const quint8* blk = reinterpret_cast<const quint8*>(payload.constData()) + 16;
        quint32 stored = (quint32)blk[pbsize - 3]
                       | ((quint32)blk[pbsize - 2] << 8)
                       | ((quint32)blk[pbsize - 1] << 16);
// crc24_lsb 内部遍历 len-3 字节;此处传 pb_size(全长)即校验块头+块体+尾保留,
// 末 3B 为本 CRC 自身(crc.h 约定,勿传 pb_size-3 否则少算 3B)
        const bool ok24 = (stored == crc24_lsb(blk, pbsize));
        MsduFieldNode pbc;
        pbc.name      = QStringLiteral("PB CRC24");
        pbc.value     = QStringLiteral("0x%1 %2")
                            .arg(stored, 6, 16, QChar('0'))
                            .arg(ok24 ? QStringLiteral("OK") : QStringLiteral("FAIL"));
        pbc.rel_start = pbsize - 3;  // 相对载荷区起点(blk = payload+16)
        pbc.rel_len   = 3;
        root.children.append(pbc);
    }

    return out;
}

// ===== i18n:文件级 中→英 显示词典(仅显示翻译;未命中回退中文) =====
namespace {
struct I18nReg {
    I18nReg() {
        trl::register_en("信标 BPCS CRC32:%1", "BEACON BPCS CRC32:%1");
        trl::register_en("成功", "OK");
        trl::register_en("失败", "FAIL");
        trl::register_en("发现信标", "Discovery Beacon");
        trl::register_en("代理信标", "Proxy Beacon");
        trl::register_en("中央信标", "Central Beacon");
        trl::register_en("保留", "Reserved");
        trl::register_en("组网完成", "Network established");
        trl::register_en("组网未完成", "Network not established");
        trl::register_en("使能网络评估", "Network estimation enabled");
        trl::register_en("未使能网络评估", "Network estimation disabled");
        trl::register_en("允许站点发起关联请求", "Association request allowed");
        trl::register_en("不允许站点发起关联请求", "Association request not allowed");
        trl::register_en("精简信标帧", "Reduced beacon frame");
        trl::register_en("标准信标帧", "Standard beacon frame");
        trl::register_en("支持BPLC", "Supports BPLC");
        trl::register_en("支持BPLC和SPLC", "Supports BPLC and SPLC");
        trl::register_en("单通道模块", "Single-channel module");
        trl::register_en("多通道通信模块", "Multi-channel module");
        trl::register_en("BPLC版本", "BPLC version");
        trl::register_en("SPLC版本", "SPLC version");
        trl::register_en("集中信标机制", "Centralized beacon mechanism");
        trl::register_en("分散信标机制", "Distributed beacon mechanism");
        trl::register_en("不允许发送发现信标", "Discovery beacon TX disabled");
        trl::register_en("允许发送发现信标", "Discovery beacon TX enabled");
        trl::register_en("站点能力条目", "STA Capability Item");
        trl::register_en("时隙分配条目", "Time Slot Allocation Item");
        trl::register_en("路由参数条目", "Route Parameter Item");
        trl::register_en("频段变更条目", "Band Change Item");
        trl::register_en("频段探测条目", "Band Probe Item");
        trl::register_en("万年历同步条目", "Calendar Sync Item");
        trl::register_en("集中信标机制", "Central beacon mechanism");
        trl::register_en("分散信标机制", "Distributed beacon mechanism");
        trl::register_en(" 周期", " cycle(s)");
        trl::register_en("无线路由参数条目", "RF Route Parameter Item");
        trl::register_en("无线信道变更条目", "RF Channel Change Item");
        trl::register_en("精简信标站点信息及时隙条目", "Reduced STA Info & Slot Item");
        trl::register_en("信标机制切换条目", "Beacon Mechanism Switch Item");
        trl::register_en("代理角色条目", "Proxy Role Item");
        trl::register_en("厂家自定义条目", "Vendor-defined Item");
        trl::register_en("保留条目", "Reserved Item");
        trl::register_en("Item[%1] %2 (%3B)", "Item[%1] %2 (%3B)");
        trl::register_en("全相线", "All lines");
        trl::register_en("A相线", "Line A");
        trl::register_en("B相线", "Line B");
        trl::register_en("C相线", "Line C");
        trl::register_en("未知", "Unknown");
        trl::register_en("使用信标评估信道", "Beacon used for channel estimation");
        trl::register_en("不使用信标评估信道", "Beacon not used for channel estimation");
        trl::register_en(" s (自 2000-01-01 00:00:00 起)", " s (since 2000-01-01 00:00:00)");
        trl::register_en(" (40ns/tick)", " (40ns/tick)");
        trl::register_en(" (固定77)", " (fixed 77)");
        trl::register_en("%1 B (含非 0x00: %2 ...)", "%1 B (non-zero bytes: %2 ...)");
    }
};
const I18nReg g_i18n_reg_nw_beacon;
}  // namespace
