/// @file nw_app_bid.h
/// @brief 南网应用层业务标识(表9)与传输方向(表8)释义 —— nw_2021 / nw_2026 共用(单一实现)
/// @details 应用层协议两版是同一套(2026 为 2021 的超集),表9 释义只在本文件维护一份,
///          两版 parse_app 都调这里 —— 补业务时只改这一处,不会各自漂移。
///
///          为什么做成 header-only(而非 .h + .cpp):本模块既有约定是 header-only
///          (crc.h / bcd.h / fieldspec.h / fieldtools.h / pb_assembler.h 全是),
///          原因是全仓 30 多个探针的 .pro / build.sh 直接编译 msdu parser 源文件;
///          若引入 .cpp 就必须逐个改这些构建文件,漏一个即 undefined reference。
///
///          入参用**纯数值**,不依赖任一协议自己的枚举,调用方 static_cast<quint8> 传入。
#ifndef NW_APP_BID_H
#define NW_APP_BID_H

#include "i18n.h"

#include <QString>
#include <QtGlobal>

namespace nw_app_bid_detail {

// 报文端口号(6.1 表1)
constexpr quint8 kPortBusiness = 0x11;  ///< 业务报文端口
constexpr quint8 kPortMgmt     = 0x13;  ///< 管理报文端口

// 帧类型域(6.3.1.3 表7)
constexpr quint8 kTypeAckNack     = 0x0;
constexpr quint8 kTypeDataForward = 0x1;
constexpr quint8 kTypeCommand     = 0x2;
constexpr quint8 kTypeEventReport = 0x3;
constexpr quint8 kTypeReaderFrame = 0x4;
constexpr quint8 kTypeBroadcast   = 0x5;
constexpr quint8 kTypeSubscribe   = 0x6;   ///< 数据订阅业务(表9 只有 0x11/0x00 一个组合)

/// @brief i18n 中→英注册(只执行一次;文案与 trl::L 同在本文件,成对维护)
inline void ensure_i18n() {
    static const bool kOnce = [] {
        trl::register_en("确认", "ACK");
        trl::register_en("否认", "NACK");
        trl::register_en("数据透传至设备", "Data Forward to Device");
        trl::register_en("数据透传至模块", "Data Forward to Module");
        trl::register_en("并发抄读端设备", "Concurrent Meter Reading");
        trl::register_en("站点间通信", "Inter-Station Communication");
        trl::register_en("查询终端搜索结果", "Query Meter Search Result");
        trl::register_en("下发搜索终端列表", "Distribute Meter Search List");
        trl::register_en("文件传输", "File Transmission");
        trl::register_en("允许/禁止从节点事件", "Enable/Disable Node Event");
        trl::register_en("从节点重启", "Node Restart");
        trl::register_en("从节点信息查询", "Node Info Query");
        trl::register_en("下发通信地址映射表列表", "Issue Comm Address Map List");
        trl::register_en("查询从节点运行状态信息", "Query Node Running Status");
        trl::register_en("查询从节点信道信息", "Query Node Channel Info");
        trl::register_en("查询模块运行参数", "Query Module Running Parameters");
        trl::register_en("台区户变关系/相位识别", "Transformer-Station Phase Identification");
        trl::register_en("测试帧", "Test Frame");
        trl::register_en("电表事件主动上报", "Meter Event Report");
        trl::register_en("停上电事件上报", "Power On/Off Event Report");
        trl::register_en("设备事件主动上报", "Device Event Report");
        trl::register_en("通信模块事件上报", "Communication Module Event Report");
        trl::register_en("抄控器-CCO协议", "Handheld Reader-CCO Protocol");
        trl::register_en("数据透传串口转发", "Data Forward via UART");
        trl::register_en("数据订阅业务", "Data Subscription");
        return true;
    }();
    (void)kOnce;
}

}  // namespace nw_app_bid_detail

/// @brief 传输方向位(6.3.1.6 表8)符号:D15=0 下行 ↓ / D15=1 上行 ↑
inline QString nw_app_dir_symbol(quint8 trans_direction_flag) {
    return trans_direction_flag ? QStringLiteral("↑") : QStringLiteral("↓");
}

/// @brief 应用层业务标识释义(应用层 6.3.2 表9;2021/2026 共用,2026 为超集)
/// @param port_num    报文端口号(6.1 表1:0x11 业务报文 / 0x13 管理报文)
/// @param packet_type 帧类型域(6.3.1.3 表7:0 确认/否认、1 数据传输、2 命令、3 主动上报、
///                     4 抄控器协议、5 广播命令、6 数据订阅业务、0xE 厂家调试、0xF 厂测)
/// @param business_id 业务标识(6.3.2 表9)
/// @return 业务名;当"报文端口号+业务标识"组合在表9 中标 "-" 时属保留,返回空 QString,
///         调用方只显示裸 BID(不带业务名、不带方向)
/// @note   表9 必须按 (端口号, 业务标识) **联合判定**:同一 BID 在不同端口下含义不同
///         (如 0x00:0x11 = 数据透传至设备、0x13 = 其它),端口与 BID 不匹配即是保留组合。
inline QString nw_app_bid_name(quint8 port_num, quint8 packet_type, quint8 business_id) {
    using namespace nw_app_bid_detail;
    ensure_i18n();
    const bool business_port = (port_num == kPortBusiness);
    const bool mgmt_port     = (port_num == kPortMgmt);
    switch (packet_type) {
    case kTypeAckNack:   // 确认/否认(表9:仅端口 0x11)
        if (!business_port) return QString();
        if (business_id == 0x00) return trl::L("确认");
        if (business_id == 0x01) return trl::L("否认");
        return QString();                                  // 0x02~0xFF 保留
    case kTypeDataForward:   // 数据传输(表9 四组合,端口必须匹配)
        if (business_id == 0x00) return business_port ? trl::L("数据透传至设备") : QString();
        if (business_id == 0x01) return mgmt_port     ? trl::L("数据透传至模块") : QString();
        if (business_id == 0x02) return business_port ? trl::L("并发抄读端设备") : QString();
        if (business_id == 0x03) return mgmt_port     ? trl::L("站点间通信")     : QString();
        return QString();                                  // 0x04~0xFF 保留
    case kTypeCommand:   // 命令(表9:端口号,BID 联合判定)
        switch (business_id) {
        // 表9 通信管理业务(端口 0x11)
        case 0x00: return business_port ? trl::L("查询终端搜索结果") : QString();
        case 0x01: return business_port ? trl::L("下发搜索终端列表") : QString();
        // 表9 功能性业务(端口 0x11)
        case 0x02: return business_port ? trl::L("文件传输") : QString();
        case 0x03: return business_port ? trl::L("允许/禁止从节点事件") : QString();
        // 表9 通信管理业务(端口 0x11)
        case 0x04: return business_port ? trl::L("从节点重启") : QString();
        case 0x05: return business_port ? trl::L("从节点信息查询") : QString();
        case 0x06: return business_port ? trl::L("下发通信地址映射表列表") : QString();
        // 表9 通信管理业务(端口 0x13)
        case 0x07: return mgmt_port ? trl::L("查询从节点运行状态信息") : QString();
        case 0x08: return mgmt_port ? trl::L("查询从节点信道信息") : QString();
        case 0x09: return mgmt_port ? trl::L("查询模块运行参数") : QString();
        // 表9 通信管理业务(端口 0x11)
        case 0x10: return business_port ? trl::L("台区户变关系/相位识别") : QString();
        case 0xF0: return business_port ? trl::L("测试帧") : QString();
        default:   return QString();
        }
    case kTypeEventReport:   // 主动上报(表9:端口号,BID 联合判定)
        if (business_id == 0x00) return business_port ? trl::L("电表事件主动上报") : QString();
        if (business_id == 0x01) return mgmt_port ? trl::L("停上电事件上报") : QString();
        // 0x02 双端口:0x11=设备事件、0x13=通信模块事件(表9 两个端口各一行)
        if (business_id == 0x02) {
            if (mgmt_port) return trl::L("通信模块事件上报");
            if (business_port) return trl::L("设备事件主动上报");
        }
        return QString();                                  // 0x03~0xFF 保留
    case kTypeReaderFrame:   // 抄控器协议(表9:仅端口 0x11)
        if (!business_port) return QString();
        if (business_id == 0x00) return trl::L("抄控器-CCO协议");
        if (business_id == 0x01) return trl::L("数据透传串口转发");
        return QString();
    case kTypeBroadcast:     // 广播命令(表9:端口号,BID 联合判定)
        switch (business_id) {
        case 0x04: return business_port ? trl::L("从节点重启") : QString();             // 0x11
        case 0x05: return business_port ? trl::L("从节点信息查询") : QString();         // 0x11
        case 0x07: return mgmt_port ? trl::L("查询从节点运行状态信息") : QString();     // 0x13
        case 0x08: return mgmt_port ? trl::L("查询从节点信道信息") : QString();         // 0x13
        default:   return QString();
        }
    case kTypeSubscribe:     // 数据订阅业务(表9:仅 0x11/0x00)
        if (business_port && business_id == 0x00) return trl::L("数据订阅业务");
        return QString();                                  // 其余保留
    default:
        return QString();
    }
}

#endif // NW_APP_BID_H
