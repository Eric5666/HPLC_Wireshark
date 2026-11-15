/// @file gw_2022_tree.h
/// @brief 国网 GW_2022 协议字段树构建器(IProtocolTreeBuilder 实现)
/// @details 国网双模标准 2022(202203)的 MPDU Base + 各帧型 FCH 字段树。
///          字段坐标/语义与 GW_2022_Parser 解析结果(MpduInfo)严格一致。
#ifndef BPLC_GW_2022_TREE_H
#define BPLC_GW_2022_TREE_H

#include "protocol_tree_builder.h"

/// 国网 GW_2022 定界符类型(FCH byte0 bit0-2)
enum class GW_2022_FrameType : quint8 {
    BEACON = 0,  ///< 信标帧
    SOF    = 1,  ///< SOF 帧
    ACK    = 2,  ///< 选择确认帧
    COORD  = 3,  ///< 网间协调帧
};

/// 国网 GW_2022 ACK 扩展帧类型(FCH byte12 bit0-3,表25/表36)
/// @note 表25(载波)/表36(无线)均仅定义 0=选择确认帧,其余为保留;
///       国网无南网 NW_2021 的"网络搜索/同步"扩展类型。
enum class GW_2022_AckExtType : quint8 {
    Normal = 0,  ///< 选择确认帧
};

/// 国网 GW_2022 标准版本号(FCH byte12 bit4-7,表16)
enum class GW_2022_Version : quint8 {
    THIS_STANDARD = 0,  ///< 本标准(表16);其他=待演进
};

/// 国网 GW_2022 ACK 常规收包结果(RxRes,FCH byte4 bit0-3)
enum class GW_2022_AckRxRes : quint8 {
    RECEIPT_OK   = 0,  ///< 接收成功(所有 PB CRC 通过)
    RECEIPT_FAIL = 1,  ///< 接收失败(≥1 块 CRC 未过)
};

/// 国网双模标准 2022 字段树构建器
class GW_2022_TreeBuilder : public IProtocolTreeBuilder {
public:
    ProtocolVariant variant() const override { return ProtocolVariant::GW_2022; }
    void build(QTreeWidgetItem* root, const PacketEntry& e) override;
};

#endif  // BPLC_GW_2022_TREE_H
