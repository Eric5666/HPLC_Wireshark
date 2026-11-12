/// @file nw_2021_tree.h
/// @brief 南网 NW_2021 协议字段树构建器(IProtocolTreeBuilder 实现)
/// @details 南网双模 2021 报批版的 MPDU Base + 各帧型 FCH 字段树。
///          字段坐标/语义与 NW_2021_Parser 解析结果(MpduInfo)严格一致。
#ifndef BPLC_NW_2021_TREE_H
#define BPLC_NW_2021_TREE_H

#include "protocol_tree_builder.h"

/// 南网 NW_2021 定界符类型(FCH byte0 bit0-2,表11)
enum class NW_2021_FrameType : quint8 {
    BEACON = 0,  ///< 信标帧
    SOF    = 1,  ///< SOF 帧
    ACK    = 2,  ///< 选择确认帧
    COORD  = 3,  ///< 网间协调帧
};

/// 南网 NW_2021 ACK 扩展帧类型(FCH byte12 bit0-3,表21)
/// @note 表21 仅定义 0/1/2,其余为保留;南网无国网 GW_2022 的"无线切频"扩展类型。
enum class NW_2021_AckExtType : quint8 {
    Normal        = 0,  ///< 选择确认帧
    Search        = 1,  ///< 网络搜索帧(抄控器)
    Sync          = 2,  ///< 同步帧(抄控器)
};

/// 南网双模 2021 报批版字段树构建器
class NW_2021_TreeBuilder : public IProtocolTreeBuilder {
public:
    ProtocolVariant variant() const override { return ProtocolVariant::NW_2021; }
    void build(QTreeWidgetItem* root, const PacketEntry& e) override;
};

#endif  // BPLC_NW_2021_TREE_H
