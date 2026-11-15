/// @file protocoltree.h
/// @brief 协议树控件(分层显示 MPDU 字段)
/// @details 本控件只负责:顶层 "Frame"/"Physical" 公共节点 + 委托
///          IProtocolTreeBuilder 构建协议特有字段树。协议字段逻辑全部在
///          各 *_tree.cpp 独立源文件中,本控件不做任何协议判断。
///          构建器按帧协议(PacketEntry::protocol)分派,与会话配置无关:
///          解析器会把帧委托给旧版解析器(GW_2026→GW_2022、NW_2026→NW_2021),
///          此时 PacketEntry::protocol 已同步为被委托方,字段树据此选布局。
#ifndef BPLC_PROTOCOLTREE_H
#define BPLC_PROTOCOLTREE_H

#include "bplcframe.h"
#include "protocol_tree_builder.h"
#include <QTreeWidget>
#include <QPair>
#include <map>
#include <memory>

class ProtocolTree : public QTreeWidget {
    Q_OBJECT
public:
    explicit ProtocolTree(QWidget* parent = nullptr);

    void show_packet(const PacketEntry& entry);
    QPair<int, int> selected_byte_range() const { return m_selected_range; }

signals:
    void range_selected(int start, int len);
    /// 多片段高亮(跨块字段多个 raw 片段) + 复制字节(字段重组内容)
    void ranges_selected(const QList<QPair<int, int>>& ranges, const QByteArray& copy_bytes);

private:
    QPair<int, int> m_selected_range;
    /// @brief 按帧协议缓存的字段树构建器(key = PacketEntry::protocol,最多 4 个)
    /// @details 逐帧判定 + 实例常驻:每次判定重做(不锁定首帧结论),
    ///          对象懒创建后复用。四个构建器均无成员状态,复用无副作用。
    std::map<quint8, std::unique_ptr<IProtocolTreeBuilder>> m_builders;

    /// @brief 取本帧协议对应的构建器(懒创建并缓存)
    IProtocolTreeBuilder* builder_for(const PacketEntry& e);
};

#endif  // BPLC_PROTOCOLTREE_H
