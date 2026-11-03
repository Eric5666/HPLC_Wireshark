/// @file protocol_tree_builder.h
/// @brief 协议树字段构建器抽象接口 + 协议无关的树渲染工具
/// @details 与协议解析器(IProtocolParser)同构:国网 GW_2022/GW_2026 / 南网 NW_2021/NW_2026
///          各实现一个 IProtocolTreeBuilder 子类(独立源文件,放各自协议目录),
///          工厂按 variant 实例化。公共渲染工具(加节点/位域节点/MSDU 字段树
///          渲染)协议无关,两实现共用。
#ifndef PROTOCOL_TREE_BUILDER_H
#define PROTOCOL_TREE_BUILDER_H

#include "bplcframe.h"
#include "common/protocolvariant.h"
#include <QTreeWidget>
#include <QColor>
#include <QVector>
#include <memory>

// ── 公共渲染工具(协议无关) ───────────────────────────────

/// 添加一个普通字段节点(byte_start/byte_len 用于 HexView 高亮;-1=无字节映射)
QTreeWidgetItem* tree_add_item(QTreeWidgetItem* parent, const QString& field,
                               const QString& value,
                               int byte_start = -1, int byte_len = 0);

/// 添加一个位域字段节点:字段名带 [Nbit] 标注,换算为覆盖字节区间用于高亮
QTreeWidgetItem* tree_add_bit_field(QTreeWidgetItem* parent, const QString& field,
                                    const QString& value,
                                    int byte_idx, int bit_off, int bit_len);

/// MSDU 字段树 raw 偏移映射参数(跨块/单块换算)
struct MsduRawMap {
    int base;        ///< 单块时 buffer[0] 的 raw 偏移;跨块=-1
    int pb_num;      ///< 物理块数(跨块映射用)
    int pb_size;     ///< 物理块大小(跨块映射用)
    int fch_size;    ///< 控制头长度(16)
    int header_len;  ///< PB 头长度(国网 1 / 南网 4)
    int body;        ///< 每块数据字节数(国网 pb_size-4 / 南网 pb_size-8)
    QVector<int> slot_raw_offset; ///< 拼接序(序列号序)→ 各块块体 raw 起点;
                                  ///< 空=退回按到达位置推算(单块/无序列号/重排失败)
};

/// 由 PB 到达序头字节推导「拼接序(序列号序)→ 块体 raw 起点」槽位表。
/// @details 帧内按序列号重排后,拼接序 ≠ raw 块序,旧的 rel/body 推块号会指错块。
///          不新增持久化字段:pb_heads 已按到达序持久化块头原始字节,重排后的块序
///          可据此重建,保证会话文件重载后高亮映射一致。
/// @param seq_mask 国网 0x3F(pb_head 低 6 位,bit7=END/bit6=START)/
///                 南网 0xFF(byte0 全 8 位;16bit 序列号低字节)
/// @return 拼接序→raw 块体起点;任一序列号越界/重复(含"全同"兜底)返回空表,
///         调用方退回按到达位置映射。
QVector<int> tree_slot_raw_offsets(const MpduInfo& mpdu, int fch_size,
                                   int header_len, quint8 seq_mask);

// QTreeWidgetItem 的 UserRole 数据角色(树渲染工具统一约定):
//   0: 主高亮区间起点 start(单块/向后兼容;跨块取首片段起点,-1=无映射)
//   1: 主高亮区间长度 len
//   2: 多高亮片段列表 QVariantList(每元素 QList<int>{start,len};跨块时多个)
//   3: 复制字节 QByteArray(字段重组字节;跨块时与 raw 片段不同,复制用)
enum TreeDataRole : int {
    kRoleStart  = Qt::UserRole + 0,   ///< 主区间起点
    kRoleLen    = Qt::UserRole + 1,   ///< 主区间长度
    kRoleRanges = Qt::UserRole + 2,   ///< 多高亮片段 QVariantList
    kRoleBytes  = Qt::UserRole + 3,   ///< 复制字节 QByteArray
};

/// 递归渲染解析器生成的 MSDU 字段树(协议无关;body/header_len 由调用方按协议填充)
/// msdu_body 为重组后的完整 MSDU 字节(供跨块字段复制其重组内容)
void tree_render_msdu(QTreeWidgetItem* parent, const QVector<MsduFieldNode>& nodes,
                      const MsduRawMap& m, const QByteArray& msdu_body);

/// 把相对重组 buffer 的 [rel_start,rel_start+rel_len) 映射到 raw 偏移;
/// 跨块且字段越块边界(或越界)返回 -1(无法单段高亮)。供 MSDU 分组节点设高亮范围。
int tree_msdu_raw_of(const MsduRawMap& m, int rel_start, int rel_len);

/// 把相对重组 buffer 的 [rel_start,rel_start+rel_len) 映射为 raw 里的高亮片段列表;
/// 跨块时返回多个片段(每个块内连续);空列表=无法映射。供字段多段高亮/复制定位。
QList<QPair<int, int>> tree_msdu_raw_ranges(const MsduRawMap& m,
                                            int rel_start, int rel_len);

/// 给分组节点(如 "MSDU (Reassembled)")设置多片段高亮 + 复制字节(协议无关)
void tree_apply_msdu_range(QTreeWidgetItem* it, const MsduRawMap& m,
                           int rel_start, int rel_len, const QByteArray& msdu_body);

/// 类型字段着色:按字段名判断报文类型字段类别。
/// 返回 0=管理消息类型(MMeType) 1=应用层报文类型(APP) 2=MSDU 类型;-1=非类型字段。
int tree_type_field_category(const QString& name);

/// 按类别+数值生成稳定颜色(色相环散列:同类别同数值同色,不同数值尽量不同色),
/// 供类型字段前景着色,深浅主题下均可读。
QColor tree_type_field_color(int category, quint64 value);

/// 给类型字段节点按类别+值着色;非类型字段不动。
/// 内置 tree_render_msdu 与插件通用渲染共用,保证着色行为一致。
void tree_apply_type_color(QTreeWidgetItem* it, const QString& name,
                           const QString& value);

// ── 字段树构建器抽象接口 ────────────────────────────────

/// 协议特有字段树构建器(国网 GW_2022 / 南网 NW_2021 各实现一个)
class IProtocolTreeBuilder {
public:
    virtual ~IProtocolTreeBuilder() = default;
    virtual ProtocolVariant variant() const = 0;
    /// 构建协议特有字段树:MPDU Base + BEACON/SOF/ACK/COORD FCH 字段 + PB 块 + MSDU 挂载
    /// (顶层 "Frame"/"Physical" 公共部分由 ProtocolTree 构建,不在此)
    virtual void build(QTreeWidgetItem* root, const PacketEntry& e) = 0;
};

/// 工厂:按 variant 实例化对应字段树构建器(实现在 protocolfactory.cpp)
std::unique_ptr<IProtocolTreeBuilder> make_tree_builder(ProtocolVariant v);

#endif // PROTOCOL_TREE_BUILDER_H
