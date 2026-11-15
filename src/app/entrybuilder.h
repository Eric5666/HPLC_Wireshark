/// @file entrybuilder.h
/// @brief 帧列表条目构建:解析线程预构建 + GUI 线程补序号/时间
/// @details 解析线程(DispatcherWorker)把 ParseResult 直接移动进 PacketEntry,
///          并预先生成可搜索全文尾部与插件喂帧模板;GUI 线程只分配帧序号、
///          定时间/Delta、拼接搜索文本并分发给拓扑/插件,不再逐字段深拷贝。
#ifndef BPLC_ENTRYBUILDER_H
#define BPLC_ENTRYBUILDER_H

#include "bplcframe.h"
#include "iprotocolparser.h"
#include <QMetaType>
#include <QSharedPointer>
#include <QString>

class TopoController;
class LocalPluginEngine;

/// @brief 解析线程预构建好的一帧(经共享指针跨线程投递,GUI 线程独占消费)
/// @details entry 中 index/epoch_ms/delta_us/search_text 由 GUI 线程补齐,
///          其余解析派生字段已就位。
struct PreparedEntry {
    PacketEntry entry;              ///< 解析派生字段已移入(序号/时间/Delta/搜索文本待补)
    QString     search_tail;        ///< make_search_text_tail(entry):不含帧序号的搜索文本
    qint64      display_delta_us = -1; ///< 解析器给出的显示 Delta(µs);-1=插件解析器未算
    BplcFrame   plugin_frame;       ///< 插件喂帧模板(decoded_index/decoded_epoch_ms 待补)
    quint64     credit_gen = 0;     ///< 源帧的背压额度代号(GUI 归还额度时原样交回)
};
using PreparedEntryPtr = QSharedPointer<PreparedEntry>;
Q_DECLARE_METATYPE(PreparedEntryPtr)

/// @brief 解析线程:把一次解析结果移动进预构建条目(无深拷贝)
/// @param r 解析结果(被移走,调用后不可再用)
PreparedEntryPtr prepare_entry(ParseResult&& r);

/// @brief GUI 线程:为预构建条目补帧序号/时间/Delta,并分发到拓扑与插件
/// @details 序号与 Delta 链状态只在 GUI 线程维护(暂停丢帧不占序号、清空归零),
///          与原 MainWindow::make_entry 行为一致。
class EntryBuilder {
public:
    EntryBuilder() = default;

    /// @brief 拓扑控制器(可空):每帧提交拓扑输入
    void set_topo_controller(TopoController* c) { m_topo_controller = c; }
    /// @brief 插件引擎(可空):每帧喂"解析好的帧"
    void set_plugin_engine(LocalPluginEngine* e) { m_plugin_engine = e; }

    /// @brief 完成一帧:分配序号、定时间/Delta、拼搜索文本、分发拓扑/插件
    /// @param p      预构建条目(entry 被移走)
    /// @param now_ms GUI 收到该帧的本地时刻(帧内无绝对时间时作 Time 列)
    PacketEntry build(PreparedEntry& p, qint64 now_ms);

    /// @brief 清空:序号与 Delta 链归零(对应"清空"按钮)
    void reset();
    /// @brief 新采集开始:只断开插件解析器的 NTB Delta 链
    void restart_delta_chain() { m_have_last_ntb = false; }

private:
    TopoController*    m_topo_controller = nullptr;
    LocalPluginEngine* m_plugin_engine = nullptr;
    int     m_index_counter = 0;     ///< 已分配的最大帧序号
    quint32 m_last_ntb = 0;          ///< 上一帧帧内 NTB(tick),插件解析器 Delta 回退用
    bool    m_have_last_ntb = false;
};

#endif  // BPLC_ENTRYBUILDER_H
