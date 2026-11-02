/// @file packetlistmodel.h
/// @brief Wireshark 风格 PacketList 的 QAbstractTableModel(磁盘换页版)
/// @note 线程约束:本模型所有访问必须发生在 GUI 线程
///       (append 来自主窗口 flush 定时器,rowCount/data 来自视图重绘)。
///       严禁在模型内加互斥锁——beginInsertRows/endInsertRows 会同步触发
///       视图回调 rowCount()/data(),若持锁将导致同一线程重入死锁(界面卡死)。
/// @note 内存策略:驻留内存条目(热区 m_hot)最多 kBlockSize 条;超出后每满
///       kBlockSize 条 flush 成一块落盘临时文件(不丢弃)。滚动/访问旧条目时
///       按块从盘打开 BlockReader 进 LRU 缓存(m_block_cache):打开只解析
///       头/字符串池/轻量索引,条目按需逐条解码(v3 块格式),以控制常驻
///       内存、支持任意深度回溯。过滤只扫索引不解码条目;导出按需流式
///       遍历全部条目。
#ifndef PACKETLISTMODEL_H
#define PACKETLISTMODEL_H

#include "bplcframe.h"
#include "packetentry_serialize.h"   // pser::BlockReader(盘块随机访问)
#include <QAbstractTableModel>
#include <QVector>
#include <QHash>
#include <QStringList>
#include <QTemporaryDir>
#include <functional>

/// @brief 过滤条件词(表达式预处理产物,定义见 packetlistmodel.cpp)
struct PacketFilterCond {
    QString term;          ///< 子串条件(已 trim+小写;tei<0 且 type_byte==-1 时用)
    int     type_byte = -1;///< >=0 帧型关键词的帧型字节;-1 子串;-2 永假(空词/TEI 溢出)
    int     tei = -1;      ///< >=0:sta-<数字> 的 TEI 等值谓词(比 src/dst TEI,不走子串)
};

/// @brief 预处理后的过滤表达式:'|' 分组、组内 '&' 合取(与 m_filter 同步重建)
struct PacketPreparedFilter {
    QVector<QVector<PacketFilterCond>> groups;
    bool empty = true;     ///< 表达式为空 = 全部通过
};

class PacketListModel : public QAbstractTableModel {
    Q_OBJECT
public:
    enum Column {
        COL_INDEX,
        COL_TIME,
        COL_DELTA,
        COL_ORIG_SRC,     ///< 原始发起 TEI(MSDU 头 SourceTEI)
        COL_SOURCE,
        COL_DEST,
        COL_ORIG_DST,     ///< 原始终点 TEI(MSDU 头 DestinationTEI)
        COL_DIR,          ///< 报文方向:↑=上行(终点=CCO) ↓=下行(发起=CCO) *=其它
        COL_PROTOCOL,
        COL_FRAME_TYPE,   ///< 帧类型列(BEACON/SOF/ACK/COORD),位于 Protocol 之后
        COL_MSDU_TYPE,    ///< MSDU 类型列(SOF 重组完成时显示 MMe/APP 类型)
        COL_MSDU_SEQ,     ///< MSDU 序号列(MSDU_BASE 的 MSDUIndex)
        COL_LENGTH,
        COL_INFO,
        COL_COUNT
    };

    /// @brief 驻留内存的条目上限(超出后 flush 落盘)
    static constexpr int kBlockSize = 1000;
    /// @brief 盘块 LRU 缓存上限(滚动预取窗口,可调;块数 × kBlockSize = 预取内存)
    static constexpr int kMaxCacheBlocks = 4;

    explicit PacketListModel(QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& idx, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orient, int role = Qt::DisplayRole) const override;
    QVariant data_color(const PacketEntry& e) const;

    /// @brief 总条目数(含已落盘历史)
    qint64 total_count() const { return m_total; }

    /// @brief 是否正在异步过滤(测试等待用)
    bool filtering() const { return m_filtering; }

    /// @brief 滚动预取:按可见行定位全局行号,预加载其所在盘块及前后相邻块
    void ensure_loaded(int visible_row);

    /// @brief 按全局顺序流式遍历全部条目(导出用;不一次性载入内存)
    void for_each_entry(const std::function<void(const PacketEntry&)>& fn);

    /// @brief 导出快照:热区拷贝 + 已落盘块文件路径(升序),供工作线程流式导出
    /// @note 在 GUI 线程调用;快照独立于模型(热区深拷贝、盘块路径为快照值),
    ///       之后模型继续 append/滚动均不影响该快照,可安全传给工作线程。
    struct ExportSnapshot {
        QVector<PacketEntry> hot;         ///< 热区条目拷贝(≤ kBlockSize)
        QStringList          block_paths; ///< 盘块文件路径(升序,对应块 0..N-1)
        /// TEI→MAC 映射表快照(CSV 导出 Source/Dest 列显示 MAC 用;深拷贝)
        QHash<quint32, QHash<quint16, quint64>> tei_mac;
    };
    ExportSnapshot make_export_snapshot() const;

    /// @brief 按可见行号取条目拷贝(供 UI 跨行时间差计算等;内部触发盘块按需加载)
    /// @return 行号越界返回 false,否则拷贝到 out 并返回 true
    bool entry_at(int visible_row, PacketEntry& out) const;

public slots:
    void append_packets(QVector<PacketEntry> entries);  // 按值:move 语义,避免 PacketEntry 深拷贝
    void append_packet(const PacketEntry& entry);
    void clear_all();
    void activate_row(int visible_row);
    void set_display_filter(const QString& expr);
    bool passes_filter(const PacketEntry& e) const;

signals:
    void packet_activated(const PacketEntry& entry);

private:
    /// @brief 全局行号 g → 条目引用(盘块或热区)
    /// @warning 盘块路径的引用来自 BlockReader 单槽缓存(见 entry_ref):
    ///          下一次 locate/data 调用即可能失效,只能瞬时消费(立即读
    ///          字段、emit 同步信号或深拷贝),严禁跨调用持有。
    const PacketEntry& locate(int g) const;
    /// @brief 加载盘块进缓存(若未在);返回是否成功
    bool load_block(int idx) const;
    /// @brief 把 m_hot 前 kBlockSize 条 flush 成一块落盘
    void flush_hot_block();
    QString block_path(int idx) const;
    void touch_lru(int idx) const;
    /// @brief 更新 TEI→MAC 映射表(按 NID 分表;取自 MSDU 头 MACAddrFlag 扩展字段)
    void update_tei_mac(const PacketEntry& e);
    /// @brief 学习一对 TEI↔MAC(正反两表同步;TEI 易主时清旧 MAC 的反向条目)
    bool learn_tei_mac(quint32 nid, quint16 tei, quint64 mac);
    /// @brief 通知当前视图重新绘制依赖 TEI→MAC 的列;不加载/扫描历史条目
    void notify_mac_mapping_changed();
    /// @brief 查 TEI 对应 MAC(48-bit;无记录返回 0)
    quint64 lookup_mac(quint32 nid, quint16 tei) const;
    /// @brief 反查 MAC 对应 TEI(48-bit;无记录返回 0)
    quint16 lookup_tei_by_mac(quint32 nid, quint64 mac) const;

    QVector<PacketEntry>  m_hot;         ///< 驻留热区(最近未 flush 条目,≤kBlockSize)
    int                    m_block_count; ///< 已落盘满块数量
    qint64                 m_total;       ///< 总条目数
    QVector<int>           m_visible;     ///< 过滤器命中的全局行号(升序)
    QString                m_filter;
    PacketPreparedFilter   m_prepared;   ///< m_filter 的预处理形式(匹配零分配)
    bool                   m_filtering = false; ///< 过滤进行中(异步;期间 append 暂存到 m_deferred)
    int                    m_filter_gen = 0; ///< 过滤代计数,丢弃过期异步结果
    QVector<PacketEntry>   m_deferred;    ///< 过滤期间暂存的 append 条目
    QHash<quint32, QHash<quint16, quint64>> m_tei_mac; ///< TEI→MAC 映射表(NID → TEI → MAC48)
    QHash<quint32, QHash<quint64, quint16>> m_mac_tei; ///< MAC→TEI 反向索引(NID → MAC48 → TEI;与 m_tei_mac 同步维护,供 lookup_tei_by_mac O(1) 反查)
    QTemporaryDir          m_paging_dir;  ///< 盘块临时目录(进程结束自动清理)

    mutable QHash<int, pser::BlockReader> m_block_cache; ///< 已打开盘块 LRU
    mutable QList<int>     m_lru;          ///< 盘块最近使用顺序(前=最旧)
};

#endif // PACKETLISTMODEL_H
