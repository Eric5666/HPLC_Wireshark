/// @file topo_window.h
/// @brief 拓扑(Topo)独立窗口:多 NID 下拉切换 + 拓扑图 + 路由变更表 + TEI→MAC 表
/// @details 与 app/io/ui 解耦,只依赖 topo_state(数据模型) + Qt widgets。
///          MainWindow 持有 QHash<quint32, TopoState> 并传入本窗口指针引用,
///          窗口按需读取当前 NID 的状态绘制/列表,不改动状态。
#ifndef TOPO_WINDOW_H
#define TOPO_WINDOW_H

#include "topo_state.h"
#include <QComboBox>
#include <QHash>
#include <QList>
#include <QWidget>

class QLabel;
class QLineEdit;
class QPushButton;
class QTableView;
class QStandardItemModel;
class QPixmap;
class QTimer;
class QEvent;

/// @brief NID 下拉框:展开下拉列表期间暂停内容刷新
/// @details 实时刷新(refresh_nids)会清空重建下拉项,若用户在展开状态下选择,
///          列表会不停重建导致无法点选。本子类在 showPopup/hidePopup 置标志,
///         刷新方据此跳过重建。
class NidComboBox : public QComboBox {
    Q_OBJECT
public:
    explicit NidComboBox(QWidget* parent = nullptr) : QComboBox(parent) {}
    /// @brief 是否正处于下拉展开状态
    bool popup_open() const { return m_popup_open; }

signals:
    /// @brief 下拉列表收起(供外部在收起后强制刷新一次 NID 列表,避免展开期跳过的更新变成过期列表)
    void popup_closed();

protected:
    void showPopup() override { m_popup_open = true;  QComboBox::showPopup(); }
    void hidePopup() override {
        m_popup_open = false;
        QComboBox::hidePopup();
        emit popup_closed();
    }

private:
    bool m_popup_open = false;
};

/// @brief 自绘层次拓扑图(CCO 顶层,STA 按层级向下展开,父子连线)
class TopoGraphWidget : public QWidget {
    Q_OBJECT
public:
    explicit TopoGraphWidget(QWidget* parent = nullptr);
    void set_state(const TopoState* state);
    /// @brief 一键适应视图:缩放+平移使整张拓扑图居中铺满控件
    void fit_view();
    /// @brief 聚焦某个 STA 节点:平移视图使其居中并高亮(TEI-MAC 表双击跳转用)
    void focus_node(quint16 tei);

protected:
    void paintEvent(QPaintEvent*) override;
    void mousePressEvent(QMouseEvent*) override;
    void mouseMoveEvent(QMouseEvent*) override;
    void mouseReleaseEvent(QMouseEvent*) override;
    void wheelEvent(QWheelEvent*) override;

private:
    /// @brief 计算节点布局坐标(世界坐标,自上而下层次树)
    void relayout();
    /// @brief widget 坐标 → 世界坐标(逆缩放/平移)
    QPointF to_world(const QPointF& w) const;
    /// @brief 命中世界坐标处的节点(返回 tei + mac;无命中返回 false)
    bool hit_node(const QPointF& world, quint16& tei, quint64& mac, QRectF& box) const;
    /// @brief 显示节点悬浮信息(通讯成功率等)
    void show_node_tip(const QPoint& widget_pos, quint16 tei, quint64 mac);

    const TopoState* m_state = nullptr;
    struct NodePos {
        quint16 tei;
        quint64 mac = 0; ///< 正在入网(关联请求)节点的 MAC;tei==0 时有效
        int     level;
        QPointF pos;
    };
    QVector<NodePos> m_layout;
    QHash<quint16, QPointF> m_pos; ///< tei → 坐标(连线用)
    QPixmap* m_icon_cco = nullptr;          ///< CCO 节点图标(cco-router.png)
    QPixmap* m_icon_online = nullptr;       ///< STA 已入网(electric-meter_online.png)
    QPixmap* m_icon_online_hplcrf = nullptr; ///< STA 已入网且双模(electric-meter_hplcrf_online.png)
    QPixmap* m_icon_online_going = nullptr; ///< STA 正在入网(electric-meter _online_going.png)
    QPixmap* m_icon_offline = nullptr;      ///< STA 离线(electric-meter _offline.png)

    // 视图变换:世界坐标 × scale + offset = widget 坐标
    QPointF m_offset;         ///< 平移偏移
    qreal   m_scale = 1.0;    ///< 缩放比例
    qreal   m_canvas_w = 400.0;
    qreal   m_canvas_h = 300.0;
    QPointF m_drag_start;     ///< 拖拽起点(widget 坐标)
    QPointF m_press_widget;   ///< 按下位置(判断点击 vs 拖拽)
    bool    m_dragging = false;
    quint16 m_focus_tei = 0;  ///< 当前高亮聚焦的 TEI(0=无;TEI-MAC 表双击跳转)
};

/// @brief 拓扑独立窗口(支持历史回放调试模式)
/// @details 实时模式:显示 MainWindow 累积的 m_topo_states(新帧到达自动刷新)。
///          历史回放模式:点击帧列表某帧后,MainWindow 按帧序号重放拓扑事件日志
///          生成冻结快照,经 show_history() 传入;此模式下 mark_dirty() 被忽略,
///          图/TEI-MAC 表冻结在选中帧,不随新帧推进,直到回到实时;
///          路由变更表保留进入回放时的全部记录行(不截断目标帧之后的行),
///          仅高亮冻结帧所在行,同样不随新帧推进。
class TopoWindow : public QWidget {
    Q_OBJECT
public:
    explicit TopoWindow(QWidget* parent = nullptr);

    /// @brief 刷新 NID 下拉列表(从当前视图状态表收集:实时或回放)
    void refresh_nids();
    /// @brief 设置实时状态表引用(不拷贝;由 MainWindow 持有)
    void set_state_map(const QHash<quint32, TopoState>* map);
    /// @brief 切到指定 NID(存在则切换并刷新)
    void set_current_nid(quint32 nid);
    /// @brief 仅强制下拉框显示并更新 m_current_nid(不重建内容;由 refresh_nids 每 200ms 幂等调用)
    void force_display_nid(quint32 nid);
    /// @brief 当前 NID(0=无)
    quint32 current_nid() const { return m_current_nid; }
    /// @brief 实时刷新:重新收集 NID 并刷新当前 NID 的图与表(新帧到达时由 MainWindow 调用)
    void refresh_current();
    /// @brief 标记有新拓扑数据(轻量,只置脏标志;定时器批量刷新,避免高频全量重建卡顿)
    /// @note 历史回放模式下直接忽略(冻结,不跟随新帧)
    void mark_dirty();
    /// @brief 历史回放:显示重放到 frame_index 的冻结快照;active=false 时回到实时
    /// @param hist 回放状态表(不拷贝不拥有;调用方保证生命周期)
    void show_history(const QHash<quint32, TopoState>* hist, bool active,
                      qint64 frame_index, qint64 frame_ms);
    /// @brief 回到实时显示
    void show_live();
    /// @brief 是否处于历史回放(冻结)模式
    bool history_mode() const { return m_hist_mode; }

signals:
    /// @brief 用户点击"回到实时"按钮
    void request_live();
    /// @brief 用户双击路由变更表某行 → 追溯到该行对应的帧(序号,时间点ms)
    void request_history(qint64 frame_index, qint64 frame_ms);

protected:
    /// @brief 关闭 = 隐藏(保留状态,下次打开复用)
    void closeEvent(QCloseEvent* e) override;
    /// @brief TEI-MAC 表滚轮翻看时暂停实时刷新(捕获 viewport 的 Wheel 事件)
    bool eventFilter(QObject* watched, QEvent* event) override;

private slots:
    void on_nid_changed(int idx);
    void on_routes_filter(const QString& text);
    void on_teimac_search(const QString& text);
    void on_routes_double_clicked(const QModelIndex& idx);  ///< 路由表双击 → 发射 request_history
    void on_teimac_double_clicked(const QModelIndex& idx);  ///< 邻居表单元格双击 → 弹出邻居明细

private:
    /// @brief 当前视图状态表(历史回放模式用快照,否则用实时表)
    const QHash<quint32, TopoState>* view_states() const {
        return m_hist_mode ? m_hist_states : m_states;
    }
    void rebuild_all();
    void rebuild_routes_table();
    void rebuild_teimac_table();
    /// @brief 刷新在网节点数汇总标签(当前 NID 的 TopoState;无数据时显示 —)
    /// @details 与图/三张表同源(view_states()):实时读实时表,历史回放读冻结快照,
    ///          故回放模式下数字自动冻结,不跟随新帧;刷新走既有 rebuild_all(),
    ///          不另起定时器。
    void update_count_label();
    /// @brief 重建「异常/冲突」表(同一 MAC 多 TEI / 同一 TEI 多 MAC / 重启次数振荡)
    void rebuild_anomaly_table();
    /// @brief 一次性把本窗口各表(邻居/TEI-MAC、路由变更、异常/冲突)列宽按内容重排
    /// @details 表头策略为 ResizeToContents/Stretch 时 resizeColumnsToContents 无效,
    ///          故临时切 Interactive 量一次再还原原策略;过窄列给最小宽度下限。
    void fit_tables_once();
    /// @brief 历史回放模式下高亮冻结帧对应的路由表行(不滚动,不移除其他行)
    void highlight_history_row();
    void update_mode_ui();
    /// @brief TEI-MAC 表翻看/双击时暂停实时刷新(冻结当前视图,避免跳转/选择被刷新覆盖)
    void pause_live();
    /// @brief 向路由变更表追加 [from, to) 区间的事件行(供全量重建/增量追加复用)
    void append_routes_rows(const TopoState* st, const QString& filter, int from, int to);

    NidComboBox*        m_nid_combo;
    QLabel*             m_mode_label = nullptr;  ///< 模式标签:实时 / 历史回放 @ #N
    QLabel*             m_count_label = nullptr; ///< 在网节点数汇总:顶部工具栏 NID 下拉框旁
    QPushButton*        m_btn_live = nullptr;    ///< 回到实时按钮(仅回放模式可见)
    TopoGraphWidget*    m_graph;
    QTableView*         m_routes_table;
    QStandardItemModel* m_routes_model;
    QLineEdit*          m_routes_filter;
    QTableView*         m_teimac_table;
    QStandardItemModel* m_teimac_model;
    QLineEdit*          m_teimac_search;
    // 异常/冲突表(独立页签;与路由变更事件表分离)
    QTableView*         m_anom_table = nullptr;
    QStandardItemModel* m_anom_model = nullptr;

    const QHash<quint32, TopoState>* m_states = nullptr;
    const QHash<quint32, TopoState>* m_hist_states = nullptr; ///< 回放快照(不拥有)
    bool m_hist_mode = false;         ///< 历史回放(冻结)模式
    bool m_pause_live = false;        ///< TEI-MAC 表交互导致的暂停实时刷新(与历史回放共用「回到实时」恢复)
    qint64 m_hist_frame = -1;         ///< 历史回放冻结到的帧序号(路由表高亮用;-1=无)
    quint32 m_current_nid = 0;
    bool    m_dirty = false;         ///< 有新拓扑数据待刷新
    QTimer* m_refresh_timer = nullptr; ///< 节流定时器(批量刷新,防高频全量重建卡顿)

    // 路由变更表滚动逻辑(与主界面 Table View 一致):
    // 用户滚到底部(最新)才自动跟随;滚离底部则保持当前位置,不强制跳回
    bool m_routes_follow_bottom = true; ///< 是否在底部(跟随最新)
    bool m_rebuilding_routes = false;   ///< 重建期间屏蔽 scrollbar 信号干扰
    // 路由变更表增量追加:记录当前视图的"数据源/NID/过滤/已展示事件数",
    // 视图变化时全量重建,否则只追加新增事件行(避免每 200ms 全量重建 O(E))
    const QHash<quint32, TopoState>* m_routes_view = nullptr;
    quint32 m_routes_nid = 0;
    QString m_routes_filter_text;
    int     m_routes_shown = 0;
    /// @brief 路由变更表的 TEI→MAC 时点映射(按事件顺序重放;用于"截至该事件前"的解析)
    /// @details 事件是历史追溯,不能用最终映射回填 —— 否则早期事件会显示它当时还不存在的
    ///          MAC(如 STA 换 TEI 后,旧 TEI 的行会显示新 MAC)。全量重建时清空重放,
    ///          增量追加时延续上一次状态。
    QHash<quint16, quint64> m_routes_mac_asof;
};

#endif // TOPO_WINDOW_H
