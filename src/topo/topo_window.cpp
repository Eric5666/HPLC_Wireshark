/// @file topo_window.cpp
/// @brief 拓扑独立窗口实现(层次拓扑图 + 路由变更表 + TEI→MAC 表)
#include "topo_window.h"
#include <climits>
#include "i18n.h"

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QColor>
#include <QDateTime>
#include "QsLog.h"
#include <QDialog>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QKeyEvent>
#include <QLineEdit>
#include <QMouseEvent>
#include <QPainter>
#include <QPixmap>
#include <QPushButton>
#include <QSplitter>
#include <QScrollBar>
#include <QSet>
#include <QStandardItemModel>
#include <QTableView>
#include <QTabWidget>
#include <QTimer>
#include <QToolTip>
#include <QVBoxLayout>
#include <QWheelEvent>
#include <QLabel>
#include <QStyledItemDelegate>
#include <QTextDocument>

#include <algorithm>

namespace {

/// @brief QTableView Ctrl+C 复制选中单元格为 TSV(制表符分隔,可粘贴到 Excel)
class TableCopyFilter : public QObject {
public:
    explicit TableCopyFilter(QObject* parent = nullptr) : QObject(parent) {}
protected:
    bool eventFilter(QObject* obj, QEvent* event) override {
        if (event->type() == QEvent::KeyPress) {
            auto* ke = static_cast<QKeyEvent*>(event);
            if (ke->matches(QKeySequence::Copy)) {
                auto* view = qobject_cast<QTableView*>(obj);
                if (view && copy_selected(view))
                    return true;
            }
        }
        return QObject::eventFilter(obj, event);
    }
private:
    static bool copy_selected(QTableView* view) {
        auto* sel = view->selectionModel();
        if (!sel || !sel->hasSelection()) return false;
        QModelIndexList idxs = sel->selectedIndexes();
        if (idxs.isEmpty()) return false;
        // 按行列排序
        std::sort(idxs.begin(), idxs.end(), [](const QModelIndex& a, const QModelIndex& b) {
            if (a.row() != b.row()) return a.row() < b.row();
            return a.column() < b.column();
        });
        QStringList rows;
        int cur_row = -1;
        QStringList cur_cols;
        for (const QModelIndex& idx : idxs) {
            if (idx.row() != cur_row) {
                if (cur_row >= 0) rows << cur_cols.join(QStringLiteral("\t"));
                cur_row = idx.row();
                cur_cols.clear();
            }
            // 邻居表列存 HTML,复制时取纯文本
            QString text = idx.data(Qt::DisplayRole).toString();
            if (text.contains(QLatin1String("<span"))) {
                QTextDocument doc;
                doc.setHtml(text);
                text = doc.toPlainText();
            }
            cur_cols << text;
        }
        if (!cur_cols.isEmpty()) rows << cur_cols.join(QStringLiteral("\t"));
        QApplication::clipboard()->setText(rows.join(QStringLiteral("\n")));
        return true;
    }
};

/// @brief 为 QTableView 启用 Ctrl+C 复制
inline void enable_table_copy(QTableView* view) {
    view->installEventFilter(new TableCopyFilter(view));
}

/// @brief 邻居表单元格 HTML 代理:同一格内各 "TEIx" 按信号强度显示不同绿色
/// (DisplayRole 存 HTML,含 <span> 时用 QTextDocument 渲染)
class NeighborHtmlDelegate : public QStyledItemDelegate {
public:
    explicit NeighborHtmlDelegate(QObject* parent = nullptr)
        : QStyledItemDelegate(parent) {}
    void paint(QPainter* painter, const QStyleOptionViewItem& option,
               const QModelIndex& index) const override {
        const QString html = index.data(Qt::DisplayRole).toString();
        if (!html.contains(QLatin1String("<span"))) {
            QStyledItemDelegate::paint(painter, option, index);
            return;
        }
        QStyleOptionViewItem opt = option;
        initStyleOption(&opt, index);
        painter->save();
        if (opt.widget) {
            QStyle* st = opt.widget->style();
            st->drawPrimitive(QStyle::PE_PanelItemViewItem, &opt, painter, opt.widget);
            const QRect textRect = st->subElementRect(
                QStyle::SE_ItemViewItemText, &opt, opt.widget);
            painter->translate(textRect.topLeft() + QPoint(4, 0));
            QTextDocument doc;
            doc.setHtml(html);
            doc.setDefaultFont(opt.font);
            doc.setTextWidth(textRect.width() - 8);
            doc.drawContents(painter);
        }
        painter->restore();
    }
};

/// @brief MAC 48-bit 帧内原始字节序 → "aa:bb:cc:dd:ee:ff"(与 Table View 一致)
QString format_mac(quint64 v) {
    QString s;
    for (int i = 0; i < 6; ++i) {
        s += QStringLiteral("%1").arg((v >> (8 * i)) & 0xFF, 2, 16, QChar('0'));
        if (i < 5) s += QLatin1Char(':');
    }
    return s;
}

/// @brief epoch ms → 本地时间文本(精确到 ms)
QString format_time(qint64 epoch_ms) {
    if (epoch_ms <= 0) return QStringLiteral("-");
    return QDateTime::fromMSecsSinceEpoch(epoch_ms)
        .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
}

QString event_kind_name(TopoEventKind k) {
    switch (k) {
        case TopoEventKind::DiscoverList:   return trl::L("发现列表");
        case TopoEventKind::AssocReq:       return trl::L("关联请求");
        case TopoEventKind::AssocCnf:       return trl::L("关联确认");
        case TopoEventKind::AssocGatherInd: return trl::L("关联汇总指示");
        case TopoEventKind::AssocInd:       return trl::L("关联指示");
        case TopoEventKind::ChangeProxyReq: return trl::L("代理变更请求");
        case TopoEventKind::ChangeProxyCnf: return trl::L("代理变更");
        case TopoEventKind::LeaveInd:       return trl::L("离线指示");
        case TopoEventKind::CcoRestart:     return trl::L("CCO重启");
        case TopoEventKind::StaRestart:     return trl::L("STA重启");
        default:                            return trl::L("其他");
    }
}

/// @brief 异常/冲突类别名(异常页签"类别"列)
QString anomaly_kind_name(TopoAnomalyKind k) {
    switch (k) {
        case TopoAnomalyKind::MacMultipleTei:          return trl::L("同一 MAC 多 TEI");
        case TopoAnomalyKind::TeiMultipleMac:          return trl::L("同一 TEI 多 MAC");
        case TopoAnomalyKind::RestartCountOscillation: return trl::L("重启次数振荡");
        case TopoAnomalyKind::LinkCountMismatch:       return trl::L("两链路计数不同");
        case TopoAnomalyKind::NidConflict:             return trl::L("同一 NID 多 CCO MAC");
    }
    return trl::L("其他");
}

/// @brief 异常/冲突表列号:双击行为按列区分(首次帧/首次时间 → 首次,其余 → 最近一次)
enum {
    kAnomColFirstFrame = 0,   ///< 首次帧
    kAnomColFirstTime  = 7,   ///< 首次时间
};

/// @brief 中→英注册(文件级,仅新增条目;重复注册无害)
struct I18nRegTopoWindow {
    I18nRegTopoWindow() {
        trl::register_en("拓扑图 TOPO", "Topology TOPO");
        trl::register_en("网络:", "Network:");
        trl::register_en("搜索 TEI / MAC…", "Search TEI / MAC…");
        trl::register_en("筛选(时间/类型/说明)…", "Filter (time/type/description)…");
        trl::register_en("TEI → MAC 映射", "TEI → MAC mapping");
        trl::register_en("路由变更记录(关联确认/关联指示/关联汇总指示/代理变更请求/代理变更/发现列表/离线指示/CCO重启/STA重启)",
                         "Route change log (assoc conf / assoc ind / gather ind / proxy change req / proxy change / discover list / leave ind / CCO reboot / STA reboot)");
        trl::register_en("CCO重启", "CCO reboot");
        trl::register_en("STA重启", "STA reboot");
        // 异常/冲突页签(同一 MAC 多 TEI / 同一 TEI 多 MAC / 重启次数振荡 / NID 冲突)
        trl::register_en("路由变更", "Route Change");
        trl::register_en("异常/冲突", "Anomaly / Conflict");
        trl::register_en("异常/冲突记录(同一 MAC 多 TEI / 同一 TEI 多 MAC / 重启次数振荡 / NID 冲突)", "Anomaly / conflict log (one MAC many TEIs / one TEI many MACs / restart-count oscillation / NID conflict)");
        trl::register_en("同一 MAC 多 TEI", "One MAC, Many TEIs");
        trl::register_en("同一 TEI 多 MAC", "One TEI, Many MACs");
        trl::register_en("重启次数振荡", "Restart-Count Oscillation");
        trl::register_en("两链路计数不同", "Link Count Mismatch");
        trl::register_en("同一 NID 多 CCO MAC", "Multiple CCO MACs in One NID");
        trl::register_en("同一 NID 下出现不同 CCO MAC", "Different CCO MACs Detected in One NID");
        trl::register_en("载波 / 无线", "PLC / RF");
        trl::register_en("次数", "Occurrences");
        // "次数"列分类型语义(A/B 冲突次数 / C 往返次数 / D 差异组合数)
        trl::register_en("冲突次数：同一主体反复冲突的累计次数", "Conflict Count: Cumulative Conflicts of the Same Subject");
        trl::register_en("冲突次数：同一 NID 下每发现一个新的 CCO MAC 计一次", "Conflict Count: One for Each New CCO MAC Detected in the Same NID");
        trl::register_en("往返次数：回到出现过的取值才计，首次出现新值不计", "Round Trips: Counted Only When Returning to a Seen Value, the First Sighting of a New Value Is Not Counted");
        trl::register_en("%1(组合)", "%1 (combinations)");
        trl::register_en("差异组合数：每个不同的 (载波,无线) 取值组合各计一次", "Distinct Combinations: Each Different (PLC, RF) Value Pair Counted Once");
        trl::register_en("类别", "Category");
        trl::register_en("最近变化", "Latest Change");
        trl::register_en("首次时间", "First Seen");
        trl::register_en("最近时间", "Last Seen");
        trl::register_en("首次帧", "First Frame");
        trl::register_en("最近帧", "Last Frame");
        trl::register_en("介质", "Medium");
        trl::register_en("双击「首次帧」跳到首次出现的帧，双击「最近帧」跳到最近一次的帧", "Double-Click 'First Frame' to Jump to That Frame; Double-Click 'Last Frame' to Jump to the Latest");
        trl::register_en("序号", "Seq");
        trl::register_en("首次", "First seen");
        trl::register_en("时间点", "Time");
        trl::register_en("类型", "Type");
        trl::register_en("变更说明", "Description");
        trl::register_en("状态", "Status");
        trl::register_en("层级", "Level");
        trl::register_en("邻居表", "Neighbors");
        trl::register_en("代理 TEI", "Proxy TEI");
        trl::register_en("本站点的代理 (PCO)", "This STA's proxy (PCO)");
        trl::register_en("STA TEI=%1 的邻居表", "Neighbors of STA TEI=%1");
        trl::register_en("在线", "Online");
        trl::register_en("入网中", "Joining");
        trl::register_en("离线", "Offline");
        trl::register_en("发现列表", "Discover list");
        trl::register_en("关联请求", "Assoc request");
        trl::register_en("关联确认", "Assoc confirm");
        trl::register_en("关联汇总指示", "Assoc gather indication");
        trl::register_en("关联指示", "Assoc indication");
        trl::register_en("代理变更请求", "Proxy change request");
        trl::register_en("代理变更", "Proxy change");
        trl::register_en("离线指示", "Leave indication");
        trl::register_en("其他", "Other");
        trl::register_en("(无拓扑数据)", "(No topology data)");
        trl::register_en("入网中(关联请求)", "Joining (assoc request)");
        trl::register_en("上级", "Parent");
        trl::register_en("载波上行成功率（我→父 %1）: %2%", "PLC uplink rate (me→parent %1): %2%");
        trl::register_en("载波下行成功率（父→我）: %1%", "PLC downlink rate (parent→me): %1%");
        trl::register_en("通讯成功率: 暂无上报", "Comm success rate: no report");
        trl::register_en("入网链路", "Link Type");
        trl::register_en("双模", "Dual-mode");
        // Unk = Undetermined 的缩写。用缩写是因为节点标签第三行宽仅 140px，
        // 全称 "Undetermined|Carrier" 约 120px 接近上限，高 DPI 下可能贴边被裁。
        // 语义:link_type==LinkTypeUnknown(SPLC-4 表79 / BPLC-2 表160 未定义该值) ⇒ 按载波兜底显示。
        trl::register_en("未定|载波", "Unk|Carrier");
        trl::register_en("无线", "RF");
        trl::register_en("是", "Yes");
        trl::register_en("否", "No");
        trl::register_en("信号强度", "Signal Strength");
        trl::register_en("载波", "PLC");
        trl::register_en("实时", "Live");
        trl::register_en("历史回放", "History replay");
        trl::register_en("回到实时", "Back to Live");
        trl::register_en("已暂停", "Paused");
        trl::register_en("适应视图", "Fit view");
        trl::register_en("缩放并居中显示整张拓扑图，并让本窗口各表列宽按内容重新适配", "Zoom to fit and center the whole topology, and refit this window's table columns to contents");
        // 邻居明细表(载波+无线混合,含可靠度评分)
        trl::register_en("信号强度 (dBm)", "Signal Strength (dBm)");
        trl::register_en("上行成功率%（对方→我）", "Uplink % (peer→me)");
        trl::register_en("下行成功率%（我→对方）", "Downlink % (me→peer)");
        trl::register_en("我报它次数", "My reports of it");
        trl::register_en("它报我次数", "Its reports of me");
        trl::register_en("双向", "Bidirectional");
        trl::register_en("可靠度", "Reliability");
        trl::register_en("未知", "Unknown");
        trl::register_en("上行 = 对方发给我的成功率（数据来自我的发现列表报文）",
                         "Uplink = success rate from peer to me (from my own discovery list frame)");
        trl::register_en("下行 = 我发给对方的成功率（数据来自邻居的发现列表报文）",
                         "Downlink = success rate from me to peer (from the neighbor's discovery list frame)");
        trl::register_en("base=%1 活跃度=%2 信号归一=%3 · 权重 0.50/0.30/0.20",
                         "base=%1 activity=%2 signal norm=%3 · weights 0.50/0.30/0.20");
        trl::register_en("对称性=%1 活跃度=%2 · 权重 0.60/0.40",
                         "symmetry=%1 activity=%2 · weights 0.60/0.40");
        trl::register_en("无线上行成功率（我→父 %1）: %2%", "RF uplink rate (me→parent %1): %2%");
        trl::register_en("无线下行成功率（父→我）: %1%", "RF downlink rate (parent→me): %1%");
    }
} i18n_reg_topo_window;

} // namespace

// ============================= TopoGraphWidget =============================

TopoGraphWidget::TopoGraphWidget(QWidget* parent) : QWidget(parent) {
    setMinimumSize(320, 280);
    setMouseTracking(true);   // 悬浮(hover)显示节点信息,无需点击
    m_icon_cco = new QPixmap(QStringLiteral(":/icons/cco-router.png"));
    m_icon_online = new QPixmap(QStringLiteral(":/icons/electric-meter_online.png"));
    m_icon_online_hplcrf = new QPixmap(QStringLiteral(":/icons/electric-meter_hplcrf_online.png"));
    m_icon_online_going = new QPixmap(QStringLiteral(":/icons/electric-meter _online_going.png"));
    m_icon_offline = new QPixmap(QStringLiteral(":/icons/electric-meter _offline.png"));
}

void TopoGraphWidget::set_state(const TopoState* state) {
    m_state = state;
    relayout();
    update();
}

void TopoGraphWidget::relayout() {
    m_layout.clear();
    m_pos.clear();
    if (!m_state) return;

    const QHash<quint16, int> levels = m_state->compute_levels();
    // 按层级分组(仅记录有层级的节点)
    QHash<int, QVector<quint16>> by_level;
    int max_level = 0;
    for (auto it = levels.begin(); it != levels.end(); ++it) {
        by_level[it.value()].append(it.key());
        if (it.value() > max_level) max_level = it.value();
    }
    // 正在入网(关联请求)节点无 TEI,归入层级 1(CCO 直属下)
    const int pending_count = m_state->pending.size();
    if (pending_count > 0 && max_level < 1) max_level = 1;

    const qreal node_w = 140.0;   // 节点框宽(图标 + 标签)
    const qreal icon_h = 64.0;    // 图标高
    const qreal label_h = 54.0;   // 标签区高(TEI + MAC 两行)
    const qreal node_h = icon_h + label_h;
    const qreal hgap = 28.0;      // 同层水平间距
    const qreal vgap = 140.0;     // 层间垂直间距
    const qreal margin = 40.0;

    // 画布宽 = 最大层宽(层级 1 含 pending),取整保证足够
    int max_tier = 1;
    for (auto it = by_level.begin(); it != by_level.end(); ++it)
        max_tier = qMax(max_tier, it.value().size());
    if (max_level >= 1) max_tier += pending_count;
    m_canvas_w = qMax<qreal>(400.0, max_tier * (node_w + hgap) + 2 * margin);

    // 逐层布局:每层节点在画布上水平居中(层级 1 末尾追加 pending 节点)
    for (int lv = 0; lv <= max_level; ++lv) {
        const QVector<quint16> tier = by_level.value(lv);
        const int extra = (lv == 1) ? pending_count : 0;
        const int total_nodes = tier.size() + extra;
        if (total_nodes == 0) continue;
        const qreal total_w = total_nodes * (node_w + hgap) - hgap;
        const qreal x0 = (m_canvas_w - total_w) / 2;
        int idx = 0;
        for (quint16 tei : tier) {
            const qreal x = x0 + idx * (node_w + hgap);
            const qreal y = margin + lv * vgap;
            m_layout.append({tei, 0, lv, QPointF(x, y)});
            m_pos[tei] = QPointF(x + node_w / 2, y + node_h / 2); // 中心
            ++idx;
        }
        if (extra > 0) {
            for (auto it = m_state->pending.begin(); it != m_state->pending.end(); ++it) {
                const qreal x = x0 + idx * (node_w + hgap);
                const qreal y = margin + lv * vgap;
                m_layout.append({0, it.key(), lv, QPointF(x, y)}); // tei=0 标记 pending
                ++idx;
            }
        }
    }
    m_canvas_h = margin * 2 + (max_level + 1) * vgap;
}

void TopoGraphWidget::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.fillRect(rect(), palette().base());
    if (!m_state || m_layout.isEmpty()) {
        p.setPen(palette().placeholderText().color());
        p.drawText(rect(), Qt::AlignCenter, trl::L("(无拓扑数据)"));
        return;
    }

    p.setRenderHint(QPainter::Antialiasing);
    // 视图变换:世界坐标 → widget 坐标(平移 + 缩放)
    p.translate(m_offset);
    p.scale(m_scale, m_scale);
    const qreal node_w = 140.0, icon_h = 64.0, label_h = 54.0;
    const qreal node_h = icon_h + label_h;

    // 1) 连线:正式节点父→子;正在入网节点连到 CCO
    //    连线颜色按子节点接入方式区分,从 palette 派生以适配深浅主题:
    //    载波=主题高亮色(蓝),无线=高亮色互补偏移(琥珀)
    const QColor hl = palette().highlight().color();
    QColor edge_plc = hl;
    QColor edge_rf = hl;
    const int hue = hl.hue() >= 0 ? hl.hue() : 220;   // 无色相(灰)时按蓝
    edge_rf.setHsv((hue + 180) % 360, 210, 225);      // 蓝→琥珀(互补色),固定饱和度/明度保证两主题清晰
    for (const NodePos& np : m_layout) {
        QPointF parent_center;
        bool child_is_rf = false;
        if (np.tei == 0) {
            // 正在入网(关联请求)节点 → 连 CCO(TEI=1)
            auto cit = m_pos.constFind(1);
            if (cit == m_pos.constEnd()) continue;
            parent_center = cit.value();
            auto pit = m_state->pending.constFind(np.mac);
            if (pit != m_state->pending.constEnd()) child_is_rf = (pit.value().link_type == LinkTypeRf || (pit.value().link_type == LinkTypeUnknown && pit.value().is_rf));
        } else {
            auto it = m_state->nodes.constFind(np.tei);
            if (it == m_state->nodes.constEnd()) continue;
            child_is_rf = (it.value().link_type == LinkTypeRf || (it.value().link_type == LinkTypeUnknown && it.value().is_rf));   // 入网链路类型(SPLC-4 表79 / BPLC-2 表160),未定时回退 is_rf
            const quint16 parent = it.value().parent_tei;
            if (parent == kTeiInvalid || parent == np.tei) continue;
            auto pit = m_pos.constFind(parent);
            if (pit == m_pos.constEnd()) continue;
            parent_center = pit.value();
        }
        const QPointF child_top(np.pos.x() + node_w / 2, np.pos.y());
        const QPointF parent_bot(parent_center.x(), parent_center.y() + node_h / 2);
        QColor edge = child_is_rf ? edge_rf : edge_plc;
        edge.setAlpha(200);
        p.setPen(QPen(edge, 1.2));
        p.drawLine(parent_bot, child_top);
    }

    // 2) 节点(CCO 路由器 / STA 电表三态 图标 + TEI/MAC 标签)
    for (const NodePos& np : m_layout) {
        const TopoNode* node = nullptr;
        if (np.tei == 0) {
            // 正在入网(关联请求)节点,按 MAC 查 pending
            auto pit = m_state->pending.constFind(np.mac);
            if (pit == m_state->pending.constEnd()) continue;
            node = &pit.value();
        } else {
            auto it = m_state->nodes.constFind(np.tei);
            if (it == m_state->nodes.constEnd()) continue;
            node = &it.value();
        }
        const bool is_cco = (np.tei == kTeiCco);
        const bool is_pending = (np.tei == 0);

        // 高亮聚焦节点(TEI-MAC 表双击跳转):橙色粗边框醒目标识
        if (np.tei != 0 && np.tei == m_focus_tei) {
            p.setPen(QPen(QColor(255, 140, 0), 3.0));
            p.setBrush(Qt::NoBrush);
            p.drawRoundedRect(QRectF(np.pos.x() - 3, np.pos.y() - 3,
                                     node_w + 6, node_h + 6), 8, 8);
        }

        // 图标:CCO 路由器 / STA 电表(按入网状态三态)
        QPixmap* icon = nullptr;
        if (is_cco) {
            icon = m_icon_cco;
        } else switch (node->status) {
            case NodeStatus::OnlineGoing: icon = m_icon_online_going; break;
            case NodeStatus::Online:
                // 双模节点(发过 RF 帧)用 HPLCRF 图标,非双模沿用原 online 图
                icon = node->rf_capable ? m_icon_online_hplcrf : m_icon_online;
                break;
            case NodeStatus::Offline:     icon = m_icon_offline;      break;
        }
        if (icon && !icon->isNull()) {
            const qreal ix = np.pos.x() + (node_w - icon_h) / 2;
            p.drawPixmap(QRectF(ix, np.pos.y(), icon_h, icon_h), *icon,
                         QRectF(0, 0, icon_h, icon_h));
        }

        // 标签区:第一行标题,第二行 MAC,第三行入网链路(载波/无线/未定)
        const QRectF label_rect(np.pos.x(), np.pos.y() + icon_h, node_w, label_h);
        const QColor tc = node->online()
            ? (is_cco ? QColor(86, 156, 214) : palette().text().color())
            : palette().placeholderText().color();
        p.setPen(tc);
        QFont f = p.font();
        f.setBold(true);
        p.setFont(f);
        const QString title = is_cco    ? QStringLiteral("CCO")
                            : is_pending ? trl::L("入网中")
                            : QStringLiteral("STA-%1").arg(np.tei);
        const qreal row_h = label_h / 3.0;
        p.drawText(label_rect.adjusted(0, 0, 0, -2 * row_h), Qt::AlignCenter, title);
        f.setBold(false);
        p.setFont(f);
        p.drawText(label_rect.adjusted(0, row_h, 0, -row_h), Qt::AlignCenter,
                   node->mac ? format_mac(node->mac) : QStringLiteral("MAC ?"));
        // 入网链路(表79/表160):读 link_type 而非 is_rf —— is_rf 是首次帧介质,不是入网链路
        const QString link_txt = (node->link_type == LinkTypeUnknown)
                                   ? trl::L("未定|载波")
                                   : (node->link_type == LinkTypeRf ? trl::L("无线") : trl::L("载波"));
        p.drawText(label_rect.adjusted(0, 2 * row_h, 0, 0), Qt::AlignCenter, link_txt);
    }
}

QPointF TopoGraphWidget::to_world(const QPointF& w) const {
    return QPointF((w.x() - m_offset.x()) / m_scale,
                   (w.y() - m_offset.y()) / m_scale);
}

bool TopoGraphWidget::hit_node(const QPointF& world, quint16& tei, quint64& mac, QRectF& box) const {
    const qreal node_w = 140.0, icon_h = 64.0, label_h = 54.0;
    const qreal node_h = icon_h + label_h;
    for (const NodePos& np : m_layout) {
        const QRectF r(np.pos.x(), np.pos.y(), node_w, node_h);
        if (r.contains(world)) {
            tei = np.tei;
            mac = np.mac;
            box = r;
            return true;
        }
    }
    return false;
}

void TopoGraphWidget::show_node_tip(const QPoint& global_pos, quint16 tei, quint64 mac) {
    QString title;
    QStringList lines;
    const TopoNode* node = nullptr;
    if (tei == 0) {
        // 正在入网节点(按 MAC 查 pending)
        auto it = m_state->pending.constFind(mac);
        if (it == m_state->pending.constEnd()) return;
        node = &it.value();
        title = trl::L("入网中(关联请求)");
    } else {
        auto it = m_state->nodes.constFind(tei);
        if (it == m_state->nodes.constEnd()) return;
        node = &it.value();
        title = (tei == kTeiCco) ? QStringLiteral("CCO") : QStringLiteral("STA-%1").arg(tei);
    }
    lines << (node->mac ? format_mac(node->mac) : QStringLiteral("MAC ?"));
    lines << QStringLiteral("%1: %2").arg(trl::L("入网链路"),
        node->link_type == LinkTypeUnknown ? trl::L("未定|载波")
        : (node->link_type == LinkTypeRf ? trl::L("无线") : trl::L("载波")));
    lines << QStringLiteral("%1: %2").arg(trl::L("双模"),
        node->rf_capable ? trl::L("是") : trl::L("否"));
    // 无线信号强度(仅 RF 帧携带过信号强度时显示;dBm 为档位下限估计)
    if (node->rssi_known)
        lines << QStringLiteral("%1: %2 dBm").arg(trl::L("信号强度")).arg(node->rssi_dbm);

    if (tei != kTeiCco) {
        const quint16 parent = node->parent_tei;
        const QString pname = (parent == kTeiCco) ? QStringLiteral("CCO") : QStringLiteral("STA-%1").arg(parent);
        // 上级(代理)
        if (parent != kTeiInvalid && parent != tei)
            lines << QStringLiteral("%1: %2").arg(trl::L("上级"), pname);
        // ── ① 成功率区:只显示与父节点(代理)的 4 项(无线 2 + 载波 2);两组都空才显示"暂无上报" ──
        const bool has_wireless = node->proxy_up_rate >= 0 || node->proxy_down_rate >= 0;
        const bool has_carrier = node->proxy_comm_rate >= 0 || node->proxy_down_comm_rate >= 0;
        if (parent != kTeiInvalid && parent != tei && has_wireless) {
            // 无线:RFDL 站点属性(表217)代理上/下行接收率
            if (node->proxy_up_rate >= 0)
                lines << trl::L("无线上行成功率（我→父 %1）: %2%").arg(pname).arg(node->proxy_up_rate);
            if (node->proxy_down_rate >= 0)
                lines << trl::L("无线下行成功率（父→我）: %1%").arg(node->proxy_down_rate);
        }
        if (parent != kTeiInvalid && parent != tei && has_carrier) {
            // 载波:0x0055 发现列表(表77)与代理站点通信成功率
            if (node->proxy_comm_rate >= 0)
                lines << trl::L("载波上行成功率（我→父 %1）: %2%").arg(pname).arg(node->proxy_comm_rate);
            if (node->proxy_down_comm_rate >= 0)
                lines << trl::L("载波下行成功率（父→我）: %1%").arg(node->proxy_down_comm_rate);
        }
        if (!has_wireless && !has_carrier) {
            lines << trl::L("通讯成功率: 暂无上报");
        }
    }
    QToolTip::showText(global_pos,
        QStringLiteral("<b>%1</b><br>%2").arg(title, lines.join(QStringLiteral("<br>"))));
}

void TopoGraphWidget::mousePressEvent(QMouseEvent* e) {
    if (e->button() == Qt::LeftButton) {
        m_drag_start = e->position();
        m_press_widget = e->position();
        m_dragging = false;
        setCursor(Qt::ClosedHandCursor);
    }
    QWidget::mousePressEvent(e);
}

void TopoGraphWidget::mouseMoveEvent(QMouseEvent* e) {
    if (e->buttons() & Qt::LeftButton) {
        const QPointF delta = e->position() - m_drag_start;
        if (!m_dragging && delta.manhattanLength() > 4.0)
            m_dragging = true;
        if (m_dragging) {
            m_offset += e->position() - m_drag_start;
            m_drag_start = e->position();
            update();
        }
    } else {
        // 悬浮(hover):命中节点则显示信息,否则隐藏 tooltip
        const QPointF world = to_world(e->position());
        quint16 tei = 0; quint64 mac = 0; QRectF box;
        if (hit_node(world, tei, mac, box))
            show_node_tip(e->globalPosition().toPoint(), tei, mac);
        else
            QToolTip::hideText();
    }
    QWidget::mouseMoveEvent(e);
}

void TopoGraphWidget::mouseReleaseEvent(QMouseEvent* e) {
    if (e->button() == Qt::LeftButton) {
        setCursor(Qt::ArrowCursor);
        m_dragging = false;
    }
    QWidget::mouseReleaseEvent(e);
}

void TopoGraphWidget::wheelEvent(QWheelEvent* e) {
    const qreal factor = (e->angleDelta().y() > 0) ? 1.15 : (1.0 / 1.15);
    // 以鼠标位置为锚点缩放:先用「旧 scale」反算鼠标下的世界坐标,
    // 再更新 scale 并重算偏移,使缩放前后鼠标下内容不动
    const QPointF world = to_world(e->position());
    m_scale = qBound(0.2, m_scale * factor, 8.0);
    m_offset = e->position() - world * m_scale;
    update();
    e->accept();
}

void TopoGraphWidget::fit_view() {
    if (m_canvas_w <= 0.0 || m_canvas_h <= 0.0)
        return;
    const qreal margin = 20.0;
    const qreal avail_w = qMax(1.0, (qreal)width() - 2.0 * margin);
    const qreal avail_h = qMax(1.0, (qreal)height() - 2.0 * margin);
    m_scale = qBound(0.2, qMin(avail_w / m_canvas_w, avail_h / m_canvas_h), 8.0);
    // 居中:缩放后的世界内容在控件内居中
    m_offset = QPointF(((qreal)width() - m_canvas_w * m_scale) / 2.0,
                       ((qreal)height() - m_canvas_h * m_scale) / 2.0);
    update();
}

void TopoGraphWidget::focus_node(quint16 tei) {
    m_focus_tei = tei;
    auto it = m_pos.constFind(tei);
    if (it != m_pos.constEnd()) {
        // 平移视图使该节点中心对齐控件中心(保持缩放不变)
        const QPointF world = it.value();
        m_offset = QPointF(width() / 2.0 - world.x() * m_scale,
                           height() / 2.0 - world.y() * m_scale);
    }
    update();
}

// =============================== TopoWindow ===============================

TopoWindow::TopoWindow(QWidget* parent) : QWidget(parent) {
    // 独立顶层窗口:自带标题栏 + 最小化/最大化/关闭按钮,可自由移动
    setWindowFlags(Qt::Window);
    setWindowTitle(trl::L("拓扑图 TOPO"));
    resize(1000, 700);

    // 顶部:NID 下拉
    m_nid_combo = new NidComboBox(this);
    connect(m_nid_combo, qOverload<int>(&QComboBox::currentIndexChanged),
            this, &TopoWindow::on_nid_changed);
    // 下拉收起后强制刷新一次 NID 列表:展开期间跳过的更新在此补齐,避免残留过期列表
    connect(m_nid_combo, &NidComboBox::popup_closed, this, [this] { refresh_nids(); });

    // 左:拓扑图
    m_graph = new TopoGraphWidget(this);

    // 右:TEI→MAC 表(搜索)
    m_teimac_search = new QLineEdit(this);
    m_teimac_search->setPlaceholderText(trl::L("搜索 TEI / MAC…"));
    connect(m_teimac_search, &QLineEdit::textChanged, this, &TopoWindow::on_teimac_search);
    m_teimac_model = new QStandardItemModel(this);
    m_teimac_table = new QTableView(this);
    m_teimac_table->setModel(m_teimac_model);
    m_teimac_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_teimac_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    // 列宽适配:邻居表列(索引 7)占满剩余宽度,其余列按内容自适应
    {
        auto* teimac_hh = m_teimac_table->horizontalHeader();
        teimac_hh->setSectionResizeMode(QHeaderView::ResizeToContents);
        teimac_hh->setSectionResizeMode(7, QHeaderView::Stretch);
    }
    m_teimac_table->verticalHeader()->setVisible(false);
    // 邻居表列(索引 7)用 HTML 代理渲染多色 TEI
    m_teimac_table->setItemDelegateForColumn(7, new NeighborHtmlDelegate(this));
    // 双击邻居表单元格 → 弹出独立窗口显示邻居 TEI/MAC/层级
    connect(m_teimac_table, &QTableView::doubleClicked,
            this, &TopoWindow::on_teimac_double_clicked);
    enable_table_copy(m_teimac_table);
    // TEI-MAC 表翻看时暂停实时刷新:仅用户拖动滑块(sliderMoved)与滚轮(wheel)触发;
    // resize 导致的程序性 value 钳制 / 重建 setValue 只发 valueChanged,不会误触发
    connect(m_teimac_table->verticalScrollBar(), &QScrollBar::sliderMoved,
            this, [this](int) { pause_live(); });
    connect(m_teimac_table->horizontalScrollBar(), &QScrollBar::sliderMoved,
            this, [this](int) { pause_live(); });
    m_teimac_table->viewport()->installEventFilter(this);  // 滚轮翻看

    // 底部:路由变更表(筛选)
    m_routes_filter = new QLineEdit(this);
    m_routes_filter->setPlaceholderText(trl::L("筛选(时间/类型/说明)…"));
    connect(m_routes_filter, &QLineEdit::textChanged, this, &TopoWindow::on_routes_filter);
    m_routes_model = new QStandardItemModel(this);
    m_routes_table = new QTableView(this);
    m_routes_table->setModel(m_routes_model);
    m_routes_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_routes_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_routes_table->horizontalHeader()->setStretchLastSection(true);
    m_routes_table->verticalHeader()->setVisible(false);
    // 双击路由变更表某行 → 追溯到该行对应的帧(序号列对应主界面帧序号)
    connect(m_routes_table, &QTableView::doubleClicked,
            this, &TopoWindow::on_routes_double_clicked);
    enable_table_copy(m_routes_table);
    // 滚动逻辑与主界面一致:滚到底部才跟随最新,滚离底部暂停跟随
    connect(m_routes_table->verticalScrollBar(), &QScrollBar::valueChanged,
            this, [this](int value) {
                if (m_rebuilding_routes) return;  // 重建期间忽略,防 clear 干扰
                m_routes_follow_bottom =
                    (value >= m_routes_table->verticalScrollBar()->maximum());
            });

    // 右侧面板(TEI→MAC)
    auto* teimac_panel = new QWidget(this);
    auto* teimac_lay = new QVBoxLayout(teimac_panel);
    teimac_lay->setContentsMargins(0, 0, 0, 0);
    teimac_lay->addWidget(new QLabel(trl::L("TEI → MAC 映射"), teimac_panel));
    teimac_lay->addWidget(m_teimac_search);
    teimac_lay->addWidget(m_teimac_table, 1);

    // 中央:图 + 右侧表
    auto* mid_split = new QSplitter(Qt::Horizontal, this);
    mid_split->addWidget(m_graph);
    mid_split->addWidget(teimac_panel);
    mid_split->setStretchFactor(0, 3);
    mid_split->setStretchFactor(1, 2);

    // 底部面板(路由变更)
    auto* routes_panel = new QWidget(this);
    auto* routes_lay = new QVBoxLayout(routes_panel);
    routes_lay->setContentsMargins(0, 0, 0, 0);
    routes_lay->addWidget(new QLabel(trl::L("路由变更记录(关联确认/关联指示/关联汇总指示/代理变更请求/代理变更/发现列表/离线指示/CCO重启/STA重启)"), routes_panel));
    routes_lay->addWidget(m_routes_filter);
    routes_lay->addWidget(m_routes_table, 1);

    // 底部另一页签:异常/冲突(同一 MAC 多 TEI / 同一 TEI 多 MAC / 重启次数振荡)
    // 与路由变更事件分离:这些不是拓扑演进,而是数据自相矛盾的嫌疑(重复组网等)
    m_anom_model = new QStandardItemModel(this);
    m_anom_table = new QTableView(this);
    m_anom_table->setModel(m_anom_model);
    m_anom_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_anom_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_anom_table->horizontalHeader()->setStretchLastSection(true);
    m_anom_table->verticalHeader()->setVisible(false);
    enable_table_copy(m_anom_table);
    m_anom_table->setToolTip(trl::L("双击「首次帧」跳到首次出现的帧，双击「最近帧」跳到最近一次的帧"));
    // 双击 → 追溯到帧:双击「首次帧」列跳首次出现的帧,双击「最近帧」(或其它列)跳最近一次的帧
    connect(m_anom_table, &QTableView::doubleClicked, this, [this](const QModelIndex& idx) {
        if (!idx.isValid() || !m_anom_model) return;
        auto* it = m_anom_model->item(idx.row(), kAnomColFirstFrame);
        if (!it) return;
        // 首次:第 0 列「首次帧」或第 7 列「首次时间」;其余列一律按"最近一次"处理
        const bool to_first = (idx.column() == kAnomColFirstFrame
                            || idx.column() == kAnomColFirstTime);
        const qint64 frame = to_first ? it->data(Qt::UserRole + 2).toLongLong()
                                      : it->data(Qt::UserRole).toLongLong();
        const qint64 ms = to_first ? it->data(Qt::UserRole + 3).toLongLong()
                                   : it->data(Qt::UserRole + 1).toLongLong();
        if (frame >= 0) emit request_history(frame, ms);
    });
    auto* anom_panel = new QWidget(this);
    auto* anom_lay = new QVBoxLayout(anom_panel);
    anom_lay->setContentsMargins(0, 0, 0, 0);
    anom_lay->addWidget(new QLabel(trl::L("异常/冲突记录(同一 MAC 多 TEI / 同一 TEI 多 MAC / 重启次数振荡)"), anom_panel));
    anom_lay->addWidget(m_anom_table, 1);

    auto* bottom_tabs = new QTabWidget(this);
    bottom_tabs->addTab(routes_panel, trl::L("路由变更"));
    bottom_tabs->addTab(anom_panel, trl::L("异常/冲突"));

    // 总布局:顶部下拉 + 中央分割 + 底部表
    auto* top_lay = new QHBoxLayout();
    top_lay->addWidget(new QLabel(trl::L("网络:"), this));
    top_lay->addWidget(m_nid_combo, 1);
    // 历史回放调试:模式标签 + 回到实时按钮
    m_mode_label = new QLabel(trl::L("实时"), this);
    m_mode_label->setStyleSheet(QStringLiteral("QLabel { color: palette(highlight); font-weight: bold; }"));
    top_lay->addWidget(m_mode_label);
    m_btn_live = new QPushButton(trl::L("回到实时"), this);
    m_btn_live->setVisible(false);
    connect(m_btn_live, &QPushButton::clicked, this, [this] {
        m_pause_live = false;      // 恢复 TEI-MAC 交互暂停
        update_mode_ui();
        request_live();            // 恢复历史回放(无历史回放时无副作用)
    });
    top_lay->addWidget(m_btn_live);
    // 一键适应视图:缩小/拖拽后找回整张拓扑图;同时让本窗口各表列宽按内容重排一次
    auto* btn_fit = new QPushButton(trl::L("适应视图"), this);
    btn_fit->setToolTip(trl::L("缩放并居中显示整张拓扑图，并让本窗口各表列宽按内容重新适配"));
    connect(btn_fit, &QPushButton::clicked, this, [this] {
        m_graph->fit_view();
        fit_tables_once();
    });
    top_lay->addWidget(btn_fit);

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(6, 6, 6, 6);
    root->addLayout(top_lay);
    root->addWidget(mid_split, 1);
    root->addWidget(bottom_tabs, 1);

    // 节流刷新:高频拓扑事件只置脏标志,定时器批量刷新(防回放/采集卡顿)
    m_refresh_timer = new QTimer(this);
    m_refresh_timer->setInterval(200);
    connect(m_refresh_timer, &QTimer::timeout, this, [this] {
        if (m_dirty && isVisible() && !m_hist_mode && !m_pause_live) {
            m_dirty = false;
            refresh_nids();
            rebuild_all();
        }
    });
    m_refresh_timer->start();
}

void TopoWindow::set_state_map(const QHash<quint32, TopoState>* map) {
    m_states = map;
    refresh_nids();
}

// 仅强制「显示 + 更新 m_current_nid」，不重建内容。
// refresh_nids() 每 200ms 调它做幂等收敛，若在此重建会造成性能灾难。
void TopoWindow::force_display_nid(quint32 nid) {
    m_current_nid = nid;
    setWindowTitle(QStringLiteral("NID:0x%1 TOPO").arg(nid, 0, 16));
    for (int i = 0; i < m_nid_combo->count(); ++i) {
        if (m_nid_combo->itemData(i).toUInt() == nid) {
            if (m_nid_combo->currentIndex() != i) {
                m_nid_combo->blockSignals(true);
                m_nid_combo->setCurrentIndex(i);
                m_nid_combo->blockSignals(false);
            }
            break;
        }
    }
}

void TopoWindow::refresh_nids() {
    if (m_nid_combo->popup_open())
        return;

    const quint32 prev = m_current_nid;
    const auto* states = view_states();

    // 1) 算目标列表(含 label)
    struct Item { QString label; quint32 nid; };
    QVector<Item> want;
    if (states) {
        // 按 NID 升序;下拉项附带 CCO MAC 与首次识别时间(区分同 MAC 新旧网络)
        QList<quint32> nids = states->keys();
        std::sort(nids.begin(), nids.end());
        for (quint32 nid : nids) {
            const TopoState& st = states->value(nid);
            if (!st.has_topology_content()) continue;  // 隐藏仅用于 RestartCount 基线的状态
            QString label = QStringLiteral("NID:0x%1").arg(nid, 0, 16);
            if (st.cco_mac)
                label += QStringLiteral(" CCO:") + format_mac(st.cco_mac);
            if (st.first_seen_frame >= 0) {
                label += QStringLiteral(" %1:#%2 %3")
                    .arg(trl::L("首次")).arg(st.first_seen_frame)
                    .arg(format_time(st.first_seen_ms));
            }
            want.append({label, nid});
        }
    }

    // 2) 列表未变 ⇒ 不重建（每 200ms 无条件 clear()+addItem() 会吞掉
    //    currentIndexChanged 信号，保住点击信号）
    bool same_list = (want.size() == m_nid_combo->count());
    if (same_list) {
        for (int i = 0; i < want.size(); ++i) {
            if (m_nid_combo->itemText(i) != want[i].label
                || m_nid_combo->itemData(i).toUInt() != want[i].nid) {
                same_list = false;
                break;
            }
        }
    }
    if (!same_list) {
        m_nid_combo->blockSignals(true);
        m_nid_combo->clear();
        for (const auto& it : want)
            m_nid_combo->addItem(it.label, it.nid);
        m_nid_combo->blockSignals(false);
    }

    // 3) 无条件强制显示当前 NID（唯一真相 = m_current_nid）
    //    列表里没有它 ⇒ 落到第一个并重置 m_current_nid
    //    注意：判 contains 而非 prev 非零 —— NID 0 是合法值(24bit 无符号)
    if (states && states->contains(prev)) {
        force_display_nid(prev);
    } else if (m_nid_combo->count() > 0) {
        const quint32 first = m_nid_combo->itemData(0).toUInt();
        const bool changed = (first != m_current_nid);
        force_display_nid(first);
        if (changed) rebuild_all();     // 目标 NID 真的变了才重建内容
    } else {
        rebuild_all();                  // 列表空了(如主界面 clear)
    }
}

void TopoWindow::set_current_nid(quint32 nid) {
    // 早退条件不能只看逻辑值：refresh_nids() 会 clear()+重建下拉项，
    // 重建后 currentIndex 落回 0，此时 m_current_nid 未变但 UI 已错位，
    // 若在此早退则下拉框永远显示第一项（用户报的「选第二个跳回第一个」）。
    const bool same_nid = (nid == m_current_nid);

    // UI 同步无条件执行（幂等：index 已正确则跳过 setCurrentIndex）
    for (int i = 0; i < m_nid_combo->count(); ++i) {
        if (m_nid_combo->itemData(i).toUInt() == nid) {
            if (m_nid_combo->currentIndex() != i) {
                m_nid_combo->blockSignals(true);
                m_nid_combo->setCurrentIndex(i);
                m_nid_combo->blockSignals(false);
            }
            break;
        }
    }

    if (same_nid)
        return;                     // 逻辑值未变 ⇒ 不重建内容（保持原有性能特性）

    m_current_nid = nid;
    setWindowTitle(QStringLiteral("NID:0x%1 TOPO").arg(nid, 0, 16));
    rebuild_all();
}

void TopoWindow::on_nid_changed(int idx) {
    if (idx < 0) return;
    const quint32 nid = m_nid_combo->itemData(idx).toUInt();
    set_current_nid(nid);
}

void TopoWindow::on_routes_filter(const QString& text) {
    Q_UNUSED(text);
    rebuild_routes_table();
}

void TopoWindow::on_teimac_search(const QString& text) {
    Q_UNUSED(text);
    rebuild_teimac_table();
}

void TopoWindow::closeEvent(QCloseEvent* e) {
    // 关闭 = 隐藏,保留拓扑状态,下次工具栏"拓扑"再次打开
    hide();
    e->ignore();
}

void TopoWindow::mark_dirty() {
    if (m_hist_mode) return;  // 历史回放模式:冻结,不跟随新帧
    m_dirty = true;  // 仅置脏标志;定时器批量刷新
}

void TopoWindow::refresh_current() {
    if (!isVisible()) return;  // 未打开时不刷新(打开时由 open_topo_window 触发)
    // 实时刷新:新帧到达后重新收集 NID(可能有新网络)并刷新当前 NID 内容
    refresh_nids();
    rebuild_all();
}

void TopoWindow::fit_tables_once() {
    // 列宽上下限:过窄列(空内容/单字符)无法点击,过宽列(长描述/邻居 HTML)会挤掉其它列
    constexpr int kMinColWidth = 48;
    constexpr int kMaxColWidth = 640;
    const QList<QTableView*> tables{m_teimac_table, m_routes_table, m_anom_table};
    for (QTableView* view : tables) {
        if (!view || !view->model()) continue;
        QHeaderView* hh = view->horizontalHeader();
        const int cols = hh->count();
        if (cols <= 0) continue;
        // 只处理"固定宽度(Interactive)"的列:ResizeToContents 的列本来就随内容自适应,
        // Stretch 的列随窗口伸缩;对它们强改会打断原策略(实测:先量再还原策略,
        // 还原时 Qt 会按内容重算,把下限覆盖掉)。邻居表(TEI-MAC)因此整体跳过。
        QVector<int> fixed_cols;
        for (int c = 0; c < cols; ++c)
            if (hh->sectionResizeMode(c) == QHeaderView::Interactive) fixed_cols.append(c);
        if (fixed_cols.isEmpty()) continue;
        // 这些列本来就不是自适配 ⇒ resizeColumnsToContents() 直接生效
        view->resizeColumnsToContents();
        for (int c : fixed_cols) {
            if (hh->sectionSize(c) < kMinColWidth) hh->resizeSection(c, kMinColWidth);
            else if (hh->sectionSize(c) > kMaxColWidth) hh->resizeSection(c, kMaxColWidth);
        }
    }
}

void TopoWindow::rebuild_anomaly_table() {
    // 异常/冲突表:每条异常占一行(同类同主体已由 TopoState 合并,trips 累加),
    // 回放模式读冻结快照,实时模式读实时表(与图/TEI-MAC 表口径一致)
    const int saved = m_anom_table->verticalScrollBar()->value();
    m_anom_model->clear();
    m_anom_model->setHorizontalHeaderLabels(
        {trl::L("首次帧"), trl::L("类别"), QStringLiteral("TEI"), QStringLiteral("MAC"),
         trl::L("介质"), trl::L("次数"), trl::L("最近变化"), trl::L("首次时间"),
         trl::L("最近时间"), trl::L("最近帧")});
    const TopoState* st = nullptr;
    if (const auto* states = view_states()) {
        auto it = states->constFind(m_current_nid);
        if (it != states->constEnd()) st = &it.value();
    }
    if (st) {
        for (const TopoAnomaly& a : st->anomalies) {
            QString tei_txt, mac_txt, change;
            switch (a.kind) {
                case TopoAnomalyKind::MacMultipleTei:
                    // 同一 MAC 先后落在两个仍在线 TEI 上:TEI 列显示 旧→新
                    tei_txt = QStringLiteral("%1→%2").arg(a.tei_old).arg(a.tei);
                    mac_txt = format_mac(a.mac);
                    break;
                case TopoAnomalyKind::TeiMultipleMac:
                    // 同一 TEI 先后被两个仍在线 MAC 使用:MAC 列显示 旧→新
                    tei_txt = QString::number(a.tei);
                    mac_txt = QStringLiteral("%1→%2").arg(format_mac(a.mac_old), format_mac(a.mac));
                    break;
                case TopoAnomalyKind::RestartCountOscillation:
                    tei_txt = QString::number(a.tei);
                    mac_txt = a.mac ? format_mac(a.mac) : QStringLiteral("-");
                    // 取值区间 + 最近一次方向(便于一眼看出 9↔12 这类往返)
                    change = QStringLiteral("%1↔%2 (%3→%4)")
                                 .arg(qMin(a.value_from, a.value_to))
                                 .arg(qMax(a.value_from, a.value_to))
                                 .arg(a.value_from)
                                 .arg(a.value_to);
                    break;
                case TopoAnomalyKind::LinkCountMismatch:
                    // 两链路各自计数:value_from=载波 rc,value_to=无线 rc
                    tei_txt = QString::number(a.tei);
                    mac_txt = a.mac ? format_mac(a.mac) : QStringLiteral("-");
                    change = QStringLiteral("%1 %2 / %3 %4")
                                 .arg(trl::L("载波")).arg(a.value_from)
                                 .arg(trl::L("无线")).arg(a.value_to);
                    break;
                case TopoAnomalyKind::NidConflict:
                    tei_txt = QStringLiteral("-");
                    mac_txt = QStringLiteral("%1→%2")
                                  .arg(format_mac(a.mac_old), format_mac(a.mac));
                    change = trl::L("同一 NID 下出现不同 CCO MAC");
                    break;
            }
            QString medium = QStringLiteral("-");
            if (a.kind == TopoAnomalyKind::RestartCountOscillation)
                medium = a.is_rf ? trl::L("无线") : trl::L("载波");
            else if (a.kind == TopoAnomalyKind::LinkCountMismatch)
                medium = trl::L("载波 / 无线");
            auto* c0 = new QStandardItem(QString::number(a.first_frame));
            // 双击追溯:UserRole 存最近一次(帧/时间),UserRole+2/+3 存首次(帧/时间),
            // 由双击列号选择(首次帧列 → 首次;最近帧列/其它列 → 最近)
            c0->setData(QVariant::fromValue(a.last_frame), Qt::UserRole);
            c0->setData(QVariant::fromValue(a.last_ms), Qt::UserRole + 1);
            c0->setData(QVariant::fromValue(a.first_frame), Qt::UserRole + 2);
            c0->setData(QVariant::fromValue(a.first_ms), Qt::UserRole + 3);
            // "次数"列在各类里含义不同(A/B/NID 冲突次数、C 往返次数、D 差异组合数):
            // 逐类给文本与说明,避免把"往返 20 次"误读成"重启 20 次"
            QString trips_txt = QString::number(a.trips);
            QString trips_tip;
            switch (a.kind) {
                case TopoAnomalyKind::MacMultipleTei:
                case TopoAnomalyKind::TeiMultipleMac:
                    trips_tip = trl::L("冲突次数：同一主体反复冲突的累计次数");
                    break;
                case TopoAnomalyKind::NidConflict:
                    trips_tip = trl::L("冲突次数：同一 NID 下每发现一个新的 CCO MAC 计一次");
                    break;
                case TopoAnomalyKind::RestartCountOscillation:
                    trips_tip = trl::L("往返次数：回到出现过的取值才计，首次出现新值不计");
                    break;
                case TopoAnomalyKind::LinkCountMismatch:
                    trips_txt = trl::L("%1(组合)").arg(a.trips);
                    trips_tip = trl::L("差异组合数：每个不同的 (载波,无线) 取值组合各计一次");
                    break;
            }
            auto* trips_item = new QStandardItem(trips_txt);
            trips_item->setToolTip(trips_tip);
            QList<QStandardItem*> row;
            row << c0
                << new QStandardItem(anomaly_kind_name(a.kind))
                << new QStandardItem(tei_txt)
                << new QStandardItem(mac_txt)
                << new QStandardItem(medium)
                << trips_item
                << new QStandardItem(change)
                << new QStandardItem(format_time(a.first_ms))
                << new QStandardItem(format_time(a.last_ms))
                << new QStandardItem(QString::number(a.last_frame));
            m_anom_model->appendRow(row);
        }
    }
    m_anom_table->verticalScrollBar()->setValue(saved);
}

void TopoWindow::rebuild_all() {
    // 图(历史回放模式读冻结快照,否则读实时表)
    const TopoState* st = nullptr;
    if (const auto* states = view_states()) {
        auto it = states->constFind(m_current_nid);
        if (it != states->constEnd()) st = &it.value();
    }
    m_graph->set_state(st);
    // 三张表
    rebuild_routes_table();
    rebuild_teimac_table();
    rebuild_anomaly_table();
}

void TopoWindow::show_history(const QHash<quint32, TopoState>* hist, bool active,
                              qint64 frame_index, qint64 frame_ms) {
    m_hist_states = hist;
    m_hist_mode = active;
    m_hist_frame = active ? frame_index : -1;
    if (active) {
        m_mode_label->setText(
            QStringLiteral("%1 @ #%2 %3").arg(trl::L("历史回放")).arg(frame_index)
                                         .arg(format_time(frame_ms)));
    }
    update_mode_ui();
    refresh_nids();
    rebuild_all();
    highlight_history_row();  // 标出冻结位置;路由表保留全部行(含目标帧之后的)
}

void TopoWindow::show_live() {
    m_hist_mode = false;
    m_pause_live = false;   // 恢复 TEI-MAC 交互暂停
    m_hist_states = nullptr;
    m_hist_frame = -1;
    if (m_routes_table && m_routes_table->selectionModel())
        m_routes_table->selectionModel()->clearSelection();
    update_mode_ui();
    refresh_nids();
    rebuild_all();
}

void TopoWindow::update_mode_ui() {
    if (m_pause_live && !m_hist_mode)
        m_mode_label->setText(trl::L("已暂停"));   // TEI-MAC 交互暂停
    else if (!m_hist_mode)
        m_mode_label->setText(trl::L("实时"));
    m_btn_live->setVisible(m_hist_mode || m_pause_live);
}

void TopoWindow::pause_live() {
    if (m_hist_mode || m_pause_live) return;   // 历史回放已冻结,或已暂停
    m_pause_live = true;
    update_mode_ui();
}

bool TopoWindow::eventFilter(QObject* watched, QEvent* event) {
    // TEI-MAC 表滚轮翻看:viewport 收到 Wheel 事件 → 暂停实时刷新
    if (watched == m_teimac_table->viewport() && event->type() == QEvent::Wheel)
        pause_live();
    return QWidget::eventFilter(watched, event);
}

namespace {
/// @brief 事件行的 MAC 文本:帧内自带 MAC 优先,其余 TEI 用"截至该事件前"的时点映射解析
/// @param asof 该事件**之前**累积的 TEI→MAC(调用方保证不含本事件)
/// @details 为什么不能直接用最终映射:事件表是历史追溯。STA 换 TEI 后,早期事件里的旧 TEI
///          在最终映射里已经不存在(或已被改成别的 MAC),用最终映射回填会把"当时"的信息
///          篡改成"现在"的信息。故一律以时点映射解析;帧内自带的 MAC(关联请求/确认的
///          nodes、离线指示的 leaves)是直接证据,优先级最高。
QString event_mac_text(const TopoEvent& e, const QHash<quint16, quint64>& asof) {
    QHash<quint16, quint64> tei_mac;   // TEI → MAC(0=未知)
    QList<quint64> orphan_macs;        // 帧内直带但 TEI 未知(如离线指示只给 MAC)
    for (const TeiMacPair& p : e.nodes) {
        if (!p.mac) continue;
        if (p.tei) tei_mac.insert(p.tei, p.mac);
        else orphan_macs.append(p.mac);
    }
    for (quint64 mac : e.leaves) {
        if (!mac) continue;
        // 离线指示帧只带 MAC:反查"此时点"该 MAC 对应的 TEI(不是最终映射)
        quint16 tei = 0;
        for (auto it = asof.constBegin(); it != asof.constEnd(); ++it) {
            if (it.value() == mac) { tei = it.key(); break; }
        }
        if (tei) tei_mac.insert(tei, mac);
        else orphan_macs.append(mac);
    }
    // 事件涉及但未带 MAC 的 TEI:按"截至该事件前"的映射补
    QList<quint16> teis;
    for (const auto& r : e.routes) {
        if (r.first) teis << r.first;
        if (r.second) teis << r.second;
    }
    for (const auto& ur : e.up_routes) {
        if (ur.first) teis << ur.first;
        if (ur.second) teis << ur.second;
    }
    for (const auto& pr : e.node_link_types) {
        if (pr.first) teis << pr.first;
    }
    for (quint16 c : e.child_teis) {
        if (c) teis << c;
    }
    if (e.discover_src_tei) teis << e.discover_src_tei;
    for (quint16 t : teis) {
        if (tei_mac.contains(t)) continue;      // 帧内直带优先
        tei_mac.insert(t, asof.value(t, 0));    // 0 = 此时点未知
    }
    QStringList parts;
    QList<quint16> keys = tei_mac.keys();
    std::sort(keys.begin(), keys.end());
    for (quint16 t : keys) {
        const quint64 mac = tei_mac.value(t);
        parts << (mac ? QStringLiteral("TEI=%1 %2").arg(t).arg(format_mac(mac))
                      : QStringLiteral("TEI=%1 %2").arg(t).arg(trl::L("未知")));
    }
    for (quint64 mac : orphan_macs) parts << format_mac(mac);   // TEI 未分配的直带 MAC
    parts.removeDuplicates();
    return parts.isEmpty() ? QStringLiteral("-") : parts.join(QStringLiteral("; "));
}

/// @brief 把本事件携带的 TEI→MAC 并入时点映射
/// @note 必须在取完本行的 MAC 文本之后调用,保证"截至该事件前"的语义
void advance_mac_asof(QHash<quint16, quint64>& asof, const TopoEvent& e) {
    for (const TeiMacPair& p : e.nodes) {
        if (p.tei && p.mac) asof.insert(p.tei, p.mac);
    }
    if (e.cco_mac) asof.insert(static_cast<quint16>(kTeiCco), e.cco_mac);
}
}  // namespace

void TopoWindow::append_routes_rows(const TopoState* st, const QString& filter,
                                   int from, int to) {
    for (int i = from; i < to; ++i) {  // 时间正序,最新在底部(与主界面一致)
        const TopoEvent& e = st->events[i];
        // MAC 先按"截至本事件前"的时点映射解析,再把本事件的 TEI→MAC 并入
        const QString mac = event_mac_text(e, m_routes_mac_asof);
        advance_mac_asof(m_routes_mac_asof, e);
        const QString time = format_time(e.epoch_ms);
        const QString kind = event_kind_name(e.kind);
        const QString nid = QStringLiteral("0x%1").arg(e.nid, 0, 16);
        const QString desc = e.desc;
        if (!filter.isEmpty()) {
            if (!time.contains(filter, Qt::CaseInsensitive) &&
                !kind.contains(filter, Qt::CaseInsensitive) &&
                !nid.contains(filter, Qt::CaseInsensitive) &&
                !mac.contains(filter, Qt::CaseInsensitive) &&
                !desc.contains(filter, Qt::CaseInsensitive))
                continue;
        }
        QList<QStandardItem*> row;
        // 首列序号:对应主界面帧列表的帧序号;UserRole 存帧序号/时间点供双击追溯
        // (过滤可能跳过行,不能用行号反推事件下标)
        QStandardItem* seq_item = new QStandardItem(QString::number(e.frame_index));
        seq_item->setData(e.frame_index, Qt::UserRole);
        seq_item->setData(e.epoch_ms, Qt::UserRole + 1);
        row << seq_item
            << new QStandardItem(time)
            << new QStandardItem(kind)
            << new QStandardItem(nid)
            << new QStandardItem(mac)
            << new QStandardItem(desc);
        m_routes_model->appendRow(row);
    }
}

/// @brief 路由变更表双击 → 按该行序号列对应的帧号发射追溯请求
void TopoWindow::on_routes_double_clicked(const QModelIndex& idx) {
    if (!idx.isValid() || !m_routes_model) return;
    const QStandardItem* seq_item = m_routes_model->item(idx.row(), 0);
    if (!seq_item) return;
    const qint64 frame = seq_item->data(Qt::UserRole).toLongLong();
    const qint64 ms = seq_item->data(Qt::UserRole + 1).toLongLong();
    if (frame < 0) return;
    emit request_history(frame, ms);
}

/// @brief TEI→MAC 表邻居表单元格双击 → 弹出独立窗口显示邻居明细(载波+无线混合,含可靠度评分)
void TopoWindow::on_teimac_double_clicked(const QModelIndex& idx) {
    if (!idx.isValid()) return;
    pause_live();   // 双击 TEI-MAC 表:暂停实时刷新,避免跳转/弹窗被刷新覆盖
    const QStandardItem* tei_item = m_teimac_model->item(idx.row(), 0);
    if (!tei_item) return;
    const quint16 sta_tei = (quint16)tei_item->data(Qt::UserRole).toUInt();

    // 非邻居表列(TEI/MAC/入网链路/双模/状态/层级/代理 TEI)双击 → 跳转到 TOPO 图对应 STA
    if (idx.column() != 7) {
        if (sta_tei != 0)
            m_graph->focus_node(sta_tei);
        return;
    }

    // 邻居表列(7)双击 → 弹独立窗口显示邻居明细(载波+无线混合,含可靠度评分)
    if (sta_tei == 0) return;  // 未分配 TEI 的入网中节点无邻居表

    const TopoState* st = nullptr;
    if (const auto* states = view_states()) {
        auto it = states->constFind(m_current_nid);
        if (it != states->constEnd()) st = &it.value();
    }
    if (!st) return;

    // 邻居集 = 载波(neighbors/counts) ∪ 无线(rates/snrs) ∪ 报告过"我"的上报方(下行方向)
    QSet<quint16> nb_set;
    for (quint16 nb : st->neighbors.value(sta_tei)) nb_set.insert(nb);
    const QHash<quint16, quint8> rates_me = st->neighbor_rates.value(sta_tei);
    for (auto it = rates_me.constBegin(); it != rates_me.constEnd(); ++it) nb_set.insert(it.key());
    const QHash<quint16, qint16> snrs_me = st->neighbor_snrs.value(sta_tei);
    for (auto it = snrs_me.constBegin(); it != snrs_me.constEnd(); ++it) nb_set.insert(it.key());
    const QHash<quint16, int> counts_me = st->neighbor_counts.value(sta_tei);
    for (auto it = counts_me.constBegin(); it != counts_me.constEnd(); ++it) nb_set.insert(it.key());
    for (auto it = st->neighbor_rates.constBegin(); it != st->neighbor_rates.constEnd(); ++it)
        if (it.value().contains(sta_tei)) nb_set.insert(it.key());
    for (auto it = st->neighbor_counts.constBegin(); it != st->neighbor_counts.constEnd(); ++it)
        if (it.value().contains(sta_tei)) nb_set.insert(it.key());
    if (nb_set.isEmpty()) return;

    // 本 STA 自己的代理(PCO):与主表"代理 TEI"列同一来源(parent_tei);
    // 0=根(CCO 自身)、0xFFFF=未知时无可标记行
    const quint16 own_pco = st->nodes.value(sta_tei).parent_tei;
    const bool has_pco = own_pco != kTeiInvalid && own_pco != 0;

    // 每邻居评分(公式见 docs/TOPO_NEIGHBOR_SCORE.md;无线用接收率,载波用发现次数)
    struct NeighborRow { quint16 tei; int r; int cnt_sum; int rssi; QString tip; };
    QVector<NeighborRow> rows;
    rows.reserve(nb_set.size());
    for (quint16 nb : nb_set) {
        const TopoNode& node = st->nodes.value(nb);
        const bool is_rf = node.link_type == LinkTypeRf || (node.link_type == LinkTypeUnknown && node.is_rf);  // 评分按入网链路,未定时回退 is_rf(与"入网链路"列口径一致)
        const int cnt_me_nb = counts_me.value(nb, 0);
        const int cnt_nb_me = st->neighbor_counts.value(nb).value(sta_tei, 0);
        const int cnt_sum = cnt_me_nb + cnt_nb_me;
        const int rssi = node.rssi_known ? node.rssi_dbm : INT_MIN;  // 未知信号强度沉底,避免按 0 dBm 压过真实 -100 dBm
        int r = 0;
        QString tip;
        if (is_rf) {
            const bool up_p = rates_me.contains(nb);
            const bool down_p = st->neighbor_rates.value(nb).contains(sta_tei);
            const int up = rates_me.value(nb, 0);
            const int down = st->neighbor_rates.value(nb).value(sta_tei, 0);
            const double base = (up_p && down_p) ? (up + down) / 2.0
                                : (up_p ? up * 0.6 : (down_p ? down * 0.6 : 0.0));
            const int activity = qMin(100, cnt_sum * 5);
            const int sig = node.rssi_known
                ? qRound(qBound(0.0, (node.rssi_dbm + 110.0) / 110.0, 1.0) * 100.0) : 0;
            r = qRound(0.50 * base + 0.30 * activity + 0.20 * sig);
            tip = trl::L("base=%1 活跃度=%2 信号归一=%3 · 权重 0.50/0.30/0.20")
                      .arg(base, 0, 'f', 1).arg(activity).arg(sig);
        } else {
            const bool both = cnt_me_nb > 0 && cnt_nb_me > 0;
            const bool one  = (cnt_me_nb > 0) != (cnt_nb_me > 0);
            const int symmetry = both ? 100 : (one ? 50 : 0);
            const int activity = qMin(100, cnt_sum * 5);
            r = qRound(0.60 * symmetry + 0.40 * activity);
            tip = trl::L("对称性=%1 活跃度=%2 · 权重 0.60/0.40").arg(symmetry).arg(activity);
        }
        rows.append({nb, r, cnt_sum, rssi, tip});
    }
    std::sort(rows.begin(), rows.end(), [](const NeighborRow& a, const NeighborRow& b) {
        if (a.r != b.r) return a.r > b.r;
        if (a.cnt_sum != b.cnt_sum) return a.cnt_sum > b.cnt_sum;
        return a.rssi > b.rssi;
    });

    auto* dlg = new QDialog(this);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setWindowTitle(trl::L("STA TEI=%1 的邻居表").arg(sta_tei));
    dlg->resize(980, 440);
    auto* lay = new QVBoxLayout(dlg);
    auto* model = new QStandardItemModel(dlg);
    model->setHorizontalHeaderLabels(
        {QStringLiteral("TEI"), QStringLiteral("MAC"), trl::L("入网链路"), trl::L("双模"), QStringLiteral("SNR (dB)"),
         trl::L("信号强度 (dBm)"), trl::L("上行成功率%（对方→我）"), trl::L("下行成功率%（我→对方）"),
         trl::L("我报它次数"), trl::L("它报我次数"), trl::L("双向"), trl::L("可靠度")});
    // PCO 行前景色:沿主表邻居绿色的主题口径,按表格背景明暗取琥珀色深/浅档,
    // 白底加深、黑底提亮,保证双主题下都与普通行可区分
    const bool light_bg = dlg->palette().color(QPalette::Base).lightness() > 128;
    const QColor pco_color = light_bg ? QColor(176, 90, 0) : QColor(255, 183, 77);
    for (const NeighborRow& row : rows) {
        const quint16 nb = row.tei;
        const TopoNode& node = st->nodes.value(nb);
        const QString s_mac = node.mac ? format_mac(node.mac) : QStringLiteral("-");
        const QString s_link = node.link_type == LinkTypeUnknown
            ? trl::L("未定|载波")
            : (node.link_type == LinkTypeRf ? trl::L("无线") : trl::L("载波"));
        const QString s_dual = node.rf_capable ? trl::L("是") : trl::L("否");
        const QString s_snr = snrs_me.contains(nb) ? QString::number(snrs_me.value(nb)) : QStringLiteral("—");
        const QString s_rssi = node.rssi_known ? QString::number(node.rssi_dbm) : QStringLiteral("—");
        const bool up_p = rates_me.contains(nb);
        const bool down_p = st->neighbor_rates.value(nb).contains(sta_tei);
        const QString s_up = up_p ? QString::number(rates_me.value(nb)) : QStringLiteral("—");
        const QString s_down = down_p ? QString::number(st->neighbor_rates.value(nb).value(sta_tei))
                                      : QStringLiteral("—");
        const int cnt_me_nb = counts_me.value(nb, 0);
        const int cnt_nb_me = st->neighbor_counts.value(nb).value(sta_tei, 0);
        const QString s_me_cnt = cnt_me_nb ? QString::number(cnt_me_nb) : QStringLiteral("—");
        const QString s_nb_cnt = cnt_nb_me ? QString::number(cnt_nb_me) : QStringLiteral("—");
        const bool bidir = node.is_rf ? (up_p && down_p) : (cnt_me_nb > 0 && cnt_nb_me > 0);
        const QString s_bidir = bidir ? QStringLiteral("✓") : QStringLiteral("✗");
        QList<QStandardItem*> items;
        items << new QStandardItem(QString::number(nb))
              << new QStandardItem(s_mac)
              << new QStandardItem(s_link)
              << new QStandardItem(s_dual)
              << new QStandardItem(s_snr)
              << new QStandardItem(s_rssi)
              << new QStandardItem(s_up)
              << new QStandardItem(s_down)
              << new QStandardItem(s_me_cnt)
              << new QStandardItem(s_nb_cnt)
              << new QStandardItem(s_bidir);
        QStandardItem* ritem = new QStandardItem(QString::number(row.r));
        ritem->setToolTip(row.tip);
        items << ritem;
        if (has_pco && nb == own_pco) {
            // 自己的 PCO 行:整行加粗 + 琥珀色前景,双主题下均显著区别于普通邻居
            for (QStandardItem* item : items) {
                QFont f = item->font();
                f.setBold(true);
                item->setFont(f);
                item->setForeground(pco_color);
                // 可靠度格已有评分公式提示,不覆盖;其余格加 PCO 说明
                if (item->toolTip().isEmpty())
                    item->setToolTip(trl::L("本站点的代理 (PCO)"));
            }
        }
        model->appendRow(items);
    }
    // 方向图例(用户要求:明确"上行=对方→我 / 下行=我→对方"的数据来源)
    auto* legend = new QLabel(
        trl::L("上行 = 对方发给我的成功率（数据来自我的发现列表报文）") + QStringLiteral("\n")
        + trl::L("下行 = 我发给对方的成功率（数据来自邻居的发现列表报文）"), dlg);
    legend->setWordWrap(true);
    lay->addWidget(legend);
    auto* view = new QTableView(dlg);
    view->setModel(model);
    view->setSelectionBehavior(QAbstractItemView::SelectRows);
    view->setEditTriggers(QAbstractItemView::NoEditTriggers);
    view->horizontalHeader()->setStretchLastSection(true);
    view->verticalHeader()->setVisible(false);
    enable_table_copy(view);  // 支持 Ctrl+C 复制
    lay->addWidget(view);
    view->resizeColumnsToContents();  // 列宽适配内容
    dlg->show();
}

/// @brief 历史回放模式下选中冻结帧对应的路由表行(仅高亮,不滚动/不删行)
void TopoWindow::highlight_history_row() {
    if (!m_hist_mode || m_hist_frame < 0 || !m_routes_model || !m_routes_table)
        return;
    // 首列 UserRole 存帧序号(过滤可能跳行,不能按行号反推)
    for (int r = 0; r < m_routes_model->rowCount(); ++r) {
        const QStandardItem* seq_item = m_routes_model->item(r, 0);
        if (seq_item && seq_item->data(Qt::UserRole).toLongLong() == m_hist_frame) {
            m_routes_table->selectRow(r);  // 该行双击时本就可见,不强制滚动
            return;
        }
    }
    // 过滤导致目标行不可见:清除旧选中,避免高亮停留在无关行
    m_routes_table->selectionModel()->clearSelection();
}

void TopoWindow::rebuild_routes_table() {
    // 保存滚动状态:用户是否在底部(跟随最新),以及当前滚动条位置(滚离底部时恢复)
    const bool was_follow = m_routes_follow_bottom;
    const int  saved_value = m_routes_table->verticalScrollBar()->value();
    m_rebuilding_routes = true;   // 屏蔽 clear/append 期间 scrollbar 信号干扰

    // 路由变更表恒读实时表:它是帧记录索引,双击进入历史回放时也不得
    // 截断目标帧之后的行(拓扑图/TEI-MAC 表仍读冻结快照,保持冻结语义)
    const QHash<quint32, TopoState>* states = m_states;
    const TopoState* st = nullptr;
    if (states) {
        auto it = states->constFind(m_current_nid);
        if (it != states->constEnd()) st = &it.value();
    }
    const QString filter = m_routes_filter->text().trimmed();
    const int ev_count = st ? st->events.size() : 0;
    // 视图变化(数据源/NID/过滤文本切换,或事件数收缩)→全量重建;
    // 否则只追加新增事件行,避免每 200ms 全量重建 O(E)(E 随抓包时长线性增长)
    const bool view_changed = (states != m_routes_view) || (m_current_nid != m_routes_nid)
                           || (filter != m_routes_filter_text) || (ev_count < m_routes_shown);
    if (view_changed) {
        m_routes_model->clear();
        // 时点映射随全量重建一起重放:清零后由 append_routes_rows 逐事件累积,
        // 保证每行 MAC 都是"截至该事件前"的值(不能用最终映射回填)
        m_routes_mac_asof.clear();
        m_routes_model->setHorizontalHeaderLabels(
            {trl::L("序号"), trl::L("时间点"), trl::L("类型"), QStringLiteral("NID"),
             QStringLiteral("MAC"), trl::L("变更说明")});
        if (st) append_routes_rows(st, filter, 0, ev_count);
        m_routes_view = states;
        m_routes_nid = m_current_nid;
        m_routes_filter_text = filter;
        m_routes_shown = ev_count;
    } else if (ev_count > m_routes_shown) {
        append_routes_rows(st, filter, m_routes_shown, ev_count);
        m_routes_shown = ev_count;
    }

    m_rebuilding_routes = false;
    // 滚动逻辑与主界面一致:在底部(最新)才跟随,否则恢复原位置(不强制跳回)
    if (was_follow)
        m_routes_table->scrollToBottom();
    else
        m_routes_table->verticalScrollBar()->setValue(saved_value);
}

void TopoWindow::rebuild_teimac_table() {
    // 保存水平滚动位置:实时刷新全量重建会重置滚动条,用户向右滑动查看邻居表
    // 时被反复拉回最左;重建后恢复原位置
    const int saved_hscroll = m_teimac_table->horizontalScrollBar()->value();
    m_teimac_model->clear();
    m_teimac_model->setHorizontalHeaderLabels(
        {QStringLiteral("TEI"), QStringLiteral("MAC"), trl::L("入网链路"), trl::L("双模"),
         trl::L("状态"), trl::L("层级"), trl::L("代理 TEI"), trl::L("邻居表")});

    const TopoState* st = nullptr;
    // 历史回放模式读冻结快照,否则读实时表(此前误读 m_states,回放时表格未冻结)
    if (const auto* states = view_states()) {
        auto it = states->constFind(m_current_nid);
        if (it != states->constEnd()) st = &it.value();
    }
    if (!st) return;

    const QString search = m_teimac_search->text().trimmed();
    const QHash<quint16, int> levels = st->compute_levels();
    QList<quint16> teis = st->nodes.keys();
    std::sort(teis.begin(), teis.end());

    for (quint16 tei : teis) {
        const TopoNode& node = st->nodes.value(tei);
        const QString s_tei = tei == kTeiCco ? QStringLiteral("CCO(1)") : QString::number(tei);
        const QString s_mac = node.mac ? format_mac(node.mac) : QStringLiteral("-");
        const QString s_online =
            node.status == NodeStatus::Offline     ? trl::L("离线") :
            node.status == NodeStatus::OnlineGoing ? trl::L("入网中") :
                                                     trl::L("在线");
        const int level = levels.value(tei, -1);
        const QString s_level = level < 0 ? QStringLiteral("-") : QString::number(level);
        // 邻居表:按发现列表出现次数降序排列;颜色统一绿色,
        // 由亮绿(出现多,信号强)→暗绿(出现少),暗端仍可见。样式 "TEI2,TEI3"
        // 白色主题下整体加深保证可读,深色主题下提亮保证可见
        QString s_neighbors;
        {
            QVector<quint16> nbs = st->neighbors.value(tei);
            const QHash<quint16, int> counts = st->neighbor_counts.value(tei);
            if (!nbs.isEmpty()) {
                std::sort(nbs.begin(), nbs.end(), [&](quint16 a, quint16 b) {
                    return counts.value(a, 0) > counts.value(b, 0);
                });
                int max_c = 0;
                for (quint16 nb : nbs) max_c = qMax(max_c, counts.value(nb, 0));
                // 按表格背景明暗选择绿色区间
                const bool light_bg = m_teimac_table->palette()
                    .color(QPalette::Base).lightness() > 128;
                // 亮端/暗端的 G 分量:白底用 (144→64),黑底用 (224→160)
                const int g_bright = light_bg ? 144 : 224;
                const int g_dark   = light_bg ? 64  : 160;
                QStringList parts;
                // 邻居过多时只显示前 3 个(已按出现次数降序),其余用 (+N) 折叠:
                // 全量 HTML 会换行,而行高固定只露出首行,导致"只显示部分"。
                // 双击该单元格弹窗仍可看全量邻居(见 on_teimac_double_clicked)。
                const int kMaxNeighborDisplay = 3;
                const int show_n = qMin(nbs.size(), kMaxNeighborDisplay);
                parts.reserve(show_n);
                for (int i = 0; i < show_n; ++i) {
                    const quint16 nb = nbs[i];
                    const double ratio = max_c > 0
                        ? (double)counts.value(nb, 0) / (double)max_c : 0.0;
                    const int g = g_dark + (int)((g_bright - g_dark) * ratio);
                    const QString color = QColor(0, g, 0).name();
                    parts << QStringLiteral("<span style=\"color:%1;\">TEI%2</span>")
                                 .arg(color).arg(nb);
                }
                s_neighbors = parts.join(QStringLiteral(","));
                if (nbs.size() > kMaxNeighborDisplay)
                    s_neighbors += QStringLiteral(
                        "<span style=\"color:#888;\">(+%1)</span>")
                                       .arg(nbs.size() - kMaxNeighborDisplay);
            } else {
                s_neighbors = QStringLiteral("-");
            }
        }
        const QString s_parent = node.parent_tei == kTeiInvalid
            ? QStringLiteral("-") : QString::number(node.parent_tei);
        // 入网链路(读 link_type,不读 is_rf):0=载波 1=无线 0xFF=未定
        const QString s_link = node.link_type == LinkTypeUnknown
            ? trl::L("未定|载波")
            : (node.link_type == LinkTypeRf ? trl::L("无线") : trl::L("载波"));
        const QString s_dual = node.rf_capable ? trl::L("是") : trl::L("否");

        if (!search.isEmpty()) {
            if (!s_tei.contains(search, Qt::CaseInsensitive) &&
                !s_mac.contains(search, Qt::CaseInsensitive))
                continue;
        }
        QList<QStandardItem*> row;
        auto* tei_item = new QStandardItem(s_tei);
        tei_item->setData(tei, Qt::UserRole);  // 双击邻居表时取 STA TEI
        row << tei_item
            << new QStandardItem(s_mac)
            << new QStandardItem(s_link)
            << new QStandardItem(s_dual)
            << new QStandardItem(s_online)
            << new QStandardItem(s_level)
            << new QStandardItem(s_parent)
            << new QStandardItem(s_neighbors);
        m_teimac_model->appendRow(row);
    }

    // 正在入网(关联请求)节点:TEI 未分配,按 MAC 列出
    for (auto it = st->pending.begin(); it != st->pending.end(); ++it) {
        const TopoNode& node = it.value();
        const QString s_tei = QStringLiteral("-");
        const QString s_mac = node.mac ? format_mac(node.mac) : QStringLiteral("-");
        const QString s_online = trl::L("入网中");
        const QString s_level = QStringLiteral("1");
        const QString s_neighbors = QStringLiteral("-");  // 未分配 TEI,无发现列表
        const QString s_parent = QStringLiteral("1");
        const QString s_link = trl::L("未定|载波");   // 入网中节点链路未定
        const QString s_dual = trl::L("否");
        if (!search.isEmpty()) {
            if (!s_tei.contains(search, Qt::CaseInsensitive) &&
                !s_mac.contains(search, Qt::CaseInsensitive))
                continue;
        }
        QList<QStandardItem*> row;
        row << new QStandardItem(s_tei)
            << new QStandardItem(s_mac)
            << new QStandardItem(s_link)
            << new QStandardItem(s_dual)
            << new QStandardItem(s_online)
            << new QStandardItem(s_level)
            << new QStandardItem(s_parent)
            << new QStandardItem(s_neighbors);
        m_teimac_model->appendRow(row);
    }

    // 恢复水平滚动位置(见函数开头注释)
    m_teimac_table->horizontalScrollBar()->setValue(saved_hscroll);
}
