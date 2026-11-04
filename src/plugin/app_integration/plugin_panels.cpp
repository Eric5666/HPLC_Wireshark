/// @file plugin_panels.cpp
/// @brief 插件功能界面实现
#include "plugin_panels.h"

#include <QHeaderView>
#include <QLabel>
#include <QMouseEvent>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollBar>
#include <QTableWidget>
#include <QTextEdit>
#include <QTimer>
#include <QVBoxLayout>
#include <QWheelEvent>

#include "i18n.h"

void register_plugin_panel_i18n() {
    static bool done = false;
    if (done) return;
    done = true;
    trl::register_en("插件", "Plugins");
    trl::register_en("插件(&G)", "Plugins(&G)");
    trl::register_en("插件目录(&D)...", "Plugin directory(&D)...");
    trl::register_en("插件市场(&M)...", "Plugin marketplace(&M)...");
    trl::register_en("显示插件面板", "Show plugin panel");
    trl::register_en("接受", "Accept");
    trl::register_en("拒绝", "Reject");
    trl::register_en("生成报表", "Generate report");
    trl::register_en("正在生成...", "Generating...");
    trl::register_en("帧号", "Frame");
    trl::register_en("告警", "Alarm");
    trl::register_en("值", "Value");
    trl::register_en("等待插件数据...", "Waiting for plugin data...");
    trl::register_en("插件加载失败", "Plugin load failed");
}

// =====================================================================
// PluginPanel 基类
// =====================================================================
PluginPanel::PluginPanel(LocalPluginEngine* engine, const PluginLoadedInfo& info,
                         QWidget* parent)
    : QWidget(parent), m_engine(engine), m_info(info) {
    register_plugin_panel_i18n();
    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(6, 6, 6, 6);
    m_stats = new QLabel(this);
    m_stats->setTextInteractionFlags(Qt::TextSelectableByMouse);
    outer->addWidget(m_stats);
    m_body = new QVBoxLayout();
    outer->addLayout(m_body, 1);
    on_plugin_stats(info.plugin_id, 0, 0);
    connect(m_engine, &LocalPluginEngine::plugin_stats,
            this, &PluginPanel::on_plugin_stats, Qt::QueuedConnection);
}

void PluginPanel::on_plugin_stats(const QString& pid, qint64 accept,
                                  qint64 reject) {
    if (pid != m_info.plugin_id || !m_stats) return;
    m_stats->setText(QStringLiteral("%1: %2  %3: %4")
                         .arg(trl::L("接受")).arg(accept)
                         .arg(trl::L("拒绝")).arg(reject));
}

// =====================================================================
// TopoPluginPanel
// =====================================================================
TopoPluginPanel::TopoPluginPanel(LocalPluginEngine* engine,
                                 const PluginLoadedInfo& info, QWidget* parent)
    : PluginPanel(engine, info, parent) {
    m_view = new QLabel(this);
    m_view->setAlignment(Qt::AlignCenter);
    m_view->setMinimumSize(200, 150);
    m_view->setText(trl::L("等待插件数据..."));
    m_view->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    m_view->setMouseTracking(true);  // hover 悬浮需要
    m_view->installEventFilter(this);
    body_layout()->addWidget(m_view, 1);

    connect(m_engine, &LocalPluginEngine::render_ready,
            this, &TopoPluginPanel::on_render_ready, Qt::QueuedConnection);
    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &TopoPluginPanel::on_refresh_tick);
    m_timer->start(800);
}

void TopoPluginPanel::on_refresh_tick() {
    if (!isVisible()) return;
    const int w = qMax(m_view->width(), 200);
    const int h = qMax(m_view->height(), 150);
    m_engine->request_render(m_info.plugin_id, w, h);
}

void TopoPluginPanel::refresh_now() {
    const int w = qMax(m_view->width(), 200);
    const int h = qMax(m_view->height(), 150);
    m_engine->request_render(m_info.plugin_id, w, h);
}

void TopoPluginPanel::on_render_ready(const QString& pid, const QImage& img) {
    if (pid != m_info.plugin_id) return;
    if (img.isNull()) {
        // 空图:插件主动 request_redraw 提示刷新,或渲染失败
        if (m_view->pixmap().isNull())
            m_view->setText(trl::L("等待插件数据..."));
        else
            on_refresh_tick();  // 已有旧图:主动拉一帧新的
        return;
    }
    m_img_size = img.size();
    m_view->setPixmap(QPixmap::fromImage(img).scaled(
        m_view->size(), Qt::KeepAspectRatio, Qt::SmoothTransformation));
}

/// @brief 视图坐标 → 插件渲染图像坐标(与 setPixmap 的 KeepAspectRatio 一致)
QPoint TopoPluginPanel::to_image_pos(const QPoint& view_pt) const {
    if (m_img_size.isEmpty() || m_view->pixmap().isNull())
        return QPoint(-1, -1);
    const QSize vs = m_view->size();
    const QSize ps = m_img_size.scaled(vs, Qt::KeepAspectRatio);
    const int ox = (vs.width() - ps.width()) / 2;
    const int oy = (vs.height() - ps.height()) / 2;
    const int px = view_pt.x() - ox;
    const int py = view_pt.y() - oy;
    if (px < 0 || py < 0 || px >= ps.width() || py >= ps.height())
        return QPoint(-1, -1);  // 落在留白区
    return QPoint(px * m_img_size.width() / ps.width(),
                  py * m_img_size.height() / ps.height());
}

void TopoPluginPanel::forward_graphics_event(GraphicsEventType type,
                                             const QPoint& view_pt,
                                             int button, int delta_y) {
    GraphicsEvent e;
    e.type = type;
    const QPoint ip = to_image_pos(view_pt);
    e.x = ip.x();
    e.y = ip.y();
    e.button = button;
    e.delta_y = delta_y;
    e.width = m_img_size.width();
    e.height = m_img_size.height();
    m_engine->send_graphics_event(m_info.plugin_id, e);
}

bool TopoPluginPanel::eventFilter(QObject* obj, QEvent* ev) {
    if (obj == m_view && m_engine) {
        switch (ev->type()) {
        case QEvent::MouseMove: {
            const auto* me = static_cast<QMouseEvent*>(ev);
            forward_graphics_event(GraphicsEventType::MouseMove, me->pos(),
                                   0, 0);
            break;
        }
        case QEvent::MouseButtonPress: {
            const auto* me = static_cast<QMouseEvent*>(ev);
            forward_graphics_event(GraphicsEventType::MousePress, me->pos(),
                                   static_cast<int>(me->button()), 0);
            break;
        }
        case QEvent::MouseButtonRelease: {
            const auto* me = static_cast<QMouseEvent*>(ev);
            forward_graphics_event(GraphicsEventType::MouseRelease, me->pos(),
                                   static_cast<int>(me->button()), 0);
            break;
        }
        case QEvent::MouseButtonDblClick: {
            const auto* me = static_cast<QMouseEvent*>(ev);
            forward_graphics_event(GraphicsEventType::MouseDblClick, me->pos(),
                                   static_cast<int>(me->button()), 0);
            break;
        }
        case QEvent::Wheel: {
            const auto* we = static_cast<QWheelEvent*>(ev);
            forward_graphics_event(GraphicsEventType::Wheel,
                                   we->position().toPoint(), 0,
                                   we->angleDelta().y());
            break;
        }
        case QEvent::Leave:
            forward_graphics_event(GraphicsEventType::Leave, QPoint(-1, -1),
                                   0, 0);
            break;
        default:
            break;
        }
    }
    return PluginPanel::eventFilter(obj, ev);
}

// =====================================================================
// ReplayPluginPanel
// =====================================================================
ReplayPluginPanel::ReplayPluginPanel(LocalPluginEngine* engine,
                                     const PluginLoadedInfo& info,
                                     QWidget* parent)
    : PluginPanel(engine, info, parent),
      m_func(info.panel_function.isEmpty() ? QStringLiteral("get_replay_data")
                                           : info.panel_function) {
    m_text = new QPlainTextEdit(this);
    m_text->setReadOnly(true);
    m_text->setPlaceholderText(trl::L("等待插件数据..."));
    QFont f = m_text->font();
    f.setFamily(QStringLiteral("monospace"));
    m_text->setFont(f);
    body_layout()->addWidget(m_text, 1);

    connect(m_engine, &LocalPluginEngine::text_ready,
            this, &ReplayPluginPanel::on_text_ready, Qt::QueuedConnection);
    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &ReplayPluginPanel::on_refresh_tick);
    m_timer->start(1000);
    on_refresh_tick();
}

void ReplayPluginPanel::on_refresh_tick() {
    if (!isVisible()) return;
    m_engine->request_text(m_info.plugin_id, m_func);
}

void ReplayPluginPanel::refresh_now() {
    m_engine->request_text(m_info.plugin_id, m_func);
}

void ReplayPluginPanel::on_text_ready(const QString& pid, const QString& func,
                                      const QString& text) {
    if (pid != m_info.plugin_id || func != m_func) return;
    // 保持滚动位置:只在内容变化时更新
    if (m_text->toPlainText() != text) {
        const int sb = m_text->verticalScrollBar()->value();
        m_text->setPlainText(text);
        m_text->verticalScrollBar()->setValue(sb);
    }
}

// =====================================================================
// DiagPluginPanel
// =====================================================================
DiagPluginPanel::DiagPluginPanel(LocalPluginEngine* engine,
                                 const PluginLoadedInfo& info, QWidget* parent)
    : PluginPanel(engine, info, parent) {
    m_table = new QTableWidget(this);
    m_table->setColumnCount(3);
    m_table->setHorizontalHeaderLabels(
        {trl::L("帧号"), trl::L("告警"), trl::L("值")});
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    body_layout()->addWidget(m_table, 1);

    connect(m_engine, &LocalPluginEngine::diag_alarms,
            this, &DiagPluginPanel::on_diag_alarms, Qt::QueuedConnection);
}

void DiagPluginPanel::on_diag_alarms(const QString& pid,
                                     const QList<PluginDiagAlarm>& alarms) {
    if (pid != m_info.plugin_id) return;
    m_table->setUpdatesEnabled(false);
    for (const auto& a : alarms) {
        const int row = m_table->rowCount();
        m_table->insertRow(row);
        m_table->setItem(row, 0, new QTableWidgetItem(QString::number(a.frame_no)));
        m_table->setItem(row, 1, new QTableWidgetItem(a.name));
        m_table->setItem(row, 2, new QTableWidgetItem(a.value));
    }
    // 上限 2000 行,超限从顶部丢弃
    while (m_table->rowCount() > 2000)
        m_table->removeRow(0);
    m_table->setUpdatesEnabled(true);
    if (!alarms.isEmpty())
        m_table->scrollToBottom();
}

// =====================================================================
// ReportPluginPanel
// =====================================================================
ReportPluginPanel::ReportPluginPanel(LocalPluginEngine* engine,
                                     const PluginLoadedInfo& info,
                                     QWidget* parent)
    : PluginPanel(engine, info, parent),
      m_func(info.panel_function.isEmpty() ? QStringLiteral("get_report")
                                           : info.panel_function) {
    m_btn = new QPushButton(trl::L("生成报表"), this);
    connect(m_btn, &QPushButton::clicked, this, &ReportPluginPanel::on_generate);
    body_layout()->addWidget(m_btn);
    m_text = new QTextEdit(this);
    m_text->setReadOnly(true);
    m_text->setPlaceholderText(trl::L("等待插件数据..."));
    body_layout()->addWidget(m_text, 1);

    connect(m_engine, &LocalPluginEngine::text_ready,
            this, &ReportPluginPanel::on_text_ready, Qt::QueuedConnection);
}

void ReportPluginPanel::on_generate() {
    m_btn->setEnabled(false);
    m_btn->setText(trl::L("正在生成..."));
    m_engine->request_text(m_info.plugin_id, m_func);
}

void ReportPluginPanel::generate_now() {
    on_generate();
}

void ReportPluginPanel::on_text_ready(const QString& pid, const QString& func,
                                      const QString& text) {
    if (pid != m_info.plugin_id || func != m_func) return;
    m_text->setPlainText(text);
    m_btn->setEnabled(true);
    m_btn->setText(trl::L("生成报表"));
}

// =====================================================================
// StatsPluginPanel
// =====================================================================
StatsPluginPanel::StatsPluginPanel(LocalPluginEngine* engine,
                                   const PluginLoadedInfo& info,
                                   QWidget* parent)
    : PluginPanel(engine, info, parent) {
    auto* lab = new QLabel(this);
    lab->setWordWrap(true);
    lab->setTextInteractionFlags(Qt::TextSelectableByMouse);
    lab->setText(info.description.isEmpty() ? info.plugin_id : info.description);
    body_layout()->addWidget(lab);
    body_layout()->addStretch(1);
}

// =====================================================================
PluginPanel* create_plugin_panel(LocalPluginEngine* engine,
                                 const PluginLoadedInfo& info, QWidget* parent) {
    const QString p = info.panel.toLower();
    if (p == QLatin1String("topo"))   return new TopoPluginPanel(engine, info, parent);
    if (p == QLatin1String("replay")) return new ReplayPluginPanel(engine, info, parent);
    if (p == QLatin1String("diag"))   return new DiagPluginPanel(engine, info, parent);
    if (p == QLatin1String("report")) return new ReportPluginPanel(engine, info, parent);
    return new StatsPluginPanel(engine, info, parent);
}
