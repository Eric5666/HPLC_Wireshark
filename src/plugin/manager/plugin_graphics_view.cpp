/// @file plugin_graphics_view.cpp
#include "plugin_graphics_view.h"

#include <QMouseEvent>
#include <QPainter>
#include <QTimer>
#include <QWheelEvent>

#include "plugin_manager.h"

PluginGraphicsView::PluginGraphicsView(PluginManager* mgr,
                                       const QString& plugin_id,
                                       QWidget* parent)
    : QWidget(parent), m_mgr(mgr), m_plugin_id(plugin_id) {
    setMouseTracking(true);
    setMinimumSize(200, 150);
    m_render_timer = new QTimer(this);
    m_render_timer->setSingleShot(true);
    m_render_timer->setInterval(50);
    connect(m_render_timer, &QTimer::timeout, this, &PluginGraphicsView::start_render);
    // 接收插件主动 RequestRedraw(视图销毁时管理器经 destroyed 自动注销)
    if (m_mgr) m_mgr->register_graphics_view(m_plugin_id, this);
    // 初始渲染
    request_render();
}

PluginGraphicsView::~PluginGraphicsView() = default;

void PluginGraphicsView::set_image(const QImage& img) {
    m_image = img;
    update();
}

void PluginGraphicsView::on_plugin_request_redraw() {
    request_render();
}

void PluginGraphicsView::request_render() {
    if (!m_mgr) return;
    if (!m_render_timer->isActive()) m_render_timer->start();
}

void PluginGraphicsView::start_render() {
    if (!m_mgr) return;
    if (m_render_inflight) {     // 慢插件:不排队,返回后再补发一次
        m_render_dirty = true;
        return;
    }
    m_render_dirty = false;
    const quint64 gen = ++m_render_gen;
    const quint64 seq = m_mgr->request_render_async(
        m_plugin_id, width(), height(), this,
        [this, gen](quint64, bool ok, const QImage& img) { on_render_done(gen, ok, img); });
    if (seq == 0) return;        // 插件未就绪/已停用:保留旧图,不在途
    m_render_inflight = true;
    ++m_renders_sent;
}

void PluginGraphicsView::on_render_done(quint64 gen, bool ok, const QImage& img) {
    m_render_inflight = false;
    // 失败(超时/断线)保留上一张图;只应用比已应用更新的结果
    if (ok && !img.isNull() && gen > m_applied_gen) {
        m_applied_gen = gen;
        ++m_renders_applied;
        set_image(img);
    }
    if (m_render_dirty) start_render();
}

void PluginGraphicsView::send_event(const GraphicsEvent& e) {
    if (!m_mgr) return;
    m_mgr->send_graphics_event_async(m_plugin_id, e, this,
        [this](quint64, bool ok, bool redraw) {
            if (ok && redraw) request_render();
        });
}

void PluginGraphicsView::paintEvent(QPaintEvent* e) {
    Q_UNUSED(e);
    QPainter p(this);
    p.fillRect(rect(), Qt::white);
    if (!m_image.isNull()) {
        // 按控件尺寸拉伸(插件按请求尺寸绘制,通常一致)
        p.drawImage(rect(), m_image);
    } else {
        p.drawText(rect(), Qt::AlignCenter, QStringLiteral("rendering..."));
    }
}

void PluginGraphicsView::resizeEvent(QResizeEvent* e) {
    QWidget::resizeEvent(e);
    GraphicsEvent ge;
    ge.type = GraphicsEventType::Resize;
    ge.width = width();
    ge.height = height();
    send_event(ge);  // 插件可忽略;render 会带新尺寸
    request_render();
}

void PluginGraphicsView::mousePressEvent(QMouseEvent* e) {
    GraphicsEvent ge;
    ge.type = GraphicsEventType::MousePress;
    ge.x = e->pos().x(); ge.y = e->pos().y();
    ge.button = e->button(); ge.modifiers = e->modifiers();
    send_event(ge);
}

void PluginGraphicsView::mouseReleaseEvent(QMouseEvent* e) {
    GraphicsEvent ge;
    ge.type = GraphicsEventType::MouseRelease;
    ge.x = e->pos().x(); ge.y = e->pos().y();
    ge.button = e->button(); ge.modifiers = e->modifiers();
    send_event(ge);
}

void PluginGraphicsView::mouseMoveEvent(QMouseEvent* e) {
    GraphicsEvent ge;
    ge.type = GraphicsEventType::MouseMove;
    ge.x = e->pos().x(); ge.y = e->pos().y();
    ge.button = e->buttons();
    ge.modifiers = e->modifiers();
    send_event(ge);
}

void PluginGraphicsView::wheelEvent(QWheelEvent* e) {
    GraphicsEvent ge;
    ge.type = GraphicsEventType::Wheel;
    ge.x = e->position().x(); ge.y = e->position().y();
    ge.delta_y = e->angleDelta().y();
    ge.modifiers = e->modifiers();
    send_event(ge);
    e->accept();
}

void PluginGraphicsView::leaveEvent(QEvent* e) {
    Q_UNUSED(e);
    GraphicsEvent ge;
    ge.type = GraphicsEventType::Leave;
    send_event(ge);
}
