/// @file plugin_graphics_view.h
/// @brief PluginGraphicsView:主进程侧图形插件视图
/// @details 显示插件进程渲染的 QImage;鼠标/滚轮/缩放事件经 IPC 转发给插件;
///          插件返回 needs_redraw 或主动 RequestRedraw 时重新请求渲染。
/// @note 线程:主线程。所有插件请求都是异步的(PluginManager 的
///       request_render_async / send_graphics_event_async),GUI 线程从不阻塞:
///       - 新图到达前一直显示上一张成功的图;
///       - 渲染合并:同一时刻最多 1 个渲染请求在途,期间再要求重绘只置 dirty,
///         在途请求返回后再补发 1 次(慢插件不会堆积请求);
///       - 过期响应(代号早于已应用的)丢弃;
///       - 图形事件发后即返回,ack 异步到达,needs_redraw 时请求重绘。
///       回调以本对象为上下文,视图销毁后不会再被回调。
#ifndef BPLC_PLUGIN_GRAPHICS_VIEW_H
#define BPLC_PLUGIN_GRAPHICS_VIEW_H

#include <QImage>
#include <QWidget>

#include "igraphicsplugin.h"

class PluginManager;
class QTimer;

/// @brief 图形插件视图(主进程)
class PluginGraphicsView : public QWidget {
    Q_OBJECT
public:
    explicit PluginGraphicsView(PluginManager* mgr, const QString& plugin_id,
                                QWidget* parent = nullptr);
    ~PluginGraphicsView() override;

    /// @brief 插件 id
    QString plugin_id() const { return m_plugin_id; }
    /// @brief 设置显示的图(渲染回调内部使用,也可外部直接设置)
    void set_image(const QImage& img);
    /// @brief 插件请求重绘(由 PluginManager 在 RequestRedraw 时调用)
    void on_plugin_request_redraw();

    // ---- 诊断/测试 ----
    /// @brief 当前显示的图(上一张成功渲染的结果)
    const QImage& image() const { return m_image; }
    /// @brief 已实际发出的渲染请求数(合并后)
    quint64 renders_sent() const { return m_renders_sent; }
    /// @brief 已应用到界面的渲染结果数
    quint64 renders_applied() const { return m_renders_applied; }
    /// @brief 是否有渲染请求在途
    bool render_in_flight() const { return m_render_inflight; }

protected:
    void paintEvent(QPaintEvent* e) override;
    void resizeEvent(QResizeEvent* e) override;
    void mousePressEvent(QMouseEvent* e) override;
    void mouseReleaseEvent(QMouseEvent* e) override;
    void mouseMoveEvent(QMouseEvent* e) override;
    void wheelEvent(QWheelEvent* e) override;
    void leaveEvent(QEvent* e) override;

private:
    /// @brief 请求重绘(节流:50 ms 内连续触发合并为一次)
    void request_render();
    /// @brief 发出渲染请求;已有在途请求则只置 dirty(合并)
    void start_render();
    /// @brief 渲染结果回调(GUI 线程,经事件循环排队)
    void on_render_done(quint64 gen, bool ok, const QImage& img);
    /// @brief 异步发送图形事件;ack 指示 needs_redraw 时请求重绘
    void send_event(const GraphicsEvent& e);

    PluginManager* m_mgr;  ///< 不拥有(进程级单例)
    QString m_plugin_id;
    QImage m_image;                    ///< 上一张成功渲染的图
    QTimer* m_render_timer = nullptr;  ///< 重绘节流
    bool m_render_inflight = false;    ///< 有渲染请求在途
    bool m_render_dirty = false;       ///< 在途期间又要求了重绘
    quint64 m_render_gen = 0;          ///< 已发出渲染请求的代号(单调递增)
    quint64 m_applied_gen = 0;         ///< 已应用结果的代号(更旧的响应丢弃)
    quint64 m_renders_sent = 0;
    quint64 m_renders_applied = 0;
};

#endif // BPLC_PLUGIN_GRAPHICS_VIEW_H
