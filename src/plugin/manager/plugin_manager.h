/// @file plugin_manager.h
/// @brief PluginManager:主程序侧插件管理(扫描/启动/监控/IPC)
/// @details 职责:
///   - 扫描 plugins/ 目录,读取 plugin.json
///   - 为每个插件创建 QLocalServer,启动 bplc-plugin-host 子进程
///   - 握手校验(api_version),注册协议到工厂
///   - 同步 IPC 解析(worker 线程调用,阻塞等待)
///   - 线程模型:管理器自有一条 IPC 线程("PluginIpc")。每个插件的
///     QLocalServer/QLocalSocket 都在该线程创建、连接、读写;
///     on_host_ready_read(IPC 线程)是唯一收包点,ParseResponse/
///     RenderResponse/EventAck 按 seq 投递:同步请求(仅 worker 线程的
///     解析)用 QWaitCondition 等待;GUI 线程的图形请求(渲染/图形事件)
///     一律异步——登记 seq + 回调后立即返回,IPC 线程收到响应后排队投递
///     到 GUI 线程执行回调,超时由 GUI 线程的扫描定时器判定。GUI 线程
///     从不阻塞等待插件 IPC。任何线程的
///     写请求都经排队调用交给 IPC 线程写出(QLocalSocket 非线程安全)。
///     Pong 在 IPC 线程只更新原子时间戳;其余非响应消息(Hello/Error/
///     RequestRedraw)与断线通知排队到 GUI 线程处理(注册协议、发信号、
///     触碰视图)。QProcess、心跳定时器留在 GUI 线程。m_plugins 由读写锁保护。
///   - 心跳 + 崩溃检测(进程退出/心跳超时 → 禁用插件并通知)
#ifndef BPLC_PLUGIN_MANAGER_H
#define BPLC_PLUGIN_MANAGER_H

#include <QObject>
#include <QHash>
#include <QImage>
#include <QPointer>
#include <QMap>
#include <QMutex>
#include <QReadWriteLock>
#include <QSet>
#include <QTimer>
#include <QWaitCondition>

#include <atomic>
#include <functional>

#include "bplcframe.h"
#include "igraphicsplugin.h"
#include "iprotocolparser.h"
#include "plugin_manifest.h"

class QLocalServer;
class QLocalSocket;
class QProcess;
class QThread;
class PluginGraphicsView;

/// 本头文件提供异步图形 API(request_render_async / send_graphics_event_async)
#define BPLC_PLUGIN_ASYNC_GRAPHICS 1

/// @brief 异步图形请求的结果(IPC 线程解码,GUI 线程交给回调)
struct PluginAsyncResult {
    bool ok = false;          ///< false = 超时/断线/停用/停机
    QImage image;             ///< 渲染结果(仅渲染请求)
    bool needs_redraw = false;  ///< 图形事件 ack(仅事件请求)
};

/// @brief 登记中的异步请求(受 PluginRuntime::ipc_mutex 保护)
struct PluginAsyncRequest {
    enum Kind : quint8 { Render, Event };
    Kind kind = Render;
    QPointer<QObject> ctx;    ///< 回调上下文:已销毁则不回调(只在 GUI 线程解引用)
    std::function<void(const PluginAsyncResult&)> cb;  ///< 只在 GUI 线程调用
    qint64 deadline_ms = 0;   ///< 超时时刻(steady 时钟,ms)
};

/// @brief 单个插件的运行时状态
struct PluginRuntime {
    PluginManifest manifest;
    QProcess*     process = nullptr;
    QLocalServer* server = nullptr;   ///< 仅 IPC 线程创建/访问/释放
    QLocalSocket* socket = nullptr;   ///< host 连接(仅 IPC 线程读写,其他线程勿碰)
    QByteArray    rx_buf;             ///< 收包缓冲(仅 IPC 线程)
    QMutex        ipc_mutex;          ///< 保护 waiting/responses(请求线程 ↔ IPC 收包)
    QWaitCondition resp_cv;           ///< 响应到达/插件停用时唤醒等待中的请求
    QSet<quint64> waiting;            ///< 等待响应中的请求 seq
    QHash<quint64, QByteArray> responses;  ///< seq → 响应帧(含类型字节)
    QHash<quint64, PluginAsyncRequest> async_reqs;  ///< 异步图形请求 seq → 回调
    std::atomic<quint64> seq{0};
    std::atomic<bool> ready{false};     ///< 握手完成
    std::atomic<bool> disabled{false};  ///< 崩溃/错误后禁用
    std::atomic<bool> connected{false}; ///< host 已连上且未断开(IPC 线程写,任意线程读)
    std::atomic<bool> retired{false}; ///< stop_all 已退役:对象本体延迟到
                                      ///< 管理器析构才释放(见 stop_all)
    QString       disable_reason;     ///< 仅 GUI 线程读写
    std::atomic<qint64> last_pong_ms{0};
};

/// @brief 插件管理器(单例,主线程)
class PluginManager : public QObject {
    Q_OBJECT
public:
    static PluginManager& instance();

    /// @brief 扫描并启动 plugins_dir 下所有插件
    void load_all(const QString& plugins_dir);
    /// @brief 停掉全部插件 host 子进程并注销其解析器(退役式两遍处理,
    ///        见实现注释)。供应用退出与插件市场删除/更新旧版前调用——
    ///        host 进程映射着插件 DLL,不停机则 Windows 下删不掉旧目录。
    void stop_all();
    /// @brief 已注册的插件协议 id 列表(供 UI/配置)
    QStringList plugin_protocol_ids() const;
    /// @brief 协议 id 是否来自插件
    bool is_plugin_protocol(const QString& protocol_id) const;

    /// @brief 经插件解析一帧(阻塞,worker 线程调用)
    /// @return ok=false 时 result.accept=false 且 reject_reason 置错误信息
    bool parse_via_plugin(const QString& protocol_id,
                        const BplcFrame& frame, MsduState& msdu,
                        const ParseFilter& filter, ParseResult* result);

    // ---- 图形(Phase3) ----
    /// @brief 插件是否有图形能力
    bool has_graphics(const QString& protocol_id) const;
    /// @brief 渲染回调:seq 为该请求的序号,ok=false 时 img 为空
    using RenderCallback = std::function<void(quint64 seq, bool ok, const QImage& img)>;
    /// @brief 图形事件 ack 回调:ok=false 表示未得到 ack(超时/断线等)
    using EventCallback = std::function<void(quint64 seq, bool ok, bool needs_redraw)>;
    /// @brief 异步请求渲染(GUI 线程调用,立即返回)。
    /// @param context 回调的上下文对象(GUI 线程对象,必填);它销毁后回调不再执行
    /// @return 请求 seq;0 = 未发出(插件不存在/未就绪/无图形能力),此时回调不会被调用。
    /// @details 回调总是经事件循环排队在 GUI 线程执行(从不在本调用内同步执行),
    ///          恰好一次:响应到达、超时(5 s)、插件停用/断线/停机任一先到。
    quint64 request_render_async(const QString& protocol_id, int w, int h,
                                 QObject* context, RenderCallback cb);
    /// @brief 异步发送图形事件(GUI 线程调用,立即返回)。cb 为空 = 发后不管
    ///        (ack 到达时直接丢弃)。返回值/回调语义同 request_render_async。
    quint64 send_graphics_event_async(const QString& protocol_id,
                                      const GraphicsEvent& e,
                                      QObject* context = nullptr,
                                      EventCallback cb = {});
    /// @brief 当前登记中的异步请求数(全部插件;测试/诊断用)
    int pending_async_requests() const;
    /// @brief 注册图形视图(收 RequestRedraw 时通知重绘)
    void register_graphics_view(const QString& protocol_id,
                                PluginGraphicsView* view);
    void unregister_graphics_view(const QString& protocol_id,
                                  PluginGraphicsView* view);

signals:
    /// @brief 插件状态变化(崩溃/禁用/就绪),UI 可据此提示
    void plugin_status_changed(const QString& plugin_id, const QString& status);

private:
    explicit PluginManager(QObject* parent = nullptr);
    ~PluginManager() override;

    bool start_plugin(const PluginManifest& m);
    /// @brief 按需启动 IPC 线程(GUI 线程调用)
    void ensure_ipc_thread();
    /// @brief 停止 IPC 线程(GUI 线程调用;须先 stop_all 释放 socket)
    void stop_ipc_thread();
    /// @brief 在 IPC 线程上同步执行 fn(调用方阻塞;IPC 线程从不反向阻塞等 GUI)
    void run_on_ipc_blocking(const std::function<void()>& fn);
    // 以下三个只在 IPC 线程运行
    void on_new_connection(PluginRuntime* rt);
    void on_host_ready_read(PluginRuntime* rt);
    void on_host_disconnected(PluginRuntime* rt);
    void on_process_finished(const QString& plugin_id, int code);
    void on_process_error(const QString& plugin_id);
    void disable_plugin(const QString& plugin_id, const QString& reason);
    /// @brief 非响应消息处理(GUI 线程;frame 含类型字节)
    void handle_message(const QString& plugin_id, const QByteArray& frame);
    /// @brief 直接写 socket(仅 IPC 线程)
    void send_message(PluginRuntime* rt, quint8 type, const QByteArray& payload);
    /// @brief 任意线程发消息:排队到 IPC 线程写 socket(已在 IPC 线程则直接写)
    void post_message(PluginRuntime* rt, quint8 type, const QByteArray& payload);
    /// @brief 分配 seq 并登记为等待响应(须在发请求前调用,防响应先到被丢)
    quint64 begin_request(PluginRuntime* rt);
    /// @brief 等 seq 的响应帧(任意非 IPC 线程:条件变量;停用/退役/断线即返回)
    bool wait_response(PluginRuntime* rt, quint64 seq, int timeout_ms,
                       QByteArray* frame);
    /// @brief 唤醒该插件全部等待中的请求(停用/退役时)
    static void wake_waiters(PluginRuntime* rt);
    /// @brief 登记异步请求并发出(GUI 线程);返回 seq,0 = 未发出
    quint64 start_async(PluginRuntime* rt, PluginAsyncRequest::Kind kind,
                        QObject* context,
                        std::function<void(const PluginAsyncResult&)> cb,
                        const std::function<QByteArray(quint64 seq)>& make_payload,
                        quint8 msg_type);
    /// @brief 把结果排队投递到 GUI 线程执行回调(任意线程;上下文已销毁则跳过)
    void deliver_async(PluginAsyncRequest req, const PluginAsyncResult& res);
    /// @brief 该插件全部登记中的异步请求以失败结束(任意线程,排队回调)
    void fail_async(PluginRuntime* rt);
    /// @brief 超时扫描(GUI 线程定时器):过期的异步请求丢弃 seq 并以失败回调
    void sweep_async_timeouts();
    PluginRuntime* find_runtime(const QString& protocol_id) const;
    void check_heartbeats();

    mutable QReadWriteLock m_plugins_lock;    ///< 保护 m_plugins(GUI 增删,worker 查找)
    QMap<QString, PluginRuntime*> m_plugins;  ///< key: protocol_id
    QList<PluginRuntime*> m_retired;  ///< stop_all 退役的运行时本体:重对象
                                      ///< (进程/socket)已在 stop_all 内释放,
                                      ///< 本体留置此处待管理器析构统一 delete,
                                      ///< 保证迟到的请求线程手中的指针永不悬空
    QMap<QString, QList<PluginGraphicsView*>> m_graphics_views;  ///< key: protocol_id
    QTimer m_async_timer;            ///< 异步请求超时扫描(GUI 线程;有登记时才运行)
    QTimer m_hb_timer;               ///< 心跳定时器(GUI 线程;Ping 经 post_message 排队)
    QThread* m_ipc_thread = nullptr;  ///< "PluginIpc" 线程
    QObject* m_ipc_ctx = nullptr;     ///< 住在 IPC 线程的上下文对象:server 的父对象、
                                      ///< 排队调用/信号连接的接收方
    bool m_quit_hooked = false;       ///< 已挂接 aboutToQuit 收尾
};

#endif // BPLC_PLUGIN_MANAGER_H
