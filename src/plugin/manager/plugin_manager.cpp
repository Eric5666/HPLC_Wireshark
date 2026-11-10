/// @file plugin_manager.cpp
/// @brief PluginManager 实现
#include "plugin_manager.h"
#include "plugin_graphics_view.h"

#include <QCoreApplication>
#include <QDataStream>
#include <QDateTime>
#include <QDeadlineTimer>
#include <QDir>
#include <QElapsedTimer>
#include <QImage>
#include <QLocalServer>
#include <QLocalSocket>
#include <QMutexLocker>
#include <QProcess>
#include <QReadLocker>
#include <QThread>
#include <QTimer>
#include <QWriteLocker>

#include <memory>

#include "plugin_ipc.h"
#include "plugin_serialization.h"
#include "plugin_parser_proxy.h"
#include "protocolfactory.h"

namespace {
constexpr int kHandshakeTimeoutMs = 10000;
constexpr int kParseTimeoutMs = 5000;
constexpr int kHeartbeatIntervalMs = 5000;
constexpr int kHeartbeatTimeoutMs = 15000;
constexpr int kGraphicsTimeoutMs = 5000;     ///< 异步图形请求超时
constexpr int kAsyncSweepIntervalMs = 50;    ///< 超时扫描粒度
/// 单调时钟(ms),用于异步请求截止时刻
qint64 steady_ms() {
    static QElapsedTimer t = [] { QElapsedTimer e; e.start(); return e; }();
    return t.elapsed();
}
/// 当前线程是否 GUI(主)线程
bool on_gui_thread() {
    const QCoreApplication* app = QCoreApplication::instance();
    return app && QThread::currentThread() == app->thread();
}
} // namespace

PluginManager& PluginManager::instance() {
    static PluginManager inst;
    return inst;
}

PluginManager::PluginManager(QObject* parent) : QObject(parent) {
    m_hb_timer.setInterval(kHeartbeatIntervalMs);
    connect(&m_hb_timer, &QTimer::timeout, this, &PluginManager::check_heartbeats);
    m_hb_timer.start();
    m_async_timer.setInterval(kAsyncSweepIntervalMs);
    connect(&m_async_timer, &QTimer::timeout, this, &PluginManager::sweep_async_timeouts);
}

PluginManager::~PluginManager() {
    stop_all();
    stop_ipc_thread();
    // 退役运行时本体在此统一释放:管理器是进程级单例,析构时已无
    // 请求线程存活,迟到指针不可能再被解引用
    for (auto* rt : m_retired) delete rt;
    m_retired.clear();
}

void PluginManager::ensure_ipc_thread() {
    if (m_ipc_thread) return;
    m_ipc_thread = new QThread;          // 无父对象:生命周期由 stop_ipc_thread 管理
    m_ipc_thread->setObjectName(QStringLiteral("PluginIpc"));
    m_ipc_ctx = new QObject;             // 无父对象,才能 moveToThread
    m_ipc_ctx->setObjectName(QStringLiteral("PluginIpcContext"));
    m_ipc_ctx->moveToThread(m_ipc_thread);
    m_ipc_thread->start();
    // 应用退出前(QCoreApplication 仍存活)收尾:停插件、关 socket、停线程。
    // 单例析构发生在静态析构期,届时再做同样的事只是兜底。
    QCoreApplication* app = QCoreApplication::instance();
    if (app && !m_quit_hooked) {
        m_quit_hooked = true;
        connect(app, &QCoreApplication::aboutToQuit, this, [this]() {
            stop_all();
            stop_ipc_thread();
        });
    }
}

void PluginManager::stop_ipc_thread() {
    if (!m_ipc_thread) return;
    // 正常路径下 stop_all 已在 IPC 线程上释放了全部 server/socket;
    // 此处 ctx 已无子对象。线程停稳后再从本线程删 ctx(此时它的线程
    // 不再处理事件,删除安全,其残留的排队调用一并丢弃)。
    m_ipc_thread->quit();
    m_ipc_thread->wait();
    delete m_ipc_ctx;
    m_ipc_ctx = nullptr;
    delete m_ipc_thread;
    m_ipc_thread = nullptr;
}

void PluginManager::run_on_ipc_blocking(const std::function<void()>& fn) {
    if (!m_ipc_thread || !m_ipc_thread->isRunning()) return;
    if (QThread::currentThread() == m_ipc_thread) { fn(); return; }
    // BlockingQueued 无死锁风险:IPC 线程上的代码从不阻塞等待其他线程
    QMetaObject::invokeMethod(m_ipc_ctx, fn, Qt::BlockingQueuedConnection);
}

void PluginManager::stop_all() {
    QList<PluginRuntime*> runtimes;
    {
        QWriteLocker wl(&m_plugins_lock);
        if (m_plugins.isEmpty()) return;
        runtimes = m_plugins.values();
        m_plugins.clear();
    }
    // 第一遍:先置禁用+退役并注销协议,断绝新请求进入(parse 入口都先
    // 查 disabled/ready/retired),并唤醒等待响应中的请求线程(它们只碰
    // rt 的 waiting/responses,从不碰 socket),使其立即以失败返回。
    for (auto* rt : runtimes) {
        rt->disabled = true;
        rt->ready = false;
        rt->retired.store(true);
        wake_waiters(rt);
        fail_async(rt);   // 在途异步图形请求以失败结束(排队回调;上下文已销毁则丢弃)
        unregister_parser(rt->manifest.protocol_id);
    }
    // 第二遍(IPC 线程,同步):发 Shutdown、断开并释放 socket/server。
    // 先断开 socket 的信号,免得 disconnected 再排队 disable_plugin。
    // 在途的排队写请求执行前复查 retired/socket,不会写到已释放的 socket。
    run_on_ipc_blocking([this, runtimes]() {
        for (auto* rt : runtimes) {
            if (rt->socket) {
                QObject::disconnect(rt->socket, nullptr, m_ipc_ctx, nullptr);
                QByteArray p;
                send_message(rt, static_cast<quint8>(plugin_ipc::MsgType::Shutdown), p);
                rt->socket->flush();
                rt->socket->disconnectFromServer();
            }
            rt->connected = false;
            delete rt->server;      // socket 是 server 的子对象,一并销毁
            rt->server = nullptr;
            rt->socket = nullptr;
            rt->rx_buf.clear();
        }
    });
    // 第三遍(GUI 线程):关停 host 进程。运行时本体(含 mutex)不在此
    // delete:可能仍有请求线程刚取到 rt 指针,本体转入 m_retired,留待
    // 管理器析构(进程退出、无请求线程存活时)释放(防 UAF)。
    for (auto* rt : runtimes) {
        if (rt->process) {
            rt->process->disconnect(this);   // 主动停机,不再走崩溃回调
            rt->process->terminate();
            if (!rt->process->waitForFinished(2000)) {
                rt->process->kill();
                rt->process->waitForFinished(1000);
            }
            delete rt->process;
            rt->process = nullptr;
        }
        m_retired.append(rt);
    }
}

PluginRuntime* PluginManager::find_runtime(const QString& protocol_id) const {
    QReadLocker rl(&m_plugins_lock);
    return m_plugins.value(protocol_id, nullptr);
}

void PluginManager::wake_waiters(PluginRuntime* rt) {
    QMutexLocker lock(&rt->ipc_mutex);
    rt->resp_cv.wakeAll();
}

void PluginManager::load_all(const QString& plugins_dir) {
    const QDir d(plugins_dir);
    if (!d.exists()) return;
    for (const QString& sub : d.entryList(QDir::Dirs | QDir::NoDotAndDotDot)) {
        const PluginManifest m = read_plugin_manifest(d.filePath(sub));
        if (!m.valid) continue;  // 无效清单跳过(可日志)
        if (m.runtime != QStringLiteral("native")
            && m.runtime != QStringLiteral("js")
            && m.runtime != QStringLiteral("lua")) continue;  // Phase2: native/js/lua
        if (find_runtime(m.protocol_id)) continue;            // 重复协议 id
        start_plugin(m);
    }
}

QStringList PluginManager::plugin_protocol_ids() const {
    QReadLocker rl(&m_plugins_lock);
    return m_plugins.keys();
}

bool PluginManager::is_plugin_protocol(const QString& protocol_id) const {
    const PluginRuntime* rt = find_runtime(protocol_id);
    return rt && rt->ready && !rt->disabled;
}

static QString host_binary_path() {
    // bplc-plugin-host 与主程序同目录
    return QCoreApplication::applicationDirPath()
         + QStringLiteral("/bplc-plugin-host");
}

bool PluginManager::start_plugin(const PluginManifest& m) {
    ensure_ipc_thread();
    auto* rt = new PluginRuntime;
    rt->manifest = m;
    const QString sock_name = plugin_ipc::socket_name(m.name);
    const QString pid = m.protocol_id;

    // server 在 IPC 线程创建(父对象 = 住在 IPC 线程的 ctx)并监听;
    // newConnection 及其后 socket 的全部信号都在 IPC 线程处理
    bool listening = false;
    run_on_ipc_blocking([this, rt, sock_name, &listening]() {
        QLocalServer::removeServer(sock_name);
        rt->server = new QLocalServer(m_ipc_ctx);
        if (!rt->server->listen(sock_name)) {
            delete rt->server;
            rt->server = nullptr;
            return;
        }
        connect(rt->server, &QLocalServer::newConnection,
                m_ipc_ctx, [this, rt]() { on_new_connection(rt); });
        listening = true;
    });
    if (!listening) {
        delete rt;
        return false;
    }
    auto release_server = [this, rt]() {
        run_on_ipc_blocking([rt]() { delete rt->server; rt->server = nullptr; rt->socket = nullptr; });
    };

    // QProcess 留在 GUI 线程(本对象所属线程)
    rt->process = new QProcess(this);
    connect(rt->process,
            QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [this, pid](int code, QProcess::ExitStatus) {
                on_process_finished(pid, code);
            });
    connect(rt->process, &QProcess::errorOccurred,
            this, [this, pid]() { on_process_error(pid); });

    rt->process->start(host_binary_path(),
        {QStringLiteral("--socket"), sock_name,
         QStringLiteral("--plugin"), m.dir_path});
    if (!rt->process->waitForStarted(5000)) {
        release_server();
        delete rt->process;
        delete rt;
        return false;
    }
    {
        QWriteLocker wl(&m_plugins_lock);
        m_plugins.insert(pid, rt);
    }
    return true;
}

// ---- 以下三个在 IPC 线程运行 ----

void PluginManager::on_new_connection(PluginRuntime* rt) {
    if (rt->retired.load() || !rt->server) return;
    QLocalSocket* s = rt->server->nextPendingConnection();
    if (!s) return;
    if (rt->socket) {            // 一个插件只接受一条连接
        s->disconnectFromServer();
        s->deleteLater();
        return;
    }
    rt->socket = s;              // 父对象 = server(同在 IPC 线程)
    connect(s, &QLocalSocket::readyRead,
            m_ipc_ctx, [this, rt]() { on_host_ready_read(rt); });
    connect(s, &QLocalSocket::disconnected,
            m_ipc_ctx, [this, rt]() { on_host_disconnected(rt); });
    rt->connected = true;
    if (s->bytesAvailable() > 0) on_host_ready_read(rt);
}

void PluginManager::on_host_disconnected(PluginRuntime* rt) {
    rt->connected = false;
    wake_waiters(rt);   // 等待中的请求立即失败返回(wait_response 查 connected)
    fail_async(rt);     // 在途异步图形请求排队失败回调
    if (rt->retired.load()) return;
    // 状态/信号/协议注册表归 GUI 线程:排队过去停用
    const QString pid = rt->manifest.protocol_id;
    // 执行时复查 rt 仍是该 id 的当前运行时(stop_all + 重新加载后同 id 是新对象)
    QMetaObject::invokeMethod(this, [this, rt, pid]() {
        if (find_runtime(pid) != rt) return;
        disable_plugin(pid, QStringLiteral("host disconnected"));
    }, Qt::QueuedConnection);
}

void PluginManager::on_host_ready_read(PluginRuntime* rt) {
    if (rt->retired.load() || !rt->socket) return;
    // 唯一收包点(IPC 线程):请求的响应按 seq 投递给等待方;Pong 只更新
    // 原子时间戳;其余消息排队到 GUI 线程的 handle_message。
    rt->rx_buf.append(rt->socket->readAll());
    QList<QByteArray> to_gui;
    bool bad_frame = false;
    for (;;) {
        QByteArray frame;
        const auto took = plugin_ipc::try_take_frame(rt->rx_buf, frame);
        if (took == plugin_ipc::FrameTake::NeedMore) break;
        if (took == plugin_ipc::FrameTake::Bad) { bad_frame = true; break; }
        QDataStream ds(frame);
        ds.setVersion(plugin_ipc::kStreamVersion);
        quint8 t = 0;
        ds >> t;
        const auto mt = static_cast<plugin_ipc::MsgType>(t);
        if (mt == plugin_ipc::MsgType::ParseResponse ||
            mt == plugin_ipc::MsgType::RenderResponse ||
            mt == plugin_ipc::MsgType::EventAck) {
            quint64 rseq = 0;
            ds >> rseq;
            QMutexLocker lock(&rt->ipc_mutex);
            if (rt->waiting.contains(rseq)) {   // 同步等待方(worker 解析)
                rt->responses.insert(rseq, frame);
                rt->resp_cv.wakeAll();
                continue;
            }
            // 异步图形请求:取出登记项(之后超时扫描不会再看到它,回调恰好一次),
            // 在 IPC 线程解码后排队交给 GUI 线程。未登记(已超时丢弃/发后不管)
            // 的迟到响应直接丢弃。
            auto it = rt->async_reqs.find(rseq);
            if (it == rt->async_reqs.end()) continue;
            PluginAsyncRequest req = std::move(it.value());
            rt->async_reqs.erase(it);
            lock.unlock();
            PluginAsyncResult res;
            if (mt == plugin_ipc::MsgType::RenderResponse &&
                req.kind == PluginAsyncRequest::Render) {
                bool rok = false;
                QImage img;
                ds >> rok >> img;
                res.ok = rok && ds.status() == QDataStream::Ok;
                if (res.ok) res.image = img;
            } else if (mt == plugin_ipc::MsgType::EventAck &&
                       req.kind == PluginAsyncRequest::Event) {
                bool redraw = false;
                ds >> redraw;
                res.ok = ds.status() == QDataStream::Ok;
                res.needs_redraw = res.ok && redraw;
            }   // 类型与登记不符:按失败回调
            deliver_async(std::move(req), res);
            continue;
        }
        if (mt == plugin_ipc::MsgType::Pong) {
            rt->last_pong_ms = QDateTime::currentMSecsSinceEpoch();
            continue;
        }
        to_gui.append(frame);
    }
    if (!to_gui.isEmpty()) {
        const QString pid = rt->manifest.protocol_id;
        QMetaObject::invokeMethod(this, [this, rt, pid, to_gui]() {
            if (find_runtime(pid) != rt) return;   // 已退役/被同 id 新运行时替换
            for (const QByteArray& fr : to_gui) handle_message(pid, fr);
        }, Qt::QueuedConnection);
    }
    if (bad_frame) {
        // 帧长非法(0 或超过 kMaxIpcFrame):流已失步,无法恢复。先排队停用
        // (原因优先于随后的 "host disconnected"),再断开连接。
        rt->rx_buf.clear();
        const QString pid = rt->manifest.protocol_id;
        QMetaObject::invokeMethod(this, [this, rt, pid]() {
            if (find_runtime(pid) != rt) return;
            disable_plugin(pid, QStringLiteral("ipc frame length invalid"));
        }, Qt::QueuedConnection);
        rt->socket->abort();
    }
}

void PluginManager::handle_message(const QString& plugin_id,
                                  const QByteArray& frame) {
    // GUI 线程:可安全注册协议、发信号、触碰视图
    PluginRuntime* rt = find_runtime(plugin_id);
    if (!rt || rt->retired.load()) return;
    QDataStream ds(frame);
    ds.setVersion(plugin_ipc::kStreamVersion);
    quint8 type = 0;
    ds >> type;
    const auto t = static_cast<plugin_ipc::MsgType>(type);
    switch (t) {
    case plugin_ipc::MsgType::Hello: {
        int api_ver = 0; QString name, proto;
        ds >> api_ver >> name >> proto;
        int wire_ver = 1;   // 旧版 host 的 Hello 无格式版本字段,按 v1 布局对待(下方校验会拒绝)
        if (!ds.atEnd()) ds >> wire_ver;
        QByteArray p;
        QDataStream o(&p, QIODevice::WriteOnly);
        o.setVersion(plugin_ipc::kStreamVersion);
        QString reason;
        if (api_ver != plugin_ipc::kApiVersion || proto != rt->manifest.protocol_id)
            reason = QStringLiteral("api_version/protocol mismatch");
        else if (wire_ver != plugin_ipc::kWireFormatVersion)
            reason = QStringLiteral("wire_format_version mismatch");
        const bool ok = reason.isEmpty();
        o << ok;
        o << reason;
        // 排队到 IPC 线程写出;之后的请求同样排队,FIFO 保证 HelloAck 先发
        post_message(rt, static_cast<quint8>(plugin_ipc::MsgType::HelloAck), p);
        if (ok && !rt->disabled.load()) {
            rt->last_pong_ms = QDateTime::currentMSecsSinceEpoch();
            rt->ready = true;
            // 注册到协议注册表(协议 id → 代理;显示名取自 plugin.json,供界面协议列表)
            const QString pid = rt->manifest.protocol_id;
            register_parser_provider(pid, rt->manifest.display_name,
                                     rt->manifest.display_name_en,
                                     [pid]() { return make_plugin_parser(pid); });
            emit plugin_status_changed(plugin_id, QStringLiteral("ready"));
        } else if (!ok) {
            disable_plugin(plugin_id, QStringLiteral("handshake failed"));
        }
        break;
    }
    case plugin_ipc::MsgType::Error: {
        quint64 seq = 0; QString msg;
        ds >> seq >> msg; Q_UNUSED(seq);
        // 解析错误不禁用插件,仅记录(可日志)
        break;
    }
    case plugin_ipc::MsgType::RequestRedraw: {
        // 插件主动请求重绘:通知所有注册的视图(GUI 对象,只能在 GUI 线程)
        for (PluginGraphicsView* v : m_graphics_views.value(plugin_id))
            v->on_plugin_request_redraw();
        break;
    }
    default:
        break;
    }
}

void PluginManager::send_message(PluginRuntime* rt, quint8 type,
                                const QByteArray& payload) {
    Q_ASSERT(!m_ipc_thread || QThread::currentThread() == m_ipc_thread);
    if (!rt->socket) return;
    QByteArray frame;
    QDataStream ds(&frame, QIODevice::WriteOnly);
    ds.setVersion(plugin_ipc::kStreamVersion);
    ds << quint32(1 + payload.size()) << type;
    frame.append(payload);
    rt->socket->write(frame);
    rt->socket->flush();
}

void PluginManager::post_message(PluginRuntime* rt, quint8 type,
                                 const QByteArray& payload) {
    if (!m_ipc_ctx) return;
    if (QThread::currentThread() == m_ipc_thread) {
        if (!rt->retired.load()) send_message(rt, type, payload);
        return;
    }
    // socket 属 IPC 线程:排队过去写出;执行时 rt 可能已退役
    // (socket 已释放),复查后再写。rt 本体在管理器析构前不会释放。
    QMetaObject::invokeMethod(m_ipc_ctx, [this, rt, type, payload]() {
        if (!rt->retired.load()) send_message(rt, type, payload);
    }, Qt::QueuedConnection);
}

quint64 PluginManager::begin_request(PluginRuntime* rt) {
    const quint64 seq = ++rt->seq;
    QMutexLocker lock(&rt->ipc_mutex);
    rt->waiting.insert(seq);
    return seq;
}

bool PluginManager::wait_response(PluginRuntime* rt, quint64 seq,
                                  int timeout_ms, QByteArray* frame) {
    // 任何请求线程(worker / GUI)统一用条件变量等 IPC 线程投递响应;
    // 停用、退役或断线时被 wake_waiters 立即唤醒。GUI 不再跑嵌套事件循环。
    Q_ASSERT(QThread::currentThread() != m_ipc_thread);
    // GUI 线程绝不应阻塞等插件 IPC(图形请求已全部异步化)。仍被调用说明
    // 有新的 GUI 调用方误用了同步路径:告警(debug 下断言)以便尽早发现。
    if (on_gui_thread()) {
        qWarning("PluginManager: wait_response called on the GUI thread "
                 "(blocking plugin IPC on GUI is not allowed; use the async API)");
        Q_ASSERT_X(false, "PluginManager::wait_response",
                   "blocking plugin IPC on the GUI thread");
    }
    QDeadlineTimer deadline(timeout_ms);
    QMutexLocker lock(&rt->ipc_mutex);
    while (!rt->responses.contains(seq) && !rt->retired.load() &&
           !rt->disabled.load() && rt->connected.load()) {
        if (deadline.hasExpired()) break;
        rt->resp_cv.wait(&rt->ipc_mutex, deadline);
    }
    const bool got = rt->responses.contains(seq);
    if (got) *frame = rt->responses.take(seq);
    rt->waiting.remove(seq);
    return got;
}

bool PluginManager::parse_via_plugin(const QString& protocol_id,
                                   const BplcFrame& frame, MsduState& msdu,
                                   const ParseFilter& filter,
                                   ParseResult* result) {
    PluginRuntime* rt = find_runtime(protocol_id);
    if (!rt) return false;
    // 退役/禁用/未就绪:不再发请求(socket 只由 IPC 线程触碰,这里不读 rt->socket)
    if (!rt->ready || rt->disabled || rt->retired.load()) return false;
    const quint64 seq = begin_request(rt);

    QByteArray payload;
    QDataStream o(&payload, QIODevice::WriteOnly);
    o.setVersion(plugin_ipc::kStreamVersion);
    o << seq << frame << msdu << filter;
    post_message(rt, static_cast<quint8>(plugin_ipc::MsgType::ParseRequest), payload);

    // 阻塞等待响应(worker 线程调用,不阻塞 UI);响应由 IPC 线程收包后按 seq 投递
    QByteArray fr;
    const bool got = wait_response(rt, seq, kParseTimeoutMs, &fr);
    ParseResult r;
    MsduState new_msdu;
    if (got) {
        QDataStream ds(fr);
        ds.setVersion(plugin_ipc::kStreamVersion);
        quint8 t = 0; quint64 rseq = 0; bool ok = false;
        ds >> t >> rseq >> ok;
        if (ok) { ds >> r >> new_msdu; }
        else { QString e; ds >> e; r.reject_reason = e; }
        r.accept = ok;
    }
    if (!got) {
        r.accept = false;
        r.reject_reason = QStringLiteral("plugin parse timeout/crash");
        if (rt->retired.load()) return false;   // stop_all 主动停机,不算超时
        if (rt->disabled.load() || !rt->connected.load()) return false;  // 已停用/断线:状态已另行上报
        // 超时很可能意味着 host 挂了,禁用插件
        // 注意:不能在 worker 线程直接调 disable_plugin(涉及信号),标记即可
        if (rt->disabled.exchange(true)) return false;
        rt->ready = false;
        wake_waiters(rt);   // 同插件其他等待者立即返回
        fail_async(rt);     // 同插件在途异步图形请求排队失败回调
        const QString reason = r.reject_reason;
        QMetaObject::invokeMethod(this, [this, rt, protocol_id, reason]() {
            if (rt->retired.load()) return;
            rt->disable_reason = reason;
            unregister_parser(rt->manifest.protocol_id);
            emit plugin_status_changed(protocol_id, QStringLiteral("timeout-disabled"));
        }, Qt::QueuedConnection);
        return false;
    }
    *result = r;
    msdu = new_msdu;
    return true;
}

void PluginManager::on_process_finished(const QString& plugin_id, int code) {
    Q_UNUSED(code);
    PluginRuntime* rt = find_runtime(plugin_id);
    if (!rt) return;
    if (!rt->disabled) {
        // 非预期退出(未主动禁用):视为崩溃
        disable_plugin(plugin_id, QStringLiteral("host process exited unexpectedly"));
    }
}

void PluginManager::on_process_error(const QString& plugin_id) {
    disable_plugin(plugin_id, QStringLiteral("host process error"));
}

void PluginManager::disable_plugin(const QString& plugin_id,
                                  const QString& reason) {
    PluginRuntime* rt = find_runtime(plugin_id);
    if (!rt || rt->disabled) return;
    rt->disabled = true;
    rt->disable_reason = reason;
    rt->ready = false;
    wake_waiters(rt);   // 等待中的请求立即失败返回,不必等满超时
    fail_async(rt);     // 在途异步图形请求排队失败回调(不在本调用内重入回调)
    unregister_parser(rt->manifest.protocol_id);
    emit plugin_status_changed(plugin_id, QStringLiteral("disabled: ") + reason);
}

void PluginManager::check_heartbeats() {
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    QMap<QString, PluginRuntime*> snapshot;
    {
        QReadLocker rl(&m_plugins_lock);
        snapshot = m_plugins;
    }
    for (auto it = snapshot.cbegin(); it != snapshot.cend(); ++it) {
        PluginRuntime* rt = it.value();
        if (!rt->ready || rt->disabled || !rt->connected.load()) continue;
        // 发 Ping:排队到 IPC 线程写 socket(GUI 线程不碰 socket)
        {
            QByteArray p;
            QDataStream o(&p, QIODevice::WriteOnly);
            o.setVersion(plugin_ipc::kStreamVersion);
            o << quint64(++rt->seq);
            post_message(rt, static_cast<quint8>(plugin_ipc::MsgType::Ping), p);
        }
        if (now - rt->last_pong_ms > kHeartbeatTimeoutMs) {
            disable_plugin(it.key(), QStringLiteral("heartbeat timeout"));
        }
    }
}

// ---- 图形(Phase3):GUI 线程异步请求 ----

bool PluginManager::has_graphics(const QString& protocol_id) const {
    const PluginRuntime* rt = find_runtime(protocol_id);
    return rt && rt->manifest.graphics;
}

quint64 PluginManager::start_async(PluginRuntime* rt, PluginAsyncRequest::Kind kind,
                                   QObject* context,
                                   std::function<void(const PluginAsyncResult&)> cb,
                                   const std::function<QByteArray(quint64)>& make_payload,
                                   quint8 msg_type) {
    if (!rt->ready || rt->disabled || rt->retired.load() || !rt->connected.load())
        return 0;
    if (!rt->manifest.graphics) return 0;
    const quint64 seq = ++rt->seq;
    const bool cb_registered = bool(cb);
    if (cb) {
        PluginAsyncRequest req;
        req.kind = kind;
        req.ctx = context;
        req.cb = std::move(cb);
        req.deadline_ms = steady_ms() + kGraphicsTimeoutMs;
        QMutexLocker lock(&rt->ipc_mutex);
        // 在锁内复查:断线/停用方先置标志再取锁 fail_async,二者必有其一看到对方,
        // 登记项不会成为孤儿(兜底还有超时扫描)
        if (!rt->connected.load() || rt->disabled.load() || rt->retired.load())
            return 0;
        rt->async_reqs.insert(seq, std::move(req));
    }
    post_message(rt, msg_type, make_payload(seq));
    if (cb_registered && !m_async_timer.isActive()) m_async_timer.start();   // 超时扫描
    return seq;
}

quint64 PluginManager::request_render_async(const QString& protocol_id, int w, int h,
                                            QObject* context, RenderCallback cb) {
    Q_ASSERT_X(!QCoreApplication::instance() || QThread::currentThread() == thread(),
               "PluginManager::request_render_async", "must be called on the GUI thread");
    if (!context || !cb) return 0;
    PluginRuntime* rt = find_runtime(protocol_id);
    if (!rt) return 0;
    auto seq_holder = std::make_shared<quint64>(0);
    const quint64 seq = start_async(
        rt, PluginAsyncRequest::Render, context,
        [cb = std::move(cb), seq_holder](const PluginAsyncResult& r) {
            cb(*seq_holder, r.ok, r.image);
        },
        [w, h](quint64 s) {
            QByteArray payload;
            QDataStream o(&payload, QIODevice::WriteOnly);
            o.setVersion(plugin_ipc::kStreamVersion);
            o << s << w << h;
            return payload;
        },
        static_cast<quint8>(plugin_ipc::MsgType::RenderRequest));
    *seq_holder = seq;   // 回调总是排队执行,此时 seq 已写入
    return seq;
}

quint64 PluginManager::send_graphics_event_async(const QString& protocol_id,
                                                 const GraphicsEvent& e,
                                                 QObject* context, EventCallback cb) {
    Q_ASSERT_X(!QCoreApplication::instance() || QThread::currentThread() == thread(),
               "PluginManager::send_graphics_event_async", "must be called on the GUI thread");
    if (cb && !context) return 0;
    PluginRuntime* rt = find_runtime(protocol_id);
    if (!rt) return 0;
    auto seq_holder = std::make_shared<quint64>(0);
    std::function<void(const PluginAsyncResult&)> inner;
    if (cb) {
        inner = [cb = std::move(cb), seq_holder](const PluginAsyncResult& r) {
            cb(*seq_holder, r.ok, r.needs_redraw);
        };
    }
    const quint64 seq = start_async(
        rt, PluginAsyncRequest::Event, context, std::move(inner),
        [e](quint64 s) {
            QByteArray payload;
            QDataStream o(&payload, QIODevice::WriteOnly);
            o.setVersion(plugin_ipc::kStreamVersion);
            o << s << e;
            return payload;
        },
        static_cast<quint8>(plugin_ipc::MsgType::GraphicsEventMsg));
    *seq_holder = seq;
    return seq;
}

void PluginManager::deliver_async(PluginAsyncRequest req, const PluginAsyncResult& res) {
    // 任意线程 → 排队到本对象(GUI 线程)。上下文只在 GUI 线程解引用:
    // 已销毁则不回调。管理器析构时未执行的排队调用随之丢弃。
    QMetaObject::invokeMethod(this, [req = std::move(req), res]() {
        if (req.ctx.isNull() || !req.cb) return;
        req.cb(res);
    }, Qt::QueuedConnection);
}

void PluginManager::fail_async(PluginRuntime* rt) {
    QHash<quint64, PluginAsyncRequest> taken;
    {
        QMutexLocker lock(&rt->ipc_mutex);
        taken.swap(rt->async_reqs);
    }
    for (auto it = taken.begin(); it != taken.end(); ++it)
        deliver_async(std::move(it.value()), PluginAsyncResult{});
}

int PluginManager::pending_async_requests() const {
    QList<PluginRuntime*> rts;
    {
        QReadLocker rl(&m_plugins_lock);
        rts = m_plugins.values();
    }
    int n = 0;
    for (PluginRuntime* rt : rts) {
        QMutexLocker lock(&rt->ipc_mutex);
        n += rt->async_reqs.size();
    }
    return n;
}

void PluginManager::sweep_async_timeouts() {
    // GUI 线程:过期登记项从表中摘除(迟到响应随后在 IPC 线程被丢弃),
    // 以失败排队回调。只持锁做摘除,不在锁内回调。
    const qint64 now = steady_ms();
    QList<PluginRuntime*> rts;
    {
        QReadLocker rl(&m_plugins_lock);
        rts = m_plugins.values();
    }
    int remaining = 0;
    for (PluginRuntime* rt : rts) {
        QList<PluginAsyncRequest> expired;
        {
            QMutexLocker lock(&rt->ipc_mutex);
            for (auto it = rt->async_reqs.begin(); it != rt->async_reqs.end();) {
                if (it.value().deadline_ms <= now) {
                    expired.append(std::move(it.value()));
                    it = rt->async_reqs.erase(it);
                } else {
                    ++it;
                }
            }
            remaining += rt->async_reqs.size();
        }
        for (PluginAsyncRequest& r : expired) deliver_async(std::move(r), PluginAsyncResult{});
    }
    if (remaining == 0) m_async_timer.stop();
}

void PluginManager::register_graphics_view(const QString& protocol_id,
                                           PluginGraphicsView* view) {
    m_graphics_views[protocol_id].append(view);
    connect(view, &QObject::destroyed, this,
            [this, protocol_id, view]() { unregister_graphics_view(protocol_id, view); });
}

void PluginManager::unregister_graphics_view(const QString& protocol_id,
                                             PluginGraphicsView* view) {
    m_graphics_views[protocol_id].removeAll(view);
}
