/// @file plugin_manager.cpp
/// @brief PluginManager 实现
#include "plugin_manager.h"
#include "plugin_graphics_view.h"

#include <QCoreApplication>
#include <QDataStream>
#include <QDateTime>
#include <QDeadlineTimer>
#include <QDir>
#include <QEventLoop>
#include <QImage>
#include <QLocalServer>
#include <QLocalSocket>
#include <QMutexLocker>
#include <QProcess>
#include <QReadLocker>
#include <QThread>
#include <QTimer>
#include <QWriteLocker>

#include "plugin_ipc.h"
#include "plugin_serialization.h"
#include "plugin_parser_proxy.h"
#include "protocolfactory.h"

namespace {
constexpr int kHandshakeTimeoutMs = 10000;
constexpr int kParseTimeoutMs = 5000;
constexpr int kHeartbeatIntervalMs = 5000;
constexpr int kHeartbeatTimeoutMs = 15000;
} // namespace

PluginManager& PluginManager::instance() {
    static PluginManager inst;
    return inst;
}

PluginManager::PluginManager(QObject* parent) : QObject(parent) {
    m_hb_timer.setInterval(kHeartbeatIntervalMs);
    connect(&m_hb_timer, &QTimer::timeout, this, &PluginManager::checkHeartbeats);
    m_hb_timer.start();
}

PluginManager::~PluginManager() {
    stop_all();
    // 退役运行时本体在此统一释放:管理器是进程级单例,析构时已无
    // 请求线程存活,迟到指针不可能再被解引用
    for (auto* rt : m_retired) delete rt;
    m_retired.clear();
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
        unregister_parser(rt->manifest.protocol_id);
    }
    // 第二遍:关停进程并释放重对象(socket/server/进程)。socket 只在
    // GUI 线程(本线程)读写,其他线程的写请求经排队调用投递、执行前
    // 复查 retired/socket,故无需再等在途请求。运行时本体(含 mutex)
    // 不在此 delete:可能仍有请求线程刚取到 rt 指针,本体转入 m_retired,
    // 留待管理器析构(进程退出、无请求线程存活时)释放(防 UAF)。
    for (auto* rt : runtimes) {
        {
            if (rt->socket) {
                // 优雅退出
                QByteArray p;
                send_message(rt, static_cast<quint8>(plugin_ipc::MsgType::Shutdown), p);
                rt->socket->flush();
                rt->socket->disconnectFromServer();
            }
            if (rt->process) {
                rt->process->terminate();
                if (!rt->process->waitForFinished(2000)) {
                    rt->process->kill();
                    rt->process->waitForFinished(1000);
                }
                delete rt->process;
                rt->process = nullptr;
            }
            delete rt->server;
            rt->server = nullptr;
            rt->socket = nullptr;   // socket 随 server 一并销毁
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

void PluginManager::loadAll(const QString& plugins_dir) {
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

QStringList PluginManager::pluginProtocolIds() const {
    QReadLocker rl(&m_plugins_lock);
    return m_plugins.keys();
}

bool PluginManager::is_plugin_protocol(const QString& protocol_id) const {
    const PluginRuntime* rt = find_runtime(protocol_id);
    return rt && rt->ready && !rt->disabled;
}

static QString hostBinaryPath() {
    // bplc-plugin-host 与主程序同目录
    return QCoreApplication::applicationDirPath()
         + QStringLiteral("/bplc-plugin-host");
}

bool PluginManager::start_plugin(const PluginManifest& m) {
    auto* rt = new PluginRuntime;
    rt->manifest = m;
    const QString sock_name = plugin_ipc::socketName(m.name);
    QLocalServer::removeServer(sock_name);

    rt->server = new QLocalServer(this);
    if (!rt->server->listen(sock_name)) {
        delete rt;
        return false;
    }
    const QString pid = m.protocol_id;
    connect(rt->server, &QLocalServer::newConnection,
            this, [this, pid]() { on_new_connection(pid); });

    rt->process = new QProcess(this);
    connect(rt->process,
            QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [this, pid](int code, QProcess::ExitStatus) {
                on_process_finished(pid, code);
            });
    connect(rt->process, &QProcess::errorOccurred,
            this, [this, pid]() { on_process_error(pid); });

    rt->process->start(hostBinaryPath(),
        {QStringLiteral("--socket"), sock_name,
         QStringLiteral("--plugin"), m.dir_path});
    if (!rt->process->waitForStarted(5000)) {
        delete rt;
        return false;
    }
    {
        QWriteLocker wl(&m_plugins_lock);
        m_plugins.insert(pid, rt);
    }
    return true;
}

void PluginManager::on_new_connection(const QString& plugin_id) {
    PluginRuntime* rt = find_runtime(plugin_id);
    if (!rt) return;
    rt->socket = rt->server->nextPendingConnection();
    connect(rt->socket, &QLocalSocket::readyRead,
            this, [this, plugin_id]() { on_host_ready_read(plugin_id); });
    connect(rt->socket, &QLocalSocket::disconnected,
            this, [this, plugin_id]() {
                disable_plugin(plugin_id, QStringLiteral("host disconnected"));
            });
}

void PluginManager::on_host_ready_read(const QString& plugin_id) {
    PluginRuntime* rt = find_runtime(plugin_id);
    if (!rt || !rt->socket) return;
    // 唯一收包点(socket 所属 GUI 线程):请求的响应按 seq 投递给等待方,
    // 其余消息走 handle_message。其他线程不得读该 socket。
    rt->rx_buf.append(rt->socket->readAll());
    while (rt->rx_buf.size() >= 5) {
        QDataStream hdr(rt->rx_buf);
        hdr.setVersion(plugin_ipc::kStreamVersion);
        quint32 len = 0;
        hdr >> len;
        if (rt->rx_buf.size() < 4 + (int)len) break;
        const QByteArray frame = rt->rx_buf.mid(4, len);
        rt->rx_buf.remove(0, 4 + len);
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
            if (rt->waiting.contains(rseq)) {   // 已超时放弃的迟到响应直接丢弃
                rt->responses.insert(rseq, frame);
                rt->resp_cv.wakeAll();
            }
            continue;
        }
        handle_message(plugin_id, t, ds);
    }
}

void PluginManager::handle_message(const QString& plugin_id, quint8 type,
                                  QDataStream& ds) {
    PluginRuntime* rt = find_runtime(plugin_id);
    if (!rt) return;
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
        send_message(rt, static_cast<quint8>(plugin_ipc::MsgType::HelloAck), p);
        if (ok) {
            rt->ready = true;
            rt->last_pong_ms = QDateTime::currentMSecsSinceEpoch();
            // 注册到协议注册表(协议 id → 代理;显示名取自 plugin.json,供界面协议列表)
            const QString pid = rt->manifest.protocol_id;
            register_parser_provider(pid, rt->manifest.display_name,
                                     rt->manifest.display_name_en,
                                     [pid]() { return make_plugin_parser(pid); });
            emit plugin_status_changed(plugin_id, QStringLiteral("ready"));
        } else {
            disable_plugin(plugin_id, QStringLiteral("handshake failed"));
        }
        break;
    }
    case plugin_ipc::MsgType::Pong: {
        quint64 seq = 0; ds >> seq; Q_UNUSED(seq);
        rt->last_pong_ms = QDateTime::currentMSecsSinceEpoch();
        break;
    }
    case plugin_ipc::MsgType::Error: {
        quint64 seq = 0; QString msg;
        ds >> seq >> msg; Q_UNUSED(seq);
        // 解析错误不禁用插件,仅记录(可日志)
        break;
    }
    case plugin_ipc::MsgType::RequestRedraw: {
        // 插件主动请求重绘:通知所有注册的视图
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
    if (QThread::currentThread() == thread()) {
        send_message(rt, type, payload);
        return;
    }
    // socket 属 GUI 线程:排队到 GUI 线程写出;执行时 rt 可能已退役
    // (socket 已释放),复查后再写。rt 本体在管理器析构前不会释放。
    QMetaObject::invokeMethod(this, [this, rt, type, payload]() {
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
    const qint64 deadline = QDateTime::currentMSecsSinceEpoch() + timeout_ms;
    bool got = false;
    if (QThread::currentThread() == thread()) {
        // GUI 线程(图形请求):跑事件循环等待,收包仍由 on_host_ready_read 完成
        while (!got && !rt->retired.load() && !rt->disabled.load() &&
               QDateTime::currentMSecsSinceEpoch() < deadline) {
            {
                QMutexLocker lock(&rt->ipc_mutex);
                got = rt->responses.contains(seq);
            }
            if (got) break;
            if (!rt->socket || rt->socket->state() != QLocalSocket::ConnectedState)
                break;
            QEventLoop loop;
            QTimer::singleShot(100, &loop, &QEventLoop::quit);
            QObject::connect(rt->socket, &QLocalSocket::readyRead, &loop,
                             &QEventLoop::quit, Qt::QueuedConnection);
            loop.exec();
        }
    }
    QMutexLocker lock(&rt->ipc_mutex);
    if (QThread::currentThread() != thread()) {
        // worker 线程:条件变量等待 GUI 线程投递响应(或停用/退役唤醒)
        while (!rt->responses.contains(seq) && !rt->retired.load() &&
               !rt->disabled.load()) {
            const qint64 left = deadline - QDateTime::currentMSecsSinceEpoch();
            if (left <= 0) break;
            rt->resp_cv.wait(&rt->ipc_mutex, QDeadlineTimer(left));
        }
    }
    got = rt->responses.contains(seq);
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
    // 退役/禁用/未就绪:不再发请求(socket 只由 GUI 线程触碰,这里不读 rt->socket)
    if (!rt->ready || rt->disabled || rt->retired.load()) return false;
    const quint64 seq = begin_request(rt);

    QByteArray payload;
    QDataStream o(&payload, QIODevice::WriteOnly);
    o.setVersion(plugin_ipc::kStreamVersion);
    o << seq << frame << msdu << filter;
    post_message(rt, static_cast<quint8>(plugin_ipc::MsgType::ParseRequest), payload);

    // 阻塞等待响应(worker 线程调用,不阻塞 UI);响应由 GUI 线程收包后按 seq 投递
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
        // 超时很可能意味着 host 挂了,禁用插件
        // 注意:不能在 worker 线程直接调 disable_plugin(涉及信号),标记即可
        rt->disabled = true;
        const QString reason = r.reject_reason;
        QMetaObject::invokeMethod(this, [this, rt, protocol_id, reason]() {
            rt->disable_reason = reason;
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
    unregister_parser(rt->manifest.protocol_id);
    emit plugin_status_changed(plugin_id, QStringLiteral("disabled: ") + reason);
}

void PluginManager::checkHeartbeats() {
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    QMap<QString, PluginRuntime*> snapshot;
    {
        QReadLocker rl(&m_plugins_lock);
        snapshot = m_plugins;
    }
    for (auto it = snapshot.cbegin(); it != snapshot.cend(); ++it) {
        PluginRuntime* rt = it.value();
        if (!rt->ready || rt->disabled || !rt->socket) continue;
        // 发 Ping(GUI 线程,直接写 socket)
        {
            QByteArray p;
            QDataStream o(&p, QIODevice::WriteOnly);
            o.setVersion(plugin_ipc::kStreamVersion);
            o << quint64(++rt->seq);
            send_message(rt, static_cast<quint8>(plugin_ipc::MsgType::Ping), p);
        }
        if (now - rt->last_pong_ms > kHeartbeatTimeoutMs) {
            disable_plugin(it.key(), QStringLiteral("heartbeat timeout"));
        }
    }
}

// ---- 图形(Phase3) ----

namespace {
constexpr int kGraphicsTimeoutMs = 5000;
} // namespace

bool PluginManager::has_graphics(const QString& protocol_id) const {
    const PluginRuntime* rt = find_runtime(protocol_id);
    return rt && rt->manifest.graphics;
}

QImage PluginManager::request_render(const QString& protocol_id,
                                     int w, int h) {
    PluginRuntime* rt = find_runtime(protocol_id);
    if (!rt) return QImage();
    if (!rt->ready || rt->disabled || !rt->socket) return QImage();
    if (!rt->manifest.graphics) return QImage();

    const quint64 seq = begin_request(rt);
    QByteArray payload;
    QDataStream o(&payload, QIODevice::WriteOnly);
    o.setVersion(plugin_ipc::kStreamVersion);
    o << seq << w << h;
    post_message(rt, static_cast<quint8>(plugin_ipc::MsgType::RenderRequest),
                 payload);

    QByteArray fr;
    if (!wait_response(rt, seq, kGraphicsTimeoutMs, &fr)) return QImage();
    QDataStream ds(fr);
    ds.setVersion(plugin_ipc::kStreamVersion);
    quint8 t = 0; quint64 rseq = 0; bool rok = false;
    QImage img;
    ds >> t >> rseq >> rok >> img;
    return rok ? img : QImage();
}

bool PluginManager::send_graphics_event(const QString& protocol_id,
                                        const GraphicsEvent& e) {
    PluginRuntime* rt = find_runtime(protocol_id);
    if (!rt) return false;
    if (!rt->ready || rt->disabled || !rt->socket) return false;
    if (!rt->manifest.graphics) return false;

    const quint64 seq = begin_request(rt);
    QByteArray payload;
    QDataStream o(&payload, QIODevice::WriteOnly);
    o.setVersion(plugin_ipc::kStreamVersion);
    o << seq << e;
    post_message(rt,
                 static_cast<quint8>(plugin_ipc::MsgType::GraphicsEventMsg),
                 payload);

    QByteArray fr;
    if (!wait_response(rt, seq, kGraphicsTimeoutMs, &fr)) return false;
    QDataStream ds(fr);
    ds.setVersion(plugin_ipc::kStreamVersion);
    quint8 t = 0; quint64 rseq = 0; bool redraw = false;
    ds >> t >> rseq >> redraw;
    return redraw;
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
