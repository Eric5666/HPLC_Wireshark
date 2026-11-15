/// @file plugin_ipc_test.cpp
/// @brief 插件 IPC 集成测试:启动 bplc-plugin-host,验证 3 种新插件
/// @details 用法: plugin_ipc_test --host <path-to-bplc-plugin-host> --examples <dir>
///          测试 js_topo/lua_diag/lua_report 的解析、图形渲染、事件
#include <QCoreApplication>
#include <QCommandLineParser>
#include <QLocalServer>
#include <QLocalSocket>
#include <QProcess>
#include <QTimer>
#include <QElapsedTimer>
#include <QDataStream>
#include <QImage>
#include <QThread>
#include <cstdio>
#include <QTextStream>
#include <QDir>
#include <QHash>

#include <chrono>
#include <cstdlib>
#include <thread>

#include "../ipc/plugin_ipc.h"
#include "../ipc/plugin_serialization.h"

namespace {

QTextStream& log() {
    static QTextStream s(stdout);
    return s;
}

int g_pass = 0;
int g_fail = 0;

void check(bool ok, const QString& name, const QString& detail = {}) {
    if (ok) {
        ++g_pass;
        log() << "  [PASS] " << name;
        if (!detail.isEmpty()) log() << " - " << detail;
        log() << "\n";
        log().flush();
    } else {
        ++g_fail;
        log() << "  [FAIL] " << name;
        if (!detail.isEmpty()) log() << " - " << detail;
        log() << "\n";
        log().flush();
    }
}

QByteArray make_payload(std::function<void(QDataStream&)> writer) {
    QByteArray p;
    QDataStream ds(&p, QIODevice::WriteOnly);
    ds.setVersion(plugin_ipc::kStreamVersion);
    writer(ds);
    return p;
}

void send_msg(QLocalSocket* sock, plugin_ipc::MsgType t, const QByteArray& payload) {
    QByteArray frame;
    QDataStream ds(&frame, QIODevice::WriteOnly);
    ds.setVersion(plugin_ipc::kStreamVersion);
    ds << quint32(1 + payload.size()) << static_cast<quint8>(t);
    frame.append(payload);
    sock->write(frame);
    sock->flush();
}

struct RecvResult {
    bool ok = false;
    plugin_ipc::MsgType type{};
    QByteArray payload;
    QString error;
};

/// @brief 收一帧 host→app 消息
/// @details 按真实帧格式(plugin_ipc::try_take_frame)从每个 socket 自己的缓冲取帧。
///   旧实现先读 4 字节头,再 waitForReadyRead() 等帧体:帧体若已随头一起到达
///   缓冲区,waitForReadyRead 不会再触发,于是一直等到超时并把后续帧读错位
///   (表现为 "timeout waiting for body" / "bad frame len" 与整体卡死)。
///   插件主动发的 RequestRedraw 与本测试无关,直接跳过。
RecvResult recv_msg(QLocalSocket* sock, int timeout_ms = 10000) {
    static QHash<QLocalSocket*, QByteArray> s_bufs;
    QByteArray& buf = s_bufs[sock];
    RecvResult r;
    QElapsedTimer timer;
    timer.start();
    for (;;) {
        QByteArray body;
        switch (plugin_ipc::try_take_frame(buf, body)) {
        case plugin_ipc::FrameTake::Ok: {
            const auto t = static_cast<plugin_ipc::MsgType>(static_cast<quint8>(body[0]));
            if (t == plugin_ipc::MsgType::RequestRedraw) continue;
            r.type = t;
            r.payload = body.mid(1);
            r.ok = true;
            return r;
        }
        case plugin_ipc::FrameTake::Bad:
            r.error = QStringLiteral("bad frame header");
            buf.clear();
            return r;
        case plugin_ipc::FrameTake::NeedMore:
            break;
        }
        if (timer.elapsed() > timeout_ms) {
            r.error = QStringLiteral("timeout (%1 bytes buffered)").arg(buf.size());
            return r;
        }
        if (sock->bytesAvailable() == 0 &&
            sock->state() != QLocalSocket::ConnectedState) {
            r.error = QStringLiteral("host disconnected");
            return r;
        }
        if (sock->bytesAvailable() == 0) sock->waitForReadyRead(100);
        buf.append(sock->readAll());
    }
}

BplcFrame make_test_frame(const QByteArray& data, qint64 arrival_us) {
    BplcFrame f;
    f.data = data;
    f.arrival_us = arrival_us;
    return f;
}

/// @brief 测试单个插件,返回 true=全部通过
bool test_plugin(const QString& host_bin, const QString& plugin_dir,
                 const QString& plugin_name, bool test_graphics) {
    log() << "\n=== Testing " << plugin_name << " ===\n";

    const QString sock_name = QStringLiteral("test_%1_%2")
        .arg(plugin_name).arg(QCoreApplication::applicationPid());
    QLocalServer::removeServer(sock_name);
    QLocalServer server;
    if (!server.listen(sock_name)) {
        check(false, QStringLiteral("server listen"), server.errorString());
        return false;
    }

    QProcess host;
    host.start(host_bin, {QStringLiteral("--socket"), sock_name,
                          QStringLiteral("--plugin"), plugin_dir});
    if (!host.waitForStarted(5000)) {
        check(false, QStringLiteral("host start"), host.errorString());
        return false;
    }

    // 轮询等待连接(兼容 offscreen 模式)
    QLocalSocket* pending_sock = nullptr;
    for (int i = 0; i < 100; ++i) {
        // 让 server 处理待接受的连接
        QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
        if (server.hasPendingConnections()) {
            pending_sock = server.nextPendingConnection();
            break;
        }
        // 检查 host 是否已退出
        if (host.state() == QProcess::NotRunning) {
            QString host_err = QString::fromLocal8Bit(host.readAllStandardError());
            break;
        }
        QThread::msleep(100);
    }
    if (!pending_sock) {
        QString host_err = QString::fromLocal8Bit(host.readAllStandardError());
        check(false, QStringLiteral("host connect"),
              QStringLiteral("timeout; host stderr: %1").arg(host_err.left(200)));
        host.kill();
        return false;
    }
    QLocalSocket* sock = pending_sock;
    check(sock != nullptr, QStringLiteral("accept connection"));
    if (!sock) { host.kill(); return false; }

    bool all_ok = true;
    auto mark = [&](bool ok) { if (!ok) all_ok = false; };

    // 1. Hello (host→app)
    {
        RecvResult rr = recv_msg(sock);
        bool ok = rr.ok && rr.type == plugin_ipc::MsgType::Hello;
        QString plugin_id;
        QString plugin_name2;
        int api_ver = 0;
        if (ok) {
            QDataStream ds(rr.payload);
            ds.setVersion(plugin_ipc::kStreamVersion);
            ds >> api_ver >> plugin_name2 >> plugin_id;
            ok = (api_ver == plugin_ipc::kApiVersion);
        }
        check(ok, QStringLiteral("Hello handshake"),
              ok ? QStringLiteral("plugin_id=%1").arg(plugin_id) : rr.error);
        mark(ok);
        // 回 HelloAck
        QByteArray p = make_payload([](QDataStream& ds) {
            ds << true << QString();
        });
        send_msg(sock, plugin_ipc::MsgType::HelloAck, p);
    }

    // 2. ParseRequest × N
    QList<QByteArray> frames;
    if (plugin_name == QStringLiteral("lua_diag")) {
        frames = {
            QByteArray::fromHex("0102"),  // too short
            QByteArray::fromHex("3c000000") + QByteArray(20, '\0'),  // zero TEI
            QByteArray::fromHex("3c000102") + QByteArray(20, '\xAA'),  // OK
        };
    } else {
        frames = {
            QByteArray::fromHex("3c000102") + QByteArray(20, '\xAA'),
            QByteArray::fromHex("3c000201") + QByteArray(30, '\xBB'),
            QByteArray::fromHex("3c000301") + QByteArray(40, '\xCC'),
        };
    }
    quint64 seq = 1;
    for (int i = 0; i < frames.size(); ++i) {
        BplcFrame frame = make_test_frame(frames[i], 1000000 + i * 1000);
        MsduState msdu;
        ParseFilter filter;
        QByteArray p = make_payload([&](QDataStream& ds) {
            ds << seq << frame << msdu << filter;
        });
        send_msg(sock, plugin_ipc::MsgType::ParseRequest, p);
        RecvResult rr = recv_msg(sock);
        bool ok = rr.ok && rr.type == plugin_ipc::MsgType::ParseResponse;
        QString summary;
        if (ok) {
            QDataStream ds(rr.payload);
            ds.setVersion(plugin_ipc::kStreamVersion);
            quint64 rseq = 0;
            bool accepted = false;
            ParseResult result;
            MsduState rmsdu;
            ds >> rseq >> accepted >> result >> rmsdu;
            ok = (rseq == seq);
            summary = result.msdu.summary.left(60);
        }
        check(ok, QStringLiteral("Parse frame %1").arg(i + 1), summary);
        mark(ok);
        ++seq;
    }

    // 3. 图形测试
    if (test_graphics) {
        // RenderRequest
        {
            QByteArray p = make_payload([&](QDataStream& ds) {
                ds << seq << 400 << 300;
            });
            send_msg(sock, plugin_ipc::MsgType::RenderRequest, p);
            RecvResult rr = recv_msg(sock);
            bool ok = rr.ok && rr.type == plugin_ipc::MsgType::RenderResponse;
            int img_bytes = 0;
            if (ok) {
                QDataStream ds(rr.payload);
                ds.setVersion(plugin_ipc::kStreamVersion);
                quint64 rseq = 0;
                bool rok = false;
                QImage img;
                ds >> rseq >> rok >> img;
                ok = (rseq == seq) && rok && !img.isNull();
                img_bytes = img.width() * img.height();
            }
            check(ok, QStringLiteral("Render 400x300"),
                  ok ? QStringLiteral("%1 px").arg(img_bytes) : rr.error);
            mark(ok);
            ++seq;
        }
        // GraphicsEvent (点击中心)
        {
            GraphicsEvent evt;
            evt.type = GraphicsEventType::MousePress;
            evt.x = 200; evt.y = 150;
            evt.button = 1;
            evt.modifiers = 0;
            evt.delta_y = 0;
            QByteArray p = make_payload([&](QDataStream& ds) {
                ds << seq << evt;
            });
            send_msg(sock, plugin_ipc::MsgType::GraphicsEventMsg, p);
            RecvResult rr = recv_msg(sock);
            bool ok = rr.ok && rr.type == plugin_ipc::MsgType::EventAck;
            bool needs_redraw = false;
            if (ok) {
                QDataStream ds(rr.payload);
                ds.setVersion(plugin_ipc::kStreamVersion);
                quint64 rseq = 0;
                ds >> rseq >> needs_redraw;
                ok = (rseq == seq);
            }
            check(ok, QStringLiteral("GraphicsEvent click"),
                  ok ? QStringLiteral("needs_redraw=%1").arg(needs_redraw) : rr.error);
            mark(ok);
            ++seq;
        }
    }

    // 4. Shutdown
    send_msg(sock, plugin_ipc::MsgType::Shutdown, {});
    sock->disconnectFromServer();
    host.waitForFinished(5000);
    if (host.state() != QProcess::NotRunning) host.kill();

    log() << (all_ok ? "  >> ALL PASS\n" : "  >> SOME FAILED\n");
    return all_ok;
}

} // namespace

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    // 总时长看门狗:任何一步卡住都在 120 s 内以失败退出,绝不挂死 CI
    // (测试全程是阻塞调用,QTimer 不会被调度,所以用独立线程)
    std::thread([] {
        std::this_thread::sleep_for(std::chrono::seconds(120));
        std::fprintf(stderr, "FAIL: plugin_ipc_test watchdog (120 s) expired\n");
        std::fflush(stderr);
        std::_Exit(3);
    }).detach();
    QCommandLineParser cli;
    cli.addHelpOption();
    QCommandLineOption host_opt(QStringList{QStringLiteral("host")},
        QStringLiteral("path to bplc-plugin-host"), QStringLiteral("bin"));
    QCommandLineOption ex_opt(QStringList{QStringLiteral("examples")},
        QStringLiteral("examples dir"), QStringLiteral("dir"));
    cli.addOption(host_opt);
    cli.addOption(ex_opt);
    cli.process(app);

    const QString host_bin = cli.value(host_opt);
    const QString ex_dir = cli.value(ex_opt);
    if (host_bin.isEmpty() || ex_dir.isEmpty()) {
        QTextStream(stderr) << "usage: plugin_ipc_test --host <bin> --examples <dir>\n";
        return 1;
    }

    log() << "Plugin IPC Integration Test\n";
    log() << "Host: " << host_bin << "\n";
    log() << "Examples: " << ex_dir << "\n";

    bool all_ok = true;
    all_ok &= test_plugin(host_bin, ex_dir + "/js_topo", QStringLiteral("js_topo"), true);
    all_ok &= test_plugin(host_bin, ex_dir + "/lua_diag", QStringLiteral("lua_diag"), false);
    all_ok &= test_plugin(host_bin, ex_dir + "/lua_report", QStringLiteral("lua_report"), false);

    log() << "\n========================================\n";
    log() << QStringLiteral("Total: %1 passed, %2 failed\n").arg(g_pass).arg(g_fail);
    log() << (all_ok ? "ALL TESTS PASSED\n" : "SOME TESTS FAILED\n");
    return all_ok ? 0 : 1;
}
