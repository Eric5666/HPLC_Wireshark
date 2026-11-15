/// @file plugin_host.cpp
/// @brief bplc-plugin-host 实现(多 backend)
#include "plugin_host.h"

#include <QCoreApplication>
#include <QDataStream>
#include <QTimer>

#include "plugin_backend.h"
#include "plugin_serialization.h"

PluginHost::PluginHost(const QString& socket_name, const QString& plugin_dir,
                       QObject* parent)
    : QObject(parent), m_socket_name(socket_name) {
    m_manifest = read_plugin_manifest(plugin_dir);
}

PluginHost::~PluginHost() {
    delete m_backend;
    m_backend = nullptr;
}

bool PluginHost::start(QString* err) {
    if (!m_manifest.valid) {
        *err = QStringLiteral("bad manifest: %1").arg(m_manifest.error);
        return false;
    }
    if (m_manifest.api_version != plugin_ipc::kApiVersion) {
        *err = QStringLiteral("api_version mismatch: plugin=%1 host=%2")
                   .arg(m_manifest.api_version).arg(plugin_ipc::kApiVersion);
        return false;
    }

    m_backend = create_backend(m_manifest.runtime);
    if (!m_backend) {
        *err = QStringLiteral("unsupported runtime '%1'")
                   .arg(m_manifest.runtime);
        return false;
    }
    if (!m_backend->initialize(m_manifest, err)) {
        delete m_backend;
        m_backend = nullptr;
        return false;
    }
    // 插件主动请求重绘 → 发 RequestRedraw 给主进程
    PluginHost* self = this;
    m_backend->set_redraw_callback([self]() {
        self->send_message(plugin_ipc::MsgType::RequestRedraw, QByteArray());
    });
    // 后端协议 id 须与清单一致
    if (m_backend->protocol_id() != m_manifest.protocol_id) {
        *err = QStringLiteral("protocolId mismatch: manifest=%1 backend=%2")
                   .arg(m_manifest.protocol_id, m_backend->protocol_id());
        delete m_backend;
        m_backend = nullptr;
        return false;
    }

    connect(&m_socket, &QLocalSocket::connected, this, &PluginHost::on_connected);
    connect(&m_socket, &QLocalSocket::readyRead, this, &PluginHost::on_ready_read);
    connect(&m_socket, &QLocalSocket::disconnected,
            qApp, &QCoreApplication::quit);
    connect(&m_socket, &QLocalSocket::errorOccurred,
            this, &PluginHost::on_socket_error);
    m_socket.connectToServer(m_socket_name);
    if (!m_socket.waitForConnected(10000)) {
        *err = QStringLiteral("connect to main app failed: %1")
                   .arg(m_socket.errorString());
        return false;
    }
    return true;
}

int PluginHost::exec() {
    return QCoreApplication::exec();
}

void PluginHost::on_connected() {
    // 握手
    QByteArray p;
    QDataStream ds(&p, QIODevice::WriteOnly);
    ds.setVersion(plugin_ipc::kStreamVersion);
    ds << plugin_ipc::kApiVersion << m_manifest.name << m_manifest.protocol_id
       << plugin_ipc::kWireFormatVersion;
    send_message(plugin_ipc::MsgType::Hello, p);
}

void PluginHost::on_ready_read() {
    m_rx_buf.append(m_socket.readAll());
    // 帧:[quint32 len][quint8 type][payload]
    for (;;) {
        QByteArray frame;
        const auto took = plugin_ipc::try_take_frame(m_rx_buf, frame);
        if (took == plugin_ipc::FrameTake::NeedMore) break;  // 等更多数据
        if (took == plugin_ipc::FrameTake::Bad) {
            // 帧长非法:流已失步,断开并退出(主程序会把插件标为断开)
            m_rx_buf.clear();
            m_socket.abort();
            QCoreApplication::exit(3);
            return;
        }

        QDataStream ds(frame);
        ds.setVersion(plugin_ipc::kStreamVersion);
        quint8 t = 0;
        ds >> t;
        handle_message(static_cast<plugin_ipc::MsgType>(t), ds);
    }
}

void PluginHost::on_disconnected() {
    QCoreApplication::quit();  // 主程序断开 → 退出
}

void PluginHost::on_socket_error(QLocalSocket::LocalSocketError e) {
    if (e != QLocalSocket::PeerClosedError)
        QCoreApplication::exit(2);
}

void PluginHost::send_message(plugin_ipc::MsgType t, const QByteArray& payload) {
    QByteArray frame;
    QDataStream ds(&frame, QIODevice::WriteOnly);
    ds.setVersion(plugin_ipc::kStreamVersion);
    ds << quint32(1 + payload.size()) << static_cast<quint8>(t);
    frame.append(payload);
    m_socket.write(frame);
    m_socket.flush();
}

void PluginHost::handle_message(plugin_ipc::MsgType t, QDataStream& ds) {
    switch (t) {
    case plugin_ipc::MsgType::HelloAck: {
        bool ok = false; QString reason;
        ds >> ok >> reason;
        m_hello_done = ok;
        if (!ok) QCoreApplication::exit(3);
        break;
    }
    case plugin_ipc::MsgType::ParseRequest:
        handle_parse_request(ds);
        break;
    case plugin_ipc::MsgType::RenderRequest:
        handle_render_request(ds);
        break;
    case plugin_ipc::MsgType::GraphicsEventMsg:
        handle_graphics_event(ds);
        break;
    case plugin_ipc::MsgType::Ping: {
        quint64 seq = 0; ds >> seq;
        QByteArray p; QDataStream o(&p, QIODevice::WriteOnly);
        o.setVersion(plugin_ipc::kStreamVersion); o << seq;
        send_message(plugin_ipc::MsgType::Pong, p);
        break;
    }
    case plugin_ipc::MsgType::Shutdown:
        QCoreApplication::quit();
        break;
    default:
        break;
    }
}

void PluginHost::handle_parse_request(QDataStream& ds) {
    quint64 seq = 0;
    BplcFrame frame; MsduState msdu; ParseFilter filter;
    ds >> seq >> frame >> msdu >> filter;

    QByteArray resp;
    QDataStream o(&resp, QIODevice::WriteOnly);
    o.setVersion(plugin_ipc::kStreamVersion);
    o << seq;
    if (!m_hello_done || !m_backend) {
        o << false;  // ok=false
        o << QStringLiteral("not ready");
    } else {
        QString err;
        const ParseResult r = m_backend->parse(frame, msdu, filter, &err);
        // JS 等脚本后端可能置 err:accept=false 时 reject_reason 已填
        o << r.accept << r << msdu;
        Q_UNUSED(err);
    }
    send_message(plugin_ipc::MsgType::ParseResponse, resp);
}

void PluginHost::handle_render_request(QDataStream& ds) {
    quint64 seq = 0; int w = 0, h = 0;
    ds >> seq >> w >> h;

    QByteArray resp;
    QDataStream o(&resp, QIODevice::WriteOnly);
    o.setVersion(plugin_ipc::kStreamVersion);
    o << seq;
    if (!m_hello_done || !m_backend || !m_backend->has_graphics()) {
        o << false << QImage();
    } else {
        QString err;
        const QImage img = m_backend->render_graphics(w, h, &err);
        o << !img.isNull() << img;
        Q_UNUSED(err);
    }
    send_message(plugin_ipc::MsgType::RenderResponse, resp);
}

void PluginHost::handle_graphics_event(QDataStream& ds) {
    quint64 seq = 0; GraphicsEvent e;
    ds >> seq >> e;

    QByteArray resp;
    QDataStream o(&resp, QIODevice::WriteOnly);
    o.setVersion(plugin_ipc::kStreamVersion);
    o << seq;
    if (!m_hello_done || !m_backend || !m_backend->has_graphics()) {
        o << false;
    } else {
        QString err;
        o << m_backend->handle_graphics_event(e, &err);
        Q_UNUSED(err);
    }
    send_message(plugin_ipc::MsgType::EventAck, resp);
}
