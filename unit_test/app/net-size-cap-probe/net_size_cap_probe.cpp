/// @file net_size_cap_probe.cpp
/// @brief 本地 HTTP 服务器按场景返回超大响应,验证 netcap::cap_reply_size 中止且不缓冲到底
#include "net_size_cap.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <cstdio>
#include <zlib.h>

static int g_fail = 0;
static void check(bool ok, const char* what) {
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++g_fail;
}

static QByteArray gzip(const QByteArray& in) {
    z_stream zs{};
    deflateInit2(&zs, 9, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
    QByteArray out(int(deflateBound(&zs, in.size())), Qt::Uninitialized);
    zs.next_in = (Bytef*)in.constData(); zs.avail_in = in.size();
    zs.next_out = (Bytef*)out.data(); zs.avail_out = out.size();
    deflate(&zs, Z_FINISH);
    out.resize(int(zs.total_out));
    deflateEnd(&zs);
    return out;
}

/// 服务器:路径决定行为
///  /small     512 KB,带 Content-Length
///  /declared  声明 Content-Length 5 GB,只发 64 KB 后挂住
///  /endless   chunked,无限发送 64 KB 块
///  /gzip      4 MB 零字节 gzip 后 (~4 KB) 发送,Content-Encoding: gzip
class Server : public QTcpServer {
public:
    Server() {
        connect(this, &QTcpServer::newConnection, this, [this]() {
            while (QTcpSocket* s = nextPendingConnection()) {
                connect(s, &QTcpSocket::readyRead, s, [s]() { on_req(s); });
                connect(s, &QTcpSocket::disconnected, s, &QObject::deleteLater);
            }
        });
    }
    static void on_req(QTcpSocket* s) {
        const QByteArray req = s->readAll();
        const QByteArray path = req.split(' ').value(1);
        if (path == "/small") {
            const QByteArray body(512 * 1024, 'a');
            s->write("HTTP/1.1 200 OK\r\nContent-Length: " + QByteArray::number(body.size()) +
                     "\r\nConnection: close\r\n\r\n" + body);
        } else if (path == "/declared") {
            s->write("HTTP/1.1 200 OK\r\nContent-Length: 5368709120\r\n\r\n" + QByteArray(64 * 1024, 'b'));
        } else if (path == "/gzip") {
            const QByteArray body = gzip(QByteArray(4 * 1024 * 1024, '\0'));
            s->write("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: " +
                     QByteArray::number(body.size()) + "\r\nConnection: close\r\n\r\n" + body);
        } else if (path == "/endless") {
            s->write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
            auto* t = new QTimer(s);
            connect(t, &QTimer::timeout, s, [s]() {
                if (s->bytesToWrite() > 1024 * 1024) return;
                const QByteArray chunk(64 * 1024, 'c');
                s->write(QByteArray::number(chunk.size(), 16) + "\r\n" + chunk + "\r\n");
            });
            t->start(0);
        }
    }
};

struct Outcome { bool exceeded; QNetworkReply::NetworkError err; qint64 body; qint64 ms; };

static Outcome fetch(QNetworkAccessManager& nam, quint16 port, const char* path, qint64 cap) {
    QNetworkRequest req(QUrl(QStringLiteral("http://127.0.0.1:%1%2").arg(port).arg(path)));
    QElapsedTimer tm; tm.start();
    QNetworkReply* r = nam.get(req);
    netcap::cap_reply_size(r, cap);
    QEventLoop loop;
    QObject::connect(r, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QTimer::singleShot(15000, &loop, &QEventLoop::quit);
    loop.exec();
    Outcome o{netcap::size_exceeded(r), r->error(), r->isOpen() ? r->readAll().size() : -1, tm.elapsed()};
    std::printf("  %s: exceeded=%d err=%d body=%lld ms=%lld finished=%d\n", path, o.exceeded, int(o.err),
                (long long)o.body, (long long)o.ms, r->isFinished());
    r->deleteLater();
    return o;
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    Server srv;
    if (!srv.listen(QHostAddress::LocalHost)) { std::puts("FAIL listen"); return 1; }
    const quint16 port = srv.serverPort();
    QNetworkAccessManager nam;
    const qint64 cap = 1024 * 1024;

    Outcome o = fetch(nam, port, "/small", cap);
    check(!o.exceeded && o.err == QNetworkReply::NoError && o.body == 512 * 1024, "512 KB under 1 MB cap passes intact");

    o = fetch(nam, port, "/declared", cap);
    check(o.exceeded && o.err == QNetworkReply::OperationCanceledError && o.ms < 5000,
          "declared 5 GB Content-Length aborted early");

    o = fetch(nam, port, "/endless", cap);
    check(o.exceeded && o.err == QNetworkReply::OperationCanceledError && o.ms < 10000,
          "endless chunked stream aborted");

    o = fetch(nam, port, "/gzip", cap);
    check(o.exceeded && o.err == QNetworkReply::OperationCanceledError,
          "gzip body inflating to 4 MB aborted");

    o = fetch(nam, port, "/small", 64 * 1024);
    check(o.exceeded, "512 KB over a 64 KB cap aborted");

    std::printf("net_size_cap_probe: %s (%d failures)\n", g_fail ? "FAIL" : "OK", g_fail);
    return g_fail ? 1 : 0;
}
