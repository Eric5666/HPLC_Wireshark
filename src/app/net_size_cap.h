/// @file net_size_cap.h
/// @brief 网络响应大小上限(CVE-2026-116337 缓解:恶意/被攻破的服务器不得耗尽内存)
/// @details 对 QNetworkReply 累计已收字节,超过上限即 abort()。abort 会以
///          OperationCanceledError 结束请求,调用方用 size_exceeded() 区分
///          "超限中止"与普通取消/超时。
#ifndef BPLC_APP_NET_SIZE_CAP_H
#define BPLC_APP_NET_SIZE_CAP_H

#include <QNetworkReply>
#include <QNetworkRequest>
#include <QObject>
#include <QtGlobal>

namespace netcap {

constexpr qint64 kMaxManifestBytes = 1LL * 1024 * 1024;    ///< update.json / 插件 feed / 版本索引 / 文本
constexpr qint64 kMaxPluginPackageBytes = 64LL * 1024 * 1024; ///< 插件 zip 包(与解压单条上限一致)

/// @brief 给 reply 加大小上限;服务器声明的总长或实际收到/缓冲的字节超过 max_bytes 即中止
/// @param reply 刚创建的请求(须在事件循环回到之前调用)
/// @param max_bytes 上限(字节)
inline void cap_reply_size(QNetworkReply* reply, qint64 max_bytes) {
    auto check = [reply, max_bytes](qint64 received, qint64 total) {
        if (reply->property("netcap_exceeded").toBool()) return;
        // bytesAvailable 是解压后的缓冲量,覆盖 gzip 膨胀;received/total 覆盖边收边读的调用方
        if (received > max_bytes || total > max_bytes ||
            reply->bytesAvailable() > max_bytes) {
            reply->setProperty("netcap_exceeded", true);
            reply->abort();
        }
    };
    QObject::connect(reply, &QNetworkReply::metaDataChanged, reply, [reply, check]() {
        // 响应头一到就按 Content-Length 判定,不必等进度信号
        bool ok = false;
        const qint64 declared =
            reply->header(QNetworkRequest::ContentLengthHeader).toLongLong(&ok);
        check(0, ok ? declared : -1);
    });
    QObject::connect(reply, &QNetworkReply::downloadProgress, reply, check);
    QObject::connect(reply, &QIODevice::readyRead, reply, [check]() { check(0, -1); });
}

/// @brief 请求是否因超过大小上限被中止
inline bool size_exceeded(const QNetworkReply* reply) {
    return reply->property("netcap_exceeded").toBool();
}

} // namespace netcap

#endif // BPLC_APP_NET_SIZE_CAP_H
