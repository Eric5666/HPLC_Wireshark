/// @file updatemirror.cpp
/// @brief UpdateMirrorResolver 实现(见 updatemirror.h 的决策流程说明)
#include "updatemirror.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTimer>
#include <QUrl>

#include "appconfig.h"
#include "net_size_cap.h"

namespace {
constexpr int kRegionTimeoutMs  = 3500;   // 出口区域识别(每源)
constexpr int kProbeTimeoutMs   = 4500;   // 清单探活(原生/每个镜像)
const char* kTraceUrl     = "https://www.cloudflare.com/cdn-cgi/trace";
const char* kCountryIsUrl = "https://api.country.is/";
const char* kIpwhoUrl     = "https://ipwho.is/";
} // namespace

UpdateMirrorResolver::UpdateMirrorResolver(QObject* parent)
    : QObject(parent), m_nam(new QNetworkAccessManager(this)) {}

void UpdateMirrorResolver::get(const QString& url, int timeoutMs,
                               const std::function<void(QNetworkReply*)>& done) {
    QNetworkRequest req{QUrl(url)};
    req.setHeader(QNetworkRequest::UserAgentHeader,
                  QStringLiteral("BPLC-STA-Monitor update-mirror probe"));
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                     QNetworkRequest::NoLessSafeRedirectPolicy);
    QNetworkReply* reply = m_nam->get(req);
    // 探活只读区域 JSON / update.json,超过上限即中止(按普通探测失败处理)
    netcap::cap_reply_size(reply, netcap::kMaxManifestBytes);
    auto* timer = new QTimer(reply);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, reply, &QNetworkReply::abort);
    timer->start(timeoutMs);
    connect(reply, &QNetworkReply::finished, this, [reply, done]() {
        done(reply);
        reply->deleteLater();
    });
}

bool UpdateMirrorResolver::looks_like_manifest(const QByteArray& body,
                                               const QString& manifest_key) {
    const QJsonDocument doc = QJsonDocument::fromJson(body);
    return doc.isObject() && doc.object().contains(manifest_key);
}

void UpdateMirrorResolver::finish(const QString& effectiveUrl, const QString& prefix) {
    if (m_done) return;
    m_done = true;
    emit resolved(effectiveUrl, prefix);
}

void UpdateMirrorResolver::resolve(const QString& updateUrl,
                                  const QString& manifest_key) {
    m_url = updateUrl;
    m_manifest_key = manifest_key;
    m_done = false;
    const QString scheme = QUrl(updateUrl).scheme().toLower();
    if (scheme != QStringLiteral("http") && scheme != QStringLiteral("https")) {
        finish(m_url, QString());
        return;
    }
    m_mirrors = appcfg::mirror_list();
    const QString mode = appcfg::mirror_mode();
    if (mode == QStringLiteral("native")) {
        qInfo("[update-mirror] mode=native, using native URL");
        finish(m_url, QString());
    } else if (mode == QStringLiteral("proxy")) {
        qInfo("[update-mirror] mode=proxy, probing mirrors");
        probe_mirror(0);
    } else {
        if (mode != QStringLiteral("auto"))
            qWarning("[update-mirror] unknown mirror_mode \"%s\", falling back to auto",
                     qPrintable(mode));
        detect_region();
    }
}

void UpdateMirrorResolver::detect_region() { detect_from_source(0); }

void UpdateMirrorResolver::detect_from_source(int idx) {
    if (idx == 0) {
        // 源 1:Cloudflare cdn-cgi/trace(纯文本,loc=XX)
        get(QString::fromLatin1(kTraceUrl), kRegionTimeoutMs, [this](QNetworkReply* r) {
            QString loc;
            if (r->error() == QNetworkReply::NoError) {
                const QString body = QString::fromUtf8(r->readAll());
                for (const QString& line : body.split(QLatin1Char('\n'))) {
                    if (line.startsWith(QStringLiteral("loc=")))
                        loc = line.mid(4).trimmed().toUpper();
                }
            }
            if (loc.size() == 2) {
                qInfo("[update-mirror] region source cloudflare-trace reports %s",
                      qPrintable(loc));
                on_region(loc);
            } else {
                detect_from_source(1);
            }
        });
        return;
    }
    // 源 2/3:JSON 接口,取国家码字段;字段名不同,逐源声明
    struct JsonSource { const char* name; const char* url; const char* key; };
    static const JsonSource kJsonSources[] = {
        { "country.is", kCountryIsUrl, "country" },
        { "ipwho.is",   kIpwhoUrl,     "country_code" },
    };
    const int si = idx - 1;
    if (si >= int(sizeof(kJsonSources) / sizeof(kJsonSources[0]))) {
        on_region(QString());   // 三源全灭 → 未知,走原生探活链
        return;
    }
    const JsonSource src = kJsonSources[si];
    get(QString::fromLatin1(src.url), kRegionTimeoutMs,
        [this, idx, src](QNetworkReply* r) {
            QString cc;
            if (r->error() == QNetworkReply::NoError) {
                const QJsonObject obj =
                    QJsonDocument::fromJson(r->readAll()).object();
                if (obj.value(QStringLiteral("success")).toBool(true))
                    cc = obj.value(QLatin1String(src.key)).toString()
                             .trimmed().toUpper();
            }
            if (cc.size() == 2) {
                qInfo("[update-mirror] region source %s reports %s",
                      src.name, qPrintable(cc));
                on_region(cc);
            } else {
                detect_from_source(idx + 1);
            }
        });
}

void UpdateMirrorResolver::on_region(const QString& countryCode) {
    if (countryCode == QStringLiteral("CN")) {
        qInfo("[update-mirror] egress region=CN, probing mirrors");
        probe_mirror(0);
    } else if (!countryCode.isEmpty()) {
        qInfo("[update-mirror] egress region=%s, using native URL",
              qPrintable(countryCode));
        finish(m_url, QString());
    } else {
        qInfo("[update-mirror] egress region unknown, probing native URL first");
        probe_native();
    }
}

void UpdateMirrorResolver::probe_native() {
    get(m_url, kProbeTimeoutMs, [this](QNetworkReply* r) {
        const bool ok = r->error() == QNetworkReply::NoError
            && r->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() == 200
            && looks_like_manifest(r->readAll(), m_manifest_key);
        if (ok) {
            qInfo("[update-mirror] native URL reachable, using native");
            finish(m_url, QString());
        } else {
            qWarning("[update-mirror] native URL probe failed, probing mirrors");
            probe_mirror(0);
        }
    });
}

void UpdateMirrorResolver::probe_mirror(int index) {
    if (index >= m_mirrors.size()) {
        qWarning("[update-mirror] all mirrors unavailable, falling back to native URL");
        finish(m_url, QString());
        return;
    }
    const QString prefix = m_mirrors.at(index);
    get(prefix + m_url, kProbeTimeoutMs, [this, index, prefix](QNetworkReply* r) {
        const bool ok = r->error() == QNetworkReply::NoError
            && r->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt() == 200
            && looks_like_manifest(r->readAll(), m_manifest_key);
        if (ok) {
            qInfo("[update-mirror] mirror selected: %s", qPrintable(prefix));
            finish(prefix + m_url, prefix);
        } else {
            qWarning("[update-mirror] mirror probe failed: %s", qPrintable(prefix));
            probe_mirror(index + 1);
        }
    });
}
