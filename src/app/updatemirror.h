/// @file updatemirror.h
/// @brief 更新下载加速解析:按出口 IP 区域决定清单/下载走原生 GitHub 还是镜像代理
/// @details 决策流程(单次检查内完成,结果仅本次有效):
///          - config general/mirror_mode=native → 原生地址;
///          - =proxy → 跳过区域识别,直接探活镜像列表;
///          - =auto(默认)→ 先识别出口 IP 国家(Cloudflare trace →
///            country.is → ipwho.is 三源依次兜底;原 ipapi.co 免费额度
///            按出口 IP 限流、实测常处于 RateLimited,已弃用):
///            中国(CN)走镜像探活;非中国走原生;识别失败则先探原生、
///            不通再探镜像。镜像按 config general/mirror_list 顺序逐个用
///            清单 URL 探活(须返回合法清单 JSON 才算可用),首个可用者生效,
///            其前缀同时用于后续安装包下载地址改写。
///          任何一步失败都回退原生地址,加速只会更好、不会比原行为更差。
///          诊断日志统一英文([update-mirror] 前缀)。
#ifndef BPLC_UPDATEMIRROR_H
#define BPLC_UPDATEMIRROR_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <functional>

class QNetworkAccessManager;
class QNetworkReply;

class UpdateMirrorResolver : public QObject {
    Q_OBJECT
public:
    explicit UpdateMirrorResolver(QObject* parent = nullptr);

    /// @brief 开始解析(异步);resolved() 恰好发出一次
    void resolve(const QString& updateUrl,
                 const QString& manifest_key = QStringLiteral("updates"));

signals:
    /// @brief 解析完成:effectiveUrl=实际清单地址;mirrorPrefix=命中的代理前缀(空=原生)
    void resolved(const QString& effectiveUrl, const QString& mirrorPrefix);

private:
    void get(const QString& url, int timeoutMs,
             const std::function<void(QNetworkReply*)>& done);
    void detect_region();
    void detect_from_source(int idx);   // 区域识别源链:0=trace,1=country.is,2=ipwho.is
    void on_region(const QString& countryCode);   // "" = 识别失败
    void probe_native();
    void probe_mirror(int index);
    void finish(const QString& effectiveUrl, const QString& prefix);
    static bool looks_like_manifest(const QByteArray& body,
                                  const QString& manifest_key);

    QNetworkAccessManager* m_nam = nullptr;
    QString     m_url;        ///< 原生清单地址
    QString     m_manifest_key; ///< 探活 JSON 必须含有的顶层键
    QStringList m_mirrors;    ///< 候选代理前缀(已规范化以 / 结尾)
    bool        m_done = false;
};

#endif  // BPLC_UPDATEMIRROR_H
