/// @file update_integrity.h
/// @brief 本地扩展:更新清单完整性辅助(sha256 格式、发布页回退 URL)
#ifndef BPLC_UPDATE_INTEGRITY_H
#define BPLC_UPDATE_INTEGRITY_H

#include <QRegularExpression>
#include <QString>

/// @brief 本地扩展:由安装包下载链接推出发布页(用于清单缺 sha256 时的手动下载回退)
/// @details 识别 github.com/<owner>/<repo>/releases/download/<tag>/<file>,
///          镜像代理前缀(如 https://proxy/https://github.com/...)同样适用;
///          推出 https://github.com/<owner>/<repo>/releases/tag/<tag>。识别不了返回空。
inline QString update_release_page_url(const QString& download_url) {
    static const QRegularExpression re(QStringLiteral(
        "github\\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/releases/download/([^/?#]+)/"));
    const QRegularExpressionMatch m = re.match(download_url);
    if (!m.hasMatch()) return {};
    return QStringLiteral("https://github.com/%1/%2/releases/tag/%3")
        .arg(m.captured(1), m.captured(2), m.captured(3));
}

/// @brief 本地扩展:清单是否给出了格式正确的安装包 sha256(64 位小写 hex)
inline bool update_sha256_is_valid(const QString& sha256) {
    static const QRegularExpression hexRe(QStringLiteral("^[0-9a-f]{64}$"));
    return hexRe.match(sha256).hasMatch();
}

#endif  // BPLC_UPDATE_INTEGRITY_H
