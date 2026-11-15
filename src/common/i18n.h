/// @file i18n.h
/// @brief 轻量中文/英文运行时翻译(免 .ts/.qm 工具链)
/// @details 源语言为中文(代码直写),显示前经 trl::L() 查英文表:
///          - zh:未启用英文时原样返回;
///          - en:命中内置/注册表返回英文,未命中回退中文(便于漏翻发现)。
///          语言由 main() 在启动时按系统语言 + QSettings("lang") 决定,
///          亦可运行中切换(动态文本立即生效,窗口 chrome 下一启动生效)。
#ifndef BPLC_I18N_H
#define BPLC_I18N_H

#include <QString>
#include <QHash>

namespace trl {

/// @brief 启用英文显示(默认 false = 中文)
void set_enabled(bool enabled);

/// @brief 当前是否为英文显示
bool enabled();

/// @brief 中文 → 英文翻译注册(文件级字典在匿名命名空间一次性注册)
void register_en(const char* zh, const char* en);

/// @brief 翻译入口:中文原文 → 英文(未启用或未命中时返回中文原文)
QString L(const char* zh);
inline QString L(const QString& zh) { return L(zh.toUtf8().constData()); }

}  // namespace trl

#endif  // BPLC_I18N_H
