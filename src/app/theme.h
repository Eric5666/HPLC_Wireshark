/// @file theme.h
/// @brief 界面主题:深色(QDarkStyleSheet,见 qdarkstyle/ 目录,MIT)+ 浅色(内置)
/// @details 主题应用为全局 QApplication 样式表,切换即时生效。
///          主题值存 config.ini [general] theme = dark(默认)/light。
#ifndef BPLC_THEME_H
#define BPLC_THEME_H

#include <QString>

namespace theme {

/// @brief 解析 auto 应用的主题名("dark"/"light",按系统深浅色)
QString resolve_auto();

/// @brief 应用主题到整个应用
/// @param name "dark" / "light" / "auto"(跟随系统,见 resolve_auto)
void apply(const QString& name);

}  // namespace theme

#endif  // BPLC_THEME_H
