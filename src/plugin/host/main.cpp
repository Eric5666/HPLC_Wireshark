/// @file main.cpp
/// @brief bplc-plugin-host 入口:用法 bplc-plugin-host --socket <name> --plugin <dir>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QGuiApplication>
#include <QTextStream>

#include "plugin_host.h"

int main(int argc, char* argv[]) {
    // 图形插件在宿主内用 QPainter 画文字/图标(QFont、QPixmap 需要 GUI 应用);
    // 宿主没有窗口,未指定平台时用 offscreen,不依赖显示服务器。
    // ';' 后为回退平台:发行包里没有 offscreen 插件时(如 windeployqt 只带
    // qwindows)仍能启动
    if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM")) {
#if defined(Q_OS_WIN)
        qputenv("QT_QPA_PLATFORM", "offscreen;windows");
#elif defined(Q_OS_MACOS)
        qputenv("QT_QPA_PLATFORM", "offscreen;cocoa");
#else
        qputenv("QT_QPA_PLATFORM", "offscreen;xcb;wayland");
#endif
    }
    // QGuiApplication 会吃掉它认识的命令行参数,其中 -plugin/--plugin 是 Qt 的
    // “通用输入插件”选项 —— 会把我们的 --plugin <dir> 拿走。先用临时
    // QCoreApplication 取完整参数(Windows 下为 Unicode 命令行),GUI 应用只给 argv[0]
    QStringList args;
    {
        QCoreApplication args_app(argc, argv);
        args = QCoreApplication::arguments();
    }
    static int gui_argc = 1;
    QGuiApplication app(gui_argc, argv);

    QCommandLineParser cli;
    cli.setApplicationDescription(QStringLiteral("BPLC plugin host process"));
    cli.addHelpOption();
    QCommandLineOption socket_opt(QStringList{QStringLiteral("socket")},
        QStringLiteral("local socket name"), QStringLiteral("name"));
    QCommandLineOption plugin_opt(QStringList{QStringLiteral("plugin")},
        QStringLiteral("plugin directory"), QStringLiteral("dir"));
    cli.addOption(socket_opt);
    cli.addOption(plugin_opt);
    cli.process(args);

    const QString socket_name = cli.value(socket_opt);
    const QString plugin_dir  = cli.value(plugin_opt);
    if (socket_name.isEmpty() || plugin_dir.isEmpty()) {
        QTextStream(stderr) << "usage: bplc-plugin-host --socket <name> --plugin <dir>\n";
        return 1;
    }

    PluginHost host(socket_name, plugin_dir);
    QString err;
    if (!host.start(&err)) {
        QTextStream(stderr) << "plugin-host start failed: " << err << "\n";
        return 2;
    }
    return host.exec();
}
