/// @file main.cpp
/// @brief 应用入口(Qt 6.11 在 win32 GUI app 会自动链接 libQt6EntryPoint)
/// @details libQt6EntryPoint 引用 qMain 符号。<QtGui/qwindowdefs.h> 中定义了
///          `#define main qMain`,所以这里写 `int main(...)` 会被预处理为 `qMain(...)`。
///          语言决定:QSettings "lang" = auto(默认,跟随系统)/zh/en。
#include "mainwindow.h"
#include "i18n.h"
#include "appconfig.h"
#include "theme.h"
#include "crash_handler.h"
#include "plugin_manager.h"
#include "plugin_market.h"
#include <QApplication>
#include <QCoreApplication>
#include <QDir>
#include <QLoggingCategory>
#include <QLocale>
#include <QStyleHints>
#include <QGuiApplication>
#include <QtGlobal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#ifdef _WIN32
#include <windows.h>  // OutputDebugStringW(消息钩子复刻 Qt 默认调试器输出)
#endif

#include "QsLog.h"
#include "QsLogDest.h"

// 隐藏自测钩子(仅 CI 崩溃可用性验证用,不对外文档):
// --self-crash-test 在崩溃处理器安装后,于本函数内触发确定性空指针崩溃,
// 使生成的 dump 能被符号化定位到 crash_selftest_trigger(main.cpp 行号),
// 证明发布包的崩溃 dump 是"可定位"的,而不只是结构有效。
//
// 注意:不能写成"局部 volatile int* p=nullptr; *p=..",
// -O2 能证明 p 为 null 并把这次解引用当 UB 整个删掉(2026-09-29 实测,
// 函数直接返回,进程不崩溃)。空指针必须经 volatile 全局做运行时 load,
// 编译器在编译期无法证明其为 null,不敢删除访存指令;
// 运行时该地址恒为 null,稳定触发 SIGSEGV。
#if defined(_MSC_VER)
#define CRASH_TEST_NOINLINE __declspec(noinline)
#else
#define CRASH_TEST_NOINLINE __attribute__((noinline))
#endif
static volatile void* volatile g_crash_test_addr = nullptr;
static CRASH_TEST_NOINLINE void crash_selftest_trigger() {
    *(volatile int*)g_crash_test_addr = 0xdead; // 必 SIGSEGV
}
static bool has_self_crash_flag(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i)
        if (std::strcmp(argv[i], "--self-crash-test") == 0)
            return true;
    return false;
}

// Qt 断言/致命错误钩子:Q_ASSERT(配合 QT_FORCE_ASSERTS)失败走 qFatal。
// Windows 下 qFatal 经 Qt 默认 handler 的 qAbort → RaiseFailFastException(不经 SIGABRT),
// 故 SIGABRT 钩子对 qFatal 无效 —— QtFatalMsg 分支必须自己落 dump 并 abort 收尾(恰好 1 份)。
// 非致命级别:有原 handler 则转交;无原 handler 时复刻 Qt 默认输出
// (stderr + Windows 调试器输出),不改变现有日志行为。
static QtMessageHandler g_prev_qt_handler = nullptr;

static void qt_message_handler(QtMsgType type, const QMessageLogContext& ctx,
                               const QString& msg) {
    if (type == QtFatalMsg) {
#ifdef _WIN32
        // Windows:落 dump(qFatal 走 qAbort/RaiseFailFastException,不经 SIGABRT;
        // SIGABRT 钩子对此路径无效,此处是唯一可靠来源)。
        // 防双份:不转交 Qt 默认 handler(否则再走 qAbort 的 FastFail),复位 SIG_DFL 后 abort;
        // 若后端 SIGABRT 钩子还会再落一份,先复位 SIG_DFL 保证恰好 1 份。
        CrashHandler::dump_without_crash();
        std::signal(SIGABRT, SIG_DFL);
        std::abort();
#else
        // Linux:dump 靠 crashpad 自带 SIGABRT 捕获(backend 不装应用层 SIGABRT 钩子)。
        // 不要复位 SIG_DFL(会顶掉 crashpad 的 SIGABRT handler 丢 dump);
        // 转交原 handler(qAbort→abort→SIGABRT) 或直接 abort,均走 crashpad 捕获。
        if (g_prev_qt_handler)
            g_prev_qt_handler(type, ctx, msg);
        else
            std::abort();
#endif
        return;
    }
    // 非致命:有原 handler 转交;无原 handler 时复刻 Qt 默认输出(stderr + 调试器输出)
    if (g_prev_qt_handler) {
        g_prev_qt_handler(type, ctx, msg);
    } else {
        const QString formatted = qFormatLogMessage(type, ctx, msg);
        std::fprintf(stderr, "%s\n", qPrintable(formatted));
#ifdef _WIN32
        // 复刻 Qt 默认 handler 的调试器输出(DebugView 可见)
        OutputDebugStringW(reinterpret_cast<const wchar_t*>(formatted.utf16()));
        OutputDebugStringW(L"\n");
#endif
    }
}

static void decide_language() {
    // config.ini [general] lang = auto(默认,跟随系统)/zh/en;不存在则先生成
    appcfg::ensure_default_file();
    const QString lang = appcfg::lang();
    bool en = false;
    if (lang == QLatin1String("en")) {
        en = true;
    } else if (lang == QLatin1String("zh")) {
        en = false;
    } else {  // auto:跟随系统(系统为中文 → 中文,否则英文)
        en = QLocale::system().language() != QLocale::Chinese;
    }
    trl::set_enabled(en);
}

/// @brief 初始化 QsLog:文件(轮转 5MB×3)+ 调试输出(OutputDebugString,DebugView 可见)
static void init_qslog() {
    using namespace QsLogging;
    Logger& logger = Logger::instance();
    logger.setLoggingLevel(DebugLevel);   // 开发期看 Debug;发布可按需降为 Info
    logger.setIncludeTimestamp(true);

    const QString log_dir =
        QCoreApplication::applicationDirPath() + QStringLiteral("/logs");
    QDir().mkpath(log_dir);
    const QString log_file = log_dir + QStringLiteral("/BPLC_STA_Monitor.log");
    logger.addDestination(DestinationFactory::MakeFileDestination(
        log_file, EnableLogRotation,
        MaxSizeBytes(5 * 1024 * 1024), MaxOldLogCount(3)));

    // 调试输出目的地(Windows 走 OutputDebugString,方便 DebugView 实时看)
    logger.addDestination(DestinationFactory::MakeDebugOutputDestination());
}

int main(int argc, char* argv[]) {
    QCoreApplication::setOrganizationName("ZbMonitor");
    QCoreApplication::setApplicationName("BPLC_STA_Monitor");
    QCoreApplication::setApplicationVersion("2.0.0");

    QApplication app(argc, argv);

    // 日志:QsLog 文件 + 调试输出(尽早初始化,崩溃处理器前后都可记日志)
    init_qslog();
    QLOG_INFO() << "BPLC_STA_Monitor start, version"
                << QCoreApplication::applicationVersion();

    // 崩溃捕获:与业务解耦,失败不影响启动。后端由 qmake CONFIG
    // (crash_sentry/crash_crashpad)决定编译进哪些,运行时按 config.ini [crash] 选择。
    {
        CrashHandler::Options co;
        co.backend = appcfg::crash_backend().toStdString();
        co.dsn = appcfg::crash_dsn().toStdString();
        co.database_path = appcfg::crash_db_path().toStdString();
        co.release = QCoreApplication::applicationVersion().toStdString();
        CrashHandler::install(co);
    }
    // Qt 消息钩子:QtFatalMsg 由 handler 直接落 dump 并 abort(不走 SIGABRT 钩子,
    // 见 qt_message_handler);需在 crash 后端激活后安装。
    g_prev_qt_handler = qInstallMessageHandler(qt_message_handler);

    // CI 崩溃可用性验证:确定性崩溃,便于符号化定位到 crash_selftest_trigger
    if (has_self_crash_flag(argc, argv))
        crash_selftest_trigger();

    decide_language();
    theme::apply(appcfg::theme());   // 主题(config.ini [general] theme,auto 默认)
    // 跟随系统:auto 模式下 Windows 深浅色切换时即时重应用主题
    QObject::connect(QGuiApplication::styleHints(), &QStyleHints::colorSchemeChanged,
                     [] { if (appcfg::theme() == QLatin1String("auto")) theme::apply(QStringLiteral("auto")); });

    MainWindow w;
    w.show();

    // 插件系统:扫描 plugins/ 并启动插件宿主进程(失败不影响主程序)
    PluginManager::instance().load_all(
        QCoreApplication::applicationDirPath() + QStringLiteral("/plugins"));
    // 退出时主动停掉全部 host 子进程,不留孤儿进程占着插件 DLL
    QObject::connect(&app, &QCoreApplication::aboutToQuit,
                     [] { PluginManager::instance().stop_all(); });

    // 命令行:
    //   --plugins-dir <dir>  主界面内置插件目录(进程内 JS/Lua 后端,展示功能界面)
    //   --replay <bin>       启动后自动回放抓包文件
    //   --plugin-autotest <shot_dir>  (需配合 --replay)回放结束后给各插件面板
    //                                及主窗口截图,保存到 shot_dir 后退出(自动化测试)
    QString plugins_dir;
    QString replay_bin;
    QString autotest_dir;
    for (int i = 1; i < argc; ++i) {
        const QString a = QString::fromLocal8Bit(argv[i]);
        if (a == QLatin1String("--plugins-dir") && i + 1 < argc)
            plugins_dir = QString::fromLocal8Bit(argv[++i]);
        else if (a == QLatin1String("--replay") && i + 1 < argc)
            replay_bin = QString::fromLocal8Bit(argv[++i]);
        else if (a == QLatin1String("--plugin-autotest") && i + 1 < argc)
            autotest_dir = QString::fromLocal8Bit(argv[++i]);
    }
    const QString default_plugins =
        QCoreApplication::applicationDirPath() + QStringLiteral("/plugins");
    if (plugins_dir.isEmpty() && QDir(default_plugins).exists())
        plugins_dir = default_plugins;
    // 插件搜索目录:命令行/默认目录 + 市场安装目录(用户自行安装的插件)
    // 两者现在都指向 <exe>/plugins(插件包总目录),去重避免重复加载
    QStringList plugin_dirs;
    if (!plugins_dir.isEmpty()) plugin_dirs << plugins_dir;
    plugin_dirs << PluginMarket::default_install_dir();
    plugin_dirs.removeDuplicates();
    if (autotest_dir.isEmpty() && replay_bin.isEmpty())
        w.load_plugin_dirs(plugin_dirs);  // 无回放:仅加载插件展示空面板
    if (!replay_bin.isEmpty() && autotest_dir.isEmpty())
        w.start_file_import(replay_bin);
    if (!replay_bin.isEmpty() && !autotest_dir.isEmpty())
        w.run_plugin_autotest(plugins_dir, replay_bin, autotest_dir);

    const int rc = app.exec();
    CrashHandler::shutdown();
    return rc;
}
