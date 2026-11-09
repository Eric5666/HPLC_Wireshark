/// @file plugin_ipc_thread_probe.cpp
/// @brief PluginManager 跨线程 IPC 回归探针(H6)
/// @details 真实启动 bplc-plugin-host 子进程加载 Lua 示例插件(lua_echo / lua_graphics):
///   ① worker 线程连续 parse_via_plugin,GUI 线程空跑事件循环(readyRead 槽在跑);
///   ② worker 线程解析 lua-graphics 的同时,GUI 线程对同一连接反复发图形事件。
///   修复前 GUI 线程的 readyRead 会读走 ParseResponse(被丢弃 → worker 等满 5 s
///   → 插件被误禁用),worker 的 waitForReadyRead 也会读走 EventAck。
///   要求:全部请求拿到响应、插件不被禁用、无 timeout-disabled 状态。
///   bplc-plugin-host 须与探针同目录;可用 --host <path> 指定,探针会复制过来。
///   预期输出 `RESULT: ALL PASS (0 failures)`,exit 0。
#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QTemporaryDir>
#include <QThread>
#include <QTimer>
#include <atomic>
#include <functional>
#include <cstdio>

#include "plugin_manager.h"

static int g_fails = 0;
static void check(const char* name, bool ok) {
    std::printf("%-60s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) ++g_fails;
}

static bool copy_dir(const QString& src, const QString& dst) {
    QDir().mkpath(dst);
    for (const QString& f : QDir(src).entryList(QDir::Files))
        if (!QFile::copy(src + QLatin1Char('/') + f, dst + QLatin1Char('/') + f)) return false;
    return true;
}

static void spin_until(const std::function<bool()>& cond, int timeout_ms) {
    QElapsedTimer t;
    t.start();
    while (!cond() && t.elapsed() < timeout_ms) {
        QEventLoop loop;
        QTimer::singleShot(20, &loop, &QEventLoop::quit);
        loop.exec();
    }
}

/// worker 线程跑 n 次解析,统计拿到响应的次数
static int parse_in_worker(const QString& pid, int n, const std::function<void()>& gui_work,
                           int* gui_ok, int* gui_total) {
    std::atomic<int> ok{0};
    std::atomic<bool> done{false};
    QThread* th = QThread::create([&]() {
        for (int i = 0; i < n; ++i) {
            BplcFrame f;
            f.data = QByteArray::fromHex("3c000102") + QByteArray(20, char(i & 0xFF));
            f.arrival_us = 1000000 + i;
            MsduState msdu;
            ParseFilter filt{};
            ParseResult r;
            if (PluginManager::instance().parse_via_plugin(pid, f, msdu, filt, &r)) ++ok;
        }
        done = true;
    });
    th->start();
    *gui_ok = 0;
    *gui_total = 0;
    while (!done) {
        if (gui_work) gui_work();
        QEventLoop loop;
        QTimer::singleShot(1, &loop, &QEventLoop::quit);
        loop.exec();
    }
    th->wait();
    delete th;
    return ok;
}

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    // 宿主进程须与本程序同目录(PluginManager::hostBinaryPath)
    const QString host_dst = QCoreApplication::applicationDirPath() + QStringLiteral("/bplc-plugin-host");
    const int hi = QCoreApplication::arguments().indexOf(QStringLiteral("--host"));
    if (hi > 0 && hi + 1 < argc && !QFile::exists(host_dst))
        QFile::copy(QCoreApplication::arguments().at(hi + 1), host_dst);
    if (!QFile::exists(host_dst)) {
        std::printf("bplc-plugin-host not found next to the probe (use --host <path>)\n");
        return 2;
    }
    QTemporaryDir tmp;
    if (!tmp.isValid()) return 2;
    const QString ex = QStringLiteral(BPLC_REPO_DIR "/src/plugin/examples");
    const QString plugins = tmp.path() + QStringLiteral("/plugins");
    check("copy lua_echo/lua_graphics examples",
          copy_dir(ex + QStringLiteral("/lua_echo"), plugins + QStringLiteral("/lua_echo")) &&
              copy_dir(ex + QStringLiteral("/lua_graphics"), plugins + QStringLiteral("/lua_graphics")));

    QStringList bad_status;
    QObject::connect(&PluginManager::instance(), &PluginManager::plugin_status_changed,
                     [&](const QString& id, const QString& st) {
                         if (st != QStringLiteral("ready")) bad_status << id + QStringLiteral(": ") + st;
                     });
    auto& pm = PluginManager::instance();
    pm.loadAll(plugins);
    const QString echo = QStringLiteral("LUAECHO_2024");
    const QString gfx = QStringLiteral("LUAGRAPH_2024");
    spin_until([&] { return pm.is_plugin_protocol(echo) && pm.is_plugin_protocol(gfx); }, 15000);
    check("plugins handshaked (ready)", pm.is_plugin_protocol(echo) && pm.is_plugin_protocol(gfx));

    // ① worker 解析 + GUI 事件循环空跑
    const int n1 = 1500;
    int gok = 0, gtot = 0;
    QElapsedTimer t;
    t.start();
    const int ok1 = parse_in_worker(echo, n1, nullptr, &gok, &gtot);
    std::printf("  phase1: %d/%d parses answered in %lld ms\n", ok1, n1, (long long)t.elapsed());
    check("worker parses all answered while GUI loop runs", ok1 == n1);
    check("lua-echo still enabled", pm.is_plugin_protocol(echo));

    // ② 同一连接:worker 解析 + GUI 线程反复发图形事件(MousePress → 脚本返回 true)
    //   注:不用 request_render —— bplc-plugin-host 以 QCoreApplication 运行,脚本画文字
    //   需要 QGuiApplication,宿主会崩溃(既有问题,与 H6 无关,见修复说明)
    const int n2 = 3000;
    t.restart();
    const int ok2 = parse_in_worker(gfx, n2, [&]() {
        ++gtot;
        GraphicsEvent ev;
        ev.type = GraphicsEventType::MousePress;
        if (pm.send_graphics_event(gfx, ev)) ++gok;
    }, &gok, &gtot);
    std::printf("  phase2: %d/%d parses, %d/%d graphics events in %lld ms\n", ok2, n2, gok, gtot,
                (long long)t.elapsed());
    check("worker parses all answered during GUI requests", ok2 == n2);
    check("GUI graphics events all answered during worker parses", gtot > 0 && gok == gtot);
    check("lua-graphics still enabled", pm.is_plugin_protocol(gfx));
    for (const QString& s : bad_status) std::printf("  status: %s\n", qPrintable(s));
    check("no disabled/timeout status emitted", bad_status.isEmpty());

    // ③ stop_all 期间/之后的迟到请求立即失败返回(不挂起)
    pm.stop_all();
    t.restart();
    BplcFrame f;
    f.data = QByteArray::fromHex("3c000102");
    MsduState msdu;
    ParseFilter filt{};
    ParseResult r;
    check("parse after stop_all fails fast",
          !pm.parse_via_plugin(echo, f, msdu, filt, &r) && t.elapsed() < 1000);

    std::printf("\nRESULT: %s (%d failures)\n", g_fails ? "FAILURES" : "ALL PASS", g_fails);
    return g_fails ? 1 : 0;
}
