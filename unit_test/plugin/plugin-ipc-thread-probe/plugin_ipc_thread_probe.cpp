/// @file plugin_ipc_thread_probe.cpp
/// @brief PluginManager 跨线程 IPC 回归探针(H6)
/// @details 真实启动 bplc-plugin-host 子进程加载 Lua 示例插件(lua_echo / lua_graphics):
///   ① worker 线程连续 parse_via_plugin,GUI 线程空跑事件循环(readyRead 槽在跑);
///   ② worker 线程解析 lua-graphics 的同时,GUI 线程对同一连接反复发图形事件。
///   修复前 GUI 线程的 readyRead 会读走 ParseResponse(被丢弃 → worker 等满 5 s
///   → 插件被误禁用),worker 的 waitForReadyRead 也会读走 EventAck。
///   ③ GUI 延迟测量:2 个 worker × 5000 次解析(lua_echo),GUI 线程每 5 ms 对
///   lua_graphics 发一次图形事件,同时 1 ms PreciseTimer 记录 GUI 事件循环迟到量
///   (max / p99)与解析吞吐(parses/s)。另测一轮不带图形事件的纯解析负载。
///   结果同时以 `LATENCY ...` 机器可读行输出(--bench-json <path> 另存 JSON)。
///   ④ (异步图形 API,BPLC_PLUGIN_ASYNC_GRAPHICS)真实 PluginGraphicsView 异步渲染
///   (lua_gfx_nofont:去掉文字绘制的 lua_graphics,宿主是 QCoreApplication 画不了字);
///   host 卡死(SIGSTOP 2 s)期间 GUI 每 5 ms 发图形事件并反复要求重绘:GUI 1 ms 定时器
///   最大迟到须 < 20 ms、旧图保持、渲染请求合并(在途时只补发 1 次)、恢复后全部 ack;
///   SIGSTOP 5.6 s:异步请求 5 s 超时以失败回调、GUI 不卡、迟到 ack 被丢弃;
///   上下文对象销毁后回调不执行。
///   源码可在旧提交(无异步 API)上编译:图形请求回落到同步 API,④ 跳过;
///   --bench-only 只跑握手 + ③(三方对比用)。
///   要求:全部请求拿到响应、插件不被禁用、无 timeout-disabled 状态;
///   全程不得出现 Qt 跨线程告警("another thread"/"different thread")。
///   bplc-plugin-host 须与探针同目录;可用 --host <path> 指定,探针会复制过来。
///   预期输出 `RESULT: ALL PASS (0 failures)`,exit 0。
#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMutex>
#include <QMutexLocker>
#include <QProcess>
#include <QTemporaryDir>
#include <QThread>
#include <QTimer>
#include <algorithm>
#include <atomic>
#include <functional>
#include <cstdio>
#include <vector>
#ifdef Q_OS_UNIX
#include <signal.h>
#include <sys/types.h>
#include <time.h>
#endif

/// 当前线程已用 CPU 时间(ms);非 Unix 平台返回 -1
static double thread_cpu_ms() {
#ifdef Q_OS_UNIX
    timespec ts{};
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
#else
    return -1;
#endif
}

#include "plugin_manager.h"
#ifdef BPLC_PLUGIN_ASYNC_GRAPHICS
#include "plugin_graphics_view.h"
#endif

static int g_fails = 0;
static void check(const char* name, bool ok) {
    std::printf("%-60s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) ++g_fails;
}

// ---- Qt 跨线程告警捕获 ----
static QMutex g_msg_mutex;
static QStringList g_thread_warnings;
static QtMessageHandler g_prev_handler = nullptr;
static void probe_msg_handler(QtMsgType type, const QMessageLogContext& ctx, const QString& msg) {
    if (msg.contains(QLatin1String("another thread")) ||
        msg.contains(QLatin1String("different thread")) ||
        msg.contains(QLatin1String("wait_response called on the GUI thread"))) {
        QMutexLocker l(&g_msg_mutex);
        g_thread_warnings << msg;
    }
    if (g_prev_handler) g_prev_handler(type, ctx, msg);
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
    while (!done) {   // gui_work 内的计数经指针别名更新
        if (gui_work) gui_work();
        QEventLoop loop;
        QTimer::singleShot(1, &loop, &QEventLoop::quit);
        loop.exec();
    }
    th->wait();
    delete th;
    return ok;
}

struct LatencyStats {
    int parses_ok = 0, parses_total = 0;
    int gfx_ok = 0, gfx_total = 0;
    qint64 elapsed_ms = 0;
    double throughput = 0;     // parses/s
    double max_late_ms = 0, p99_late_ms = 0, p50_late_ms = 0;
    int ticks = 0;
    double gui_cpu_ms = 0;     // 测量期间 GUI 线程 CPU 时间
};

/// 2 个 worker × n 次解析;GUI 每 gfx_every_ms 发一次图形事件(0 = 不发);
/// 1 ms PreciseTimer 记录每次 tick 相对上次的迟到量(间隔 - 1 ms)
static LatencyStats measure_gui_latency(const QString& parse_pid, const QString& gfx_pid,
                                        int workers, int n, int gfx_every_ms) {
    auto& pm = PluginManager::instance();
    LatencyStats st;
    st.parses_total = workers * n;
    std::atomic<int> ok{0};
    std::atomic<int> done{0};
    std::vector<double> late;
    late.reserve(200000);
    QElapsedTimer clock;
    clock.start();
    qint64 last_ns = -1;
    QEventLoop loop;
    QTimer tick;
    tick.setTimerType(Qt::PreciseTimer);
    tick.setInterval(1);
    QObject::connect(&tick, &QTimer::timeout, [&]() {
        const qint64 now = clock.nsecsElapsed();
        if (last_ns >= 0) late.push_back(std::max(0.0, (now - last_ns) / 1e6 - 1.0));
        last_ns = now;
        if (done.load() == workers) loop.quit();
    });
    QTimer gfx;
    bool in_gfx = false;   // 旧设计里 GUI 等待跑嵌套事件循环,防止重入
    QObject gctx;          // 异步回调上下文
    int gfx_done = 0;
    if (gfx_every_ms > 0) {
        gfx.setInterval(gfx_every_ms);
        QObject::connect(&gfx, &QTimer::timeout, [&]() {
            if (in_gfx) return;
            in_gfx = true;
            GraphicsEvent ev;
            ev.type = GraphicsEventType::MousePress;
#ifdef BPLC_PLUGIN_ASYNC_GRAPHICS
            // 发后即返回,ack 异步回调
            if (pm.send_graphics_event_async(gfx_pid, ev, &gctx, [&](quint64, bool ok, bool) {
                    ++gfx_done;
                    if (ok) ++st.gfx_ok;
                }))
                ++st.gfx_total;
#else
            ++st.gfx_total;
            if (pm.send_graphics_event(gfx_pid, ev)) ++st.gfx_ok;
            ++gfx_done;
#endif
            in_gfx = false;
        });
    }
    QList<QThread*> ths;
    for (int w = 0; w < workers; ++w) {
        ths << QThread::create([&, w]() {
            for (int i = 0; i < n; ++i) {
                BplcFrame f;
                f.data = QByteArray::fromHex("3c000102") + QByteArray(20, char((i + w) & 0xFF));
                f.arrival_us = 1000000 + i;
                MsduState msdu;
                ParseFilter filt{};
                ParseResult r;
                if (pm.parse_via_plugin(parse_pid, f, msdu, filt, &r)) ++ok;
            }
            ++done;
        });
    }
    const double cpu0 = thread_cpu_ms();
    QElapsedTimer t;
    t.start();
    tick.start();
    if (gfx_every_ms > 0) gfx.start();
    for (QThread* th : ths) th->start();
    loop.exec();
    st.elapsed_ms = t.elapsed();
    st.gui_cpu_ms = thread_cpu_ms() - cpu0;
    tick.stop();
    gfx.stop();
    for (QThread* th : ths) { th->wait(); delete th; }
    spin_until([&] { return gfx_done >= st.gfx_total; }, 6000);   // 在途 ack 收尾(不计入测量)
    st.parses_ok = ok;
    st.throughput = st.elapsed_ms > 0 ? st.parses_ok * 1000.0 / st.elapsed_ms : 0;
    st.ticks = int(late.size());
    if (!late.empty()) {
        std::sort(late.begin(), late.end());
        st.max_late_ms = late.back();
        st.p99_late_ms = late[std::min(late.size() - 1, size_t(late.size() * 0.99))];
        st.p50_late_ms = late[late.size() / 2];
    }
    return st;
}

static QJsonObject stats_json(const LatencyStats& s) {
    QJsonObject o;
    o[QStringLiteral("parses_ok")] = s.parses_ok;
    o[QStringLiteral("parses_total")] = s.parses_total;
    o[QStringLiteral("gfx_ok")] = s.gfx_ok;
    o[QStringLiteral("gfx_total")] = s.gfx_total;
    o[QStringLiteral("elapsed_ms")] = double(s.elapsed_ms);
    o[QStringLiteral("parses_per_s")] = s.throughput;
    o[QStringLiteral("gui_late_max_ms")] = s.max_late_ms;
    o[QStringLiteral("gui_late_p99_ms")] = s.p99_late_ms;
    o[QStringLiteral("gui_late_p50_ms")] = s.p50_late_ms;
    o[QStringLiteral("ticks")] = s.ticks;
    o[QStringLiteral("gui_cpu_ms")] = s.gui_cpu_ms;
    return o;
}

static void print_stats(const char* tag, const LatencyStats& s) {
    std::printf("  LATENCY %s: parses %d/%d in %lld ms = %.0f parses/s; gfx %d/%d; "
                "GUI 1ms-timer lateness max=%.2f ms p99=%.2f ms p50=%.3f ms (%d ticks); GUI thread CPU %.0f ms\n",
                tag, s.parses_ok, s.parses_total, (long long)s.elapsed_ms, s.throughput,
                s.gfx_ok, s.gfx_total, s.max_late_ms, s.p99_late_ms, s.p50_late_ms, s.ticks, s.gui_cpu_ms);
}

/// 生成 lua_gfx_nofont:lua_graphics 去掉 set_font/draw_text,换协议 id,用于 SIGSTOP/合并等
/// 渲染往返用例(历史原因:宿主曾是 QCoreApplication,画字会崩;现已改 QGuiApplication,
/// 画字由 "text render" 用例单独覆盖)
static bool make_nofont_plugin(const QString& src, const QString& dst) {
    if (!copy_dir(src, dst)) return false;
    auto patch = [](const QString& path, const std::function<QByteArray(QByteArray)>& fn) {
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) return false;
        const QByteArray d = fn(f.readAll());
        f.close();
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
        return f.write(d) == d.size();
    };
    const bool a = patch(dst + QStringLiteral("/plugin.json"), [](QByteArray d) {
        return d.replace("LUAGRAPH_2024", "LUAGFXNF_2024").replace("\"lua-graphics\"", "\"lua-gfx-nofont\"");
    });
    const bool b = patch(dst + QStringLiteral("/graphics.lua"), [](QByteArray d) {
        QList<QByteArray> out;
        for (const QByteArray& line : d.split('\n'))
            if (!line.contains("set_font") && !line.contains("draw_text")) out << line;
        return out.join('\n').replace("LUAGRAPH_2024", "LUAGFXNF_2024");
    });
    return a && b;
}

#if defined(BPLC_PLUGIN_ASYNC_GRAPHICS) && defined(Q_OS_UNIX)
/// 找到加载 plugin_dir_tag 的 host 进程 pid(pgrep -f)
static qint64 host_pid(const QString& plugin_dir_tag) {
    QProcess pg;
    pg.start(QStringLiteral("pgrep"), {QStringLiteral("-f"),
                                       QStringLiteral("bplc-plugin-host.*") + plugin_dir_tag});
    pg.waitForFinished(3000);
    const QList<QByteArray> ls = pg.readAllStandardOutput().trimmed().split('\n');
    return ls.isEmpty() ? -1 : ls.first().toLongLong();
}
#endif

/// GUI 1 ms PreciseTimer 迟到量记录器(stall 测试用)
struct LateMeter {
    QElapsedTimer clock;
    qint64 last_ns = -1;
    double max_late = 0;
    int ticks = 0;
    QTimer tick;
    LateMeter() {
        tick.setTimerType(Qt::PreciseTimer);
        tick.setInterval(1);
        QObject::connect(&tick, &QTimer::timeout, [this]() {
            const qint64 now = clock.nsecsElapsed();
            if (last_ns >= 0) max_late = std::max(max_late, (now - last_ns) / 1e6 - 1.0);
            last_ns = now;
            ++ticks;
        });
    }
    void start() { clock.start(); last_ns = -1; max_late = 0; ticks = 0; tick.start(); }
    void stop() { tick.stop(); }
};

int main(int argc, char** argv) {
    g_prev_handler = qInstallMessageHandler(probe_msg_handler);
    QApplication app(argc, argv);
    // 宿主进程须与本程序同目录(PluginManager::host_binary_path)
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
    check("copy lua_echo/lua_graphics examples (+ lua_gfx_nofont)",
          copy_dir(ex + QStringLiteral("/lua_echo"), plugins + QStringLiteral("/lua_echo")) &&
              copy_dir(ex + QStringLiteral("/lua_graphics"), plugins + QStringLiteral("/lua_graphics")) &&
              make_nofont_plugin(ex + QStringLiteral("/lua_graphics"),
                                 plugins + QStringLiteral("/lua_gfx_nofont")));
    const bool bench_only = QCoreApplication::arguments().contains(QStringLiteral("--bench-only"));

    QStringList bad_status;
    QObject::connect(&PluginManager::instance(), &PluginManager::plugin_status_changed,
                     [&](const QString& id, const QString& st) {
                         if (st != QStringLiteral("ready")) bad_status << id + QStringLiteral(": ") + st;
                     });
    auto& pm = PluginManager::instance();
    pm.load_all(plugins);
    const QString echo = QStringLiteral("LUAECHO_2024");
    const QString gfx = QStringLiteral("LUAGRAPH_2024");
    const QString gnf = QStringLiteral("LUAGFXNF_2024");
    spin_until([&] { return pm.is_plugin_protocol(echo) && pm.is_plugin_protocol(gfx) &&
                            pm.is_plugin_protocol(gnf); }, 15000);
    check("plugins handshaked (ready)", pm.is_plugin_protocol(echo) && pm.is_plugin_protocol(gfx) &&
                                            pm.is_plugin_protocol(gnf));
    QElapsedTimer t;
    if (bench_only) goto bench;

    {
    // ① worker 解析 + GUI 事件循环空跑
    const int n1 = 1500;
    int gok = 0, gtot = 0;
    t.start();
    const int ok1 = parse_in_worker(echo, n1, nullptr, &gok, &gtot);
    std::printf("  phase1: %d/%d parses answered in %lld ms\n", ok1, n1, (long long)t.elapsed());
    check("worker parses all answered while GUI loop runs", ok1 == n1);
    check("lua-echo still enabled", pm.is_plugin_protocol(echo));

    // ② 同一连接:worker 解析 + GUI 线程反复发图形事件(MousePress → 脚本返回 true)
    //   注:不用 request_render(渲染另见 ④;本段只测事件往返)
    const int n2 = 3000;
    t.restart();
#ifdef BPLC_PLUGIN_ASYNC_GRAPHICS
    int gdone = 0;
    QObject gctx;
    const int ok2 = parse_in_worker(gfx, n2, [&]() {
        GraphicsEvent ev;
        ev.type = GraphicsEventType::MousePress;
        if (pm.send_graphics_event_async(gfx, ev, &gctx, [&](quint64, bool ok, bool) {
                ++gdone;
                if (ok) ++gok;
            }))
            ++gtot;
    }, &gok, &gtot);
    spin_until([&] { return gdone == gtot; }, 6000);   // 收尾:剩余 ack 异步到达
#else
    const int ok2 = parse_in_worker(gfx, n2, [&]() {
        ++gtot;
        GraphicsEvent ev;
        ev.type = GraphicsEventType::MousePress;
        if (pm.send_graphics_event(gfx, ev)) ++gok;
    }, &gok, &gtot);
#endif
    std::printf("  phase2: %d/%d parses, %d/%d graphics events in %lld ms\n", ok2, n2, gok, gtot,
                (long long)t.elapsed());
    check("worker parses all answered during GUI requests", ok2 == n2);
    check("GUI graphics events all answered during worker parses", gtot > 0 && gok == gtot);
    check("lua-graphics still enabled", pm.is_plugin_protocol(gfx));
    for (const QString& s : bad_status) std::printf("  status: %s\n", qPrintable(s));
    check("no disabled/timeout status emitted", bad_status.isEmpty());
    }

bench:
    {
    // ③ GUI 延迟 / 吞吐测量(2 worker × 5000,lua_echo)
    const int lw = 2, ln = 5000;
    const LatencyStats ls0 = measure_gui_latency(echo, gfx, lw, ln, 0);
    print_stats("parse-only", ls0);
    const LatencyStats ls1 = measure_gui_latency(echo, gfx, lw, ln, 5);
    print_stats("parse+gfx", ls1);
    check("latency run (parse-only): all parses answered", ls0.parses_ok == ls0.parses_total);
    check("latency run (parse+gfx): all parses answered", ls1.parses_ok == ls1.parses_total);
    check("latency run (parse+gfx): all graphics events answered",
          ls1.gfx_total > 0 && ls1.gfx_ok == ls1.gfx_total);
    check("plugins still enabled after latency runs",
          pm.is_plugin_protocol(echo) && pm.is_plugin_protocol(gfx));
    const int ji = QCoreApplication::arguments().indexOf(QStringLiteral("--bench-json"));
    if (ji > 0 && ji + 1 < argc) {
        QJsonObject o;
        o[QStringLiteral("parse_only")] = stats_json(ls0);
        o[QStringLiteral("parse_gfx")] = stats_json(ls1);
        QFile jf(QCoreApplication::arguments().at(ji + 1));
        if (jf.open(QIODevice::WriteOnly)) jf.write(QJsonDocument(o).toJson());
    }
    }
    if (bench_only) {
        pm.stop_all();
        std::printf("\nRESULT: %s (%d failures)\n", g_fails ? "FAILURES" : "ALL PASS", g_fails);
        return g_fails ? 1 : 0;
    }

#if defined(BPLC_PLUGIN_ASYNC_GRAPHICS) && defined(Q_OS_UNIX)
    // ④ 异步图形:真实视图渲染、host 卡死期间 GUI 不阻塞、合并、超时、上下文销毁
    {
        bad_status.clear();
        PluginGraphicsView view(&pm, gnf);
        view.resize(320, 240);
        view.show();
        spin_until([&] { return view.renders_applied() >= 1; }, 5000);
        std::printf("  render: applied %llu, image %dx%d\n", (unsigned long long)view.renders_applied(),
                    view.image().width(), view.image().height());
        check("async render: view received image", view.renders_applied() >= 1 &&
                  view.image().size() == QSize(320, 240));
        // 画文字:原版 lua_graphics(set_font/draw_text)经真实 host 渲染。
        // host 改为 QGuiApplication(offscreen)前,这里 host 进程崩溃、无图像
        {
            PluginGraphicsView tview(&pm, gfx);
            tview.resize(320, 240);
            tview.show();
            spin_until([&] { return tview.renders_applied() >= 1; }, 5000);
            check("text render: lua_graphics with set_font/draw_text rendered by host",
                  tview.renders_applied() >= 1 && tview.image().size() == QSize(320, 240));
            check("text render: host still running, plugin still enabled",
                  pm.is_plugin_protocol(gfx) && host_pid(QStringLiteral("lua_graphics")) > 0);
        }
        // 合并:无卡顿时,连续 5 次重绘要求(间隔 > 50 ms 节流)各发 1 次
        const qint64 hp = host_pid(QStringLiteral("lua_gfx_nofont"));
        check("found lua_gfx_nofont host pid", hp > 0);

        // ④a host SIGSTOP 2 s:GUI 每 5 ms 发图形事件 + 每 60 ms 要求重绘
        const QImage before = view.image();
        const quint64 sent0 = view.renders_sent(), applied0 = view.renders_applied();
        int ev_sent = 0, ev_done = 0, ev_ok = 0;
        QTimer evt;
        evt.setInterval(5);
        QObject::connect(&evt, &QTimer::timeout, [&]() {
            GraphicsEvent ev;
            ev.type = GraphicsEventType::MouseMove;
            if (pm.send_graphics_event_async(gnf, ev, &view, [&](quint64, bool ok, bool) {
                    ++ev_done;
                    if (ok) ++ev_ok;
                }))
                ++ev_sent;
        });
        QTimer redraw;
        redraw.setInterval(60);
        QObject::connect(&redraw, &QTimer::timeout, [&]() { view.on_plugin_request_redraw(); });
        LateMeter lm;
        ::kill(pid_t(hp), SIGSTOP);
        QElapsedTimer st;
        st.start();
        lm.start();
        evt.start();
        redraw.start();
        spin_until([&] { return st.elapsed() >= 2000; }, 2500);
        const double stall_late = lm.max_late;   // 计到恢复前(含下方 100 ms)
        const int stall_ticks = lm.ticks;
        const quint64 sent_during = view.renders_sent() - sent0;
        const bool kept_image = view.image().cacheKey() == before.cacheKey();
        redraw.stop();
        evt.stop();
        spin_until([] { return false; }, 100);   // 让已排上的 50 ms 节流定时器在卡死期间触发
        const quint64 sent_stalled = view.renders_sent() - sent0;
        ::kill(pid_t(hp), SIGCONT);
        spin_until([&] { return ev_done == ev_sent && !view.render_in_flight() &&
                                pm.pending_async_requests() == 0; }, 5000);
        spin_until([] { return false; }, 200);   // 合并补发的那次渲染回来
        lm.stop();
        std::printf("  stall 2s: GUI 1ms-timer max lateness %.2f ms (%d ticks); events %d sent, %d acked "
                    "after resume; renders sent during stall %llu (redraw asked ~33x), total renders %llu, "
                    "applied %llu\n",
                    stall_late, stall_ticks, ev_sent, ev_ok, (unsigned long long)sent_during,
                    (unsigned long long)(view.renders_sent() - sent0),
                    (unsigned long long)(view.renders_applied() - applied0));
        check("stall 2s: GUI max lateness < 20 ms", stall_late < 20.0 && stall_ticks > 1000);
        check("stall 2s: last good image kept while host stalled", kept_image && !before.isNull());
        check("stall 2s: renders coalesced (<= 1 in flight while stalled)",
              sent_during <= 1 && sent_stalled <= 1);
        check("stall 2s: all events acked after resume", ev_sent > 300 && ev_ok == ev_sent);
        check("stall 2s: coalesced follow-up render applied",
              view.renders_sent() - sent0 == 2 && view.renders_applied() - applied0 == 2);

        // ④b host SIGSTOP 5.6 s:异步请求 5 s 超时 → 失败回调;GUI 不卡;迟到 ack 丢弃
        bool to_done = false, to_ok = true;
        qint64 to_ms = -1;
        QElapsedTimer tt;
        lm.start();
        ::kill(pid_t(hp), SIGSTOP);
        tt.start();
        GraphicsEvent ev;
        ev.type = GraphicsEventType::MousePress;
        const quint64 tseq = pm.send_graphics_event_async(gnf, ev, &view, [&](quint64, bool ok, bool) {
            to_done = true;
            to_ok = ok;
            to_ms = tt.elapsed();
        });
        // 上下文在回调前销毁:回调不得执行
        bool dead_cb = false;
        {
            QObject tmp_ctx;
            pm.send_graphics_event_async(gnf, ev, &tmp_ctx, [&](quint64, bool, bool) { dead_cb = true; });
        }
        spin_until([&] { return tt.elapsed() >= 5600; }, 6000);
        const double to_late = lm.max_late;
        ::kill(pid_t(hp), SIGCONT);
        spin_until([] { return false; }, 300);   // 迟到 ack 到达(须被丢弃)
        lm.stop();
        std::printf("  stall 5.6s: seq %llu callback ok=%d after %lld ms; GUI max lateness %.2f ms; "
                    "pending after resume %d\n",
                    (unsigned long long)tseq, int(to_ok), (long long)to_ms, to_late,
                    pm.pending_async_requests());
        check("timeout: async request fails after ~5 s (not before)",
              tseq > 0 && to_done && !to_ok && to_ms >= 4900 && to_ms < 5600);
        check("timeout: GUI max lateness < 20 ms", to_late < 20.0);
        check("timeout: callback skipped for destroyed context", !dead_cb);
        check("timeout: late ack dropped, nothing pending", pm.pending_async_requests() == 0);
        int ok_after = -1;
        pm.send_graphics_event_async(gnf, ev, &view, [&](quint64, bool ok, bool) { ok_after = ok; });
        spin_until([&] { return ok_after >= 0; }, 2000);
        check("timeout: plugin still usable afterwards", ok_after == 1 && pm.is_plugin_protocol(gnf));
        for (const QString& s2 : bad_status) std::printf("  status: %s\n", qPrintable(s2));
        check("stall: no disabled/timeout status emitted", bad_status.isEmpty());
    }
#endif

#ifdef Q_OS_UNIX
    // ③b host 崩溃:worker 解析途中 SIGKILL lua_echo 的 host,断线须立即唤醒
    //    等待方(不等满 5 s),并在 GUI 线程上报 disabled 状态
    {
        QStringList st_after_kill;
        auto c = QObject::connect(&pm, &PluginManager::plugin_status_changed,
                                  [&](const QString& id, const QString& st) {
                                      if (id == echo) st_after_kill << st;
                                  });
        std::atomic<qint64> max_call_ms{0};
        std::atomic<bool> stop{false};
        QThread* th = QThread::create([&]() {
            while (!stop) {
                BplcFrame fr;
                fr.data = QByteArray::fromHex("3c000102");
                MsduState ms;
                ParseFilter fl{};
                ParseResult rr;
                QElapsedTimer ct;
                ct.start();
                const bool ok = pm.parse_via_plugin(echo, fr, ms, fl, &rr);
                max_call_ms = std::max<qint64>(max_call_ms, ct.elapsed());
                if (!ok && !pm.is_plugin_protocol(echo)) break;
            }
        });
        th->start();
        spin_until([] { return false; }, 100);
        QProcess::execute(QStringLiteral("pkill"),
                          {QStringLiteral("-KILL"), QStringLiteral("-f"),
                           QStringLiteral("bplc-plugin-host.*lua_echo")});
        spin_until([&] { return th->isFinished(); }, 7000);
        stop = true;
        th->wait();
        delete th;
        spin_until([&] { return !st_after_kill.isEmpty(); }, 2000);
        QObject::disconnect(c);
        std::printf("  host kill: longest in-flight parse %lld ms, status: %s\n",
                    (long long)max_call_ms.load(), qPrintable(st_after_kill.join(QStringLiteral(" | "))));
        check("host kill: in-flight parse returns < 1 s", max_call_ms.load() < 1000);
        check("host kill: plugin disabled, status reported on GUI",
              !pm.is_plugin_protocol(echo) && !st_after_kill.isEmpty() &&
              st_after_kill.first().startsWith(QStringLiteral("disabled")));
    }
#endif

    // ④ stop_all 期间/之后的迟到请求立即失败返回(不挂起)
    pm.stop_all();
    t.restart();
    BplcFrame f;
    f.data = QByteArray::fromHex("3c000102");
    MsduState msdu;
    ParseFilter filt{};
    ParseResult r;
    check("parse after stop_all fails fast",
          !pm.parse_via_plugin(echo, f, msdu, filt, &r) && t.elapsed() < 1000);

    // ⑤ stop_all 后重新加载(插件市场更新流程):IPC 通道可再次使用
    pm.load_all(plugins);
    spin_until([&] { return pm.is_plugin_protocol(echo); }, 15000);
    int gok5 = 0, gtot5 = 0;
    const int ok5 = pm.is_plugin_protocol(echo) ? parse_in_worker(echo, 200, nullptr, &gok5, &gtot5) : 0;
    check("reload after stop_all: parses answered", ok5 == 200);

    // ⑥ 走应用正常退出路径(aboutToQuit → 停插件、关 socket、停 IPC 线程),
    //    期间的 Qt 告警同样计入
    QTimer::singleShot(0, &app, &QCoreApplication::quit);
    app.exec();
    pm.stop_all();
    check("parse after app quit fails fast", !pm.parse_via_plugin(echo, f, msdu, filt, &r));

    {
        QMutexLocker l(&g_msg_mutex);
        for (const QString& w : g_thread_warnings) std::printf("  qt warning: %s\n", qPrintable(w));
        check("no Qt cross-thread warnings (another/different thread)", g_thread_warnings.isEmpty());
    }

    std::printf("\nRESULT: %s (%d failures)\n", g_fails ? "FAILURES" : "ALL PASS", g_fails);
    return g_fails ? 1 : 0;
}
