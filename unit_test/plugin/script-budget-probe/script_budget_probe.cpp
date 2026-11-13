/// @file script_budget_probe.cpp
/// @brief M10 回归探针:脚本插件死循环在有限时间内被打断,之后插件仍可用
///  - Lua:count hook 指令预算(parse 内 while true、pcall 包裹的死循环、
///    入口脚本顶层死循环)
///  - JS :看门狗 setInterrupted(parse 内 for(;;)),打断后中断标志复位
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QGuiApplication>
#include <QTemporaryDir>
#include <cstdio>

#include "js_backend.h"
#include "lua_backend.h"

static int g_fails = 0;
static void check(const char* name, bool ok) {
    std::printf("%-64s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) ++g_fails;
}

static bool write_file(const QString& path, const QByteArray& data) {
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    return f.write(data) == data.size();
}

static QString make_plugin(const QString& root, const QString& name,
                           const char* runtime, const char* entry,
                           const QByteArray& code) {
    const QString dir = root + QLatin1Char('/') + name;
    QDir().mkpath(dir);
    write_file(dir + QLatin1Char('/') + QLatin1String(entry), code);
    write_file(dir + QStringLiteral("/plugin.json"),
               QStringLiteral(R"({"name":"%1","version":"1.0.0","runtime":"%2",)"
                              R"("entry":"%3","api_version":1,"protocol_id":"LOOP"})")
                   .arg(name, QLatin1String(runtime), QLatin1String(entry))
                   .toUtf8());
    return dir;
}

/// @brief data[0] 选择脚本分支:0=正常返回,1=死循环,2=pcall 包裹的死循环,
///        3=pcall + 协程里的死循环
static ParseResult call_parse(IPluginBackend& b, quint8 mode, QString* err,
                              qint64* ms) {
    BplcFrame f;
    f.data = QByteArray(1, char(mode));
    MsduState st;
    ParseFilter filter;
    QElapsedTimer t;
    t.start();
    err->clear();
    ParseResult r = b.parse(f, st, filter, err);
    *ms = t.elapsed();
    return r;
}

static const char* kLuaLoop = R"LUA(
function get_info() return {protocolId = "LOOP", displayName = "loop"} end
function parse(frame)
  local m = frame.data[1]
  if m == 1 then while true do end end
  if m == 2 then
    while true do pcall(function() while true do end end) end
  end
  if m == 3 then
    while true do pcall(coroutine.wrap(function() while true do end end)) end
  end
  -- 4/5:结果表带死循环 __index/__len。宿主若用 lua_getfield/luaL_len 读结果,
  -- 元方法在 pcall 外跑到指令预算上限 → Lua panic → SIGABRT(回归用例)
  local spin = function() while true do end end
  if m == 4 then return setmetatable({}, {__index = spin}) end
  if m == 5 then
    return {accept = true,
            mpdu = setmetatable({}, {__index = spin}),
            fields = setmetatable({}, {__index = spin, __len = spin})}
  end
  return {accept = false, rejectReason = "alive"}
end
)LUA";

static void test_lua(const QString& root) {
    const PluginManifest m = read_plugin_manifest(
        make_plugin(root, QStringLiteral("lua-loop"), "lua", "main.lua", kLuaLoop));
    check("lua: manifest valid", m.valid);
    LuaBackend b;
    QString err;
    check("lua: initialize", b.initialize(m, &err));
    qint64 ms = 0;
    ParseResult r = call_parse(b, 1, &err, &ms);
    std::printf("  while-true stopped after %lld ms: %s\n", ms, qPrintable(err));
    check("lua: while true do end stopped by instruction budget",
          !r.accept && err.contains(QStringLiteral("instruction budget")) && ms < 30000);
    r = call_parse(b, 2, &err, &ms);
    std::printf("  pcall-wrapped loop stopped after %lld ms: %s\n", ms, qPrintable(err));
    check("lua: pcall-wrapped loop cannot swallow the budget error",
          !r.accept && err.contains(QStringLiteral("instruction budget")) && ms < 30000);
    r = call_parse(b, 3, &err, &ms);
    std::printf("  pcall+coroutine loop stopped after %lld ms: %s\n", ms, qPrintable(err));
    check("lua: loop inside coroutine under pcall stopped",
          !r.accept && err.contains(QStringLiteral("instruction budget")) && ms < 30000);
    r = call_parse(b, 0, &err, &ms);
    check("lua: plugin still usable after overrun (budget reset per call)",
          r.reject_reason == QStringLiteral("alive") && err.isEmpty());
    // 结果表 __index 死循环:宿主只做 raw 读取,不触发元方法,不再 panic/abort
    r = call_parse(b, 4, &err, &ms);
    std::printf("  __index-loop result read in %lld ms: accept=%d reason=%s\n", ms, int(r.accept),
                qPrintable(r.reject_reason));
    check("lua: result table __index loop does not abort host (raw reads)",
          !r.accept && r.reject_reason == QStringLiteral("rejected by plugin") && ms < 30000);
    r = call_parse(b, 5, &err, &ms);
    check("lua: nested mpdu/fields __index/__len loops ignored (raw reads)",
          r.accept && err.isEmpty() && r.msdu.tree.isEmpty() && ms < 30000);
    r = call_parse(b, 0, &err, &ms);
    check("lua: plugin still usable after metamethod-trap results",
          r.reject_reason == QStringLiteral("alive") && err.isEmpty());
    // get_info() 返回带死循环 __index 的代理表:初始化失败而非 abort
    const PluginManifest m3 = read_plugin_manifest(make_plugin(
        root, QStringLiteral("lua-info-trap"), "lua", "main.lua",
        "function get_info() return setmetatable({}, {__index = function() while true do end end}) end\n"
        "function parse(f) return {accept=false} end\n"));
    LuaBackend b3;
    const bool ok3 = b3.initialize(m3, &err);
    check("lua: get_info() __index loop fails init instead of aborting",
          !ok3 && err.contains(QStringLiteral("protocolId")));

    const PluginManifest m2 = read_plugin_manifest(make_plugin(
        root, QStringLiteral("lua-toplevel"), "lua", "main.lua",
        "while true do end\nfunction get_info() return {protocolId='LOOP'} end\n"));
    LuaBackend b2;
    QElapsedTimer t;
    t.start();
    const bool ok2 = b2.initialize(m2, &err);
    check("lua: top-level loop in entry script stopped at load",
          !ok2 && err.contains(QStringLiteral("instruction budget")) && t.elapsed() < 30000);
}

static const char* kJsLoop = R"JS(
function get_info() { return { protocolId: "LOOP", displayName: "loop" }; }
function parse(frame) {
  if (frame.data[0] === 1) { for (;;) {} }
  return { accept: false, rejectReason: "alive" };
}
)JS";

static void test_js(const QString& root) {
    const PluginManifest m = read_plugin_manifest(
        make_plugin(root, QStringLiteral("js-loop"), "js", "main.js", kJsLoop));
    check("js: manifest valid", m.valid);
    JsBackend b;
    QString err;
    check("js: initialize", b.initialize(m, &err));
    qint64 ms = 0;
    ParseResult r = call_parse(b, 1, &err, &ms);
    std::printf("  for(;;) stopped after %lld ms: %s\n", ms, qPrintable(err));
    check("js: for(;;){} stopped by watchdog",
          !r.accept && err.contains(QStringLiteral("time limit")) && ms < 30000);
    r = call_parse(b, 0, &err, &ms);
    check("js: plugin still usable after interrupt (flag reset)",
          r.reject_reason == QStringLiteral("alive") && err.isEmpty());
    for (int i = 0; i < 200; ++i) call_parse(b, 0, &err, &ms);
    check("js: 200 quick calls, none falsely interrupted", err.isEmpty());

    const PluginManifest m2 = read_plugin_manifest(make_plugin(
        root, QStringLiteral("js-toplevel"), "js", "main.js",
        "for (;;) {}\nfunction get_info() { return {protocolId: 'LOOP'}; }\n"));
    JsBackend b2;
    QElapsedTimer t;
    t.start();
    const bool ok2 = b2.initialize(m2, &err);
    check("js: top-level loop in entry script stopped at load",
          !ok2 && err.contains(QStringLiteral("time limit")) && t.elapsed() < 30000);
}

int main(int argc, char** argv) {
    // 缩短预算让探针跑得快;默认值(2 亿条 / 3000 ms)在 README 中说明
    if (qEnvironmentVariableIsEmpty("BPLC_LUA_INSTR_BUDGET"))
        qputenv("BPLC_LUA_INSTR_BUDGET", "20000000");
    if (qEnvironmentVariableIsEmpty("BPLC_JS_CALL_TIMEOUT_MS"))
        qputenv("BPLC_JS_CALL_TIMEOUT_MS", "500");
    QGuiApplication app(argc, argv);
    QTemporaryDir tmp;
    if (!tmp.isValid()) return 2;
    const QString root = QDir(tmp.path()).canonicalPath();
    test_lua(root);
    test_js(root);
    std::printf("\nRESULT: %s (%d failures)\n", g_fails ? "FAILURES" : "ALL PASS", g_fails);
    return g_fails ? 1 : 0;
}
