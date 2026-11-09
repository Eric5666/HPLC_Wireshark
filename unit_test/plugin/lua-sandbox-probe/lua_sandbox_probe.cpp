/// @file lua_sandbox_probe.cpp
/// @brief Lua 插件沙箱回归探针(src/plugin/host/lua_backend.cpp open_sandboxed_libs)
/// @details 合成一个探测插件:脚本在 get_info() 里逐项自检沙箱,全部通过才返回
///          与清单一致的 protocolId,否则把首个失败项作为 protocolId 返回
///          (LuaBackend::initialize 会以 "protocolId mismatch" 报出)。
///          另外确认仓库自带的 Lua 示例插件(src/plugin/examples/lua_*)仍能加载。
///          预期输出 `RESULT: ALL PASS (0 failures)`,exit 0。
#include <QDir>
#include <QFile>
#include <QGuiApplication>
#include <QTemporaryDir>
#include <cstdio>

#include "lua_backend.h"

static int g_fails = 0;
static void check(const char* name, bool ok) {
    std::printf("%-60s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) ++g_fails;
}

static bool write_file(const QString& path, const QByteArray& data) {
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    return f.write(data) == data.size();
}

// 每项:{条件表达式, 失败名}。条件为真 = 沙箱行为符合预期
static const char* kProbeScript = R"LUA(
local function bad_dofile(p) return not pcall(dofile, p) end
local checks = {
  {function() return io == nil end, "io-present"},
  {function() return debug == nil end, "debug-present"},
  {function() return os.execute == nil and os.exit == nil end, "os.execute/exit-present"},
  {function() return os.remove == nil and os.rename == nil and os.tmpname == nil end, "os.fs-present"},
  {function() return os.getenv == nil end, "os.getenv-present"},
  {function() return type(os.time()) == "number" and type(os.clock()) == "number" end, "os.time-missing"},
  {function() return package.loadlib == nil and package.cpath == "" end, "package.loadlib/cpath"},
  {function() return #package.searchers == 2 end, "C-searchers-present"},
  {function() return require("helper").v == 42 end, "require-in-dir-broken"},
  {function() return dofile("helper.lua").v == 42 end, "dofile-in-dir-broken"},
  {function() return loadfile("helper.lua") ~= nil end, "loadfile-in-dir-broken"},
  {function() return loadfile("/etc/hostname") == nil end, "loadfile-abs-allowed"},
  {function() return loadfile("../outside.lua") == nil end, "loadfile-dotdot-allowed"},
  {function() return bad_dofile("../outside.lua") end, "dofile-outside-allowed"},
  {function() return load("return 7")() == 7 end, "load-text-broken"},
  {function() local env = {x = 5}; return load("return x", "c", "t", env)() == 5 end, "load-env-broken"},
  {function() return load(string.dump(function() return 1 end)) == nil end, "load-bytecode-allowed"},
  {function() return load(string.dump(function() return 1 end), "b", "b") == nil end, "load-mode-b-allowed"},
  {function()
     package.path = PARENT .. "/?.lua"
     package.loaded["outside"] = nil
     local ok = pcall(require, "outside")
     return not ok
   end, "require-outside-allowed"},
}
local fail = nil
for _, c in ipairs(checks) do
  local ok, res = pcall(c[1])
  if not (ok and res) then fail = c[2] .. (ok and "" or (": " .. tostring(res))); break end
end
function get_info() return {protocolId = fail or "SANDBOX_OK", displayName = "sandbox"} end
function parse(frame) return {accept = false} end
)LUA";

static void test_sandbox(const QString& root) {
    const QString parent = root + QStringLiteral("/p");
    const QString dir = parent + QStringLiteral("/lua-sandbox");
    QDir().mkpath(dir);
    write_file(parent + QStringLiteral("/outside.lua"), "return {v = 666}");
    write_file(dir + QStringLiteral("/helper.lua"), "return {v = 42}");
    write_file(dir + QStringLiteral("/main.lua"),
               QByteArray("PARENT = [[") + parent.toUtf8() + "]]\n" + kProbeScript);
    write_file(dir + QStringLiteral("/plugin.json"),
               R"({"name":"lua-sandbox","version":"1.0.0","runtime":"lua","entry":"main.lua",)"
               R"("api_version":1,"protocol_id":"SANDBOX_OK"})");
    const PluginManifest m = read_plugin_manifest(dir);
    check("sandbox: manifest valid", m.valid);
    LuaBackend b;
    QString err;
    const bool ok = b.initialize(m, &err);
    if (!ok) std::printf("  err: %s\n", qPrintable(err));
    check("sandbox: all in-script checks pass", ok);

    // 入口脚本为字节码时拒绝加载
    const QString bdir = parent + QStringLiteral("/lua-bytecode");
    QDir().mkpath(bdir);
    write_file(bdir + QStringLiteral("/main.lua"), QByteArray("\x1bLua\x54\x00", 6));
    write_file(bdir + QStringLiteral("/plugin.json"),
               R"({"name":"lua-bytecode","version":"1.0.0","runtime":"lua","entry":"main.lua",)"
               R"("api_version":1,"protocol_id":"X"})");
    LuaBackend b2;
    check("sandbox: bytecode entry rejected",
          !b2.initialize(read_plugin_manifest(bdir), &err) &&
              err.contains(QStringLiteral("attempt to load a binary chunk")));
}

static void test_bundled_examples() {
    const QDir ex(QStringLiteral(BPLC_REPO_DIR "/src/plugin/examples"));
    int n = 0;
    for (const QString& d : ex.entryList({QStringLiteral("lua_*")}, QDir::Dirs)) {
        const PluginManifest m = read_plugin_manifest(ex.absoluteFilePath(d));
        LuaBackend b;
        QString err;
        const bool ok = m.valid && b.initialize(m, &err);
        if (!ok) std::printf("  %s: %s\n", qPrintable(d), qPrintable(m.valid ? err : m.error));
        check(qPrintable(QStringLiteral("bundled example loads: %1").arg(d)), ok);
        ++n;
    }
    check("bundled lua examples found (>=4)", n >= 4);
}

int main(int argc, char** argv) {
    QGuiApplication app(argc, argv);
    QTemporaryDir tmp;
    if (!tmp.isValid()) return 2;
    test_sandbox(QDir(tmp.path()).canonicalPath());
    test_bundled_examples();
    std::printf("\nRESULT: %s (%d failures)\n", g_fails ? "FAILURES" : "ALL PASS", g_fails);
    return g_fails ? 1 : 0;
}
