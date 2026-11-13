/// @file entry_containment_probe.cpp
/// @brief 回归探针:
///  1) 插件 manifest 的 entry 必须落在插件目录内(canonical 包含检查),
///     ../、绝对路径、越界符号链接一律拒绝;Lua/JS/native 后端加载时再查一次
#include <QDir>
#include <QFile>
#include <QGuiApplication>
#include <QTemporaryDir>
#include <cstdio>

#include "js_backend.h"
#include "lua_backend.h"
#include "native_backend.h"

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
                           const char* runtime, const QString& entry) {
    const QString dir = root + QLatin1Char('/') + name;
    QDir().mkpath(dir);
    write_file(dir + QStringLiteral("/plugin.json"),
               QStringLiteral(R"({"name":"%1","version":"1.0.0","runtime":"%2",)"
                              R"("entry":"%3","api_version":1,"protocol_id":"X"})")
                   .arg(name, QLatin1String(runtime), entry)
                   .toUtf8());
    return dir;
}

static const QByteArray kLua =
    "function get_info() return {protocolId = \"X\", displayName = \"x\"} end\n"
    "function parse(frame) return {accept = false} end\n";
static const QByteArray kJs =
    "function parse(frame) { return null; }\n";

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QGuiApplication app(argc, argv);
    QTemporaryDir tmp;
    const QString root = tmp.path() + QStringLiteral("/plugins");
    QDir().mkpath(root);
    const QString outside = tmp.path() + QStringLiteral("/outside");
    QDir().mkpath(outside);
    write_file(outside + QStringLiteral("/evil.lua"), kLua);
    write_file(outside + QStringLiteral("/evil.js"), kJs);
    write_file(outside + QStringLiteral("/libevil.so"), "not a lib");

    // --- 正常入口(含子目录)
    {
        const QString d = make_plugin(root, QStringLiteral("ok-lua"), "lua", QStringLiteral("main.lua"));
        write_file(d + QStringLiteral("/main.lua"), kLua);
        const PluginManifest m = read_plugin_manifest(d);
        check("manifest: plain lua entry valid", m.valid);
        LuaBackend b; QString err;
        const bool ok = b.initialize(m, &err);
        if (!ok) std::printf("  err: %s\n", qPrintable(err));
        check("lua: initialize plain entry", ok);
        b.shutdown();
    }
    {
        const QString d = make_plugin(root, QStringLiteral("ok-sub"), "js", QStringLiteral("src/main.js"));
        QDir().mkpath(d + QStringLiteral("/src"));
        write_file(d + QStringLiteral("/src/main.js"), kJs);
        check("manifest: subdir js entry valid", read_plugin_manifest(d).valid);
    }
    {
        const QString d = make_plugin(root, QStringLiteral("ok-dot"), "lua", QStringLiteral("./a/../main.lua"));
        write_file(d + QStringLiteral("/main.lua"), kLua);
        check("manifest: '..' segment rejected even if it stays inside", !read_plugin_manifest(d).valid);
    }

    // --- 越界入口
    struct Case { const char* name; const char* rt; QString entry; };
    const Case cases[] = {
        {"manifest: ../outside lua rejected", "lua", QStringLiteral("../../outside/evil.lua")},
        {"manifest: ../outside js rejected", "js", QStringLiteral("../../outside/evil.js")},
        {"manifest: ../outside native rejected", "native", QStringLiteral("../../outside/libevil.so")},
        {"manifest: absolute lua path rejected", "lua", outside + QStringLiteral("/evil.lua")},
        {"manifest: backslash path rejected", "lua", QStringLiteral("..\\\\..\\\\outside\\\\evil.lua")},
        {"manifest: missing entry rejected", "lua", QStringLiteral("nope.lua")},
    };
    int i = 0;
    for (const Case& c : cases) {
        const QString d = make_plugin(root, QStringLiteral("bad%1").arg(i++), c.rt, c.entry);
        check(c.name, !read_plugin_manifest(d).valid);
    }
    {
        const QString d = make_plugin(root, QStringLiteral("dir-entry"), "lua", QStringLiteral("sub"));
        QDir().mkpath(d + QStringLiteral("/sub"));
        check("manifest: directory as entry rejected", !read_plugin_manifest(d).valid);
    }

#ifndef Q_OS_WIN
    // --- 符号链接越界(文件链接、目录链接)
    {
        const QString d = make_plugin(root, QStringLiteral("link-file"), "lua", QStringLiteral("main.lua"));
        QFile::link(outside + QStringLiteral("/evil.lua"), d + QStringLiteral("/main.lua"));
        check("manifest: symlinked entry pointing outside rejected", !read_plugin_manifest(d).valid);
    }
    {
        const QString d = make_plugin(root, QStringLiteral("link-dir"), "js", QStringLiteral("lib/evil.js"));
        QFile::link(outside, d + QStringLiteral("/lib"));
        check("manifest: entry under symlinked dir outside rejected", !read_plugin_manifest(d).valid);
    }
    {
        const QString d = make_plugin(root, QStringLiteral("link-in"), "lua", QStringLiteral("alias.lua"));
        write_file(d + QStringLiteral("/real.lua"), kLua);
        QFile::link(d + QStringLiteral("/real.lua"), d + QStringLiteral("/alias.lua"));
        check("manifest: symlink staying inside plugin dir allowed", read_plugin_manifest(d).valid);
    }
    // --- 校验通过后入口被换成越界链接:后端加载时必须再拒绝(TOCTOU)
    {
        const QString d = make_plugin(root, QStringLiteral("swap-lua"), "lua", QStringLiteral("main.lua"));
        write_file(d + QStringLiteral("/main.lua"), kLua);
        const PluginManifest m = read_plugin_manifest(d);
        check("swap: manifest valid before swap", m.valid);
        QFile::remove(d + QStringLiteral("/main.lua"));
        QFile::link(outside + QStringLiteral("/evil.lua"), d + QStringLiteral("/main.lua"));
        LuaBackend b; QString err;
        check("swap: lua backend refuses swapped entry", !b.initialize(m, &err));
    }
    {
        const QString d = make_plugin(root, QStringLiteral("swap-js"), "js", QStringLiteral("main.js"));
        write_file(d + QStringLiteral("/main.js"), kJs);
        const PluginManifest m = read_plugin_manifest(d);
        QFile::remove(d + QStringLiteral("/main.js"));
        QFile::link(outside + QStringLiteral("/evil.js"), d + QStringLiteral("/main.js"));
        JsBackend b; QString err;
        check("swap: js backend refuses swapped entry", m.valid && !b.initialize(m, &err));
    }
    {
        PluginManifest m;
        m.dir_path = root + QStringLiteral("/native-x");
        QDir().mkpath(m.dir_path);
        m.runtime = QStringLiteral("native");
        m.entry = QStringLiteral("../../outside/libevil.so");
        m.api_version = 1;
        NativeBackend b; QString err;
        check("native backend refuses outside entry", !b.initialize(m, &err) &&
                                                      err.contains(QStringLiteral("outside")));
    }
#endif

    std::printf("RESULT: %s (%d failures)\n", g_fails ? "FAIL" : "ALL PASS", g_fails);
    return g_fails ? 1 : 0;
}
