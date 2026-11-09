/// @file market_safety_probe.cpp
/// @brief 插件市场安全回归探针:插件名/安装目录路径穿越(H2)
/// @details 无外部输入:zip 包用 miniz 现场合成,安装目录为
///          <探针所在目录>/plugins(PluginMarket::default_install_dir),跑完清理。
///          预期输出 `RESULT: ALL PASS (0 failures)`,exit 0。
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <cstdio>
#include <utility>
#include <vector>

#include "miniz.h"
#include "plugin_market.h"

static int g_fails = 0;
static void check(const char* name, bool ok) {
    std::printf("%-60s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) ++g_fails;
}

using ZipEntry = std::pair<QByteArray, QByteArray>;  // 条目名(原样字节), 内容

/// 用 miniz 合成 zip(条目名原样写入,用于构造恶意路径)
static bool make_zip(const QString& path, const std::vector<ZipEntry>& entries) {
    mz_zip_archive zip;
    memset(&zip, 0, sizeof(zip));
    const QByteArray p = path.toLocal8Bit();
    if (!mz_zip_writer_init_file(&zip, p.constData(), 0)) return false;
    bool ok = true;
    for (const auto& e : entries)
        ok = ok && mz_zip_writer_add_mem(&zip, e.first.constData(), e.second.constData(),
                                         size_t(e.second.size()), MZ_DEFAULT_COMPRESSION);
    ok = mz_zip_writer_finalize_archive(&zip) && ok;
    mz_zip_writer_end(&zip);
    return ok;
}

static bool write_file(const QString& path, const QByteArray& data) {
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    return f.write(data) == data.size();
}

static QByteArray manifest_json(const QByteArray& name) {
    return QByteArray(R"({"name":")") + name +
           R"(","version":"1.0.0","runtime":"js","entry":"x.js","api_version":1,"protocol_id":"T"})";
}

// ── H2:插件名白名单 + 安装目录一级子目录约束 ──
static void test_plugin_name() {
    for (const char* ok : {"js-topo", "lua_echo", "Cpp.Coverage2", "a"})
        check(qPrintable(QStringLiteral("name ok: %1").arg(QLatin1String(ok))),
              plugin_name_is_safe(QString::fromLatin1(ok)));
    const QString bad[] = {QString(), QStringLiteral("."), QStringLiteral(".."),
                           QStringLiteral("../x"), QStringLiteral("a/b"),
                           QStringLiteral("a\\b"), QStringLiteral("C:x"),
                           QStringLiteral(".hidden"), QStringLiteral("-x"),
                           QStringLiteral("a b"), QString(65, QLatin1Char('a')),
                           QStringLiteral("插件")};
    bool all_rej = true;
    for (const QString& b : bad) all_rej = all_rej && !plugin_name_is_safe(b);
    check("name rejected: empty . .. ../x a/b a\\b C:x .x -x space 65ch CJK", all_rej);
}

static void test_plugin_dir_path(const QString& root) {
    const QString base = root + QStringLiteral("/plugins");
    QDir().mkpath(base);
    check("dir: plain name -> base/name",
          PluginMarket::plugin_dir_path(base, QStringLiteral("js-topo")) ==
              QDir::cleanPath(base + QStringLiteral("/js-topo")));
    check("dir: '..' rejected",
          PluginMarket::plugin_dir_path(base, QStringLiteral("..")).isEmpty());
    check("dir: 'a/../../x' rejected",
          PluginMarket::plugin_dir_path(base, QStringLiteral("a/../../x")).isEmpty());
    check("dir: absolute rejected",
          PluginMarket::plugin_dir_path(base, root).isEmpty());
#ifndef Q_OS_WIN
    // 安装根内指向外部的符号链接:真实路径不在根下 → 拒绝(防 removeRecursively 跟随)
    const QString outside = root + QStringLiteral("/outside");
    QDir().mkpath(outside);
    QFile::link(outside, base + QStringLiteral("/evil"));
    check("dir: symlink escaping base rejected",
          PluginMarket::plugin_dir_path(base, QStringLiteral("evil")).isEmpty());
#endif
}

static void test_manifest_name(const QString& root) {
    const QString d = root + QStringLiteral("/mf");
    QDir().mkpath(d);
    write_file(d + QStringLiteral("/x.js"), "1");
    for (const QByteArray& n : {QByteArray(".."), QByteArray("a/../../x"), QByteArray("ok-name")}) {
        write_file(d + QStringLiteral("/plugin.json"), manifest_json(n));
        const PluginManifest m = read_plugin_manifest(d);
        const bool expect_ok = (n == "ok-name");
        check(qPrintable(QStringLiteral("manifest name '%1' %2")
                             .arg(QString::fromLatin1(n), expect_ok ? "accepted" : "rejected")),
              m.valid == expect_ok);
    }
}

/// 离线安装 name=".." 的包:必须失败,且安装根的上级目录(=探针目录)不被删除
static void test_install_traversal(const QString& root) {
    const QString zip = root + QStringLiteral("/evil.zip");
    check("zip: build name='..' package",
          make_zip(zip, {{"plugin.json", manifest_json("..")}, {"x.js", "1"}}));
    const QString sentinel =
        QCoreApplication::applicationDirPath() + QStringLiteral("/market_probe_sentinel");
    write_file(sentinel, "keep");
    PluginMarket mk;
    bool fin_ok = true;
    QObject::connect(&mk, &PluginMarket::install_finished,
                     [&](bool ok, const QString& e, const QString&) { fin_ok = ok; if (!ok) std::printf("  err: %s\n", qPrintable(e)); });
    mk.install_from_file(zip);
    check("install: name='..' rejected", !fin_ok);
    check("install: app dir untouched", QFile::exists(sentinel));
    check("uninstall: '..' rejected", !mk.uninstall(QStringLiteral("..")));
    check("set_enabled: '..' rejected", !mk.set_enabled(QStringLiteral(".."), false));
    QFile::remove(sentinel);

    // 正常包仍可安装/覆盖升级/卸载(防护不误伤)
    const QString good = root + QStringLiteral("/good.zip");
    make_zip(good, {{"plugin.json", manifest_json("ok-name")}, {"x.js", "1"}});
    fin_ok = false;
    mk.install_from_file(good);
    check("install: valid package ok", fin_ok);
    fin_ok = false;
    mk.install_from_file(good);
    check("install: overwrite (upgrade) ok", fin_ok);
    check("set_enabled: valid ok", mk.set_enabled(QStringLiteral("ok-name"), false));
    check("uninstall: valid ok", mk.uninstall(QStringLiteral("ok-name")));
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("BPLC_MarketSafetyProbe"));
    QCoreApplication::setApplicationVersion(QStringLiteral("2.0.1"));
    QTemporaryDir tmp;
    if (!tmp.isValid()) {
        std::printf("no temp dir\n");
        return 2;
    }
    test_plugin_name();
    test_plugin_dir_path(tmp.path());
    test_manifest_name(tmp.path());
    test_install_traversal(tmp.path());
    QDir(PluginMarket::default_install_dir()).removeRecursively();
    std::printf("\nRESULT: %s (%d failures)\n", g_fails ? "FAILURES" : "ALL PASS", g_fails);
    return g_fails ? 1 : 0;
}
