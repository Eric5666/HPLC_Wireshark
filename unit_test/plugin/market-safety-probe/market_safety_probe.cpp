/// @file market_safety_probe.cpp
/// @brief 插件市场安全回归探针:插件名/安装目录路径穿越(H2)、zip 解包防护(H3)、
///        市场安装强制 sha256(H4)
/// @details 无外部输入:zip 包用 miniz 现场合成,安装目录为
///          <探针所在目录>/plugins(PluginMarket::default_install_dir),跑完清理。
///          预期输出 `RESULT: ALL PASS (0 failures)`,exit 0。
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QEventLoop>
#include <QMap>
#include <QTimer>
#include <QUrl>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <cstdio>
#include <utility>
#include <vector>

#include "i18n.h"
#include "miniz.h"
#include "plugin_market.h"

static int g_fails = 0;
static void check(const char* name, bool ok) {
    std::printf("%-60s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) ++g_fails;
}

using ZipEntry = std::pair<QByteArray, QByteArray>;  // 条目名(原样字节), 内容

/// 用 miniz 合成 zip(条目名原样写入,用于构造恶意路径)
static bool make_zip(const QString& path, const std::vector<ZipEntry>& entries,
                     mz_uint level = MZ_DEFAULT_COMPRESSION) {
    mz_zip_archive zip;
    memset(&zip, 0, sizeof(zip));
    const QByteArray p = path.toLocal8Bit();
    if (!mz_zip_writer_init_file(&zip, p.constData(), 0)) return false;
    // miniz 写端拒绝以 '/' 开头的名字:先以 '#' 占位写入,再在字节层改回 '/'
    bool ok = true;
    QList<QByteArray> abs_names;
    for (const auto& e : entries) {
        QByteArray name = e.first;
        if (name.startsWith('/')) {
            name[0] = '#';
            abs_names.append(name);
        }
        ok = ok && mz_zip_writer_add_mem(&zip, name.constData(), e.second.constData(),
                                         size_t(e.second.size()), level);
    }
    ok = mz_zip_writer_finalize_archive(&zip) && ok;
    mz_zip_writer_end(&zip);
    if (ok && !abs_names.isEmpty()) {
        QFile f(path);
        if (!f.open(QIODevice::ReadWrite)) return false;
        QByteArray all = f.readAll();
        for (const QByteArray& n : abs_names) {
            QByteArray fixed = n;
            fixed[0] = '/';
            all.replace(n, fixed);   // 本地头 + 中央目录两处,等长替换
        }
        f.seek(0);
        ok = f.write(all) == all.size();
    }
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

// ── H3:zip 条目名校验 + 解包上限 ──
static void test_zip_entry_names(const QString& root) {
    const QString dest = root + QStringLiteral("/x/staged");
    const char* bad[] = {"../evil.txt", "a/../../evil.txt", "/abs/evil.txt",
                         "C:/Users/Public/evil.dll", "C:evil.dll",
                         "\\\\server\\share\\evil", "\\Windows\\evil.dll",
                         "a\\..\\..\\evil.txt", "..", "./", "sub/.."};
    bool all_rej = true;
    for (const char* b : bad) {
        const bool rej = PluginMarket::safe_extract_path(dest, QString::fromLatin1(b)).isEmpty();
        if (!rej) std::printf("  not rejected: %s\n", b);
        all_rej = all_rej && rej;
    }
    check("zip path: abs/drive/UNC/backslash/.. rejected", all_rej);
    check("zip path: 'sub/x.js' accepted",
          PluginMarket::safe_extract_path(dest, QStringLiteral("sub/x.js")) ==
              QDir::cleanPath(QDir(dest).absolutePath() + QStringLiteral("/sub/x.js")));
    check("zip path: 'a..b.txt' accepted (not a '..' component)",
          !PluginMarket::safe_extract_path(dest, QStringLiteral("a..b.txt")).isEmpty());

    // 端到端:含恶意条目的包整体拒绝,且不在目标外落盘(也不写合法条目:先校验后写)
    for (const char* b : {"../evil.txt", "C:evil.txt", "\\\\srv\\s\\evil.txt", "/tmp/evil.txt"}) {
        const QString zip = root + QStringLiteral("/slip.zip");
        QFile::remove(zip);
        make_zip(zip, {{"ok.txt", "1"}, {b, "pwned"}});
        QDir(dest).removeRecursively();
        QString err;
        const bool ok = PluginMarket::unzip_to_dir(zip, dest, &err);
        check(qPrintable(QStringLiteral("unzip: entry '%1' rejected").arg(QString::fromLatin1(b))),
              !ok && err.startsWith(QStringLiteral("Unsafe Zip Entry")));
        check(qPrintable(QStringLiteral("unzip: '%1' wrote nothing").arg(QString::fromLatin1(b))),
              !QFile::exists(root + QStringLiteral("/x/evil.txt")) &&
                  !QFile::exists(dest + QStringLiteral("/ok.txt")));
    }
    // 正常包(含子目录)照常解包
    {
        const QString zip = root + QStringLiteral("/fine.zip");
        make_zip(zip, {{"plugin.json", "{}"}, {"lib/", ""}, {"lib/util.js", "2"}});
        QDir(dest).removeRecursively();
        QString err;
        check("unzip: normal package with subdir ok",
              PluginMarket::unzip_to_dir(zip, dest, &err) &&
                  QFile::exists(dest + QStringLiteral("/lib/util.js")));
    }
}

static void test_zip_limits(const QString& root) {
    const QString dest = root + QStringLiteral("/lim/staged");
    QString err;
    {   // 条目数上限 4096
        std::vector<ZipEntry> many;
        for (int i = 0; i < 4097; ++i)
            many.push_back({QByteArray("f") + QByteArray::number(i), QByteArray("x")});
        const QString zip = root + QStringLiteral("/many.zip");
        make_zip(zip, many, MZ_BEST_SPEED);
        check("unzip: >4096 entries rejected",
              !PluginMarket::unzip_to_dir(zip, dest, &err) &&
                  err.startsWith(QStringLiteral("Too Many Zip Entries")));
    }
    {   // 单条目上限 64 MB
        const QString zip = root + QStringLiteral("/big.zip");
        make_zip(zip, {{"big.bin", QByteArray(64 * 1024 * 1024 + 1, '\0')}}, MZ_BEST_SPEED);
        QDir(dest).removeRecursively();
        check("unzip: entry > 64MB rejected",
              !PluginMarket::unzip_to_dir(zip, dest, &err) &&
                  err.startsWith(QStringLiteral("Zip Entry Too Large")) &&
                  !QFile::exists(dest + QStringLiteral("/big.bin")));
    }
    {   // 总量上限 256 MB(5 × 60 MB)
        const QByteArray chunk(60 * 1024 * 1024, '\0');
        const QString zip = root + QStringLiteral("/bomb.zip");
        make_zip(zip, {{"a", chunk}, {"b", chunk}, {"c", chunk}, {"d", chunk}, {"e", chunk}},
                 MZ_BEST_SPEED);
        QDir(dest).removeRecursively();
        check("unzip: total > 256MB rejected",
              !PluginMarket::unzip_to_dir(zip, dest, &err) &&
                  err.startsWith(QStringLiteral("Zip Content Too Large")));
        QFile::remove(zip);
    }
}

// ── H4:市场安装必须带 sha256(缺失/格式错/不匹配一律拒装) ──
static void test_market_sha256(const QString& root) {
    const QString zip = root + QStringLiteral("/mk.zip");
    make_zip(zip, {{"plugin.json", manifest_json("mk-plugin")}, {"x.js", "1"}});
    QFile zf(zip);
    const bool opened = zf.open(QIODevice::ReadOnly);
    const QString good_sha =
        opened ? QString::fromLatin1(QCryptographicHash::hash(zf.readAll(),
                                                              QCryptographicHash::Sha256).toHex())
               : QString();
    zf.close();
    check("sha256 hex: valid accepted", PluginMarket::is_sha256_hex(good_sha));
    check("sha256 hex: empty/short/non-hex rejected",
          !PluginMarket::is_sha256_hex(QString()) &&
              !PluginMarket::is_sha256_hex(QStringLiteral("abc")) &&
              !PluginMarket::is_sha256_hex(QString(64, QLatin1Char('g'))));

    auto run = [&](const QString& sha, QString* err_out) {
        MarketPlugin p;
        p.name = QStringLiteral("mk-plugin");
        MarketVersion v;
        v.version = QStringLiteral("1.0.0");
        v.url = QUrl::fromLocalFile(zip).toString();   // file://,不走镜像/网络
        v.sha256 = sha;
        p.versions.append(v);
        PluginMarket mk;
        bool done = false, ok = false;
        QEventLoop loop;
        QObject::connect(&mk, &PluginMarket::install_finished,
                         [&](bool r, const QString& e, const QString&) {
                             done = true; ok = r; *err_out = e; loop.quit();
                         });
        mk.install_market_plugin(p, 0);
        if (!done) {
            QTimer::singleShot(10000, &loop, &QEventLoop::quit);
            loop.exec();
        }
        if (ok) mk.uninstall(QStringLiteral("mk-plugin"));
        return ok;
    };
    QString err;
    check("market: missing sha256 refused",
          !run(QString(), &err) && err.contains(QStringLiteral("Has No Valid SHA-256")));
    check("market: malformed sha256 refused", !run(QStringLiteral("deadbeef"), &err));
    check("market: wrong sha256 refused",
          !run(QString(64, QLatin1Char('0')), &err) && err.contains(QStringLiteral("SHA-256 Mismatch")));
    trl::set_enabled(false);   // 中文界面:同一错误给中文文案(L3)
    check("market: mismatch message localized (zh UI)",
          !run(QString(64, QLatin1Char('0')), &err) && err.contains(QStringLiteral("SHA-256 不匹配")));
    trl::set_enabled(true);
    const bool good = run(good_sha, &err);
    if (!good) std::printf("  err: %s\n", qPrintable(err));
    check("market: correct sha256 installs", good);
}

// ── L6:并发安装上下文隔离 + unload_cb 推迟到拷贝前、失败时 reload_cb ──
static QString sha_of(const QString& path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return QString();
    return QString::fromLatin1(QCryptographicHash::hash(f.readAll(), QCryptographicHash::Sha256).toHex());
}

static MarketPlugin market_entry(const QString& name, const QString& zip, const QString& sha) {
    MarketPlugin p;
    p.name = name;
    MarketVersion v;
    v.version = QStringLiteral("1.0.0");
    v.url = QUrl::fromLocalFile(zip).toString();
    v.sha256 = sha;
    p.versions.append(v);
    return p;
}

static void test_install_context(const QString& root) {
    const QString za = root + QStringLiteral("/ctx-a.zip");
    const QString zb = root + QStringLiteral("/ctx-b.zip");
    make_zip(za, {{"plugin.json", manifest_json("ctx-a")}, {"x.js", "1"}});
    make_zip(zb, {{"plugin.json", manifest_json("ctx-b")}, {"x.js", "22"}});
    PluginMarket mk;
    int unloads = 0, reloads = 0;
    mk.unload_cb = [&] { ++unloads; };
    mk.reload_cb = [&] { ++reloads; };
    QMap<QString, bool> result;
    QEventLoop loop;
    QObject::connect(&mk, &PluginMarket::install_finished,
                     [&](bool ok, const QString& e, const QString& name) {
                         result[name] = ok;
                         if (!ok) std::printf("  err(%s): %s\n", qPrintable(name), qPrintable(e));
                         if (result.size() == 2) loop.quit();
                     });
    // 两个安装同时在途:旧实现共享 m_pending_*,先完成的那个会拿后一个的名字/sha256
    mk.install_market_plugin(market_entry(QStringLiteral("ctx-a"), za, sha_of(za)), 0);
    mk.install_market_plugin(market_entry(QStringLiteral("ctx-b"), zb, sha_of(zb)), 0);
    if (result.size() < 2) {
        QTimer::singleShot(10000, &loop, &QEventLoop::quit);
        loop.exec();
    }
    check("concurrent installs: both succeed with their own context",
          result.value(QStringLiteral("ctx-a")) && result.value(QStringLiteral("ctx-b")));
    const QString base = PluginMarket::default_install_dir();
    QFile meta(base + QStringLiteral("/ctx-a/meta.json"));
    check("concurrent installs: ctx-a meta.json written",
          meta.open(QIODevice::ReadOnly) && meta.readAll().contains("\"source\""));

    // 校验失败(sha256 不符)不得卸载插件
    unloads = reloads = 0;
    bool fin = true;
    QObject::disconnect(&mk, &PluginMarket::install_finished, nullptr, nullptr);
    QObject::connect(&mk, &PluginMarket::install_finished,
                     [&](bool ok, const QString&, const QString&) { fin = ok; loop.quit(); });
    mk.install_market_plugin(market_entry(QStringLiteral("ctx-a"), za, QString(64, QLatin1Char('0'))), 0);
    QTimer::singleShot(10000, &loop, &QEventLoop::quit);
    loop.exec();
    check("bad sha256: refused without unloading plugins", !fin && unloads == 0 && reloads == 0);

#ifndef Q_OS_WIN
    // 卸载后删旧版失败(目录不可写):必须 reload_cb 恢复加载
    const QString locked = base + QStringLiteral("/ctx-a/locked");
    QDir().mkpath(locked);
    write_file(locked + QStringLiteral("/f.txt"), "x");
    QFile::setPermissions(locked, QFileDevice::ReadOwner | QFileDevice::ExeOwner);
    unloads = reloads = 0;
    fin = true;
    mk.install_market_plugin(market_entry(QStringLiteral("ctx-a"), za, sha_of(za)), 0);
    QTimer::singleShot(10000, &loop, &QEventLoop::quit);
    loop.exec();
    check("deploy failure after unload: reload_cb called",
          !fin && unloads == 1 && reloads == 1);
    QFile::setPermissions(locked, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);
#endif
    mk.uninstall(QStringLiteral("ctx-a"));
    mk.uninstall(QStringLiteral("ctx-b"));
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    // 市场错误文案已本地化(L3):默认按英文界面断言英文文本;另有一条中文界面用例
    trl::set_enabled(true);
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
    test_zip_entry_names(tmp.path());
    test_zip_limits(tmp.path());
    test_market_sha256(tmp.path());
    test_install_context(tmp.path());
    QDir(PluginMarket::default_install_dir()).removeRecursively();
    std::printf("\nRESULT: %s (%d failures)\n", g_fails ? "FAILURES" : "ALL PASS", g_fails);
    return g_fails ? 1 : 0;
}
