/// @file market_test.cpp
/// @brief 插件市场后端单元测试(feed 解析/版本比较/sha256/解包/安装/启停/卸载)
/// @details 用法(仓库根):
///   cd src/plugin/tests && mkdir -p build_market && cd build_market \
///     && /home/hatch/qt/6.5.3/gcc_64/bin/qmake ../market_test.pro && make \
///     && QT_QPA_PLATFORM=offscreen ./market_test
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QtGlobal>

#include "plugin_market.h"
#include "plugin_env.h"

static int g_fail = 0;
#define CHECK(cond, msg)                                            \
    do {                                                            \
        if (!(cond)) {                                              \
            qWarning("FAIL: %s (line %d)", msg, __LINE__);           \
            ++g_fail;                                               \
        } else {                                                    \
            qInfo("ok: %s", msg);                                   \
        }                                                           \
    } while (0)

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName("BPLC_MarketTest");
    QCoreApplication::setApplicationVersion("1.3.0");

    // feed 解析:用真实市场仓库的 market.json
    const QString feed_path =
        QString::fromLocal8Bit(qgetenv("MARKET_JSON"));
    QFile ff(feed_path.isEmpty()
                 ? QStringLiteral("/home/hatch/workspace/BPLC_Plugin_Market/"
                                  "market.json")
                 : feed_path);
    CHECK(ff.open(QIODevice::ReadOnly), "open market.json");
    QString perr;
    const QList<MarketPlugin> feed =
        PluginMarket::parse_feed(ff.readAll(), &perr);
    CHECK(perr.isEmpty() && feed.size() == 4, "parse 4 plugins");
    const MarketPlugin& topo = feed[0];
    CHECK(topo.name == "js-topo", "topo name");
    CHECK(topo.versions.size() == 4, "topo 4 versions");
    CHECK(topo.latest()->version == "1.3.0", "topo latest 1.3.0");
    CHECK(!topo.display_name_en.isEmpty(), "topo en name");
    // 脚本插件:platforms 为空=全平台
    CHECK(topo.latest()->platforms.isEmpty(), "script plugin all platforms");
    CHECK(PluginMarket::version_platform_ok(*topo.latest()),
          "script version platform ok");
    CHECK(topo.latest_compatible() != nullptr, "script latest_compatible");
    // native 插件:cpp-coverage 带 platforms/abi 标注
    const MarketPlugin& cov = feed[3];
    CHECK(cov.name == "cpp-coverage", "cov name");
    CHECK(cov.versions.size() == 4, "cov 4 versions");
    // 最新条目 1.3.0 目前只发了 Windows 包;本机取 latest_compatible
    CHECK(cov.latest()->version == "1.3.0", "cov latest 1.3.0");
    const MarketVersion* cov_compat = cov.latest_compatible();
    const QString plat = PluginMarket::current_platform();
    if (plat == QLatin1String("windows-x86_64")) {
        // Windows x64:1.3.0 带 qt6-mingw-x64 ABI,当前平台可装
        CHECK(cov_compat != nullptr && cov_compat->version == "1.3.0",
              "cov latest_compatible 1.3.0 on windows");
    } else if (plat == QLatin1String("linux-x86_64")) {
        // Linux x64:1.3.0 只标注了 windows 平台,回落到 1.1.0(qt6-gcc-x64)
        CHECK(cov_compat != nullptr && cov_compat->version == "1.1.0",
              "cov latest_compatible 1.1.0 on linux");
    } else {
        // arm64 等:feed 未发对应平台的 native 包 → 无兼容版本(被过滤)
        CHECK(cov_compat == nullptr,
              "cov no compatible version on non-x86_64 platform");
    }
    if (cov_compat) {
        CHECK(cov_compat->platforms.contains(plat),
              "cov compat platforms has current");
        CHECK(PluginMarket::version_platform_ok(*cov_compat),
              "cov compat version platform ok");
        CHECK(PluginMarket::version_abi_ok(*cov_compat),
              "cov compat version abi ok");
        CHECK(cov_compat->abi == plugin_host_abi(),
              "cov compat abi == host abi");
    }
    // 不兼容平台被过滤
    MarketVersion win_only = *cov.latest();
    win_only.platforms = QStringList{"windows-x86_64"};
    MarketPlugin cov_win = cov;
    cov_win.versions = QList<MarketVersion>{win_only};
    CHECK(!PluginMarket::version_platform_ok(win_only) ||
              PluginMarket::current_platform() == "windows-x86_64",
          "win-only filtered on linux");
    if (PluginMarket::current_platform() != "windows-x86_64")
        CHECK(cov_win.latest_compatible() == nullptr,
              "win-only latest_compatible null on linux");
    // 新增 feed 字段:readme_url / updated_at / source
    CHECK(topo.readme_url.endsWith(QStringLiteral("/readme/js-topo.md")),
          "readme_url");
    CHECK(topo.versions[0].updated_at == "2026-09-28", "v1 updated_at");
    CHECK(topo.latest()->updated_at == "2026-10-02", "v2 updated_at");
    ff.seek(0);
    const QList<MarketPlugin> feed2 =
        PluginMarket::parse_feed(ff.readAll(), &perr,
                                 QStringLiteral("https://feed.example/m.json"));
    CHECK(perr.isEmpty() && !feed2.isEmpty() &&
              feed2[0].source == "https://feed.example/m.json",
          "feed source recorded");
    ff.seek(0);
    const QList<MarketPlugin> mirrored_feed =
        PluginMarket::parse_feed(ff.readAll(), &perr,
                                 QStringLiteral("https://feed.example/m.json"),
                                 QStringLiteral("https://mirror.example/"));
    CHECK(perr.isEmpty() && !mirrored_feed.isEmpty() &&
              mirrored_feed[0].source == "https://feed.example/m.json" &&
              mirrored_feed[0].mirror_prefix == "https://mirror.example/",
          "feed origin and mirror prefix recorded separately");
    CHECK(PluginMarket::resolve_market_url(
              "https://raw.githubusercontent.com/org/repo/main/readme.md",
              "https://mirror.example/") ==
              "https://mirror.example/https://raw.githubusercontent.com/org/repo/main/readme.md",
          "README URL uses selected mirror");
    CHECK(PluginMarket::resolve_market_url(
              "https://github.com/org/repo/raw/main/pkg.zip",
              "https://mirror.example/") ==
              "https://mirror.example/https://github.com/org/repo/raw/main/pkg.zip",
          "package URL uses selected mirror");
    CHECK(PluginMarket::resolve_market_url(
              "https://mirror.example/https://raw.githubusercontent.com/org/repo/main/pkg.zip",
              "https://mirror.example/") ==
              "https://mirror.example/https://raw.githubusercontent.com/org/repo/main/pkg.zip",
          "already mirrored package URL is not double-prefixed");
    CHECK(PluginMarket::resolve_market_url("file:///tmp/local.zip",
                                           "https://mirror.example/") ==
              "file:///tmp/local.zip",
          "local resource URL bypasses network mirror");

    // 版本比较
    CHECK(PluginMarket::compare_version("1.1.0", "1.0.0") > 0, "ver gt");
    CHECK(PluginMarket::compare_version("1.0.0", "1.0.0") == 0, "ver eq");
    CHECK(PluginMarket::compare_version("1.0.0", "1.10.0") < 0, "ver lt");
    CHECK(PluginMarket::app_version_ok("1.3.0"), "app ver ok");
    CHECK(!PluginMarket::app_version_ok("9.9.9"), "app ver reject");
    CHECK(PluginMarket::app_version_ok(""), "app ver empty ok");

    // sha256 校验:与 market.json 记录值比对(js-topo 最新版)
    const QString zip_env = QString::fromLocal8Bit(qgetenv("MARKET_ZIP"));
    const QString zip_path = zip_env.isEmpty()
        ? QStringLiteral("/home/hatch/workspace/BPLC_Plugin_Market/plugins/"
                         "js-topo/js-topo-1.3.0.zip")
        : zip_env;
    CHECK(PluginMarket::verify_sha256(zip_path, topo.latest()->sha256),
          "sha256 match feed");
    CHECK(!PluginMarket::verify_sha256(
              zip_path, QString(64, QLatin1Char('0'))),
          "sha256 mismatch detected");

    // 解包
    QTemporaryDir tmp;
    CHECK(tmp.isValid(), "tmp dir");
    const QString staged = tmp.path() + "/staged";
    QString uerr;
    CHECK(PluginMarket::unzip_to_dir(zip_path, staged, &uerr),
          "unzip ok");
    const PluginManifest m = read_plugin_manifest(staged);
    CHECK(m.valid && m.name == "js-topo" && m.version == "1.3.0",
          "staged manifest valid");
    // settings schema 解析
    CHECK(m.settings.size() == 3, "settings count");
    CHECK(m.settings[0].key == "max_nodes" &&
              m.settings[0].type == "integer" &&
              m.settings[0].default_value.toInt() == 200 &&
              m.settings[0].has_minimum && m.settings[0].has_maximum,
          "settings[0] int");
    CHECK(m.settings[1].type == "boolean" &&
              m.settings[1].default_value.toBool(),
          "settings[1] bool");
    CHECK(m.settings[2].enum_options.size() == 3 &&
              m.settings[2].default_value.toString() == "auto",
          "settings[2] enum");
    // 非法 settings 项被跳过(未知 type / 缺 key)
    {
        QTemporaryDir t2;
        CHECK(t2.isValid(), "tmp dir 2");
        QFile e2(t2.path() + "/x.js");
        CHECK(e2.open(QIODevice::WriteOnly), "write entry");
        e2.write("1");
        e2.close();
        QFile j2(t2.path() + "/plugin.json");
        CHECK(j2.open(QIODevice::WriteOnly), "write manifest");
        j2.write(R"({"name":"t","version":"1.0.0","runtime":"js","entry":"x.js",
            "api_version":1,"protocol_id":"T",
            "settings":[{"key":"ok","type":"boolean","default":true},
                        {"key":"badtype","type":"weird","default":1},
                        {"type":"boolean","default":true}]})");
        j2.close();
        const PluginManifest m2 = read_plugin_manifest(t2.path());
        CHECK(m2.valid && m2.settings.size() == 1 &&
                  m2.settings[0].key == "ok",
              "bad settings skipped");
    }
    // zip-slip 防护
    CHECK(!PluginMarket::unzip_to_dir(QStringLiteral("/nope.zip"), staged,
                                      &uerr),
          "bad zip rejected");

    // 安装/启停/卸载(走默认安装目录,应用名为 BPLC_MarketTest,隔离)
    PluginMarket mk;
    bool fin_ok = false;
    QString fin_err, fin_name;
    QObject::connect(&mk, &PluginMarket::install_finished,
                     [&](bool ok, const QString& err, const QString& name) {
                         fin_ok = ok;
                         fin_err = err;
                         fin_name = name;
                     });
    mk.install_from_file(zip_path);
    CHECK(fin_ok && fin_name == "js-topo", "install_from_file ok");

    QList<InstalledPlugin> inst = mk.installed_plugins();
    CHECK(inst.size() == 1 && inst[0].manifest.version == "1.3.0" &&
              inst[0].enabled,
          "installed listed, enabled");
    // meta.json 记录来源与更新时间(离线安装:source=file)
    CHECK(inst[0].source == "file", "installed source=file");
    CHECK(!inst[0].updated_at.isEmpty(), "installed updated_at set");

    // 公共环境变量(5b7ba88 起新增 BPLC_THEME,共 6 个)
    const QList<PluginEnvVar> envs = plugin_common_env_vars();
    CHECK(envs.size() == 6, "env count");
    CHECK(plugin_env_value("BPLC_THEME", QString(), false) == "dark",
          "env theme default dark");
    CHECK(plugin_env_value("BPLC_API_VERSION", QString(), false) == "1",
          "env api version");
    CHECK(plugin_env_value("BPLC_LANG", QString(), false) == "zh" &&
              plugin_env_value("BPLC_LANG", QString(), true) == "en",
          "env lang");
    CHECK(plugin_env_value("BPLC_PLUGIN_DIR", "/tmp/x", false) == "/tmp/x",
          "env plugin dir");
    CHECK(plugin_env_value("NOPE", QString(), false).isEmpty(),
          "env unknown empty");
    // settings.json 读写
    CHECK(plugin_setting_value(tmp.path(), "k", 7).toInt() == 7,
          "setting default");
    QString werr;
    CHECK(plugin_write_settings(tmp.path(), {{"k", 42}, {"s", "a"}}, &werr),
          "write settings");
    CHECK(plugin_setting_value(tmp.path(), "k", 7).toInt() == 42,
          "setting read back");
    CHECK(plugin_setting_value(tmp.path(), "missing", 7).toInt() == 7,
          "setting missing default");

    // 更新检查:已装 1.3.0=最新 → 无更新;伪造 1.0.0 → 有更新
    CHECK(PluginMarket::update_for(inst[0], feed) == nullptr,
          "no update at latest");
    InstalledPlugin old = inst[0];
    old.manifest.version = "1.0.0";
    const MarketVersion* upd = PluginMarket::update_for(old, feed);
    CHECK(upd && upd->version == "1.3.0", "update found");

    CHECK(mk.set_enabled("js-topo", false), "disable ok");
    CHECK(!PluginMarket::plugin_dir_enabled(
              inst[0].dir),
          "dir disabled");
    inst = mk.installed_plugins();
    CHECK(inst.size() == 1 && !inst[0].enabled, "listed disabled");
    CHECK(mk.set_enabled("js-topo", true), "re-enable ok");

    CHECK(mk.uninstall("js-topo"), "uninstall ok");
    CHECK(mk.installed_plugins().isEmpty(), "uninstalled gone");
    CHECK(!mk.uninstall("js-topo"), "uninstall missing fails");
    CHECK(!mk.uninstall(".."), "uninstall traversal guard");

    // 坏包拒绝:非 zip
    fin_ok = true;
    mk.install_from_file(QStringLiteral("/tmp"));
    CHECK(!fin_ok, "non-zip rejected");

    if (g_fail == 0) qInfo("ALL MARKET TESTS PASSED");
    return g_fail == 0 ? 0 : 1;
}
