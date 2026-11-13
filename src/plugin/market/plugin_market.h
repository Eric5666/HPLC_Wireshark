/// @file plugin_market.h
/// @brief 插件市场后端:远端 feed 拉取、下载安装、离线安装、启停、卸载
/// @details
///   Feed 格式见 BPLC_Plugin_Market/market.json:
///     { "version": 1, "updated": "...",
///       "plugins": [ { "name", "display_name", "display_name_en",
///                       "description", "description_en", "category",
///                       "author", "readme_url",
///                       "versions": [
///                         { "version", "url", "size",
///                           "min_app_version", "updated_at" } ] } ] }
///   插件包为 zip,内含 plugin.json(清单,见 plugin_api/plugin_manifest.h)
///   与入口脚本。安装目录(插件包总目录):
///     <主程序安装目录>/plugins/<name>/
///   每个已安装插件目录下有 meta.json: { "enabled": bool, "installed_at",
///   "source", "updated_at" }。README 优先读插件目录下 README.md,
///   其次拉取 feed 的 readme_url。
///   校验链(当前):包大小上限 + zip 解包防护 + 清单合法性/插件名白名单 +
///   min_app_version/平台/ABI 兼容性。不做 SHA-256 校验(feed 若带 "sha256" 字段一律忽略)。
///   Ed25519 官方签名为后续步骤,见 docs/MARKET.md。
#ifndef BPLC_PLUGIN_MARKET_H
#define BPLC_PLUGIN_MARKET_H

#include <QList>
#include <QNetworkAccessManager>
#include <QObject>
#include <QString>
#include <functional>

#include "../plugin_api/plugin_manifest.h"

/// @brief 市场 feed 中的单个版本
struct MarketVersion {
    QString version;
    QString url;
    qint64  size = 0;
    QString min_app_version; ///< 要求宿主最低版本
    QString updated_at;      ///< 版本更新时间(ISO 日期,可空)
    QStringList platforms;   ///< 适用平台(如 linux-x86_64);空=全平台(脚本插件)
    QString abi;             ///< native 插件 ABI(如 qt6.10.1-mingw-x64);脚本插件为空
};

/// @brief 市场 feed 中的一个插件
struct MarketPlugin {
    QString name;
    QString display_name;
    QString display_name_en;
    QString description;
    QString description_en;
    QString category;        ///< diagnosis | report | graphics | protocol ...
    QString author;
    QString readme_url;      ///< README markdown 地址(可空)
    QString source;          ///< feed 来源 URL(解析时填充,保留原始地址)
    QString mirror_prefix;   ///< feed 探活选中的镜像前缀,用于 README/插件包链接
    QList<MarketVersion> versions;

    const MarketVersion* latest() const {
        return versions.isEmpty() ? nullptr : &versions.last();
    }
    /// @brief 最新且当前平台可安装的版本(无则 nullptr)
    const MarketVersion* latest_compatible() const;
    QString localized_name(bool english) const {
        if (english && !display_name_en.isEmpty()) return display_name_en;
        return display_name.isEmpty() ? name : display_name;
    }
    QString localized_desc(bool english) const {
        if (english && !description_en.isEmpty()) return description_en;
        return description;
    }
};

/// @brief 本地已安装插件
struct InstalledPlugin {
    PluginManifest manifest;
    bool    enabled = true;
    QString dir;             ///< 插件目录绝对路径
    QString source;          ///< 安装来源:feed URL | offline | file
    QString installed_at;    ///< 安装时间(ISO)
    QString updated_at;      ///< 所装版本的更新时间(ISO,可空)
};

/// @brief 插件市场后端(网络/文件 IO 均在本类,GUI 线程使用)
class PluginMarket : public QObject {
    Q_OBJECT
public:
    explicit PluginMarket(QObject* parent = nullptr);
    ~PluginMarket() override;

    /// @brief 用户插件安装根目录
    static QString default_install_dir();
    /// @brief 默认远端 feed 地址(BPLC_Plugin_Market/market.json)
    static QString default_feed_url();

    /// @brief 拉取远端 feed(异步,经 feed_ready/feed_error 回传)
    void fetch_feed(const QString& url);
    /// @brief 解析 feed JSON(静态,便于测试)
    /// @param source_url feed 来源 URL,写入各 MarketPlugin::source
    static QList<MarketPlugin> parse_feed(const QByteArray& json, QString* err,
                                          const QString& source_url = QString(),
                                          const QString& mirror_prefix = QString());
    /// @brief 将市场资源 URL 按 feed 选中的代理前缀改写(已改写/非 HTTP URL 保持不变)
    static QString resolve_market_url(const QString& url,
                                      const QString& mirror_prefix);
    /// @brief 拉取任意文本(如 README markdown,异步)
    void fetch_text(const QString& url,
                    const QString& mirror_prefix = QString());

    /// @brief 从市场安装指定版本(异步,经 install_* 信号回传)
    void install_market_plugin(const MarketPlugin& plugin, int version_index);
    /// @brief 离线安装本地 zip 包(异步,经 install_* 信号回传)
    void install_from_file(const QString& zip_path);

    /// @brief 部署/卸载前卸载插件的回调(删除旧目录前调用,需同步等待
    ///        native DLL 释放文件锁;由主界面注入 unload_all_sync)
    std::function<void()> unload_cb;
    /// @brief unload_cb 之后部署失败时调用:重新加载插件,避免用户插件停在卸载状态
    std::function<void()> reload_cb;

    /// @brief 扫描安装目录,返回已安装插件
    QList<InstalledPlugin> installed_plugins() const;
    /// @brief 启用/禁用(写 meta.json,下次加载生效)
    bool set_enabled(const QString& name, bool enabled);
    /// @brief 卸载(删除插件目录)
    bool uninstall(const QString& name);
    /// @brief 该插件在 feed 中是否有更新(返回新版本,无则 nullptr)
    static const MarketVersion* update_for(const InstalledPlugin& inst,
                                           const QList<MarketPlugin>& feed);

    // ---- 静态工具(可独立测试) ----
    /// @brief 安装根目录 base 下插件 name 的目录路径(路径穿越防护,三处入口共用)
    /// @return 合法时返回规范化绝对路径;name 不合白名单、不是 base 的一级子目录、
    ///         或已存在目录(含符号链接)解析后落在 base 之外时返回空串
    static QString plugin_dir_path(const QString& base_dir, const QString& name);
    /// @brief 解包到 dest_dir:拒绝不安全条目名(见 safe_extract_path),
    ///        限制单条目 64 MB / 总量 256 MB / 条目数 4096
    static bool unzip_to_dir(const QString& zip_path, const QString& dest_dir,
                             QString* err);
    /// @brief zip 条目在 dest_dir 下的落盘路径;绝对路径、盘符、UNC、反斜杠、
    ///        ".." 组件或规范化后不在 dest_dir 内时返回空串
    static QString safe_extract_path(const QString& dest_dir,
                                     const QString& entry_name);
    /// @brief 语义化版本比较: <0(a<b) 0(==) >0(a>b)
    static int compare_version(const QString& a, const QString& b);
    /// @brief 当前宿主版本是否满足 min_app_version
    static bool app_version_ok(const QString& min_app_version);
    /// @brief 当前运行平台标识,如 linux-x86_64 / linux-arm64 / windows-x86_64 / windows-arm64(见 plugin_host_platform())
    static QString current_platform();
    /// @brief 该版本是否可在当前平台安装(platforms 为空=全平台)
    static bool version_platform_ok(const MarketVersion& v);
    /// @brief native 版本 ABI 是否与主程序匹配(abi 空=脚本插件,恒 true)
    static bool version_abi_ok(const MarketVersion& v);
    /// @brief 插件目录是否被禁用(meta.json enabled==false)
    static bool plugin_dir_enabled(const QString& plugin_dir);

signals:
    void feed_ready(const QList<MarketPlugin>& plugins);
    void feed_error(const QString& error);
    void text_ready(const QString& url, const QString& text);
    void text_error(const QString& url, const QString& error);
    void install_progress(const QString& text);
    void install_finished(bool ok, const QString& error, const QString& name);

private:
    /// @brief 一次安装的上下文(按值随请求传递;并发安装互不串扰)
    struct InstallContext {
        QString name;        ///< 期望的插件名(离线安装解包后才知道)
        QString source;      ///< 来源(feed URL / file)
        QString updated_at;  ///< 版本更新时间(可空)
    };
    void finish_install_from_zip(const QString& zip_path, const InstallContext& ctx);
    bool deploy_staged(const QString& staged_dir, const QString& plugin_name,
                       const InstallContext& ctx, QString* err);
    /// 写插件目录下的 meta.json(默认启用,记录来源与版本更新时间)
    static bool write_meta_json(const QString& plugin_dir, const InstallContext& ctx,
                                QString* err);

    QNetworkAccessManager* m_nam = nullptr;
};

#endif // BPLC_PLUGIN_MARKET_H
