/// @file plugin_market.cpp
/// @brief 插件市场后端实现
#include "plugin_market.h"

#include "plugin_market.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QProcess>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QUrl>

#include "i18n.h"
#include "miniz.h"  // 3rdparty/miniz, public domain, zip 解包
#include "net_size_cap.h"
#include "updatemirror.h"

namespace {
// 中→英注册(文件级,L3:市场错误/进度文案随界面语言切换)
struct I18nRegPluginMarket {
    I18nRegPluginMarket() {
        trl::register_en("无写权限：%1，且未找到 pkexec；请以 root 运行或安装到可写位置",
                         "No Write Permission for %1, and pkexec Not Found; Run as Root or Install to a Writable Location");
        trl::register_en("提权安装失败",
                         "Privileged Install Failed");
        trl::register_en("无写权限，且未找到 pkexec",
                         "No Write Permission, and pkexec Not Found");
        trl::register_en("提权卸载失败",
                         "Privileged Uninstall Failed");
        trl::register_en("提权写入失败：%1",
                         "Privileged Write Failed: %1");
        trl::register_en("无法创建目录：%1",
                         "Cannot Create Directory: %1");
        trl::register_en("复制失败：%1",
                         "Copy Failed: %1");
        trl::register_en("插件列表超出大小上限",
                         "Plugin Feed Exceeds the Size Limit");
        trl::register_en("文本超出大小上限",
                         "Text Exceeds the Size Limit");
        trl::register_en("插件列表解析错误：%1",
                         "Plugin Feed Parse Error: %1");
        trl::register_en("版本索引无效",
                         "Invalid Version Index");
        trl::register_en("版本 %1 不支持当前平台（%2）",
                         "Version %1 Does Not Support This Platform (%2)");
        trl::register_en("需要主程序版本 >= %1（当前 %2）",
                         "Requires App Version >= %1 (Current %2)");
        trl::register_en("插件列表中 %1 %2 没有有效的 SHA-256，拒绝安装未校验的安装包",
                         "Feed Entry for %1 %2 Has No Valid SHA-256; Refusing to Install an Unverified Package");
        trl::register_en("正在下载 %1",
                         "Downloading %1");
        trl::register_en("安装包超出大小上限",
                         "Package Exceeds the Size Limit");
        trl::register_en("无法创建临时目录",
                         "Cannot Create a Temporary Directory");
        trl::register_en("写入临时文件失败",
                         "Writing the Temporary File Failed");
        trl::register_en("SHA-256 不匹配，安装包已拒收",
                         "SHA-256 Mismatch, Package Rejected");
        trl::register_en("安装包名称不匹配：%1",
                         "Package Name Mismatch: %1");
        trl::register_en("已安装 %1 %2",
                         "Installed %1 %2");
        trl::register_en("插件名称不安全：%1",
                         "Unsafe Plugin Name: %1");
        trl::register_en("正在请求管理员权限...",
                         "Requesting Administrator Privileges...");
        trl::register_en("无写权限：%1；请以管理员身份运行或选择可写位置",
                         "No Write Permission for %1; Run as Administrator or Choose a Writable Location");
        trl::register_en("无法删除旧版本：%1",
                         "Cannot Remove the Old Version: %1");
        trl::register_en("无法写入 meta.json：%1",
                         "Cannot Write meta.json: %1");
        trl::register_en("压缩包条目过多：%1",
                         "Too Many Zip Entries: %1");
        trl::register_en("不安全的压缩包条目：%1",
                         "Unsafe Zip Entry: %1");
        trl::register_en("压缩包条目过大：%1",
                         "Zip Entry Too Large: %1");
        trl::register_en("压缩包内容过大",
                         "Zip Content Too Large");
        trl::register_en("解压失败：%1",
                         "Extract Failed: %1");
        trl::register_en("压缩包读取错误",
                         "Zip Read Error");
        trl::register_en("不是有效的 zip 文件：%1",
                         "Not a Valid Zip File: %1");
    }
};
const I18nRegPluginMarket g_i18n_reg_plugin_market;
}  // namespace

namespace {

QString meta_path(const QString& plugin_dir) {
    return QDir(plugin_dir).filePath(QStringLiteral("meta.json"));
}

/// 插件安装目录是否可写(目录不存在时向上找已存在的父目录判断)
bool install_dir_writable() {
    const QString base =
        QDir(PluginMarket::default_install_dir()).absolutePath();
    QDir d(base);
    if (d.exists()) return QFileInfo(base).isWritable();
    QDir parent(base);
    while (!parent.exists() && parent.cdUp()) {
    }
    return QFileInfo(parent.absolutePath()).isWritable();
}

#ifdef Q_OS_LINUX
/// pkexec(PolicyKit 图形鉴权)是否可用
bool pkexec_available() {
    return !QStandardPaths::findExecutable(QStringLiteral("pkexec")).isEmpty();
}

/// 以提权方式部署插件: mkdir -p base && rm -rf dest && mv staged dest
/// 路径均以 sh 位置参数传递,避免 shell 注入
bool pkexec_deploy(const QString& base_dir, const QString& dest_dir,
                   const QString& staged_dir, QString* err) {
    if (!pkexec_available()) {
        if (err)
            *err = trl::L("无写权限：%1，且未找到 pkexec；请以 root 运行或安装到可写位置")
                       .arg(base_dir);
        return false;
    }
    QProcess proc;
    proc.start(
        QStringLiteral("pkexec"),
        QStringList()
            << QStringLiteral("sh") << QStringLiteral("-c")
            << QStringLiteral("mkdir -p \"$0\" && rm -rf \"$1\" && mv \"$2\" \"$1\"")
            << base_dir << dest_dir << staged_dir);
    proc.waitForFinished(180000);  // 等用户完成鉴权,给足时间
    if (proc.exitStatus() != QProcess::NormalExit || proc.exitCode() != 0) {
        if (err) {
            const QString se =
                QString::fromLocal8Bit(proc.readAllStandardError()).trimmed();
            *err = trl::L("提权安装失败") +
                   (se.isEmpty() ? QString() : QStringLiteral(": ") + se);
        }
        return false;
    }
    return true;
}

/// 以提权方式删除目录(pkexec rm -rf,路径以参数传递)
bool pkexec_remove(const QString& target_dir, QString* err) {
    if (!pkexec_available()) {
        if (err)
            *err = trl::L("无写权限，且未找到 pkexec");
        return false;
    }
    QProcess proc;
    proc.start(QStringLiteral("pkexec"),
               QStringList() << QStringLiteral("rm") << QStringLiteral("-rf")
                             << target_dir);
    proc.waitForFinished(180000);
    if (proc.exitStatus() != QProcess::NormalExit || proc.exitCode() != 0) {
        if (err) *err = trl::L("提权卸载失败");
        return false;
    }
    return true;
}

/// 以提权方式写文件:内容经 stdin 传入 pkexec sh -c 'cat > "$0"'
bool pkexec_write_file(const QString& path, const QByteArray& data,
                       QString* err) {
    if (!pkexec_available()) {
        if (err)
            *err = trl::L("无写权限，且未找到 pkexec");
        return false;
    }
    QProcess proc;
    proc.start(QStringLiteral("pkexec"),
               QStringList() << QStringLiteral("sh") << QStringLiteral("-c")
                             << QStringLiteral("cat > \"$0\"") << path);
    proc.write(data);
    proc.closeWriteChannel();
    proc.waitForFinished(180000);
    if (proc.exitStatus() != QProcess::NormalExit || proc.exitCode() != 0) {
        if (err) *err = trl::L("提权写入失败：%1").arg(path);
        return false;
    }
    return true;
}
#endif  // Q_OS_LINUX

bool copy_dir_recursive(const QString& src, const QString& dst, QString* err) {
    QDir s(src);
    if (!QDir().mkpath(dst)) {
        if (err) *err = trl::L("无法创建目录：%1").arg(dst);
        return false;
    }
    for (const QString& e : s.entryList(QDir::Dirs | QDir::NoDotAndDotDot)) {
        if (!copy_dir_recursive(s.absoluteFilePath(e),
                                QDir(dst).absoluteFilePath(e), err))
            return false;
    }
    for (const QString& e : s.entryList(QDir::Files)) {
        const QString from = s.absoluteFilePath(e);
        const QString to = QDir(dst).absoluteFilePath(e);
        QFile::remove(to);
        if (!QFile::copy(from, to)) {
            if (err) *err = trl::L("复制失败：%1").arg(from);
            return false;
        }
    }
    return true;
}

}  // namespace

PluginMarket::PluginMarket(QObject* parent) : QObject(parent) {
    m_nam = new QNetworkAccessManager(this);
}

PluginMarket::~PluginMarket() = default;

QString PluginMarket::default_install_dir() {
    // 插件包总目录:主程序安装目录下的 plugins/ 子目录(与随程序分发的
    // 插件同目录,统一由 load_plugin_dirs 扫描;per-user 安装目录可写,无需 UAC)。
    return QCoreApplication::applicationDirPath() + QStringLiteral("/plugins");
}

QString PluginMarket::default_feed_url() {
    // BPLC_MARKET_FEED_URL:开发/测试覆盖远端 feed 地址(支持 file://)
    const QByteArray env = qgetenv("BPLC_MARKET_FEED_URL");
    if (!env.isEmpty()) return QString::fromLocal8Bit(env);
    return QStringLiteral("https://raw.githubusercontent.com/aron566/"
                          "BPLC_Plugin_Market/main/market.json");
}

QString PluginMarket::resolve_market_url(const QString& url,
                                          const QString& mirror_prefix) {
    const QString scheme = QUrl(url).scheme().toLower();
    if (mirror_prefix.isEmpty() ||
        (scheme != QStringLiteral("http") && scheme != QStringLiteral("https")) ||
        url.startsWith(mirror_prefix))
        return url;
    return mirror_prefix + url;
}

void PluginMarket::fetch_feed(const QString& url) {
    // 同应用更新共用区域识别/镜像探活策略;市场 feed 用顶层 plugins 键校验。
    auto* resolver = new UpdateMirrorResolver(this);
    connect(resolver, &UpdateMirrorResolver::resolved, this,
            [this, resolver, url](const QString& effective_url,
                                  const QString& mirror_prefix) {
        resolver->deleteLater();
        QNetworkRequest req{QUrl(effective_url)};
        req.setHeader(QNetworkRequest::UserAgentHeader,
                      QStringLiteral("BPLC_STA_Monitor/") +
                          QCoreApplication::applicationVersion());
        QNetworkReply* rep = m_nam->get(req);
        netcap::cap_reply_size(rep, netcap::kMaxManifestBytes);
        connect(rep, &QNetworkReply::finished, this,
                [this, rep, url, mirror_prefix]() {
            rep->deleteLater();
            if (netcap::size_exceeded(rep)) {
                emit feed_error(trl::L("插件列表超出大小上限"));
                return;
            }
            if (rep->error() != QNetworkReply::NoError) {
                emit feed_error(rep->errorString());
                return;
            }
            QString err;
            const QList<MarketPlugin> plugins =
                parse_feed(rep->readAll(), &err, url, mirror_prefix);
            if (!err.isEmpty()) emit feed_error(err);
            else emit feed_ready(plugins);
        });
    });
    resolver->resolve(url, QStringLiteral("plugins"));
}

/// @brief 拉取任意文本(README markdown 等,异步,经 text_ready/text_error)
void PluginMarket::fetch_text(const QString& url,
                               const QString& mirror_prefix) {
    const QString request_url = resolve_market_url(url, mirror_prefix);
    QNetworkReply* rep = m_nam->get(QNetworkRequest(QUrl(request_url)));
    netcap::cap_reply_size(rep, netcap::kMaxManifestBytes);
    connect(rep, &QNetworkReply::finished, this, [this, rep, url]() {
        rep->deleteLater();
        if (netcap::size_exceeded(rep)) {
            emit text_error(url, trl::L("文本超出大小上限"));
            return;
        }
        if (rep->error() != QNetworkReply::NoError) {
            emit text_error(url, rep->errorString());
            return;
        }
        emit text_ready(url, QString::fromUtf8(rep->readAll()));
    });
}

QList<MarketPlugin> PluginMarket::parse_feed(const QByteArray& json,
                                             QString* err,
                                             const QString& source_url,
                                             const QString& mirror_prefix) {
    QList<MarketPlugin> out;
    QJsonParseError pe;
    const QJsonDocument doc = QJsonDocument::fromJson(json, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
        if (err) *err = trl::L("插件列表解析错误：%1").arg(pe.errorString());
        return out;
    }
    const QJsonObject root = doc.object();
    for (const QJsonValue& pv : root.value(QStringLiteral("plugins")).toArray()) {
        const QJsonObject o = pv.toObject();
        MarketPlugin p;
        p.name = o.value(QStringLiteral("name")).toString();
        p.display_name = o.value(QStringLiteral("display_name")).toString();
        p.display_name_en = o.value(QStringLiteral("display_name_en")).toString();
        p.description = o.value(QStringLiteral("description")).toString();
        p.description_en = o.value(QStringLiteral("description_en")).toString();
        p.category = o.value(QStringLiteral("category")).toString();
        p.author = o.value(QStringLiteral("author")).toString();
        p.readme_url = o.value(QStringLiteral("readme_url")).toString();
        p.source = source_url;
        p.mirror_prefix = mirror_prefix;
        for (const QJsonValue& vv :
             o.value(QStringLiteral("versions")).toArray()) {
            const QJsonObject vo = vv.toObject();
            MarketVersion v;
            v.version = vo.value(QStringLiteral("version")).toString();
            v.url = vo.value(QStringLiteral("url")).toString();
            v.sha256 = vo.value(QStringLiteral("sha256")).toString().toLower();
            v.size = qint64(vo.value(QStringLiteral("size")).toDouble());
            v.min_app_version =
                vo.value(QStringLiteral("min_app_version")).toString();
            v.updated_at = vo.value(QStringLiteral("updated_at")).toString();
            for (const QJsonValue& pv :
                 vo.value(QStringLiteral("platforms")).toArray())
                v.platforms.append(pv.toString());
            // feed 的 abi 可为字符串(单平台)或按平台对象,与 plugin.json 一致;
            // 解析为当前平台的值
            {
                const QJsonValue abi_v = vo.value(QStringLiteral("abi"));
                if (abi_v.isObject())
                    v.abi = abi_v.toObject()
                                .value(current_platform())
                                .toString();
                else
                    v.abi = abi_v.toString();
            }
            p.versions.append(v);
        }
        if (!p.name.isEmpty() && !p.versions.isEmpty()) out.append(p);
    }
    return out;
}

void PluginMarket::install_market_plugin(const MarketPlugin& plugin,
                                         int version_index) {
    if (version_index < 0 || version_index >= plugin.versions.size()) {
        emit install_finished(false, trl::L("版本索引无效"),
                              plugin.name);
        return;
    }
    const MarketVersion& v = plugin.versions[version_index];
    if (!version_platform_ok(v)) {
        emit install_finished(
            false,
            trl::L("版本 %1 不支持当前平台（%2）")
                .arg(v.version, current_platform()),
            plugin.name);
        return;
    }
    if (!app_version_ok(v.min_app_version)) {
        emit install_finished(
            false,
            trl::L("需要主程序版本 >= %1（当前 %2）")
                .arg(v.min_app_version,
                     QCoreApplication::applicationVersion()),
            plugin.name);
        return;
    }
    if (!version_abi_ok(v)) {
        emit install_finished(
            false,
            QStringLiteral("ABI mismatch: plugin %1, host %2")
                .arg(v.abi.isEmpty() ? QStringLiteral("(none)") : v.abi,
                     plugin_host_abi()),
            plugin.name);
        return;
    }
    // 完整性:市场包必须带 sha256(64 位 hex),缺失/格式错一律拒装,不再静默跳过校验
    if (!is_sha256_hex(v.sha256)) {
        emit install_finished(
            false,
            trl::L("插件列表中 %1 %2 没有有效的 SHA-256，拒绝安装未校验的安装包")
                .arg(plugin.name, v.version),
            plugin.name);
        return;
    }
    InstallContext ctx;
    ctx.name = plugin.name;
    ctx.sha256 = v.sha256;
    ctx.source = plugin.source.isEmpty() ? default_feed_url() : plugin.source;
    ctx.updated_at = v.updated_at;
    const QString package_url = resolve_market_url(v.url, plugin.mirror_prefix);
    emit install_progress(trl::L("正在下载 %1").arg(package_url));
    QNetworkReply* rep = m_nam->get(QNetworkRequest(QUrl(package_url)));
    netcap::cap_reply_size(rep, netcap::kMaxPluginPackageBytes);
    // 安装上下文按值捕获:另一个安装同时进行也不会改写本请求的名字/sha256
    connect(rep, &QNetworkReply::finished, this, [this, rep, ctx]() {
        rep->deleteLater();
        if (netcap::size_exceeded(rep)) {
            emit install_finished(false,
                                  trl::L("安装包超出大小上限"),
                                  ctx.name);
            return;
        }
        if (rep->error() != QNetworkReply::NoError) {
            emit install_finished(false, rep->errorString(), ctx.name);
            return;
        }
        QTemporaryDir tmp;
        if (!tmp.isValid()) {
            emit install_finished(false, trl::L("无法创建临时目录"), ctx.name);
            return;
        }
        const QString zip_path =
            tmp.path() + QStringLiteral("/pkg.zip");
        const QByteArray data = rep->readAll();
        QFile f(zip_path);
        // 用 data.size()(实际读到的字节数)而非 rep->size()(Content-Length):
        // QNAM 自动解压 gzip 后,readAll() 大小与 Content-Length 可能不等,
        // 且 chunked 响应 size() 为 -1,都会导致误判 write temp failed。
        if (data.isEmpty() || !f.open(QIODevice::WriteOnly) ||
            f.write(data) != data.size()) {
            emit install_finished(false, trl::L("写入临时文件失败"),
                                  ctx.name);
            return;
        }
        f.close();
        finish_install_from_zip(zip_path, ctx);
    });
}

void PluginMarket::install_from_file(const QString& zip_path) {
    InstallContext ctx;
    ctx.source = QStringLiteral("file");
    ctx.updated_at =
        QFileInfo(zip_path).lastModified().toUTC().toString(Qt::ISODate);
    // 先解包读清单拿到插件名(离线包无 feed,不做 sha256 校验)
    QTemporaryDir tmp;
    if (!tmp.isValid()) {
        emit install_finished(false, trl::L("无法创建临时目录"), QString());
        return;
    }
    const QString staged = tmp.path() + QStringLiteral("/staged");
    QString err;
    if (!unzip_to_dir(zip_path, staged, &err)) {
        emit install_finished(false, err, QString());
        return;
    }
    const PluginManifest m = read_plugin_manifest(staged);
    if (!m.valid) {
        emit install_finished(false, m.error, QString());
        return;
    }
    ctx.name = m.name;
    finish_install_from_zip(zip_path, ctx);
}

void PluginMarket::finish_install_from_zip(const QString& zip_path,
                                           const InstallContext& ctx) {
    const QString& name = ctx.name;
    const QString& expected_sha256 = ctx.sha256;
    // 市场安装已在 install_market_plugin 保证 expected_sha256 非空;
    // 仅离线安装(install_from_file,用户自选本地包)不带 sha256
    if (!expected_sha256.isEmpty() &&
        !verify_sha256(zip_path, expected_sha256)) {
        emit install_finished(false,
                              trl::L("SHA-256 不匹配，安装包已拒收"),
                              name);
        return;
    }
    QTemporaryDir tmp;
    if (!tmp.isValid()) {
        emit install_finished(false, trl::L("无法创建临时目录"), name);
        return;
    }
    const QString staged = tmp.path() + QStringLiteral("/staged");
    QString err;
    if (!unzip_to_dir(zip_path, staged, &err)) {
        emit install_finished(false, err, name);
        return;
    }
    const PluginManifest m = read_plugin_manifest(staged);
    if (!m.valid) {
        emit install_finished(false, m.error, name);
        return;
    }
    if (!name.isEmpty() && m.name != name) {
        emit install_finished(
            false, trl::L("安装包名称不匹配：%1").arg(m.name), name);
        return;
    }
    if (deploy_staged(staged, m.name, ctx, &err)) {
        emit install_progress(trl::L("已安装 %1 %2").arg(m.name, m.version));
        emit install_finished(true, QString(), m.name);
    } else {
        emit install_finished(false, err, m.name);
    }
}

QString PluginMarket::plugin_dir_path(const QString& base_dir,
                                      const QString& name) {
    // 白名单:单级目录名,不含分隔符/盘符,不是 "." / ".."
    if (!plugin_name_is_safe(name)) return QString();
    // QDir::absoluteFilePath 不规范化 "..",必须 cleanPath 后再比较
    const QString base = QDir::cleanPath(QDir(base_dir).absolutePath());
    const QString dest = QDir::cleanPath(base + QLatin1Char('/') + name);
    if (!dest.startsWith(base + QLatin1Char('/')) ||
        QFileInfo(dest).absolutePath() != base)
        return QString();  // 只能是 base 的一级子目录
    // 已存在(含符号链接):真实路径也必须是安装根的一级子目录,
    // 防止覆盖安装/卸载时 removeRecursively 跟随链接删到目录外
    const QFileInfo fi(dest);
    if (fi.exists() || fi.isSymLink()) {
        const QString cbase = QFileInfo(base).canonicalFilePath();
        const QString cdest = fi.canonicalFilePath();
        if (cbase.isEmpty() || cdest.isEmpty() ||
            QFileInfo(cdest).absolutePath() != cbase)
            return QString();
    }
    return dest;
}

bool PluginMarket::deploy_staged(const QString& staged_dir,
                                 const QString& plugin_name,
                                 const InstallContext& ctx, QString* err) {
    const QString base = QDir::cleanPath(QDir(default_install_dir()).absolutePath());
    // 路径穿越防护:目标必须是安装目录下的一级子目录
    const QString dest = plugin_dir_path(base, plugin_name);
    if (dest.isEmpty()) {
        if (err) *err = trl::L("插件名称不安全：%1").arg(plugin_name);
        return false;
    }
    // meta.json 先写进 staged:提权路径只需一次文件移动,无需提权后二次写文件
    if (!write_meta_json(staged_dir, ctx, err)) return false;

    // 卸载放到真正改动安装目录之前的最后一刻(释放 native DLL 文件锁,Windows
    // 删不掉被加载的 dll);此后任何失败都重新加载,插件不停在卸载状态
    auto fail_and_reload = [this]() {
        if (reload_cb) reload_cb();
        return false;
    };
    if (!install_dir_writable()) {
#ifdef Q_OS_LINUX
        // Linux: 安装目录不可写时请求提权(pkexec 弹出图形鉴权框)
        emit install_progress(
            trl::L("正在请求管理员权限..."));
        if (unload_cb) unload_cb();
        if (!pkexec_deploy(base, dest, staged_dir, err)) return fail_and_reload();
        return true;
#else
        if (err)
            *err = trl::L("无写权限：%1；请以管理员身份运行或选择可写位置").arg(base);
        return false;
#endif
    }

    if (unload_cb) unload_cb();
    // 备份旧版:先删目标再拷贝(同名覆盖=升级)
    QDir d(dest);
    if (d.exists()) {
        if (!d.removeRecursively()) {
            if (err) *err = trl::L("无法删除旧版本：%1").arg(dest);
            return fail_and_reload();
        }
    }
    if (!copy_dir_recursive(staged_dir, dest, err)) return fail_and_reload();
    return true;
}

/// 写 meta.json(默认启用,记录来源与版本更新时间)
bool PluginMarket::write_meta_json(const QString& plugin_dir,
                                   const InstallContext& ctx, QString* err) {
    QFile mf(meta_path(plugin_dir));
    if (!mf.open(QIODevice::WriteOnly)) {
        if (err)
            *err = trl::L("无法写入 meta.json：%1").arg(plugin_dir);
        return false;
    }
    mf.write(QJsonDocument(QJsonObject{
                               {QStringLiteral("enabled"), true},
                               {QStringLiteral("installed_at"),
                                QDateTime::currentDateTimeUtc().toString(Qt::ISODate)},
                               {QStringLiteral("source"), ctx.source},
                               {QStringLiteral("updated_at"), ctx.updated_at},
                           })
                 .toJson());
    return true;
}

QList<InstalledPlugin> PluginMarket::installed_plugins() const {
    QList<InstalledPlugin> out;
    const QDir d(default_install_dir());
    for (const QString& name :
         d.entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name)) {
        const QString pdir = d.absoluteFilePath(name);
        const PluginManifest m = read_plugin_manifest(pdir);
        if (!m.valid) continue;
        InstalledPlugin ip;
        ip.manifest = m;
        ip.enabled = plugin_dir_enabled(pdir);
        ip.dir = pdir;
        QFile mf(meta_path(pdir));
        if (mf.open(QIODevice::ReadOnly)) {
            const QJsonObject mo =
                QJsonDocument::fromJson(mf.readAll()).object();
            ip.source = mo.value(QStringLiteral("source")).toString();
            ip.installed_at =
                mo.value(QStringLiteral("installed_at")).toString();
            ip.updated_at = mo.value(QStringLiteral("updated_at")).toString();
        }
        out.append(ip);
    }
    return out;
}

bool PluginMarket::set_enabled(const QString& name, bool enabled) {
    // 路径穿越防护:与 deploy_staged/uninstall 共用 plugin_dir_path
    const QString pdir = plugin_dir_path(default_install_dir(), name);
    if (pdir.isEmpty()) return false;
    if (!QDir(pdir).exists()) return false;
    QFile mf(meta_path(pdir));
    QJsonObject o;
    if (mf.exists() && mf.open(QIODevice::ReadOnly)) {
        o = QJsonDocument::fromJson(mf.readAll()).object();
        mf.close();
    }
    o[QStringLiteral("enabled")] = enabled;
    const QByteArray data = QJsonDocument(o).toJson();
#ifdef Q_OS_LINUX
    // Linux: 提权安装的插件 meta.json 属 root,不可写时提权重写
    if (!QFileInfo(mf.fileName()).isWritable() && !install_dir_writable()) {
        QString err;
        return pkexec_write_file(mf.fileName(), data, &err);
    }
#endif
    if (!mf.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    mf.write(data);
    return true;
}

bool PluginMarket::uninstall(const QString& name) {
    // 路径穿越防护:name 必须是单级目录名(与 deploy_staged/set_enabled 共用)
    const QString pdir = plugin_dir_path(default_install_dir(), name);
    if (pdir.isEmpty()) return false;
    if (!QDir(pdir).exists()) return false;
    // 先卸载插件释放 native DLL 文件锁(Windows 删不掉被加载的 dll)
    if (unload_cb) unload_cb();
    bool ok = false;
#ifdef Q_OS_LINUX
    // Linux: 安装目录不可写时请求提权删除
    if (!install_dir_writable()) {
        QString err;
        ok = pkexec_remove(pdir, &err);
    } else
#endif
    ok = QDir(pdir).removeRecursively();
    if (!ok && reload_cb) reload_cb();   // 删除失败:恢复加载,插件不停在卸载状态
    return ok;
}

const MarketVersion* PluginMarket::update_for(
    const InstalledPlugin& inst, const QList<MarketPlugin>& feed) {
    for (const MarketPlugin& p : feed) {
        if (p.name != inst.manifest.name) continue;
        const MarketVersion* lat = p.latest_compatible();
        if (lat && compare_version(lat->version, inst.manifest.version) > 0)
            return lat;
        return nullptr;
    }
    return nullptr;
}

bool PluginMarket::is_sha256_hex(const QString& s) {
    if (s.size() != 64) return false;
    for (const QChar c : s) {
        const bool hex = (c >= QLatin1Char('0') && c <= QLatin1Char('9')) ||
                         (c >= QLatin1Char('a') && c <= QLatin1Char('f')) ||
                         (c >= QLatin1Char('A') && c <= QLatin1Char('F'));
        if (!hex) return false;
    }
    return true;
}

bool PluginMarket::verify_sha256(const QString& file_path,
                                 const QString& expected_hex) {
    QFile f(file_path);
    if (!f.open(QIODevice::ReadOnly)) return false;
    QCryptographicHash h(QCryptographicHash::Sha256);
    if (!h.addData(&f)) return false;
    return h.result().toHex() == expected_hex.toLower().toLatin1();
}

QString PluginMarket::safe_extract_path(const QString& dest_dir,
                                        const QString& entry_name) {
    // zip 条目名一律视为不可信:规范要求 '/' 分隔,出现 '\\' 直接拒绝
    // (Windows 上 "\\Windows\\x"、"\\\\server\\share\\x" 都是绝对/UNC 路径)
    if (entry_name.isEmpty() || entry_name.contains(QLatin1Char('\\')) ||
        entry_name.contains(QLatin1Char(':')) ||          // 盘符 C:/x、C:x 与 ADS
        entry_name.startsWith(QLatin1Char('/')) ||
        QDir::isAbsolutePath(entry_name) ||
        entry_name.contains(QChar(0)))
        return QString();
    for (const QString& part : entry_name.split(QLatin1Char('/')))
        if (part == QStringLiteral("..")) return QString();
    const QString base = QDir::cleanPath(QDir(dest_dir).absolutePath());
    const QString out = QDir::cleanPath(base + QLatin1Char('/') + entry_name);
    if (!out.startsWith(base + QLatin1Char('/'))) return QString();
    return out;
}

namespace {
/// 解包上限(zip 炸弹防护):单条目 64 MB、总量 256 MB、条目数 4096
constexpr mz_uint64 kZipMaxEntryBytes = 64ull * 1024 * 1024;
constexpr mz_uint64 kZipMaxTotalBytes = 256ull * 1024 * 1024;
constexpr mz_uint kZipMaxEntries = 4096;

/// 解压写回调:实际写出字节数不得超过中央目录声明的大小(防声明值作假)
struct CappedFileWriter {
    QFile* file;
    mz_uint64 limit;
    mz_uint64 written;
};
size_t capped_file_write(void* opaque, mz_uint64 ofs, const void* buf, size_t n) {
    auto* w = static_cast<CappedFileWriter*>(opaque);
    if (ofs != w->written || w->written + n > w->limit) return 0;  // 非顺序/超限 → 中止
    if (w->file->write(static_cast<const char*>(buf), qint64(n)) != qint64(n))
        return 0;
    w->written += n;
    return n;
}

/// 父目录真实路径(解析符号链接后)仍须位于解包根内
bool real_dir_inside(const QString& dir, const QString& canonical_root) {
    const QString c = QFileInfo(dir).canonicalFilePath();
    return !c.isEmpty() &&
           (c == canonical_root || c.startsWith(canonical_root + QLatin1Char('/')));
}
}  // namespace

bool PluginMarket::unzip_to_dir(const QString& zip_path,
                                const QString& dest_dir, QString* err) {
    mz_zip_archive zip;
    memset(&zip, 0, sizeof(zip));
    const QByteArray zp = zip_path.toLocal8Bit();
    if (!mz_zip_reader_init_file(&zip, zp.constData(), 0)) {
        if (err)
            *err = trl::L("不是有效的 zip 文件：%1").arg(QFileInfo(zip_path).fileName());
        return false;
    }
    const mz_uint n = mz_zip_reader_get_num_files(&zip);
    if (n > kZipMaxEntries) {
        mz_zip_reader_end(&zip);
        if (err) *err = trl::L("压缩包条目过多：%1").arg(n);
        return false;
    }
    QDir().mkpath(dest_dir);
    const QString root = QFileInfo(dest_dir).canonicalFilePath();
    bool ok = !root.isEmpty();
    if (!ok && err) *err = trl::L("无法创建目录：%1").arg(dest_dir);
    // 先按中央目录校验全部条目(路径 + 声明大小),全部通过才开始写盘
    mz_uint64 total = 0;
    for (mz_uint i = 0; i < n && ok; ++i) {
        mz_zip_archive_file_stat st;
        if (!mz_zip_reader_file_stat(&zip, i, &st)) {
            ok = false;
            break;
        }
        const QString rel = QString::fromUtf8(st.m_filename);
        // 防 zip-slip:绝对路径/盘符/UNC/反斜杠/".." 组件一律拒绝
        if (safe_extract_path(dest_dir, rel).isEmpty()) {
            ok = false;
            if (err) *err = trl::L("不安全的压缩包条目：%1").arg(rel);
            break;
        }
        if (st.m_uncomp_size > kZipMaxEntryBytes) {
            ok = false;
            if (err) *err = trl::L("压缩包条目过大：%1").arg(rel);
            break;
        }
        total += st.m_uncomp_size;
        if (total > kZipMaxTotalBytes) {
            ok = false;
            if (err) *err = trl::L("压缩包内容过大");
            break;
        }
    }
    for (mz_uint i = 0; i < n && ok; ++i) {
        mz_zip_archive_file_stat st;
        if (!mz_zip_reader_file_stat(&zip, i, &st)) {
            ok = false;
            break;
        }
        const QString rel = QString::fromUtf8(st.m_filename);
        const QString out_path = safe_extract_path(dest_dir, rel);
        const QString out_dir = mz_zip_reader_is_file_a_directory(&zip, i)
                                    ? out_path
                                    : QFileInfo(out_path).absolutePath();
        QDir().mkpath(out_dir);
        if (!real_dir_inside(out_dir, root)) {
            ok = false;
            if (err) *err = trl::L("不安全的压缩包条目：%1").arg(rel);
            break;
        }
        if (mz_zip_reader_is_file_a_directory(&zip, i)) continue;
        QFile out(out_path);
        if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            ok = false;
            if (err) *err = trl::L("解压失败：%1").arg(rel);
            break;
        }
        CappedFileWriter w{&out, st.m_uncomp_size, 0};
        if (!mz_zip_reader_extract_to_callback(&zip, i, capped_file_write, &w, 0) ||
            w.written != st.m_uncomp_size) {
            ok = false;
            if (err) *err = trl::L("解压失败：%1").arg(rel);
        }
    }
    mz_zip_reader_end(&zip);
    if (!ok && err && err->isEmpty())
        *err = trl::L("压缩包读取错误");
    return ok;
}

int PluginMarket::compare_version(const QString& a, const QString& b) {
    const auto pa = a.split(QLatin1Char('.'));
    const auto pb = b.split(QLatin1Char('.'));
    const int n = qMax(pa.size(), pb.size());
    for (int i = 0; i < n; ++i) {
        const int va = i < pa.size() ? pa[i].toInt() : 0;
        const int vb = i < pb.size() ? pb[i].toInt() : 0;
        if (va != vb) return va < vb ? -1 : 1;
    }
    return 0;
}

bool PluginMarket::app_version_ok(const QString& min_app_version) {
    if (min_app_version.isEmpty()) return true;
    return compare_version(QCoreApplication::applicationVersion(),
                           min_app_version) >= 0;
}

bool PluginMarket::plugin_dir_enabled(const QString& plugin_dir) {
    QFile mf(meta_path(plugin_dir));
    if (!mf.open(QIODevice::ReadOnly)) return true;  // 无 meta.json=启用
    const QJsonObject o = QJsonDocument::fromJson(mf.readAll()).object();
    return o.value(QStringLiteral("enabled")).toBool(true);
}

QString PluginMarket::current_platform() {
    // 与 plugin.json 按平台 abi 的解析共用同一实现(按编译目标架构区分
    // x86_64 / arm64,如 windows-arm64 / linux-arm64)
    return plugin_host_platform();
}

bool PluginMarket::version_platform_ok(const MarketVersion& v) {
    if (v.platforms.isEmpty()) return true;  // 未标注=全平台(脚本插件)
    return v.platforms.contains(current_platform());
}

bool PluginMarket::version_abi_ok(const MarketVersion& v) {
    if (v.abi.isEmpty()) return true;  // 未标注=脚本插件(ABI 无关)
    return v.abi == plugin_host_abi();
}

const MarketVersion* MarketPlugin::latest_compatible() const {
    for (int i = versions.size() - 1; i >= 0; --i) {
        if (PluginMarket::version_platform_ok(versions[i]) &&
            PluginMarket::version_abi_ok(versions[i]))
            return &versions[i];
    }
    return nullptr;
}
