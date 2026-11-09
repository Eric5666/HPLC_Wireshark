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

#include "miniz.h"  // 3rdparty/miniz, public domain, zip 解包
#include "updatemirror.h"

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
            *err = QStringLiteral("no write permission for ") + base_dir +
                   QStringLiteral(", and pkexec not found;"
                                  " run as root or install to a writable location");
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
            *err = QStringLiteral("privileged install failed") +
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
            *err = QStringLiteral("no write permission, and pkexec not found");
        return false;
    }
    QProcess proc;
    proc.start(QStringLiteral("pkexec"),
               QStringList() << QStringLiteral("rm") << QStringLiteral("-rf")
                             << target_dir);
    proc.waitForFinished(180000);
    if (proc.exitStatus() != QProcess::NormalExit || proc.exitCode() != 0) {
        if (err) *err = QStringLiteral("privileged uninstall failed");
        return false;
    }
    return true;
}

/// 以提权方式写文件:内容经 stdin 传入 pkexec sh -c 'cat > "$0"'
bool pkexec_write_file(const QString& path, const QByteArray& data,
                       QString* err) {
    if (!pkexec_available()) {
        if (err)
            *err = QStringLiteral("no write permission, and pkexec not found");
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
        if (err) *err = QStringLiteral("privileged write failed: ") + path;
        return false;
    }
    return true;
}
#endif  // Q_OS_LINUX

bool copy_dir_recursive(const QString& src, const QString& dst, QString* err) {
    QDir s(src);
    if (!QDir().mkpath(dst)) {
        if (err) *err = QStringLiteral("cannot create dir: ") + dst;
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
            if (err) *err = QStringLiteral("copy failed: ") + from;
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
        connect(rep, &QNetworkReply::finished, this,
                [this, rep, url, mirror_prefix]() {
            rep->deleteLater();
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
    connect(rep, &QNetworkReply::finished, this, [this, rep, url]() {
        rep->deleteLater();
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
        if (err) *err = QStringLiteral("feed parse error: ") + pe.errorString();
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
        emit install_finished(false, QStringLiteral("bad version index"),
                              plugin.name);
        return;
    }
    const MarketVersion& v = plugin.versions[version_index];
    if (!version_platform_ok(v)) {
        emit install_finished(
            false,
            QStringLiteral("version %1 does not support this platform (%2)")
                .arg(v.version, current_platform()),
            plugin.name);
        return;
    }
    if (!app_version_ok(v.min_app_version)) {
        emit install_finished(
            false,
            QStringLiteral("requires app >= %1 (current %2)")
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
    m_pending_name = plugin.name;
    m_pending_sha256 = v.sha256;
    m_pending_source =
        plugin.source.isEmpty() ? default_feed_url() : plugin.source;
    m_pending_updated_at = v.updated_at;
    const QString package_url = resolve_market_url(v.url, plugin.mirror_prefix);
    emit install_progress(QStringLiteral("downloading ") + package_url);
    QNetworkReply* rep = m_nam->get(QNetworkRequest(QUrl(package_url)));
    connect(rep, &QNetworkReply::finished, this, [this, rep]() {
        rep->deleteLater();
        if (rep->error() != QNetworkReply::NoError) {
            emit install_finished(false, rep->errorString(), m_pending_name);
            return;
        }
        QTemporaryDir tmp;
        if (!tmp.isValid()) {
            emit install_finished(false, QStringLiteral("no temp dir"),
                                  m_pending_name);
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
            emit install_finished(false, QStringLiteral("write temp failed"),
                                  m_pending_name);
            return;
        }
        f.close();
        finish_install_from_zip(zip_path, m_pending_sha256);
    });
}

void PluginMarket::install_from_file(const QString& zip_path) {
    m_pending_name.clear();
    m_pending_sha256.clear();
    m_pending_source = QStringLiteral("file");
    m_pending_updated_at =
        QFileInfo(zip_path).lastModified().toUTC().toString(Qt::ISODate);
    // 先解包读清单拿到插件名(离线包无 feed,不做 sha256 校验)
    QTemporaryDir tmp;
    if (!tmp.isValid()) {
        emit install_finished(false, QStringLiteral("no temp dir"), QString());
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
    m_pending_name = m.name;
    finish_install_from_zip(zip_path, QString());
}

void PluginMarket::finish_install_from_zip(const QString& zip_path,
                                           const QString& expected_sha256) {
    const QString name = m_pending_name;
    if (!expected_sha256.isEmpty() &&
        !verify_sha256(zip_path, expected_sha256)) {
        emit install_finished(false,
                              QStringLiteral("sha256 mismatch, package "
                                             "rejected"),
                              name);
        return;
    }
    QTemporaryDir tmp;
    if (!tmp.isValid()) {
        emit install_finished(false, QStringLiteral("no temp dir"), name);
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
            false, QStringLiteral("package name mismatch: ") + m.name, name);
        return;
    }
    if (deploy_staged(staged, m.name, &err)) {
        emit install_progress(QStringLiteral("installed ") + m.name + " " +
                              m.version);
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
                                 const QString& plugin_name, QString* err) {
    const QString base = QDir::cleanPath(QDir(default_install_dir()).absolutePath());
    // 路径穿越防护:目标必须是安装目录下的一级子目录
    const QString dest = plugin_dir_path(base, plugin_name);
    if (dest.isEmpty()) {
        if (err) *err = QStringLiteral("unsafe plugin name: ") + plugin_name;
        return false;
    }
    // 先卸载插件释放 native DLL 文件锁(Windows 删不掉被加载的 dll)
    if (unload_cb) unload_cb();
    // meta.json 先写进 staged:提权路径只需一次文件移动,无需提权后二次写文件
    if (!write_meta_json(staged_dir, err)) return false;

    if (!install_dir_writable()) {
#ifdef Q_OS_LINUX
        // Linux: 安装目录不可写时请求提权(pkexec 弹出图形鉴权框)
        emit install_progress(
            QStringLiteral("requesting administrator privileges..."));
        return pkexec_deploy(base, dest, staged_dir, err);
#else
        if (err)
            *err = QStringLiteral("no write permission for ") + base +
                   QStringLiteral("; run as administrator or choose a writable location");
        return false;
#endif
    }

    // 备份旧版:先删目标再拷贝(同名覆盖=升级)
    QDir d(dest);
    if (d.exists()) {
        if (!d.removeRecursively()) {
            if (err) *err = QStringLiteral("cannot remove old version: ") + dest;
            return false;
        }
    }
    if (!copy_dir_recursive(staged_dir, dest, err)) return false;
    return true;
}

/// 写 meta.json(默认启用,记录来源与版本更新时间)
bool PluginMarket::write_meta_json(const QString& plugin_dir, QString* err) {
    QFile mf(meta_path(plugin_dir));
    if (!mf.open(QIODevice::WriteOnly)) {
        if (err)
            *err = QStringLiteral("cannot write meta.json: ") + plugin_dir;
        return false;
    }
    mf.write(QJsonDocument(QJsonObject{
                               {QStringLiteral("enabled"), true},
                               {QStringLiteral("installed_at"),
                                QDateTime::currentDateTimeUtc().toString(Qt::ISODate)},
                               {QStringLiteral("source"), m_pending_source},
                               {QStringLiteral("updated_at"), m_pending_updated_at},
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
#ifdef Q_OS_LINUX
    // Linux: 安装目录不可写时请求提权删除
    if (!install_dir_writable()) {
        QString err;
        return pkexec_remove(pdir, &err);
    }
#endif
    return QDir(pdir).removeRecursively();
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

bool PluginMarket::verify_sha256(const QString& file_path,
                                 const QString& expected_hex) {
    QFile f(file_path);
    if (!f.open(QIODevice::ReadOnly)) return false;
    QCryptographicHash h(QCryptographicHash::Sha256);
    if (!h.addData(&f)) return false;
    return h.result().toHex() == expected_hex.toLower().toLatin1();
}

bool PluginMarket::unzip_to_dir(const QString& zip_path,
                                const QString& dest_dir, QString* err) {
    mz_zip_archive zip;
    memset(&zip, 0, sizeof(zip));
    const QByteArray zp = zip_path.toLocal8Bit();
    if (!mz_zip_reader_init_file(&zip, zp.constData(), 0)) {
        if (err)
            *err = QStringLiteral("not a valid zip: ") +
                   QFileInfo(zip_path).fileName();
        return false;
    }
    const mz_uint n = mz_zip_reader_get_num_files(&zip);
    QDir().mkpath(dest_dir);
    bool ok = true;
    for (mz_uint i = 0; i < n && ok; ++i) {
        mz_zip_archive_file_stat st;
        if (!mz_zip_reader_file_stat(&zip, i, &st)) {
            ok = false;
            break;
        }
        QString rel = QString::fromUtf8(st.m_filename);
        // 防 zip-slip:拒绝绝对路径与 ".."
        if (rel.startsWith(QLatin1Char('/')) || rel.contains(QStringLiteral(".."))) {
            ok = false;
            if (err) *err = QStringLiteral("unsafe entry: ") + rel;
            break;
        }
        const QString out_path =
            QDir(dest_dir).absoluteFilePath(rel);
        if (mz_zip_reader_is_file_a_directory(&zip, i)) {
            QDir().mkpath(out_path);
            continue;
        }
        QDir().mkpath(QFileInfo(out_path).absolutePath());
        if (!mz_zip_reader_extract_to_file(&zip, i, out_path.toLocal8Bit().constData(), 0)) {
            ok = false;
            if (err) *err = QStringLiteral("extract failed: ") + rel;
        }
    }
    mz_zip_reader_end(&zip);
    if (!ok && err && err->isEmpty())
        *err = QStringLiteral("zip read error");
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
#if defined(Q_OS_WIN)
    return QStringLiteral("windows-x86_64");
#elif defined(Q_OS_MACOS)
#if defined(Q_PROCESSOR_ARM_64)
    return QStringLiteral("macos-arm64");
#else
    return QStringLiteral("macos-x86_64");
#endif
#else
    return QStringLiteral("linux-x86_64");
#endif
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
