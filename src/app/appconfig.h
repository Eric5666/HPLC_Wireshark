/// @file appconfig.h
/// @brief 应用配置文件(config.ini,exe 同目录,Qt IniFormat)
/// @details 首次启动自动生成带注释模板;后续由本模块统一读写。
///          承载:更新检查地址、语言、串口/回放参数、显示过滤器等。
///          兼容旧注册表:仅在 config.ini 不存在且注册表有值时迁移一次。
#ifndef BPLC_APPCONFIG_H
#define BPLC_APPCONFIG_H

#include <QString>
#include <QSettings>
#include <QCoreApplication>
#include <QFile>
#include <QSet>
#include <QByteArray>

namespace appcfg {

/// @brief config.ini 完整路径(exe 同目录)
inline QString ini_path() {
    return QCoreApplication::applicationDirPath() + QStringLiteral("/config.ini");
}

/// @brief 配置文件读写句柄(IniFormat,UTF-8)
inline QSettings settings() { return QSettings(ini_path(), QSettings::IniFormat); }

/// @brief 把旧格式 ini 的保留段 [general]/[General] 及其组段 [%general] 迁移为非保留段 [app]
/// @details 背景: "General" 是 QSettings INI 的**保留默认组名**, 该段的键会被映射到
///          根级(不带组前缀) —— 故 value("general/xxx") 永远读不到, protocol/lang 等
///          8 项配置全部回退默认值(协议恒 gw_2026, 南网帧被国网解析器 DROP),
///          且用户手改 config.ini 完全无效。
///          其它任何段名([app]/[reader]/[crash])不受影响, 普通写法即可正常分组。
///          (对照实验已证伪"首段特殊"的说法: [app] 作首段照样正常分组。)
///          迁移规则:
///          · 收集 [general]/[General] 普通段与 [%general]/[%General] 组段里的全部键;
///          · 并入 [app] 段, **[app] 已有的键不覆盖**(以 [app] 为准);
///          · 删除旧的 general 相关段, 不留下 [%...] 形式的歧义段;
///          · 其它段([reader]/[crash])与注释原样保留;
///          · 迁移前自动备份 config.ini.bak; 已是 [app] 格式的文件不动(幂等)。
inline void migrate_ini_groups(const QString& path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return;
    const QByteArray data = f.readAll();
    f.close();

    const char kLf = 10;
    QList<QByteArray> lines;
    {
        int start = 0;
        while (start <= data.size()) {
            int nl = data.indexOf(kLf, start);
            if (nl < 0) { if (start < data.size()) { QByteArray tail = data.mid(start); if (tail.endsWith('\r')) tail.chop(1); lines.append(tail); } break; }
            { QByteArray line = data.mid(start, nl - start); if (line.endsWith('\r')) line.chop(1); lines.append(line); }
            start = nl + 1;
        }
    }
    // 段头识别: 段名(去掉 % 前缀) + 是否组段
    auto parse_header = [](const QByteArray& line, QByteArray* name, bool* isGroup) {
        int t = 0;
        while (t < line.size() && (line[t] == ' ' || line[t] == '\t')) ++t;
        if (t >= line.size() || line[t] != '[') return false;
        int e = line.indexOf(']', t);
        if (e < 0) return false;
        QByteArray n = line.mid(t + 1, e - t - 1).trimmed();
        if (n.isEmpty()) return false;
        *isGroup = n.startsWith('%');
        if (*isGroup) n = n.mid(1);
        *name = n;
        return true;
    };
    auto is_named = [](const QByteArray& n, const char* target) {
        return n.toLower() == QByteArray(target);
    };
    // 键名解析: "key=value" -> key; 注释/空行/段头返回空
    auto key_of = [](const QByteArray& line) {
        int t = 0;
        while (t < line.size() && (line[t] == ' ' || line[t] == '\t')) ++t;
        if (t >= line.size() || line[t] == ';' || line[t] == '#' || line[t] == '[') return QByteArray();
        int eq = line.indexOf('=', t);
        if (eq < 0) return QByteArray();
        return line.mid(t, eq - t).trimmed();
    };

    // 第一遍: 收集 general 段(普通段/组段)的内容行, 以及 [app] 段已有内容行
    QList<QByteArray> generalBody, appBody;
    bool appSeen = false;
    {
        QByteArray name; bool isGroup = false;
        int mode = 0;  // 0=其它 1=general 2=app
        for (const QByteArray& line : lines) {
            if (parse_header(line, &name, &isGroup)) {
                if (is_named(name, "general")) mode = 1;
                else if (!isGroup && is_named(name, "app")) { mode = 2; appSeen = true; }
                else mode = 0;
                continue;
            }
            if (mode == 1) generalBody.append(line);
            else if (mode == 2) appBody.append(line);
        }
    }
    if (generalBody.isEmpty()) return;   // 已是 [app] 格式或无 general 段, 无需迁移(幂等)

    // [app] 已有键名集合 —— 这些键不覆盖
    QSet<QByteArray> appKeys;
    for (const QByteArray& l : appBody) {
        const QByteArray k = key_of(l);
        if (!k.isEmpty()) appKeys.insert(k);
    }

    // 第二遍: 输出(丢弃 general 段, 把它的键并入 [app])
    QList<QByteArray> out;
    bool appWritten = false;
    {
        QByteArray name; bool isGroup = false;
        int mode = 0;
        for (const QByteArray& line : lines) {
            if (parse_header(line, &name, &isGroup)) {
                if (is_named(name, "general")) {
                    // 原文件没有 [app] 段时, 就在此处生成 [app]
                    if (!appSeen && !appWritten) {
                        out.append("[app]");
                        for (const QByteArray& l : generalBody) {
                            const QByteArray k = key_of(l);
                            if (!k.isEmpty() && appKeys.contains(k)) continue;   // [app] 优先
                            out.append(l);
                        }
                        appWritten = true;
                    }
                    mode = 1;
                    continue;   // 丢弃 general 段头
                }
                if (!isGroup && is_named(name, "app")) {
                    out.append(line);
                    for (const QByteArray& l : generalBody) {
                        const QByteArray k = key_of(l);
                        if (!k.isEmpty() && appKeys.contains(k)) continue;       // [app] 优先
                        out.append(l);
                    }
                    appWritten = true;
                    mode = 2;
                    continue;
                }
                out.append(line);
                mode = 0;
                continue;
            }
            if (mode == 1) continue;                  // 丢弃 general 段内容
            if (mode == 2) { out.append(line); continue; }
            out.append(line);
        }
    }
    if (out.isEmpty()) return;

    // 组装输出(统一 CRLF 行尾)
    QByteArray result;
    for (const QByteArray& l : out) { result += l; result += '\r'; result += '\n'; }
    if (result == data) return;

    // 先备份再改写, 出问题可回退
    QFile::remove(path + ".bak");
    QFile bak(path + ".bak");
    if (bak.open(QIODevice::WriteOnly)) { bak.write(data); bak.close(); }
    QFile w(path);
    if (!w.open(QIODevice::WriteOnly | QIODevice::Truncate)) return;
    w.write(result);
    w.close();
}

/// @brief 初次启动生成默认配置文件(带中文注释模板);已存在则做一次旧段名迁移
inline void ensure_default_file() {
    const QString path = ini_path();
    if (QFile::exists(path)) { migrate_ini_groups(path); return; }
    const QByteArray tmpl =
        "; BPLC STA Monitor 配置文件(首次启动自动生成,删除后下次启动重建)\n"
        "; BPLC STA Monitor configuration (auto-generated)\n"
        "\n"
        "[app]\n"
        "; 语言:auto=跟随系统 / zh=中文 / en=English\n"
        "lang=auto\n"
        "; 更新检查地址(update.json 清单)\n"
        "update_url=https://raw.githubusercontent.com/aron566/HPLC_Wireshark/main/update.json\n"
        "; 显示过滤器(启动时自动应用,留空=不过滤)\n"
        "filter=\n"
        "; 界面主题:auto=跟随系统(默认)/ dark=深色 / light=浅色\n"
        "theme=auto\n"
        "; 启动时自动检查更新(true=检查 / false=不检查)\n"
        "auto_check=true\n"
        "; 更新下载加速:auto=按出口IP区域自动(中国IP走代理)/ native=始终原生GitHub / proxy=始终走代理\n"
        "mirror_mode=auto\n"
        "; 代理前缀列表(逗号分隔,按序探活取首个可用;留空=内置 ghfast.top/gh-proxy.com/ghproxy.net)\n"
        "mirror_list=\n"
        "; 协议:gw_2026=国网双模标准2026(默认) / gw_2022=国网双模标准2022 / nw_2021=南网双模2021报批版 / nw_2026=南网双模2026\n"
        "protocol=gw_2026\n"
        "\n"
        "[reader]\n"
        "; 输入源:0=串口 1=文件回放(bin) 2=裸hex文本\n"
        "mode=0\n"
        "; 串口参数\n"
        "com=COM3\n"
        "baud=460800\n"
        "; 回放/裸hex 文件路径\n"
        "file_path=\n"
        "\n"
        "[crash]\n"
        "; 崩溃捕获后端:sentry=上报Sentry服务 / crashpad=仅本地minidump / auto=自动(默认)\n"
        "; 编译时用 qmake CONFIG+=crash_sentry / CONFIG+=crash_crashpad 选择包含的后端\n"
        "backend=auto\n"
        "; Sentry DSN(backend=sentry 时上报用);留空则只本地落盘不上报\n"
        "dsn=\n"
        "; 本地 dump 目录(留空=exe 同目录 crashpad_db)\n"
        "db_path=\n";
    QFile f(path);
    if (f.open(QIODevice::WriteOnly)) f.write(tmpl);
}

// ---- app ----
inline QString update_url() {
    ensure_default_file();
    return settings().value(QStringLiteral("app/update_url"),
        QStringLiteral("https://raw.githubusercontent.com/aron566/HPLC_Wireshark/main/update.json"))
        .toString();
}
inline void set_update_url(const QString& url) {
    settings().setValue(QStringLiteral("app/update_url"), url);
}

inline QString lang() {
    ensure_default_file();
    return settings().value(QStringLiteral("app/lang"), QStringLiteral("auto")).toString();
}
inline void set_lang(const QString& v) {
    settings().setValue(QStringLiteral("app/lang"), v);
}

inline QString filter() {
    ensure_default_file();
    return settings().value(QStringLiteral("app/filter"), QString()).toString();
}
inline void set_filter(const QString& f) {
    settings().setValue(QStringLiteral("app/filter"), f);
}

inline QString theme() {
    ensure_default_file();
    return settings().value(QStringLiteral("app/theme"), QStringLiteral("auto")).toString();
}
inline void set_theme(const QString& t) {
    settings().setValue(QStringLiteral("app/theme"), t);
}

inline bool auto_check() {
    ensure_default_file();
    return settings().value(QStringLiteral("app/auto_check"), true).toBool();
}

/// @brief 更新加速模式:auto(按出口区域)/ native(强制原生)/ proxy(强制代理)
inline QString mirror_mode() {
    ensure_default_file();
    return settings().value(QStringLiteral("app/mirror_mode"),
                            QStringLiteral("auto")).toString().trimmed().toLower();
}

/// @brief 更新加速代理前缀列表(按序探活);config 留空时用内置实测可用三家
inline QStringList mirror_list() {
    ensure_default_file();
    const QString raw = settings().value(QStringLiteral("app/mirror_list"),
                                         QString()).toString();
    QStringList out;
    for (QString s : raw.split(QLatin1Char(','), Qt::SkipEmptyParts)) {
        s = s.trimmed();
        if (!s.isEmpty()) {
            if (!s.endsWith(QLatin1Char('/'))) s += QLatin1Char('/');
            out += s;
        }
    }
    if (!out.isEmpty()) return out;
    return { QStringLiteral("https://ghfast.top/"),
             QStringLiteral("https://gh-proxy.com/"),
             QStringLiteral("https://ghproxy.net/") };
}
inline void set_auto_check(bool v) {
    settings().setValue(QStringLiteral("app/auto_check"), v);
}

/// 协议变体:gw_2022=国网双模标准2022 / nw_2021=南网双模2021报批版
inline QString protocol() {
    ensure_default_file();
    return settings().value(QStringLiteral("app/protocol"),
                            QStringLiteral("gw_2026")).toString();
}
inline void set_protocol(const QString& v) {
    settings().setValue(QStringLiteral("app/protocol"), v);
}

// ---- reader ----
inline int  reader_mode()      { return settings().value(QStringLiteral("reader/mode"), 0).toInt(); }
inline QString reader_com()    { return settings().value(QStringLiteral("reader/com"), QStringLiteral("COM3")).toString(); }
inline int  reader_baud()      { return settings().value(QStringLiteral("reader/baud"), 460800).toInt(); }
inline QString reader_file()   { return settings().value(QStringLiteral("reader/file_path")).toString(); }

// ---- crash ----
inline QString crash_backend() {
    const QString v = settings().value(QStringLiteral("crash/backend"),
                                       QStringLiteral("auto")).toString().trimmed().toLower();
    return (v == QLatin1String("sentry") || v == QLatin1String("crashpad"))
               ? v : QStringLiteral("auto");
}
inline QString crash_dsn() {
    // 环境变量 SENTRY_DSN 优先,便于 CI/测试覆盖
    const QByteArray env = qgetenv("SENTRY_DSN");
    if (!env.isEmpty()) return QString::fromUtf8(env).trimmed();
    return settings().value(QStringLiteral("crash/dsn")).toString().trimmed();
}
inline QString crash_db_path() {
    return settings().value(QStringLiteral("crash/db_path")).toString().trimmed();
}

inline void set_reader(int mode, const QString& com, int baud,
                       const QString& file) {
    QSettings s = settings();
    s.setValue(QStringLiteral("reader/mode"), mode);
    s.setValue(QStringLiteral("reader/com"), com);
    s.setValue(QStringLiteral("reader/baud"), baud);
    s.setValue(QStringLiteral("reader/file_path"), file);
}

}  // namespace appcfg

#endif  // BPLC_APPCONFIG_H
