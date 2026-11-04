// updater 端到端验证:URL 参数(update.json)检查更新。
//   silent 模式(argv[3]=="silent"):仅验证"发现新版本"判定(不弹窗不下载)
//   默认模式:自动点"是"→ Downloader 下载 exe → downloadFinished 验证文件
// 离屏运行:QT_QPA_PLATFORM=offscreen ./updatecheck.exe <json-url> [local-version] [silent]
#include <cstdio>
#include <QApplication>
#include <QTimer>
#include <QMessageBox>
#include <QPushButton>
#include <QFileInfo>
#include <QDir>

#include "QSimpleUpdater.h"

static bool g_silent = false;
static bool g_downloaded = false;
static QString g_dlPath;

static void logmsg(const char* s) { fprintf(stderr, "%s\n", s); fflush(stderr); }

static void finish_ok() {
    if (g_silent) {
        logmsg("E2E-PASS (update detected)");
        qApp->exit(0);
        return;
    }
    bool ok = g_downloaded && QFileInfo::exists(g_dlPath) && QFileInfo(g_dlPath).size() > 100000;
    fprintf(stderr, "%s size=%lld\n", ok ? "E2E-PASS" : "E2E-FAIL",
            g_downloaded ? (long long)QFileInfo(g_dlPath).size() : 0LL);
    qApp->exit(ok ? 0 : 1);
}

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    if (argc < 2) { logmsg("usage: updatecheck <url> [version] [silent]"); return 2; }
    const QString url   = QString::fromLocal8Bit(argv[1]);
    const QString ver   = argc > 2 ? QString::fromLocal8Bit(argv[2]) : QStringLiteral("1.0.0");
    g_silent            = argc > 3 && QString::fromLocal8Bit(argv[3]) == QStringLiteral("silent");

    logmsg("== updatecheck start");
    auto* su = QSimpleUpdater::getInstance();
    su->setModuleVersion(url, ver);
    su->setModuleName(url, QStringLiteral("BPLC STA Monitor"));
    su->setNotifyOnUpdate(url, !g_silent);
    su->setNotifyOnFinish(url, false);
    su->setDownloadDir(url, QDir::tempPath());
    logmsg("config done");

    QTimer* poll = new QTimer;
    QObject::connect(poll, &QTimer::timeout, []() {
        QWidget* m = QApplication::activeModalWidget();
        if (auto* box = qobject_cast<QMessageBox*>(m)) {
            if (auto* yes = box->button(QMessageBox::Yes)) { logmsg("click Yes"); yes->click(); }
        }
    });
    poll->start(50);

    QObject::connect(su, &QSimpleUpdater::checkingFinished, [&](const QString& u) {
        if (u != url) return;
        bool avail = su->getUpdateAvailable(url);
        fprintf(stderr, "checkingFinished available=%d latest=%s\n",
                int(avail), qPrintable(su->getLatestVersion(url)));
        if (!avail || g_silent) finish_ok();
    });
    QObject::connect(su, &QSimpleUpdater::downloadFinished, [&](const QString& u, const QString& fp) {
        if (u != url) return;
        g_downloaded = true;
        g_dlPath = fp;
        fprintf(stderr, "downloadFinished file=%s\n", qPrintable(fp));
        finish_ok();
    });

    su->checkForUpdates(url);
    QTimer::singleShot(30000, []() { logmsg("TIMEOUT"); qApp->exit(1); });
    return app.exec();
}
