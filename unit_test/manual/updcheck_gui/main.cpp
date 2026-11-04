// 复现主程序"检查更新"菜单 lambda:私有 URL → 网络错误/弹窗路径
#include <cstdio>
#include <QApplication>
#include <QTimer>
#include <QMessageBox>
#include <QPushButton>
#include <QAbstractButton>
#include <QDialogButtonBox>

#include "QSimpleUpdater.h"

static void logmsg(const char* s) { fprintf(stderr, "%s\n", s); fflush(stderr); }

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("BPLC STA Monitor"));
    app.setApplicationVersion(QStringLiteral("1.0.0"));
    logmsg("== start");
    const QString url = argc > 1 ? QString::fromLocal8Bit(argv[1])
        : QStringLiteral("https://raw.githubusercontent.com/aron566/HPLC_Wireshark/main/update.json");

    auto* su = QSimpleUpdater::getInstance();
    su->setModuleVersion(url, QStringLiteral("1.0.0"));
    su->setModuleName(url, QStringLiteral("BPLC STA Monitor"));
    su->setNotifyOnUpdate(url, true);
    su->setNotifyOnFinish(url, true);
    logmsg("config done");

    QTimer* poll = new QTimer;
    QObject::connect(poll, &QTimer::timeout, []() {
        QWidget* m = QApplication::activeModalWidget();
        if (auto* box = qobject_cast<QMessageBox*>(m)) {
            QAbstractButton* hit = box->button(QMessageBox::Yes);
            if (!hit) hit = box->button(QMessageBox::Ok);
            if (!hit) hit = box->button(QMessageBox::Close);
            if (!hit) {
                auto* bb = box->findChild<QDialogButtonBox*>();
                if (bb) { const auto bs = bb->buttons(); if (!bs.isEmpty()) hit = bs.first(); }
            }
            if (hit) { logmsg("click dialog button"); hit->click(); }
            else logmsg("dialog no button found");
        }
    });
    poll->start(50);

    QObject::connect(su, &QSimpleUpdater::checkingFinished, [](const QString& u) {
        fprintf(stderr, "checkingFinished url=%s\n", qPrintable(u));
    });
    QObject::connect(su, &QSimpleUpdater::downloadFinished, [](const QString&, const QString& fp) {
        fprintf(stderr, "downloadFinished %s\n", qPrintable(fp));
    });

    logmsg("checkForUpdates…");
    static QString g_url = url;
    static QSimpleUpdater* g_su = su;
    su->checkForUpdates(url);
    QTimer::singleShot(20000, []() { logmsg("TIMEOUT"); qApp->exit(2); });
    QTimer::singleShot(4000, []() { logmsg("repeat check (reentry)"); g_su->checkForUpdates(g_url); });
    QTimer::singleShot(12000, []() { logmsg("still alive (no crash)"); qApp->exit(0); });
    return app.exec();
}
