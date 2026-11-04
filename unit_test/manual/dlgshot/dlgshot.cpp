// 离屏渲染"设置"对话框(深色/浅色)截图,用于检查布局显示问题
#include <cstdio>
#include <QApplication>
#include <QTimer>
#include <QComboBox>
#include <QAbstractItemView>
#include <QFile>
#include "commconfigdialog.h"
#include "theme.h"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    theme::apply(argc > 2 ? QString::fromLocal8Bit(argv[2]) : QStringLiteral("dark"));
    ReaderConfig rc;
    CommConfigDialog dlg(nullptr, rc);
    dlg.show();
    const bool popup_mode = argc > 3 && QString::fromLocal8Bit(argv[3]) == QLatin1String("popup");
    QTimer::singleShot(400, [&]() {
        const QString out = QString::fromLocal8Bit(argv[1]);
        QPixmap pm;
        if (popup_mode) {
            // 打开第一个下拉框的选项弹层并截取(view 独立窗口)
            if (auto* cb = dlg.findChild<QComboBox*>()) {
                // 指定序号或取选项最多的下拉
                QComboBox* target = cb;
                int want = argc > 4 ? QString::fromLocal8Bit(argv[4]).toInt() : -1;
                const auto all = dlg.findChildren<QComboBox*>();
                if (want >= 0 && want < all.size()) target = all.at(want);
                else for (auto* c : all) if (c->count() > target->count()) target = c;
                std::printf("combo #%d items: %d\n", want, target->count());
                target->showPopup();
                QTimer::singleShot(300, [&, target, out]() {
                    auto* v = target->view();   // QAbstractItemView*
                    std::printf("view size: %dx%d\n", v->width(), v->height());
                    QPixmap pp = v->grab();
                    if (pp.save(out)) std::printf("saved %s\n", qPrintable(out));
                    app.exit(0);
                });
                return;
            }
            app.exit(1);
            return;
        }
        pm = dlg.grab();
        std::printf("dlg size: %dx%d  screen hint: %dx%d\n",
                    dlg.width(), dlg.height(),
                    pm.width(), pm.height());
        if (pm.save(out))
            std::printf("saved %s\n", qPrintable(out));
        else
            std::printf("save FAILED\n");
        app.exit(0);
    });
    return app.exec();
}
