// 深色主题资源自检:qss 可读、内部图标 url 可解析(排除暗色主题显示异常)
#include <cstdio>
#include <QApplication>
#include <QFile>
#include <QPixmap>
#include <QRegularExpression>
#include <QSet>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    int missing = 0;
    QFile f(QStringLiteral(":/qdarkstyle/dark/darkstyle.qss"));
    if (!f.open(QIODevice::ReadOnly)) {
        std::printf("FAIL: qss 资源不可读\n");
        return 1;
    }
    const QString qss = QString::fromUtf8(f.readAll());
    std::printf("qss bytes: %d\n", qss.size());
    QRegularExpression re(QStringLiteral("url\\(\"([^\"]+)\"\\)"));
    auto it = re.globalMatch(qss);
    QSet<QString> seen;
    int total = 0;
    while (it.hasNext()) {
        const QString u = it.next().captured(1);
        if (seen.contains(u)) continue;
        seen.insert(u);
        ++total;
        if (!QFile::exists(u)) { ++missing; std::printf("missing: %s\n", qPrintable(u)); }
    }
    std::printf("unique icons: %d missing: %d -> %s\n", total, missing,
                missing == 0 ? "DARK-THEME-CHECK-PASS" : "DARK-THEME-CHECK-FAIL");
    return missing == 0 ? 0 : 1;
}
