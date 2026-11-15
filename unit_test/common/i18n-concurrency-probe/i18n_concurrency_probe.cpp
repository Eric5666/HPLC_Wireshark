/// @file i18n_concurrency_probe.cpp
/// @brief M6 回归:trl::L 并发查找 + 运行期 register_en(触发多次 rehash)
#include "i18n.h"

#include <QByteArray>
#include <QThread>
#include <atomic>
#include <cstdio>
#include <vector>

int main() {
    trl::register_en("探针键", "Probe Key");
    trl::set_enabled(true);
    std::atomic<bool> stop{false};
    std::atomic<long> lookups{0};
    std::atomic<long> wrong{0};
    std::vector<QThread*> readers;
    for (int t = 0; t < 4; ++t) {
        readers.push_back(QThread::create([&] {
            while (!stop.load()) {
                if (trl::L("探针键") != QLatin1String("Probe Key")) ++wrong;
                if (trl::L("不存在的键") != QStringLiteral("不存在的键")) ++wrong;
                ++lookups;
            }
        }));
        readers.back()->start();
    }
    // 写线程:插入 20 万个新键(QHash 多次 rehash),同时切换语言开关
    for (int i = 0; i < 200000; ++i) {
        const QByteArray zh = "动态键" + QByteArray::number(i);
        const QByteArray en = "Dynamic Key " + QByteArray::number(i);
        trl::register_en(zh.constData(), en.constData());
        trl::register_en("探针键", "Probe Key");   // 同值重复注册(设置对话框每次打开)
    }
    stop = true;
    for (QThread* t : readers) { t->wait(); delete t; }
    const bool ok_last = trl::L("动态键199999") == QLatin1String("Dynamic Key 199999");
    std::printf("lookups=%ld wrong=%ld last_key_ok=%d\n", lookups.load(), wrong.load(), ok_last);
    const bool ok = wrong.load() == 0 && ok_last && lookups.load() > 0;
    std::printf("i18n_concurrency_probe: %s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}
