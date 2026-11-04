/// @file modelstress.cpp
/// @brief PacketListModel + QTableView 批量追加死锁复现 + 磁盘换页正确性验证
/// @details 与 MainWindow::on_flush_buffer -> append_packets 相同路径。
///          正常结束打印 PASS;若卡死则被 timeout 杀掉(exit 124)。
///          换页段:追加超过 kBlockSize 条,触发 flush 落盘,再验证 data()
///          往返 / for_each_entry 顺序 / 过滤遍历盘 / ensure_loaded 不崩。
#include "packetlistmodel.h"
#include <QApplication>
#include <QTableView>
#include <QThread>
#include <cstdio>
#include <functional>

static int g_fail = 0;
static void check(bool ok, const char* what) {
    if (!ok) { std::printf("  FAIL: %s\n", what); ++g_fail; }
}

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    PacketListModel model;
    QTableView view;
    view.setModel(&model);
    view.resize(800, 300);
    view.show();
    for (int i = 0; i < 3; ++i) app.processEvents();  // 让视图完成布局/连接

    const int TOTAL = 25000;   // 触发 2 次 flush(每块 10000)
    for (int batch = 0; batch * 200 < TOTAL; ++batch) {
        QVector<PacketEntry> entries;
        entries.reserve(200);
        for (int i = 0; batch * 200 + i < TOTAL && i < 200; ++i) {
            PacketEntry e;
            e.index    = batch * 200 + i + 1;
            e.epoch_ms = 0;
            e.accepted = true;
            e.mpdu.frame_type = 0;          // BEACON
            e.mpdu.net_id = 0xA1D500;
            e.meta.is_rf = false;
            e.raw_bytes = QByteArray(40, char(0x55));
            e.raw_wire  = QByteArray(48, char(0x3C));  // 非空,导出路径可用
            entries.append(e);
        }
        model.append_packets(entries);
        app.processEvents();
    }

    std::printf("total=%lld rows=%d\n",
                (long long)model.total_count(), int(model.rowCount()));
    check(model.total_count() == TOTAL, "total_count==25000");
    check(model.rowCount() == TOTAL, "rowCount==25000(无过滤全可见)");

    // data() 往返:抽读跨块边界与热区条目(无过滤时 row==全局行号)
    auto index_at = [&](int row) {
        return model.data(model.index(row, PacketListModel::COL_INDEX)).toInt();
    };
    check(index_at(0)     == 1,       "行0  index==1");
    check(index_at(9999)  == 10000,   "行9999  index==10000(块0末)");
    check(index_at(10000) == 10001,   "行10000 index==10001(块1首,盘上)");
    check(index_at(19999) == 20000,   "行19999 index==20000(块1末)");
    check(index_at(20000) == 20001,   "行20000 index==20001(块2首,盘上)");
    check(index_at(24999) == 25000,   "行24999 index==25000(热区末)");

    // ensure_loaded 跨块不崩
    for (int r : {0, 5000, 9999, 10000, 15000, 20000, 24999})
        model.ensure_loaded(r);

    // for_each_entry 全序:index 严格 1..25000 递增无缺
    int prev = 0, count = 0;
    bool ordered = true;
    model.for_each_entry([&](const PacketEntry& e) {
        ++count;
        if (e.index != prev + 1) ordered = false;
        prev = e.index;
    });
    check(count == TOTAL, "for_each_entry 遍历 25000 条");
    check(ordered, "for_each_entry 顺序 1..25000 连续");

    // 过滤遍历盘:BEACON 全命中 / coord 零命中 / 组合条件(异步过滤,等待完成)
    auto wait_filter = [&]() {
        while (model.filtering()) { app.processEvents(); QThread::msleep(1); }
    };
    model.set_display_filter("beacon");
    wait_filter();
    check(model.rowCount() == TOTAL, "过滤 beacon → 25000 行");
    model.set_display_filter("coord");
    wait_filter();
    check(model.rowCount() == 0, "过滤 coord → 0 行");
    model.set_display_filter("beacon & a1d5");
    wait_filter();
    check(model.rowCount() == TOTAL, "过滤 beacon & a1d5 → 25000 行");
    model.set_display_filter("");   // 恢复(同步清空)

    std::printf(g_fail == 0 ? "PASS rows=%d\n" : "FAIL(fail=%d)\n",
                int(model.rowCount()), g_fail);
    return g_fail == 0 ? 0 : 1;
}
