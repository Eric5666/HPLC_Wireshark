/// @file paging_race_probe.cpp
/// @brief M2/M3 回归:盘块后台落盘未完成时,data()/过滤/导出快照不得丢帧;clear 后会话隔离
/// @details 用阻塞任务占满全局线程池,让落盘任务排队不执行,稳定复现"块号已分配、文件未写"窗口。
#include "packetlistmodel.h"
#include "packetentry_serialize.h"

#include <QApplication>
#include <QSemaphore>
#include <QThread>
#include <QThreadPool>
#include <cstdio>

static int g_fail = 0;
static void check(bool ok, const char* what) {
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++g_fail;
}

static QVector<PacketEntry> make_entries(int first_index, int n) {
    QVector<PacketEntry> v;
    v.reserve(n);
    for (int i = 0; i < n; ++i) {
        PacketEntry e;
        e.index = first_index + i;
        e.accepted = true;
        e.mpdu.frame_type = 0;   // BEACON
        e.mpdu.net_id = 0xA1D500;
        e.raw_bytes = QByteArray(40, char(0x55));
        e.raw_wire = QByteArray(48, char(0x3C));
        v.append(e);
    }
    return v;
}

/// 占满全局线程池:返回后所有新任务排队,直到 release()
struct PoolGate {
    QSemaphore gate;
    QSemaphore started;
    int n = 0;
    void block() {
        n = QThreadPool::globalInstance()->maxThreadCount();
        for (int i = 0; i < n; ++i)
            QThreadPool::globalInstance()->start([this]() { started.release(); gate.acquire(); });
        started.acquire(n);
    }
    void release() { gate.release(n); }
};

static int row_index(PacketListModel& m, int row) {
    return m.data(m.index(row, PacketListModel::COL_INDEX)).toInt();
}

/// 与 MainWindow::run_export 同口径:内存副本优先,否则读文件
static qint64 count_snapshot(const PacketListModel::ExportSnapshot& s, bool* order_ok, int first_index) {
    qint64 n = 0;
    *order_ok = true;
    auto take = [&](const PacketEntry& e) {
        if (e.index != first_index + n) *order_ok = false;
        ++n;
    };
    for (int b = 0; b < s.block_paths.size(); ++b) {
        if (const auto mem = s.block_mem.value(b)) { for (const auto& e : *mem) take(e); continue; }
        QVector<PacketEntry> blk;
        if (!pser::read_block_file(s.block_paths[b], blk)) continue;
        for (const auto& e : blk) take(e);
    }
    for (const auto& e : s.hot) take(e);
    return n;
}

static void drain(QApplication& app, PacketListModel& m) {
    for (int i = 0; i < 5000 && (m.pending_block_count() > 0 || m.filtering()); ++i) {
        QThreadPool::globalInstance()->waitForDone(5);
        app.processEvents();
    }
    app.processEvents();
}

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    PacketListModel model;
    PoolGate gate;

    // ① 落盘任务全部排队:5 块已分配块号但文件不存在
    gate.block();
    model.append_packets(make_entries(1, 5500));
    check(model.pending_block_count() == 5, "5 blocks pending while pool is blocked");
    bool all_rows = true;
    for (int r : {0, 999, 1000, 2500, 4999, 5000, 5499})
        if (row_index(model, r) != r + 1) all_rows = false;
    check(all_rows, "rows in unwritten blocks are served from memory (no blank rows)");

    // ② 导出快照:未就绪块带内存副本,条数与顺序完整
    {
        const auto snap = model.make_export_snapshot();
        bool order = false;
        const qint64 n = count_snapshot(snap, &order, 1);
        check(snap.total == 5500 && n == 5500 && order, "export snapshot includes unwritten blocks");
    }

    // ③ 过滤快照在落盘前取得,结果必须覆盖全部 5500 行
    model.set_display_filter(QStringLiteral("beacon"));
    gate.release();
    drain(app, model);
    check(!model.filtering() && model.rowCount() == 5500, "filter over unwritten blocks keeps all rows");
    check(model.pending_block_count() == 0, "all blocks became ready after the pool drained");
    model.set_display_filter(QString());

    // ④ 就绪后从文件读
    all_rows = true;
    for (int r : {0, 1999, 3000, 4999, 5400})
        if (row_index(model, r) != r + 1) all_rows = false;
    check(all_rows, "rows read back from published block files");
    {
        const auto snap = model.make_export_snapshot();
        bool order = false;
        check(count_snapshot(snap, &order, 1) == 5500 && order, "export snapshot from files complete");
    }

    // ⑤ clear 与旧会话迟到的写:旧块写任务在 clear 之后才执行,不得混入新会话
    gate.block();
    model.clear_all();
    model.append_packets(make_entries(100001, 1500));   // 旧会话无块;造 1 个新块后再 clear 一次
    model.clear_all();
    model.append_packets(make_entries(200001, 3200));   // 新会话 3 块
    gate.release();
    drain(app, model);
    all_rows = model.rowCount() == 3200;
    for (int r : {0, 999, 1000, 2999, 3199})
        if (row_index(model, r) != 200001 + r) all_rows = false;
    check(all_rows && model.pending_block_count() == 0, "new session blocks not mixed with stale writes");
    {
        const auto snap = model.make_export_snapshot();
        bool order = false;
        check(count_snapshot(snap, &order, 200001) == 3200 && order, "export after clear is the new session only");
    }

    std::printf("paging_race_probe: %s (%d failures)\n", g_fail ? "FAIL" : "OK", g_fail);
    return g_fail ? 1 : 0;
}
