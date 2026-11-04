// 基准 2:真实 PacketListModel + QTableView 上点"自动列宽"的实际代价
// 量两件事:resizeColumnsToContents() 耗时,以及它到底回调了多少次 data()。

#include <QApplication>
#include <QElapsedTimer>
#include <QTableView>
#include <QHeaderView>
#include <QIdentityProxyModel>
#include <QDebug>
#include <QVector>
#include <QHash>
#include <QPair>
#include <algorithm>

#include "bplcframe.h"
#include "packetlistmodel.h"

// 统计 data() 调用次数的透明代理
class CountingProxy : public QIdentityProxyModel {
public:
    mutable quint64 calls = 0;
    mutable quint64 display = 0;
    mutable QHash<int, quint64> by_role;   ///< role → 调用次数
    mutable QHash<int, qint64>  us_by_role;///< role → 累计耗时(µs)
    QVariant data(const QModelIndex& idx, int role) const override {
        ++calls;
        ++by_role[role];
        if (role == Qt::DisplayRole) ++display;
        QElapsedTimer t; t.start();
        QVariant v = QIdentityProxyModel::data(idx, role);
        us_by_role[role] += t.nsecsElapsed() / 1000;
        return v;
    }
};

static QString role_name(int r) {
    switch (r) {
        case Qt::DisplayRole:          return QStringLiteral("Display(0)");
        case Qt::DecorationRole:       return QStringLiteral("Decoration(1)");
        case Qt::EditRole:             return QStringLiteral("Edit(2)");
        case Qt::ToolTipRole:          return QStringLiteral("ToolTip(3)");
        case Qt::StatusTipRole:        return QStringLiteral("StatusTip(4)");
        case Qt::WhatsThisRole:        return QStringLiteral("WhatsThis(5)");
        case Qt::FontRole:             return QStringLiteral("Font(6)");
        case Qt::TextAlignmentRole:    return QStringLiteral("TextAlignment(7)");
        case Qt::BackgroundRole:       return QStringLiteral("Background(8)");
        case Qt::ForegroundRole:       return QStringLiteral("Foreground(9)");
        case Qt::CheckStateRole:       return QStringLiteral("CheckState(10)");
        case Qt::AccessibleTextRole:   return QStringLiteral("AccessibleText(11)");
        case Qt::AccessibleDescriptionRole: return QStringLiteral("AccessibleDesc(12)");
        case Qt::SizeHintRole:         return QStringLiteral("SizeHint(13)");
        default:                       return QStringLiteral("role=%1").arg(r);
    }
}

static PacketEntry make_entry(int idx, int tree_nodes) {
    PacketEntry e;
    e.index    = idx + 1;
    e.accepted = true;
    e.epoch_ms = 1700000000000LL + idx;
    e.delta_us = 1250;
    e.protocol = kProtocolGw2026;
    e.raw_wire  = QByteArray(150, '\x5A');
    e.raw_bytes = QByteArray(120, '\xA5');
    e.msdu_body = QByteArray(48,  '\x11');
    e.mpdu.frame_type = 1;
    e.mpdu.net_id = 0x0F0F12;
    e.mpdu.src_tei = quint16(3 + idx % 40);
    e.mpdu.dst_tei = 1;
    e.mpdu.pb_num = 3;
    e.msdu.present = true;
    e.msdu.summary = QStringLiteral("MMe.AssocReq");
    e.search_text = QStringLiteral("sof sta-%1 0x0f0f12 mme assocreq").arg(idx % 40);

    e.msdu.tree.reserve(tree_nodes);
    for (int i = 0; i < tree_nodes; ++i) {
        MsduFieldNode n;
        n.name  = QStringLiteral("Field %1 [%2bit]").arg(i).arg(8 + i % 5);
        n.value = QStringLiteral("0x%1").arg(i, 4, 16, QChar('0'));
        n.rel_start = i; n.rel_len = 1;
        if (i % 10 == 0)
            for (int k = 0; k < 2; ++k) {
                MsduFieldNode c;
                c.name = QStringLiteral("sub %1").arg(k);
                c.value = QStringLiteral("%1").arg(k * 17 + i);
                c.rel_start = i; c.rel_len = 1;
                n.children.append(c);
            }
        e.msdu.tree.append(n);
    }
    return e;
}

static void bench(int nrows, int tree_nodes, int precision) {
    PacketListModel model;
    QVector<PacketEntry> batch;
    batch.reserve(nrows);
    for (int i = 0; i < nrows; ++i) batch.append(make_entry(i, tree_nodes));
    model.append_packets(std::move(batch));   // 内部按 1000 条 flush 落盘

    QTableView view;
    view.setModel(&model);
    view.resize(1600, 900);
    view.show();
    view.horizontalHeader()->setResizeContentsPrecision(precision);

    CountingProxy proxy;
    proxy.setSourceModel(&model);
    view.setModel(&proxy);

    QCoreApplication::processEvents();       // 让视图先完成初次布局
    proxy.calls = proxy.display = 0;

    QElapsedTimer t; t.start();
    view.resizeColumnsToContents();
    const qint64 ms = t.elapsed();

    qDebug().noquote()
        << QStringLiteral("rows=%1 blocks=%2 tree=%3 precision=%4 -> %5 ms, data() calls=%6 (Display %7)")
               .arg(nrows).arg((nrows + 999) / 1000).arg(tree_nodes).arg(precision)
               .arg(ms).arg(proxy.calls).arg(proxy.display);

    // role 直方图:证明"一个单元格被问了几次 data()"
    if (nrows == 20000 && tree_nodes == 100 && precision == 1000) {
        qDebug().noquote() << "  ---- roles asked per cell ----";
        QList<QPair<quint64, int>> v;
        for (auto it = proxy.by_role.constBegin(); it != proxy.by_role.constEnd(); ++it)
            v.append({it.value(), it.key()});
        std::sort(v.begin(), v.end(), [](const auto& a, const auto& b) { return a.first > b.first; });
        const quint64 cells = quint64(nrows > 1000 ? 1000 : nrows) * 14;
        for (const auto& p : v)
            qDebug().noquote()
                << QStringLiteral("    %1 : %2 calls  (%3 per cell)")
                       .arg(role_name(p.second), -20)
                       .arg(p.first)
                       .arg(double(p.first) / double(cells), 0, 'f', 2);
        qDebug().noquote() << QStringLiteral("    total %1 calls / %2 cells = %3 per cell")
                                  .arg(proxy.calls).arg(cells)
                                  .arg(double(proxy.calls) / double(cells), 0, 'f', 2);
        qDebug().noquote() << "  ---- time spent inside model->data(), by role ----";
        qint64 sum_us = 0;
        for (const auto& p : v) {
            const qint64 us = proxy.us_by_role.value(p.second);
            sum_us += us;
            qDebug().noquote() << QStringLiteral("    %1 : %2 ms  (%3 us/call)")
                                      .arg(role_name(p.second), -20)
                                      .arg(double(us) / 1000.0, 0, 'f', 1)
                                      .arg(double(us) / double(p.first), 0, 'f', 1);
        }
        qDebug().noquote() << QStringLiteral("    model->data() 合计 %1 ms（resize 总耗时里剩下的在 Qt 的布局/尺寸计算）")
                                  .arg(double(sum_us) / 1000.0, 0, 'f', 1);
    }
}

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    qDebug().noquote() << "=== AUTO FIT real cost ===";
    // 行数少于 precision 的边界(用户关心:不足 20 行会不会出问题)
    bench(10, 100, 20);
    bench(5,  100, 200);
    bench(0,  100, 200);   // 空模型
    bench(20000, 100, 1000);   // 默认 precision
    bench(20000, 100, 50);
    bench(20000, 100, 20);
    return 0;
}
