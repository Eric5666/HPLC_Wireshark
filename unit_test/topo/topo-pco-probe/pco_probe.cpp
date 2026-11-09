// 邻居明细弹窗 PCO 行显著标记回归探针(只读验证,不改产品代码)。
// 场景:STA 5 的代理为 TEI 2(PCO),邻居 {2,3,4};STA 3 的代理为 CCO(1)但不在其邻居 {4,5} 内。
// 断言:
//  A(浅色主题):STA 5 弹窗中 TEI 2 行整行加粗 + 前景深琥珀(176,90,0),
//    TEI 格提示为 PCO 说明,可靠度格保留评分公式提示;TEI 3/4 行不加粗、无前景色。
//  B:STA 3 弹窗中无任何加粗行(代理不在邻居内)。
//  C(深色主题):STA 5 弹窗中 TEI 2 行为亮琥珀(255,183,77) + 加粗。
#include "topo_window.h"
#include <QApplication>
#include <QDialog>
#include <QMetaObject>
#include <QPalette>
#include <QStandardItemModel>
#include <QTableView>
#include <cstdio>

static int g_fail = 0;
#define CHECK(cond, ...) do { \
    if (cond) { printf("PASS: "); printf(__VA_ARGS__); printf("\n"); } \
    else { printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); ++g_fail; } } while (0)

static TopoNode make_node(quint16 tei, quint64 mac, quint16 parent) {
    TopoNode n;
    n.tei = tei;
    n.mac = mac;
    n.parent_tei = parent;
    return n;
}

// 在指定窗口的邻居弹窗中找 TEI 列文本为 tei_text 的行号,找不到返回 -1
static int find_row_by_tei(QStandardItemModel* m, const QString& tei_text) {
    for (int r = 0; r < m->rowCount(); ++r) {
        QStandardItem* it = m->item(r, 0);
        if (it && it->text() == tei_text) return r;
    }
    return -1;
}

// 打开某 STA 的邻居弹窗并返回其 QTableView(未找到返回 nullptr)
static QTableView* open_neighbor_dialog(TopoWindow& win, QTableView* teimac, quint16 sta_tei) {
    QStandardItemModel* tm = qobject_cast<QStandardItemModel*>(teimac->model());
    if (!tm) return nullptr;
    int row = -1;
    for (int r = 0; r < tm->rowCount(); ++r) {
        QStandardItem* it = tm->item(r, 0);
        if (it && it->data(Qt::UserRole).toUInt() == sta_tei) { row = r; break; }
    }
    if (row < 0) return nullptr;
    const QModelIndex idx = tm->index(row, 7);
    const bool ok = QMetaObject::invokeMethod(&win, "on_teimac_double_clicked",
                                              Q_ARG(QModelIndex, idx));
    if (!ok) return nullptr;
    // 取最新弹出的邻居弹窗(标题含"邻居表"且含该 STA 的 TEI)
    QTableView* found = nullptr;
    const QString want = QStringLiteral("TEI=%1").arg(sta_tei);
    for (QDialog* d : win.findChildren<QDialog*>()) {
        if (d->windowTitle().contains(QStringLiteral("邻居表")) &&
            d->windowTitle().contains(want))
            found = d->findChild<QTableView*>();
    }
    return found;
}

int main(int argc, char** argv) {
    QApplication app(argc, argv);

    QHash<quint32, TopoState> states;
    TopoState st;
    st.nid = 1;
    st.nodes.insert(1, make_node(1, 0xAABBCCDDEE01ULL, 0));        // CCO,parent=0(根)
    st.nodes.insert(2, make_node(2, 0xAABBCCDDEE02ULL, 1));        // PCO,parent=CCO
    st.nodes.insert(5, make_node(5, 0xAABBCCDDEE05ULL, 2));        // STA 5,parent=PCO 2
    st.nodes.insert(3, make_node(3, 0xAABBCCDDEE03ULL, 1));        // STA 3,parent=CCO
    st.nodes.insert(4, make_node(4, 0xAABBCCDDEE04ULL, 2));        // STA 4,parent=PCO 2
    st.neighbors.insert(5, QVector<quint16>{2, 3, 4});
    st.neighbors.insert(3, QVector<quint16>{4, 5});
    states.insert(1, st);

    TopoWindow win;
    win.set_live_states(states);
    win.refresh_nids();
    win.set_current_nid(1);

    // 定位 TEI-MAC 表(8 列的那张)
    QTableView* teimac = nullptr;
    for (QTableView* v : win.findChildren<QTableView*>()) {
        if (v->model() && v->model()->columnCount() == 8) teimac = v;
    }
    CHECK(teimac != nullptr, "找到 TEI-MAC 表");
    if (!teimac) { printf("RESULT: %d failures\n", g_fail + 1); return 1; }

    // ---- Case A:浅色主题,STA 5 ----
    QTableView* viewA = open_neighbor_dialog(win, teimac, 5);
    CHECK(viewA != nullptr, "STA 5 邻居弹窗已打开");
    if (viewA) {
        auto* m = qobject_cast<QStandardItemModel*>(viewA->model());
        CHECK(m != nullptr && m->columnCount() == 12, "弹窗模型 12 列");
        const int r_pco = find_row_by_tei(m, QStringLiteral("2"));
        const int r_ord = find_row_by_tei(m, QStringLiteral("3"));
        CHECK(r_pco >= 0, "PCO 行(TEI 2)存在");
        CHECK(r_ord >= 0, "普通行(TEI 3)存在");
        if (r_pco >= 0) {
            bool all_bold = true, all_amber = true;
            for (int c = 0; c < m->columnCount(); ++c) {
                QStandardItem* it = m->item(r_pco, c);
                if (!it->font().bold()) all_bold = false;
                if (it->foreground().color() != QColor(176, 90, 0)) all_amber = false;
            }
            CHECK(all_bold, "PCO 行整行加粗(浅色)");
            CHECK(all_amber, "PCO 行整行深琥珀(176,90,0)(浅色)");
            CHECK(m->item(r_pco, 0)->toolTip() == QStringLiteral("本站点的代理 (PCO)"),
                  "PCO 行 TEI 格提示为 PCO 说明");
            CHECK(m->item(r_pco, 11)->toolTip().contains(QStringLiteral("权重")),
                  "PCO 行可靠度格保留评分公式提示(未被 PCO 提示覆盖)");
        }
        if (r_ord >= 0) {
            bool any_bold = false, any_fg = false;
            for (int c = 0; c < m->columnCount(); ++c) {
                QStandardItem* it = m->item(r_ord, c);
                if (it->font().bold()) any_bold = true;
                if (it->foreground().style() != Qt::NoBrush) any_fg = true;
            }
            CHECK(!any_bold, "普通行(TEI 3)不加粗");
            CHECK(!any_fg, "普通行(TEI 3)无前景色");
        }
    }

    // ---- Case B:STA 3(代理 CCO 不在邻居内) ----
    QTableView* viewB = open_neighbor_dialog(win, teimac, 3);
    CHECK(viewB != nullptr, "STA 3 邻居弹窗已打开");
    if (viewB) {
        auto* m = qobject_cast<QStandardItemModel*>(viewB->model());
        bool any_bold = false;
        for (int r = 0; r < m->rowCount(); ++r)
            for (int c = 0; c < m->columnCount(); ++c)
                if (m->item(r, c)->font().bold()) any_bold = true;
        CHECK(!any_bold, "STA 3 弹窗无加粗行(代理不在邻居内)");
    }

    // ---- Case C:深色主题,STA 5 ----
    {
        QPalette dark;
        dark.setColor(QPalette::Base, QColor(30, 30, 30));
        dark.setColor(QPalette::Window, QColor(53, 53, 53));
        dark.setColor(QPalette::WindowText, Qt::white);
        dark.setColor(QPalette::Text, Qt::white);
        QApplication::setPalette(dark);
    }
    QTableView* viewC = open_neighbor_dialog(win, teimac, 5);
    CHECK(viewC != nullptr, "深色主题下 STA 5 邻居弹窗已打开");
    if (viewC) {
        auto* m = qobject_cast<QStandardItemModel*>(viewC->model());
        // 取最后一个 TEI=5 弹窗的视图即本次新建的(浅色那张仍在,须区分):
        // open_neighbor_dialog 返回的是标题匹配的最后一张,此处直接用返回的视图
        const int r_pco = find_row_by_tei(m, QStringLiteral("2"));
        CHECK(r_pco >= 0, "深色 PCO 行(TEI 2)存在");
        if (r_pco >= 0) {
            bool all_bold = true, all_amber = true;
            for (int c = 0; c < m->columnCount(); ++c) {
                QStandardItem* it = m->item(r_pco, c);
                if (!it->font().bold()) all_bold = false;
                if (it->foreground().color() != QColor(255, 183, 77)) all_amber = false;
            }
            CHECK(all_bold, "PCO 行整行加粗(深色)");
            CHECK(all_amber, "PCO 行整行亮琥珀(255,183,77)(深色)");
        }
    }

    printf("RESULT: %d failures\n", g_fail);
    return g_fail ? 1 : 0;
}
