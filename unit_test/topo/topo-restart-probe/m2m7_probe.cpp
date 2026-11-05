/// 探针:M2(CCO 介质首次写入锁定)+M7(child_teis 首次写入锁定、node_link_types kind 门)
#include "topo_state.h"
#include <QCoreApplication>
#include <cstdio>

static int g_fail = 0;
#define CHECK(name, cond) do { \
    std::printf("%s %s\n", (cond) ? "PASS" : "FAIL", name); \
    if (!(cond)) ++g_fail; } while (0)

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    const quint64 CCO = 0xAABBCCDDEEFFULL;

    // M2a:PLC CCO 事件先到 -> (0, known)
    // M2b:RF STA 事件后到 -> 仍 (0, known),不翻转
    // M2c:未知介质事件 -> 仍 (0, known)
    {
        TopoState st; TopoEvent a, b, c;
        a.nid = 0x0E; b.nid = 0x0E; c.nid = 0x0E;
        a.kind = TopoEventKind::Other; a.cco_mac = CCO;
        a.is_rf = false; a.is_rf_known = true; a.epoch_ms = 1000;
        b.kind = TopoEventKind::Other; b.cco_mac = CCO;
        b.is_rf = true; b.is_rf_known = true; b.epoch_ms = 2000;
        c.kind = TopoEventKind::Other; c.cco_mac = CCO;
        c.is_rf = true; c.is_rf_known = false; c.epoch_ms = 3000;
        st.apply(a);
        CHECK("M2a PLC CCO first -> (0,known)", !st.nodes[1].is_rf && st.nodes[1].is_rf_known);
        st.apply(b);
        CHECK("M2b RF STA event does not flip CCO", !st.nodes[1].is_rf && st.nodes[1].is_rf_known);
        st.apply(c);
        CHECK("M2c unknown event does not flip CCO", !st.nodes[1].is_rf && st.nodes[1].is_rf_known);
    }
    // M2d:反向先到先得:RF CCO 事件先到 -> (1, known),PLC 事件后到不翻回
    {
        TopoState st; TopoEvent a, b;
        a.nid = 0x0E; b.nid = 0x0E;
        a.kind = TopoEventKind::Other; a.cco_mac = CCO;
        a.is_rf = true; a.is_rf_known = true; a.epoch_ms = 1000;
        b.kind = TopoEventKind::Other; b.cco_mac = CCO;
        b.is_rf = false; b.is_rf_known = true; b.epoch_ms = 2000;
        st.apply(a);
        CHECK("M2d RF CCO first -> (1,known)", st.nodes[1].is_rf && st.nodes[1].is_rf_known);
        st.apply(b);
        CHECK("M2d PLC event does not flip back", st.nodes[1].is_rf && st.nodes[1].is_rf_known);
    }
    // M7a:child_teis 首次写入锁定:无线先到 -> (1,known),载波后到不翻回
    {
        TopoState st; TopoEvent a, b;
        a.nid = 0x0E; b.nid = 0x0E;
        a.kind = TopoEventKind::ChangeProxyCnf; a.link_type = 1; a.epoch_ms = 1000;
        a.child_teis.append(90);
        b.kind = TopoEventKind::ChangeProxyCnf; b.link_type = 0; b.epoch_ms = 2000;
        b.child_teis.append(90);
        st.apply(a);
        CHECK("M7a child_teis wireless first -> (1,known)", st.nodes[90].is_rf && st.nodes[90].is_rf_known);
        st.apply(b);
        CHECK("M7a child_teis carrier later does not flip", st.nodes[90].is_rf && st.nodes[90].is_rf_known);
    }
    // M7b:node_link_types kind 门:非权威 kind 不写;权威 kind 照常写并锁定
    {
        TopoState st; TopoEvent a, b;
        a.nid = 0x0E; b.nid = 0x0E;
        a.kind = TopoEventKind::Other; a.epoch_ms = 1000;
        a.node_link_types.append(qMakePair<quint16, quint8>(78, 1));
        st.apply(a);
        CHECK("M7b non-authoritative kind does not write link_type", !st.nodes.contains(78));
        b.kind = TopoEventKind::AssocCnf; b.epoch_ms = 1000;
        b.node_link_types.append(qMakePair<quint16, quint8>(79, 1));
        st.apply(b);
        CHECK("M7b authoritative kind writes + locks", st.nodes[79].link_type == 1
              && st.nodes[79].link_type_known);
    }
    std::printf(g_fail ? "RESULT: %d FAIL\n" : "RESULT: ALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}
