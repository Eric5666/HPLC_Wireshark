/// 探针:双模认定(用户 2026-10-28 定)
/// 规则1:入网链路为无线(link_type==1)即双模,权威/弱路径全算,只认结果
/// 规则2:CCO 自己发过 RF 帧即双模;RF STA 事件不得误标 CCO 双模
#include "topo_state.h"
#include <QCoreApplication>
#include <cstdio>

static int g_fail = 0;
#define CHECK(name, cond) do { \
    std::printf("%s %s\n", (cond) ? "PASS" : "FAIL", name); \
    if (!(cond)) ++g_fail; } while (0)

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    const quint64 MAC78 = 0x111111111178ULL, MAC79 = 0x111111111179ULL;
    const quint64 MAC80 = 0x111111111180ULL, MAC81 = 0x111111111181ULL;
    const quint64 CCO = 0xAABBCCDDEEFFULL, STA = 0x222222222222ULL;

    // P1 权威路径:AssocCnf link_type=1
    {
        TopoState st; TopoEvent e;
        e.nid = 0x0E;
        e.kind = TopoEventKind::AssocCnf; e.link_type = 1; e.epoch_ms = 1000;
        e.nodes.append(TeiMacPair{78, MAC78});
        st.apply(e);
        CHECK("P1 authoritative link_type=1 -> dual", st.nodes[78].link_type == 1
              && st.nodes[78].link_type_known && st.nodes[78].rf_capable);
    }
    // P2 弱路径:非权威帧首个 link_type=1
    {
        TopoState st; TopoEvent e;
        e.nid = 0x0E;
        e.kind = TopoEventKind::DiscoverList; e.link_type = 1; e.epoch_ms = 1000;
        e.nodes.append(TeiMacPair{79, MAC79});
        st.apply(e);
        CHECK("P2 weak first-wins link_type=1 -> dual", st.nodes[79].link_type == 1
              && !st.nodes[79].link_type_known && st.nodes[79].rf_capable);
    }
    // P3 媒介回退:无 link_type 字段,RF 帧回退 link_type=1
    {
        TopoState st; TopoEvent e;
        e.nid = 0x0E;
        e.kind = TopoEventKind::DiscoverList; e.link_type = -1;
        e.is_rf = true; e.is_rf_known = true; e.epoch_ms = 1000;
        e.nodes.append(TeiMacPair{80, MAC80});
        st.apply(e);
        CHECK("P3 medium fallback RF -> link_type=1 -> dual", st.nodes[80].link_type == 1
              && st.nodes[80].rf_capable);
    }
    // P4 载波不误标
    {
        TopoState st; TopoEvent e;
        e.nid = 0x0E;
        e.kind = TopoEventKind::AssocCnf; e.link_type = 0; e.epoch_ms = 1000;
        e.nodes.append(TeiMacPair{81, MAC81});
        st.apply(e);
        CHECK("P4 carrier link_type=0 -> not dual", st.nodes[81].link_type == 0
              && !st.nodes[81].rf_capable);
    }
    // P5 CCO 自己发 RF 事件帧 -> CCO 双模
    {
        TopoState st; TopoEvent e;
        e.nid = 0x0E;
        e.kind = TopoEventKind::Other; e.cco_mac = CCO; e.sender_mac = CCO;
        e.is_rf = true; e.is_rf_known = true; e.epoch_ms = 1000;
        st.apply(e);
        CHECK("P5 CCO-sent RF event -> CCO dual", st.nodes[1].rf_capable);
    }
    // P6 RF STA 事件不得误标 CCO 双模(CCO is_rf 会翻,见 M2;rf_capable 不应动)
    {
        TopoState st; TopoEvent e;
        e.nid = 0x0E;
        e.kind = TopoEventKind::Other; e.cco_mac = CCO; e.sender_mac = STA;
        e.is_rf = true; e.is_rf_known = true; e.epoch_ms = 1000;
        st.apply(e);
        CHECK("P6 RF STA event -> CCO not dual", !st.nodes[1].rf_capable);
    }
    // P7 node_link_types 循环:无线条目 -> 双模
    {
        TopoState st; TopoEvent e;
        e.nid = 0x0E;
        e.kind = TopoEventKind::AssocCnf; e.epoch_ms = 1000;
        e.node_link_types.append(qMakePair<quint16, quint8>(82, 1));
        st.apply(e);
        CHECK("P7 node_link_types wireless -> dual", st.nodes[82].link_type == 1
              && st.nodes[82].link_type_known && st.nodes[82].rf_capable);
    }
    // P8 逐帧路径:CCO 节点已存在时 note_rf_capable(1, RF) 置位
    {
        TopoState st; TopoEvent e;
        e.nid = 0x0E;
        e.kind = TopoEventKind::Other; e.cco_mac = CCO; e.epoch_ms = 1000;
        st.apply(e);
        const bool touched = st.note_rf_capable(1, true);
        CHECK("P8 note_rf_capable(1, RF) -> CCO dual", touched && st.nodes[1].rf_capable);
    }
    std::printf(g_fail ? "RESULT: %d FAIL\n" : "RESULT: ALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}
