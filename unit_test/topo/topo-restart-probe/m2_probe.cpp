/// 探针:M2 CCO is_rf 翻转 —— 事件侧守卫(e.is_rf_known)与节点侧锁定缺失的区分验证
#include "topo_state.h"
#include <QCoreApplication>
#include <cstdio>

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    const quint64 CCO = 0xAABBCCDDEEFFULL;

    // (a) PLC CCO 事件:介质已知=载波
    TopoEvent a;
    a.kind = TopoEventKind::DiscoverList; a.cco_mac = CCO;
    a.is_rf = false; a.is_rf_known = true; a.epoch_ms = 1000; a.frame_index = 1;

    // (b) RF STA 事件:同一 CCO,介质已知=无线(模拟 RF 入网 STA 事件带 cco_mac)
    TopoEvent b;
    b.kind = TopoEventKind::Other; b.cco_mac = CCO;
    b.is_rf = true; b.is_rf_known = true; b.epoch_ms = 2000; b.frame_index = 2;

    // (c) 未知介质事件: is_rf_known=false(即使 is_rf 带真值也应不覆盖)
    TopoEvent c;
    c.kind = TopoEventKind::Other; c.cco_mac = CCO;
    c.is_rf = true; c.is_rf_known = false; c.epoch_ms = 3000; c.frame_index = 3;

    TopoState st;
    a.nid = b.nid = c.nid = 0x0E;   // 探针用真实 NID(生产不允许 NID==0 的事件进拓扑)
    st.apply(a);
    std::printf("after PLC CCO event:   cco.is_rf=%d is_rf_known=%d\n",
                (int)st.nodes[1].is_rf, (int)st.nodes[1].is_rf_known);
    st.apply(b);
    std::printf("after RF STA event:    cco.is_rf=%d is_rf_known=%d\n",
                (int)st.nodes[1].is_rf, (int)st.nodes[1].is_rf_known);

    TopoState st2;
    st2.apply(a);
    st2.apply(c);
    std::printf("after unknown-medium:  cco.is_rf=%d is_rf_known=%d\n",
                (int)st2.nodes[1].is_rf, (int)st2.nodes[1].is_rf_known);
    return 0;
}
