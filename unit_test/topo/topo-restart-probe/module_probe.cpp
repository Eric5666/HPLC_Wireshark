/// 探针:关联请求模块类型双模认定回显(96369fe review 修复验证)
/// 规则:关联请求模块类型=1(双模 HPLC+RF,表164/表84)即双模,入网请求时刻即可知;
/// 关联请求走 pending 分支(tei=0),分配 TEI 后 promotion 须保留该标记;
/// 模块类型 0/2/0xFF 不置位。
/// 用法:./module_probe ; exit 0 = 全部断言通过
#include "topo_state.h"
#include <QCoreApplication>
#include <cstdio>

static int g_fail = 0;
#define CHECK(name, cond) do { \
    std::printf("%s %s\n", (cond) ? "PASS" : "FAIL", name); \
    if (!(cond)) ++g_fail; } while (0)

static TopoEvent assoc_req(quint64 mac, quint8 module_type, qint64 idx) {
    TopoEvent e;
    e.kind = TopoEventKind::AssocReq;
    e.nid = 0x0E;   // 探针用真实 NID(生产不允许 NID==0 的事件进拓扑)
    e.module_type = module_type;
    e.nodes.append(TeiMacPair{0, mac});
    e.epoch_ms = 1000 + idx;
    e.frame_index = idx;
    return e;
}

static TopoEvent assoc_cnf(quint16 tei, quint64 mac, qint64 idx) {
    TopoEvent e;
    e.kind = TopoEventKind::AssocCnf;
    e.nid = 0x0E;   // 探针用真实 NID(生产不允许 NID==0 的事件进拓扑)
    e.nodes.append(TeiMacPair{tei, mac});
    e.epoch_ms = 2000 + idx;
    e.frame_index = idx;
    return e;
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    const quint64 MAC = 0xAABBCCDDEEFFULL;

    // M1: 模块类型=1 的关联请求,pending 节点即双模
    {
        TopoState st;
        st.apply(assoc_req(MAC, 1, 1));
        CHECK("M1 module=1 AssocReq -> pending rf_capable",
              st.pending.contains(MAC) && st.pending[MAC].rf_capable);
    }
    // M2: 分配 TEI 后 promotion 保留双模标记
    {
        TopoState st;
        st.apply(assoc_req(MAC, 1, 1));
        st.apply(assoc_cnf(78, MAC, 2));
        CHECK("M2 module=1 promotion -> nodes[78] rf_capable",
              st.nodes.contains(78) && st.nodes[78].rf_capable);
        CHECK("M2b pending cleared after AssocCnf", !st.pending.contains(MAC));
    }
    // M3: 模块类型=0(HPLC 单模)不置位,入网后也不误标
    {
        TopoState st;
        st.apply(assoc_req(MAC, 0, 1));
        CHECK("M3 module=0 pending not dual",
              st.pending.contains(MAC) && !st.pending[MAC].rf_capable);
        st.apply(assoc_cnf(78, MAC, 2));
        CHECK("M3b module=0 nodes[78] not dual",
              st.nodes.contains(78) && !st.nodes[78].rf_capable);
    }
    // M4: 模块类型缺省 0xFF(无此字段)不置位、不崩
    {
        TopoState st;
        st.apply(assoc_req(MAC, 0xFF, 1));
        CHECK("M4 module=0xFF pending not dual",
              st.pending.contains(MAC) && !st.pending[MAC].rf_capable);
    }
    // M5: 模块类型=2(无线单模)不是双模,不置位
    {
        TopoState st;
        st.apply(assoc_req(MAC, 2, 1));
        CHECK("M5 module=2 pending not dual",
              st.pending.contains(MAC) && !st.pending[MAC].rf_capable);
    }
    // M6: 重上电再次关联请求(同 MAC),模块类型=1 仍认定
    {
        TopoState st;
        st.apply(assoc_req(MAC, 1, 1));
        st.apply(assoc_req(MAC, 1, 2));
        CHECK("M6 re-assoc module=1 pending still dual",
              st.pending.contains(MAC) && st.pending[MAC].rf_capable);
    }

    std::printf(g_fail ? "RESULT: %d FAILURES\n" : "RESULT: ALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}
