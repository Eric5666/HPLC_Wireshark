/// 探针:ChangeProxyCnf 权威帧(仅成功)——assign_link_type 锁定行为
/// P1 成功代理变更确认先到 -> 锁定,随后 AssocCnf 改不动
/// P2 AssocCnf 先锁定,随后成功代理变更确认改不动
/// P3 失败样式事件(link_type=-1,解析器层已门控)不碰 link_type
/// P4 弱路径回归:非权威 kind 填 0xFF 不锁,随后 AssocCnf 可覆盖并锁定
#include "topo_state.h"
#include <QCoreApplication>
#include <cstdio>

static int g_fail = 0;
#define CHECK(name, cond) do { \
    std::printf("%s %s\n", (cond) ? "PASS" : "FAIL", name); \
    if (!(cond)) ++g_fail; } while (0)

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    // P1
    {
        TopoState st; TopoEvent a, b;
        a.nid = 0x0E; b.nid = 0x0E;
        a.kind = TopoEventKind::ChangeProxyCnf; a.link_type = 1; a.epoch_ms = 1000;
        a.routes.append({90, 1});
        b.kind = TopoEventKind::AssocCnf; b.link_type = 0; b.epoch_ms = 2000;
        b.routes.append({90, 1});
        st.apply(a);
        CHECK("P1 ChangeProxyCnf success -> (1,locked)", st.nodes[90].link_type == 1 && st.nodes[90].link_type_known);
        st.apply(b);
        CHECK("P1 AssocCnf later cannot override locked 1", st.nodes[90].link_type == 1 && st.nodes[90].link_type_known);
    }
    // P2
    {
        TopoState st; TopoEvent a, b;
        a.nid = 0x0E; b.nid = 0x0E;
        a.kind = TopoEventKind::AssocCnf; a.link_type = 0; a.epoch_ms = 1000;
        a.routes.append({91, 1});
        b.kind = TopoEventKind::ChangeProxyCnf; b.link_type = 1; b.epoch_ms = 2000;
        b.routes.append({91, 1});
        st.apply(a);
        CHECK("P2 AssocCnf first -> (0,locked)", st.nodes[91].link_type == 0 && st.nodes[91].link_type_known);
        st.apply(b);
        CHECK("P2 ChangeProxyCnf later cannot override locked 0", st.nodes[91].link_type == 0 && st.nodes[91].link_type_known);
    }
    // P3
    {
        TopoState st; TopoEvent a, b;
        a.nid = 0x0E; b.nid = 0x0E;
        a.kind = TopoEventKind::ChangeProxyCnf; a.link_type = -1; a.epoch_ms = 1000;
        a.routes.append({92, 1});
        b.kind = TopoEventKind::AssocCnf; b.link_type = 1; b.epoch_ms = 2000;
        b.routes.append({92, 1});
        st.apply(a);
        CHECK("P3 failed-style event leaves 0xFF unlocked", st.nodes[92].link_type == 0xFF && !st.nodes[92].link_type_known);
        st.apply(b);
        CHECK("P3 AssocCnf later locks 1", st.nodes[92].link_type == 1 && st.nodes[92].link_type_known);
    }
    // P4
    {
        TopoState st; TopoEvent a, b;
        a.nid = 0x0E; b.nid = 0x0E;
        a.kind = TopoEventKind::ChangeProxyReq; a.link_type = 1; a.epoch_ms = 1000;
        a.routes.append({93, 1});
        b.kind = TopoEventKind::AssocCnf; b.link_type = 0; b.epoch_ms = 2000;
        b.routes.append({93, 1});
        st.apply(a);
        CHECK("P4 weak kind fills 0xFF unlocked", st.nodes[93].link_type == 1 && !st.nodes[93].link_type_known);
        st.apply(b);
        CHECK("P4 AssocCnf overrides weak 1 -> 0 locked", st.nodes[93].link_type == 0 && st.nodes[93].link_type_known);
    }
    std::printf(g_fail ? "FAILURES: %d\n" : "ALL PASS\n", g_fail);
    return g_fail ? 1 : 0;
}
