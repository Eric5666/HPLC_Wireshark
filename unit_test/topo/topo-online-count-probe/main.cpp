/// 探针:TOPO 在网节点数 TopoState::online_counts()(用户 2026-11-06 定稿口径)
/// 口径:
///   主数 online 仅统计 status == Online 的 STA,不含 CCO(TEI 固定为 1,kTeiCco)、
///   不含入网中(OnlineGoing / pending)、不含离线;入网中和离线另行给出。
/// 覆盖:
///   T1  空状态全 0;T2 只有 CCO 时主数仍为 0;T3 关联请求(TEI 未分配)→pending 计入网中;
///   T4  关联请求(TEI 已知)→nodes 计入网中;T5 关联确认晋升在线(pending 移除,不重复计);
///   T6  两 STA 在线 + CCO 不计;T7 离网指示→在线减 1、离线加 1;
///   T8  切 NID 不串数(两 TopoState 实例,同 MAC/TEI 各自独立);
///   T9  历史回放冻结(快照拷贝后 live 再演进,快照计数不变);
///   T10 TEI 复用异常按 TEI 数计(同一 MAC 先后占两个在线 TEI,主数计 2,不去重)
///   T11 has_topology_content() 边界:空状态 false(窗口显示 —)、首帧后 true(窗口显示数字)
/// 用法:./build/online_count_probe ; exit 0 = 全部断言通过
#include "topo_state.h"
#include <QCoreApplication>
#include <cstdio>

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { std::printf("FAIL: %s\n", msg); ++failures; } \
    else { std::printf("ok: %s\n", msg); } } while (0)

static TopoEvent assoc_req(quint16 tei, quint64 mac, qint64 idx,
                           quint32 nid = 0x0E) {
    TopoEvent e;
    e.kind = TopoEventKind::AssocReq;
    e.nid = nid;
    e.restart_count = -1;  // 本探针不测重启,无该字段
    e.nodes.append({tei, mac});
    e.epoch_ms = 1000 + idx;
    e.frame_index = idx;
    return e;
}

static TopoEvent assoc_cnf(quint16 tei, quint64 mac, qint64 idx,
                           quint64 cco_mac, quint32 nid = 0x0E) {
    TopoEvent e;
    e.kind = TopoEventKind::AssocCnf;
    e.nid = nid;
    e.restart_count = -1;
    e.cco_mac = cco_mac;
    e.nodes.append({tei, mac});
    e.epoch_ms = 1000 + idx;
    e.frame_index = idx;
    return e;
}

static TopoEvent leave_ind(quint64 mac, qint64 idx, quint32 nid = 0x0E) {
    TopoEvent e;
    e.kind = TopoEventKind::LeaveInd;
    e.nid = nid;
    e.restart_count = -1;
    e.leaves.append(mac);
    e.epoch_ms = 1000 + idx;
    e.frame_index = idx;
    return e;
}

static bool counts_eq(const TopoOnlineCounts& c, int online, int going, int offline) {
    return c.online == online && c.online_going == going && c.offline == offline;
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);

    const quint64 MAC_CCO = 0x001122334455ULL;
    const quint64 MAC_A = 0xAABBCCDDEEFFULL;
    const quint64 MAC_B = 0x112233445566ULL;

    // T1:空状态全 0
    {
        TopoState st;
        CHECK(counts_eq(st.online_counts(), 0, 0, 0), "T1 empty state counts are all zero");
    }
    // T2:只有 CCO 时主数仍为 0(CCO 不计入在网节点数)
    {
        TopoState st;
        TopoEvent e;
        e.kind = TopoEventKind::AssocCnf;
        e.nid = 0x0E;
        e.restart_count = -1;
        e.cco_mac = MAC_CCO;
        e.epoch_ms = 1001;
        e.frame_index = 1;
        st.apply(e);
        CHECK(st.nodes.contains(kTeiCco), "T2a CCO node exists after AssocCnf with cco_mac");
        CHECK(counts_eq(st.online_counts(), 0, 0, 0), "T2b CCO only does not count as online STA");
    }
    // T3:关联请求(TEI 未分配)→pending 计入网中
    {
        TopoState st;
        st.apply(assoc_req(0, MAC_A, 1));
        CHECK(st.pending.contains(MAC_A), "T3a AssocReq with TEI 0 creates a pending node");
        CHECK(counts_eq(st.online_counts(), 0, 1, 0), "T3b pending node counts as joining, not online");
    }
    // T4:关联请求(TEI 已知)→nodes 计入网中
    {
        TopoState st;
        st.apply(assoc_req(2, MAC_A, 1));
        CHECK(counts_eq(st.online_counts(), 0, 1, 0), "T4 AssocReq with TEI counts as joining in nodes");
    }
    // T5:关联确认晋升在线(pending 移除,不重复计)
    {
        TopoState st;
        st.apply(assoc_req(0, MAC_A, 1));
        CHECK(counts_eq(st.online_counts(), 0, 1, 0), "T5a joining before AssocCnf");
        st.apply(assoc_cnf(2, MAC_A, 2, MAC_CCO));
        CHECK(!st.pending.contains(MAC_A), "T5b pending removed after AssocCnf");
        CHECK(counts_eq(st.online_counts(), 1, 0, 0), "T5c promoted STA counts once as online");
    }
    // T6:两 STA 在线 + CCO 不计
    {
        TopoState st;
        st.apply(assoc_cnf(2, MAC_A, 1, MAC_CCO));
        st.apply(assoc_cnf(3, MAC_B, 2, MAC_CCO));
        CHECK(counts_eq(st.online_counts(), 2, 0, 0), "T6 two online STAs plus CCO count as 2");
    }
    // T7:离网指示→在线减 1、离线加 1
    {
        TopoState st;
        st.apply(assoc_cnf(2, MAC_A, 1, MAC_CCO));
        st.apply(assoc_cnf(3, MAC_B, 2, MAC_CCO));
        st.apply(leave_ind(MAC_A, 3));
        CHECK(counts_eq(st.online_counts(), 1, 0, 1), "T7 LeaveInd moves one STA from online to offline");
    }
    // T8:切 NID 不串数(两 TopoState 实例,同 MAC/TEI 各自独立)
    {
        TopoState s1, s2;
        s1.apply(assoc_cnf(2, MAC_A, 1, MAC_CCO, 0x0E));
        s2.apply(assoc_cnf(2, MAC_A, 1, MAC_CCO, 0x14));
        CHECK(counts_eq(s1.online_counts(), 1, 0, 0)
              && counts_eq(s2.online_counts(), 1, 0, 0),
              "T8a same MAC/TEI under two NIDs counts independently");
        s1.apply(leave_ind(MAC_A, 2, 0x0E));
        CHECK(counts_eq(s1.online_counts(), 0, 0, 1)
              && counts_eq(s2.online_counts(), 1, 0, 0),
              "T8b leave in one NID does not affect the other NID");
    }
    // T9:历史回放冻结(快照拷贝后 live 再演进,快照计数不变)
    {
        TopoState live;
        live.apply(assoc_cnf(2, MAC_A, 1, MAC_CCO));
        const TopoState snapshot = live;  // 冻结快照(回放模式读快照,不跟随新帧)
        live.apply(assoc_cnf(3, MAC_B, 2, MAC_CCO));
        live.apply(leave_ind(MAC_A, 3));
        CHECK(counts_eq(live.online_counts(), 1, 0, 1), "T9a live state advances after snapshot");
        CHECK(counts_eq(snapshot.online_counts(), 1, 0, 0), "T9b snapshot counts stay frozen");
    }
    // T10:TEI 复用异常按 TEI 数计(同一 MAC 先后占两个在线 TEI,主数计 2,不去重)
    {
        TopoState st;
        st.apply(assoc_cnf(2, MAC_A, 1, MAC_CCO));
        st.apply(assoc_cnf(3, MAC_A, 2, MAC_CCO));
        CHECK(counts_eq(st.online_counts(), 2, 0, 0),
              "T10a same MAC on two online TEIs counts as 2 (no dedup)");
        bool anomaly = false;
        for (const TopoAnomaly& a : st.anomalies)
            if (a.kind == TopoAnomalyKind::MacMultipleTei) anomaly = true;
        CHECK(anomaly, "T10b TEI reuse is still recorded as a MacMultipleTei anomaly");
    }
    // T11:has_topology_content() 边界(窗口"— vs 数字"的分界)
    {
        TopoState st;
        CHECK(!st.has_topology_content(), "T11a empty state has no topology content (window shows dash)");
        st.apply(assoc_req(0, MAC_A, 1));
        CHECK(st.has_topology_content(), "T11b first frame makes content visible (window shows numbers)");
    }

    std::printf(failures ? "RESULT: %d FAILURES\n" : "RESULT: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
