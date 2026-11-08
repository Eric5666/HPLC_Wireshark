/// 探针:拓扑异常/冲突检测(用户 2026-11 定)
/// A 同一 MAC 多 TEI / B 同一 TEI 多 MAC / C 重启次数往返振荡 / D 两链路计数不同
/// 口径:
///   A/B 通常在"旧节点仍在线"时记(正常 STA 离网后换 TEI 不算);
///       CCO/STA 共用 MAC 的角色冲突每次均记,包括旧角色已离线时;
///   C 按 (TEI, 介质) 建轨迹,取值回到"出现过的旧值"即记一次往返,
///     变成从未见过的新值不记但纳入集合(用户口径:变为了 4 就以 4 计算新的往返);
///   D 同一 TEI 载波与无线都已有取值且不相等 → 记一条(只提示不判重启),
///     同一 (载波rc, 无线rc) 组合只计一次,恢复一致后再不同仍可记;
///     两侧最近采样时间相差超过 30s 不比较(陈旧值参与会持续假报)。
///   F2 4-bit 规整前进不回绕口径:只有"连续前进 ≥2 步后回到旧值"才视为计数器回绕静默通过;
///      其余回到旧值一律记往返(差 1 的双实体振荡 9/10、11/10 必须照记)。新值一律入集合。
///   F3 A/B 行合并时 tei/tei_old 一起更新(避免显示自指 "5→5")。
/// 用法:./build/anomaly_probe ; exit 0 = 全部断言通过
#include "topo_state.h"
#include <QCoreApplication>
#include <cstdio>

static int g_fail = 0;
// 注意:expr 只求值一次 —— 断言里带副作用(如 note_restart_count 会推进状态),
// 若宏内二次求值会静默把状态改两遍,导致"全 PASS 但 failures>0"的假象。
#define CHECK(name, expr) do { \
    const bool ok_ = (expr); \
    std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", name); \
    if (!ok_) ++g_fail; } while (0)

static TopoEvent node_event(TopoEventKind kind, quint16 tei, quint64 mac, qint64 idx) {
    TopoEvent e;
    e.kind = kind;
    e.nid = 0x0E;   // 探针用真实 NID(生产不允许 NID==0 的事件进拓扑)
    e.epoch_ms = 1000 + idx;
    e.frame_index = idx;
    e.nodes.append(TeiMacPair{tei, mac});
    return e;
}

static const TopoAnomaly* find_anom(const TopoState& st, TopoAnomalyKind kind) {
    for (const TopoAnomaly& a : st.anomalies)
        if (a.kind == kind) return &a;
    return nullptr;
}

static int count_kind(const TopoState& st, TopoAnomalyKind kind) {
    int n = 0;
    for (const TopoAnomaly& a : st.anomalies)
        if (a.kind == kind) ++n;
    return n;
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    const quint64 MAC_A = 0x111111111111ULL;
    const quint64 MAC_B = 0x222222222222ULL;

    // ---------- A:同一 MAC 多 TEI ----------
    {
        TopoState st;
        st.apply(node_event(TopoEventKind::AssocCnf, 5, MAC_A, 1));
        CHECK("A1 首个 TEI 不报冲突", st.anomalies.isEmpty());
        st.apply(node_event(TopoEventKind::AssocCnf, 7, MAC_A, 2));
        const TopoAnomaly* a = find_anom(st, TopoAnomalyKind::MacMultipleTei);
        CHECK("A2 同一 MAC 迁到另一个在线 TEI → 记 1 条", a != nullptr && a->trips == 1);
        CHECK("A3 记录旧/新 TEI(5→7)", a && a->tei_old == 5 && a->tei == 7);
        CHECK("A4 记录主体 MAC", a && a->mac == MAC_A);
        CHECK("A5 记录来源帧号", a && a->first_frame == 2 && a->last_frame == 2);
    }
    // A':旧 TEI 已离线 → 正常换 TEI,不记为冲突
    {
        TopoState st;
        st.apply(node_event(TopoEventKind::AssocCnf, 5, MAC_A, 1));
        TopoEvent leave;
        leave.nid = 0x0E;
        leave.kind = TopoEventKind::LeaveInd;
        leave.epoch_ms = 1002;
        leave.frame_index = 2;
        leave.leaves.append(MAC_A);
        st.apply(leave);
        CHECK("A6 离网使旧 TEI 离线", st.nodes[5].status == NodeStatus::Offline);
        st.apply(node_event(TopoEventKind::AssocCnf, 7, MAC_A, 3));
        CHECK("A7 离网后换 TEI 不算冲突", count_kind(st, TopoAnomalyKind::MacMultipleTei) == 0);
    }

    // ---------- B:同一 TEI 多 MAC ----------
    {
        TopoState st;
        st.apply(node_event(TopoEventKind::AssocCnf, 5, MAC_A, 1));
        st.apply(node_event(TopoEventKind::AssocCnf, 5, MAC_B, 2));
        const TopoAnomaly* b = find_anom(st, TopoAnomalyKind::TeiMultipleMac);
        CHECK("B1 同一在线 TEI 换 MAC → 记 1 条", b != nullptr && b->trips == 1);
        CHECK("B2 记录旧/新 MAC", b && b->mac_old == MAC_A && b->mac == MAC_B);
        CHECK("B3 TEI 正确", b && b->tei == 5);
    }
    // B':旧节点已离线 → TEI 被复用,不记
    {
        TopoState st;
        st.apply(node_event(TopoEventKind::AssocCnf, 5, MAC_A, 1));
        TopoEvent leave;
        leave.nid = 0x0E;
        leave.kind = TopoEventKind::LeaveInd;
        leave.frame_index = 2;
        leave.leaves.append(MAC_A);
        st.apply(leave);
        st.apply(node_event(TopoEventKind::AssocCnf, 5, MAC_B, 3));
        CHECK("B4 离线后 TEI 复用不算冲突", count_kind(st, TopoAnomalyKind::TeiMultipleMac) == 0);
    }

    // ---------- C:重启次数振荡 ----------
    {
        TopoState st;
        CHECK("C1 首帧只建基线", !st.note_restart_count(3, false, 9, 1000, 1));
        // 新值 12 不算往返(从未出现过)
        CHECK("C2 出现新值 12 不记", !st.note_restart_count(3, false, 12, 1001, 2));
        // 回到旧值 9 → 往返 1
        CHECK("C3 回到旧值 9 → 记一次", st.note_restart_count(3, false, 9, 1002, 3));
        CHECK("C4 只有 1 行(合并)", count_kind(st, TopoAnomalyKind::RestartCountOscillation) == 1);
        const TopoAnomaly* c = find_anom(st, TopoAnomalyKind::RestartCountOscillation);
        CHECK("C5 记录最近方向 12→9", c && c->value_from == 12 && c->value_to == 9);
        CHECK("C6 trips 累加", c && c->trips == 1);
        CHECK("C7 再次 9→12 记第二次", st.note_restart_count(3, false, 12, 1003, 4));
        c = find_anom(st, TopoAnomalyKind::RestartCountOscillation);
        CHECK("C8 trips=2 且仍 1 行", c && c->trips == 2
              && count_kind(st, TopoAnomalyKind::RestartCountOscillation) == 1);
        CHECK("C9 同值重复不记", !st.note_restart_count(3, false, 12, 1004, 5));
        // 介质隔离:RF 侧同一 TEI 独立建轨迹
        // (注意:两链路计数不同时 D 项会返回 true 并有自己的记录,故此处只断言
        //  "载波侧振荡次数不变",不看返回值)
        st.note_restart_count(3, true, 9, 1005, 6);
        CHECK("C10 另一介质独立建基线(载波振荡次数不变)",
              count_kind(st, TopoAnomalyKind::RestartCountOscillation) == 1);
        st.note_restart_count(3, true, 7, 1006, 7);
        CHECK("C11 另一介质不产生振荡", count_kind(st, TopoAnomalyKind::RestartCountOscillation) == 1);
        CHECK("C12 载波那条仍只占 1 行", count_kind(st, TopoAnomalyKind::RestartCountOscillation) == 1);
    }
    // C':用户口径「变为了 4 则以 4 计算新的往返,4→2、2→4」
    {
        TopoState st;
        st.note_restart_count(4, false, 2, 1000, 1);
        st.note_restart_count(4, false, 3, 1001, 2);   // 新值
        CHECK("C13 2/3 交替前的首次变化不记", count_kind(st, TopoAnomalyKind::RestartCountOscillation) == 0);
        st.note_restart_count(4, false, 2, 1002, 3);   // 回旧值 → 记
        CHECK("C14 2→3→2 记一次", count_kind(st, TopoAnomalyKind::RestartCountOscillation) == 1);
        CHECK("C15 出现新值 4 不记", !st.note_restart_count(4, false, 4, 1003, 4));
        CHECK("C16 4→2 记(回到旧值)", st.note_restart_count(4, false, 2, 1004, 5));
        CHECK("C17 2→4 记(4 已成为旧值)", st.note_restart_count(4, false, 4, 1005, 6));
        const TopoAnomaly* c = find_anom(st, TopoAnomalyKind::RestartCountOscillation);
        CHECK("C18 trips=3", c && c->trips == 3);
    }
    // C'':单调递增(真实重启次数推进)不误报
    {
        TopoState st;
        bool any = false;
        for (int v = 1; v <= 15; ++v)
            any = st.note_restart_count(9, false, v, 2000 + v, v) || any;
        CHECK("C19 单调递增(含 15 上限)不报振荡", !any
              && count_kind(st, TopoAnomalyKind::RestartCountOscillation) == 0);
    }
    // C''':无该字段(0xFF)/TEI 0/越界 TEI 一律忽略
    {
        TopoState st;
        CHECK("C20 rc=0xFF 忽略", !st.note_restart_count(3, false, (int)kRestartCountInvalid, 1, 1));
        CHECK("C21 TEI=0 忽略", !st.note_restart_count(0, false, 5, 1, 1));
        CHECK("C22 TEI=0xFFFF 忽略", !st.note_restart_count(kTeiInvalid, false, 5, 1, 1));
        CHECK("C23 无异常记录", st.anomalies.isEmpty());
    }
    // ---------- D:两链路计数不同(载波 ≠ 无线,用户口径) ----------
    {
        TopoState st;
        st.note_restart_count(2, false, 1, 1000, 1);
        CHECK("D1 只有单链路计数不报", count_kind(st, TopoAnomalyKind::LinkCountMismatch) == 0);
        CHECK("D2 两链路计数不同 → 记一次", st.note_restart_count(2, true, 9, 1001, 2));
        const TopoAnomaly* d = find_anom(st, TopoAnomalyKind::LinkCountMismatch);
        CHECK("D3 记录 载波1 / 无线9", d && d->value_from == 1 && d->value_to == 9);
        CHECK("D4 记录 TEI=2", d && d->tei == 2);
        d = find_anom(st, TopoAnomalyKind::LinkCountMismatch);
        const int trips_after_first = d ? d->trips : -1;
        CHECK("D5 同一组合重复不累加", !st.note_restart_count(2, true, 9, 1002, 3));
        d = find_anom(st, TopoAnomalyKind::LinkCountMismatch);
        CHECK("D6 trips 保持不变", d && d->trips == trips_after_first && d->trips == 1);
        CHECK("D7 组合变化(2/9)再记", st.note_restart_count(2, false, 2, 1003, 4));
        d = find_anom(st, TopoAnomalyKind::LinkCountMismatch);
        CHECK("D8 trips=2 且为 2/9", d && d->trips == 2 && d->value_from == 2 && d->value_to == 9);
        CHECK("D9 仍只占 1 行", count_kind(st, TopoAnomalyKind::LinkCountMismatch) == 1);
    }
    // D':两链路一致不报;恢复一致后再不同仍可记(次数=差异出现过的不同组合数)
    {
        TopoState st;
        st.note_restart_count(5, false, 7, 1000, 1);
        CHECK("D10 无线同为 7 → 不报", !st.note_restart_count(5, true, 7, 1001, 2));
        CHECK("D11 无 D 行", count_kind(st, TopoAnomalyKind::LinkCountMismatch) == 0);
        CHECK("D12 无线变 8 → 记", st.note_restart_count(5, true, 8, 1002, 3));
        st.note_restart_count(5, true, 7, 1003, 4);   // 无线回到 7(恢复一致;RF 侧另有振荡,不在此断言)
        const TopoAnomaly* d2 = find_anom(st, TopoAnomalyKind::LinkCountMismatch);
        CHECK("D13 恢复一致后 D 行次数不变", d2 && d2->trips == 1);
        CHECK("D14 再次不同(7/9)→ 记第 2 次", st.note_restart_count(5, true, 9, 1004, 5));
        d2 = find_anom(st, TopoAnomalyKind::LinkCountMismatch);
        CHECK("D15 trips=2", d2 && d2->trips == 2 && d2->value_from == 7 && d2->value_to == 9);
    }
    // ---------- F2:4-bit 规整递增(含 15→0 回绕)不得算成往返 ----------
    {
        TopoState st;
        st.note_restart_count(7, false, 15, 1000, 1);
        CHECK("F2-1 15→0 是规整回绕,不记往返", !st.note_restart_count(7, false, 0, 1001, 2));
        CHECK("F2-2 回绕后无异常行", st.anomalies.isEmpty());
        for (int v = 1; v <= 15; ++v)   // 0,1,…,15 绕一整圈
            st.note_restart_count(7, false, v, 1002 + v, 3 + v);
        CHECK("F2-3 单调绕一圈仍是 0 行", st.anomalies.isEmpty());
        CHECK("F2-4 15→0 再回绕不记", !st.note_restart_count(7, false, 0, 1200, 40));
        CHECK("F2-5 0→15 回到旧值记 1 次", st.note_restart_count(7, false, 15, 1201, 41));
        const TopoAnomaly* c = find_anom(st, TopoAnomalyKind::RestartCountOscillation);
        CHECK("F2-6 trips=1", c && c->trips == 1);
    }
    // ---------- F2b(复核驳回回归):差 1 的双实体振荡不得被"回绕豁免"吞掉 ----------
    // 旧实现(单步 forward 豁免 + forward 不入 seen)会把 9/10、11/10 这类只差 1 的振荡整段吞掉。
    // 现改为"回到旧值即记,唯一例外是连续前进 ≥2 步后的回绕"。
    {
        TopoState st;   // 复核场景2(对照组):9→10→11→9 —— 9 在初始集合里,应记 1
        st.note_restart_count(8, false, 9, 1000, 1);
        st.note_restart_count(8, false, 10, 1001, 2);
        st.note_restart_count(8, false, 11, 1002, 3);
        CHECK("F2b-0a 9→10→11→9 记 1 次", st.note_restart_count(8, false, 9, 1003, 4));
        const TopoAnomaly* c0 = find_anom(st, TopoAnomalyKind::RestartCountOscillation);
        CHECK("F2b-0b 最近 11→9",
              c0 && c0->value_from == 11 && c0->value_to == 9 && c0->trips == 1);
    }
    {
        TopoState st;
        st.note_restart_count(8, false, 9, 1000, 1);
        st.note_restart_count(8, false, 10, 1001, 2);
        st.note_restart_count(8, false, 11, 1002, 3);
        CHECK("F2b-1 9→10→11→10 记 1 次", st.note_restart_count(8, false, 10, 1003, 4));
        const TopoAnomaly* c = find_anom(st, TopoAnomalyKind::RestartCountOscillation);
        CHECK("F2b-2 行数=1 且最近 11→10",
              count_kind(st, TopoAnomalyKind::RestartCountOscillation) == 1
              && c && c->value_from == 11 && c->value_to == 10);
    }
    {
        TopoState st;   // 11/10 交替 ×8(起始 11)
        st.note_restart_count(8, false, 11, 1000, 1);
        int trips = 0;
        for (int i = 0; i < 8; ++i) {
            const int v = (i % 2 == 0) ? 10 : 11;
            if (st.note_restart_count(8, false, v, 1001 + i, 2 + i)) ++trips;
        }
        CHECK("F2b-3 11/10 交替 8 次 ⇒ 记 7 次", trips == 7);
        CHECK("F2b-4 仍只占 1 行",
              count_kind(st, TopoAnomalyKind::RestartCountOscillation) == 1);
    }
    {
        TopoState st;   // 9/10 交替 ×8(起始 9)
        st.note_restart_count(8, false, 9, 1000, 1);
        int trips = 0;
        for (int i = 0; i < 8; ++i) {
            const int v = (i % 2 == 0) ? 10 : 9;
            if (st.note_restart_count(8, false, v, 1001 + i, 2 + i)) ++trips;
        }
        CHECK("F2b-5 9/10 交替 8 次 ⇒ 记 7 次", trips == 7);
        CHECK("F2b-6 仍只占 1 行",
              count_kind(st, TopoAnomalyKind::RestartCountOscillation) == 1);
    }
    {
        TopoState st;   // 单调 0..15 绕一整圈 ⇒ 0 行;随后的 15→0 属正常回绕
        st.note_restart_count(9, false, 0, 1000, 1);
        for (int v = 1; v <= 15; ++v)
            st.note_restart_count(9, false, v, 1001 + v, 2 + v);
        CHECK("F2b-7 0..15 单调绕一圈 ⇒ 0 行", st.anomalies.isEmpty());
        CHECK("F2b-8 连续前进后 15→0 回绕抑制生效",
              !st.note_restart_count(9, false, 0, 1100, 40));
        CHECK("F2b-9 回绕后仍 0 行", st.anomalies.isEmpty());
    }
    {
        TopoState st;   // 15→0 作为首个变化:0 从未出现 ⇒ 属新值,不记
        st.note_restart_count(10, false, 15, 1000, 1);
        CHECK("F2b-10 首个变化 15→0 不记(0 未见过)",
              !st.note_restart_count(10, false, 0, 1001, 2));
        CHECK("F2b-11 无异常行", st.anomalies.isEmpty());
    }

    // ---------- F1:D 只在两侧同样新鲜时比较(陈旧值不得参与) ----------
    {
        TopoState st;
        const qint64 t0 = 1000000;
        st.note_restart_count(6, false, 12, t0, 1);                       // 载波 12
        CHECK("F1-1 同刻无线 9 → 记 1 次差异", st.note_restart_count(6, true, 9, t0 + 5, 2));
        CHECK("F1-2 D 行已存在", count_kind(st, TopoAnomalyKind::LinkCountMismatch) == 1);
        const int trips1 = find_anom(st, TopoAnomalyKind::LinkCountMismatch)->trips;
        // +60s 只有载波变化:无线侧已陈旧(窗口 30s)⇒ 不比较、不新增
        CHECK("F1-3 无线陈旧时载波变化不新增", !st.note_restart_count(6, false, 5, t0 + 60000, 3));
        CHECK("F1-4 D 次数未变", find_anom(st, TopoAnomalyKind::LinkCountMismatch)->trips == trips1);
        // 无线恢复新鲜且与载波一致(5)⇒ D 状态清除
        CHECK("F1-5 无线新鲜回到与载波一致 → 清 D 状态",
              !st.note_restart_count(6, true, 5, t0 + 60010, 4));
        // 两者都新鲜且再次不一致 ⇒ 按新组合重记(证明上面确实清了状态)
        CHECK("F1-6 之后的差异按新组合记录", st.note_restart_count(6, true, 12, t0 + 60020, 5));
        const TopoAnomaly* d = find_anom(st, TopoAnomalyKind::LinkCountMismatch);
        CHECK("F1-7 新组合为 载波5/无线12", d && d->value_from == 5 && d->value_to == 12);
        CHECK("F1-8 仍只占 1 行", count_kind(st, TopoAnomalyKind::LinkCountMismatch) == 1);
    }
    // ---------- F3:A 行合并后 tei 必须跟着更新(不能显示自指 "5→5") ----------
    {
        TopoState st;
        const quint64 M = 0x999999999999ULL;
        st.apply(node_event(TopoEventKind::AssocCnf, 3, M, 1));
        st.apply(node_event(TopoEventKind::AssocCnf, 5, M, 2));   // 3→5 冲突第 1 次
        st.apply(node_event(TopoEventKind::AssocCnf, 3, M, 3));   // 5→3 冲突第 2 次
        const TopoAnomaly* a = find_anom(st, TopoAnomalyKind::MacMultipleTei);
        CHECK("F3-1 A 行 tei 与 tei_old 不同(非自指)", a && a->tei != a->tei_old);
        CHECK("F3-2 合并后 tei=3 且 tei_old=5", a && a->tei == 3 && a->tei_old == 5);
        CHECK("F3-3 trips=2", a && a->trips == 2);
    }

    // ---------- 长序列不刷屏:一次抓包式交替只占 1 行 ----------
    {
        TopoState st;
        st.note_restart_count(3, false, 9, 1000, 1);
        int trips = 0;
        for (int i = 0; i < 100; ++i) {
            const int v = (i % 2 == 0) ? 12 : 9;
            if (st.note_restart_count(3, false, v, 1001 + i, 2 + i)) ++trips;
        }
        CHECK("E1 100 帧交替只记 1 行", st.anomalies.size() == 1);
        const TopoAnomaly* c = find_anom(st, TopoAnomalyKind::RestartCountOscillation);
        CHECK("E2 trips 累加等于往返次数", c && c->trips == trips && trips == 99);
        CHECK("E3 记录最近帧号", c && c->last_frame == 101);
    }

    std::printf("\n%s (%d failures)\n", g_fail ? "RESULT: FAIL" : "RESULT: ALL PASS", g_fail);
    return g_fail ? 1 : 0;
}
