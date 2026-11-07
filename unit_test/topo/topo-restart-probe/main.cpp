/// 探针:TopoState 重启检测 —— 方案 B(全帧采样 + (NID, 主体 MAC) 分键)
/// 覆盖:
///   A/B/C 既有口径(sender_mac==0 回落主体 MAC、中继按发送方建基线、无键静默跳过)
///   D     方案 B 新增:CCO/STA 非白名单帧、NID 隔离、MAC 隔离、TEI=1 归 CCO、
///         逐帧采样路径(note_restart_origin)、同帧不重复报、无变化不报
///   D13   身份记忆按 (NID, MAC) 分键:同 MAC 在不同 NID 下 CCO/STA 身份互不串
///   D14   mac_to_tei 按 (NID, MAC) 分键:同 MAC 在不同 NID 下映射到不同 TEI,互不串
/// 用法:./probe ; exit 0 = 全部断言通过
#include "topo_state.h"
#include <QCoreApplication>
#include <cstdio>

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { std::printf("FAIL: %s\n", msg); ++failures; } \
    else { std::printf("ok: %s\n", msg); } } while (0)

static TopoEvent assoc(quint64 sender, quint64 subject_mac, int restart, qint64 idx) {
    TopoEvent e;
    e.kind = TopoEventKind::AssocReq;
    e.nid = 0x0E;   // 探针用真实 NID(生产不允许 NID==0 的事件进拓扑)
    e.restart_count = restart;
    e.sender_mac = sender;
    if (subject_mac) e.nodes.append({0, subject_mac});
    e.epoch_ms = 1000 + idx;
    e.frame_index = idx;
    return e;
}

static int count_kind(const TopoState& st, TopoEventKind k) {
    int n = 0;
    for (const TopoEvent& ev : st.events)
        if (ev.kind == k) ++n;
    return n;
}

static int count_restart_events(const TopoState& st) {
    return count_kind(st, TopoEventKind::StaRestart);
}

/// @brief 构造任意种类的帧级事件(方案 B:采样点不再限于发现列表/关联请求)
static TopoEvent frame(TopoEventKind kind, quint32 nid, quint64 sender, int restart,
                       qint64 idx, quint64 cco_mac = 0) {
    TopoEvent e;
    e.kind = kind;
    e.nid = nid;
    e.sender_mac = sender;
    e.restart_count = restart;
    e.cco_mac = cco_mac;
    e.epoch_ms = 1000 + idx;
    e.frame_index = idx;
    return e;
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);

    const quint64 MAC_A   = 0xAABBCCDDEEFFULL; // 主体 STA,显示为 ff:ee:dd:cc:bb:aa
    const quint64 MAC_B   = 0x112233445566ULL; // 发送方(中继)/第二主体,显示为 66:55:44:33:22:11
    const quint64 MAC_CCO = 0x001122334455ULL; // CCO,显示为 55:44:33:22:11:00

    // A: sender_mac==0 回落主体 MAC —— 基线建立 + 变化检出
    {
        TopoState st;
        st.apply(assoc(0, MAC_A, 2, 1));
        CHECK(count_restart_events(st) == 0, "A1 sender=0 首帧建基线不报重启");
        CHECK(st.pending.contains(MAC_A), "A2 sender=0 仍正常建 pending 节点");
        st.apply(assoc(0, MAC_A, 3, 2));
        CHECK(count_restart_events(st) == 1, "A3 sender=0 重启次数变化报 1 次 StaRestart");
        bool desc_ok = false;
        for (const TopoEvent& ev : st.events)
            if (ev.kind == TopoEventKind::StaRestart)
                desc_ok = ev.desc.contains(QStringLiteral("ff:ee:dd:cc:bb:aa"))
                       && ev.desc.contains(QStringLiteral("2→3"));
        CHECK(desc_ok, "A4 StaRestart 描述用主体 MAC 且次数 2→3");
        st.apply(assoc(0, MAC_A, 3, 3));
        CHECK(count_restart_events(st) == 1, "A5 次数不变不重复报");
    }
    // B: sender_mac 非零时仍按发送方建基线(52bd2eb0 口径不退化)
    {
        TopoState st;
        st.apply(assoc(MAC_B, MAC_A, 2, 1));
        st.apply(assoc(MAC_B, MAC_A, 2, 2));
        CHECK(count_restart_events(st) == 0, "B1 发送方基线次数不变不报");
        st.apply(assoc(MAC_B, MAC_A, 5, 3));
        CHECK(count_restart_events(st) == 1, "B2 发送方次数变化报 1 次");
        bool desc_ok = false;
        for (const TopoEvent& ev : st.events)
            if (ev.kind == TopoEventKind::StaRestart)
                desc_ok = ev.desc.contains(QStringLiteral("66:55:44:33:22:11"));
        CHECK(desc_ok, "B3 中继情形描述仍用发送方 MAC 而非主体");
    }
    // C: sender_mac==0 且 nodes 为空 —— 无键可建,静默跳过且不崩
    {
        TopoState st;
        st.apply(assoc(0, 0, 2, 1));
        st.apply(assoc(0, 0, 3, 2));
        CHECK(count_restart_events(st) == 0, "C 无源无主体时跳过且不崩");
    }

    // ================= 方案 B:全帧采样 + (NID, 主体 MAC) 分键 =================
    // D1: CCO 非发现列表帧(旧路径只在 DiscoverList 上采 CCO ⇒ 必漏)
    {
        TopoState st;
        st.apply(frame(TopoEventKind::AssocCnf, 0x0E, MAC_CCO, 3, 1, MAC_CCO));
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 0, "D1a 首帧只建 CCO 基线不报");
        st.apply(frame(TopoEventKind::SuccessRate, 0x0E, MAC_CCO, 4, 2, MAC_CCO));
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 1,
              "D1b 非发现列表帧 CCO 计数 3→4 报 1 条(旧路径必漏)");
        CHECK(count_restart_events(st) == 0, "D1c CCO 变化不误记 STA");
        bool ok = false;
        for (const TopoEvent& ev : st.events)
            if (ev.kind == TopoEventKind::CcoRestart)
                ok = ev.desc.contains(QStringLiteral("3→4")) && ev.nid == 0x0E;
        CHECK(ok, "D1d CcoRestart 文案 3→4 且事件带 NID");
    }
    // D2: STA 非关联请求帧(旧路径只在 AssocReq 上采 STA ⇒ 必漏)
    {
        TopoState st;
        st.apply(frame(TopoEventKind::ChangeProxyCnf, 0x0E, MAC_A, 5, 1));
        st.apply(frame(TopoEventKind::ChangeProxyCnf, 0x0E, MAC_A, 6, 2));
        CHECK(count_restart_events(st) == 1, "D2 非关联请求帧 STA 计数 5→6 报 1 条(旧路径必漏)");
    }
    // D3: NID 隔离(旧 CCO 基线是单一全局值 ⇒ 多 NID 互相踩)
    {
        TopoState s1, s2;
        s1.apply(frame(TopoEventKind::SuccessRate, 0x000E, MAC_A, 3, 1));
        s2.apply(frame(TopoEventKind::SuccessRate, 0x0014, MAC_A, 3, 1));
        s1.apply(frame(TopoEventKind::SuccessRate, 0x000E, MAC_A, 4, 2));
        CHECK(count_restart_events(s1) == 1 && count_restart_events(s2) == 0,
              "D3a 不同 NID 同 MAC 各建基线,一方变化不影响另一方");
        s2.apply(frame(TopoEventKind::SuccessRate, 0x0014, MAC_A, 4, 2));
        CHECK(count_restart_events(s2) == 1, "D3b 另一 NID 自身变化时也报 1 条");

        TopoState st;   // 同一实例内 NID 改变 ⇒ 视为不同主体
        st.apply(frame(TopoEventKind::SuccessRate, 0x000E, MAC_A, 7, 1));
        st.apply(frame(TopoEventKind::SuccessRate, 0x0014, MAC_A, 7, 2));
        CHECK(count_restart_events(st) == 0, "D3c 同一实例改 NID 后同计数不报(基线按 NID 分键)");
        st.apply(frame(TopoEventKind::SuccessRate, 0x0014, MAC_A, 8, 3));
        CHECK(count_restart_events(st) == 1, "D3d 新 NID 内自身变化才报");
    }
    // D4: MAC 隔离(同 NID 下两个主体各建各的基线,文案不串)
    {
        TopoState st;
        st.apply(frame(TopoEventKind::AssocCnf, 0x0E, MAC_A, 3, 1));
        st.apply(frame(TopoEventKind::AssocCnf, 0x0E, MAC_B, 7, 2));
        st.apply(frame(TopoEventKind::AssocCnf, 0x0E, MAC_A, 4, 3));
        st.apply(frame(TopoEventKind::AssocCnf, 0x0E, MAC_B, 8, 4));
        CHECK(count_restart_events(st) == 2, "D4a 同 NID 两 MAC 各报 1 条(共 2 条,不串)");
        int a = 0, b = 0;
        for (const TopoEvent& ev : st.events) {
            if (ev.kind != TopoEventKind::StaRestart) continue;
            if (ev.desc.contains(QStringLiteral("ff:ee:dd:cc:bb:aa"))
                && ev.desc.contains(QStringLiteral("3→4"))) ++a;
            if (ev.desc.contains(QStringLiteral("66:55:44:33:22:11"))
                && ev.desc.contains(QStringLiteral("7→8"))) ++b;
        }
        CHECK(a == 1 && b == 1, "D4b 两条文案里 MAC 与次数各自正确");
    }
    // D5: TEI=1(固定)归 CCO —— cco_mac 未知时也能判
    {
        TopoState st;
        TopoEvent learn;
        learn.kind = TopoEventKind::DiscoverList;
        learn.nid = 0x0E;
        learn.restart_count = -1;        // 本帧不带重启次数
        learn.frame_index = 1;
        learn.epoch_ms = 1001;
        learn.nodes.append({kTeiCco, MAC_CCO});
        st.apply(learn);
        CHECK(st.mac_to_tei.value(TopoState::nid_mac_key(0x0E, MAC_CCO), quint16(0)) == kTeiCco, "D5a 已学到 TEI=1 → CCO MAC");
        CHECK(st.cco_mac == MAC_CCO, "D5b TEI=1 学习同步最新 CCO MAC");
        st.cco_mac = 0; // 模拟兼容路径未持有 CCO 字段,仍必须用索引正确归属
        st.apply(frame(TopoEventKind::AssocCnf, 0x0E, MAC_CCO, 2, 2));
        st.apply(frame(TopoEventKind::AssocCnf, 0x0E, MAC_CCO, 3, 3));
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 1,
              "D5c MAC 已映射到 TEI=1 ⇒ 判 CCO(不依赖 cco_mac)");
    }
    // D6: 同值重复不报
    {
        TopoState st;
        for (int i = 0; i < 5; ++i) st.apply(frame(TopoEventKind::AssocCnf, 0x0E, MAC_A, 9, i));
        CHECK(count_restart_events(st) == 0, "D6 同值重复 5 次 0 条");
    }
    // D7: 逐帧采样路径(mainwindow 每帧调用),CCO/STA 归属与无源不检测
    {
        TopoState st;
        CHECK(!st.note_restart_origin(0x0E, 5, MAC_A, 2, 1000, 1, false, true),
              "D7a 逐帧首帧建基线不报");
        CHECK(st.note_restart_origin(0x0E, 5, MAC_A, 3, 1001, 2, false, true),
              "D7b 逐帧 STA 计数 2→3 报变化");
        CHECK(count_restart_events(st) == 1, "D7c 逐帧路径产出 StaRestart");
        CHECK(!st.note_restart_origin(0x0E, kTeiCco, MAC_CCO, 5, 1002, 3, false, true),
              "D7d 逐帧 CCO(TEI=1)首帧建基线不报");
        CHECK(st.note_restart_origin(0x0E, kTeiCco, MAC_CCO, 6, 1003, 4, false, true),
              "D7e 逐帧 CCO 计数 5→6 报变化");
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 1, "D7f 逐帧路径产出 CcoRestart");
        CHECK(!st.note_restart_origin(0x0E, 5, 0, 9, 1004, 5, false, true),
              "D7g src_mac=0 不检测(宁可不报,也不串主体)");
        CHECK(!st.note_restart_origin(0x0E, 5, MAC_A, kRestartCountInvalid, 1005, 6, false, true),
              "D7h 重启次数 0xFF(无该字段)不采样");
    }
    // D7i: 普通数据帧早于首个拓扑事件时,有效 NID + RestartCount 也建立轻量基线；
    //      基线-only 状态不显示为空拓扑,后续计数变化可报告且事件侧不重复。
    {
        QHash<quint32, TopoState> states;
        TopoState* st = ensure_restart_sample_state(states, 0x0E, 7);
        CHECK(st != nullptr && states.size() == 1 && st->nid == 0x0E,
              "D7i 有效 NID/RestartCount 创建采样状态");
        CHECK(!st->has_topology_content(), "D7j 仅有计数基线时不显示空拓扑");
        CHECK(!st->note_restart_origin(0x0E, 5, MAC_A, 7, 1000, 1, false, true),
              "D7k 首个普通帧只建立 STA 基线");
        CHECK(st->note_restart_origin(0x0E, 5, MAC_A, 8, 1001, 2, false, true),
              "D7l 拓扑建档前的后续计数变化仍报重启");
        CHECK(count_kind(*st, TopoEventKind::StaRestart) == 1 && st->has_topology_content(),
              "D7m 变化事件可见且只产生一条");
        TopoEvent assoc = frame(TopoEventKind::AssocReq, 0x0E, MAC_A, 8, 3);
        st->apply(assoc);
        CHECK(count_kind(*st, TopoEventKind::StaRestart) == 1,
              "D7n 后续拓扑事件复用同一基线,不重复报重启");
        CHECK(ensure_restart_sample_state(states, 0, 4) == nullptr
                  && ensure_restart_sample_state(states, 0x0F, kRestartCountInvalid) == nullptr
                  && states.size() == 1,
              "D7o NID==0/无效 RestartCount 不新建采样状态");
    }

    // D8: 同一帧既走事件侧又走逐帧侧 ⇒ 只报一次
    {
        TopoState st;
        st.apply(frame(TopoEventKind::AssocCnf, 0x0E, MAC_A, 3, 1));
        st.apply(frame(TopoEventKind::AssocCnf, 0x0E, MAC_A, 4, 2));
        CHECK(count_restart_events(st) == 1, "D8a 事件侧已报 1 条");
        CHECK(!st.note_restart_origin(0x0E, 0, MAC_A, 4, 1002, 2, false, true),
              "D8b 同帧逐帧侧不重复报(基线已相等)");
        CHECK(count_restart_events(st) == 1, "D8c 总数仍为 1");
    }

    // D9(M2 回归):发现列表缺源 MAC(src_tei==1、src_mac==0)⇒ 归 CCO,不得记到 nodes 里那个 STA 头上
    {
        TopoState st;
        TopoEvent dl = frame(TopoEventKind::DiscoverList, 0x0E, 0, 3, 1);
        dl.nodes.append({5, MAC_A});   // 发现列表里第一个 STA:旧实现会把 CCO 的重启记到它头上
        st.apply(dl);
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 0
              && count_restart_events(st) == 0, "D9a 首帧只建 CCO 基线(不误记 STA)");
        dl.restart_count = 4;
        dl.frame_index = 2;
        dl.epoch_ms = 1002;
        st.apply(dl);
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 1,
              "D9b CCO 缺源 MAC 时仍报 1 条 CcoRestart");
        bool bad = false;
        for (const TopoEvent& ev : st.events) {
            if (ev.kind == TopoEventKind::StaRestart) bad = true;
            if (ev.kind == TopoEventKind::CcoRestart
                && ev.desc.contains(QStringLiteral("ff:ee:dd:cc:bb:aa"))) bad = true;
        }
        CHECK(!bad, "D9c 不出现任何 StaRestart,也不把 STA MAC 写进 CCO 文案");
        // 逐帧侧同场景(src_tei==1、src_mac==0)归同一条 CCO 基线,不重复报
        CHECK(!st.note_restart_origin(0x0E, kTeiCco, 0, 4, 1002, 2, false, true),
              "D9d 逐帧侧 CCO 缺 MAC 与事件侧同一基线,不重复报");
        CHECK(st.note_restart_origin(0x0E, kTeiCco, 0, 5, 1003, 3, false, true),
              "D9e 逐帧侧下一帧计数变化仍能报 CcoRestart");
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 2
              && count_restart_events(st) == 0, "D9f CCO 2 条、STA 0 条");
    }
    // D10(M1 回归):事件侧无 CCO 证据、逐帧侧 src_tei==1 —— 同一次变化只报 1 条且归 CCO
    {
        TopoState st;
        const quint64 MAC_X = 0x0A0B0C0D0E0FULL;
        // 帧1:事件侧先建基线(此时无 CCO 证据),随后逐帧侧按 TEI=1 认出 CCO 并写入身份记忆
        st.apply(frame(TopoEventKind::AssocCnf, 0x0E, MAC_X, 3, 1));
        st.note_restart_origin(0x0E, kTeiCco, MAC_X, 3, 1001, 1, false, true);
        // 帧2:计数 3→4(两侧都会看到)
        st.apply(frame(TopoEventKind::AssocCnf, 0x0E, MAC_X, 4, 2));
        st.note_restart_origin(0x0E, kTeiCco, MAC_X, 4, 1002, 2, false, true);
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 1
              && count_restart_events(st) == 0,
              "D10 同一次变化只报 1 条且为 CcoRestart(M1)");
    }
    // D11:两条路径身份一致 —— 同一 (nid,mac)、同一变化,各自单独跑都产出同类事件
    {
        TopoState a, b;
        a.apply(frame(TopoEventKind::AssocCnf, 0x0E, MAC_CCO, 2, 1, MAC_CCO));   // 事件侧带 cco_mac
        a.apply(frame(TopoEventKind::AssocCnf, 0x0E, MAC_CCO, 3, 2, MAC_CCO));
        b.note_restart_origin(0x0E, kTeiCco, MAC_CCO, 2, 1001, 1, false, true);  // 逐帧侧 src_tei=1
        b.note_restart_origin(0x0E, kTeiCco, MAC_CCO, 3, 1002, 2, false, true);
        CHECK(count_kind(a, TopoEventKind::CcoRestart) == 1
              && count_restart_events(a) == 0, "D11a 事件侧判 CCO");
        CHECK(count_kind(b, TopoEventKind::CcoRestart) == 1
              && count_restart_events(b) == 0, "D11b 逐帧侧判 CCO(两路径一致)");
    }
    // D12:身份记忆 —— 先以 CCO 身份见过该 MAC,随后事件缺 cco_mac 仍判 CCO
    {
        TopoState st;
        st.apply(frame(TopoEventKind::AssocCnf, 0x0E, MAC_CCO, 2, 1, MAC_CCO));  // 带 cco_mac ⇒ 记住
        st.apply(frame(TopoEventKind::AssocCnf, 0x0E, MAC_CCO, 3, 2));          // 缺 cco_mac
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 1
              && count_restart_events(st) == 0,
              "D12b 身份记忆生效:缺 cco_mac 仍归 CCO,不漂移成 STA");
    }
    // D13:身份记忆按 (NID, MAC) 分键 —— 同一 MAC 在 NID 0x0E 是 CCO,在 NID 0x14 是 STA,互不串
    //     (逐帧侧不经过 mac_to_tei 学习,本用例只测 m_cco_macs 本身;旧 MAC-only 记忆会把
    //      NID 0x14 的同一 MAC 也判成 CCO ⇒ D13f 失败)
    {
        TopoState st;
        const quint64 MAC_X = 0x0A0B0C0D0E0FULL;
        // NID 0x0E:逐帧侧 src_tei==1 认出 CCO,写入 (0x0E, MAC_X) 身份记忆
        CHECK(!st.note_restart_origin(0x0E, kTeiCco, MAC_X, 2, 1001, 1, false, true),
              "D13a NID 0x0E 首帧建 CCO 基线不报");
        CHECK(st.note_restart_origin(0x0E, kTeiCco, MAC_X, 3, 1002, 2, false, true),
              "D13b NID 0x0E 计数 2→3 报 CcoRestart");
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 1,
              "D13c NID 0x0E 共 1 条 CcoRestart");
        // NID 0x14:同一 MAC、无 CCO 证据 ⇒ 判 STA
        CHECK(!st.note_restart_origin(0x14, 5, MAC_X, 5, 1003, 3, false, true),
              "D13d NID 0x14 首帧建 STA 基线不报");
        CHECK(st.note_restart_origin(0x14, 5, MAC_X, 6, 1004, 4, false, true),
              "D13e NID 0x14 计数 5→6 报 StaRestart");
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 1
              && count_restart_events(st) == 1,
              "D13f 两 NID 各 1 条、互不串(CCO 1 + STA 1)");
    }
    // D14:mac_to_tei 按 (NID, MAC) 分键 —— 同一 MAC 在 NID 0x0E 是 CCO(TEI=1)、在 NID 0x14 是 STA(TEI=5)
    //     (事件侧;旧 MAC-only 索引会把 0x14 的同一 MAC 也判成 CCO ⇒ D14c 失败)
    {
        TopoState st;
        const quint64 MAC_X = 0x0A0B0C0D0E0FULL;
        // NID 0x0E:发现列表学到 (0x0E, MAC_X) → TEI 1(不带重启次数,不触发重启采样)
        TopoEvent learn;
        learn.kind = TopoEventKind::DiscoverList;
        learn.nid = 0x0E;
        learn.restart_count = -1;
        learn.frame_index = 1;
        learn.epoch_ms = 1001;
        learn.nodes.append({kTeiCco, MAC_X});
        st.apply(learn);
        CHECK(st.mac_to_tei.value(TopoState::nid_mac_key(0x0E, MAC_X), quint16(0)) == kTeiCco,
              "D14a NID 0x0E 学到 (NID, MAC_X) → TEI=1");
        // NID 0x14:同一 MAC 以 TEI=5 入网,重启 5→6 应报 StaRestart
        TopoEvent f1 = frame(TopoEventKind::AssocCnf, 0x14, MAC_X, 5, 2);
        f1.nodes.append({5, MAC_X});
        st.apply(f1);
        CHECK(st.mac_to_tei.value(TopoState::nid_mac_key(0x14, MAC_X), quint16(0)) == 5,
              "D14b NID 0x14 学到 (NID, MAC_X) → TEI=5,两网映射并存");
        TopoEvent f2 = frame(TopoEventKind::AssocCnf, 0x14, MAC_X, 6, 3);
        f2.nodes.append({5, MAC_X});
        st.apply(f2);
        CHECK(count_kind(st, TopoEventKind::StaRestart) == 1
              && count_kind(st, TopoEventKind::CcoRestart) == 0,
              "D14c NID 0x14 计数 5→6 报 StaRestart、不报 CcoRestart");
    }
    // D15:组合键取完整 quint32 NID —— 同一 MAC 在 NID 0x123456(CCO)与 0x003456(STA)互不串
    //     (旧打包只取 NID 低 16bit,两网键相同 ⇒ 0x003456 的 STA 会被误判 CCO)
    {
        TopoState st;
        const quint64 MAC_Y = 0x112233445566ULL;
        // NID 0x123456:发现列表学到 (0x123456, MAC_Y) → TEI 1
        TopoEvent learn;
        learn.kind = TopoEventKind::DiscoverList;
        learn.nid = 0x123456;
        learn.restart_count = -1;
        learn.frame_index = 1;
        learn.epoch_ms = 1001;
        learn.nodes.append({kTeiCco, MAC_Y});
        st.apply(learn);
        CHECK(st.mac_to_tei.value(TopoState::nid_mac_key(0x123456, MAC_Y), quint16(0)) == kTeiCco,
              "D15a NID 0x123456 学到 (NID, MAC_Y) → TEI=1");
        // NID 0x003456:同一 MAC 以 TEI=5 入网,重启 5→6 应报 StaRestart(不报 CcoRestart)
        TopoEvent f1 = frame(TopoEventKind::AssocCnf, 0x003456, MAC_Y, 5, 2);
        f1.nodes.append({5, MAC_Y});
        st.apply(f1);
        CHECK(st.mac_to_tei.value(TopoState::nid_mac_key(0x003456, MAC_Y), quint16(0)) == 5,
              "D15b NID 0x003456 学到 (NID, MAC_Y) → TEI=5,仅高 8bit 不同的两网映射并存");
        TopoEvent f2 = frame(TopoEventKind::AssocCnf, 0x003456, MAC_Y, 6, 3);
        f2.nodes.append({5, MAC_Y});
        st.apply(f2);
        CHECK(count_kind(st, TopoEventKind::StaRestart) == 1
              && count_kind(st, TopoEventKind::CcoRestart) == 0,
              "D15c NID 0x003456 计数 5→6 报 StaRestart、不报 CcoRestart");
        CHECK(st.mac_to_tei.value(TopoState::nid_mac_key(0x123456, MAC_Y), quint16(0)) == kTeiCco,
              "D15d NID 0x123456 的映射仍为 TEI=1");
        // 反向:0x123456 的 CCO 基线独立,计数 7→8 报 CcoRestart
        TopoEvent f3 = frame(TopoEventKind::AssocCnf, 0x123456, MAC_Y, 7, 4);
        f3.nodes.append({kTeiCco, MAC_Y});
        st.apply(f3);
        TopoEvent f4 = frame(TopoEventKind::AssocCnf, 0x123456, MAC_Y, 8, 5);
        f4.nodes.append({kTeiCco, MAC_Y});
        st.apply(f4);
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 1
              && count_kind(st, TopoEventKind::StaRestart) == 1,
              "D15e NID 0x123456 计数 7→8 报 CcoRestart,两网基线互不串");
    }
    // D16:网络标识符不完整(NID==0)的事件不进拓扑 —— 不学节点、不建基线、不报重启
    {
        TopoState st;
        const quint64 MAC_Z = 0x223344556677ULL;
        TopoEvent bad;
        bad.kind = TopoEventKind::DiscoverList;
        bad.nid = 0;
        bad.restart_count = 3;
        bad.frame_index = 1;
        bad.epoch_ms = 1001;
        bad.nodes.append({kTeiCco, MAC_Z});
        st.apply(bad);
        CHECK(st.mac_to_tei.isEmpty() && st.nodes.isEmpty() && st.events.isEmpty(),
              "D16a NID==0 的发现列表不学节点、不记事件");
        TopoEvent bad2 = frame(TopoEventKind::AssocCnf, 0, MAC_Z, 4, 2);
        bad2.nodes.append({5, MAC_Z});
        st.apply(bad2);
        CHECK(count_kind(st, TopoEventKind::StaRestart) == 0
              && count_kind(st, TopoEventKind::CcoRestart) == 0
              && st.mac_to_tei.isEmpty(),
              "D16b NID==0 的关联确认不建基线、不报重启");
        st.note_restart_origin(0, 5, MAC_Z, 5, 2002, 3, false, true);
        CHECK(!st.note_restart_origin(0, 5, MAC_Z, 6, 2003, 4, false, true),
              "D16c note_restart_origin 拒绝 NID==0,两次采样均不建基线");
    }
    // D17:离网清理 CCO 身份记忆 —— 同一 NID/MAC 复用为 STA 后不得误报 CcoRestart;
    //      其他 NID 的同 MAC 记忆必须保留。
    {
        TopoState st;
        const quint64 MAC_REUSE = 0x334455667788ULL;
        // 逐帧路径先以 TEI=1 识别为 CCO,建立身份记忆和 CCO 基线。
        CHECK(!st.note_restart_origin(0x0E, kTeiCco, MAC_REUSE, 2, 3001, 1, false, true),
              "D17a 非 CCO 节点 MAC 被逐帧路径识别为 CCO时首帧建基线");
        // 同 MAC 在另一 NID 下也建立 CCO 记忆,验证离网只删目标 NID。
        CHECK(!st.note_restart_origin(0x14, kTeiCco, MAC_REUSE, 7, 3002, 2, false, true),
              "D17b 另一 NID 同 MAC 建立独立 CCO 基线");
        TopoEvent leave = frame(TopoEventKind::LeaveInd, 0x0E, 0, -1, 3);
        leave.leaves.append(MAC_REUSE);
        st.apply(leave);
        // 同一 NID、同一 MAC 作为 STA 首帧只建 STA 基线,下一次变化必须是 StaRestart。
        CHECK(st.note_restart_origin(0x0E, 5, MAC_REUSE, 4, 3003, 4, false, true),
              "D17c 离网后 CCO/STA 同 MAC 记冲突,不误报重启");
        CHECK(st.note_restart_origin(0x0E, 5, MAC_REUSE, 5, 3004, 5, false, true),
              "D17d 离网后同 NID 同 MAC 计数变化触发 StaRestart");
        CHECK(count_kind(st, TopoEventKind::StaRestart) == 1
              && count_kind(st, TopoEventKind::CcoRestart) == 0,
              "D17e MAC 复用后只报 StaRestart、不误报 CcoRestart");
        CHECK(st.note_restart_origin(0x14, kTeiCco, MAC_REUSE, 8, 3005, 6, false, true),
              "D17f 其他 NID 的 CCO 记忆未被离网清理,仍报 CcoRestart");
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 1,
              "D17g 其他 NID CCO 身份记忆保持独立");
    }

    // D18:真实 CCO 节点/TEI=1 索引 -> 离网 -> STA 普通帧先于关联确认。
    // 每次 CCO/STA 身份冲突都累计记录,最新有效信息覆盖旧索引/记忆,角色间不串基线。
    {
        TopoState st;
        const quint32 net = 0x0E;
        const quint64 mac = 0x334455667788ULL;
        const NidMacKey key = TopoState::nid_mac_key(net, mac);
        TopoEvent learn = frame(TopoEventKind::DiscoverList, net, mac, 2, 1, mac);
        st.apply(learn);
        CHECK(st.mac_of(kTeiCco) == mac && st.mac_to_tei.value(key) == kTeiCco,
              "D18a 创建真实 CCO 节点和索引");
        TopoEvent leave = frame(TopoEventKind::LeaveInd, net, 0, -1, 2);
        leave.leaves.append(mac);
        st.apply(leave);
        st.note_restart_origin(net, 5, mac, 4, 1003, 3, false, true);
        CHECK(st.mac_to_tei.value(key) == 5 && st.mac_of(kTeiCco) == 0 && st.cco_mac == 0,
              "D18b 普通 STA 帧覆盖旧 TEI=1 映射和 CCO 字段");
        CHECK(st.anomalies.size() == 1 && st.anomalies[0].kind == TopoAnomalyKind::MacMultipleTei
                  && st.anomalies[0].trips == 1 && st.anomalies[0].tei_old == 1
                  && st.anomalies[0].tei == 5,
              "D18c 离线 CCO 与 STA 同 MAC 仍记录一次冲突");
        TopoEvent reassoc = frame(TopoEventKind::AssocCnf, net, mac, 4, 4);
        reassoc.nodes.append({5, mac});
        st.apply(reassoc);
        st.note_restart_origin(net, 5, mac, 5, 1005, 5, false, true);
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 0
                  && count_kind(st, TopoEventKind::StaRestart) == 1,
              "D18d 关联后计数变化只报 STA,旧 CCO 身份不回灌");
        CHECK(st.anomalies[0].trips == 1, "D18e 相同最新身份的后续帧不重复冲突");
        st.note_restart_origin(net, 1, mac, 9, 1006, 6, false, true);
        CHECK(st.mac_to_tei.value(key) == 1 && st.cco_mac == mac
                  && st.anomalies[0].trips == 2 && st.anomalies[0].tei_old == 5
                  && st.anomalies[0].tei == 1,
              "D18f 再次冲突继续记录并覆盖回 CCO");
        st.note_restart_origin(net, 1, mac, 10, 1007, 7, false, true);
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 1,
              "D18g CCO 新角色基线独立,后续变化正常报告");
        st.note_restart_origin(net, 5, mac, 12, 1008, 8, false, true);
        CHECK(st.mac_to_tei.value(key) == 5 && st.anomalies[0].trips == 3
                  && st.anomalies[0].last_frame == 8 && st.anomalies[0].tei_old == 1
                  && st.anomalies[0].tei == 5,
              "D18h 第三次冲突继续累计并更新最近方向/帧号");
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 1
                  && count_kind(st, TopoEventKind::StaRestart) == 1,
              "D18i 角色切换本身不生成虚假重启");
        st.note_restart_origin(net, 0, mac, 12, 1008, 8, false, true);
        CHECK(st.mac_to_tei.value(key) == 5 && st.anomalies[0].trips == 3,
              "D18j 无源 TEI 回退最新 STA 身份,不恢复旧 CCO");
    }
    // D19:事件侧必须先学习当前映射再判重启;反复冲突沿用异常表 trips 累加。
    {
        TopoState st;
        const quint64 mac = 0x334455667788ULL;
        st.apply(frame(TopoEventKind::DiscoverList, 0x0E, mac, 2, 1, mac));
        TopoEvent sta = frame(TopoEventKind::AssocCnf, 0x0E, mac, 8, 2);
        sta.nodes.append({5, mac});
        st.apply(sta);
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 0
                  && count_kind(st, TopoEventKind::StaRestart) == 0
                  && st.anomalies.size() == 1 && st.anomalies[0].trips == 1,
              "D19a 事件新 STA 身份先覆盖旧 CCO,不拿旧基线误报");
        sta.restart_count = 9; sta.frame_index = 3; sta.epoch_ms = 1003;
        st.apply(sta);
        CHECK(count_kind(st, TopoEventKind::StaRestart) == 1 && st.anomalies[0].trips == 1,
              "D19b 同角色事件继续正常检测重启");
        st.apply(frame(TopoEventKind::DiscoverList, 0x0E, mac, 3, 4, mac));
        CHECK(st.anomalies[0].trips == 2 && st.mac_of(5) == 0 && st.mac_of(1) == mac,
              "D19c 事件 CCO 再次出现仍记冲突并覆盖节点");
        sta.restart_count = 10; sta.frame_index = 5; sta.epoch_ms = 1005;
        st.apply(sta);
        CHECK(st.anomalies[0].trips == 3 && st.mac_of(1) == 0 && st.mac_of(5) == mac,
              "D19d 事件再次切回 STA 继续累计冲突");
    }
    // D20:无 RestartCount 的源角色也生效;广播/未知 TEI 不得覆盖有效身份。
    {
        TopoState st;
        st.note_restart_origin(0x0E, 1, MAC_A, 2, 1001, 1, false, true);
        CHECK(st.note_restart_origin(0x0E, 5, MAC_A, kRestartCountInvalid, 1002, 2, false, true),
              "D20a 无重启计数仍记录 CCO/STA 冲突供 UI 刷新");
        st.note_restart_origin(0x0E, kTeiBroadcast, MAC_A, kRestartCountInvalid, 1003, 3, false, true);
        st.note_restart_origin(0x0E, kTeiInvalid, MAC_A, kRestartCountInvalid, 1004, 4, false, true);
        CHECK(st.mac_to_tei.value(TopoState::nid_mac_key(0x0E, MAC_A)) == 5
                  && st.anomalies.size() == 1 && st.anomalies[0].trips == 1,
              "D20b 广播/无效 TEI 不改变当前身份或新增冲突");
        st.note_restart_origin(0x0E, 5, MAC_A, 9, 1005, 5, false, true);
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 0
                  && count_kind(st, TopoEventKind::StaRestart) == 0,
              "D20c 无计数的角色切换清理旧基线,新身份首个计数只建基线");
    }

    // D21:离网后的未知身份不能借残留 TEI=1 索引恢复 CCO;有效 CCO 重现仍可检测重启。
    {
        TopoState st;
        const quint32 net = 0x0E;
        st.apply(frame(TopoEventKind::DiscoverList, net, MAC_CCO, 2, 1, MAC_CCO));
        TopoEvent leave = frame(TopoEventKind::LeaveInd, net, 0, -1, 2);
        leave.leaves.append(MAC_CCO);
        st.apply(leave);
        st.note_restart_origin(net, 0, MAC_CCO, 3, 1003, 3, false, true);
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 0,
              "D21a 未知源 TEI 不使用离线 CCO 索引恢复身份");
        st.note_restart_origin(net, 1, MAC_CCO, 4, 1004, 4, false, true);
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 1 && st.anomalies.isEmpty()
                  && st.nodes.value(1).status == NodeStatus::Online,
              "D21b 同一 CCO 有效源 TEI 重现恢复在线并检测重启,不当作角色冲突");
    }

    // D22:关联请求不把已分配 TEI 的离线节点直接判在线;已入网请求及其他正向帧可恢复。
    {
        TopoState st;
        const quint32 net = 0x0E;
        TopoEvent joined = frame(TopoEventKind::AssocCnf, net, MAC_A, kRestartCountInvalid, 1);
        joined.nodes.append({5, MAC_A});
        st.apply(joined);
        TopoEvent leave = frame(TopoEventKind::LeaveInd, net, 0, kRestartCountInvalid, 2);
        leave.leaves.append(MAC_A);
        st.apply(leave);
        CHECK(st.nodes.value(5).status == NodeStatus::Offline,
              "D22a LeaveInd 后 STA 保持离线");
        st.note_restart_origin(net, 5, MAC_A, kRestartCountInvalid, 1002, 2, false, true,
                               TopoEventKind::LeaveInd);
        CHECK(st.nodes.value(5).status == NodeStatus::Offline
                  && st.nodes.value(5).last_seen_ms == leave.epoch_ms,
              "D22b 离网指示对应帧不能复活节点");

        // ChangeProxyReq 在 apply 中也只是记录请求;逐帧采样不能把离线 STA 复活。
        TopoEvent proxy_req = frame(TopoEventKind::ChangeProxyReq, net, MAC_A,
                                    kRestartCountInvalid, 3);
        proxy_req.nodes.append({5, 0});
        st.apply(proxy_req);
        st.note_restart_origin(net, 5, MAC_A, kRestartCountInvalid, 1003, 3, false, true,
                               TopoEventKind::ChangeProxyReq);
        CHECK(st.nodes.value(5).status == NodeStatus::Online
                  && st.nodes.value(5).last_seen_ms == 1003,
              "D22c 已入网 STA 的代理变更请求可恢复在线");

        TopoEvent second_leave = frame(TopoEventKind::LeaveInd, net, 0,
                                       kRestartCountInvalid, 4);
        second_leave.leaves.append(MAC_A);
        st.apply(second_leave);
        st.note_restart_origin(net, 5, MAC_A, kRestartCountInvalid, 1005, 5, false, true,
                               TopoEventKind::Other);
        CHECK(st.nodes.value(5).status == NodeStatus::Online
                  && st.nodes.value(5).last_seen_ms == 1005,
              "D22d 普通数据帧仍可恢复既有节点在线");

        // 关联请求只表示重新入网中,不能把节点标成在线。
        TopoEvent third_leave = frame(TopoEventKind::LeaveInd, net, 0,
                                      kRestartCountInvalid, 6);
        third_leave.leaves.append(MAC_A);
        st.apply(third_leave);
        TopoEvent assoc_req = frame(TopoEventKind::AssocReq, net, MAC_A,
                                    kRestartCountInvalid, 7);
        assoc_req.nodes.append({0, MAC_A});
        st.apply(assoc_req);
        st.note_restart_origin(net, 0, MAC_A, kRestartCountInvalid, 1008, 8, false, true,
                               TopoEventKind::AssocReq);
        CHECK(st.pending.contains(MAC_A) && !st.nodes.contains(5)
                  && st.pending.value(MAC_A).status == NodeStatus::OnlineGoing,
              "D22e 关联请求仅建立入网中状态,不复活离线 TEI 节点");
    }

    // D23:离线→入网中→在线/离网,以及只更新状态的权威来源。
    {
        TopoState st;
        const quint32 net = 0x0F;
        TopoEvent joined = frame(TopoEventKind::AssocCnf, net, MAC_A, kRestartCountInvalid, 1);
        joined.nodes.append({5, MAC_A});
        st.apply(joined);
        TopoEvent leave = frame(TopoEventKind::LeaveInd, net, 0, kRestartCountInvalid, 2);
        leave.leaves.append(MAC_A);
        st.apply(leave);

        TopoEvent assoc_req = frame(TopoEventKind::AssocReq, net, MAC_A,
                                    kRestartCountInvalid, 3);
        assoc_req.nodes.append({0, MAC_A});
        st.apply(assoc_req);
        CHECK(!st.nodes.contains(5) && st.pending.contains(MAC_A)
                  && st.pending.value(MAC_A).status == NodeStatus::OnlineGoing,
              "D23a 离线 STA 的关联请求转为入网中");

        TopoEvent leave_pending = frame(TopoEventKind::LeaveInd, net, 0,
                                        kRestartCountInvalid, 4);
        leave_pending.leaves.append(MAC_A);
        st.apply(leave_pending);
        CHECK(!st.pending.contains(MAC_A),
              "D23b 离网指示清除未完成的 pending 入网状态");

        assoc_req.epoch_ms = 5;
        assoc_req.frame_index = 5;
        st.apply(assoc_req);
        TopoEvent assoc_cnf = frame(TopoEventKind::AssocCnf, net, MAC_A,
                                    kRestartCountInvalid, 6);
        assoc_cnf.nodes.append({5, MAC_A});
        st.apply(assoc_cnf);
        CHECK(!st.pending.contains(MAC_A) && st.nodes.value(5).status == NodeStatus::Online,
              "D23c 关联确认将 pending 节点提升为在线");
    }
    {
        TopoState st;
        const quint32 net = 0x10;
        TopoEvent joined = frame(TopoEventKind::AssocCnf, net, MAC_A, kRestartCountInvalid, 1);
        joined.nodes.append({5, MAC_A});
        st.apply(joined);
        TopoEvent leave = frame(TopoEventKind::LeaveInd, net, 0, kRestartCountInvalid, 2);
        leave.leaves.append(MAC_A);
        st.apply(leave);
        TopoEvent synthetic = frame(TopoEventKind::StaRestart, net, MAC_A,
                                    kRestartCountInvalid, 3);
        synthetic.nodes.append({5, MAC_A});
        synthetic.routes.append({5, 2});
        st.apply(synthetic);
        CHECK(st.nodes.value(5).status == NodeStatus::Offline,
              "D23d 非在线证据事件不把离线节点改为在线");

        TopoEvent proxy = frame(TopoEventKind::ChangeProxyCnf, net, 0,
                                kRestartCountInvalid, 4);
        proxy.link_type = 0;
        proxy.child_teis.append(7);
        st.apply(proxy);
        CHECK(st.nodes.value(7).status == NodeStatus::Online
                  && st.nodes.value(7).last_seen_ms == proxy.epoch_ms,
              "D23e 成功代理确认中的子 TEI 位图建立在线节点");

        TopoEvent sta = frame(TopoEventKind::AssocCnf, net, MAC_B,
                              kRestartCountInvalid, 5);
        sta.nodes.append({8, MAC_B});
        st.apply(sta);
        TopoEvent sta_leave = frame(TopoEventKind::LeaveInd, net, 0,
                                    kRestartCountInvalid, 6);
        sta_leave.leaves.append(MAC_B);
        st.apply(sta_leave);
        TopoEvent channel = frame(TopoEventKind::Other, net, MAC_B,
                                  kRestartCountInvalid, 7);
        channel.proxy_tei = 1;
        channel.proxy_up_rate = 90;
        st.apply_channel_info(8, channel);
        CHECK(st.nodes.value(8).status == NodeStatus::Online
                  && st.nodes.value(8).last_seen_ms == channel.epoch_ms,
              "D23f 离线节点发出有效信道报告后恢复在线");
    }

    std::printf(failures ? "RESULT: %d FAILURES\n" : "RESULT: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
