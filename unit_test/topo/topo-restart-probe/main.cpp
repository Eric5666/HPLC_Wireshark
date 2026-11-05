/// 探针:TopoState 重启检测 —— 方案 B(全帧采样 + (NID, 主体 MAC) 分键)
/// 覆盖:
///   A/B/C 既有口径(sender_mac==0 回落主体 MAC、中继按发送方建基线、无键静默跳过)
///   D     方案 B 新增:CCO/STA 非白名单帧、NID 隔离、MAC 隔离、TEI=1 归 CCO、
///         逐帧采样路径(note_restart_origin)、同帧不重复报、无变化不报
///   D13   身份记忆按 (NID, MAC) 分键:同 MAC 在不同 NID 下 CCO/STA 身份互不串
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
        CHECK(st.mac_to_tei.value(MAC_CCO, quint16(0)) == kTeiCco, "D5a 已学到 TEI=1 → CCO MAC");
        CHECK(st.cco_mac == 0, "D5b 该帧未给 cco_mac");
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

    std::printf(failures ? "RESULT: %d FAILURES\n" : "RESULT: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
