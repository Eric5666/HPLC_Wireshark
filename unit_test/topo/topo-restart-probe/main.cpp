/// 探针:TopoState 重启检测 —— 方案 B(全帧采样 + (NID, 主体 MAC) 分键)
/// 覆盖:
///   A/B/C 既有口径(sender_mac==0 回落主体 MAC、中继按发送方建基线、无键静默跳过)
///   D     方案 B 新增:CCO/STA 非白名单帧、NID 隔离、MAC 隔离、TEI=1 归 CCO、
///         逐帧采样路径(note_restart_origin)、同帧不重复报、无变化不报
///   D13   身份记忆按 (NID, MAC) 分键:同 MAC 在不同 NID 下 CCO/STA 身份互不串
///   D14   mac_to_tei 按 (NID, MAC) 分键:同 MAC 在不同 NID 下映射到不同 TEI,互不串
///   D17   CCO 基线按 MAC 隔离;同一 NID 多 CCO MAC 标为 NID 冲突,无 MAC 样本不猜身份
///   D18   逐帧重启进历史回放:replay_topo_logs 合并事件日志与采样日志重放
///   D24   离网清理 CCO 身份记忆:同一 NID/MAC 复用为 STA 后不得误报 CcoRestart
///   D25   真实 CCO 节点/TEI=1 索引 -> 离网 -> STA 普通帧先于关联确认
///   D26   事件侧先学习当前映射再判重启;反复冲突沿用异常表 trips 累加
///   D27   无 RestartCount 的源角色也生效;广播/未知 TEI 不得覆盖有效身份
///   D28   离网后的未知身份不能借残留 TEI=1 索引恢复 CCO;有效 CCO 重现仍可检测重启
///   D29   离线复活:关联请求不复活,白名单帧复活且留复活原因记录
///   D30   离线→入网中→在线/离网,以及只更新状态的权威来源
///   D31   无重启计数复活的实时与回放一致:只给真正复活的帧补记 rc=0xFF 采样
///   D32   单跳帧信道观测复活的实时与回放一致:第三条信道日志重调 apply_channel_info,
///         复活留 kind=ChannelInfo 的记录;同帧事件先、信道后
///   D33   停上电事件上报:断电算离线(LeaveInd 同款),断电/上电都记录,上电只记录不改状态
///         不复活;位图按 TEI 点名、地址按电表地址点名;不存在的节点跳过;NID 隔离
///   D34   三类日志单调帧序追加、同帧稳定顺序与增量回放
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

/// @brief 离线复活原因记录条数(描述含“节点恢复在线”的事件)
static int count_revival_events(const TopoState& st) {
    int n = 0;
    for (const TopoEvent& ev : st.events)
        if (ev.desc.contains(QStringLiteral("节点恢复在线"))) ++n;
    return n;
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
    // D17(CCO 基线归一到已知 cco_mac,04531b9 遗留):缺源 MAC 的 CCO 帧走 (NID, 0)、带 MAC
    //     的走 (NID, cco_mac) 时,同一次重启两条基线各报一次。现规范键为 (NID, 已知
    //     cco_mac):未知时暂用 (NID, 0) 占位,一旦已知就把基线值迁移过去并删占位键。
    {
        TopoState st;
        // 逐帧侧:帧1 缺 MAC 建基线,帧2 带 MAC 同值只迁移不报,帧3 带 MAC 变化报 1 条且 prev 为迁移值
        CHECK(!st.note_restart_origin(0x0E, kTeiCco, 0, 2, 1001, 1, false, true),
              "D17a 逐帧 CCO 缺 MAC 首帧建基线不报");
        CHECK(!st.note_restart_origin(0x0E, kTeiCco, MAC_CCO, 2, 1002, 2, false, true),
              "D17b 先无 MAC 后有 MAC,同值只迁移不报");
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 0,
              "D17c 迁移后总数仍为 0");
        CHECK(st.note_restart_origin(0x0E, kTeiCco, MAC_CCO, 3, 1003, 3, false, true),
              "D17d 迁移后计数 2→3 报 1 条 CcoRestart");
        bool desc_ok = false;
        for (const TopoEvent& ev : st.events)
            if (ev.kind == TopoEventKind::CcoRestart)
                desc_ok = ev.desc.contains(QStringLiteral("2→3"))
                       && ev.sender_mac == MAC_CCO && ev.frame_index == 3;
        CHECK(desc_ok, "D17e CcoRestart 文案 2→3 且 sender_mac 保留真实 cco_mac");
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 1
              && count_restart_events(st) == 0, "D17f 总数 1 条且为 CcoRestart");
        CHECK(st.note_restart_origin(0x0E, kTeiCco, 0, 4, 1004, 4, false, true),
              "D17g 再回缺 MAC 形态,计数 3→4 仍报");
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 2, "D17h 两次变化共 2 条,不多不少");
        // 反向顺序:先带 MAC 建基线,后缺 MAC 同值不报、变值只报 1 条(旧实现会漏报)
        TopoState st2;
        CHECK(!st2.note_restart_origin(0x0E, kTeiCco, MAC_CCO, 5, 1001, 1, false, true),
              "D17i 逐帧 CCO 带 MAC 首帧建基线不报");
        CHECK(!st2.note_restart_origin(0x0E, kTeiCco, 0, 5, 1002, 2, false, true),
              "D17j 先有 MAC 后无 MAC,同值不报");
        CHECK(st2.note_restart_origin(0x0E, kTeiCco, 0, 6, 1003, 3, false, true),
              "D17k 反向计数 5→6 报 1 条(旧实现漏报)");
        CHECK(count_kind(st2, TopoEventKind::CcoRestart) == 1, "D17l 反向总数 1 条");
        bool desc2_ok = false;
        for (const TopoEvent& ev : st2.events)
            if (ev.kind == TopoEventKind::CcoRestart)
                desc2_ok = ev.desc.contains(QStringLiteral("5→6"))
                        && ev.sender_mac == 0 && ev.frame_index == 3;
        CHECK(desc2_ok, "D17m 反向 CcoRestart 文案 5→6 且无 MAC 帧 sender_mac 为 0");
        // 事件侧同样归一:发现列表缺 MAC 建基线,带 cco_mac 的关联确认同值不报、变值只报 1 条
        TopoState st3;
        TopoEvent dl = frame(TopoEventKind::DiscoverList, 0x0E, 0, 2, 1);
        st3.apply(dl);
        TopoEvent cnf_same = frame(TopoEventKind::AssocCnf, 0x0E, MAC_CCO, 2, 2, MAC_CCO);
        st3.apply(cnf_same);
        CHECK(count_kind(st3, TopoEventKind::CcoRestart) == 0,
              "D17n 事件侧先无 MAC 后有 MAC,同值只迁移不报");
        TopoEvent cnf = frame(TopoEventKind::AssocCnf, 0x0E, MAC_CCO, 3, 3, MAC_CCO);
        st3.apply(cnf);
        bool desc3_ok = false;
        for (const TopoEvent& ev : st3.events)
            if (ev.kind == TopoEventKind::CcoRestart)
                desc3_ok = ev.desc.contains(QStringLiteral("2→3"))
                        && ev.sender_mac == MAC_CCO;
        CHECK(count_kind(st3, TopoEventKind::CcoRestart) == 1
              && count_restart_events(st3) == 0 && desc3_ok,
              "D17o 事件侧迁移后变值只报 1 条,文案 2→3 且 sender_mac 为 cco_mac");
        // 事件侧反向:先带 MAC 建基线,后缺 MAC 同值不报、变值只报 1 条
        TopoState st5;
        TopoEvent cnf_first = frame(TopoEventKind::AssocCnf, 0x0E, MAC_CCO, 5, 1, MAC_CCO);
        st5.apply(cnf_first);
        TopoEvent dl_same = frame(TopoEventKind::DiscoverList, 0x0E, 0, 5, 2);
        st5.apply(dl_same);
        CHECK(count_kind(st5, TopoEventKind::CcoRestart) == 0,
              "D17p 事件侧先有 MAC 后无 MAC,同值不报");
        TopoEvent dl_chg = frame(TopoEventKind::DiscoverList, 0x0E, 0, 6, 3);
        st5.apply(dl_chg);
        bool desc5_ok = false;
        for (const TopoEvent& ev : st5.events)
            if (ev.kind == TopoEventKind::CcoRestart)
                desc5_ok = ev.desc.contains(QStringLiteral("5→6"))
                        && ev.sender_mac == 0;
        CHECK(count_kind(st5, TopoEventKind::CcoRestart) == 1
              && count_restart_events(st5) == 0 && desc5_ok,
              "D17q 事件侧反向变值只报 1 条,文案 5→6 且 sender_mac 为 0");
        // STA 基线不受影响:仍按 (NID, 主体 MAC) 分键,两 STA 各自报
        TopoState st4;
        CHECK(!st4.note_restart_origin(0x0E, 5, MAC_A, 2, 1001, 1, false, true),
              "D17r STA 首帧建基线不报");
        CHECK(st4.note_restart_origin(0x0E, 5, MAC_A, 3, 1002, 2, false, true),
              "D17s STA 计数 2→3 报 StaRestart");
        CHECK(count_kind(st4, TopoEventKind::CcoRestart) == 0
              && count_restart_events(st4) == 1, "D17t STA 变化仍为 1 条 StaRestart");
    }
    // D17u:不同 CCO MAC 即使计数相同也属于不同身份;同一 NID 下同时记为 NID 冲突。
    //       无 MAC 样本只更新独立占位基线,后续带 MAC 样本仍各自按原基线判断。
    {
        TopoState st;
        CHECK(!st.note_restart_origin(0x0E, kTeiCco, MAC_CCO, 3, 1001, 1, false, true),
              "D17u-a 首个 CCO MAC 的计数 3 建基线");
        CHECK(!st.note_restart_origin(0x0E, kTeiCco, MAC_B, 3, 1002, 2, false, true),
              "D17u-b 第二个 CCO MAC 的相同计数仍建独立基线");
        int nid_conflicts = 0;
        bool conflict_pair_ok = false;
        for (const TopoAnomaly& a : st.anomalies) {
            if (a.kind != TopoAnomalyKind::NidConflict) continue;
            ++nid_conflicts;
            conflict_pair_ok = a.mac_old == MAC_CCO && a.mac == MAC_B
                            && a.trips == 1 && a.first_frame == 2;
        }
        CHECK(nid_conflicts == 1 && conflict_pair_ok,
              "D17u-c 同一 NID 下不同 CCO MAC 记录 NID 冲突及 MAC 对");
        CHECK(!st.note_restart_origin(0x0E, kTeiCco, 0, 4, 1003, 3, false, true)
                  && count_kind(st, TopoEventKind::CcoRestart) == 0,
              "D17u-d 多身份时无 MAC 样本只建独立占位基线,不冒认任一设备");
        CHECK(st.note_restart_origin(0x0E, kTeiCco, MAC_CCO, 4, 1004, 4, false, true),
              "D17u-e 后续 MAC_CCO 样本仍按自身 3→4 基线告警");
        CHECK(!st.note_restart_origin(0x0E, kTeiCco, MAC_B, 3, 1005, 5, false, true),
              "D17u-f 另一 MAC 的基线未被无 MAC 样本改写");
        CHECK(st.note_restart_origin(0x0E, kTeiCco, MAC_B, 4, 1006, 6, false, true),
              "D17u-g 第二个 MAC 独立 3→4 时也报告");
        bool independent_events_ok = false;
        int cco_restart_count = 0;
        for (const TopoEvent& ev : st.events) {
            if (ev.kind != TopoEventKind::CcoRestart) continue;
            ++cco_restart_count;
            if (ev.sender_mac == MAC_B && ev.frame_index == 6
                && ev.desc.contains(QStringLiteral("3→4")))
                independent_events_ok = true;
        }
        CHECK(cco_restart_count == 2 && independent_events_ok,
              "D17u-h 两台设备分别告警,事件保留真实 MAC 与帧号");

        TopoState ambiguous;
        ambiguous.note_restart_origin(0x0E, kTeiCco, MAC_CCO, 3, 2001, 1, false, true);
        ambiguous.note_restart_origin(0x0E, kTeiCco, MAC_B, 7, 2002, 2, false, true);
        CHECK(!ambiguous.note_restart_origin(0x0E, kTeiCco, 0, 4, 2003, 3, false, true)
                  && count_kind(ambiguous, TopoEventKind::CcoRestart) == 0,
              "D17u-i 候选值不同的无 MAC 样本不借用任一身份的基线");
        CHECK(ambiguous.note_restart_origin(0x0E, kTeiCco, MAC_CCO, 4, 2004, 4, false, true)
                  && !ambiguous.note_restart_origin(0x0E, kTeiCco, MAC_B, 7, 2005, 5, false, true),
              "D17u-j 候选冲突后各带 MAC 样本仍分别使用 3 与 7 的基线");
        CHECK(count_kind(ambiguous, TopoEventKind::CcoRestart) == 1,
              "D17u-k 只有 MAC_CCO 的 3→4 产生重启事件");

        TopoState separate_nids;
        separate_nids.note_restart_origin(0x0E, kTeiCco, MAC_CCO, 3, 3001, 1, false, true);
        separate_nids.note_restart_origin(0x14, kTeiCco, MAC_B, 3, 3002, 2, false, true);
        CHECK(separate_nids.anomalies.isEmpty(),
              "D17u-l 不同 NID 的 CCO MAC 不构成彼此的 NID 冲突");
        TopoState multiple_nids;
        multiple_nids.note_restart_origin(0x0E, kTeiCco, MAC_CCO, 1, 4001, 1, false, true);
        multiple_nids.note_restart_origin(0x0E, kTeiCco, MAC_B, 1, 4002, 2, false, true);
        multiple_nids.note_restart_origin(0x14, kTeiCco, MAC_A, 1, 4003, 3, false, true);
        multiple_nids.note_restart_origin(0x14, kTeiCco, MAC_B, 1, 4004, 4, false, true);
        nid_conflicts = 0;
        for (const TopoAnomaly& a : multiple_nids.anomalies)
            if (a.kind == TopoAnomalyKind::NidConflict) ++nid_conflicts;
        CHECK(nid_conflicts == 2,
              "D17u-m 同一状态内两个 NID 的冲突异常也分别保留");

        TopoState no_counter;
        no_counter.apply(frame(TopoEventKind::DiscoverList, 0x0E, 0,
                               kRestartCountInvalid, 1, MAC_CCO));
        no_counter.apply(frame(TopoEventKind::DiscoverList, 0x0E, 0,
                               kRestartCountInvalid, 2, MAC_B));
        nid_conflicts = 0;
        for (const TopoAnomaly& a : no_counter.anomalies)
            if (a.kind == TopoAnomalyKind::NidConflict) ++nid_conflicts;
        CHECK(nid_conflicts == 1,
              "D17u-n 即使没有重启计数,TEI=1 的不同 CCO MAC 仍记录 NID 冲突");
    }
    // D18(逐帧重启进历史回放,04531b9 遗留):普通数据帧触发的重启只走逐帧采样,
    //     不进拓扑事件日志;回放必须按帧序合并两条日志重放,否则历史快照里重启全消失。
    {
        // 模拟 MainWindow 实时路径:帧1 关联确认(事件+采样),帧2 普通数据帧(仅采样)。
        // 实时侧:事件侧与逐帧侧共用同一基线,同一次重启只报一次。
        QHash<quint32, TopoState> live;
        QVector<TopoLogItem> topo_log;
        QVector<TopoChannelSample> channel_log;
        QVector<TopoRestartSample> restart_log;
        TopoState& live_st = live[0x0E];
        live_st.nid = 0x0E;
        TopoEvent assoc1 = frame(TopoEventKind::AssocCnf, 0x0E, MAC_A, 2, 1);
        assoc1.nodes.append({5, MAC_A});
        live_st.apply(assoc1);
        topo_log.append({1, assoc1});
        live_st.note_restart_origin(0x0E, 5, MAC_A, 2, 1001, 1, false, true);
        restart_log.append({1, 0x0E, 5, MAC_A, 2, 1001, false, true});
        CHECK(count_restart_events(live_st) == 0, "D18a 帧1 实时只建基线不报");
        CHECK(live_st.note_restart_origin(0x0E, 5, MAC_A, 3, 1002, 2, false, true),
              "D18b 帧2 普通数据帧逐帧采样报 StaRestart");
        restart_log.append({2, 0x0E, 5, MAC_A, 3, 1002, false, true});
        CHECK(count_restart_events(live_st) == 1, "D18c 实时共 1 条 StaRestart");
        // 回放到帧1:冻结快照里还没有重启(变化在帧2)
        QHash<quint32, TopoState> hist;
        qint64 replayed = -1;
        replay_topo_logs(topo_log, channel_log, restart_log, 1, replayed, hist);
        CHECK(hist.contains(0x0E) && count_restart_events(hist[0x0E]) == 0,
              "D18d 回放到帧1,快照里 0 条重启");
        // 增量回放到帧2:快照里出现实时那 1 条,不多不少
        replay_topo_logs(topo_log, channel_log, restart_log, 2, replayed, hist);
        CHECK(count_restart_events(hist[0x0E]) == 1, "D18e 增量回放到帧2,快照里 1 条 StaRestart");
        bool desc_ok = false;
        for (const TopoEvent& ev : hist[0x0E].events)
            if (ev.kind == TopoEventKind::StaRestart)
                desc_ok = ev.desc.contains(QStringLiteral("2→3")) && ev.frame_index == 2;
        CHECK(desc_ok, "D18f 快照里的 StaRestart 文案 2→3 且来源帧为 2");
        // 回拨到帧1 再重放到帧2:全量重建后仍为 1 条,不 double-apply
        replay_topo_logs(topo_log, channel_log, restart_log, 1, replayed, hist);
        CHECK(count_restart_events(hist[0x0E]) == 0, "D18g 回拨到帧1,快照清回 0 条");
        replay_topo_logs(topo_log, channel_log, restart_log, 2, replayed, hist);
        CHECK(count_restart_events(hist[0x0E]) == 1, "D18h 回拨后再重放到帧2,仍为 1 条");
    }
    // D34:单调帧序追加与同帧稳定顺序;新帧在回放水位之后时增量应用。
    {
        qint64 replayed = -1;
        QVector<TopoLogItem> topo_log;
        TopoEvent topo2;  topo2.sender_mac = MAC_B;
        TopoEvent topo6;  topo6.sender_mac = MAC_CCO;
        TopoEvent topo9a; topo9a.sender_mac = MAC_A;
        TopoEvent topo9b; topo9b.sender_mac = MAC_B + 1;
        record_topo_log_entry(topo_log, TopoLogItem{2, topo2}, replayed);
        record_topo_log_entry(topo_log, TopoLogItem{6, topo6}, replayed);
        record_topo_log_entry(topo_log, TopoLogItem{9, topo9a}, replayed);
        record_topo_log_entry(topo_log, TopoLogItem{9, topo9b}, replayed);
        CHECK(topo_log.size() == 4 && topo_log[0].frame_index == 2
                  && topo_log[1].frame_index == 6 && topo_log[2].frame_index == 9
                  && topo_log[3].frame_index == 9
                  && topo_log[2].event.sender_mac == MAC_A
                  && topo_log[3].event.sender_mac == MAC_B + 1,
              "D34a 拓扑日志单调追加且同帧保留调用顺序");

        QVector<TopoChannelSample> channel_log;
        record_topo_log_entry(channel_log, TopoChannelSample{2, 0x0E, 5, 1002, TopoEvent{}}, replayed);
        record_topo_log_entry(channel_log, TopoChannelSample{6, 0x0E, 5, 1006, TopoEvent{}}, replayed);
        record_topo_log_entry(channel_log, TopoChannelSample{9, 0x0E, 5, 1009, TopoEvent{}}, replayed);
        CHECK(channel_log.size() == 3 && channel_log[0].frame_index == 2
                  && channel_log[1].frame_index == 6 && channel_log[2].frame_index == 9,
              "D34b 信道日志单调追加");

        QVector<TopoRestartSample> restart_log;
        record_topo_log_entry(restart_log, TopoRestartSample{2, 0x0E, 5, MAC_A, 2, 1002, false, true}, replayed);
        record_topo_log_entry(restart_log, TopoRestartSample{6, 0x0E, 5, MAC_A, 3, 1006, false, true}, replayed);
        record_topo_log_entry(restart_log, TopoRestartSample{9, 0x0E, 5, MAC_A, 4, 1009, false, true}, replayed);
        CHECK(restart_log.size() == 3 && restart_log[0].frame_index == 2
                  && restart_log[1].frame_index == 6 && restart_log[2].frame_index == 9,
              "D34c 重启日志单调追加");
    }
    {
        // 防御性覆盖：正常输入按序追加;若将来某路径意外传入旧帧,Release 也要保序并回拨水位。
        qint64 replayed = 3;
        QVector<TopoLogItem> log;
        TopoEvent frame1; frame1.sender_mac = MAC_A;
        TopoEvent frame3; frame3.sender_mac = MAC_CCO;
        TopoEvent frame2a; frame2a.sender_mac = MAC_B;
        TopoEvent frame2b; frame2b.sender_mac = MAC_B + 1;
        record_topo_log_entry(log, TopoLogItem{1, frame1}, replayed);
        record_topo_log_entry(log, TopoLogItem{3, frame3}, replayed);
        record_topo_log_entry(log, TopoLogItem{2, frame2a}, replayed);
        record_topo_log_entry(log, TopoLogItem{2, frame2b}, replayed);
        CHECK(log.size() == 4 && log[0].frame_index == 1
                  && log[1].frame_index == 2 && log[2].frame_index == 2
                  && log[3].frame_index == 3
                  && log[1].event.sender_mac == MAC_B
                  && log[2].event.sender_mac == MAC_B + 1 && replayed == -1,
              "D34i 逆序记录在 Release 仍稳定排序并使回放水位失效");
    }
    {
        const quint32 net = 0x0E;
        QVector<TopoLogItem> topo_log;
        TopoEvent joined = frame(TopoEventKind::AssocCnf, net, MAC_A,
                                 kRestartCountInvalid, 1);
        joined.nodes.append({5, MAC_A});
        qint64 replayed = -1;
        record_topo_log_entry(topo_log, TopoLogItem{1, joined}, replayed);
        QHash<quint32, TopoState> hist;
        replay_topo_logs(topo_log, {}, {}, 1, replayed, hist);
        CHECK(replayed == 1 && hist[net].nodes.value(5).status == NodeStatus::Online,
              "D34d 首帧回放建立在线节点");
        TopoEvent leave = frame(TopoEventKind::LeaveInd, net, 0,
                                kRestartCountInvalid, 2);
        leave.leaves.append(MAC_A);
        record_topo_log_entry(topo_log, TopoLogItem{2, leave}, replayed);
        CHECK(replayed == 1, "D34e 追加新帧不使较早水位失效");
        replay_topo_logs(topo_log, {}, {}, 2, replayed, hist);
        CHECK(replayed == 2 && hist[net].nodes.value(5).status == NodeStatus::Offline,
              "D34f 按序增量回放应用离网事件");
    }
    {
        const quint32 net = 0x0E;
        QVector<TopoLogItem> topo_log;
        TopoEvent joined = frame(TopoEventKind::AssocCnf, net, MAC_A,
                                 kRestartCountInvalid, 1);
        joined.nodes.append({5, MAC_A});
        qint64 replayed = -1;
        record_topo_log_entry(topo_log, TopoLogItem{1, joined}, replayed);
        QHash<quint32, TopoState> hist;
        replay_topo_logs(topo_log, {}, {}, 1, replayed, hist);
        TopoEvent channel; channel.proxy_up_rate = 77;
        QVector<TopoChannelSample> channel_log;
        record_topo_log_entry(channel_log, TopoChannelSample{2, net, 5, 1002, channel}, replayed);
        replay_topo_logs(topo_log, channel_log, {}, 2, replayed, hist);
        CHECK(replayed == 2 && hist[net].nodes.value(5).proxy_up_rate == 77,
              "D34g 按序增量回放应用信道观测");
    }
    {
        const quint32 net = 0x0E;
        QVector<TopoLogItem> topo_log;
        TopoEvent joined = frame(TopoEventKind::AssocCnf, net, MAC_A,
                                 kRestartCountInvalid, 1);
        joined.nodes.append({5, MAC_A});
        qint64 replayed = -1;
        record_topo_log_entry(topo_log, TopoLogItem{1, joined}, replayed);
        QVector<TopoRestartSample> restart_log;
        record_topo_log_entry(restart_log,
                              TopoRestartSample{1, net, 5, MAC_A, 2, 1001, false, true}, replayed);
        QHash<quint32, TopoState> hist;
        replay_topo_logs(topo_log, {}, restart_log, 1, replayed, hist);
        record_topo_log_entry(restart_log,
                              TopoRestartSample{2, net, 5, MAC_A, 3, 1002, false, true}, replayed);
        replay_topo_logs(topo_log, {}, restart_log, 2, replayed, hist);
        CHECK(replayed == 2 && count_restart_events(hist[net]) == 1
                  && hist[net].events.last().frame_index == 2,
              "D34h 按序增量回放从重启采样派生事件");
    }
    // D24:离网清理 CCO 身份记忆 —— 同一 NID/MAC 复用为 STA 后不得误报 CcoRestart;
    //      其他 NID 的同 MAC 记忆必须保留。
    {
        TopoState st;
        const quint64 MAC_REUSE = 0x334455667788ULL;
        // 逐帧路径先以 TEI=1 识别为 CCO,建立身份记忆和 CCO 基线。
        CHECK(!st.note_restart_origin(0x0E, kTeiCco, MAC_REUSE, 2, 3001, 1, false, true),
              "D24a 非 CCO 节点 MAC 被逐帧路径识别为 CCO时首帧建基线");
        // 同 MAC 在另一 NID 下也建立 CCO 记忆,验证离网只删目标 NID。
        CHECK(!st.note_restart_origin(0x14, kTeiCco, MAC_REUSE, 7, 3002, 2, false, true),
              "D24b 另一 NID 同 MAC 建立独立 CCO 基线");
        TopoEvent leave = frame(TopoEventKind::LeaveInd, 0x0E, 0, -1, 3);
        leave.leaves.append(MAC_REUSE);
        st.apply(leave);
        // 同一 NID、同一 MAC 作为 STA 首帧只建 STA 基线,下一次变化必须是 StaRestart。
        CHECK(st.note_restart_origin(0x0E, 5, MAC_REUSE, 4, 3003, 4, false, true),
              "D24c 离网后 CCO/STA 同 MAC 记冲突,不误报重启");
        CHECK(st.note_restart_origin(0x0E, 5, MAC_REUSE, 5, 3004, 5, false, true),
              "D24d 离网后同 NID 同 MAC 计数变化触发 StaRestart");
        CHECK(count_kind(st, TopoEventKind::StaRestart) == 1
              && count_kind(st, TopoEventKind::CcoRestart) == 0,
              "D24e MAC 复用后只报 StaRestart、不误报 CcoRestart");
        CHECK(st.note_restart_origin(0x14, kTeiCco, MAC_REUSE, 8, 3005, 6, false, true),
              "D24f 其他 NID 的 CCO 记忆未被离网清理,仍报 CcoRestart");
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 1,
              "D24g 其他 NID CCO 身份记忆保持独立");
    }

    // D25:真实 CCO 节点/TEI=1 索引 -> 离网 -> STA 普通帧先于关联确认。
    // 每次 CCO/STA 身份冲突都累计记录,最新有效信息覆盖旧索引/记忆,角色间不串基线。
    {
        TopoState st;
        const quint32 net = 0x0E;
        const quint64 mac = 0x334455667788ULL;
        const NidMacKey key = TopoState::nid_mac_key(net, mac);
        TopoEvent learn = frame(TopoEventKind::DiscoverList, net, mac, 2, 1, mac);
        st.apply(learn);
        CHECK(st.mac_of(kTeiCco) == mac && st.mac_to_tei.value(key) == kTeiCco,
              "D25a 创建真实 CCO 节点和索引");
        TopoEvent leave = frame(TopoEventKind::LeaveInd, net, 0, -1, 2);
        leave.leaves.append(mac);
        st.apply(leave);
        st.note_restart_origin(net, 5, mac, 4, 1003, 3, false, true);
        CHECK(st.mac_to_tei.value(key) == 5 && st.mac_of(kTeiCco) == 0 && st.cco_mac == 0,
              "D25b 普通 STA 帧覆盖旧 TEI=1 映射和 CCO 字段");
        CHECK(st.anomalies.size() == 1 && st.anomalies[0].kind == TopoAnomalyKind::MacMultipleTei
                  && st.anomalies[0].trips == 1 && st.anomalies[0].tei_old == 1
                  && st.anomalies[0].tei == 5,
              "D25c 离线 CCO 与 STA 同 MAC 仍记录一次冲突");
        TopoEvent reassoc = frame(TopoEventKind::AssocCnf, net, mac, 4, 4);
        reassoc.nodes.append({5, mac});
        st.apply(reassoc);
        st.note_restart_origin(net, 5, mac, 5, 1005, 5, false, true);
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 0
                  && count_kind(st, TopoEventKind::StaRestart) == 1,
              "D25d 关联后计数变化只报 STA,旧 CCO 身份不回灌");
        CHECK(st.anomalies[0].trips == 1, "D25e 相同最新身份的后续帧不重复冲突");
        st.note_restart_origin(net, 1, mac, 9, 1006, 6, false, true);
        CHECK(st.mac_to_tei.value(key) == 1 && st.cco_mac == mac
                  && st.anomalies[0].trips == 2 && st.anomalies[0].tei_old == 5
                  && st.anomalies[0].tei == 1,
              "D25f 再次冲突继续记录并覆盖回 CCO");
        st.note_restart_origin(net, 1, mac, 10, 1007, 7, false, true);
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 1,
              "D25g CCO 新角色基线独立,后续变化正常报告");
        st.note_restart_origin(net, 5, mac, 12, 1008, 8, false, true);
        CHECK(st.mac_to_tei.value(key) == 5 && st.anomalies[0].trips == 3
                  && st.anomalies[0].last_frame == 8 && st.anomalies[0].tei_old == 1
                  && st.anomalies[0].tei == 5,
              "D25h 第三次冲突继续累计并更新最近方向/帧号");
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 1
                  && count_kind(st, TopoEventKind::StaRestart) == 1,
              "D25i 角色切换本身不生成虚假重启");
        st.note_restart_origin(net, 0, mac, 12, 1008, 8, false, true);
        CHECK(st.mac_to_tei.value(key) == 5 && st.anomalies[0].trips == 3,
              "D25j 无源 TEI 回退最新 STA 身份,不恢复旧 CCO");
    }
    // D26:事件侧必须先学习当前映射再判重启;反复冲突沿用异常表 trips 累加。
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
              "D26a 事件新 STA 身份先覆盖旧 CCO,不拿旧基线误报");
        sta.restart_count = 9; sta.frame_index = 3; sta.epoch_ms = 1003;
        st.apply(sta);
        CHECK(count_kind(st, TopoEventKind::StaRestart) == 1 && st.anomalies[0].trips == 1,
              "D26b 同角色事件继续正常检测重启");
        st.apply(frame(TopoEventKind::DiscoverList, 0x0E, mac, 3, 4, mac));
        CHECK(st.anomalies[0].trips == 2 && st.mac_of(5) == 0 && st.mac_of(1) == mac,
              "D26c 事件 CCO 再次出现仍记冲突并覆盖节点");
        sta.restart_count = 10; sta.frame_index = 5; sta.epoch_ms = 1005;
        st.apply(sta);
        CHECK(st.anomalies[0].trips == 3 && st.mac_of(1) == 0 && st.mac_of(5) == mac,
              "D26d 事件再次切回 STA 继续累计冲突");
    }
    // D27:无 RestartCount 的源角色也生效;广播/未知 TEI 不得覆盖有效身份。
    {
        TopoState st;
        st.note_restart_origin(0x0E, 1, MAC_A, 2, 1001, 1, false, true);
        CHECK(st.note_restart_origin(0x0E, 5, MAC_A, kRestartCountInvalid, 1002, 2, false, true),
              "D27a 无重启计数仍记录 CCO/STA 冲突供 UI 刷新");
        st.note_restart_origin(0x0E, kTeiBroadcast, MAC_A, kRestartCountInvalid, 1003, 3, false, true);
        st.note_restart_origin(0x0E, kTeiInvalid, MAC_A, kRestartCountInvalid, 1004, 4, false, true);
        CHECK(st.mac_to_tei.value(TopoState::nid_mac_key(0x0E, MAC_A)) == 5
                  && st.anomalies.size() == 1 && st.anomalies[0].trips == 1,
              "D27b 广播/无效 TEI 不改变当前身份或新增冲突");
        st.note_restart_origin(0x0E, 5, MAC_A, 9, 1005, 5, false, true);
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 0
                  && count_kind(st, TopoEventKind::StaRestart) == 0,
              "D27c 无计数的角色切换清理旧基线,新身份首个计数只建基线");
    }

    // D28:离网后的未知身份不能借残留 TEI=1 索引恢复 CCO;有效 CCO 重现仍可检测重启。
    {
        TopoState st;
        const quint32 net = 0x0E;
        st.apply(frame(TopoEventKind::DiscoverList, net, MAC_CCO, 2, 1, MAC_CCO));
        TopoEvent leave = frame(TopoEventKind::LeaveInd, net, 0, -1, 2);
        leave.leaves.append(MAC_CCO);
        st.apply(leave);
        st.note_restart_origin(net, 0, MAC_CCO, 3, 1003, 3, false, true);
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 0,
              "D28a 未知源 TEI 不使用离线 CCO 索引恢复身份");
        st.note_restart_origin(net, 1, MAC_CCO, 4, 1004, 4, false, true);
        CHECK(count_kind(st, TopoEventKind::CcoRestart) == 1 && st.anomalies.isEmpty()
                  && st.nodes.value(1).status == NodeStatus::Online,
              "D28b 同一 CCO 有效源 TEI 重现恢复在线并检测重启,不当作角色冲突");
    }

    // D29:关联请求不把已分配 TEI 的离线节点直接判在线;已入网请求及其他正向帧可恢复。
    // 复活要留痕:离线→在线跃迁在事件记录里留一条带原因的记录(只记跃迁,不每帧刷屏)。
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
              "D29a LeaveInd 后 STA 保持离线");
        st.note_restart_origin(net, 5, MAC_A, kRestartCountInvalid, 1002, 2, false, true,
                               TopoEventKind::LeaveInd);
        CHECK(st.nodes.value(5).status == NodeStatus::Offline
                  && st.nodes.value(5).last_seen_ms == leave.epoch_ms,
              "D29b 离网指示对应帧不能复活节点");

        // ChangeProxyReq 在 apply 中也只是记录请求;逐帧采样不能把离线 STA 复活。
        TopoEvent proxy_req = frame(TopoEventKind::ChangeProxyReq, net, MAC_A,
                                    kRestartCountInvalid, 3);
        proxy_req.nodes.append({5, 0});
        st.apply(proxy_req);
        st.note_restart_origin(net, 5, MAC_A, kRestartCountInvalid, 1003, 3, false, true,
                               TopoEventKind::ChangeProxyReq);
        CHECK(st.nodes.value(5).status == NodeStatus::Online
                  && st.nodes.value(5).last_seen_ms == 1003,
              "D29c 已入网 STA 的代理变更请求可恢复在线");
        // 复活要留痕:逐帧采样复活留 1 条带原因的事件记录(apply 未翻状态,无重复记)。
        CHECK(count_revival_events(st) == 1,
              "D29f 代理变更请求复活留 1 条复活原因记录");
        bool proxy_revival_ok = false;
        for (const TopoEvent& ev : st.events)
            if (ev.desc.contains(QStringLiteral("节点恢复在线")))
                proxy_revival_ok = ev.kind == TopoEventKind::ChangeProxyReq
                    && ev.desc.contains(QStringLiteral("代理变更请求"))
                    && ev.frame_index == 3 && ev.epoch_ms == 1003
                    && ev.nodes.size() == 1 && ev.nodes[0].tei == 5
                    && ev.nodes[0].mac == MAC_A;
        CHECK(proxy_revival_ok, "D29g 复活记录带 kind/原因/帧号/节点");

        TopoEvent second_leave = frame(TopoEventKind::LeaveInd, net, 0,
                                       kRestartCountInvalid, 4);
        second_leave.leaves.append(MAC_A);
        st.apply(second_leave);
        st.note_restart_origin(net, 5, MAC_A, kRestartCountInvalid, 1005, 5, false, true,
                               TopoEventKind::Other);
        CHECK(st.nodes.value(5).status == NodeStatus::Online
                  && st.nodes.value(5).last_seen_ms == 1005,
              "D29d 普通数据帧仍可恢复既有节点在线");
        CHECK(count_revival_events(st) == 2,
              "D29h 普通数据帧复活再留 1 条,不多不少");
        bool data_revival_ok = false;
        for (const TopoEvent& ev : st.events)
            if (ev.desc.contains(QStringLiteral("节点恢复在线"))
                    && ev.kind == TopoEventKind::Other)
                data_revival_ok = ev.desc.contains(QStringLiteral("普通数据帧"))
                    && ev.frame_index == 5 && ev.epoch_ms == 1005
                    && ev.nodes.size() == 1 && ev.nodes[0].tei == 5
                    && ev.nodes[0].mac == MAC_A;
        CHECK(data_revival_ok, "D29i 普通数据帧复活记录带原因普通数据帧");
        // 已在线节点再收到普通数据帧只更新 last_seen,不重复记复活原因。
        st.note_restart_origin(net, 5, MAC_A, kRestartCountInvalid, 1006, 6, false, true,
                               TopoEventKind::Other);
        CHECK(count_revival_events(st) == 2
                  && st.nodes.value(5).last_seen_ms == 1006,
              "D29j 已在线节点普通数据帧不重复记复活原因");

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
              "D29e 关联请求仅建立入网中状态,不复活离线 TEI 节点");
    }
    // D29k-o: apply() 的状态机翻转同样留复活记录(实机上 AssocCnf 带 (TEI,MAC) 先到 apply,
    // 随后逐帧采样见已在线,不重复记)。
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
              "D29k 离网后 STA 离线");
        TopoEvent cnf = frame(TopoEventKind::AssocCnf, net, MAC_A, kRestartCountInvalid, 3);
        cnf.nodes.append({5, MAC_A});
        st.apply(cnf);
        CHECK(st.nodes.value(5).status == NodeStatus::Online,
              "D29l 关联确认经 apply 复活节点");
        bool apply_revival_ok = false;
        for (const TopoEvent& ev : st.events)
            if (ev.desc.contains(QStringLiteral("节点恢复在线")))
                apply_revival_ok = ev.kind == TopoEventKind::AssocCnf
                    && ev.desc.contains(QStringLiteral("关联确认"))
                    && ev.frame_index == 3 && ev.epoch_ms == 1003
                    && ev.nodes.size() == 1 && ev.nodes[0].tei == 5
                    && ev.nodes[0].mac == MAC_A;
        CHECK(apply_revival_ok, "D29m apply 复活记录带 kind/原因/帧号/节点");
        CHECK(count_revival_events(st) == 1,
              "D29n apply 复活只留 1 条记录");
        st.note_restart_origin(net, 5, MAC_A, kRestartCountInvalid, 1003, 3, false, true,
                               TopoEventKind::AssocCnf);
        CHECK(count_revival_events(st) == 1,
              "D29o apply 与逐帧采样同一复活不重复记");
    }

    // D30:离线→入网中→在线/离网,以及只更新状态的权威来源。
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
              "D30a 离线 STA 的关联请求转为入网中");

        TopoEvent leave_pending = frame(TopoEventKind::LeaveInd, net, 0,
                                        kRestartCountInvalid, 4);
        leave_pending.leaves.append(MAC_A);
        st.apply(leave_pending);
        CHECK(!st.pending.contains(MAC_A),
              "D30b 离网指示清除未完成的 pending 入网状态");

        assoc_req.epoch_ms = 5;
        assoc_req.frame_index = 5;
        st.apply(assoc_req);
        TopoEvent assoc_cnf = frame(TopoEventKind::AssocCnf, net, MAC_A,
                                    kRestartCountInvalid, 6);
        assoc_cnf.nodes.append({5, MAC_A});
        st.apply(assoc_cnf);
        CHECK(!st.pending.contains(MAC_A) && st.nodes.value(5).status == NodeStatus::Online,
              "D30c 关联确认将 pending 节点提升为在线");
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
              "D30d 非在线证据事件不把离线节点改为在线");

        TopoEvent proxy = frame(TopoEventKind::ChangeProxyCnf, net, 0,
                                kRestartCountInvalid, 4);
        proxy.link_type = 0;
        proxy.child_teis.append(7);
        st.apply(proxy);
        CHECK(st.nodes.value(7).status == NodeStatus::Online
                  && st.nodes.value(7).last_seen_ms == proxy.epoch_ms,
              "D30e 成功代理确认中的子 TEI 位图建立在线节点");

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
              "D30f 离线节点发出有效信道报告后恢复在线");
    }

    // D31:无重启计数的普通数据帧复活离线节点时,实时与回放必须一致。
    //     rc=0xFF 的帧不进拓扑事件日志(kind==Other),也不进采样日志(只记有效计数),
    //     但实时 note_restart_origin 仍会复活(复活块在计数检查之前)。收紧版:只给
    //     真正复活的帧补记一条采样(rc=0xFF),回放重走同一函数复现复活与原因。
    {
        const quint32 net = 0x0E;
        // 模拟 MainWindow 实时路径:帧1 关联确认(事件+采样),帧2 离网(事件),
        // 帧3 普通数据帧 rc=0xFF(仅逐帧路径,复活了才补记采样)。
        QHash<quint32, TopoState> live;
        QVector<TopoLogItem> topo_log;
        QVector<TopoChannelSample> channel_log;
        QVector<TopoRestartSample> restart_log;
        TopoState& live_st = live[net];
        live_st.nid = net;
        TopoEvent joined = frame(TopoEventKind::AssocCnf, net, MAC_A, kRestartCountInvalid, 1);
        joined.nodes.append({5, MAC_A});
        live_st.apply(joined);
        topo_log.append({1, joined});
        TopoEvent leave = frame(TopoEventKind::LeaveInd, net, 0, kRestartCountInvalid, 2);
        leave.leaves.append(MAC_A);
        live_st.apply(leave);
        topo_log.append({2, leave});
        CHECK(live_st.nodes.value(5).status == NodeStatus::Offline,
              "D31a LeaveInd 后 STA 离线");
        bool did_revive = false;
        live_st.note_restart_origin(net, 5, MAC_A, kRestartCountInvalid, 1003, 3, false, true,
                                    TopoEventKind::Other, &did_revive);
        CHECK(did_revive, "D31b 无计数普通数据帧复活时报告复活");
        if (did_revive)
            restart_log.append({3, net, 5, MAC_A, kRestartCountInvalid, 1003, false, true,
                                TopoEventKind::Other});
        CHECK(live_st.nodes.value(5).status == NodeStatus::Online
                  && count_revival_events(live_st) == 1,
              "D31c 实时复活在线且留 1 条复活记录");
        // 回放到帧2:快照仍离线、无复活记录;增量回放到帧3:节点在线且记录与实时一致。
        QHash<quint32, TopoState> hist;
        qint64 replayed = -1;
        replay_topo_logs(topo_log, channel_log, restart_log, 2, replayed, hist);
        CHECK(hist.contains(net) && hist[net].nodes.value(5).status == NodeStatus::Offline
                  && count_revival_events(hist[net]) == 0,
              "D31d 回放到帧2,快照仍离线、无复活记录");
        replay_topo_logs(topo_log, channel_log, restart_log, 3, replayed, hist);
        CHECK(hist.contains(net) && hist[net].nodes.value(5).status == NodeStatus::Online,
              "D31e 回放到帧3,快照节点在线");
        bool hist_revival_ok = false;
        for (const TopoEvent& ev : hist[net].events)
            if (ev.desc.contains(QStringLiteral("节点恢复在线")))
                hist_revival_ok = ev.kind == TopoEventKind::Other
                    && ev.desc.contains(QStringLiteral("普通数据帧"))
                    && ev.frame_index == 3 && ev.epoch_ms == 1003
                    && ev.nodes.size() == 1 && ev.nodes[0].tei == 5
                    && ev.nodes[0].mac == MAC_A;
        CHECK(hist_revival_ok, "D31f 回放快照复活记录带 kind/原因/帧号/节点");
        CHECK(count_revival_events(hist[net]) == 1,
              "D31g 回放复活只留 1 条记录");
        // 阴性对照:同样的事件日志但采样日志里没有这条采样,回放到帧3仍离线、无复活记录。
        QVector<TopoChannelSample> empty_channel_log;
        QVector<TopoRestartSample> empty_restart_log;
        QHash<quint32, TopoState> hist2;
        qint64 replayed2 = -1;
        replay_topo_logs(topo_log, empty_channel_log, empty_restart_log, 3, replayed2, hist2);
        CHECK(hist2.contains(net) && hist2[net].nodes.value(5).status == NodeStatus::Offline
                  && count_revival_events(hist2[net]) == 0,
              "D31h 无采样时回放到帧3仍离线、无复活记录");
        // 已在线节点再收普通数据帧不报告复活、不重复记。
        bool did_revive_again = true;
        live_st.note_restart_origin(net, 5, MAC_A, kRestartCountInvalid, 1004, 4, false, true,
                                    TopoEventKind::Other, &did_revive_again);
        CHECK(!did_revive_again && count_revival_events(live_st) == 1
                  && live_st.nodes.value(5).last_seen_ms == 1004,
              "D31i 已在线节点普通数据帧不报告复活、不重复记");
        // 离网指示帧不复活,也不报告复活。
        TopoEvent leave2 = frame(TopoEventKind::LeaveInd, net, 0, kRestartCountInvalid, 5);
        leave2.leaves.append(MAC_A);
        live_st.apply(leave2);
        bool did_revive_leave = true;
        live_st.note_restart_origin(net, 5, MAC_A, kRestartCountInvalid, 1005, 6, false, true,
                                    TopoEventKind::LeaveInd, &did_revive_leave);
        CHECK(!did_revive_leave && live_st.nodes.value(5).status == NodeStatus::Offline,
              "D31j 离网指示帧不复活、不报告复活");
    }
    // D31k-l:NID 隔离对照——0x0E 与 0x0F 各有一个 TEI=5 节点(不同 MAC),0x0E 的离线、
    //        0x0F 的在线;一帧属于 0x0F 的 rc=0xFF 数据帧不得复活 0x0E 的节点。
    {
        QHash<quint32, TopoState> live;
        QVector<TopoLogItem> topo_log;
        QVector<TopoChannelSample> channel_log;
        QVector<TopoRestartSample> restart_log;
        TopoEvent joined_e = frame(TopoEventKind::AssocCnf, 0x0E, MAC_A,
                                   kRestartCountInvalid, 1);
        joined_e.nodes.append({5, MAC_A});
        live[0x0E].nid = 0x0E;
        live[0x0E].apply(joined_e);
        topo_log.append({1, joined_e});
        TopoEvent leave_e = frame(TopoEventKind::LeaveInd, 0x0E, 0, kRestartCountInvalid, 2);
        leave_e.leaves.append(MAC_A);
        live[0x0E].apply(leave_e);
        topo_log.append({2, leave_e});
        TopoEvent joined_f = frame(TopoEventKind::AssocCnf, 0x0F, MAC_B,
                                   kRestartCountInvalid, 3);
        joined_f.nodes.append({5, MAC_B});
        live[0x0F].nid = 0x0F;
        live[0x0F].apply(joined_f);
        topo_log.append({3, joined_f});
        // 模拟 MainWindow 逐帧块:0x0F 的无计数数据帧走 0x0F 自己的状态,节点已在线,
        // 不复活、不补记采样。
        bool did_revive = true;
        live[0x0F].note_restart_origin(0x0F, 5, MAC_B, kRestartCountInvalid, 1004, 4,
                                       false, true, TopoEventKind::Other, &did_revive);
        CHECK(!did_revive && restart_log.isEmpty()
                  && live[0x0E].nodes.value(5).status == NodeStatus::Offline
                  && live[0x0F].nodes.value(5).status == NodeStatus::Online,
              "D31k 0x0F 在线节点的无计数数据帧不报告复活、不补记采样、不碰 0x0E");
        // 即使采样日志里有一条 0x0F 的采样,回放也只作用于 0x0F,不碰 0x0E 的快照。
        restart_log.append({4, 0x0F, 5, MAC_B, kRestartCountInvalid, 1004, false, true,
                            TopoEventKind::Other});
        QHash<quint32, TopoState> hist;
        qint64 replayed = -1;
        replay_topo_logs(topo_log, channel_log, restart_log, 4, replayed, hist);
        CHECK(hist.contains(0x0E) && hist[0x0E].nodes.value(5).status == NodeStatus::Offline
                  && count_revival_events(hist[0x0E]) == 0
                  && hist.contains(0x0F) && hist[0x0F].nodes.value(5).status == NodeStatus::Online
                  && count_revival_events(hist[0x0F]) == 0,
              "D31l 回放里 0x0F 采样不复活 0x0E 节点,两组快照互不串");
    }
    // D32:单跳帧信道观测复活离线节点时,实时与回放必须一致。
    //     信道观测只走第三条信道日志,不进拓扑事件日志(kind==Other)也不进采样日志
    //     (rc=0xFF 无计数);回放重调 apply_channel_info 复现 Online 翻转、last_seen
    //     与邻居数据;复活离线节点时留一条复活记录(kind=ChannelInfo,原因“信道观测”)。
    {
        const quint32 net = 0x0E;
        // 模拟 MainWindow 实时路径:帧1 关联确认 TEI=8 入网,帧2 关联确认 TEI=5 入网
        // (邻居节点,供 RSSI 落地),帧3 离网 TEI=8,帧4 单跳信道观测复活,帧5 同节点已在线
        // 时再观测(不重复记),帧6 同帧既有离网事件又有信道观测(事件先、信道后)。
        QHash<quint32, TopoState> live;
        QVector<TopoLogItem> topo_log;
        QVector<TopoChannelSample> channel_log;
        QVector<TopoRestartSample> restart_log;
        TopoState& live_st = live[net];
        live_st.nid = net;
        TopoEvent joined8 = frame(TopoEventKind::AssocCnf, net, MAC_B, kRestartCountInvalid, 1);
        joined8.nodes.append({8, MAC_B});
        live_st.apply(joined8);
        topo_log.append({1, joined8});
        TopoEvent joined5 = frame(TopoEventKind::AssocCnf, net, MAC_A, kRestartCountInvalid, 2);
        joined5.nodes.append({5, MAC_A});
        live_st.apply(joined5);
        topo_log.append({2, joined5});
        TopoEvent leave = frame(TopoEventKind::LeaveInd, net, 0, kRestartCountInvalid, 3);
        leave.leaves.append(MAC_B);
        live_st.apply(leave);
        topo_log.append({3, leave});
        CHECK(live_st.nodes.value(8).status == NodeStatus::Offline,
              "D32a LeaveInd 后 TEI=8 离线");
        TopoEvent channel4 = frame(TopoEventKind::Other, net, MAC_B, kRestartCountInvalid, 4);
        channel4.proxy_tei = 1;
        channel4.proxy_up_rate = 90;
        channel4.neighbor_rates.append({5, 90});
        channel4.neighbor_snrs.append({5, 12});
        channel4.rssi_entries.append({5, -70});
        live_st.apply_channel_info(8, channel4);
        channel_log.append({4, net, 8, 1004, channel4});
        CHECK(live_st.nodes.value(8).status == NodeStatus::Online
                  && live_st.nodes.value(8).last_seen_ms == 1004,
              "D32b 信道观测复活离线节点在线且 last_seen 已写");
        CHECK(live_st.neighbor_rates.value(8).value(5) == 90
                  && live_st.neighbor_snrs.value(8).value(5) == 12
                  && live_st.nodes.value(5).rssi_dbm == -70
                  && live_st.nodes.value(5).rssi_known,
              "D32c 信道观测的邻居接收率/SNR/RSSI 已落地");
        bool live_revival_ok = false;
        for (const TopoEvent& ev : live_st.events)
            if (ev.desc.contains(QStringLiteral("节点恢复在线")))
                live_revival_ok = ev.kind == TopoEventKind::ChannelInfo
                    && ev.desc.contains(QStringLiteral("信道观测"))
                    && ev.frame_index == 4 && ev.epoch_ms == 1004
                    && ev.nodes.size() == 1 && ev.nodes[0].tei == 8
                    && ev.nodes[0].mac == MAC_B && ev.sender_mac == MAC_B
                    && ev.nid == net;
        CHECK(live_revival_ok && count_revival_events(live_st) == 1,
              "D32d 信道观测复活只留 1 条记录,kind/原因/帧号/节点正确");
        // 回放到帧3:快照仍离线、无邻居数据、无复活记录;增量回放到帧4:节点在线且记录与实时一致。
        QHash<quint32, TopoState> hist;
        qint64 replayed = -1;
        replay_topo_logs(topo_log, channel_log, restart_log, 3, replayed, hist);
        CHECK(hist.contains(net) && hist[net].nodes.value(8).status == NodeStatus::Offline
                  && hist[net].neighbor_rates.value(8).isEmpty()
                  && count_revival_events(hist[net]) == 0,
              "D32e 回放到帧3,快照仍离线、无邻居数据、无复活记录");
        replay_topo_logs(topo_log, channel_log, restart_log, 4, replayed, hist);
        CHECK(hist.contains(net) && hist[net].nodes.value(8).status == NodeStatus::Online
                  && hist[net].nodes.value(8).last_seen_ms == 1004
                  && hist[net].neighbor_rates.value(8).value(5) == 90
                  && hist[net].neighbor_snrs.value(8).value(5) == 12
                  && hist[net].nodes.value(5).rssi_dbm == -70
                  && hist[net].nodes.value(5).rssi_known,
              "D32f 回放到帧4,快照节点在线且 last_seen/邻居数据已落地");
        bool hist_revival_ok = false;
        for (const TopoEvent& ev : hist[net].events)
            if (ev.desc.contains(QStringLiteral("节点恢复在线")))
                hist_revival_ok = ev.kind == TopoEventKind::ChannelInfo
                    && ev.desc.contains(QStringLiteral("信道观测"))
                    && ev.frame_index == 4 && ev.epoch_ms == 1004
                    && ev.nodes.size() == 1 && ev.nodes[0].tei == 8
                    && ev.nodes[0].mac == MAC_B && ev.sender_mac == MAC_B
                    && ev.nid == net;
        CHECK(hist_revival_ok && count_revival_events(hist[net]) == 1,
              "D32g 回放快照复活记录与实时一致,只 1 条");
        // 阴性对照:同样的事件日志但信道日志为空,回放到帧4仍离线、无邻居数据、无复活记录。
        QVector<TopoChannelSample> empty_channel_log;
        QHash<quint32, TopoState> hist2;
        qint64 replayed2 = -1;
        replay_topo_logs(topo_log, empty_channel_log, restart_log, 4, replayed2, hist2);
        CHECK(hist2.contains(net) && hist2[net].nodes.value(8).status == NodeStatus::Offline
                  && hist2[net].neighbor_rates.value(8).isEmpty()
                  && count_revival_events(hist2[net]) == 0,
              "D32h 无信道观测时回放到帧4仍离线、无邻居数据、无复活记录");
        // 已在线节点再收信道观测:不重复记复活原因,邻居数据照常更新。
        TopoEvent channel5 = frame(TopoEventKind::Other, net, MAC_B, kRestartCountInvalid, 5);
        channel5.proxy_tei = 1;
        channel5.proxy_up_rate = 88;
        channel5.neighbor_rates.append({5, 88});
        live_st.apply_channel_info(8, channel5);
        channel_log.append({5, net, 8, 1005, channel5});
        replay_topo_logs(topo_log, channel_log, restart_log, 5, replayed, hist);
        CHECK(count_revival_events(live_st) == 1
                  && live_st.neighbor_rates.value(8).value(5) == 88
                  && count_revival_events(hist[net]) == 1
                  && hist[net].neighbor_rates.value(8).value(5) == 88,
              "D32i 已在线节点信道观测不重复记复活原因,邻居数据照常更新");
        // 同帧顺序:帧6 既有离网事件又有信道观测,事件先应用、信道后应用,最终在线且再记 1 条。
        TopoEvent leave6 = frame(TopoEventKind::LeaveInd, net, 0, kRestartCountInvalid, 6);
        leave6.leaves.append(MAC_B);
        live_st.apply(leave6);
        topo_log.append({6, leave6});
        TopoEvent channel6 = frame(TopoEventKind::Other, net, MAC_B, kRestartCountInvalid, 6);
        channel6.proxy_tei = 1;
        channel6.proxy_up_rate = 85;
        channel6.neighbor_rates.append({5, 85});
        live_st.apply_channel_info(8, channel6);
        channel_log.append({6, net, 8, 1006, channel6});
        replay_topo_logs(topo_log, channel_log, restart_log, 6, replayed, hist);
        CHECK(live_st.nodes.value(8).status == NodeStatus::Online
                  && count_revival_events(live_st) == 2
                  && hist.contains(net) && hist[net].nodes.value(8).status == NodeStatus::Online
                  && count_revival_events(hist[net]) == 2,
              "D32j 同帧离网事件在先、信道观测在后,最终在线且各记 1 条");
    }
    // D32k-l:NID 隔离对照——0x0E 与 0x0F 各有一个 TEI=8 节点(不同 MAC),0x0E 的离线、
    //        0x0F 的在线;一帧属于 0x0F 的信道观测不得碰 0x0E 的快照,也不得给它记复活记录。
    {
        const quint64 MAC_D = 0x5566778899AAULL;
        QHash<quint32, TopoState> live;
        QVector<TopoLogItem> topo_log;
        QVector<TopoChannelSample> channel_log;
        QVector<TopoRestartSample> restart_log;
        TopoEvent joined_e = frame(TopoEventKind::AssocCnf, 0x0E, MAC_B, kRestartCountInvalid, 1);
        joined_e.nodes.append({8, MAC_B});
        live[0x0E].nid = 0x0E;
        live[0x0E].apply(joined_e);
        topo_log.append({1, joined_e});
        TopoEvent leave_e = frame(TopoEventKind::LeaveInd, 0x0E, 0, kRestartCountInvalid, 2);
        leave_e.leaves.append(MAC_B);
        live[0x0E].apply(leave_e);
        topo_log.append({2, leave_e});
        TopoEvent joined_f = frame(TopoEventKind::AssocCnf, 0x0F, MAC_D, kRestartCountInvalid, 3);
        joined_f.nodes.append({8, MAC_D});
        live[0x0F].nid = 0x0F;
        live[0x0F].apply(joined_f);
        topo_log.append({3, joined_f});
        // 模拟 MainWindow 信道块:0x0F 的信道观测只走 0x0F 自己的状态;节点已在线,不复活、
        // 不记复活记录,但邻居数据照常落地。
        TopoEvent channel_f = frame(TopoEventKind::Other, 0x0F, MAC_D, kRestartCountInvalid, 4);
        channel_f.proxy_tei = 1;
        channel_f.proxy_up_rate = 90;
        channel_f.neighbor_rates.append({5, 90});
        live[0x0F].apply_channel_info(8, channel_f);
        channel_log.append({4, 0x0F, 8, 1004, channel_f});
        CHECK(live[0x0E].nodes.value(8).status == NodeStatus::Offline
                  && count_revival_events(live[0x0E]) == 0
                  && live[0x0F].nodes.value(8).status == NodeStatus::Online
                  && count_revival_events(live[0x0F]) == 0
                  && live[0x0F].neighbor_rates.value(8).value(5) == 90,
              "D32k 0x0F 在线节点的信道观测不复活、不记记录、不碰 0x0E,邻居数据只落本组");
        QHash<quint32, TopoState> hist;
        qint64 replayed = -1;
        replay_topo_logs(topo_log, channel_log, restart_log, 4, replayed, hist);
        CHECK(hist.contains(0x0E) && hist[0x0E].nodes.value(8).status == NodeStatus::Offline
                  && count_revival_events(hist[0x0E]) == 0
                  && hist[0x0E].neighbor_rates.value(8).isEmpty()
                  && hist.contains(0x0F) && hist[0x0F].nodes.value(8).status == NodeStatus::Online
                  && count_revival_events(hist[0x0F]) == 0
                  && hist[0x0F].neighbor_rates.value(8).value(5) == 90,
              "D32l 回放里 0x0F 信道观测不碰 0x0E 快照,两组互不串");
    }

    // D33:停上电事件上报进 TOPO——断电算离线(LeaveInd 同款),断电/上电都记录,
    //     上电只记录、不改状态、不复活。位图方式按 TEI 点名(解析层填 {TEI,0}),
    //     地址方式按电表地址点名(解析层填 {0,MAC} + leaves)。
    {
        const quint32 net = 0x0E;
        QHash<quint32, TopoState> live;
        QVector<TopoLogItem> topo_log;
        QVector<TopoChannelSample> channel_log;
        QVector<TopoRestartSample> restart_log;
        TopoState& live_st = live[net];
        live_st.nid = net;
        TopoEvent joined5 = frame(TopoEventKind::AssocCnf, net, MAC_A, kRestartCountInvalid, 1);
        joined5.nodes.append({5, MAC_A});
        live_st.apply(joined5);
        topo_log.append({1, joined5});
        TopoEvent joined8 = frame(TopoEventKind::AssocCnf, net, MAC_B, kRestartCountInvalid, 2);
        joined8.nodes.append({8, MAC_B});
        live_st.apply(joined8);
        topo_log.append({2, joined8});
        CHECK(live_st.nodes.value(5).status == NodeStatus::Online
                  && live_st.nodes.value(8).status == NodeStatus::Online,
              "D33a 关联确认后 TEI=5/8 均在线");
        // 帧3:位图断电 TEI=8(上报方 MAC_A,受影响节点不是上报方)。
        TopoEvent off8 = frame(TopoEventKind::PowerOff, net, MAC_A, kRestartCountInvalid, 3);
        off8.nodes.append({8, 0});
        off8.desc = QStringLiteral("断电事件: TEI=8 断电离线");
        live_st.apply(off8);
        topo_log.append({3, off8});
        CHECK(live_st.nodes.value(8).status == NodeStatus::Offline
                  && live_st.nodes.value(5).status == NodeStatus::Online
                  && count_kind(live_st, TopoEventKind::PowerOff) == 1,
              "D33b 位图断电后 TEI=8 离线、TEI=5 仍在线,留 1 条断电记录");
        // 回放到帧2:两节点都在线、无断电记录;增量回放到帧3:TEI=8 离线且记录一致。
        QHash<quint32, TopoState> hist;
        qint64 replayed = -1;
        replay_topo_logs(topo_log, channel_log, restart_log, 2, replayed, hist);
        CHECK(hist.contains(net) && hist[net].nodes.value(8).status == NodeStatus::Online
                  && count_kind(hist[net], TopoEventKind::PowerOff) == 0,
              "D33c 回放到帧2,TEI=8 仍在线、无断电记录");
        replay_topo_logs(topo_log, channel_log, restart_log, 3, replayed, hist);
        bool hist_off_ok = false;
        for (const TopoEvent& ev : hist[net].events)
            if (ev.kind == TopoEventKind::PowerOff)
                hist_off_ok = ev.desc.contains(QStringLiteral("断电"))
                    && ev.frame_index == 3 && ev.epoch_ms == 1003
                    && ev.nodes.size() == 1 && ev.nodes[0].tei == 8
                    && ev.sender_mac == MAC_A && ev.nid == net;
        CHECK(hist.contains(net) && hist[net].nodes.value(8).status == NodeStatus::Offline
                  && hist_off_ok && count_kind(hist[net], TopoEventKind::PowerOff) == 1,
              "D33d 回放到帧3,TEI=8 离线且断电记录带说明/帧号/节点");
        // 帧4:地址上电 TEI=8 的电表(MAC_B),离线节点只记录、不复活。
        TopoEvent on8 = frame(TopoEventKind::PowerOn, net, MAC_CCO, kRestartCountInvalid, 4);
        on8.nodes.append({0, MAC_B});
        on8.desc = QStringLiteral("上电事件: STA 66:55:44:33:22:11 上电");
        live_st.apply(on8);
        topo_log.append({4, on8});
        CHECK(live_st.nodes.value(8).status == NodeStatus::Offline
                  && count_kind(live_st, TopoEventKind::PowerOn) == 1
                  && count_revival_events(live_st) == 0,
              "D33e 地址上电后离线节点仍离线,只留记录、不复活");
        // 帧5:地址上电 TEI=5 的电表(MAC_A),在线节点只记录、状态不变。
        TopoEvent on5 = frame(TopoEventKind::PowerOn, net, MAC_CCO, kRestartCountInvalid, 5);
        on5.nodes.append({0, MAC_A});
        on5.desc = QStringLiteral("上电事件: STA ff:ee:dd:cc:bb:aa 上电");
        live_st.apply(on5);
        topo_log.append({5, on5});
        CHECK(live_st.nodes.value(5).status == NodeStatus::Online
                  && count_kind(live_st, TopoEventKind::PowerOn) == 2
                  && count_revival_events(live_st) == 0,
              "D33f 地址上电后在线节点仍在线,上电记录累计 2 条、不复活");
        // 帧6:地址断电 TEI=5 的电表(MAC_A,leaves 走 LeaveInd 同款路径)。
        TopoEvent off5 = frame(TopoEventKind::PowerOff, net, MAC_CCO, kRestartCountInvalid, 6);
        off5.nodes.append({0, MAC_A});
        off5.leaves.append(MAC_A);
        off5.desc = QStringLiteral("断电事件: STA ff:ee:dd:cc:bb:aa 断电离线");
        live_st.apply(off5);
        topo_log.append({6, off5});
        CHECK(live_st.nodes.value(5).status == NodeStatus::Offline
                  && count_kind(live_st, TopoEventKind::PowerOff) == 2,
              "D33g 地址断电后 TEI=5 离线,断电记录累计 2 条");
        // 帧7/8:两节点重新入网(关联确认复活,各留 1 条复活记录);
        // 帧9:位图一帧报两节点断电(首事件 + extra 事件)。
        TopoEvent rejoin5 = frame(TopoEventKind::AssocCnf, net, MAC_A, kRestartCountInvalid, 7);
        rejoin5.nodes.append({5, MAC_A});
        live_st.apply(rejoin5);
        topo_log.append({7, rejoin5});
        TopoEvent rejoin8 = frame(TopoEventKind::AssocCnf, net, MAC_B, kRestartCountInvalid, 8);
        rejoin8.nodes.append({8, MAC_B});
        live_st.apply(rejoin8);
        topo_log.append({8, rejoin8});
        TopoEvent off5b = frame(TopoEventKind::PowerOff, net, MAC_A, kRestartCountInvalid, 9);
        off5b.nodes.append({5, 0});
        off5b.desc = QStringLiteral("断电事件: TEI=5 断电离线");
        live_st.apply(off5b);
        topo_log.append({9, off5b});
        TopoEvent off8b = frame(TopoEventKind::PowerOff, net, MAC_A, kRestartCountInvalid, 9);
        off8b.nodes.append({8, 0});
        off8b.desc = QStringLiteral("断电事件: TEI=8 断电离线");
        live_st.apply(off8b);
        topo_log.append({9, off8b});
        CHECK(live_st.nodes.value(5).status == NodeStatus::Offline
                  && live_st.nodes.value(8).status == NodeStatus::Offline
                  && count_kind(live_st, TopoEventKind::PowerOff) == 4,
              "D33h 位图一帧两节点断电(首事件+extra),两节点均离线、记录累计 4 条");
        replay_topo_logs(topo_log, channel_log, restart_log, 9, replayed, hist);
        CHECK(hist.contains(net) && hist[net].nodes.value(5).status == NodeStatus::Offline
                  && hist[net].nodes.value(8).status == NodeStatus::Offline
                  && count_kind(hist[net], TopoEventKind::PowerOff) == 4
                  && count_kind(hist[net], TopoEventKind::PowerOn) == 2
                  && count_revival_events(hist[net]) == 2,
              "D33i 回放到帧9,两节点离线且断电/上电记录与实时一致,复活记录只来自帧7/8 重入网");
    }
    // D33j-m:不存在的节点跳过(不凭空建)、NID 隔离。
    {
        const quint64 MAC_D = 0x5566778899AAULL;
        const quint64 MAC_UNKNOWN = 0xDEADBEEF0001ULL;
        QHash<quint32, TopoState> live;
        QVector<TopoLogItem> topo_log;
        QVector<TopoChannelSample> channel_log;
        QVector<TopoRestartSample> restart_log;
        TopoEvent joined_e = frame(TopoEventKind::AssocCnf, 0x0E, MAC_A, kRestartCountInvalid, 1);
        joined_e.nodes.append({5, MAC_A});
        live[0x0E].nid = 0x0E;
        live[0x0E].apply(joined_e);
        topo_log.append({1, joined_e});
        TopoEvent joined_f = frame(TopoEventKind::AssocCnf, 0x0F, MAC_D, kRestartCountInvalid, 2);
        joined_f.nodes.append({5, MAC_D});
        live[0x0F].nid = 0x0F;
        live[0x0F].apply(joined_f);
        topo_log.append({2, joined_f});
        // 帧3:位图断电 TEI=9(0x0E 下从未入网)。
        TopoEvent off9 = frame(TopoEventKind::PowerOff, 0x0E, MAC_A, kRestartCountInvalid, 3);
        off9.nodes.append({9, 0});
        off9.desc = QStringLiteral("断电事件: TEI=9 断电离线");
        live[0x0E].apply(off9);
        topo_log.append({3, off9});
        CHECK(!live[0x0E].nodes.contains(9)
                  && live[0x0E].nodes.value(5).status == NodeStatus::Online
                  && count_kind(live[0x0E], TopoEventKind::PowerOff) == 1,
              "D33j 位图断电不存在的 TEI=9 不建节点,TEI=5 仍在线、记录仍留 1 条");
        // 帧4:地址断电未知 MAC(0x0E 下从未入网)。
        TopoEvent off_unknown = frame(TopoEventKind::PowerOff, 0x0E, MAC_CCO, kRestartCountInvalid, 4);
        off_unknown.nodes.append({0, MAC_UNKNOWN});
        off_unknown.leaves.append(MAC_UNKNOWN);
        off_unknown.desc = QStringLiteral("断电事件: STA 01:00:ef:be:ad:de 断电离线");
        live[0x0E].apply(off_unknown);
        topo_log.append({4, off_unknown});
        CHECK(live[0x0E].nodes.size() == 1
                  && count_kind(live[0x0E], TopoEventKind::PowerOff) == 2,
              "D33k 地址断电未知 MAC 不建节点,断电记录累计 2 条");
        // 帧5:位图断电 TEI=5(0x0E),0x0F 的 TEI=5 不受影响。
        TopoEvent off5_e = frame(TopoEventKind::PowerOff, 0x0E, MAC_A, kRestartCountInvalid, 5);
        off5_e.nodes.append({5, 0});
        off5_e.desc = QStringLiteral("断电事件: TEI=5 断电离线");
        live[0x0E].apply(off5_e);
        topo_log.append({5, off5_e});
        CHECK(live[0x0E].nodes.value(5).status == NodeStatus::Offline
                  && live[0x0F].nodes.value(5).status == NodeStatus::Online,
              "D33l 位图断电只离线本 NID 的 TEI=5,另一 NID 同 TEI 仍在线");
        QHash<quint32, TopoState> hist;
        qint64 replayed = -1;
        replay_topo_logs(topo_log, channel_log, restart_log, 5, replayed, hist);
        CHECK(hist.contains(0x0E) && hist[0x0E].nodes.value(5).status == NodeStatus::Offline
                  && !hist[0x0E].nodes.contains(9) && hist[0x0E].nodes.size() == 1
                  && count_kind(hist[0x0E], TopoEventKind::PowerOff) == 3
                  && hist.contains(0x0F) && hist[0x0F].nodes.value(5).status == NodeStatus::Online,
              "D33m 回放里不存在的节点同样不建、两 NID 快照互不串");
    }

    std::printf(failures ? "RESULT: %d FAILURES\n" : "RESULT: ALL PASS\n", failures);
    return failures ? 1 : 0;
}
