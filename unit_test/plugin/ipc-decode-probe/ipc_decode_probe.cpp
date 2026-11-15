/// @file ipc_decode_probe.cpp
/// @brief 插件 IPC 反序列化防护回归探针(M2 字段树深度/节点数 + Qt 容器计数 reserve)
/// @details 插件宿主进程不可信:它发来的 ParseResponse 在主程序(worker 线程)里
///   用 plugin_serialization 的 operator>> 解码。修复前
///   - MsduFieldNode / DissectField 递归无深度上限:1 MiB 帧可嵌套 5 万层 ⇒ 栈溢出;
///   - 所有 QVector/QList 字段走 Qt 默认 readArrayBasedContainer,对流里读出的计数
///     直接 reserve(n):声明 0xFFFFFFFD 个元素 ⇒ bad_alloc(未捕获即崩溃)/数 GB 分配;
///   - 主程序不看 ds.status(),损坏/半棵树照收。
///   ① 单元部分(每例 fork 子进程解码,子进程 RLIMIT_AS=1 GiB;ASan 构建不设上限,
///     用 ASAN_OPTIONS=max_allocation_size_mb 观察巨额分配):
///     完整往返、64 层/10000 节点为界、65 层/10001 节点、5 万层嵌套、各容器计数 0xFFFFFFFD、
///     截断 ⇒ 须"拒绝"(status != Ok、无崩溃、无 bad_alloc)。
///   ② 端到端:本程序复制为 bplc-plugin-host 充当恶意宿主(按插件目录里的 response.bin
///     原样回 ParseResponse),PluginManager 真实收包:合法响应照常;损坏响应 ⇒ parse 失败、
///     插件被停用(状态 protocol-error-disabled)、主程序不崩。
///   预期输出 `RESULT: ALL PASS (0 failures)`,exit 0。
#include "ipc/plugin_ipc.h"
#include "ipc/plugin_serialization.h"
#include "manager/plugin_manager.h"

#include <QApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalSocket>
#include <QTemporaryDir>
#include <QThread>
#include <QTimer>
#include <atomic>
#include <cstdio>
#include <functional>
#include <new>
#ifdef Q_OS_UNIX
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if defined(__SANITIZE_ADDRESS__)
#define PROBE_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define PROBE_ASAN 1
#endif
#endif

static int g_fails = 0;
static void check(const QByteArray& name, bool ok, const QByteArray& detail = QByteArray()) {
    std::printf("%-66s %s%s%s\n", name.constData(), ok ? "PASS" : "FAIL",
                detail.isEmpty() ? "" : "  ", detail.constData());
    std::fflush(stdout);
    if (!ok) ++g_fails;
}

// ---------------------------------------------------------------- 编码工具
static QByteArray be32(quint32 v) {
    QByteArray b(4, 0);
    b[0] = char(v >> 24); b[1] = char(v >> 16); b[2] = char(v >> 8); b[3] = char(v);
    return b;
}
template <typename T>
static QByteArray ser(const T& v) {
    QByteArray b;
    QDataStream o(&b, QIODevice::WriteOnly);
    o.setVersion(plugin_ipc::kStreamVersion);
    o << v;
    return b;
}
/// QString 线上正文(UTF-16 BE,不含 4 字节长度)
static QByteArray str_body(const QString& s) { return ser(s).mid(4); }

static MsduFieldNode node(const QString& n, const QString& v = QString(), int rs = 0, int rl = 0) {
    MsduFieldNode x; x.name = n; x.value = v; x.rel_start = rs; x.rel_len = rl; return x;
}

/// 基准 ParseResult:每个容器放一个独特图样,便于在字节流里定位它的计数字段
static ParseResult base_result() {
    ParseResult r;
    r.accept = true;
    r.meta.timestamp = 0x01020304;
    r.mpdu.frame_type = 1;
    r.mpdu.pb_heads = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5};
    r.mpdu.pb_crc_oks = {true, false, false, true, true, true, false, true, false, false, true};
    r.msdu_body = QByteArray("\x11\x22\x33", 3);
    r.msdu.present = true;
    r.msdu.summary = QStringLiteral("probe");
    MsduFieldNode parent = node(QStringLiteral("@@PARENT@@"), QStringLiteral("p"), 1, 2);
    parent.children << node(QStringLiteral("@@CHILD@@"), QStringLiteral("c"), 3, 4);
    r.msdu.tree << node(QStringLiteral("@@TREE@@")) << parent;
    r.msdu.tei_mac_pairs = {{0x0ABC, 0x0102030405060708ull}};
    r.msdu.topo_event.nodes = {{0x0DEF, 0x1112131415161718ull}};
    r.msdu.topo_event.routes = {{0x7A01, 0x7A02}, {0x7A03, 0x7A04}};
    r.msdu.topo_event.up_routes = {{0x7B01, 0x7B02}};
    r.msdu.topo_event.neighbor_teis = {0x6C01, 0x6C02, 0x6C03};
    r.msdu.topo_event.leaves = {0x2122232425262728ull};
    CommRateInfo cr; cr.tei = 0x5E01; cr.down = 0x33; cr.up = 0x44;
    r.msdu.topo_event.comm_rates = {cr};
    r.msdu.topo_event.desc = QStringLiteral("d");
    r.beacon.tree << node(QStringLiteral("beacon"), QStringLiteral("b"));
    DissectField dp(QStringLiteral("@@DPAR@@"), QStringLiteral("v"), 0, 1);
    dp.children << DissectField(QStringLiteral("@@DCHILD@@"), QStringLiteral("w"), 1, 1);
    r.dissect_fields << DissectField(QStringLiteral("@@DIS@@"), QString(), 0, 0) << dp;
    r.reject_reason = QStringLiteral("none");
    return r;
}

/// ParseResponse 中 ok 之后的载荷:ParseResult + MsduState(主程序 parse_via_plugin 解码的部分)
static QByteArray payload_of(const ParseResult& r) {
    MsduState m; m.buffer = QByteArray("\x01\x02", 2); m.received_count = 1;
    return ser(r) + ser(m);
}

/// 把图样前 back 字节处的计数(须等于 expect)改为 n;图样须唯一
static bool patch_count(QByteArray& b, const QByteArray& pattern, int back, quint32 expect, quint32 n) {
    const int pos = int(b.indexOf(pattern));
    if (pos < back || b.lastIndexOf(pattern) != pos) return false;
    if (b.mid(pos - back, 4) != be32(expect)) return false;
    b.replace(pos - back, 4, be32(n));
    return true;
}
static QByteArray pat(std::initializer_list<int> v) {
    QByteArray b; for (int x : v) b.append(char(x)); return b;
}

/// 字段树深链:levels 层,每层 name/value 为 null 串、1 个子节点(末层 0 个),20 字节/层
static QByteArray deep_msdu_chain(int levels) {
    QByteArray b;
    b.reserve(levels * 20);
    for (int i = 0; i < levels; ++i)
        b += be32(0xFFFFFFFF) + be32(0xFFFFFFFF) + be32(i + 1 < levels ? 1 : 0);
    for (int i = 0; i < levels; ++i) b += be32(0) + be32(0);   // rel_start / rel_len
    return b;
}
/// DissectField 深链:name/value null、start/len/severity、子节点计数,21 字节/层
static QByteArray deep_dissect_chain(int levels) {
    QByteArray b;
    b.reserve(levels * 21);
    for (int i = 0; i < levels; ++i)
        b += be32(0xFFFFFFFF) + be32(0xFFFFFFFF) + be32(0) + be32(0) + QByteArray(1, 0) +
             be32(i + 1 < levels ? 1 : 0);
    return b;
}

/// 把 msdu.tree 第一个元素(@@TREE@@,无子节点)所在的整个向量替换为 crafted(含计数)
static bool splice_msdu_tree(QByteArray& b, const QByteArray& crafted) {
    const QByteArray mk = str_body(QStringLiteral("@@TREE@@"));
    const int pos = int(b.indexOf(mk));
    if (pos < 8 || b.mid(pos - 8, 4) != be32(2)) return false;   // 向量计数 = 2(@@TREE@@ + @@PARENT@@)
    // 向量结束:@@PARENT@@ 节点之后(@@CHILD@@ 的 rel_len 之后再跟 parent 的 rel_start/rel_len)
    const QByteArray ck = str_body(QStringLiteral("@@CHILD@@"));
    const int cpos = int(b.indexOf(ck));
    if (cpos < 0) return false;
    // child: name | value("c") | children(0) | rel_start | rel_len,然后 parent 的 rel_start | rel_len
    const int child_val = cpos + ck.size();
    const int end = child_val + 4 + int(str_body(QStringLiteral("c")).size()) + 4 + 4 + 4 + 4 + 4;
    b.replace(pos - 8, end - (pos - 8), crafted);
    return true;
}
/// 把 dissect_fields 整个向量(在 ParseResult 末尾)替换为 crafted(含计数)
static bool splice_dissect(QByteArray& b, const QByteArray& crafted, int msdu_state_bytes) {
    const QByteArray mk = str_body(QStringLiteral("@@DIS@@"));
    const int pos = int(b.indexOf(mk));
    if (pos < 8 || b.mid(pos - 8, 4) != be32(2)) return false;
    const int end = b.size() - msdu_state_bytes;   // dissect_fields 是 ParseResult 的最后一个字段
    b.replace(pos - 8, end - (pos - 8), crafted);
    return true;
}

// ---------------------------------------------------------------- 子进程解码
enum : int { kRejected = 10, kAccepted = 11, kBadAlloc = 12, kMismatch = 13 };

static bool same_tree(const QVector<MsduFieldNode>& a, const QVector<MsduFieldNode>& b) {
    if (a.size() != b.size()) return false;
    for (int i = 0; i < a.size(); ++i)
        if (a[i].name != b[i].name || a[i].value != b[i].value || a[i].rel_start != b[i].rel_start ||
            a[i].rel_len != b[i].rel_len || !same_tree(a[i].children, b[i].children))
            return false;
    return true;
}
static bool same_dissect(const QVector<DissectField>& a, const QVector<DissectField>& b) {
    if (a.size() != b.size()) return false;
    for (int i = 0; i < a.size(); ++i)
        if (a[i].name != b[i].name || a[i].value != b[i].value || a[i].start != b[i].start ||
            a[i].len != b[i].len || a[i].severity != b[i].severity ||
            !same_dissect(a[i].children, b[i].children))
            return false;
    return true;
}
static bool same_result(const ParseResult& a, const ParseResult& b) {
    const TopoEvent& x = a.msdu.topo_event; const TopoEvent& y = b.msdu.topo_event;
    auto cr_eq = [](const QVector<CommRateInfo>& p, const QVector<CommRateInfo>& q) {
        if (p.size() != q.size()) return false;
        for (int i = 0; i < p.size(); ++i)
            if (p[i].tei != q[i].tei || p[i].down != q[i].down || p[i].up != q[i].up) return false;
        return true;
    };
    auto tm_eq = [](const QVector<TeiMacPair>& p, const QVector<TeiMacPair>& q) {
        if (p.size() != q.size()) return false;
        for (int i = 0; i < p.size(); ++i) if (p[i].tei != q[i].tei || p[i].mac != q[i].mac) return false;
        return true;
    };
    return a.meta.timestamp == b.meta.timestamp && a.mpdu.pb_heads == b.mpdu.pb_heads &&
           a.mpdu.pb_crc_oks == b.mpdu.pb_crc_oks && a.msdu_body == b.msdu_body &&
           a.msdu.summary == b.msdu.summary && same_tree(a.msdu.tree, b.msdu.tree) &&
           same_tree(a.beacon.tree, b.beacon.tree) && tm_eq(a.msdu.tei_mac_pairs, b.msdu.tei_mac_pairs) &&
           tm_eq(x.nodes, y.nodes) && x.routes == y.routes && x.up_routes == y.up_routes &&
           x.neighbor_teis == y.neighbor_teis && x.leaves == y.leaves && cr_eq(x.comm_rates, y.comm_rates) &&
           x.desc == y.desc && a.reject_reason == b.reject_reason && a.accept == b.accept &&
           same_dissect(a.dissect_fields, b.dissect_fields);
}

/// 子进程体:解码 payload;expect 非空时还要逐字段相等
static int decode_body(const QByteArray& payload, const ParseResult* expect) {
    try {
        QDataStream ds(payload);
        ds.setVersion(plugin_ipc::kStreamVersion);
        ParseResult r; MsduState m;
        ds >> r >> m;
        if (ds.status() != QDataStream::Ok) return kRejected;
        if (expect && !same_result(r, *expect)) return kMismatch;
        return kAccepted;
    } catch (const std::bad_alloc&) {
        return kBadAlloc;
    }
}

/// fork 子进程跑 fn,返回 "rejected"/"accepted"/"bad_alloc"/"crashed: signal N"/...
static QByteArray run_forked(const std::function<int()>& fn) {
#ifdef Q_OS_UNIX
    std::fflush(stdout);
    const pid_t p = fork();
    if (p == 0) {
#ifndef PROBE_ASAN
        // 1 GiB 地址空间:旧代码 reserve(4 GiB / 数百 GiB) 必然失败 ⇒ bad_alloc 可观测
        struct rlimit rl;
        rl.rlim_cur = rl.rlim_max = rlim_t(1) << 30;
        setrlimit(RLIMIT_AS, &rl);
#endif
        _exit(fn());
    }
    int st = 0;
    waitpid(p, &st, 0);
    if (WIFSIGNALED(st)) return "crashed: signal " + QByteArray::number(WTERMSIG(st));
    const int c = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    switch (c) {
    case kRejected: return "rejected";
    case kAccepted: return "accepted";
    case kBadAlloc: return "bad_alloc";
    case kMismatch: return "accepted-but-mismatch";
    default: return "abnormal exit " + QByteArray::number(c);
    }
#else
    const int c = fn();
    return c == kRejected ? "rejected" : c == kAccepted ? "accepted" : c == kBadAlloc ? "bad_alloc" : "mismatch";
#endif
}

static constexpr qint64 kPayloadMax = plugin_ipc::kMaxIpcFrame - 1 - 8 - 1;   // 减 type/seq/ok

static void expect_rejected(const QByteArray& name, const QByteArray& payload) {
    if (payload.size() > kPayloadMax) { check(name, false, "payload exceeds 1 MiB frame"); return; }
    const QByteArray how = run_forked([&] { return decode_body(payload, nullptr); });
    check(name, how == "rejected", how);
}
static void expect_accepted(const QByteArray& name, const QByteArray& payload, const ParseResult& r) {
    const QByteArray how = run_forked([&] { return decode_body(payload, &r); });
    check(name, how == "accepted", how);
}

static void unit_cases() {
    std::printf("== unit: plugin_serialization decode (forked children) ==\n");
    const ParseResult base = base_result();
    const QByteArray good = payload_of(base);
    MsduState ms; ms.buffer = QByteArray("\x01\x02", 2); ms.received_count = 1;
    const int msdu_state_bytes = int(ser(ms).size());
    expect_accepted("roundtrip: full ParseResult (all containers) decodes equal", good, base);

    // 64 层为界(与 pser::kMaxFieldDepth 同语义),65 层拒绝
    auto chain = [](int levels) {
        MsduFieldNode root = node(QStringLiteral("L0"));
        MsduFieldNode* cur = &root;
        for (int i = 1; i < levels; ++i) { cur->children << node(QStringLiteral("L%1").arg(i)); cur = &cur->children.last(); }
        return root;
    };
    {
        ParseResult r = base; r.msdu.tree = {chain(64)};
        expect_accepted("depth: 64-level MsduFieldNode tree accepted", payload_of(r), r);
        r.msdu.tree = {chain(65)};
        expect_rejected("depth: 65-level MsduFieldNode tree rejected", payload_of(r));
        ParseResult d = base;
        DissectField root(QStringLiteral("D0"), QString());
        DissectField* cur = &root;
        for (int i = 1; i < 65; ++i) { cur->children << DissectField(QStringLiteral("D%1").arg(i), QString()); cur = &cur->children.last(); }
        d.dissect_fields = {root};
        expect_rejected("depth: 65-level DissectField tree rejected", payload_of(d));
    }
    // 节点总数 10000 为界
    {
        ParseResult r = base; r.msdu.tree.clear();
        for (int i = 0; i < 10000; ++i) r.msdu.tree << node(QString(), QString());
        expect_accepted("nodes: 10000 MsduFieldNode accepted", payload_of(r), r);
        r.msdu.tree << node(QString(), QString());
        expect_rejected("nodes: 10001 MsduFieldNode rejected", payload_of(r));
        ParseResult d = base; d.dissect_fields.clear();
        DissectField big(QStringLiteral("root"), QString());
        for (int i = 0; i < 10000; ++i) big.children << DissectField(QString(), QString());
        d.dissect_fields << big;   // 1 + 10000 节点
        expect_rejected("nodes: 10001 DissectField (nested) rejected", payload_of(d));
    }
    // 1 MiB 帧内的极深嵌套(修复前递归无上限 ⇒ 栈溢出)
    {
        QByteArray b = good;
        const int levels = int((kPayloadMax - good.size()) / 20) - 16;
        const bool ok = splice_msdu_tree(b, be32(1) + deep_msdu_chain(levels));
        check("craft: deep MsduFieldNode chain spliced", ok);
        expect_rejected("deep: " + QByteArray::number(levels) + "-level MsduFieldNode chain in 1 MiB rejected", b);
        QByteArray d = good;
        const int dl = int((kPayloadMax - good.size()) / 21) - 16;
        check("craft: deep DissectField chain spliced",
              splice_dissect(d, be32(1) + deep_dissect_chain(dl), msdu_state_bytes));
        expect_rejected("deep: " + QByteArray::number(dl) + "-level DissectField chain in 1 MiB rejected", d);
    }
    // 各容器计数改成 0xFFFFFFFD(Qt_6_5 布局下的最大合法计数值):修复前 reserve 巨额 ⇒ bad_alloc
    struct Cnt { const char* what; QByteArray pattern; int back; quint32 expect; };
    const Cnt cnts[] = {
        {"mpdu.pb_heads", pat({0xA1, 0xB2, 0xC3, 0xD4, 0xE5}), 4, 5},
        {"mpdu.pb_crc_oks", pat({1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1}), 4, 11},
        {"msdu.tree", str_body(QStringLiteral("@@TREE@@")), 8, 2},
        {"msdu.tree[].children", str_body(QStringLiteral("@@CHILD@@")), 8, 1},
        {"msdu.tei_mac_pairs", pat({0x0A, 0xBC, 1, 2, 3, 4, 5, 6, 7, 8}), 4, 1},
        {"topo_event.nodes", pat({0x0D, 0xEF, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}), 4, 1},
        {"topo_event.routes", pat({0x7A, 1, 0x7A, 2, 0x7A, 3, 0x7A, 4}), 4, 2},
        {"topo_event.up_routes", pat({0x7B, 1, 0x7B, 2}), 4, 1},
        {"topo_event.neighbor_teis", pat({0x6C, 1, 0x6C, 2, 0x6C, 3}), 4, 3},
        {"topo_event.leaves", pat({0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28}), 4, 1},
        {"topo_event.comm_rates", pat({0x5E, 1, 0x33, 0x44}), 4, 1},
        {"dissect_fields", str_body(QStringLiteral("@@DIS@@")), 8, 2},
        {"dissect_fields[].children", str_body(QStringLiteral("@@DCHILD@@")), 8, 1},
    };
    for (const Cnt& c : cnts) {
        for (quint32 n : {0xFFFFFFFDu, 0x00100000u}) {
            QByteArray b = good;
            const bool ok = patch_count(b, c.pattern, c.back, c.expect, n);
            const QByteArray nm = QByteArray("count: ") + c.what + " = 0x" + QByteArray::number(n, 16);
            if (!ok) { check(nm + " (craft)", false, "pattern/count not found"); continue; }
            expect_rejected(nm + " rejected", b);
        }
    }
    // ParseFilter(host 侧解码主程序请求)同样受限
    {
        ParseFilter f; f.nid_list = {0xCAFEBABEu}; f.tei_list = {0x4D4D};
        QByteArray b = ser(f);
        const bool ok = patch_count(b, pat({0xCA, 0xFE, 0xBA, 0xBE}), 4, 1, 0xFFFFFFFDu);
        check("craft: ParseFilter.nid_list count", ok);
        const QByteArray how = run_forked([&] {
            try {
                QDataStream ds(b); ds.setVersion(plugin_ipc::kStreamVersion);
                ParseFilter g; ds >> g;
                return ds.status() != QDataStream::Ok && g.nid_list.isEmpty() ? int(kRejected) : int(kAccepted);
            } catch (const std::bad_alloc&) { return int(kBadAlloc); }
        });
        check("count: ParseFilter.nid_list = 0xfffffffd rejected", how == "rejected", how);
    }
    // 截断:任意位置截断都不得被接受
    {
        int accepted = 0, tried = 0;
        QByteArray how_all;
        for (int cut = 1; cut < good.size(); cut += qMax(1, good.size() / 40)) {
            ++tried;
            const QByteArray how = run_forked([&] { return decode_body(good.left(cut), nullptr); });
            if (how != "rejected") { ++accepted; how_all += " cut=" + QByteArray::number(cut) + ":" + how; }
        }
        check("truncation: " + QByteArray::number(tried) + " truncated payloads all rejected", accepted == 0, how_all);
    }
}

// ---------------------------------------------------------------- 恶意宿主
/// 本程序以 bplc-plugin-host 身份运行:握手后对每个 ParseRequest 原样回 <plugin>/response.bin
static int fake_host_main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    const QStringList a = QCoreApplication::arguments();
    const int si = a.indexOf(QStringLiteral("--socket")), pi = a.indexOf(QStringLiteral("--plugin"));
    if (si < 0 || pi < 0 || si + 1 >= a.size() || pi + 1 >= a.size()) return 2;
    const QString dir = a.at(pi + 1);
    QFile mf(dir + QStringLiteral("/plugin.json")), rf(dir + QStringLiteral("/response.bin"));
    if (!mf.open(QIODevice::ReadOnly) || !rf.open(QIODevice::ReadOnly)) return 2;
    const QJsonObject m = QJsonDocument::fromJson(mf.readAll()).object();
    const QByteArray response = rf.readAll();
    QLocalSocket s;
    QByteArray rx;
    auto send = [&](plugin_ipc::MsgType t, const QByteArray& p) {
        QByteArray f;
        QDataStream o(&f, QIODevice::WriteOnly);
        o.setVersion(plugin_ipc::kStreamVersion);
        o << quint32(1 + p.size()) << quint8(t);
        s.write(f + p);
        s.flush();
    };
    QObject::connect(&s, &QLocalSocket::disconnected, &app, &QCoreApplication::quit);
    QObject::connect(&s, &QLocalSocket::readyRead, [&]() {
        rx.append(s.readAll());
        for (;;) {
            QByteArray fr;
            const auto t = plugin_ipc::try_take_frame(rx, fr);
            if (t != plugin_ipc::FrameTake::Ok) { if (t == plugin_ipc::FrameTake::Bad) app.exit(3); return; }
            QDataStream ds(fr);
            ds.setVersion(plugin_ipc::kStreamVersion);
            quint8 type = 0; quint64 seq = 0;
            ds >> type;
            const auto mt = plugin_ipc::MsgType(type);
            if (mt == plugin_ipc::MsgType::ParseRequest || mt == plugin_ipc::MsgType::Ping) {
                ds >> seq;
                QByteArray p;
                QDataStream o(&p, QIODevice::WriteOnly);
                o.setVersion(plugin_ipc::kStreamVersion);
                o << seq;
                if (mt == plugin_ipc::MsgType::Ping) { send(plugin_ipc::MsgType::Pong, p); continue; }
                o << true;
                send(plugin_ipc::MsgType::ParseResponse, p + response);
            } else if (mt == plugin_ipc::MsgType::Shutdown) {
                app.quit();
            }
        }
    });
    s.connectToServer(a.at(si + 1));
    if (!s.waitForConnected(10000)) return 2;
    QByteArray hello;
    QDataStream o(&hello, QIODevice::WriteOnly);
    o.setVersion(plugin_ipc::kStreamVersion);
    o << plugin_ipc::kApiVersion << m.value(QStringLiteral("name")).toString()
      << m.value(QStringLiteral("protocol_id")).toString() << plugin_ipc::kWireFormatVersion;
    send(plugin_ipc::MsgType::Hello, hello);
    return app.exec();
}

static void spin_until(const std::function<bool()>& cond, int timeout_ms) {
    QElapsedTimer t;
    t.start();
    while (!cond() && t.elapsed() < timeout_ms) {
        QEventLoop loop;
        QTimer::singleShot(20, &loop, &QEventLoop::quit);
        loop.exec();
    }
}

static bool make_plugin(const QString& root, const QString& tag, const QByteArray& response) {
    const QString d = root + QLatin1Char('/') + tag;
    QDir().mkpath(d);
    QJsonObject m;
    m.insert(QStringLiteral("api_version"), 1);
    m.insert(QStringLiteral("name"), QStringLiteral("atk-") + tag);
    m.insert(QStringLiteral("protocol_id"), QStringLiteral("ATK_") + tag.toUpper());
    m.insert(QStringLiteral("display_name"), tag);
    m.insert(QStringLiteral("display_name_en"), tag);
    m.insert(QStringLiteral("entry"), QStringLiteral("parser.lua"));
    m.insert(QStringLiteral("runtime"), QStringLiteral("lua"));
    m.insert(QStringLiteral("version"), QStringLiteral("1.0.0"));
    QFile mf(d + QStringLiteral("/plugin.json")), lf(d + QStringLiteral("/parser.lua")),
        rf(d + QStringLiteral("/response.bin"));
    return mf.open(QIODevice::WriteOnly) && mf.write(QJsonDocument(m).toJson()) > 0 &&
           lf.open(QIODevice::WriteOnly) && lf.write("-- served by ipc_decode_probe fake host\n") > 0 &&
           rf.open(QIODevice::WriteOnly) && rf.write(response) == response.size();
}

/// worker 线程调一次 parse_via_plugin
static bool parse_once(const QString& pid, ParseResult* out, qint64* ms) {
    std::atomic<bool> ok{false};
    QElapsedTimer t;
    t.start();
    QThread* th = QThread::create([&]() {
        BplcFrame f;
        f.data = QByteArray::fromHex("3c000102");
        MsduState msdu;
        ParseFilter filt{};
        ok = PluginManager::instance().parse_via_plugin(pid, f, msdu, filt, out);
    });
    th->start();
    spin_until([&] { return th->isFinished(); }, 15000);
    th->wait();
    delete th;
    *ms = t.elapsed();
    return ok;
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i)
        if (qstrcmp(argv[i], "--socket") == 0) return fake_host_main(argc, argv);

    unit_cases();   // fork 在创建任何线程之前

    QApplication app(argc, argv);
    std::printf("== e2e: PluginManager vs malicious host ==\n");
    const QString host = QCoreApplication::applicationDirPath() + QStringLiteral("/bplc-plugin-host");
    QFile::remove(host);
    check("fake host installed as bplc-plugin-host", QFile::copy(QCoreApplication::applicationFilePath(), host));
    QFile(host).setPermissions(QFile(host).permissions() | QFileDevice::ExeOwner);

    QTemporaryDir tmp;
    const QString plugins = tmp.path() + QStringLiteral("/plugins");
    const ParseResult base = base_result();
    const QByteArray good = payload_of(base);
    QByteArray huge = good;
    patch_count(huge, str_body(QStringLiteral("@@DIS@@")), 8, 2, 0xFFFFFFFDu);
    QByteArray deep = good;
    splice_msdu_tree(deep, be32(1) + deep_msdu_chain(int((kPayloadMax - good.size()) / 20) - 16));
    ParseResult many = base;
    many.msdu.tree.clear();
    for (int i = 0; i < 10001; ++i) many.msdu.tree << node(QString(), QString());
    QByteArray trunc = good.left(good.size() / 2);
    struct Case { const char* tag; QByteArray resp; bool expect_ok; };
    const Case cases[] = {
        {"good", good, true},
        {"hugecount", huge, false},
        {"deep", deep, false},
        {"manynodes", payload_of(many), false},
        {"truncated", trunc, false},
    };
    bool made = true;
    for (const Case& c : cases) made = make_plugin(plugins, QString::fromLatin1(c.tag), c.resp) && made;
    check("plugin dirs written", made);

    QHash<QString, QStringList> status;
    QObject::connect(&PluginManager::instance(), &PluginManager::plugin_status_changed,
                     [&](const QString& id, const QString& st) { status[id] << st; });
    auto& pm = PluginManager::instance();
    pm.load_all(plugins);
    auto pid_of = [](const char* tag) { return QStringLiteral("ATK_") + QString::fromLatin1(tag).toUpper(); };
    spin_until([&] {
        for (const Case& c : cases) if (!pm.is_plugin_protocol(pid_of(c.tag))) return false;
        return true;
    }, 15000);
    bool all_ready = true;
    for (const Case& c : cases) all_ready = all_ready && pm.is_plugin_protocol(pid_of(c.tag));
    check("all fake-host plugins handshaked (ready)", all_ready);

    for (const Case& c : cases) {
        const QString pid = pid_of(c.tag);
        ParseResult r;
        qint64 ms_used = 0;
        const bool ok = parse_once(pid, &r, &ms_used);
        spin_until([&] { return c.expect_ok || !status.value(pid).isEmpty(); }, 3000);
        const QByteArray tag(c.tag);
        if (c.expect_ok) {
            check("e2e " + tag + ": parse ok, result intact, plugin still enabled",
                  ok && same_result(r, base) && pm.is_plugin_protocol(pid),
                  "ok=" + QByteArray::number(ok) + " " + QByteArray::number(ms_used) + " ms");
        } else {
            const QString st = status.value(pid).join(QStringLiteral(" | "));
            check("e2e " + tag + ": parse refused, no half tree, plugin disabled (protocol error)",
                  !ok && r.msdu.tree.isEmpty() && r.dissect_fields.isEmpty() && !pm.is_plugin_protocol(pid) &&
                      st.contains(QStringLiteral("protocol-error-disabled")) && ms_used < 3000,
                  QByteArray::number(ms_used) + " ms, status: " + st.toUtf8());
        }
    }
    check("e2e: good plugin unaffected by others' corrupt responses", pm.is_plugin_protocol(pid_of("good")));

    pm.stop_all();
    QTimer::singleShot(0, &app, &QCoreApplication::quit);
    app.exec();
    QFile::remove(host);
    std::printf("\nRESULT: %s (%d failures)\n", g_fails ? "FAILURES" : "ALL PASS", g_fails);
    return g_fails ? 1 : 0;
}
