/// @file serialize_bounds_probe.cpp
/// @brief L8 回归探针:packetentry_serialize.h 读到损坏数据时
///        - 计数字段超过剩余字节 → 流标记 ReadCorruptData,不 reserve 巨量内存
///        - 字段树嵌套 > 64 层 → 停止递归(20 万层也不栈溢出)
///        - 截断 / 随机变异的条目载荷 → deserialize_entry 返回 false 或正常结束,不崩
///        - 损坏块(字符串池计数超出池字节)→ BlockReader 拒收
#include <QBuffer>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QRandomGenerator>
#include <cstdio>

#include "packetentry_serialize.h"

#ifdef Q_OS_UNIX
#include <sys/resource.h>
#endif

static int g_fails = 0;
static void check(const char* name, bool ok) {
    std::printf("%-64s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) ++g_fails;
}

static PacketEntry sample_entry(int i) {
    PacketEntry e;
    e.index = i;
    e.epoch_ms = 1700000000000LL + i;
    e.accepted = true;
    e.reason = QStringLiteral("ok");
    e.raw_wire = QByteArray(32, char(i));
    e.mpdu.frame_type = 1;
    e.mpdu.pb_heads = {1, 2, 3};
    e.mpdu.pb_crc_oks = {true, false, true};
    e.msdu.present = true;
    e.msdu.summary = QStringLiteral("summary %1").arg(i);
    MsduFieldNode root;
    root.name = QStringLiteral("root");
    root.value = QStringLiteral("v");
    for (int c = 0; c < 4; ++c) {
        MsduFieldNode ch;
        ch.name = QStringLiteral("child%1").arg(c);
        ch.value = QStringLiteral("%1").arg(c);
        root.children.append(ch);
    }
    e.msdu.tree.append(root);
    e.msdu.topo_event.nodes.append({quint16(2), 0x112233445566ULL});
    e.msdu.orig_srcs.append({quint16(3), 0x665544332211ULL});
    return e;
}

static void test_counts() {
    const QVector<QString> table{QStringLiteral("x")};
    {   // 字段节点:children 计数 0xFFFFFFFF
        QByteArray buf;
        QDataStream w(&buf, QIODevice::WriteOnly);
        w << quint32(0) << quint32(0) << qint32(0) << qint32(1) << quint32(0xFFFFFFFFu);
        QDataStream r(buf);
        MsduFieldNode n;
        pser::read_field_node(r, n, table);
        check("field node: child count 0xFFFFFFFF -> corrupt, no children",
              r.status() == QDataStream::ReadCorruptData && n.children.isEmpty());
    }
    {   // 拓扑事件:nodes 计数 0x7FFFFFFF
        QByteArray buf;
        QDataStream w(&buf, QIODevice::WriteOnly);
        w << quint8(0) << quint32(1) << quint64(0) << quint32(0x7FFFFFFFu);
        buf.append(QByteArray(64, '\0'));
        QDataStream r(buf);
        TopoEvent t;
        pser::read_topo_event(r, t, table);
        check("topo event: nodes count 0x7FFFFFFF -> corrupt, nodes empty",
              r.status() == QDataStream::ReadCorruptData && t.nodes.isEmpty()
                  && t.nodes.capacity() < 1024);
    }
    {   // MPDU:pb_heads 计数(前缀 27 字节后)改成 0xFFFFFFF0
        QByteArray buf;
        QDataStream w(&buf, QIODevice::WriteOnly);
        MpduInfo m;
        m.pb_heads = {7, 8};
        pser::write_mpdu(w, m);
        QByteArray bad = buf;
        QDataStream patch(&bad, QIODevice::ReadWrite);
        patch.device()->seek(27);
        patch << quint32(0xFFFFFFF0u);
        QDataStream ok_r(buf);
        MpduInfo m_ok;
        pser::read_mpdu(ok_r, m_ok);
        check("mpdu: intact stream round-trips (offset sanity)",
              ok_r.status() == QDataStream::Ok && m_ok.pb_heads == m.pb_heads);
        QDataStream r(bad);
        MpduInfo m2;
        pser::read_mpdu(r, m2);
        check("mpdu: pb_heads count 0xFFFFFFF0 -> corrupt, empty",
              r.status() == QDataStream::ReadCorruptData && m2.pb_heads.isEmpty()
                  && m2.pb_heads.capacity() < 1024);
    }
}

static void test_depth() {
    const QVector<QString> table{QStringLiteral("x")};
    auto nested = [](int levels) {
        QByteArray buf;
        QDataStream w(&buf, QIODevice::WriteOnly);
        for (int i = 0; i < levels; ++i)
            w << quint32(0) << quint32(0) << qint32(0) << qint32(1)
              << quint32(i + 1 < levels ? 1 : 0);
        return buf;
    };
    {
        QDataStream r(nested(64));
        MsduFieldNode n;
        pser::read_field_node(r, n, table);
        int depth = 1;
        for (const MsduFieldNode* p = &n; !p->children.isEmpty(); p = &p->children[0]) ++depth;
        check("field tree: 64 levels accepted", r.status() == QDataStream::Ok && depth == 64);
    }
    {
        QDataStream r(nested(65));
        MsduFieldNode n;
        pser::read_field_node(r, n, table);
        check("field tree: 65 levels -> corrupt", r.status() == QDataStream::ReadCorruptData);
    }
    {
        QDataStream r(nested(200000));
        MsduFieldNode n;
        pser::read_field_node(r, n, table);
        check("field tree: 200000 levels -> corrupt, no stack overflow",
              r.status() == QDataStream::ReadCorruptData);
    }
}

static void test_entries() {
    pser::StrPool pool;
    const PacketEntry e = sample_entry(5);
    const QByteArray good = pser::serialize_entry(e, pool);
    PacketEntry d;
    check("entry: intact payload round-trips",
          pser::deserialize_entry(good, d, pool.list) && d.msdu.tree.size() == 1
              && d.msdu.tree[0].children.size() == 4);
    int trunc_ok = 0;
    for (int len = 0; len < good.size(); ++len) {
        PacketEntry t;
        if (!pser::deserialize_entry(good.left(len), t, pool.list)) ++trunc_ok;
    }
    check("entry: every truncation rejected", trunc_ok == good.size());

    // 随机变异:覆盖 4 字节为大数/随机值,读完不崩、用时有界
    QRandomGenerator rng(20261111);
    QElapsedTimer timer;
    timer.start();
    int rejected = 0;
    const int kIters = 20000;
    for (int it = 0; it < kIters; ++it) {
        QByteArray b = good;
        const int pos = int(rng.bounded(b.size() - 4));
        const quint32 v = (it % 3 == 0) ? 0xFFFFFFF0u
                         : (it % 3 == 1) ? 0x10000000u : rng.generate();
        b[pos] = char(v >> 24); b[pos + 1] = char(v >> 16);
        b[pos + 2] = char(v >> 8); b[pos + 3] = char(v);
        PacketEntry t;
        if (!pser::deserialize_entry(b, t, pool.list)) ++rejected;
    }
    std::printf("  mutations: %d/%d rejected in %lld ms\n", rejected, kIters,
                timer.elapsed());
    check("entry: 20000 mutated payloads decode without crash/huge alloc",
          rejected > 0 && timer.elapsed() < 60000);
}

static void test_block() {
    QVector<PacketEntry> entries;
    for (int i = 0; i < 120; ++i) entries.append(sample_entry(i));
    const QByteArray blk = pser::encode_block(entries);
    pser::BlockReader rd;
    check("block: intact block opens", rd.open_data(blk) && rd.count() == 120);
    QVector<PacketEntry> back;
    check("block: read_all", rd.read_all(back) && back.size() == 120);

    // 未压缩池:构造 str_count 远大于池字节的块头
    QByteArray bad;
    QDataStream w(&bad, QIODevice::WriteOnly);
    QByteArray pool_raw;
    QDataStream pw(&pool_raw, QIODevice::WriteOnly);
    pw << quint32(900000);   // 声称 90 万个字符串,池只有 4 字节
    w << pser::block_magic() << pser::block_version() << quint32(1) << quint8(0)
      << pool_raw << QByteArray() << QByteArray();
    pser::BlockReader rd2;
    check("block: string-pool count larger than pool rejected", !rd2.open_data(bad));
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    // 地址空间上限 2 GB:修复前损坏计数会 reserve 数 GB,这里直接 bad_alloc 崩溃
#ifdef Q_OS_UNIX
    struct rlimit rl{2048ull << 20, 2048ull << 20};
    setrlimit(RLIMIT_AS, &rl);
#endif
    test_counts();
    test_depth();
    test_entries();
    test_block();
    std::printf("\nRESULT: %s (%d failures)\n", g_fails ? "FAILURES" : "ALL PASS", g_fails);
    return g_fails ? 1 : 0;
}
