// 基准:AUTO FIT(自动列宽)点击时主线程的实际代价
// 复现 QTableView::resizeColumnsToContents() 的访问模式:
//   列主序,每列扫 resizeContentsPrecision(默认 1000) 行
//   → 每次 data() 调 locate() → entry_at() 解码整条 PacketEntry(含 MpduInfo::tree)
// 输出:每次解码的 µs、总耗时、以及字段树占多少。

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QDebug>
#include <QVector>

#include "bplcframe.h"
#include "packetentry_serialize.h"

static PacketEntry make_entry(int idx, int tree_nodes) {
    PacketEntry e;
    e.index      = idx + 1;
    e.accepted   = true;
    e.epoch_ms   = 1700000000000LL + idx;
    e.delta_us   = 1250;
    e.protocol   = kProtocolGw2026;

    e.raw_wire  = QByteArray(150, '\x5A');   // 串口原始帧(含 0x3C/0x3E + 转义)
    e.raw_bytes = QByteArray(120, '\xA5');   // HexView 净荷
    e.msdu_body = QByteArray(48,  '\x11');

    e.mpdu.frame_type = 1;
    e.mpdu.net_id     = 0x0F0F12;
    e.mpdu.src_tei    = quint16(3 + idx % 40);
    e.mpdu.dst_tei    = 1;
    e.mpdu.pb_num     = 3;
    e.mpdu.sof_band   = 7;
    e.msdu.present    = true;
    e.msdu.summary    = QStringLiteral("MMe.AssocReq");

    e.search_text = QStringLiteral("sof sta-%1 0x0f0f12 mme assocreq")
                        .arg(idx % 40);

    // 字段树:与实测一致的自由度(gw_2026 渲染 61~132 节点)
    e.msdu.tree.reserve(tree_nodes);
    for (int i = 0; i < tree_nodes; ++i) {
        MsduFieldNode n;
        n.name  = QStringLiteral("Field %1 [%2bit]").arg(i).arg(8 + i % 5);
        n.value = QStringLiteral("0x%1").arg(i, 4, 16, QChar('0'));
        n.rel_start = i;
        n.rel_len   = 1;
        if (i % 10 == 0) {                    // 分组节点带 2 个子节点
            for (int k = 0; k < 2; ++k) {
                MsduFieldNode c;
                c.name  = QStringLiteral("sub %1").arg(k);
                c.value = QStringLiteral("%1").arg(k * 17 + i);
                c.rel_start = i; c.rel_len = 1;
                n.children.append(c);
            }
        }
        e.msdu.tree.append(n);
    }
    return e;
}

static void bench(int tree_nodes, int ncols, int nrows) {
    QVector<PacketEntry> entries;
    entries.reserve(1000);
    for (int i = 0; i < 1000; ++i) entries.append(make_entry(i, tree_nodes));

    QElapsedTimer tw; tw.start();
    const QByteArray blob = pser::encode_block(entries);
    const qint64 encode_ms = tw.elapsed();

    pser::BlockReader r;
    if (!r.open_data(blob)) { qDebug() << "!! open_data failed"; return; }
    if (r.count() != 1000)  { qDebug() << "!! count" << r.count(); return; }

    PacketEntry out;
    QElapsedTimer t; t.start();
    int calls = 0;
    for (int col = 0; col < ncols; ++col)          // 列主序,与 QHeaderView 一致
        for (int row = 0; row < nrows; ++row) {    // 每列都从第 0 行重扫
            r.entry_at(row, out);
            ++calls;
        }
    const qint64 ms = t.elapsed();

    qDebug().noquote()
        << QStringLiteral("[tree=%1 节点] 块大小 %2 KB,编码 %3 ms | "
                          "解码 %4 次(%5 列 × %6 行) = %7 ms, %8 µs/次 | 解出树节点 %9 个")
               .arg(tree_nodes)
               .arg(blob.size() / 1024)
               .arg(encode_ms)
               .arg(calls).arg(ncols).arg(nrows).arg(ms)
               .arg(QString::number(calls > 0 ? double(ms) * 1000.0 / calls : 0.0, 'f', 1))
               .arg(QString::number(qint64(calls) * tree_nodes));
}

// 换页块 v10 往返校验:布局删除 3 个死字段后,字段位置必须仍然对齐
static bool roundtrip_check() {
    QVector<PacketEntry> v;
    for (int i = 0; i < 120; ++i) {   // 120 条 > kBlockChunkEntries(50) → 跨 3 个压缩分块
        PacketEntry e = make_entry(i, 5);
        e.mpdu.frame_type     = quint8(i % 4);
        e.mpdu.net_id         = quint32(0x0F0F00 + i);
        e.mpdu.tmi            = quint8(i & 0x0F);
        e.mpdu.pb_size        = quint16(70 + i);
        e.mpdu.ack_rx_status  = quint8(i & 0x0F);
        e.mpdu.beacon_cco_mac = 0xAABBCCDD0000ULL + quint64(i);
        e.mpdu.coord_rsv1     = quint16((i * 7) & 0x3FF);   // v10 补写字段
        e.mpdu.coord_rsv2     = quint8(i & 0x01);
        e.mpdu.coord_rsv3     = quint8(i & 0x0F);
        v.append(e);
    }
    const QByteArray blob = pser::encode_block(v);
    pser::BlockReader r;
    if (!r.open_data(blob)) { qDebug() << "roundtrip: open_data FAILED"; return false; }
    PacketEntry out;
    for (int i = 0; i < 120; ++i) {
        if (!r.entry_at(i, out)) { qDebug() << "roundtrip: entry_at" << i << "FAILED"; return false; }
        const PacketEntry& s = v.at(i);
        if (out.index != s.index || out.mpdu.frame_type != s.mpdu.frame_type
            || out.mpdu.net_id != s.mpdu.net_id || out.mpdu.tmi != s.mpdu.tmi
            || out.mpdu.pb_size != s.mpdu.pb_size
            || out.mpdu.ack_rx_status != s.mpdu.ack_rx_status
            || out.mpdu.beacon_cco_mac != s.mpdu.beacon_cco_mac
            || out.mpdu.coord_rsv1 != s.mpdu.coord_rsv1
            || out.mpdu.coord_rsv2 != s.mpdu.coord_rsv2
            || out.mpdu.coord_rsv3 != s.mpdu.coord_rsv3
            || out.raw_bytes != s.raw_bytes) {
            qDebug() << "roundtrip: mismatch at" << i;
            return false;
        }
    }
    return true;
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    qDebug().noquote() << "=== AUTO FIT 代价基准(resizeContentsPrecision 默认 1000)===";
    qDebug().noquote() << QStringLiteral("sizeof(MpduInfo)=%1  sizeof(PacketEntry)=%2")
                              .arg(sizeof(MpduInfo)).arg(sizeof(PacketEntry));
    qDebug().noquote() << QStringLiteral("block v%1 roundtrip(120 条,跨 3 chunk,删死字段+补 coord_rsv1/2/3): %2")
                              .arg(pser::block_version())
                              .arg(roundtrip_check() ? "PASS" : "FAIL");
    bench(0,   14, 1000);   // 无字段树:只解 57 个标量/容器
    bench(100, 14, 1000);   // 真实形态
    bench(100, 14, 100);    // 若把 precision 降到 100
    bench(100, 14, 20);     // 若把 precision 降到 20
    return 0;
}
