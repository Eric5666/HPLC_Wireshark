#include "packetentry_serialize.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QStringList>
#include <cstdio>

static MsduFieldNode node(const QString& n, const QString& v, int rs, int rl) {
    MsduFieldNode f; f.name = n; f.value = v; f.rel_start = rs; f.rel_len = rl;
    return f;
}
static PacketEntry make_entry(int i) {
    PacketEntry e;
    e.index = i; e.epoch_ms = 1700000000000LL + i; e.delta_us = 1000 + i;
    e.accepted = (i % 7 != 0);
    e.reason = e.accepted ? QString() : QStringLiteral("CRC error");
    e.raw_wire = QByteArray::fromHex("3c00ff3e");
    e.meta.timestamp = 12345 + i; e.meta.is_rf = (i % 2 == 0);
    e.meta.frame_time = QDateTime::fromMSecsSinceEpoch(e.epoch_ms);
    e.mpdu.frame_type = quint8(i % 4); e.mpdu.src_tei = quint16(100 + (i % 50));
    e.mpdu.dst_tei = (i % 5 == 0) ? quint16(0xFFF) : quint16(200 + (i % 30));
    e.mpdu.beacon_cco_mac = 0x112233445566ULL;
    e.msdu.present = true; e.msdu.msdu_seq = quint16(i);
    e.msdu.summary = QStringLiteral("summary-%1").arg(i);
    MsduFieldNode root = node(QStringLiteral("ItemHead [8b]"), QStringLiteral("0x12"), 0, 1);
    root.children.append(node(QStringLiteral("TEI [12b]"), QString::number(i), 1, 2));
    e.msdu.tree.append(root);
    e.msdu.tei_mac_pairs.append({quint16(i & 0xFFF), 0xAABBCCDDEE00ULL + quint64(i)});
    e.raw_bytes = QByteArray(64, char(i & 0xFF));
    e.msdu_raw_base = 10;
    e.search_text = make_search_text(e);
    return e;
}
// 用法:
//   golden                      旧行为:在 CWD 写 v<ver>_n<N>.bin 并打印 n/bytes/sha256(不要在用例根目录跑)
//   golden --check <dir>        CI 门禁:①编码→解码→再编码逐字节一致(无损往返);
//                               ②与 <dir>/v<ver>_n<N>.bin 逐字节一致(<ver> = pser::block_version())。
//                               ②失败 = 编码字节变了:若是有意的格式变更,须 bump block_version()
//                               并用 --record 重录 golden;没 bump 就变了说明是意外漂移
//   golden --record <dir>       写 <dir>/v<ver>_n<N>.bin(格式有意变更、bump 版本后重录用)
// 退出码:0 通过,1 有失败,2 用法错误
static int fails = 0;
static void check(const QString& name, bool ok, const QString& detail = QString()) {
    std::printf("%-58s %s%s\n", qPrintable(name), ok ? "PASS" : "FAIL",
                detail.isEmpty() ? "" : qPrintable(QStringLiteral("  (") + detail + QLatin1Char(')')));
    if (!ok) ++fails;
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    const QStringList args = app.arguments();
    QString mode, dir;
    if (args.size() == 3 && (args[1] == QLatin1String("--check") || args[1] == QLatin1String("--record"))) {
        mode = args[1].mid(2);
        dir = args[2];
    } else if (args.size() != 1) {
        std::fprintf(stderr, "usage: %s [--check <golden_dir> | --record <golden_dir>]\n", argv[0]);
        return 2;
    }
    const quint32 ver = pser::block_version();
    std::printf("block_version=%u\n", ver);
    for (int n : {1, 57, 250, 1000}) {
        QVector<PacketEntry> es;
        for (int i = 0; i < n; ++i) es.append(make_entry(i));
        const QByteArray blob = pser::encode_block(es);
        const QString base = QStringLiteral("v%1_n%2.bin").arg(ver).arg(n);
        std::printf("n=%d bytes=%d sha256=%s\n", n, int(blob.size()),
                    QCryptographicHash::hash(blob, QCryptographicHash::Sha256).toHex().constData());
        if (mode.isEmpty()) {
            QFile f(base);
            if (!f.open(QIODevice::WriteOnly) || f.write(blob) != blob.size()) { std::fprintf(stderr, "write %s failed\n", qPrintable(base)); return 1; }
            continue;
        }
        const QString path = dir + QLatin1Char('/') + base;
        if (mode == QLatin1String("record")) {
            QFile f(path);
            const bool ok = f.open(QIODevice::WriteOnly) && f.write(blob) == blob.size();
            check(QStringLiteral("record %1").arg(base), ok, path);
            continue;
        }
        // --check ①无损往返
        QVector<PacketEntry> back;
        const bool dec = pser::decode_block(blob, back);
        check(QStringLiteral("n=%1 decode_block(encode_block) ok, count").arg(n), dec && back.size() == n,
              QStringLiteral("decoded %1").arg(back.size()));
        if (dec) {
            const QByteArray again = pser::encode_block(back);
            check(QStringLiteral("n=%1 re-encode after decode is byte-identical").arg(n), again == blob,
                  QStringLiteral("%1 vs %2 bytes").arg(again.size()).arg(blob.size()));
        }
        // --check ②与入库 golden 逐字节一致
        QFile g(path);
        if (!g.open(QIODevice::ReadOnly)) {
            check(QStringLiteral("n=%1 golden %2 present").arg(n).arg(base), false,
                  QStringLiteral("block_version bumped? re-record with --record"));
            continue;
        }
        const QByteArray ref = g.readAll();
        // 块内字符串池/分片经 qCompress(系统 zlib)压缩:不同 zlib 版本/实现(CI 的 Ubuntu vs 本地)
        // 压缩字节可能不同而内容相同。判定按"内容":用当前读取器解 golden、再用当前编码器重编码,
        // 须与本次编码逐字节一致(两边同一 zlib)。格式变了而 block_version 没 bump ⇒ 解出的条目不同
        // 或解码失败 ⇒ FAIL;bump 了 ⇒ 版本校验拒绝旧 golden / 新文件名不存在 ⇒ FAIL,提示重录。
        QVector<PacketEntry> gback;
        const bool gdec = pser::decode_block(ref, gback) && gback.size() == n;
        check(QStringLiteral("n=%1 golden %2 decodes with current reader").arg(n).arg(base), gdec);
        const bool same_content = gdec && pser::encode_block(gback) == blob;
        check(QStringLiteral("n=%1 golden %2 content == current encode").arg(n).arg(base), same_content,
              same_content ? QString()
                           : QStringLiteral("golden %1 B sha256 %2…, now %3 B; format drift without block_version bump?")
                                 .arg(ref.size())
                                 .arg(QString::fromLatin1(QCryptographicHash::hash(ref, QCryptographicHash::Sha256).toHex().left(16)))
                                 .arg(blob.size()));
        if (same_content && ref != blob)
            std::printf("  note: n=%d bytes differ only in zlib output (different zlib build); content identical\n", n);
    }
    if (mode == QLatin1String("check"))
        std::printf("RESULT: %s (%d failures)\n", fails ? "FAIL" : "ALL PASS", fails);
    return fails ? 1 : 0;
}
