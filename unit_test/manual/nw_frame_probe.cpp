// 临时探针:验证单帧在南网 NW_2021 解析器下的解析结果与字段树
#include <QCoreApplication>
#include <QTreeWidget>
#include <QTextStream>
#include <cstdio>
#include "bplcframe.h"
#include "nw_2021_parser.h"
#include "nw_2021_tree.h"
#include "protocol_tree_builder.h"

static void dump(QTreeWidgetItem* it, int depth) {
    for (int i = 0; i < it->childCount(); ++i) {
        QTreeWidgetItem* c = it->child(i);
        QString line = QString(depth * 2, QChar(' '))
            + c->text(0) + QStringLiteral(" = ") + c->text(1);
        printf("%s\n", qPrintable(line));
        dump(c, depth + 1);
    }
}

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    // 可选:第一个参数为十六进制帧(含 dlen..MPDU,不含 0x3C/0x3E 哨兵)
    QString hexArg = QStringLiteral("14 00 f4 25 52 ad 00 00 00 00 ba 01 00 0a 64 00 00 00 00 00 00 00 13 48 61 1f");
    if (argc > 1) hexArg = QString::fromLocal8Bit(argv[1]);
    QByteArray hex = QByteArray::fromHex(hexArg.remove(QLatin1Char(' ')).remove(QLatin1Char(',')).toLatin1());
    BplcFrame f;
    f.data = hex;
    f.meta.has_time_tag = false;
    f.meta.from_raw = false;

    NW_2021_Parser parser;
    MsduState msdu;
    NW_2021_Parser::Filter flt;  // 默认全接受

    auto r = parser.parse(f, msdu, flt);
    printf("accept=%d  reject_reason=%s\n", r.accept ? 1 : 0, qPrintable(r.reject_reason));
    printf("frame_type=%u(%s)  net_id(SNID)=0x%X  version=%u  fch_crc_ok=%d\n",
           r.mpdu.frame_type, qPrintable(r.mpdu.frame_type_name()),
           r.mpdu.net_id, r.mpdu.version, r.mpdu.fch_crc_ok ? 1 : 0);
    printf("ack_ext_type=%u  ack_dst_addr=0x%012llX  ack_channel_quality=%u  ack_sta_load=%u\n",
           r.mpdu.ack_ext_type, (unsigned long long)r.mpdu.ack_dst_addr,
           r.mpdu.ack_channel_quality, r.mpdu.ack_sta_load);

    // 渲染字段树(等价于 UI 展示)
    PacketEntry e;
    e.mpdu = r.mpdu;
    e.meta = r.meta;
    e.raw_bytes = r.payload_for_log;   // 树里用 raw_bytes 取字段
    e.msdu_body = r.msdu_body;
    e.msdu = r.msdu;
    e.beacon = r.beacon;
    e.msdu_raw_base = r.msdu_raw_base;

    QTreeWidgetItem root;
    NW_2021_TreeBuilder tb;
    tb.build(&root, e);
    printf("--- tree ---\n");
    dump(&root, 0);
    return 0;
}
