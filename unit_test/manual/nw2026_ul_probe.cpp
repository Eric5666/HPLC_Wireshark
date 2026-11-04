// 临时探针:验证 NW_2026 OFDMA 类型1(UL-OFDMA 数据/DL-SACK) + 类型2 trigger 上下文
#include <QCoreApplication>
#include <QTreeWidget>
#include <QFile>
#include <QTextStream>
#include <cstdio>
#include "bplcframe.h"
#include "nw_2026_parser.h"
#include "nw_2026_tree.h"
#include "protocol_tree_builder.h"

static void dump(QTreeWidgetItem* it, int depth) {
    for (int i = 0; i < it->childCount(); ++i) {
        QTreeWidgetItem* c = it->child(i);
        QString line = QString(depth * 2, QChar(' ')) + c->text(0) + QStringLiteral(" = ") + c->text(1);
        printf("%s\n", qPrintable(line));
        dump(c, depth + 1);
    }
}

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    NW_2026_Parser parser;  // 同一实例,保持 trigger 上下文
    MsduState msdu;
    NW_2026_Parser::Filter flt;

    const char* files[] = {
        "wireshark_support_plugins/nw2026_trigger.bin",
        "wireshark_support_plugins/nw2026_ul_ofdma_data.bin",
        "wireshark_support_plugins/nw2026_dl_sack.bin",
        // 单站 16B UL 数据(MsgID!=0):树必须渲染为站点 PB 分组,不得标为 DL-SACK
        "wireshark_support_plugins/nw2026_trigger_tmi26.bin",
        "wireshark_support_plugins/nw2026_ul_single16.bin",
    };
    const char* files_nocontext[] = {
        "wireshark_support_plugins/nw2026_ul_ofdma_data.bin",
    };
    const bool nocontext = (argc > 1 && QString::fromLocal8Bit(argv[1]) == "nocontext");
    const char** fset = nocontext ? files_nocontext : files;
    const int fcnt = nocontext ? 1 : 5;
    for (int fi = 0; fi < fcnt; ++fi) {
        const char* fn = fset[fi];
        QFile f(QString::fromLocal8Bit(fn));
        if (!f.open(QIODevice::ReadOnly)) { printf("open fail %s\n", fn); continue; }
        QByteArray bin = f.readAll();
        BplcFrame fr;
        fr.data = QByteArray(1, '\x00') + bin;   // isRF=0 前缀 + MPDU(FCH byte0 起)
        fr.meta.from_raw = true;
        fr.meta.has_time_tag = false;

        auto r = parser.parse(fr, msdu, flt);
        printf("=== %s ===\n", fn);
        printf("accept=%d reject=%s frame_type=%u net_id(SNID)=0x%X version=%u fch_crc_ok=%d\n",
               r.accept ? 1 : 0, qPrintable(r.reject_reason), r.mpdu.frame_type,
               r.mpdu.net_id, r.mpdu.version, r.mpdu.fch_crc_ok ? 1 : 0);
        printf("pb_num=%u pb_size=%u sof_stations=%d src_tei=0x%X dst_tei=0x%X\n",
               r.mpdu.pb_num, r.mpdu.pb_size, r.mpdu.sof_stations.size(),
               r.mpdu.src_tei, r.mpdu.dst_tei);
        for (int si = 0; si < r.mpdu.sof_stations.size(); ++si) {
            const auto& st = r.mpdu.sof_stations[si];
            printf("  sta%d: tei=%u pb_num=%u pb_size=%u base=%d crc_oks=%d msdu_len=%d\n",
                   si, st.tei, st.pb_num, st.pb_size, st.block_base,
                   st.pb_crc_oks.size(), st.msdu.size());
            for (int bi = 0; bi < st.pb_crc_oks.size(); ++bi)
                printf("    block%d crc_ok=%d\n", bi, st.pb_crc_oks[bi] ? 1 : 0);
        }
        if (r.msdu.present) printf("msdu.present=1 summary=%s\n", qPrintable(r.msdu.summary));

        PacketEntry e;
        e.mpdu = r.mpdu; e.meta = r.meta; e.raw_bytes = r.payload_for_log;
        e.msdu_body = r.msdu_body; e.msdu = r.msdu; e.beacon = r.beacon;
        e.msdu_raw_base = r.msdu_raw_base;
        QTreeWidgetItem root;
        NW_2026_TreeBuilder tb;
        tb.build(&root, e);
        printf("--- tree ---\n");
        dump(&root, 0);
    }
    return 0;
}
