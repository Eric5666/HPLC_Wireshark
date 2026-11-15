// 批量探针:对抓包逐帧跑指定解析器,统计接受/拒绝原因/帧型/MSDU/PB-CRC
#include <QCoreApplication>
#include <QFile>
#include <QHash>
#include <cstdio>
#include "nw_2021_parser.h"
#include "nw_2026_parser.h"
#include "gw_2022_parser.h"
#include "gw_2026_parser.h"

static bool extract_frame(QByteArray& buf, BplcFrame& out) {
    while (!buf.isEmpty()) {
        int idx = buf.indexOf(char(0x3C));
        if (idx < 0) { buf.clear(); return false; }
        buf.remove(0, idx + 1);
        idx = buf.indexOf(char(0x3E));
        if (idx < 0) return false;
        QByteArray esc = buf.left(idx);
        buf.remove(0, idx + 1);
        QByteArray unesc; unesc.reserve(esc.size());
        for (int i = 0; i < esc.size(); ++i) {
            quint8 b = quint8(esc[i]);
            if (b == 0x3D && i + 1 < esc.size()) { ++i; unesc.append(char(0xFF - quint8(esc[i]))); }
            else unesc.append(char(b));
        }
        out.data = unesc;
        out.meta.has_time_tag = false;
        out.meta.from_raw = false;
        return true;
    }
    return false;
}

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    if (argc < 3) { std::printf("usage: %s <nw2021|nw2026|gw2022|gw2026> <capture> [detail]\n", argv[0]); return 2; }
    const QString which = QString::fromLocal8Bit(argv[1]);
    QFile f(QString::fromLocal8Bit(argv[2]));
    if (!f.open(QIODevice::ReadOnly)) { std::printf("open fail\n"); return 1; }
    QByteArray buf = f.readAll(); f.close();
    const int detail = argc > 3 ? QString::fromLocal8Bit(argv[3]).toInt() : 0;
    std::unique_ptr<IProtocolParser> parser;
    if (which == "nw2026") parser = std::make_unique<NW_2026_Parser>();
    else if (which == "gw2026") parser = std::make_unique<GW_2026_Parser>();
    else if (which == "gw2022") parser = std::make_unique<GW_2022_Parser>();
    else parser = std::make_unique<NW_2021_Parser>();
    MsduState msdu; ParseFilter flt;
    long total = 0, acc = 0, msdu_ok = 0, pbcrc_ok = 0, sof = 0, bcn_ok = 0;
    QHash<QString, long> reasons; QHash<int, long> ftypes; QHash<int, long> protos;
    BplcFrame fr;
    while (extract_frame(buf, fr)) {
        ++total;
        ParseResult r = parser->parse(fr, msdu, flt);
        protos[int(r.protocol)]++;
        if (r.accept) {
            ++acc; ftypes[r.mpdu.frame_type]++;
            if (r.mpdu.frame_type == 1) { ++sof; if (r.mpdu.pb_crc_ok) ++pbcrc_ok; }
            if (r.msdu.present) ++msdu_ok; if (r.mpdu.frame_type == 0 && r.beacon.present) ++bcn_ok;
            if (detail && total <= detail) {
                std::function<void(const QVector<MsduFieldNode>&, int)> dump = [&dump](const QVector<MsduFieldNode>& ns, int d) {
                    for (const auto& n : ns) { std::printf("%*s%s = %s\n", d*2, "", qPrintable(n.name), qPrintable(n.value)); dump(n.children, d+1); }
                };
                std::printf("  mpdu: pb_num=%d pb_size=%d tmi=%d frame_len=%d msdu_body=%dB\n", r.mpdu.pb_num, r.mpdu.pb_size, r.mpdu.tmi, r.mpdu.frame_len, int(r.msdu_body.size()));
                if (r.msdu.present) dump(r.msdu.tree, 2);
                std::printf("#%ld ACC type=%d proto=%d ver=%d nid=0x%x src=%d dst=%d msdu=%d pbcrc=%d sum=%s\n",
                            total, r.mpdu.frame_type, int(r.protocol), r.mpdu.version, r.mpdu.net_id,
                            r.mpdu.src_tei, r.mpdu.dst_tei, (int)r.msdu.present, (int)r.mpdu.pb_crc_ok,
                            qPrintable(r.msdu.summary));
            }
        } else {
            reasons[r.reject_reason]++;
            if (detail && total <= detail)
                std::printf("#%ld REJ %s\n", total, qPrintable(r.reject_reason));
        }
    }
    std::printf("== %s: total=%ld accepted=%ld msdu=%ld sof=%ld pb_crc_ok=%ld beacon=%ld\n",
                qPrintable(which), total, acc, msdu_ok, sof, pbcrc_ok, bcn_ok);
    std::printf("frame_types:"); for (auto it = ftypes.begin(); it != ftypes.end(); ++it) std::printf(" [%d]=%ld", it.key(), it.value()); std::printf("\n");
    std::printf("result protocol marks:"); for (auto it = protos.begin(); it != protos.end(); ++it) std::printf(" [%d]=%ld", it.key(), it.value()); std::printf("\n");
    std::printf("reject reasons:\n"); for (auto it = reasons.begin(); it != reasons.end(); ++it) std::printf("  %ld x %s\n", it.value(), qPrintable(it.key()));
    return 0;
}
