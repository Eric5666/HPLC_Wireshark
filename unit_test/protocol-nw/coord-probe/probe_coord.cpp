// COORD / version distribution probe (research only, 2026-10-17)
// Counts, on a NW capture, using the fix/nw-mme-spec-fields parser (3851fd5):
//  - FCH frame_type and FCH version distribution (all accepted frames)
//  - COORD frames: coord_rf_channel (byte3), coord_rsv3 (byte7; NW_2021 bit2-7 — the former
//    coord_option bit2-3 was folded into this reserved field, MpduInfo no longer has coord_option),
//    neighbouring reserved fields (rsv1 byte4-5 10b, rsv2, rsv3), src TEI, is_rf
//  - MSDU version (msdu_body byte0 bit1-2) distribution for reassembled MSDUs,
//    with the decoded summary for non-1 versions
// Usage: probe_coord <capture.txt>
#include <QApplication>
#include <QEventLoop>
#include <QTimer>
#include <QMap>
#include <cstdio>
#include "serialreader.h"
#include "nw_2021_parser.h"
#include "bplcframe.h"

static quint32 get_bits_local(const QByteArray& d, int byte, int bit, int len) {
    quint32 v = 0;
    for (int i = 0; i < len; ++i) {
        int b = byte + (bit + i) / 8;
        int o = (bit + i) % 8;
        if (b >= d.size()) break;
        v |= (quint32)(((quint8)d[b] >> o) & 1u) << i;
    }
    return v;
}

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    qRegisterMetaType<BplcFrame>("BplcFrame");
    qRegisterMetaType<ReaderConfig>("ReaderConfig");

    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <capture.txt|capture.bin>\n", argv[0]);
        return 2;
    }
    const QString path = QString::fromLocal8Bit(argv[1]);
    SerialReader reader;
    NW_2021_Parser parser;
    MsduState state;
    NW_2021_Parser::Filter filt;
    int total = 0, accepted = 0;
    QMap<int,int> ftypeCount, fchVerCount;
    QMap<int,int> msduVerCount;
    int coordTotal = 0;
    QMap<int,int> chanCount, rsv1Count, rsv2Count, rsv3Count, coordSrcCount;
    QMap<QString,int> coordJoint;
    int coordRf = 0;
    struct VFrame { int ver; QString summary; quint16 mme; int ftype; int src; int dst; quint16 mtype; };
    QList<VFrame> oddVer;

    QObject::connect(&reader, &SerialReader::frame_ready, [&](const BplcFrame& f) {
        auto r = parser.parse(f, state, filt);
        ++total;
        if (!r.accept) return;
        ++accepted;
        ftypeCount[r.mpdu.frame_type]++;
        fchVerCount[r.mpdu.version]++;
        if (r.mpdu.frame_type == 3) { // COORD
            ++coordTotal;
            if (r.meta.is_rf) ++coordRf;
            chanCount[r.mpdu.coord_rf_channel]++;
            rsv1Count[r.mpdu.coord_rsv1]++;
            rsv2Count[r.mpdu.coord_rsv2]++;
            rsv3Count[r.mpdu.coord_rsv3]++;
            coordSrcCount[r.mpdu.src_tei]++;
            coordJoint[QStringLiteral("ch%1/rsv3_%2").arg(r.mpdu.coord_rf_channel).arg(r.mpdu.coord_rsv3)]++;
        }
        if (r.msdu.present && !r.msdu_body.isEmpty()) {
            int v = (int)get_bits_local(r.msdu_body, 0, 1, 2);
            msduVerCount[v]++;
            if (v != 1)
                oddVer.push_back({v, r.msdu.summary, r.msdu.mme_type, r.mpdu.frame_type,
                                  r.mpdu.src_tei, r.mpdu.dst_tei, r.msdu.msdu_type});
        }
    });
    QEventLoop loop;
    QObject::connect(&reader, &SerialReader::finished, &loop, &QEventLoop::quit);
    QTimer::singleShot(120000, &loop, &QEventLoop::quit);
    ReaderConfig cfg;
    cfg.mode = path.endsWith(QStringLiteral(".bin")) ? ReaderMode::FilePlayback : ReaderMode::RawHex;
    cfg.file_path = path;
    reader.start(cfg);
    loop.exec();
    reader.stop();

    printf("file=%s total=%d accepted=%d\n", qPrintable(path), total, accepted);
    printf("frame_type:");
    for (auto it = ftypeCount.begin(); it != ftypeCount.end(); ++it) printf(" %d=%d", it.key(), it.value());
    printf("\nFCH version:");
    for (auto it = fchVerCount.begin(); it != fchVerCount.end(); ++it) printf(" %d=%d", it.key(), it.value());
    printf("\nMSDU version (reassembled only):");
    for (auto it = msduVerCount.begin(); it != msduVerCount.end(); ++it) printf(" %d=%d", it.key(), it.value());
    printf("\nCOORD total=%d rf=%d\n", coordTotal, coordRf);
    auto dump = [](const char* name, const QMap<int,int>& m) {
        printf("%s:", name);
        for (auto it = m.begin(); it != m.end(); ++it) printf(" %d=%d", it.key(), it.value());
        printf("\n");
    };
    dump("coord_channel", chanCount);
    dump("coord_rsv1(byte4-5,10b)", rsv1Count);
    dump("coord_rsv2(byte7bit0)", rsv2Count);
    dump("coord_rsv3(byte7 bit2-7)", rsv3Count);
    dump("coord_src_tei", coordSrcCount);
    printf("coord_joint:");
    for (auto it = coordJoint.begin(); it != coordJoint.end(); ++it) printf(" %s=%d", qPrintable(it.key()), it.value());
    printf("\nMSDU version !=1 frames (%d):\n", (int)oddVer.size());
    for (auto& vf : oddVer)
        printf("  ver=%d ftype=%d src=%d dst=%d msdu_type=0x%04x mme=0x%04x summary=%s\n",
               vf.ver, vf.ftype, vf.src, vf.dst, vf.mtype, vf.mme, qPrintable(vf.summary));
    return 0;
}
