// Orig Src multi-source probe.
// Usage: orig_src_probe <gw_topo_merge.bin>
//  A. Parser invariant on GW multi-station frames: merged orig_srcs must equal
//     dedup(direct station MSDU header sources, in station order).
//  B. Model column: multi-source display format, dedup, single-frame fallback,
//     rejected-frame empty, CCO naming.
//  C. Filter: sta- word match (incl. sta-1 vs sta-11 boundary), MAC-pattern
//     expansion to orig TEIs, substring path, negatives.
//  D. Dir: merged frame with only-CCO orig sources shows downlink (NW cascade
//     E2E: 2 aggregated PBs, 2 CCO records, relay-PCO hop).
// Exit 0 iff every check passes.
#include <cstdio>
#include <cstdint>
#include <QCoreApplication>
#include <QByteArray>
#include <QString>
#include <QVector>
#include "bplcframe.h"
#include "iprotocolparser.h"
#include "gw_protocol/gw_2026/gw_2026_parser.h"
#include "gw_protocol/gw_2026/gw_2026_msdu_parser.h"
#include "nw_2026_parser.h"
#include "fieldtools.h"
#include "crc.h"
#include "packetlistmodel.h"

static int g_fails = 0;
static void check(bool ok, const char* what) {
    std::printf("%s: %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++g_fails;
}
static quint64 mac6(quint8 b0, quint8 b1, quint8 b2, quint8 b3, quint8 b4, quint8 b5) {
    return quint64(b0) | (quint64(b1) << 8) | (quint64(b2) << 16)
         | (quint64(b3) << 24) | (quint64(b4) << 32) | (quint64(b5) << 40);
}
static QString srcs_str(const QVector<TeiMacPair>& v) {
    QStringList parts;
    for (const auto& p : v)
        parts << QString("%1:%2").arg(p.tei).arg(p.mac, 12, 16, QChar('0'));
    return parts.join(" ");
}
static void put_mac(quint8* p, quint64 mac) {
    for (int i = 0; i < 6; ++i) p[i] = (quint8)((mac >> (8 * i)) & 0xFF);
}
static void put_crc24(quint8* blk, int len) {
    const quint32 calc = crc24_lsb(blk, len);
    blk[len - 3] = calc & 0xFF;
    blk[len - 2] = (calc >> 8) & 0xFF;
    blk[len - 1] = (calc >> 16) & 0xFF;
}
// 与 nw-dlofdma-crc-probe 的 build_nw_assoc 同构:NW AssocReq MAC 帧 134B。
static QByteArray build_nw_assoc(int dst_tei, quint64 dst_mac, int src_tei,
                                 quint64 src_mac, int restart) {
    QByteArray mme(80, 0);
    quint8* m = reinterpret_cast<quint8*>(mme.data());
    m[0] = 0x01;
    m[1] = 0x30; m[2] = 0x00;        // MMType 0x0030 ASSOCREQ (LE)
    put_mac(m + 6, src_mac);         // STAMAC at mme offset 6
    const int msdu_len = 18 + (int)mme.size();
    QByteArray f(32 + msdu_len + 4, 0);
    quint8* p = reinterpret_cast<quint8*>(f.data());
    p[0] = 0x02;                     // version 1, long head
    p[2] = quint8(msdu_len & 0xFF); p[3] = quint8((msdu_len >> 8) & 0xFF);
    p[4] = quint8(dst_tei & 0xFF);
    p[5] = quint8(((dst_tei >> 8) & 0x0F) | ((src_tei & 0x0F) << 4));
    p[6] = quint8((src_tei >> 4) & 0xFF);
    p[7] = quint8((restart & 0x0F) << 4);
    p[10] = 0xEE; p[11] = 0x64;
    put_mac(p + 12, dst_mac);
    put_mac(p + 32, dst_mac);
    put_mac(p + 38, src_mac);
    p[44] = 0x00; p[45] = 0x81; p[46] = 0x00; p[47] = 0x00;  // VLAN 0x8100
    p[48] = 0xE1; p[49] = 0x88;                              // type 0x88E1
    memcpy(p + 50, mme.constData(), mme.size());
    return f;
}
// NW 级联帧:单站点 SOF v2,2 块聚合 PB(264B,TMI 9),级联体流 272B =
// 2 条记录(头 2B:长度 12b + Start/End + MAC 帧 134B),源均为 CCO。
// 帧级本跳为中继 PCO(FCH 源 TEI 5):本跳说明不了源,orig 才是源证据。
static QByteArray build_cascade_frame(quint64 cco, quint64 sta27, quint64 sta42) {
    QByteArray stream;
    const QByteArray mac1 = build_nw_assoc(27, sta27, 1, cco, 5);  // CCO -> STA27
    const QByteArray mac2 = build_nw_assoc(42, sta42, 1, cco, 5);  // CCO -> STA42
    auto append_rec = [&stream](const QByteArray& mac, bool start, bool end) {
        const int clen = mac.size();
        stream.append(char(clen & 0xFF));
        stream.append(char(((clen >> 8) & 0x0F) | (start ? 0x10 : 0) | (end ? 0x20 : 0)));
        stream.append(mac);
    };
    append_rec(mac1, true, false);
    append_rec(mac2, false, true);
    // 体流分装 2 块聚合 PB(每块体 256B):记录 2 跨块边界,级联解析按体流连续读。
    QByteArray body(512, 0);
    memcpy(body.data(), stream.constData(), stream.size());
    QByteArray f(544, 0);
    quint8* p = reinterpret_cast<quint8*>(f.data());
    p[0] = 0x01;                     // SOF, SNID 0
    set_bits(p, 1, 0, 12, 5);        // FCH 源 TEI = 5(中继 PCO 本跳,非 CCO)
    set_bits(p, 2, 4, 12, 0xFFF);    // FCH 目的 TEI = 广播
    p[4] = quint8(2 << 2);           // 单站、非训练、PB 个数 2(bits2-5)
    set_bits(p, 8, 0, 12, 100);      // 帧长(显示用)
    p[12] = 0x20;                    // version 2
    p[6] = quint8(9 << 1);           // TMI 9 -> 264B(bit0=0 非 Bitloading)
    put_crc24(p, 16);                // FCH CRC24
    auto block = [](const QByteArray& body256, int seq) {
        QByteArray blk(264, 0);
        quint8* b = reinterpret_cast<quint8*>(blk.data());
        b[0] = quint8(seq & 0xFF); b[1] = quint8((seq >> 8) & 0xFF);
        b[2] = 0x01;                 // agg bit0 = 1:聚合分支
        memcpy(b + 4, body256.constData(), body256.size());
        put_crc24(b, 264);
        return blk;
    };
    f.replace(16, 264, block(body.mid(0, 256), 0));
    f.replace(280, 264, block(body.mid(256, 256), 1));
    return f;
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    if (argc < 2) { std::fprintf(stderr, "usage: %s <gw_topo_merge.bin> [gw_topo_merge_multi.bin]\n", argv[0]); return 2; }

    // ---- A. Parser invariant on GW multi-station frames (hard-coded expected) ----
    // argv[1] = gw_topo_merge.bin (3 frames, each single source [1:CCO_MAC])
    // argv[2] = gw_topo_merge_multi.bin (1 frame, two distinct sources 41/42)
    {
        const quint64 cco_mac = 0xAABBCCDDEE01ULL;
        const quint64 sta29 = 0xAABBCCDDEE29ULL;
        const quint64 sta2a = 0xAABBCCDDEE2AULL;
        // 逐 bin 的逐帧期望 orig_srcs/orig_dsts(写死,不反推;验证"该收集却没收集"的场景)
        // - 老 bin:3 帧,CCO→站下行,单 src [1:CCO];各站 MSDU 头目的=各站自己 → dst 逐站去重
        //   F1: AssocCnf(11)/AssocCnf(12) → dst [11,12]
        //   F2: AssocCnf(21)/Gather(24)   → dst [21,24]
        //   F3: app(31)/AssocCnf(32)      → dst [31,32]
        // - 多源 bin:1 帧,两站上行,源 41/42 不同;目的均为 CCO → 单 dst [1:CCO](去重)
        const QVector<QVector<TeiMacPair>> want_by_bin[] = {
            { { {1, cco_mac} }, { {1, cco_mac} }, { {1, cco_mac} } },
            { { {41, sta29}, {42, sta2a} } },
        };
        const QVector<QVector<TeiMacPair>> want_dst_by_bin[] = {
            { { {11, 0xAABBCCDDEE0BULL}, {12, 0xAABBCCDDEE0CULL} },
              { {21, 0xAABBCCDDEE15ULL}, {24, 0xAABBCCDDEE18ULL} },
              { {31, 0xAABBCCDDEE1FULL}, {32, 0xAABBCCDDEE20ULL} } },
            { { {1, cco_mac} } },
        };
        const int nbins = (argc >= 3) ? 2 : 1;
        long frame_no = 0;
        for (int b = 0; b < nbins; ++b) {
            FILE* in = std::fopen(argv[1 + b], "rb");
            if (!in) { std::fprintf(stderr, "cannot open %s\n", argv[1 + b]); ++g_fails; continue; }
            GW_2026_Parser parser;
            ParseFilter filt;
            const auto& want_frames = want_by_bin[b];
            const auto& want_dst_frames = want_dst_by_bin[b];
            for (int fi = 0; fi < want_frames.size(); ++fi) {
                unsigned char lb[4];
                if (std::fread(lb, 1, 4, in) != 4) break;
                uint32_t len = (uint32_t)lb[0] | ((uint32_t)lb[1] << 8)
                             | ((uint32_t)lb[2] << 16) | ((uint32_t)lb[3] << 24);
                QByteArray body((int)len, 0);
                if (len > 0 && std::fread(body.data(), 1, len, in) != len) break;
                ++frame_no;
                BplcFrame fr;
                fr.meta.from_raw = true;
                fr.data = body;
                fr.meta.is_rf = (len > 0 && body[0] != 0);
                MsduState msdu_state;
                ParseResult r = parser.parse(fr, msdu_state, filt);
                const QVector<TeiMacPair>& want = want_frames[fi];
                bool ok = (r.msdu.orig_srcs.size() == want.size());
                if (ok) {
                    for (int k = 0; k < want.size(); ++k)
                        if (r.msdu.orig_srcs[k].tei != want[k].tei || r.msdu.orig_srcs[k].mac != want[k].mac) { ok = false; break; }
                }
                std::printf("FRAME %ld accept=%d merged_orig=[%s] want=[%s]\n", frame_no, r.accept ? 1 : 0,
                            qPrintable(srcs_str(r.msdu.orig_srcs)), qPrintable(srcs_str(want)));
                char buf[64];
                std::snprintf(buf, sizeof(buf), "parser frame %ld orig_srcs invariant", frame_no);
                check(r.accept && ok, buf);
                // Orig Dst 镜像(7f707aa):同口径写死期望
                const QVector<TeiMacPair>& want_dst = want_dst_frames[fi];
                bool ok_dst = (r.msdu.orig_dsts.size() == want_dst.size());
                if (ok_dst) {
                    for (int k = 0; k < want_dst.size(); ++k)
                        if (r.msdu.orig_dsts[k].tei != want_dst[k].tei || r.msdu.orig_dsts[k].mac != want_dst[k].mac) { ok_dst = false; break; }
                }
                std::printf("FRAME %ld merged_dst=[%s] want=[%s]\n", frame_no,
                            qPrintable(srcs_str(r.msdu.orig_dsts)), qPrintable(srcs_str(want_dst)));
                std::snprintf(buf, sizeof(buf), "parser frame %ld orig_dsts invariant", frame_no);
                check(r.accept && ok_dst, buf);
            }
            // EOF 断言:读满期望帧后文件须恰好结束;尾部多余记录/残字节均判失败
            // (旧版读到 EOF 才断言帧数,写死期望改写时丢了这层严格性,此次补回)
            unsigned char tail[4];
            const size_t ntail = std::fread(tail, 1, 4, in);
            char ebuf[64];
            std::snprintf(ebuf, sizeof(ebuf), "bin %d no trailing data after %d frames",
                          b, (int)want_frames.size());
            check(ntail == 0, ebuf);
            std::fclose(in);
        }
        check(frame_no == (nbins == 2 ? 4 : 3), "parser read all frames");
    }

    // ---- B. Model column ----
    const quint64 macA = mac6(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0b);  // "aa:bb:cc:dd:ee:0b"
    const quint64 macB = mac6(0x01, 0x02, 0x03, 0x04, 0x05, 0x06);  // "01:02:03:04:05:06"
    const quint64 macC = mac6(0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f);  // "0a:0b:0c:0d:0e:0f"
    const quint64 macCco = mac6(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    PacketListModel model;
    {
        PacketEntry m;  // merged-style: present=false, dup source
        m.accepted = true;
        m.msdu.present = false;
        m.msdu.simple_head = false;
        m.msdu.msdu_src_tei = -1;
        m.msdu.orig_srcs.append({11, macA});
        m.msdu.orig_srcs.append({12, macB});
        m.msdu.orig_srcs.append({11, macA});
        PacketEntry s;  // single-frame fallback
        s.accepted = true;
        s.msdu.present = true;
        s.msdu.simple_head = false;
        s.msdu.msdu_src_tei = 5;
        s.msdu.msdu_src_mac = macC;
        PacketEntry rj;  // rejected: empty even with orig_srcs
        rj.accepted = false;
        rj.msdu.orig_srcs.append({11, macA});
        PacketEntry cco;  // CCO naming
        cco.accepted = true;
        cco.msdu.present = false;
        cco.msdu.simple_head = false;
        cco.msdu.msdu_src_tei = -1;
        cco.msdu.orig_srcs.append({1, macCco});
        PacketEntry p;  // precondition: frame src present -> single, never multi
        p.accepted = true;
        p.msdu.present = true;
        p.msdu.simple_head = false;
        p.msdu.msdu_src_tei = 5;
        p.msdu.msdu_src_mac = macC;
        p.msdu.orig_srcs.append({11, macA});
        p.msdu.orig_srcs.append({12, macB});
        model.append_packets(QVector<PacketEntry>{m, s, rj, cco, p});
        model.set_display_filter(QString());
        const auto col = [&](int row) {
            return model.data(model.index(row, PacketListModel::COL_ORIG_SRC), Qt::DisplayRole).toString();
        };
        check(col(0) == QStringLiteral("STA-11 [aa:bb:cc:dd:ee:0b],STA-12 [01:02:03:04:05:06]"),
              "column multi format + dedup");
        check(col(1) == QStringLiteral("STA-5 [0a:0b:0c:0d:0e:0f]"),
              "column single fallback unchanged");
        check(col(2).isEmpty(), "column rejected empty");
        check(col(3) == QStringLiteral("CCO [00:11:22:33:44:55]"), "column CCO naming");
        check(col(4) == QStringLiteral("STA-5 [0a:0b:0c:0d:0e:0f]"),
              "column precondition: frame src present -> single, not multi");
        // Dir: merged frame whose orig sources are only CCO shows downlink.
        const auto dir = [&](int row) {
            return model.data(model.index(row, PacketListModel::COL_DIR), Qt::DisplayRole).toString();
        };
        check(dir(0) == QStringLiteral("*"), "dir multi non-CCO unchanged");
        check(dir(1) == QStringLiteral("*"), "dir single unchanged");
        check(dir(2) == QStringLiteral("*"), "dir rejected unchanged");
        check(dir(3) == QStringLiteral("\u2193"), "dir merged only-CCO downlink");
        check(dir(4) == QStringLiteral("*"), "dir frame-src-present unchanged");
    }

    // ---- C. Filter ----
    {
        // Learn MAC->TEI table via the public append path (as mac-filter-probe does).
        PacketEntry l;
        l.accepted = true;
        l.mpdu.net_id = 1;
        l.msdu.tei_mac_pairs.append({11, macA});
        l.msdu.tei_mac_pairs.append({12, macB});
        model.append_packets(QVector<PacketEntry>{l});

        PacketEntry m;  // merged-style entry, hop TEIs 0 to isolate the word path
        m.accepted = true;
        m.msdu.present = false;
        m.msdu.simple_head = false;
        m.msdu.msdu_src_tei = -1;
        m.msdu.orig_srcs.append({11, macA});
        m.msdu.orig_srcs.append({12, macB});
        m.search_text = make_search_text(m);
        PacketEntry s;  // single frame, hop TEIs 0, frame src 5
        s.accepted = true;
        s.msdu.present = true;
        s.msdu.simple_head = false;
        s.msdu.msdu_src_tei = 5;
        s.msdu.msdu_src_mac = macC;
        s.search_text = make_search_text(s);
        auto t = [&](const char* name, const QString& expr, const PacketEntry& e, bool want) {
            model.set_display_filter(expr);
            const bool got = model.passes_filter(e);
            char buf[128];
            std::snprintf(buf, sizeof(buf), "filter %s '%s' -> %d want %d",
                          name, qPrintable(expr), got ? 1 : 0, want ? 1 : 0);
            check(got == want, buf);
        };
        t("sta-word", "sta-12", m, true);
        t("sta-word", "sta-11", m, true);
        t("sta-word-boundary", "sta-1", m, false);
        t("sta-word-neg", "sta-99", m, false);
        t("mac-pattern", "01:02", m, true);
        t("mac-pattern", "aa:bb", m, true);
        t("mac-pattern-neg", "ff:ff", m, false);
        t("substring", "dd:ee:0", m, true);
        t("single-frame-src-word", "sta-5", s, true);
        t("single-frame-src-word-neg", "sta-6", s, false);
        // Precondition on the filter side: frame src present -> orig words absent.
        PacketEntry p;
        p.accepted = true;
        p.msdu.present = true;
        p.msdu.simple_head = false;
        p.msdu.msdu_src_tei = 5;
        p.msdu.msdu_src_mac = macC;
        p.msdu.orig_srcs.append({11, macA});
        p.msdu.orig_srcs.append({12, macB});
        p.search_text = make_search_text(p);
        t("precondition-filter", "sta-12", p, false);
        t("precondition-filter", "sta-5", p, true);
    }

    // ---- B2. Model column: Orig Dst (mirror of B) ----
    {
        PacketListModel model2;
        PacketEntry m;  // merged-style: present=false, dup destination
        m.accepted = true;
        m.msdu.present = false;
        m.msdu.simple_head = false;
        m.msdu.msdu_dst_tei = -1;
        m.msdu.orig_dsts.append({11, macA});
        m.msdu.orig_dsts.append({12, macB});
        m.msdu.orig_dsts.append({11, macA});
        PacketEntry s;  // single-frame fallback
        s.accepted = true;
        s.msdu.present = true;
        s.msdu.simple_head = false;
        s.msdu.msdu_dst_tei = 5;
        s.msdu.msdu_dst_mac = macC;
        PacketEntry cco;  // CCO naming
        cco.accepted = true;
        cco.msdu.present = false;
        cco.msdu.simple_head = false;
        cco.msdu.msdu_dst_tei = -1;
        cco.msdu.orig_dsts.append({1, macCco});
        PacketEntry bc;  // broadcast naming
        bc.accepted = true;
        bc.msdu.present = false;
        bc.msdu.simple_head = false;
        bc.msdu.msdu_dst_tei = -1;
        bc.msdu.orig_dsts.append({0xFFF, mac6(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)});
        PacketEntry p;  // precondition: frame dst present -> single, never multi
        p.accepted = true;
        p.msdu.present = true;
        p.msdu.simple_head = false;
        p.msdu.msdu_dst_tei = 5;
        p.msdu.msdu_dst_mac = macC;
        p.msdu.orig_dsts.append({11, macA});
        p.msdu.orig_dsts.append({12, macB});
        model2.append_packets(QVector<PacketEntry>{m, s, cco, bc, p});
        model2.set_display_filter(QString());
        const auto col = [&](int row) {
            return model2.data(model2.index(row, PacketListModel::COL_ORIG_DST), Qt::DisplayRole).toString();
        };
        check(col(0) == QStringLiteral("STA-11 [aa:bb:cc:dd:ee:0b],STA-12 [01:02:03:04:05:06]"),
              "dst column multi format + dedup");
        check(col(1) == QStringLiteral("STA-5 [0a:0b:0c:0d:0e:0f]"),
              "dst column single fallback unchanged");
        check(col(2) == QStringLiteral("CCO [00:11:22:33:44:55]"), "dst column CCO naming");
        check(col(3) == QStringLiteral("BCAST [ff:ff:ff:ff:ff:ff]"), "dst column BCAST naming");
        check(col(4) == QStringLiteral("STA-5 [0a:0b:0c:0d:0e:0f]"),
              "dst column precondition: frame dst present -> single, not multi");
    }

    // ---- C2. Filter: Orig Dst words (mirror of C) ----
    {
        PacketListModel model3;
        PacketEntry m;  // merged-style entry, hop TEIs 0 to isolate the word path
        m.accepted = true;
        m.msdu.present = false;
        m.msdu.simple_head = false;
        m.msdu.msdu_src_tei = -1;
        m.msdu.msdu_dst_tei = -1;
        m.msdu.orig_dsts.append({11, macA});
        m.msdu.orig_dsts.append({12, macB});
        m.search_text = make_search_text(m);
        PacketEntry p;  // precondition on the filter side
        p.accepted = true;
        p.msdu.present = true;
        p.msdu.simple_head = false;
        p.msdu.msdu_src_tei = -1;
        p.msdu.msdu_dst_tei = 5;
        p.msdu.msdu_dst_mac = macC;
        p.msdu.orig_dsts.append({11, macA});
        p.msdu.orig_dsts.append({12, macB});
        p.search_text = make_search_text(p);
        auto t = [&](const char* name, const QString& expr, const PacketEntry& e, bool want) {
            model3.set_display_filter(expr);
            const bool got = model3.passes_filter(e);
            char buf[128];
            std::snprintf(buf, sizeof(buf), "dst filter %s '%s' -> %d want %d",
                          name, qPrintable(expr), got ? 1 : 0, want ? 1 : 0);
            check(got == want, buf);
        };
        t("sta-word", "sta-12", m, true);
        t("sta-word", "sta-11", m, true);
        t("sta-word-boundary", "sta-1", m, false);
        t("sta-word-neg", "sta-99", m, false);
        t("precondition-filter", "sta-12", p, false);
        t("precondition-filter", "sta-5", p, true);
    }

    // ---- D. Dir: merged frame with only-CCO orig sources shows downlink ----
    // NW cascade E2E: single-station SOF v2, 2 aggregated PBs, cascade stream
    // of 2 records, both CCO-originated. Frame-level hop is a relay PCO.
    {
        const quint64 cco   = mac6(0x02, 0, 0, 0, 0, 0x01);
        const quint64 sta27 = mac6(0x02, 0, 0, 0, 0, 0x27);
        const quint64 sta42 = mac6(0x02, 0, 0, 0, 0, 0x42);
        NW_2026_Parser parser;
        ParseFilter filt;
        BplcFrame fr;
        fr.meta.from_raw = true;
        fr.data = QByteArray(1, char(0)) + build_cascade_frame(cco, sta27, sta42);
        MsduState msdu;
        const auto r = parser.parse(fr, msdu, filt);
        check(r.accept, "cascade accept");
        check(r.msdu.cascade, "cascade flag");
        // 级联帧 present=true:级联分支每解析一条记录即置 present(与 UL-OFDMA
        // 等 present=false 的合并类不同,此前“present false”断言是误写)。
        check(r.msdu.present, "cascade present true");
        check(r.msdu.orig_srcs.size() == 1
              && r.msdu.orig_srcs[0].tei == 1
              && r.msdu.orig_srcs[0].mac == cco,
              "cascade orig_srcs only CCO");
        PacketListModel modelD;
        PacketEntry e;
        e.accepted = r.accept;
        e.msdu = r.msdu;
        e.mpdu = r.mpdu;
        e.protocol = kProtocolNw2026;
        modelD.append_packets(QVector<PacketEntry>{e});
        modelD.set_display_filter(QString());
        check(modelD.data(modelD.index(0, PacketListModel::COL_DIR), Qt::DisplayRole).toString()
                  == QStringLiteral("\u2193"),
              "dir cascade only-CCO downlink");
        check(modelD.data(modelD.index(0, PacketListModel::COL_ORIG_SRC), Qt::DisplayRole).toString()
                  == QStringLiteral("CCO [02:00:00:00:00:01]"),
              "orig cascade only-CCO display");
        // Synthetic guards: mixed origins and TEI-0-only origins stay "*".
        PacketListModel modelG;
        PacketEntry mx;  // mixed CCO + station
        mx.accepted = true;
        mx.msdu.present = false;
        mx.msdu.simple_head = false;
        mx.msdu.msdu_src_tei = -1;
        mx.msdu.orig_srcs.append({1, cco});
        mx.msdu.orig_srcs.append({27, sta27});
        PacketEntry z;  // TEI-0-only: no valid source
        z.accepted = true;
        z.msdu.present = false;
        z.msdu.simple_head = false;
        z.msdu.msdu_src_tei = -1;
        z.msdu.orig_srcs.append({0, 0});
        modelG.append_packets(QVector<PacketEntry>{mx, z});
        modelG.set_display_filter(QString());
        const auto dirG = [&](int row) {
            return modelG.data(modelG.index(row, PacketListModel::COL_DIR), Qt::DisplayRole).toString();
        };
        check(dirG(0) == QStringLiteral("*"), "dir mixed origins unchanged");
        check(dirG(1) == QStringLiteral("*"), "dir TEI-0-only unchanged");
    }

    std::printf("RESULT: %s (%d failures)\n", g_fails == 0 ? "ALL PASS" : "FAIL", g_fails);
    return g_fails == 0 ? 0 : 1;
}
