/// pb-crc-red-probe —— PB 块 CRC 失败时的解析/标红口径回归(南网 + 国网,四个内置解析器)
/// 用户 2026-11 裁决:
///   FC(FCH) CRC OK + PB 块 CRC FAIL                 ⇒ 帧照常解析(accept,FC 字段不变),行红
///   FC OK + PB FAIL + MSDU CRC32 OK                  ⇒ MSDU 也解析(摘要/学习对与好帧一致),行红
///   FC OK + PB FAIL + MSDU CRC32 FAIL                ⇒ MSDU 不采信(摘要空、只留 CRC 证据、
///                                                      无 TEI↔MAC 学习对/拓扑事件),行红
///   FC CRC FAIL                                      ⇒ DROP(accept=0)
/// 方法:从入库 fixture 里为 NW_2021 / NW_2026 / GW_2022 / GW_2026 各挑若干「好」单块 SOF 帧
/// (FCH OK、PB CRC 全过、MSDU CRC32 OK、摘要非空),做三类定点变异后用全新解析器重解析:
///   P  只翻 PB 块尾 CRC24 的 3 个字节之一(MSDU 字节含 CRC32 完好)
///   M  翻 PB 块尾 CRC24 一字节 + 翻 MSDU 帧尾 CRC32 一字节(PB 坏且 MSDU 坏)
///   F  翻 FCH 一字节
/// 行色经真实 PacketListModel 的 ForegroundRole 读回。
/// 用法:./pb_crc_red_probe <repo-root>   exit 0 = 全部断言通过
#include <QCoreApplication>
#include <QFile>
#include <QColor>
#include <cstdio>
#include <memory>
#include "bplcframe.h"
#include "msdu_crc_state.h"
#include "crc.h"
#include "nw_2021_parser.h"
#include "nw_2026_parser.h"
#include "gw_2022_parser.h"
#include "gw_2026_parser.h"
#include "packetlistmodel.h"
#include "playbackwriter.h"

static int g_fail = 0;
static int g_ok = 0;
#define CHECK(c, ...) do { if (!(c)) { ++g_fail; std::printf("FAIL: "); std::printf(__VA_ARGS__); std::printf("\n"); } else ++g_ok; } while (0)

struct Input { QByteArray data; bool from_raw; int mpdu_off; QString src; };

/// fmt: wire(3C..3E 转义帧流) | lenpfx([u32 LE 长度][isRF][MPDU]…) | raw(整文件为 MPDU,前补 isRF=0)
static QVector<Input> load(const QString& fmt, const QString& path) {
    QVector<Input> out;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) { std::printf("FAIL: cannot open %s\n", qPrintable(path)); ++g_fail; return out; }
    QByteArray b = f.readAll();
    const QString name = path.section('/', -1);
    if (fmt == QLatin1String("wire")) {
        int n = 0;
        while (true) {
            const int s = b.indexOf(char(0x3C)); if (s < 0) break;
            const int e = b.indexOf(char(0x3E), s + 1); if (e < 0) break;
            QByteArray inner; int fixes = 0;
            playback::unescape_frame_data(b.mid(s + 1, e - s - 1), inner, &fixes);
            out.append({inner, false, -1, QStringLiteral("%1#%2").arg(name).arg(n++)});
            b.remove(0, e + 1);
        }
    } else if (fmt == QLatin1String("lenpfx")) {
        int p = 0, n = 0;
        while (p + 4 <= b.size()) {
            const quint32 len = quint8(b[p]) | quint8(b[p + 1]) << 8 | quint8(b[p + 2]) << 16
                              | quint32(quint8(b[p + 3])) << 24;
            p += 4;
            if (len == 0 || p + int(len) > b.size()) break;
            out.append({b.mid(p, len), true, 1, QStringLiteral("%1#%2").arg(name).arg(n++)});
            p += len;
        }
    } else {
        out.append({QByteArray(1, char(0)) + b, true, 1, name});
    }
    return out;
}

static std::unique_ptr<IProtocolParser> make_parser(int k) {
    switch (k) {
        case 0: return std::make_unique<NW_2021_Parser>();
        case 1: return std::make_unique<NW_2026_Parser>();
        case 2: return std::make_unique<GW_2022_Parser>();
        default: return std::make_unique<GW_2026_Parser>();
    }
}
static const char* kName[4] = {"NW_2021", "NW_2026", "GW_2022", "GW_2026"};

static ParseResult run(int k, const QByteArray& data, bool from_raw) {
    auto p = make_parser(k);
    MsduState st; ParseFilter flt;
    BplcFrame in; in.data = data; in.meta.from_raw = from_raw;
    if (from_raw) in.meta.is_rf = data.size() > 0 && data[0] != 0;
    return p->parse(in, st, flt);
}

static PacketEntry entry_of(const ParseResult& r) {
    PacketEntry e;
    e.accepted = r.accept; e.reason = r.reject_reason; e.meta = r.meta; e.mpdu = r.mpdu;
    e.protocol = entry_protocol_id(r.protocol); e.msdu_body = r.msdu_body; e.raw_wire = r.raw_wire;
    e.msdu = r.msdu; e.beacon = r.beacon; e.msdu_raw_base = r.msdu_raw_base;
    e.raw_bytes = r.payload_for_log; e.dissect_fields = r.dissect_fields;
    return e;
}

static bool pb_fail(const ParseResult& r) { for (bool ok : r.mpdu.pb_crc_oks) if (!ok) return true; return false; }
static bool good_candidate(const ParseResult& r) {
    return r.accept && r.mpdu.frame_type == 1 && r.mpdu.fch_crc_checked && r.mpdu.fch_crc_ok
        && r.mpdu.pb_num == 1 && r.mpdu.pb_crc_oks.size() == 1 && !pb_fail(r) && r.msdu.present
        && msdu_crc_state(r.msdu) == MsduCrcState::Ok && !r.msdu.summary.isEmpty()
        && r.msdu_raw_base > 0;
}
static int crc32_rel(const QVector<MsduFieldNode>& nodes) {
    for (const MsduFieldNode& n : nodes) {
        if (n.name == QLatin1String("MSDU CRC32") && n.rel_len == 4) return n.rel_start;
        const int c = crc32_rel(n.children);
        if (c >= 0) return c;
    }
    return -1;
}
static bool same_fc(const ParseResult& a, const ParseResult& b) {
    return a.mpdu.frame_type == b.mpdu.frame_type && a.mpdu.src_tei == b.mpdu.src_tei
        && a.mpdu.dst_tei == b.mpdu.dst_tei && a.mpdu.net_id == b.mpdu.net_id;
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    const QString R = argc > 1 ? QString::fromLocal8Bit(argv[1]) : QStringLiteral(REPO_ROOT);
    QVector<Input> inputs;
    inputs += load("wire",   R + "/unit_test/frames/frame-probe/nw_log_tail_pb_crc_fail.bin");
    inputs += load("wire",   R + "/unit_test/frames/frame-probe/nw_frame_20261021.bin");
    inputs += load("wire",   R + "/unit_test/frames/frame-probe/nw_frame_20261022_full.bin");
    inputs += load("lenpfx", R + "/unit_test/protocol-gw/gw-learn-probe/crafted.bin");
    inputs += load("wire",   R + "/unit_test/ci/roundtrip/roundtrip_test.bin");
    std::printf("inputs: %d frames\n", int(inputs.size()));
    const QColor kRed(224, 64, 64);

    // 0) 南网线上帧原样:FC OK + PB FAIL + MSDU OK(无需变异)
    if (!inputs.isEmpty()) {
        const ParseResult r = run(0, inputs.first().data, false);
        CHECK(r.accept && r.mpdu.fch_crc_ok && pb_fail(r), "NW live frame: FC OK + PB FAIL, accepted");
        CHECK(r.msdu.present && msdu_crc_state(r.msdu) == MsduCrcState::Ok && !r.msdu.summary.isEmpty(),
              "NW live frame: MSDU CRC32 OK => MSDU parsed");
        CHECK(frame_crc_red(entry_of(r)), "NW live frame: row red");
    }

    for (int k = 0; k < 4; ++k) {
        int cands = 0, nP = 0, nP_ok = 0, nM = 0, nM_ok = 0, nF = 0;
        QVector<PacketEntry> rows;
        QVector<QString> tags;
        for (const Input& in : inputs) {
            if (cands >= 3) break;
            const ParseResult g = run(k, in.data, in.from_raw);
            if (!good_candidate(g)) continue;
            const int moff = in.mpdu_off >= 0 ? in.mpdu_off : in.data.indexOf(g.payload_for_log);
            const int L = g.mpdu.pb_size;
            if (moff < 0 || moff + 16 + L > in.data.size()) continue;
            const quint8* b = reinterpret_cast<const quint8*>(in.data.constData()) + moff + 16;
            const quint32 c = crc24_lsb(b, L);
            if ((c & 0xFF) != b[L - 3] || ((c >> 8) & 0xFF) != b[L - 2] || ((c >> 16) & 0xFF) != b[L - 1])
                continue;   // 单块布局未能定位块尾 CRC24
            const int rel = crc32_rel(g.msdu.tree);
            if (rel < 0) continue;
            ++cands;
            const int crc24 = moff + 16 + L - 3;
            const int msdu_crc = moff + g.msdu_raw_base + rel;
            const QByteArray src_u8 = in.src.toUtf8();
            const char* src = src_u8.constData();
            std::printf("[%s] candidate %s pb_size=%d summary=%s pairs=%d\n", kName[k], src, L,
                        qPrintable(g.msdu.summary), int(g.msdu.tei_mac_pairs.size()));
            CHECK(!frame_crc_red(entry_of(g)), "%s %s: good frame not red", kName[k], src);

            // F:FCH 翻转 ⇒ DROP
            {
                QByteArray m = in.data; m[moff + 2] = char(quint8(m[moff + 2]) ^ 0xFF);
                const ParseResult r = run(k, m, in.from_raw);
                CHECK(!r.accept, "%s %s: FCH flip => DROP", kName[k], src);
                if (!r.accept) ++nF;
            }
            for (int i = 0; i < 3; ++i) {
                // P:只坏 PB CRC24 ⇒ 帧解析 + MSDU 解析(与好帧一致)+ 红
                {
                    QByteArray m = in.data; m[crc24 + i] = char(quint8(m[crc24 + i]) ^ 0xFF);
                    const ParseResult r = run(k, m, in.from_raw);
                    ++nP;
                    const PacketEntry e = entry_of(r);
                    CHECK(r.accept && r.mpdu.fch_crc_ok && pb_fail(r) && same_fc(r, g),
                          "%s %s P%d: FC OK + PB FAIL => frame parsed, FC fields unchanged", kName[k], src, i);
                    const bool parsed = r.msdu.present && msdu_crc_state(r.msdu) == MsduCrcState::Ok
                        && r.msdu.summary == g.msdu.summary
                        && r.msdu.tei_mac_pairs.size() == g.msdu.tei_mac_pairs.size()
                        && r.msdu.topo_event.kind == g.msdu.topo_event.kind
                        && r.msdu_body == g.msdu_body;
                    CHECK(parsed, "%s %s P%d: PB FAIL + MSDU CRC32 OK => MSDU parsed (present=%d crc=%d summary='%s')",
                          kName[k], src, i, int(r.msdu.present), int(msdu_crc_state(r.msdu)), qPrintable(r.msdu.summary));
                    CHECK(frame_crc_red(e), "%s %s P%d: row red", kName[k], src, i);
                    if (parsed && frame_crc_red(e)) ++nP_ok;
                    rows.append(e); tags.append(QStringLiteral("%1 P%2").arg(in.src).arg(i));
                }
                // M:PB CRC24 坏 + MSDU CRC32 坏 ⇒ MSDU 不采信、无学习、红
                {
                    QByteArray m = in.data;
                    m[crc24 + i] = char(quint8(m[crc24 + i]) ^ 0xFF);
                    m[msdu_crc + i] = char(quint8(m[msdu_crc + i]) ^ 0x5A);
                    const ParseResult r = run(k, m, in.from_raw);
                    ++nM;
                    const PacketEntry e = entry_of(r);
                    CHECK(r.accept && r.mpdu.fch_crc_ok && pb_fail(r) && same_fc(r, g),
                          "%s %s M%d: FC OK + PB FAIL => frame parsed", kName[k], src, i);
                    const bool rejected = msdu_crc_state(r.msdu) == MsduCrcState::Fail
                        && r.msdu.summary.isEmpty()
                        && r.msdu.tei_mac_pairs.isEmpty() && r.msdu.orig_srcs.isEmpty()
                        && r.msdu.topo_event.kind == TopoEventKind::Other
                        && r.msdu.topo_extra_events.isEmpty()
                        && r.msdu.msdu_src_mac == 0 && r.msdu.msdu_dst_mac == 0;
                    CHECK(rejected, "%s %s M%d: PB FAIL + MSDU CRC32 FAIL => MSDU not parsed/no learning (crc=%d summary='%s' pairs=%d)",
                          kName[k], src, i, int(msdu_crc_state(r.msdu)), qPrintable(r.msdu.summary),
                          int(r.msdu.tei_mac_pairs.size()));
                    CHECK(frame_crc_red(e), "%s %s M%d: row red", kName[k], src, i);
                    if (rejected && frame_crc_red(e)) ++nM_ok;
                    rows.append(e); tags.append(QStringLiteral("%1 M%2").arg(in.src).arg(i));
                }
            }
        }
        // UI:真实 PacketListModel 的 ForegroundRole
        int red_rows = 0;
        {
            PacketListModel model;
            for (int i = 0; i < rows.size(); ++i) { rows[i].index = i + 1; rows[i].search_text = make_search_text(rows[i]); }
            model.append_packets(rows);
            CHECK(model.rowCount() == rows.size(), "%s: model row count", kName[k]);
            for (int i = 0; i < model.rowCount(); ++i) {
                const QVariant fg = model.data(model.index(i, PacketListModel::COL_INFO), Qt::ForegroundRole);
                if (fg.value<QColor>() == kRed) ++red_rows;
                else CHECK(false, "%s %s: model row not red", kName[k], qPrintable(tags.value(i)));
            }
        }
        std::printf("PROTO %s candidates=%d fc_drop=%d pbbad_msduok=%d/%d pbbad_msdubad=%d/%d red_rows=%d/%d\n",
                    kName[k], cands, nF, nP_ok, nP, nM_ok, nM, red_rows, int(rows.size()));
        CHECK(cands >= 2, "%s: at least 2 usable fixture frames (got %d)", kName[k], cands);
    }
    std::printf(g_fail ? "RESULT: FAIL (%d failed, %d ok)\n" : "RESULT: ALL PASS (%d failed, %d ok)\n", g_fail, g_ok);
    return g_fail ? 1 : 0;
}
