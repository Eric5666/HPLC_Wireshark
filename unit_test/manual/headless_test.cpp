// Headless test:用 GW_2022_Parser 直接切帧并解析 replay_test.bin
// 不启动 Qt GUI,只验证协议解析器与 Python comdrv 一致
//
// Build: 放在 unit_test/manual/ 下,与 Qt 工程独立编译(链接 QtCore)

#include <QCoreApplication>
#include <QFile>
#include <QByteArray>
#include <QDebug>
#include <QDateTime>

#include "bplcframe.h"
#include "gw_2022_parser.h"
#include "statistics.h"

#include <cstdio>
#include <cstdint>
#include <functional>

// 哨兵切帧(0x3C..0x3E + 反转义 0x3D)
static bool extract_frame(QByteArray& buf, BplcFrame& out) {
    while (!buf.isEmpty()) {
        // 找 0x3C
        int idx = buf.indexOf(char(0x3C));
        if (idx < 0) { buf.clear(); return false; }
        buf.remove(0, idx + 1);
        // 找 0x3E
        idx = buf.indexOf(char(0x3E));
        if (idx < 0) return false;
        QByteArray esc = buf.left(idx);
        buf.remove(0, idx + 1);
        // 反转义
        QByteArray unesc;
        unesc.reserve(esc.size());
        for (int i = 0; i < esc.size(); ++i) {
            quint8 b = static_cast<quint8>(esc[i]);
            if (b == 0x3D && i + 1 < esc.size()) {
                ++i;
                unesc.append(static_cast<char>(0xFF ^ static_cast<quint8>(esc[i])));
            } else {
                unesc.append(static_cast<char>(b));
            }
        }
        out.data = unesc;
        out.meta.has_time_tag = false;
        return true;
    }
    return false;
}

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    qRegisterMetaType<GW_2022_Parser::Result>("GW_2022_Parser::Result");
    qRegisterMetaType<BplcFrame>("BplcFrame");
    qRegisterMetaType<PacketEntry>("PacketEntry");

    QString path = (argc > 1) ? QString::fromLocal8Bit(argv[1])
                              : QStringLiteral("D:\\code\\gitlab\\HPLC_HRF_GW\\monitor\\BPLC_STA_QtMonitor\\samples\\replay_test.bin");
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        qCritical() << "open failed:" << path;
        return 1;
    }
    QByteArray buf = f.readAll();
    f.close();

    std::printf("Loaded %lld bytes from %s\n",
                (long long)buf.size(), qPrintable(path));

    GW_2022_Parser parser;
    MsduState  msdu;
    GW_2022_Parser::Filter f0;
    // 默认全部接受
    f0.allow_beacon = f0.allow_sof = f0.allow_ack = f0.allow_coord = true;
    f0.link_hplc = f0.link_hrf = true;

    int frames = 0, accepted = 0, dropped = 0;
    int ftype_counts[8] = {0};
    QSet<quint32> nids;
    QHash<quint32, int> netid_count;
    int printed_sof = 0;
    int printed_bcn = 0;
    int printed_ack = 0;
    int printed_coord = 0;
    int printed_app = 0;
    int bcn_crc_ok = 0, bcn_crc_fail = 0, bcn_parse_fail = 0;
    int bcn_type_cnt[3] = {0, 0, 0};
    int bcn_item_total = 0;
    QHash<QString, int> msdu_types;
    QHash<QString, QString> msdu_sample;

    // 递归打印 MsduFieldNode 树(前 N 层)
    std::function<void(const QVector<MsduFieldNode>&, int)> dump_msdu =
        [&dump_msdu](const QVector<MsduFieldNode>& nodes, int depth) {
        for (const auto& n : nodes) {
            QString ind(depth * 2, ' ');
            std::printf("%s%s = %s\n", qPrintable(ind),
                        qPrintable(n.name), qPrintable(n.value));
            dump_msdu(n.children, depth + 1);
        }
    };

    BplcFrame fr;
    while (extract_frame(buf, fr)) {
        ++frames;
        auto r = parser.parse(fr, msdu, f0);
        if (r.accept) {
            ++accepted;
            ftype_counts[r.mpdu.frame_type]++;
            nids.insert(r.mpdu.net_id);
            netid_count[r.mpdu.net_id]++;
            if (r.mpdu.frame_type == 1 && printed_sof < 2) {
                ++printed_sof;
                std::printf("SOF #%d: src=%d dst=%d flen=%d pb=%d sym=%d tmi=%d\n",
                            frames, r.mpdu.src_tei, r.mpdu.dst_tei,
                            r.mpdu.frame_len, r.mpdu.pb_num,
                            r.mpdu.symbol_num, r.mpdu.tmi);
                if (r.msdu.present) {
                    std::printf("  MSDU summary: %s\n",
                                qPrintable(r.msdu.summary));
                    dump_msdu(r.msdu.tree, 2);
                }
            }
            // MSDU 类型统计(所有完整 MSDU)
            if (r.msdu.present) {
                msdu_types[r.msdu.summary]++;
                if (!msdu_sample.contains(r.msdu.summary) &&
                    r.msdu.summary.startsWith("MMe")) {
                    msdu_sample[r.msdu.summary] =
                        QString("SOF#%1").arg(frames);
                    std::printf("\n===== %s first sample (SOF#%d) =====\n",
                                qPrintable(r.msdu.summary), frames);
                    dump_msdu(r.msdu.tree, 1);
                }
                if (r.msdu.summary.startsWith("APP") && printed_app == 0) {
                    ++printed_app;
                    std::printf("\n===== APP first sample (SOF#%d) =====\n", frames);
                    dump_msdu(r.msdu.tree, 1);
                }
            }
            if (r.mpdu.frame_type == 0 && printed_bcn < 2) {
                ++printed_bcn;
                std::printf("BEACON #%d: ts=0x%08X src=%d sym=%d tmi=%d line=%d\n",
                            frames, r.mpdu.beacon_timestamp, r.mpdu.src_tei,
                            r.mpdu.symbol_num, r.mpdu.tmi, r.mpdu.beacon_line);
                if (r.beacon.present) {
                    std::printf("  Beacon Load: %s (type=%d netsn=%d period=%u item=%d)\n",
                                qPrintable(r.beacon.summary),
                                r.mpdu.beacon_type, r.mpdu.beacon_netsn,
                                r.mpdu.beacon_period_cnt, r.mpdu.beacon_item_num);
                    dump_msdu(r.beacon.tree, 2);
                }
            }
            // BEACON 载荷全量统计
            if (r.mpdu.frame_type == 0) {
                if (!r.beacon.present) {
                    ++bcn_parse_fail;
                } else if (r.beacon.summary.contains("FAIL")) {
                    ++bcn_crc_fail;
                } else {
                    ++bcn_crc_ok;
                }
                if (r.mpdu.beacon_type <= 2) bcn_type_cnt[r.mpdu.beacon_type]++;
                bcn_item_total += r.mpdu.beacon_item_num;
            }
            if (r.mpdu.frame_type == 2 && printed_ack < 2) {
                ++printed_ack;
                std::printf("ACK #%d: ext=%d rxstatus=%d src=%d dst=%d rxpb=%d chq=%d load=%d\n",
                            frames, r.mpdu.ack_ext_type, r.mpdu.ack_rx_status,
                            r.mpdu.src_tei, r.mpdu.dst_tei,
                            r.mpdu.ack_rx_pb_num, r.mpdu.ack_channel_quality,
                            r.mpdu.ack_sta_load);
            }
            if (r.mpdu.frame_type == 3 && printed_coord < 2) {
                ++printed_coord;
                std::printf("COORD #%d: dur=%d shift=%d nbrnid=0x%06X ch=%d rsv0=%d\n",
                            frames, r.mpdu.coord_duration, r.mpdu.coord_shift,
                            r.mpdu.coord_neighbour_nid, r.mpdu.coord_rf_channel,
                            r.mpdu.coord_rsv0);
            }
        } else {
            ++dropped;
            std::printf("  DROP frame %d: %s\n", frames,
                        qPrintable(r.reject_reason));
        }
    }

    std::printf("\n========== Qt 端解析结果 ==========\n");
    std::printf("Frames:     %d\n", frames);
    std::printf("Accepted:   %d\n", accepted);
    std::printf("Dropped:    %d\n", dropped);
    const char* names[] = {"BEACON","SOF","ACK","COORD","?","SEARCH","SWITCH","?"};
    for (int i = 0; i < 8; ++i) {
        if (ftype_counts[i] > 0) {
            std::printf("  %-10s (%d): %d\n", names[i], i, ftype_counts[i]);
        }
    }
    std::printf("Unique NetIDs: %d\n", int(nids.size()));
    for (auto nid : nids) {
        std::printf("  0x%06X  (count=%d)\n", nid, netid_count[nid]);
    }
    std::printf("-- MSDU 类型统计(完整 MSDU 数=%d) --\n", int(msdu_types.size()));
    for (auto it = msdu_types.constBegin(); it != msdu_types.constEnd(); ++it) {
        std::printf("  %-28s x%d%s%s\n", qPrintable(it.key()), it.value(),
                    msdu_sample.contains(it.key()) ? "  first@" : "",
                    qPrintable(msdu_sample.value(it.key())));
    }
    std::printf("-- BEACON 载荷统计 --\n");
    std::printf("  CRC32 OK=%d FAIL=%d 解析失败=%d 条目总数=%d\n",
                bcn_crc_ok, bcn_crc_fail, bcn_parse_fail, bcn_item_total);
    std::printf("  BeaconType: STA=%d PCO=%d CCO=%d\n",
                bcn_type_cnt[0], bcn_type_cnt[1], bcn_type_cnt[2]);
    std::printf("=====================================\n");

    // 期望(与 Python 原版 MPDU_Process 对照,2026-09-05 log 重转后):
    // 2457 frames, 0 drop; BEACON 871 / SOF 347 / ACK 170 / COORD 1069; NetID 0xCDA1D5
    bool ok = (frames == 2457 && dropped == 0 &&
               ftype_counts[0] == 871 && ftype_counts[1] == 347 &&
               ftype_counts[2] == 170 && ftype_counts[3] == 1069 &&
               nids.size() == 1 && nids.contains(0xCDA1D5));
    std::printf(ok ? "PASS\n" : "FAIL\n");
    return ok ? 0 : 1;
}
