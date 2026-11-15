// 单帧探针:3C/3E+3D 线上帧 -> NW_2021_Parser,打印信封/MPDU/MSDU 全量结果
#include <QCoreApplication>
#include <QFile>
#include <QByteArray>
#include <cstdio>
#include <functional>
#include "bplcframe.h"
#include "nw_2021_parser.h"

static bool extract_frame(QByteArray& buf, QByteArray& out) {
    while (!buf.isEmpty()) {
        int idx = buf.indexOf(char(0x3C));
        if (idx < 0) { buf.clear(); return false; }
        buf.remove(0, idx + 1);
        idx = buf.indexOf(char(0x3E));
        if (idx < 0) return false;
        QByteArray esc = buf.left(idx);
        buf.remove(0, idx + 1);
        QByteArray unesc;
        for (int i = 0; i < esc.size(); ++i) {
            quint8 b = (quint8)esc[i];
            // 与主程序 serialreader 同规则:0x3D xx -> 0xFF - xx
            if (b == 0x3D && i + 1 < esc.size()) { ++i; unesc.append((char)(0xFF - (quint8)esc[i])); }
            else unesc.append((char)b);
        }
        out = unesc;
        return true;
    }
    return false;
}

static void dump_msdu(const QVector<MsduFieldNode>& nodes, int depth) {
    for (const auto& n : nodes) {
        std::printf("%*s%s = %s\n", depth * 2, "", qPrintable(n.name), qPrintable(n.value));
        dump_msdu(n.children, depth + 1);
    }
}

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    if (argc < 2) { std::printf("usage: %s <nw_frame.bin>\n", argv[0]); return 2; }
    QFile file(QString::fromLocal8Bit(argv[1]));
    if (!file.open(QIODevice::ReadOnly)) { std::printf("cannot open\n"); return 1; }
    QByteArray buf = file.readAll();
    QByteArray raw;
    if (!extract_frame(buf, raw)) { std::printf("no frame\n"); return 1; }
    std::printf("unescaped inner bytes: %d\n", (int)raw.size());

    BplcFrame in; in.data = raw; in.meta.has_time_tag = false;
    NW_2021_Parser parser; MsduState st; ParseFilter f;
    auto r = parser.parse(in, st, f);
    std::printf("accept=%d\n", (int)r.accept);
    std::printf("meta: is_rf=%d channel=%d option=%d phr_mcs=%d ntb=0x%08x\n",
                (int)r.meta.is_rf, r.meta.channel, r.meta.option, r.meta.phr_mcs, r.meta.timestamp);
    const MpduInfo& m = r.mpdu;
    std::printf("mpdu: type=%d net_type=%d net_id=0x%x ver=%d src_tei=%d dst_tei=%d link_id=0x%x\n",
                m.frame_type, m.net_type, m.net_id, m.version, m.src_tei, m.dst_tei, m.link_id);
    std::printf("  frame_len=%d pb_num=%d pb_num_field=%d pblen=%d mcs=%d pb_size=%d symbol_num=%d tmi=%d tmi_ext=%d\n",
                m.frame_len, m.pb_num, m.pb_num_field, m.pblen, m.mcs, m.pb_size, m.symbol_num, m.tmi, m.tmi_ext);
    std::printf("  bc=%d resend=%d enc=%d fch_crc_ok=%d pb_crc_ok=%d pb_head=0x%02x\n",
                (int)m.bc_flag, (int)m.re_send_flag, (int)m.encryp_flag, (int)m.fch_crc_ok, (int)m.pb_crc_ok, m.pb_head);
    std::printf("  beacon: ts=%u line=%d type=%d netsn=%d cco_mac=%012llx period=%u rf_ch=%d rf_opt=%d items=%d rsv=0x%x\n",
                m.beacon_timestamp, m.beacon_line, m.beacon_type, m.beacon_netsn,
                (unsigned long long)m.beacon_cco_mac, m.beacon_period_cnt,
                m.beacon_rf_channel, m.beacon_rf_option, m.beacon_item_num, m.beacon_rsv);
    // MpduInfo 已无 coord_option:字节 7 bit2-3 归入保留位(NW_2021 coord_rsv3 = bit2-7),按 rsv0..3 打印
    std::printf("  coord: dur=%d shift=%d nbr_nid=0x%x rf_ch=%d rsv0=%d rsv1=%d rsv2=%d rsv3=%d band_end=%d end_off=%d start_off=%d\n",
                m.coord_duration, m.coord_shift, m.coord_neighbour_nid, m.coord_rf_channel,
                m.coord_rsv0, m.coord_rsv1, m.coord_rsv2, m.coord_rsv3,
                (int)m.coord_band_end_flag, m.coord_band_end_offset, m.coord_band_start_offset);
    std::printf("payload_for_log (MPDU) bytes: %d\n", (int)r.payload_for_log.size());
    std::printf("msdu: present=%d summary=%s\n", (int)r.msdu.present, qPrintable(r.msdu.summary));
    if (r.msdu.present) dump_msdu(r.msdu.tree, 1);
    return 0;
}
