/// @file gw_2022_tree.cpp
/// @brief 国网 GW_2022 协议字段树构建器实现
#include "gw_2022_tree.h"
#include "i18n.h"
#include "gw_2022_mcs.h"

namespace {

// Link ID 中文释义(国网 SOF 链路标识符)
struct I18nReg {
    I18nReg() {
        trl::register_en("报文优先级(越小越低)", "Message Priority (Smaller = Lower)");
        trl::register_en("业务分类LID", "Service-Class LID");
        trl::register_en("无效值", "Invalid Value");
        trl::register_en("广播报文", "Broadcast Frame");
        trl::register_en("非广播报文", "Non-Broadcast Frame");
        trl::register_en("重传报文", "Retransmitted Frame");
        trl::register_en("非重传报文", "Non-Retransmitted Frame");
        trl::register_en("预留信息段", "Reserved for Future Encryption");
        trl::register_en("保留", "Reserved");
        // 无线 MCS 释义(表28:分集次数/调制方式/码率)
        trl::register_en("分集4次 BPSK 码率1/2", "Diversity 4, BPSK, Code Rate 1/2");
        trl::register_en("分集2次 BPSK 码率1/2", "Diversity 2, BPSK, Code Rate 1/2");
        trl::register_en("分集2次 QPSK 码率1/2", "Diversity 2, QPSK, Code Rate 1/2");
        trl::register_en("分集1次 QPSK 码率1/2", "Diversity 1, QPSK, Code Rate 1/2");
        trl::register_en("分集1次 QPSK 码率4/5", "Diversity 1, QPSK, Code Rate 4/5");
        trl::register_en("分集1次 16QAM 码率1/2", "Diversity 1, 16QAM, Code Rate 1/2");
        trl::register_en("分集1次 16QAM 码率4/5", "Diversity 1, 16QAM, Code Rate 4/5");
    }
};
const I18nReg g_i18n_reg_gw_tree;

}  // namespace

void GW_2022_TreeBuilder::build(QTreeWidgetItem* root, const PacketEntry& e) {
    // ── MPDU Base(16B 帧控制) ──
    auto* mpdu_base = tree_add_item(root, "MPDU Base", "", 0, 16);
    tree_add_bit_field(mpdu_base, "Frame Type",
        QStringLiteral("%1 (%2)").arg(e.mpdu.frame_type_name()).arg(e.mpdu.frame_type),
        0, 0, 3);
    {
        // 网络类型(表15):0=MPDU在用电信息采集系统中传输,其他=保留 / 0=metering info collection, else reserved
        const QString nt = (e.mpdu.net_type == 0)
            ? QStringLiteral("0 - Metering info collection")
            : QStringLiteral("%1 - Reserved").arg(e.mpdu.net_type);
        tree_add_bit_field(mpdu_base, "Net Type", nt, 0, 3, 5);
    }
    tree_add_bit_field(mpdu_base, "Net ID", QStringLiteral("0x%1")
        .arg(e.mpdu.net_id, 6, 16, QChar('0')), 1, 0, 24);
    {
        // 标准版本号(表16):0=本标准,其他=待演进
        const QString ver = (e.mpdu.version == static_cast<quint8>(GW_2022_Version::THIS_STANDARD))
            ? QStringLiteral("0 (This standard)")
            : QStringLiteral("%1 (Reserved / to evolve)").arg(e.mpdu.version);
        tree_add_bit_field(mpdu_base, "Version", ver, 12, 4, 4);
    }
    const QString fch_txt = !e.mpdu.fch_crc_checked ? QStringLiteral("N/A")
                          : (e.mpdu.fch_crc_ok ? QStringLiteral("OK") : QStringLiteral("FAIL"));
    tree_add_bit_field(mpdu_base, "FCH CRC24", fch_txt, 13, 0, 24);

    switch (static_cast<GW_2022_FrameType>(e.mpdu.frame_type)) {
    case GW_2022_FrameType::BEACON: {
        auto* bcn = tree_add_item(root, "BEACON", "");
        tree_add_bit_field(bcn, "TimeStamp", QStringLiteral("0x%1")
            .arg(e.mpdu.beacon_timestamp, 8, 16, QChar('0')), 4, 0, 32);
        tree_add_bit_field(bcn, "Source TEI", QString::number(e.mpdu.src_tei), 8, 0, 12);
        {
            if (e.meta.is_rf) {
                // 无线信标(表27):MCS(9,4,4,释义表28)/载荷PB大小(10,0,4,表29)/保留16b
                const quint8 mcs = e.mpdu.mcs;
                const char* mcs_zh = gw_2022_mcs_desc(mcs);
                const QString mcs_desc = mcs_zh ? trl::L(mcs_zh) : trl::L("保留");
                tree_add_bit_field(bcn, "MCS",
                    QStringLiteral("%1 - %2").arg(mcs).arg(mcs_desc), 9, 4, 4);
                {
                    static const int kRfPbSize[] = {16, 40, 72, 136, 264, 520};
                    const quint8 code = e.mpdu.pb_num_field;
                    const QString desc = (code <= 5)
                        ? QStringLiteral("%1B").arg(kRfPbSize[code]) : QStringLiteral("Reserved");
                    tree_add_bit_field(bcn, "Payload PB Size",
                        QStringLiteral("%1 - %2").arg(code).arg(desc), 10, 0, 4);
                }
                tree_add_bit_field(bcn, "Reserved",
                    QStringLiteral("0x%1").arg(e.mpdu.beacon_rsv, 4, 16, QChar('0')), 10, 4, 16);
            } else {
                tree_add_bit_field(bcn, "TMI", QString::number(e.mpdu.tmi), 9, 4, 4);
                tree_add_bit_field(bcn, "Symbol Num", QString::number(e.mpdu.symbol_num), 10, 0, 9);
                {
                    // 相线(表18):0=未知相线 1=A 2=B 3=C / 0=unknown, 1=A, 2=B, 3=C
                    static const char* ph[] = {"Unknown", "LineA", "LineB", "LineC"};
                    const quint8 pl = e.mpdu.beacon_line;
                    tree_add_bit_field(bcn, "Line",
                        (pl <= 3) ? QStringLiteral("%1 - %2").arg(pl).arg(QLatin1String(ph[pl]))
                                  : QStringLiteral("%1 - Reserved").arg(pl),
                        11, 1, 2);
                }
                // 保留(表17:(11,3,5)+(12,0,4),共 9b)
                tree_add_bit_field(bcn, "Reserved",
                    QStringLiteral("0x%1").arg(e.mpdu.beacon_rsv & 0x1FF, 3, 16, QChar('0')), 11, 3, 9);
            }
        }
        if (e.mpdu.pb_size > 0)
            tree_add_item(bcn, "PB Size", QString::number(e.mpdu.pb_size));
        // Beacon Load(载荷区,字段树由解析器生成)
        if (e.beacon.present) {
            auto* load = tree_add_item(bcn, "Beacon Load", "");
            MsduRawMap rm;
            rm.base = 16;
            rm.pb_num = 1;
            rm.pb_size = 0;
            rm.fch_size = 16;
            rm.header_len = 1;
            rm.body = 0;
            tree_render_msdu(load, e.beacon.tree, rm, e.raw_bytes.mid(16));
        }
        break;
    }
    case GW_2022_FrameType::SOF: {
        auto* sof = tree_add_item(root, "SOF", "");
        tree_add_bit_field(sof, "Source TEI", QString::number(e.mpdu.src_tei), 4, 0, 12);
        tree_add_bit_field(sof, "Destination TEI", QString::number(e.mpdu.dst_tei), 5, 4, 12);
        {
            QString link_desc;
            if (e.mpdu.link_id <= 3)
                link_desc = trl::L("报文优先级(越小越低)");
            else if (e.mpdu.link_id <= 254)
                link_desc = trl::L("业务分类LID");
            else
                link_desc = trl::L("无效值");
            tree_add_bit_field(sof, "Link ID",
                QStringLiteral("0x%1 - %2").arg(e.mpdu.link_id, 2, 16, QChar('0')).arg(link_desc),
                7, 0, 8);
        }
        // 帧长单位:载波(表19)10 微秒、无线(表30)100 微秒
        tree_add_bit_field(sof, "Frame Length",
            QStringLiteral("%1 (%2)").arg(e.mpdu.frame_len)
                                      .arg(e.meta.is_rf ? QStringLiteral("x100us")
                                                        : QStringLiteral("x10us")),
            8, 0, 12);
        // 字节9 bit4-7 / 字节10-11 bit0:载波(表19)=物理块个数/符号数;无线(表30)=载荷PB大小/保留
        if (e.meta.is_rf) {
            // 载荷PB大小(表29):0-5 = 16/40/72/136/264/520 字节
            static const int kRfPbSize[] = {16, 40, 72, 136, 264, 520};
            const quint8  idx = e.mpdu.pb_num_field;
            const QString desc = (idx <= 5)
                ? QStringLiteral("%1B").arg(kRfPbSize[idx]) : QStringLiteral("Reserved");
            tree_add_bit_field(sof, "Payload PB Size",
                QStringLiteral("%1 - %2").arg(idx).arg(desc), 9, 4, 4);
            tree_add_bit_field(sof, "Reserved", QString::number(e.mpdu.symbol_num), 10, 0, 9);
        } else {
            tree_add_bit_field(sof, "PB Num", QString::number(e.mpdu.pb_num_field), 9, 4, 4);
            tree_add_bit_field(sof, "Symbol Num", QString::number(e.mpdu.symbol_num), 10, 0, 9);
        }
        // 广播标志位(表21):0=非广播报文 1=广播报文
        tree_add_bit_field(sof, "Broadcast",
            e.mpdu.bc_flag ? QStringLiteral("1 - %1").arg(trl::L("广播报文"))
                           : QStringLiteral("0 - %1").arg(trl::L("非广播报文")),
            11, 1, 1);
        // 重传标志位(表22):0=非重传报文 1=重传报文
        tree_add_bit_field(sof, "ReSend",
            e.mpdu.re_send_flag ? QStringLiteral("1 - %1").arg(trl::L("重传报文"))
                                : QStringLiteral("0 - %1").arg(trl::L("非重传报文")),
            11, 2, 1);
        // 加密标志位:预留信息段(文档无 0/1 标准语义)
        tree_add_bit_field(sof, "Encrypted",
            QStringLiteral("%1 (%2)").arg(e.mpdu.encryp_flag).arg(trl::L("预留信息段")),
            11, 3, 1);
        if (e.meta.is_rf) {
            // 无线(表30):字节11 bit4-7 = MCS(表28),字节12 bit0-3 = 保留
            // 表28 MCS 取值:0-6 为分集次数/调制方式/码率组合,7 以上保留
            const quint8 mcs = e.mpdu.mcs;
            const char* mcs_zh = gw_2022_mcs_desc(mcs);
            const QString mcs_desc = mcs_zh ? trl::L(mcs_zh) : trl::L("保留");
            tree_add_bit_field(sof, "MCS",
                QStringLiteral("%1 - %2").arg(mcs).arg(mcs_desc), 11, 4, 4);
            tree_add_bit_field(sof, "Reserved", QString::number(e.mpdu.tmi_ext), 12, 0, 4);
        } else {
            tree_add_bit_field(sof, "TMI", QString::number(e.mpdu.tmi), 11, 4, 4);
            tree_add_bit_field(sof, "TMI_EXT", QString::number(e.mpdu.tmi_ext), 12, 0, 4);
        }
        tree_add_item(sof, "PB Size", QString::number(e.mpdu.pb_size));

        // 逐 PB 块渲染:国网 PB 头 1B + 数据 pb_size-4 B + CRC24 3B
        {
            const int header_len = 1;
            const int body_len   = e.mpdu.pb_size - 4;
            const int pb_num     = (e.mpdu.pb_num > 0) ? e.mpdu.pb_num : 1;
            const quint8* d = reinterpret_cast<const quint8*>(e.raw_bytes.constData());
            const int raw_sz = e.raw_bytes.size();
            for (int bi = 0; bi < pb_num; ++bi) {
                const int blk_off = 16 + bi * e.mpdu.pb_size;
                const bool multi = pb_num > 1;
                // PB Header(1B:END/START/seq)
                quint8 h = (bi < e.mpdu.pb_heads.size())
                               ? e.mpdu.pb_heads[bi]
                               : (blk_off < raw_sz ? d[blk_off] : 0);
                QStringList flags;
                if (h & 0x80) flags << QStringLiteral("END");
                if (h & 0x40) flags << QStringLiteral("START");
                QString desc = flags.isEmpty()
                                   ? QStringLiteral("(continuation)")
                                   : flags.join(QLatin1Char('|'));
                tree_add_bit_field(sof,
                    multi ? QStringLiteral("PB Header (%1/%2)").arg(bi).arg(pb_num)
                          : QStringLiteral("PB Header"),
                    QStringLiteral("0x%1 (%2, seq=%3)")
                        .arg(h, 2, 16, QChar('0')).arg(desc).arg(h & 0x3F),
                    blk_off, 0, 8);
                // PB Body
                if (body_len > 0 && blk_off + header_len < raw_sz) {
                    auto* pb = tree_add_item(sof,
                        multi ? QStringLiteral("PB Body (%1/%2)").arg(bi).arg(pb_num)
                              : QStringLiteral("PB Body"),
                        QStringLiteral("%1 B").arg(body_len),
                        blk_off + header_len, body_len);
                    if (e.msdu.present && e.msdu.total_len > 0) {
                        int buf_off = bi * body_len;
                        int msdu_end_in_blk = e.msdu.total_len - buf_off;
                        if (msdu_end_in_blk > 0 && msdu_end_in_blk < body_len) {
                            tree_add_item(pb, "PB Padding",
                                QStringLiteral("%1 B (0x00 fill)")
                                    .arg(body_len - msdu_end_in_blk),
                                blk_off + header_len + msdu_end_in_blk,
                                body_len - msdu_end_in_blk);
                        }
                    }
                }
                // PB CRC24(块尾 3B)
                bool have = (blk_off + e.mpdu.pb_size) <= raw_sz;
                quint32 crc = 0;
                if (have) {
                    int o = blk_off + e.mpdu.pb_size - 3;
                    crc = (quint32)d[o] | ((quint32)d[o + 1] << 8) | ((quint32)d[o + 2] << 16);
                }
                // PB CRC 三态: 未校验(数组空) / 通过 / 失败
                const bool pb_checked = (bi < e.mpdu.pb_crc_oks.size());
                const bool okb = pb_checked ? e.mpdu.pb_crc_oks[bi] : false;
                tree_add_item(sof,
                    multi ? QStringLiteral("PB CRC24 (block %1/%2)").arg(bi).arg(pb_num)
                          : QStringLiteral("PB CRC24"),
                    have ? QStringLiteral("0x%1 %2").arg(crc, 6, 16, QChar('0'))
                                 .arg(pb_checked ? (okb ? "OK" : "FAIL") : "N/A")
                         : (pb_checked ? (okb ? "OK" : "FAIL") : "N/A"),
                    blk_off + e.mpdu.pb_size - 3, 3);
            }
        }

        // MSDU 字段树挂载
        if (e.msdu.present) {
            auto* msdu = tree_add_item(root, "MSDU (Reassembled)",
                QStringLiteral("%1 B  %2").arg(e.msdu_body.size()).arg(e.msdu.summary));
            MsduRawMap rm;
            rm.base = e.msdu_raw_base;
            rm.pb_num = (e.msdu_raw_base >= 0) ? 1 : (e.mpdu.pb_num > 0 ? e.mpdu.pb_num : 1);
            rm.pb_size = e.mpdu.pb_size;
            rm.fch_size = 16;
            rm.header_len = 1;
            rm.body = e.mpdu.pb_size - 4;
            // 序列号重排后拼接序≠raw 块序:用槽位表定位(表133/表47 序列号)
            rm.slot_raw_offset = tree_slot_raw_offsets(e.mpdu, 16, 1, 0x3F);
            tree_apply_msdu_range(msdu, rm, 0, e.msdu.total_len, e.msdu_body);
            tree_add_item(msdu, "Length", QString::number(e.msdu_body.size()));
            tree_render_msdu(msdu, e.msdu.tree, rm, e.msdu_body);
        } else if (!e.msdu_body.isEmpty()) {
            auto* msdu = tree_add_item(root, "MSDU (Reassembled)",
                QStringLiteral("%1 B").arg(e.msdu_body.size()));
            tree_add_item(msdu, "Length", QString::number(e.msdu_body.size()));
            tree_add_item(msdu, "Hex", QString(e.msdu_body.toHex(' ')));
        }
        break;
    }
    case GW_2022_FrameType::ACK: {
        auto* ack = tree_add_item(root, "ACK", "");
        // 选择确认帧(表23,载波);未知扩展帧类型(表25/表36"其他")默认按选择确认帧解析并警告
        const quint8 et = e.mpdu.ack_ext_type;
        const bool known = (et == static_cast<quint8>(GW_2022_AckExtType::Normal));
        {
            const quint8 rxres = e.mpdu.ack_rx_res;
            QString rv;
            if (static_cast<GW_2022_AckRxRes>(rxres) == GW_2022_AckRxRes::RECEIPT_OK)
                rv = QStringLiteral("0 - Receipt OK (all PB CRC passed)");
            else if (static_cast<GW_2022_AckRxRes>(rxres) == GW_2022_AckRxRes::RECEIPT_FAIL)
                rv = QStringLiteral("1 - Receipt FAIL (≥1 PB CRC failed)");
            else
                rv = QStringLiteral("%1 - Reserved").arg(rxres);
            tree_add_bit_field(ack, "RxRes", rv, 4, 0, 4);
            {
                const quint8 st = e.mpdu.ack_rx_status;
                QStringList oks;
                for (int i = 0; i < 4; ++i)
                    if (st & (1u << i)) oks << QStringLiteral("PB%1").arg(i + 1);
                tree_add_bit_field(ack, "RxStatus",
                    QStringLiteral("0x%1 (%2 CRC ok)")
                        .arg(st, 1, 16, QChar('0'))
                        .arg(oks.isEmpty() ? QStringLiteral("no PB") : oks.join(QLatin1String(", "))),
                    4, 4, 4);
            }
            tree_add_bit_field(ack, "Source TEI", QString::number(e.mpdu.src_tei), 5, 0, 12);
            tree_add_bit_field(ack, "Destination TEI", QString::number(e.mpdu.dst_tei), 6, 4, 12);
            tree_add_bit_field(ack, "RxPBNum", QString::number(e.mpdu.ack_rx_pb_num), 8, 0, 3);
            tree_add_bit_field(ack, "RSV0", QString::number(e.mpdu.ack_rsv0), 8, 3, 5);
            tree_add_bit_field(ack, "ChannelQuality", QStringLiteral("%1 dB").arg(e.mpdu.ack_channel_quality), 9, 0, 8);
            tree_add_bit_field(ack, "STALoad", QString::number(e.mpdu.ack_sta_load), 10, 0, 8);
            tree_add_bit_field(ack, "RSV1", QString::number(e.mpdu.ack_rsv1), 11, 0, 8);
            tree_add_bit_field(ack, "ExtFrameType",
                known ? QString::number(et)
                      : QStringLiteral("%1 - Reserved (parsed as selective ACK)").arg(et),
                12, 0, 4);
        }
        break;
    }
    case GW_2022_FrameType::COORD: {
        auto* coord = tree_add_item(root, "COORD", "");
        tree_add_bit_field(coord, "TimeDuration", QStringLiteral("%1 ms").arg(e.mpdu.coord_duration), 4, 0, 16);
        tree_add_bit_field(coord, "NextTimeSlotShift", QStringLiteral("%1 ms").arg(e.mpdu.coord_shift), 6, 0, 16);
        tree_add_bit_field(coord, "NeighbourNID", QStringLiteral("0x%1")
            .arg(e.mpdu.coord_neighbour_nid, 6, 16, QChar('0')), 8, 0, 24);
        tree_add_bit_field(coord, "NetRfChannel", QString::number(e.mpdu.coord_rf_channel), 11, 0, 8);
        tree_add_bit_field(coord, "RSV0", QString::number(e.mpdu.coord_rsv0), 12, 0, 4);
        break;
    }
    }
}
