/// @file nw_2021_tree.cpp
/// @brief 南网 NW_2021 协议字段树构建器实现
#include "nw_2021_tree.h"
#include "nw_2021_beacon_parser.h"
#include "i18n.h"

namespace {

// 南网字段值中文释义(与国网 gw_2022_tree 同风格:中文原文 + trl 英文翻译)
struct I18nReg {
    I18nReg() {
        trl::register_en("保留", "Reserved");
        trl::register_en("保留(按选择确认帧解析)", "Reserved (parsed as selective ACK)");
        trl::register_en("应用报文 LID(优先级)", "App LID (priority)");
        trl::register_en("网络管理 LID(自定义 0-255)", "Network-mgmt LID (custom 0-255)");
        trl::register_en("载波接入网络传输", "HPLC access network");
        trl::register_en("本标准版本号", "This Standard Version");
        trl::register_en("未知相线", "Unknown Phase");
        trl::register_en("A相线", "Phase A");
        trl::register_en("B相线", "Phase B");
        trl::register_en("C相线", "Phase C");
        trl::register_en("选择确认帧", "Selective ACK Frame");
        trl::register_en("网络搜索帧(抄控器)", "Network Search Frame (Meter Reader)");
        trl::register_en("同步帧(抄控器)", "Sync Frame (Meter Reader)");
        trl::register_en("SOF帧全部接收成功", "SOF frame fully received OK");
        trl::register_en("物理块存在CRC校验失败", "Some PB CRC Failed");
        trl::register_en("校验成功", "CRC ok");
        trl::register_en("全部校验失败", "All CRC Failed");
        trl::register_en("含解析错误", "Incl. Parse Errors");
        trl::register_en("物理层不检查报文 TEI", "Physical Layer Does Not Check TEI");
        trl::register_en("物理层检查报文 TEI", "Physical Layer Checks TEI");
        trl::register_en("重传报文", "Retransmitted Frame");
        trl::register_en("非重传报文", "Non-Retransmitted Frame");
        trl::register_en("上个带宽时隙已结束", "Previous Band Slot Ended");
        trl::register_en("上个带宽时隙未结束", "Previous Band Slot Not Ended");
        // 无线 MCS 释义(第2部分表129:分集次数/调制方式/码率)
        trl::register_en("分集4次 BPSK 码率1/2", "Diversity 4, BPSK, Code Rate 1/2");
        trl::register_en("分集2次 BPSK 码率1/2", "Diversity 2, BPSK, Code Rate 1/2");
        trl::register_en("分集2次 QPSK 码率1/2", "Diversity 2, QPSK, Code Rate 1/2");
        trl::register_en("分集1次 QPSK 码率1/2", "Diversity 1, QPSK, Code Rate 1/2");
        trl::register_en("分集1次 QPSK 码率4/5", "Diversity 1, QPSK, Code Rate 4/5");
        trl::register_en("分集1次 16QAM 码率1/2", "Diversity 1, 16QAM, Code Rate 1/2");
        trl::register_en("分集1次 16QAM 码率4/5", "Diversity 1, 16QAM, Code Rate 4/5");
    }
};
const I18nReg g_i18n_reg_nw_tree;

// MCS 取值文本「值 - 释义」(第2部分表129;7 以上为保留)
QString nw_mcs_text(quint8 mcs) {
    static const char* const kDesc[] = {
        "分集4次 BPSK 码率1/2", "分集2次 BPSK 码率1/2",
        "分集2次 QPSK 码率1/2", "分集1次 QPSK 码率1/2",
        "分集1次 QPSK 码率4/5", "分集1次 16QAM 码率1/2",
        "分集1次 16QAM 码率4/5",
    };
    const QString desc = (mcs <= 6) ? trl::L(kDesc[mcs]) : trl::L("保留");
    return QStringLiteral("%1 - %2").arg(mcs).arg(desc);
}

}  // namespace

void NW_2021_TreeBuilder::build(QTreeWidgetItem* root, const PacketEntry& e) {
    // ── MPDU Base(16B 帧控制,表10) ──
    auto* mpdu_base = tree_add_item(root, "MPDU Base", "", 0, 16);
    tree_add_bit_field(mpdu_base, "Frame Type",
        QStringLiteral("%1 (%2)").arg(e.mpdu.frame_type_name()).arg(e.mpdu.frame_type),
        0, 0, 3);
    {
        // 接入指示(表12):0=保留 1=MPDU 在宽带载波通信接入网络中传输
        QString conind = (e.mpdu.net_type == 1)
            ? QStringLiteral("1 - %1").arg(trl::L("载波接入网络传输"))
            : QStringLiteral("0 - %1").arg(trl::L("保留"));
        tree_add_bit_field(mpdu_base, "ConInd", conind, 0, 3, 1);
    }
    tree_add_bit_field(mpdu_base, "SNID", QStringLiteral("0x%1")
        .arg(e.mpdu.net_id, 1, 16, QChar('0')), 0, 4, 4);
    {
        // 标准版本号(表13):0=保留 1=本标准版本号(2=SPLC 帧由 NW_2026 会话解析;
        // NW_2021 会话下 version=2 帧按默认解析展示,"2 - 保留"为预期行为,用户决策)
        QString ver = (e.mpdu.version == 1)
            ? QStringLiteral("1 - %1").arg(trl::L("本标准版本号"))
            : QStringLiteral("%1 - %2").arg(e.mpdu.version).arg(trl::L("保留"));
        tree_add_bit_field(mpdu_base, "Version", ver, 12, 4, 4);
    }
    const QString fch_txt = !e.mpdu.fch_crc_checked ? QStringLiteral("N/A")
                          : (e.mpdu.fch_crc_ok ? QStringLiteral("OK") : QStringLiteral("FAIL"));
    tree_add_bit_field(mpdu_base, "FCH CRC24", fch_txt, 13, 0, 24);

    switch (static_cast<NW_2021_FrameType>(e.mpdu.frame_type)) {
    case NW_2021_FrameType::BEACON: {
        auto* bcn = tree_add_item(root, "BEACON", "");
        tree_add_bit_field(bcn, "TimeStamp", QStringLiteral("0x%1")
            .arg(e.mpdu.beacon_timestamp, 8, 16, QChar('0')), 1, 0, 32);
        tree_add_bit_field(bcn, "BeaconPeriodCount", QString::number(e.mpdu.beacon_period_cnt), 5, 0, 32);
        tree_add_bit_field(bcn, "Source TEI", QString::number(e.mpdu.src_tei), 9, 0, 12);
        if (e.meta.is_rf) {
            // 无线(第2部分表128):MCS(10,4,4,释义见表129) + PBLen 载荷PB大小(11,0,4)
            tree_add_bit_field(bcn, "MCS", nw_mcs_text(e.mpdu.mcs), 10, 4, 4);
            tree_add_bit_field(bcn, "PBLen", QString::number(e.mpdu.pblen), 11, 0, 4);
            // 保留(表128:(11,4,4)+(12,0,4))
            const quint8 rsv_hi = (e.raw_bytes.size() > 11)
                ? (quint8)(((quint8)e.raw_bytes[11] >> 4) & 0x0F) : 0;
            tree_add_bit_field(bcn, "RSV", QStringLiteral("0x%1").arg(rsv_hi, 1, 16, QChar('0')), 11, 4, 4);
            // 无线信标 FCH:短网络标识高位(12,0,1)+保留(12,1,3)
            const quint8 snid_hi = (e.raw_bytes.size() > 12) ? ((quint8)e.raw_bytes[12] & 0x01) : 0;
            tree_add_bit_field(bcn, "SNID High", QString::number(snid_hi), 12, 0, 1);
            const quint8 rsv_lo = (e.raw_bytes.size() > 12)
                ? (quint8)(((quint8)e.raw_bytes[12] >> 1) & 0x07) : 0;
            tree_add_bit_field(bcn, "RSV", QStringLiteral("0x%1").arg(rsv_lo, 1, 16, QChar('0')), 12, 1, 3);
        } else {
            // 载波:TMI(10,4,4) SymbolNum(11,0,9) 短网络标识高位(12,1,1) 相线(12,2,2)
            tree_add_bit_field(bcn, "TMI", QString::number(e.mpdu.tmi), 10, 4, 4);
            tree_add_bit_field(bcn, "Symbol Num", QString::number(e.mpdu.symbol_num), 11, 0, 9);
            {
                const quint8 b12 = (e.raw_bytes.size() > 12) ? (quint8)e.raw_bytes[12] : 0;
                const quint8 snid_hi = (b12 >> 1) & 0x01;
                tree_add_bit_field(bcn, "SNID High", QString::number(snid_hi), 12, 1, 1);
            }
            // 相线(表15):0=未知 1=A 2=B 3=C
            QString line;
            switch (static_cast<NW_2021_PhaseLine>(e.mpdu.beacon_line)) {
                case NW_2021_PhaseLine::ALL_LINES: line = trl::L("未知相线"); break;  // 表15:0=未知
                case NW_2021_PhaseLine::LINE_A:    line = trl::L("A相线"); break;
                case NW_2021_PhaseLine::LINE_B:    line = trl::L("B相线"); break;
                case NW_2021_PhaseLine::LINE_C:    line = trl::L("C相线"); break;
                default: line = QString::number(e.mpdu.beacon_line); break;
            }
            tree_add_bit_field(bcn, "Line",
                QStringLiteral("%1 - %2").arg(e.mpdu.beacon_line).arg(line), 12, 2, 2);
        }
        if (e.mpdu.pb_size > 0)
            tree_add_item(bcn, "PB Size", QString::number(e.mpdu.pb_size));
        if (e.beacon.present) {
            auto* load = tree_add_item(bcn, "Beacon Load", "");
            MsduRawMap rm;
            rm.base = 16;
            rm.pb_num = 1;
            rm.pb_size = 0;
            rm.fch_size = 16;
            rm.header_len = 4;
            rm.body = 0;
            tree_render_msdu(load, e.beacon.tree, rm, e.raw_bytes.mid(16));
        }
        break;
    }
    case NW_2021_FrameType::SOF: {
        auto* sof = tree_add_item(root, "SOF", "");
        tree_add_bit_field(sof, "Source TEI", QString::number(e.mpdu.src_tei), 1, 0, 12);
        tree_add_bit_field(sof, "Destination TEI", QString::number(e.mpdu.dst_tei), 2, 4, 12);
        // 链路标识符(LID)= 优先级/业务分类(表98/8.2.13):应用报文 LID 0-3,网络管理 LID 0-255 自定义
        tree_add_bit_field(sof, "Link ID",
            QStringLiteral("%1 - %2").arg(e.mpdu.link_id)
                .arg(e.mpdu.link_id <= 3 ? trl::L("应用报文 LID(优先级)")
                                         : trl::L("网络管理 LID(自定义 0-255)")),
            4, 0, 8);
        // SOF 可变域按介质分表独立渲染:载波走第5部分表16、无线走第2部分表131
        // (源/目的 TEI 与链路标识符两介质同坐标,已在上方共用渲染)
        const quint8* d = reinterpret_cast<const quint8*>(e.raw_bytes.constData());
        const int raw_sz = e.raw_bytes.size();
        if (e.meta.is_rf) {
            // 无线 SOF(第2部分表131):帧长(5,0,12)/载荷PB大小(6,4,4)/MCS(7,0,4)/
            // TEI过滤(7,4,1)/重传(7,5,1)/保留(7,6,2)/保留(8,0,32)/保留(12,0,4)
            tree_add_bit_field(sof, "Frame Length",
                QStringLiteral("%1 (x100us)").arg(e.mpdu.frame_len), 5, 0, 12);
            {
                // 载荷 PB 大小(第2部分表130):0-5 = 16/40/72/136/264/520 字节,其他保留
                static const int kRfPbSize[] = {16, 40, 72, 136, 264, 520};
                const quint8 code = e.mpdu.pblen;   // 载荷 PB 大小索引(表130)
                const QString desc = (code <= 5)
                    ? QStringLiteral("%1B").arg(kRfPbSize[code]) : trl::L("保留");
                tree_add_bit_field(sof, "PBLen",
                    QStringLiteral("%1 - %2").arg(code).arg(desc), 6, 4, 4);
            }
            tree_add_bit_field(sof, "MCS", nw_mcs_text(e.mpdu.mcs), 7, 0, 4);
            const quint8 tei_filter = (raw_sz > 7) ? ((d[7] >> 4) & 0x01) : 1;
            tree_add_bit_field(sof, "TEI Filter",
                tei_filter ? QStringLiteral("1 - %1").arg(trl::L("物理层不检查报文 TEI"))
                           : QStringLiteral("0 - %1").arg(trl::L("物理层检查报文 TEI")),
                7, 4, 1);
            tree_add_bit_field(sof, "ReSend",
                e.mpdu.re_send_flag ? QStringLiteral("1 - %1").arg(trl::L("重传报文"))
                                    : QStringLiteral("0 - %1").arg(trl::L("非重传报文")),
                7, 5, 1);
            const quint8 rsv2 = (raw_sz > 7) ? (quint8)((d[7] >> 6) & 0x03) : 0;
            tree_add_bit_field(sof, "RSV", QStringLiteral("0x%1").arg(rsv2, 1, 16, QChar('0')), 7, 6, 2);
            const quint32 rsv32 = (raw_sz > 11)
                ? (quint32)d[8] | ((quint32)d[9] << 8) | ((quint32)d[10] << 16) | ((quint32)d[11] << 24) : 0;
            tree_add_bit_field(sof, "RSV", QStringLiteral("0x%1").arg(rsv32, 8, 16, QChar('0')), 8, 0, 32);
            tree_add_bit_field(sof, "RSV", QString::number(e.mpdu.tmi_ext), 12, 0, 4);
        } else {
            // 载波 SOF(表20):短网络标识高位(5,0,1)+保留15b(5,1,15) + PBNum(7,0,4)/TMI(7,4,4)/FrameLen(8,0,12)
            //   + 保留9b(9,4,9) + TEI过滤(10,5,1)/重传(10,6,1)/符号数(10,7,9) + TMI_EXT(12,0,4)
            // 短网络标识高位(表20:SNID 5bit 的高1bit,与 FCH 低位共同构成 SNID)
            const quint8 snid_hi = (raw_sz > 5) ? (d[5] & 0x01) : 0;
            tree_add_bit_field(sof, "SNID High", QString::number(snid_hi), 5, 0, 1);
            // 保留 15b(字节5 bit1-7 + 字节6)
            const quint16 rsv0 = (raw_sz > 6)
                ? (quint16)(((quint8)d[5] >> 1) | ((quint16)(quint8)d[6] << 7)) : 0;
            tree_add_bit_field(sof, "RSV", QStringLiteral("0x%1").arg(rsv0, 4, 16, QChar('0')), 5, 1, 15);
            // 位段节点显示线值(归一门前留存的原始 PBNum);采用块数由下方 PB 块节点数体现。
            tree_add_bit_field(sof, "PB Num", QString::number(e.mpdu.pb_num_field), 7, 0, 4);
            tree_add_bit_field(sof, "TMI", QString::number(e.mpdu.tmi), 7, 4, 4);
            tree_add_bit_field(sof, "Frame Length",
                QStringLiteral("%1 (x10us)").arg(e.mpdu.frame_len), 8, 0, 12);
            // 保留 9b(字节9 bit4-7 + 字节10 bit0-4)
            const quint16 rsv1 = (raw_sz > 10) ? (quint16)(((d[9] >> 4) & 0x0F) | ((d[10] & 0x1F) << 4)) : 0;
            tree_add_bit_field(sof, "RSV", QStringLiteral("0x%1").arg(rsv1, 3, 16, QChar('0')), 9, 4, 9);
            // TEI 过滤标志位(表17,固定为1)
            const quint8 tei_filter = (raw_sz > 10) ? ((d[10] >> 5) & 0x01) : 1;
            tree_add_bit_field(sof, "TEI Filter",
                tei_filter ? QStringLiteral("1 - %1").arg(trl::L("物理层不检查报文 TEI"))
                           : QStringLiteral("0 - %1").arg(trl::L("物理层检查报文 TEI")),
                10, 5, 1);
            // 重传标志位(表18)
            tree_add_bit_field(sof, "ReSend",
                e.mpdu.re_send_flag ? QStringLiteral("1 - %1").arg(trl::L("重传报文"))
                                    : QStringLiteral("0 - %1").arg(trl::L("非重传报文")),
                10, 6, 1);
            // 符号数(表16)
            tree_add_bit_field(sof, "Symbol Num", QString::number(e.mpdu.symbol_num), 10, 7, 9);
            tree_add_bit_field(sof, "TMI_EXT", QString::number(e.mpdu.tmi_ext), 12, 0, 4);
        }
        tree_add_item(sof, "PB Size", QString::number(e.mpdu.pb_size));

        // 逐 PB 块渲染:南网 PB 头 4B + 数据 pb_size-8 B + 保留 1B + CRC24 3B
        {
            const int header_len = 4;
            const int body_len   = e.mpdu.pb_size - 8;
            const int pb_num     = (e.mpdu.pb_num > 0) ? e.mpdu.pb_num : 1;
            const quint8* d = reinterpret_cast<const quint8*>(e.raw_bytes.constData());
            const int raw_sz = e.raw_bytes.size();
            for (int bi = 0; bi < pb_num; ++bi) {
                const int blk_off = 16 + bi * e.mpdu.pb_size;
                const bool multi = pb_num > 1;
                // PB Header(4B:序列号 16b + 保留 16b,表23)
                {
                    quint16 seq = 0;
                    quint16 rsv = 0;
                    if (blk_off + 4 <= raw_sz) {
                        seq = (quint16)(d[blk_off] | (d[blk_off + 1] << 8));
                        rsv = (quint16)(d[blk_off + 2] | (d[blk_off + 3] << 8));
                    }
                    auto* pbh = tree_add_item(sof,
                        multi ? QStringLiteral("PB Header (%1/%2)").arg(bi).arg(pb_num)
                              : QStringLiteral("PB Header"),
                        QStringLiteral("4 B"),
                        blk_off, header_len);
                    tree_add_bit_field(pbh, "SeqNum", QString::number(seq), blk_off, 0, 16);
                    tree_add_bit_field(pbh, "RSV", QStringLiteral("0x%1").arg(rsv, 4, 16, QChar('0')),
                        blk_off + 2, 0, 16);
                }
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
                // 保留字节(块体后、CRC24 前 1B,表7)
                {
                    const int rsv_off = blk_off + e.mpdu.pb_size - 4;
                    const quint8 rsv = (rsv_off >= 0 && rsv_off < raw_sz) ? d[rsv_off] : 0;
                    tree_add_bit_field(sof, "RSV", QStringLiteral("0x%1").arg(rsv, 2, 16, QChar('0')),
                        rsv_off, 0, 8);
                }
                // PB CRC24(块尾 3B,前 1B 是保留)
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
            rm.header_len = 4;
            rm.body = e.mpdu.pb_size - 8;
            // 序列号重排后拼接序≠raw 块序:用槽位表定位(BPLC 表133 序列号)
            rm.slot_raw_offset = tree_slot_raw_offsets(e.mpdu, 16, 4, 0xFF);
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
    case NW_2021_FrameType::ACK: {
        auto* ack = tree_add_item(root, "ACK", "");
        // 扩展帧类型值释义(表21):0=选择确认帧 1=网络搜索帧 2=同步帧 其他=保留
        // (未知扩展帧类型默认按选择确认帧解析并给出警告)
        const quint8 et = e.mpdu.ack_ext_type;
        QString ext_ev;
        switch (static_cast<NW_2021_AckExtType>(et)) {
        case NW_2021_AckExtType::Normal:        ext_ev = QStringLiteral("0 - %1").arg(trl::L("选择确认帧")); break;
        case NW_2021_AckExtType::Search:        ext_ev = QStringLiteral("1 - %1").arg(trl::L("网络搜索帧(抄控器)")); break;
        case NW_2021_AckExtType::Sync:          ext_ev = QStringLiteral("2 - %1").arg(trl::L("同步帧(抄控器)")); break;
        default: ext_ev = QStringLiteral("%1 - %2").arg(et).arg(trl::L("保留(按选择确认帧解析)")); break;
        }
        switch (static_cast<NW_2021_AckExtType>(et)) {
        case NW_2021_AckExtType::Search:
            tree_add_bit_field(ack, "DstAddr", QStringLiteral("0x%1")
                .arg(e.mpdu.ack_dst_addr, 12, 16, QChar('0')), 1, 0, 48);
            tree_add_bit_field(ack, "SearchTEI", QString::number(e.mpdu.ack_search_tei), 7, 0, 12);
            // 保留(表C-2:(8,4,4)、字节9-10)与序号(字节11):解析器未存,按原始字节呈现
            {
                const quint8* d = reinterpret_cast<const quint8*>(e.raw_bytes.constData());
                const int raw_sz = e.raw_bytes.size();
                const quint8 rsv0 = (raw_sz > 8) ? (quint8)((d[8] >> 4) & 0x0F) : 0;
                tree_add_bit_field(ack, "Reserved", QStringLiteral("0x%1").arg(rsv0, 1, 16, QChar('0')), 8, 4, 4);
                const quint16 rsv1 = (raw_sz > 10) ? (quint16)(d[9] | (d[10] << 8)) : 0;
                tree_add_bit_field(ack, "Reserved", QStringLiteral("0x%1").arg(rsv1, 4, 16, QChar('0')), 9, 0, 16);
                const quint8 seq = (raw_sz > 11) ? (quint8)d[11] : 0;
                tree_add_bit_field(ack, "SeqNum", QString::number(seq), 11, 0, 8);
            }
            tree_add_bit_field(ack, "ExtType", ext_ev, 12, 0, 4);
            break;
        case NW_2021_AckExtType::Sync:
            tree_add_bit_field(ack, "Timestamp", QStringLiteral("0x%1")
                .arg(e.mpdu.ack_sync_timestamp, 8, 16, QChar('0')), 1, 0, 32);
            tree_add_bit_field(ack, "SyncTEI", QString::number(e.mpdu.ack_sync_tei), 5, 0, 12);
            // 保留(表C-3:(6,4,4)、字节7-10)与序号(字节11):解析器未存,按原始字节呈现
            {
                const quint8* d = reinterpret_cast<const quint8*>(e.raw_bytes.constData());
                const int raw_sz = e.raw_bytes.size();
                const quint8 rsv0 = (raw_sz > 6) ? (quint8)((d[6] >> 4) & 0x0F) : 0;
                tree_add_bit_field(ack, "Reserved", QStringLiteral("0x%1").arg(rsv0, 1, 16, QChar('0')), 6, 4, 4);
                const quint32 rsv1 = (raw_sz > 10)
                    ? (quint32)d[7] | ((quint32)d[8] << 8) | ((quint32)d[9] << 16) | ((quint32)d[10] << 24) : 0;
                tree_add_bit_field(ack, "Reserved", QStringLiteral("0x%1").arg(rsv1, 8, 16, QChar('0')), 7, 0, 32);
                const quint8 seq = (raw_sz > 11) ? (quint8)d[11] : 0;
                tree_add_bit_field(ack, "SeqNum", QString::number(seq), 11, 0, 8);
            }
            tree_add_bit_field(ack, "ExtType", ext_ev, 12, 0, 4);
            break;
        case NW_2021_AckExtType::Normal:
        default: {
            // 选择确认帧(表19);未知扩展帧类型默认按选择确认帧解析
            const quint8 r = e.mpdu.ack_rx_res;
            QString rv;
            if (r == 0) rv = QStringLiteral("0 - %1").arg(trl::L("SOF帧全部接收成功"));
            else if (r == 1) rv = QStringLiteral("1 - %1").arg(trl::L("物理块存在CRC校验失败"));
            else rv = QStringLiteral("%1 - %2").arg(r).arg(trl::L("保留"));
            tree_add_bit_field(ack, "RxRes", rv, 1, 0, 4);
            {
                const quint8 st = e.mpdu.ack_rx_status;
                QStringList oks;
                for (int i = 0; i < 4; ++i)
                    if (st & (1u << i)) oks << QStringLiteral("PB%1").arg(i);
                tree_add_bit_field(ack, "RxStatus",
                    QStringLiteral("0x%1 (%2)")
                        .arg(st, 1, 16, QChar('0'))
                        .arg(oks.isEmpty() ? trl::L("全部校验失败")
                                           : oks.join(QLatin1String(", ")) + QStringLiteral(" %1").arg(trl::L("校验成功"))),
                    1, 4, 4);
            }
            tree_add_bit_field(ack, "Destination TEI", QString::number(e.mpdu.dst_tei), 2, 0, 12);
            tree_add_bit_field(ack, "RxPBNum",
                QStringLiteral("%1 (%2)").arg(e.mpdu.ack_rx_pb_num).arg(trl::L("含解析错误")),
                3, 4, 4);
            // 保留(表19:byte4-11, 64bit)
            {
                quint64 rsv = 0;
                const int avail = e.raw_bytes.size() - 4;
                for (int i = 0; i < 8 && i < avail; ++i)
                    rsv = (rsv << 8) | (quint8)e.raw_bytes[4 + i];
                tree_add_bit_field(ack, "Reserved",
                    QStringLiteral("0x%1").arg(rsv, 16, 16, QChar('0')), 4, 0, 64);
            }
            // 扩展帧类型(表19:byte12 bit0-3)
            tree_add_bit_field(ack, "ExtType", ext_ev, 12, 0, 4);
            break;
        }
        }
        break;
    }
    case NW_2021_FrameType::COORD: {
        auto* coord = tree_add_item(root, "COORD", "");
        {
            // 邻居网络位图(表22):bit i 对应 SNID i+1,置 1 表示收到过该网络报文
            QStringList heard;
            for (int i = 0; i < 16; ++i)
                if (e.mpdu.coord_neighbour_nid & (1u << i))
                    heard << QStringLiteral("SNID %1").arg(i + 1);
            tree_add_bit_field(coord, "NeighbourNIDBitMap",
                heard.isEmpty()
                    ? QStringLiteral("0x%1").arg(e.mpdu.coord_neighbour_nid, 4, 16, QChar('0'))
                    : QStringLiteral("0x%1 (%2)").arg(e.mpdu.coord_neighbour_nid, 4, 16, QChar('0'))
                          .arg(heard.join(QLatin1String(", "))),
                1, 0, 16);
        }
        // 字节3:载波为保留(表22);无线为本网络无线信道编号(第2部分表127)
        {
            const quint8 b3 = (e.raw_bytes.size() > 3) ? (quint8)e.raw_bytes[3] : 0;
            if (e.meta.is_rf)
                tree_add_bit_field(coord, "RF Channel", QString::number(b3), 3, 0, 8);
            else
                tree_add_bit_field(coord, "RSV", QStringLiteral("0x%1").arg(b3, 2, 16, QChar('0')), 3, 0, 8);
        }
        tree_add_bit_field(coord, "RSV1", QStringLiteral("0x%1")
            .arg(e.mpdu.coord_rsv1, 3, 16, QChar('0')), 4, 0, 10);
        tree_add_bit_field(coord, "TimeDuration", QStringLiteral("%1 (x40ms)").arg(e.mpdu.coord_duration), 5, 2, 14);
        tree_add_bit_field(coord, "RSV2", QString::number(e.mpdu.coord_rsv2), 7, 0, 1);
        {
            // 带宽结束标志位(表22):1=上个带宽时隙已结束 0=未结束
            QString flag = (e.mpdu.coord_band_end_flag == 1)
                ? QStringLiteral("1 - %1").arg(trl::L("上个带宽时隙已结束"))
                : QStringLiteral("0 - %1").arg(trl::L("上个带宽时隙未结束"));
            tree_add_bit_field(coord, "BandSlotEndFlag", flag, 7, 1, 1);
        }
        if (e.meta.is_rf) {
            // 无线(第2部分表127):(7,2,2) 为本网络无线 option,(7,4,4) 为保留
            tree_add_bit_field(coord, "RF Option", QString::number(e.mpdu.coord_rsv3 & 0x03), 7, 2, 2);
            tree_add_bit_field(coord, "RSV", QStringLiteral("0x%1")
                .arg((e.mpdu.coord_rsv3 >> 2) & 0x0F, 1, 16, QChar('0')), 7, 4, 4);
        } else {
            // 保留(表22:byte7 bit2-7, 6b)
            tree_add_bit_field(coord, "RSV3", QStringLiteral("0x%1")
                .arg(e.mpdu.coord_rsv3, 2, 16, QChar('0')), 7, 2, 6);
        }
        tree_add_bit_field(coord, "BandSlotEndOffset", QStringLiteral("%1 (x4ms)").arg(e.mpdu.coord_band_end_offset), 8, 0, 16);
        tree_add_bit_field(coord, "BandSlotStartOffset", QStringLiteral("%1 (x4ms)").arg(e.mpdu.coord_band_start_offset), 10, 0, 16);
        tree_add_bit_field(coord, "RSV0", QStringLiteral("0x%1")
            .arg(e.mpdu.coord_rsv0, 1, 16, QChar('0')), 12, 0, 4);
        break;
    }
    }
}
