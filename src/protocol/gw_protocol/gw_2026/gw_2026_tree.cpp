/// @file gw_2026_tree.cpp
/// @brief 国网 GW_2026 协议字段树构建器实现
#include "gw_2026_tree.h"
#include "i18n.h"
#include "gw_2026_mcs.h"
#include "common/fieldtools.h"

namespace {

// MCS 释义(HDC2.0 4-2 表18,与 gw_2026_mcs.h 中文 key 对应)+ 兜底词条
struct I18nReg {
    I18nReg() {
        trl::register_en("保留", "Reserved");
        trl::register_en("截断(帧长 %1B < 32B)", "Truncated (Frame Length %1B < 32B)");
        trl::register_en("广播报文", "Broadcast Frame");
        trl::register_en("非广播报文", "Non-Broadcast Frame");
        trl::register_en("重传报文", "Retransmitted Frame");
        trl::register_en("非重传报文", "Non-Retransmitted Frame");
        trl::register_en("预留信息段", "Reserved for Future Encryption");
        trl::register_en("信道探测帧无数据物理块, 表9 无 PB 字段",
                         "No Data PB in Channel Sounding Frame (Table 9 Has No PB Field)");
        // 无线 MCS 释义(HDC2.0 4-2 表18:分集次数/调制方式/码率)
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

void GW_2026_TreeBuilder::build(QTreeWidgetItem* root, const PacketEntry& e) {
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
        .arg(e.mpdu.net_id, 4, 16, QChar('0')), 1, 0, 16);
    {
        // 标准版本号(表4):0=HDC 1.0 1=HDC 2.0,其他保留
        QString ver;
        switch (static_cast<GW_2026_Version>(e.mpdu.version)) {
            case GW_2026_Version::HDC_1_0:
                ver = QStringLiteral("0 (HDC 1.0)");
                break;
            case GW_2026_Version::HDC_2_0:
                ver = QStringLiteral("1 (HDC 2.0)");
                break;
            default:
                ver = QStringLiteral("%1 (Reserved)").arg(e.mpdu.version);
                break;
        }
        tree_add_bit_field(mpdu_base, "Version", ver, 12, 4, 4);
    }
    const QString fch_txt = !e.mpdu.fch_crc_checked ? QStringLiteral("N/A")
                          : (e.mpdu.fch_crc_ok ? QStringLiteral("OK") : QStringLiteral("FAIL"));
    tree_add_bit_field(mpdu_base, "FCH CRC24", fch_txt, 13, 0, 24);

    switch (static_cast<GW_2026_FrameType>(e.mpdu.frame_type)) {
    case GW_2026_FrameType::BEACON: {
        auto* bcn = tree_add_item(root, "BEACON", "");
        tree_add_bit_field(bcn, "TimeStamp", QStringLiteral("0x%1")
            .arg(e.mpdu.beacon_timestamp, 8, 16, QChar('0')), 4, 0, 32);
        tree_add_bit_field(bcn, "Source TEI", QString::number(e.mpdu.src_tei), 8, 0, 12);
        {
            if (e.meta.is_rf) {
                // 无线信标(HDC2.0 4-2 表18):MCS(9,4,4,释义表18)/载荷PB大小(10,0,4,表18)/保留16b
                const quint8 mcs = e.mpdu.mcs;
                const char* mcs_zh = gw_2026_mcs_desc(mcs);
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
                    // FCH符号数(表5 (11,3,2)):0=短FCH 1=标准FCH 2=长FCH 3=保留
                    const quint8 fs = e.mpdu.beacon_fch_sym;
                    QString fs_desc;
                    switch (static_cast<GW_2026_FchSymNum>(fs)) {
                        case GW_2026_FchSymNum::SHORT:    fs_desc = QStringLiteral("0 - Short FCH"); break;
                        case GW_2026_FchSymNum::STANDARD: fs_desc = QStringLiteral("1 - Standard FCH"); break;
                        case GW_2026_FchSymNum::LONG:     fs_desc = QStringLiteral("2 - Long FCH"); break;
                        default:                          fs_desc = QStringLiteral("%1 - Reserved").arg(fs); break;
                    }
                    tree_add_bit_field(bcn, "FCH Symbol Num", fs_desc, 11, 3, 2);
                }
                {
                    // 相线(表18):0=未知相线 1=A 2=B 3=C / 0=unknown, 1=A, 2=B, 3=C
                    static const char* ph[] = {"Unknown", "LineA", "LineB", "LineC"};
                    const quint8 pl = e.mpdu.beacon_line;
                    tree_add_bit_field(bcn, "Line",
                        (pl <= 3) ? QStringLiteral("%1 - %2").arg(pl).arg(QLatin1String(ph[pl]))
                                  : QStringLiteral("%1 - Reserved").arg(pl),
                        11, 1, 2);
                }
                // 保留(表5:(11,5,7) 共 7b,12 全字节为可变区域尾)
                tree_add_bit_field(bcn, "Reserved",
                    QStringLiteral("0x%1").arg(e.mpdu.beacon_rsv & 0x7F, 2, 16, QChar('0')), 11, 5, 7);
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
    case GW_2026_FrameType::SOF: {
        auto* sof = tree_add_item(root, "SOF", "");
        const auto sof_st = static_cast<GW_2026_SofDataType>(e.mpdu.sof_data_type);
        const quint8* raw = reinterpret_cast<const quint8*>(e.raw_bytes.constData());
        const int rsz = e.raw_bytes.size();
        tree_add_bit_field(sof, "Source TEI", QString::number(e.mpdu.src_tei), 4, 0, 12);
        tree_add_bit_field(sof, "Destination TEI", QString::number(e.mpdu.dst_tei), 5, 4, 12);
        // 帧长单位:载波(表7/表9-13)10 微秒、无线(HDC2.0 4-2 表19)100 微秒
        tree_add_bit_field(sof, "Frame Length",
            QStringLiteral("%1 (%2)").arg(e.mpdu.frame_len)
                                      .arg(e.meta.is_rf ? QStringLiteral("x100us")
                                                        : QStringLiteral("x10us")),
            8, 0, 12);
        if (e.meta.is_rf) {
            // 无线(HDC2.0 4-2 表19,布局同 HDC 1.0 表30):字节9 bit4-7 = 载荷PB大小(表19),
            // 字节10-11 bit0 = 保留,字节11 bit4-7 = MCS(表18),字节12 bit0-3 = 保留
            static const int kRfPbSize[] = {16, 40, 72, 136, 264, 520};
            const quint8  idx = e.mpdu.pb_num_field;
            const QString desc = (idx <= 5)
                ? QStringLiteral("%1B").arg(kRfPbSize[idx]) : QStringLiteral("Reserved");
            tree_add_bit_field(sof, "Payload PB Size",
                QStringLiteral("%1 - %2").arg(idx).arg(desc), 9, 4, 4);
            tree_add_bit_field(sof, "Reserved", QString::number(e.mpdu.symbol_num), 10, 0, 9);
        } else {
            // 载波(表7):帧子类型/TF符号位置/TF符号数
            QString dt_desc;
            switch (static_cast<GW_2026_SofDataType>(e.mpdu.sof_data_type)) {
                case GW_2026_SofDataType::DATA:  dt_desc = QStringLiteral("0 - Data"); break;
                case GW_2026_SofDataType::SOUND: dt_desc = QStringLiteral("1 - Sounding"); break;
                case GW_2026_SofDataType::OFDMA: dt_desc = QStringLiteral("2 - OFDMA Downlink"); break;
                case GW_2026_SofDataType::TDA:   dt_desc = QStringLiteral("3 - TDA Downlink"); break;
                default: dt_desc = QStringLiteral("%1 - Reserved").arg(e.mpdu.sof_data_type); break;
            }
            tree_add_bit_field(sof, "Frame Type", dt_desc, 7, 0, 3);
            // 帧子类型专属布局:数据帧=表7 / 信道探测=表9 / OFDMA 下行=表10+11 / TDA 下行=表12+13
            static const int kEfcSym[] = {2, 4, 8, 12, 16};  // 扩展帧控制符号数取值(表10/表12)
            auto fch_sym_txt = [](quint8 fs) -> QString {
                switch (static_cast<GW_2026_FchSymNum>(fs)) {
                    case GW_2026_FchSymNum::SHORT:    return QStringLiteral("0 - Short FCH");
                    case GW_2026_FchSymNum::STANDARD: return QStringLiteral("1 - Standard FCH");
                    case GW_2026_FchSymNum::LONG:     return QStringLiteral("2 - Long FCH");
                    default:                          return QStringLiteral("%1 - Reserved").arg(fs);
                }
            };
            auto tf_sym_txt = [](quint8 tn) -> QString {
                // 表7/表9/表10/表12 同位同义:1-5 = 4/6/8/10/12 符号,其他保留
                return (tn >= 1 && tn <= 5)
                    ? QStringLiteral("%1 - %2").arg(tn).arg(tn * 2 + 2)
                    : QStringLiteral("%1 - Reserved").arg(tn);
            };
            auto band_txt = [](quint8 bd) -> QString {
                static const char* bd_desc[] = {
                    "1.953~11.96 MHz", "2.441~5.615 MHz", "0.781~2.930 MHz",
                    nullptr, "0.781~5.615 MHz", "0.781~11.96 MHz", "6.08~11.962 MHz"};
                return (bd <= 6 && bd_desc[bd])
                    ? QStringLiteral("%1 - %2").arg(bd).arg(QLatin1String(bd_desc[bd]))
                    : QStringLiteral("%1 - Reserved").arg(bd);
            };
            auto sta_num_txt = [](quint8 sn) -> QString {
                // 表10/表12 (7,3,2):0 保留/1:2 站/2:3 站/3:4 站
                return (sn >= 1 && sn <= 3)
                    ? QStringLiteral("%1 - %2 stations").arg(sn).arg(sn + 1)
                    : QStringLiteral("%1 - Reserved").arg(sn);
            };
            switch (sof_st) {
            case GW_2026_SofDataType::SOUND: {
                // 表9:子载波分组(7,3,2):0=4 个子载波一组/1=6 个(文档值表该行截断,2/3 保留)
                const quint8 sg = e.mpdu.sof_tf_symbol_pos;  // 同一比特位(7,3,2)
                tree_add_bit_field(sof, "Subcarrier Group",
                    (sg == 0) ? QStringLiteral("0 - 4 subcarriers/group")
                              : (sg == 1) ? QStringLiteral("1 - 6 subcarriers/group")
                                          : QStringLiteral("%1 - Reserved").arg(sg),
                    7, 3, 2);
                tree_add_bit_field(sof, "TF Symbol Num",
                    tf_sym_txt(e.mpdu.sof_tf_symbol_num), 7, 5, 3);
                // FCH符号数(表9 (9,4,2))——注意与表7 (9,7,2) 位置不同
                tree_add_bit_field(sof, "FCH Symbol Num",
                    fch_sym_txt(e.mpdu.sof_fch_sym_num), 9, 4, 2);
                // 训练序列频段标识(表9 (9,6,3) 跨字节 9,6-7+10,0)
                tree_add_bit_field(sof, "Training Seq Band",
                    band_txt((quint8)get_bits(raw, 9, 6, 3)), 9, 6, 3);
                // 信道探测训练序列符号数(表9 (10,1,7)):(v+1)*2
                const quint8 ts = (rsz > 10) ? (quint8)((raw[10] >> 1) & 0x7F) : 0;
                tree_add_bit_field(sof, "Training Seq Symbol Num",
                    QStringLiteral("%1 (%2 symbols)").arg(ts).arg((ts + 1) * 2), 10, 1, 7);
                // 扩展目的TEI(表9 (11,0,12))
                const quint16 ext_dst = (rsz > 12)
                    ? (quint16)(raw[11] | ((raw[12] & 0x0F) << 8)) : 0;
                tree_add_bit_field(sof, "Extended Dst TEI",
                    QString::number(ext_dst), 11, 0, 12);
                break;
            }
            case GW_2026_SofDataType::OFDMA: {
                // 表10:站点数(7,3,2)/TF符号数(7,5-7)/FCH符号数(9,4-5)
                const quint8 sn = e.mpdu.sof_tf_symbol_pos;  // (7,3,2)
                tree_add_bit_field(sof, "Station Num", sta_num_txt(sn), 7, 3, 2);
                tree_add_bit_field(sof, "TF Symbol Num",
                    tf_sym_txt(e.mpdu.sof_tf_symbol_num), 7, 5, 3);
                tree_add_bit_field(sof, "FCH Symbol Num",
                    fch_sym_txt(e.mpdu.sof_fch_sym_num), 9, 4, 2);
                // 数据载荷符号数(表10 (9,6,9) 跨字节,多站点取最大值)
                tree_add_bit_field(sof, "Payload Symbol Num",
                    QString::number((quint16)get_bits(raw, 9, 6, 9)), 9, 6, 9);
                // 扩展帧控制符号数(表10 (10,7,3) 跨 11,0-1):0:2/1:4/2:8/3:12/4:16 符号
                const quint8 ec = (quint8)get_bits(raw, 10, 7, 3);
                tree_add_bit_field(sof, "eFC Symbol Num",
                    (ec <= 4) ? QStringLiteral("%1 - %2 symbols").arg(ec).arg(kEfcSym[ec])
                              : QStringLiteral("%1 - Reserved").arg(ec), 10, 7, 3);
                // 站点0物理块个数(表10 (11,2,1)):0/1→1/2 块
                tree_add_bit_field(sof, "Sta0 PB Num",
                    QString::number((quint8)get_bits(raw, 11, 2, 1) + 1), 11, 2, 1);
                // 站点0分集拷贝模式(表10 (11,3,5))
                tree_add_bit_field(sof, "Sta0 DivCopy",
                    QString::number((quint8)get_bits(raw, 11, 3, 5)), 11, 3, 5);
                // 站点0RU(表10 (12,0,4));(12,4-7) 表10 该区间行提取缺失→RSV
                tree_add_bit_field(sof, "Sta0 RU",
                    QString::number((quint8)get_bits(raw, 12, 0, 4)), 12, 0, 4);
                tree_add_bit_field(sof, "RSV",
                    QStringLiteral("0x%1").arg((quint8)get_bits(raw, 12, 4, 4), 1, 16, QChar('0')),
                    12, 4, 4);
                // eFC(表11,自 byte16):站点1-3 ×[TEI 12b/RU 4b/分集拷贝 5b/PB个数 1b/RSV 2b],每站 3B,
                // 站点数由 FCH 站点数字段决定;其后加密标志位(eFC (9,0))+保留至 (12,0-7)
                // eFC(表11,固定 16B,内部字节 0-15,其中 13-15 为帧控制校验) ⇒ PB 自 byte32 起
                // 帧长不足 32B 时 eFC 不存在,本站循环跳过(新 H1 纵深防御;截断帧
                // 已由 assemble() 拒收,这里只防 get_bits(raw, 16..27) 越界读),并标注截断。
                const int n_efc = (rsz >= 32 && sn >= 1 && sn <= 3) ? sn : 0;
                if (rsz < 32 && sn >= 1 && sn <= 3)
                    tree_add_item(sof, "eFC", trl::L("截断(帧长 %1B < 32B)").arg(rsz));
                for (int s = 1; s <= n_efc; ++s) {
                    const int b = 16 + (s - 1) * 3;
                    tree_add_bit_field(sof, QString("eFC Sta%1 DstTEI").arg(s),
                        QString::number((quint16)get_bits(raw, b, 0, 12)), b, 0, 12);
                    tree_add_bit_field(sof, QString("eFC Sta%1 RU").arg(s),
                        QString::number((quint8)get_bits(raw, b + 1, 4, 4)), b + 1, 4, 4);
                    tree_add_bit_field(sof, QString("eFC Sta%1 DivCopy").arg(s),
                        QString::number((quint8)get_bits(raw, b + 2, 0, 5)), b + 2, 0, 5);
                    tree_add_bit_field(sof, QString("eFC Sta%1 PBNum").arg(s),
                        QString::number((quint8)get_bits(raw, b + 2, 5, 1) + 1), b + 2, 5, 1);
                    tree_add_bit_field(sof, QString("eFC Sta%1 RSV").arg(s),
                        QStringLiteral("0x%1").arg((quint8)get_bits(raw, b + 2, 6, 2), 1, 16, QChar('0')),
                        b + 2, 6, 2);
                }
                break;
            }
            case GW_2026_SofDataType::TDA: {
                // 表12:站点数(7,3-4)/TF符号数(7,5-7)/帧控制符号数(9,4-5)
                const quint8 sn = e.mpdu.sof_tf_symbol_pos;  // (7,3,2)
                tree_add_bit_field(sof, "Station Num", sta_num_txt(sn), 7, 3, 2);
                tree_add_bit_field(sof, "TF Symbol Num",
                    tf_sym_txt(e.mpdu.sof_tf_symbol_num), 7, 5, 3);
                tree_add_bit_field(sof, "FCH Symbol Num",
                    fch_sym_txt(e.mpdu.sof_fch_sym_num), 9, 4, 2);
                // 站点0数据载荷符号数(表12 (9,6,9) 跨字节)
                tree_add_bit_field(sof, "Sta0 Payload Symbol Num",
                    QString::number((quint16)get_bits(raw, 9, 6, 9)), 9, 6, 9);
                // 扩展帧控制符号数(表12 (10,7,3) 跨 11,0-1):0:2/1:4/2:8/3:12/4:16 符号
                const quint8 ec = (quint8)get_bits(raw, 10, 7, 3);
                tree_add_bit_field(sof, "eFC Symbol Num",
                    (ec <= 4) ? QStringLiteral("%1 - %2 symbols").arg(ec).arg(kEfcSym[ec])
                              : QStringLiteral("%1 - Reserved").arg(ec), 10, 7, 3);
                // 加密标志位(表12 (11,2,1)):预留信息段
                tree_add_bit_field(sof, "Encrypted (TDA)",
                    QStringLiteral("%1 (%2)").arg((quint8)get_bits(raw, 11, 2, 1))
                        .arg(trl::L("预留信息段")), 11, 2, 1);
                // 站点0分集拷贝模式(表12 (11,3,5))
                tree_add_bit_field(sof, "Sta0 DivCopy",
                    QString::number((quint8)get_bits(raw, 11, 3, 5)), 11, 3, 5);
                // 站点0TF和数据载荷频段标识(表12 (12,0,3))
                tree_add_bit_field(sof, "Sta0 TF & Payload Band",
                    band_txt((quint8)get_bits(raw, 12, 0, 3)), 12, 0, 3);
                // 站点0TF标识(表12 (12,3,1)):0=携带 1=不携带(帧长不含站点0 TF 传输时间)
                const quint8 tfi = (quint8)get_bits(raw, 12, 3, 1);
                tree_add_bit_field(sof, "Sta0 TF Flag",
                    (tfi == 0) ? QStringLiteral("0 - Carried")
                               : QStringLiteral("1 - Not carried"), 12, 3, 1);
                tree_add_bit_field(sof, "RSV",
                    QStringLiteral("0x%1").arg((quint8)get_bits(raw, 12, 4, 4), 1, 16, QChar('0')),
                    12, 4, 4);
                // eFC(表13,自 byte16):每站 4B×(站点数-1):
                //   TEI(b,0,12)/数据载荷符号数(b+1,4,9)/TF与数据载荷频段(b+2,5,3)/分集拷贝(b+3,0,5)/RSV(b+3,5,3)
                //   eFC(表13,固定 16B) ⇒ PB 自 byte32 起
                // 帧长不足 32B 时 eFC 不存在,本站循环跳过(新 H1 纵深防御;截断帧
                // 已由 assemble() 拒收,这里只防 get_bits(raw, 16..27) 越界读),并标注截断。
                const int n_efc = (rsz >= 32 && sn >= 1 && sn <= 3) ? sn : 0;
                if (rsz < 32 && sn >= 1 && sn <= 3)
                    tree_add_item(sof, "eFC", trl::L("截断(帧长 %1B < 32B)").arg(rsz));
                for (int s = 1; s <= n_efc; ++s) {
                    const int b = 16 + (s - 1) * 4;
                    tree_add_bit_field(sof, QString("eFC Sta%1 DstTEI").arg(s),
                        QString::number((quint16)get_bits(raw, b, 0, 12)), b, 0, 12);
                    tree_add_bit_field(sof, QString("eFC Sta%1 Payload Symbol Num").arg(s),
                        QString::number((quint16)get_bits(raw, b + 1, 4, 9)), b + 1, 4, 9);
                    tree_add_bit_field(sof, QString("eFC Sta%1 Band").arg(s),
                        band_txt((quint8)get_bits(raw, b + 2, 5, 3)), b + 2, 5, 3);
                    tree_add_bit_field(sof, QString("eFC Sta%1 DivCopy").arg(s),
                        QString::number((quint8)get_bits(raw, b + 3, 0, 5)), b + 3, 0, 5);
                    tree_add_bit_field(sof, QString("eFC Sta%1 RSV").arg(s),
                        QStringLiteral("0x%1").arg((quint8)get_bits(raw, b + 3, 5, 3), 1, 16, QChar('0')),
                        b + 3, 5, 3);
                }
                break;
            }
            case GW_2026_SofDataType::DATA:
            default: {
                // 表7(数据帧):TF符号位置(7,3,2):0=不携带TF 1=数据载荷之前 2=数据载荷之后
                const quint8 tp = e.mpdu.sof_tf_symbol_pos;
                QString tp_desc;
                switch (static_cast<GW_2026_TfSymbolPos>(tp)) {
                    case GW_2026_TfSymbolPos::NONE:  tp_desc = QStringLiteral("0 - No TF"); break;
                    case GW_2026_TfSymbolPos::FRONT: tp_desc = QStringLiteral("1 - Before Payload"); break;
                    case GW_2026_TfSymbolPos::BACK:  tp_desc = QStringLiteral("2 - After Payload"); break;
                    default:                         tp_desc = QStringLiteral("%1 - Reserved").arg(tp); break;
                }
                tree_add_bit_field(sof, "TF Symbol Position", tp_desc, 7, 3, 2);
                tree_add_bit_field(sof, "TF Symbol Num",
                    tf_sym_txt(e.mpdu.sof_tf_symbol_num), 7, 5, 3);
                tree_add_bit_field(sof, "PB Num", QString::number(e.mpdu.pb_num), 10, 7, 2);
                // FCH符号数(表7 (9,7,2) 跨字节):0=短FCH 1=标准FCH 2=长FCH
                tree_add_bit_field(sof, "FCH Symbol Num",
                    fch_sym_txt(e.mpdu.sof_fch_sym_num), 9, 7, 2);
                // 调制方式标识(表7 (10,1)):0=分集拷贝 1=动态加载;调制参数含义随方式切换
                const quint8 mm = e.mpdu.sof_mod_mode;
                const quint8 mp = e.mpdu.sof_mod_param;
                QString mm_desc;
                switch (static_cast<GW_2026_ModMode>(mm)) {
                    case GW_2026_ModMode::DIVERSITY_COPY:
                        mm_desc = QStringLiteral("0 - Diversity Copy (TMI %1)").arg(mp);
                        break;
                    case GW_2026_ModMode::DYNAMIC_LOAD:
                        mm_desc = QStringLiteral("1 - Dynamic Load (PB Type %1)").arg(mp);
                        break;
                    default:
                        mm_desc = QStringLiteral("%1 - Reserved").arg(mm);
                        break;
                }
                tree_add_bit_field(sof, "Modulation Mode", mm_desc, 10, 1, 1);
                tree_add_bit_field(sof, "Modulation Param", QString::number(mp), 10, 2, 5);
                break;
            }
            }
        }
        // 广播/重传/加密标志位(表19/表32/表7):仅无线与载波数据帧定义该组字段,
        // 信道探测(表9)/OFDMA(表10)/TDA(表12)的 byte11-12 为子类型专属布局,不渲染
        if (e.meta.is_rf || sof_st == GW_2026_SofDataType::DATA) {
        tree_add_bit_field(sof, "Broadcast",
            e.mpdu.bc_flag ? QStringLiteral("1 - %1").arg(trl::L("广播报文"))
                           : QStringLiteral("0 - %1").arg(trl::L("非广播报文")),
            11, 1, 1);
        // 重传标志位(表22/表33):0=非重传报文 1=重传报文
        tree_add_bit_field(sof, "ReSend",
            e.mpdu.re_send_flag ? QStringLiteral("1 - %1").arg(trl::L("重传报文"))
                                : QStringLiteral("0 - %1").arg(trl::L("非重传报文")),
            11, 2, 1);
        // 加密标志位:预留信息段(文档无 0/1 标准语义)
        tree_add_bit_field(sof, "Encrypted",
            QStringLiteral("%1 (%2)").arg(e.mpdu.encryp_flag).arg(trl::L("预留信息段")),
            11, 3, 1);
        }
        if (e.meta.is_rf) {
            // 无线(HDC2.0 4-2 表19):字节11 bit4-7 = MCS(表18),字节12 bit0-3 = 保留
            // 表18 MCS 取值:0-6 为分集次数/调制方式/码率组合,7 以上保留
            const quint8 mcs = e.mpdu.mcs;
            const char* mcs_zh = gw_2026_mcs_desc(mcs);
            const QString mcs_desc = mcs_zh ? trl::L(mcs_zh) : trl::L("保留");
            tree_add_bit_field(sof, "MCS",
                QStringLiteral("%1 - %2").arg(mcs).arg(mcs_desc), 11, 4, 4);
            tree_add_bit_field(sof, "Reserved", QString::number(e.mpdu.tmi_ext), 12, 0, 4);
        } else if (sof_st == GW_2026_SofDataType::DATA) {
            // 载波数据帧(表7):TF与数据载荷频段标识(11,4,3,取值表49)/数据载荷增益
            // (11,7)+(12,0-2)/动态加载表ID标识(12,3);信道探测(表9)/OFDMA(表10)/TDA(表12)
            // 的 byte9-12 为子类型专属布局,已在上方各分支渲染
            {
                const quint8 bd = e.mpdu.sof_band;
                static const char* bd_desc[] = {
                    "1.953~11.96 MHz", "2.441~5.615 MHz", "0.781~2.930 MHz",
                    nullptr, "0.781~5.615 MHz", "0.781~11.96 MHz", "6.08~11.962 MHz"};
                const QString bd_txt = (bd <= 6 && bd_desc[bd])
                    ? QStringLiteral("%1 - %2").arg(bd).arg(QLatin1String(bd_desc[bd]))
                    : QStringLiteral("%1 - Reserved").arg(bd);
                tree_add_bit_field(sof, "TF & Payload Band", bd_txt, 11, 4, 3);
            }
            tree_add_bit_field(sof, "Payload Gain",
                QStringLiteral("%1 - %2").arg(e.mpdu.sof_gain)
                    .arg(1.0 + e.mpdu.sof_gain * 0.0625, 0, 'f', 4),
                11, 7, 4);
            tree_add_bit_field(sof, "Dynamic Load Table ID",
                QString::number(e.mpdu.sof_load_table_id), 12, 3, 1);
        }
        tree_add_item(sof, "PB Size", QString::number(e.mpdu.pb_size));

        if (!e.mpdu.sof_stations.isEmpty()) {
            // ===== 多站点（OFDMA 表10/11 / TDA 表12/13）=====
            // 验证状态不在树里显示(维护信息见 gw_2026_sof_parser.cpp 多站点分支注释)。
            for (int si = 0; si < e.mpdu.sof_stations.size(); ++si) {
                const auto& st = e.mpdu.sof_stations[si];
                auto* snode = tree_add_item(sof,
                    QStringLiteral("PB Station %1 (TEI=%2, copy_mode=%3, %4 block(s) × %5B)")
                        .arg(si).arg(st.tei).arg(st.copy_mode).arg(st.pb_num).arg(st.pb_size),
                    QString());
                for (int j = 0; j < st.pb_heads.size(); ++j) {
                    const int off = st.block_base + j * st.pb_size;
                    const quint8 h = st.pb_heads[j];
                    const bool ok = (j < st.pb_crc_oks.size()) && st.pb_crc_oks[j];
                    tree_add_bit_field(snode, QStringLiteral("PB Header (%1/%2)").arg(j).arg(st.pb_num),
                        QStringLiteral("0x%1 (seq=%2)").arg(h, 2, 16, QChar('0')).arg(h & 0x3F),
                        off, 0, 8);
                    tree_add_item(snode, "PB Body", QStringLiteral("%1 B").arg(st.pb_size - 4),
                        off + 1, st.pb_size - 4);
                    tree_add_bit_field(snode, "PB CRC24",
                        ok ? QStringLiteral("OK") : QStringLiteral("FAIL"),
                        off + st.pb_size - 3, 0, 24);
                }
                if (!st.msdu.isEmpty())
                    tree_add_item(snode, "MSDU", QStringLiteral("%1 B").arg(st.msdu.size()));
            }
        } else if (e.mpdu.sof_data_type == 1) {
            // ===== 信道探测帧（表9）：无数据物理块 =====
            tree_add_item(sof, "PB", QStringLiteral("0 B (%1)").arg(trl::L("信道探测帧无数据物理块, 表9 无 PB 字段")));
        } else {
            // ===== 单站点数据帧（表7）：现状逻辑保持不变 =====
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
            // 序列号重排后拼接序≠raw 块序:用槽位表定位(国网 pb_head 低 6 位)
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
    case GW_2026_FrameType::ACK: {
        auto* ack = tree_add_item(root, "ACK", "");
        // 选择确认帧:BRU SNR 反馈标志=1 → 表15(反馈SNR版);=0 → 表14(不反馈SNR版)
        // 未知扩展帧类型(表14/表15"其他")默认按选择确认帧解析并警告
        const quint8 et = e.mpdu.ack_ext_type;
        const bool known = (et == static_cast<quint8>(GW_2026_AckExtType::Normal));
        {
            tree_add_bit_field(ack, "BRU SNR Flag",
                QStringLiteral("%1 (0: No BRU SNR, 1: Feedback BRU SNR)")
                    .arg(e.mpdu.ack_bru_snr_flag), 4, 0, 1);
            tree_add_bit_field(ack, "SAT ID Flag",
                QStringLiteral("%1 (0: SAT ID OK/N-A, 1: SAT ID Wrong)")
                    .arg(e.mpdu.ack_sat_id_flag), 4, 1, 1);
            if (e.mpdu.ack_bru_snr_flag) {
                // 表15(反馈SNR版):接收物理块个数(4,2,2)/接收状态(4,4,4)
                //   源TEI(5,0,12)/目的TEI(6,4,12)/BRU0-7 SNR(8-11,8×4b)
                const quint8 pn = e.mpdu.ack_rx_pb_num;
                tree_add_bit_field(ack, "RxPBNum",
                    QStringLiteral("%1 (%2 PB)").arg(pn).arg(pn + 1), 4, 2, 2);
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
                // BRU0-7 SNR(表15 (8-11) 8×4b):0=无效值;1-15 档 → SNR∈[-10+3(v-1), -7+3(v-1)]dB
                //   (以表15 行内定义为准——表16 档位表文档提取错位,数值不自洽,不采用)
                const quint8* d = reinterpret_cast<const quint8*>(e.raw_bytes.constData());
                for (int i = 0; i < 8; ++i) {
                    const quint8 v = (quint8)get_bits(d, 8 + i / 2, (i % 2) * 4, 4);
                    const QString desc = (v == 0)
                        ? QStringLiteral("0 - Invalid")
                        : QStringLiteral("%1 (SNR %2~%3dB)")
                              .arg(v).arg(-10 + 3 * (v - 1)).arg(-7 + 3 * (v - 1));
                    tree_add_bit_field(ack, QString("BRU%1 SNR").arg(i), desc,
                        8 + i / 2, (i % 2) * 4, 4);
                }
            } else {
            {
                // 接收结果(表14 (4,2,1)):0=接收成功 1=存在 PB CRC 失败
                const quint8 rxres = e.mpdu.ack_rx_res;
                QString rv;
                switch (static_cast<GW_2026_AckRxRes>(rxres)) {
                    case GW_2026_AckRxRes::RECEIPT_OK:
                        rv = QStringLiteral("0 - Receipt OK (all PB CRC passed)");
                        break;
                    case GW_2026_AckRxRes::RECEIPT_FAIL:
                        rv = QStringLiteral("1 - Receipt FAIL (≥1 PB CRC failed)");
                        break;
                    default:
                        rv = QStringLiteral("%1 - Reserved").arg(rxres);
                        break;
                }
                tree_add_bit_field(ack, "RxRes", rv, 4, 2, 1);
            }
            {
                // 接收物理块个数(表14 (4,3,2)):0-3 = 1-4 个物理块
                const quint8 pn = e.mpdu.ack_rx_pb_num;
                tree_add_bit_field(ack, "RxPBNum",
                    QStringLiteral("%1 (%2 PB)").arg(pn).arg(pn + 1), 4, 3, 2);
            }
            {
                const quint8 st = e.mpdu.ack_rx_status;
                QStringList oks;
                for (int i = 0; i < 4; ++i)
                    if (st & (1u << i)) oks << QStringLiteral("PB%1").arg(i + 1);
                tree_add_bit_field(ack, "RxStatus",
                    QStringLiteral("0x%1 (%2 CRC ok)")
                        .arg(st, 1, 16, QChar('0'))
                        .arg(oks.isEmpty() ? QStringLiteral("no PB") : oks.join(QLatin1String(", "))),
                    4, 5, 4);
            }
            tree_add_bit_field(ack, "Source TEI", QString::number(e.mpdu.src_tei), 5, 1, 12);
            tree_add_bit_field(ack, "Destination TEI", QString::number(e.mpdu.dst_tei), 6, 5, 12);
            tree_add_bit_field(ack, "RemainSTANum", QString::number(e.mpdu.ack_remain_sta_num), 8, 1, 2);
            tree_add_bit_field(ack, "RSV0", QString::number(e.mpdu.ack_rsv0), 8, 3, 5);
            tree_add_bit_field(ack, "ChannelQuality", QStringLiteral("%1 dB").arg(e.mpdu.ack_channel_quality), 9, 1, 8);
            tree_add_bit_field(ack, "STALoad", QString::number(e.mpdu.ack_sta_load), 10, 1, 8);
            tree_add_bit_field(ack, "RSV1", QString::number(e.mpdu.ack_rsv1), 11, 1, 8);
            }
            tree_add_bit_field(ack, "ExtFrameType",
                known ? QString::number(et)
                      : QStringLiteral("%1 - Reserved (parsed as selective ACK)").arg(et),
                12, 1, 4);
        }
        break;
    }
    case GW_2026_FrameType::COORD: {
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
