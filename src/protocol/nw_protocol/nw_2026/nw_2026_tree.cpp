/// @file nw_2026_tree.cpp
/// @brief 南网 NW_2026 协议字段树构建器实现
#include "nw_2026_tree.h"
#include "nw_2026_beacon_parser.h"
#include "common/fieldtools.h"   // get_bits(QByteArray 重载)
#include "i18n.h"

namespace {

// 南网字段值中文释义(与国网 gw_2022_tree 同风格:中文原文 + trl 英文翻译)
struct I18nReg {
    I18nReg() {
        trl::register_en("保留", "Reserved");
        trl::register_en("通过", "Pass");
        trl::register_en("失败", "Fail");
        trl::register_en("DL-OFDMA SACK 物理块", "DL-OFDMA SACK PB");
        trl::register_en("站点 %1 PB 分组 (TEI=%2, %3 块 × %4 B)",
                         "Station %1 PB Group (TEI=%2, %3 Block(s) x %4 B)");
        trl::register_en("级联体流 %1 B · %2", "Cascade body stream %1 B · %2");
        trl::register_en("PB 块不完整", "PB blocks incomplete");
        trl::register_en("声明 %1 块 / 实收 %2 块", "Declared %1 / Received %2");
        trl::register_en(" (超出级联流范围, 已停止解析)", " (beyond cascade stream, parsing stopped)");
        trl::register_en("不完整(无法校验)", "Incomplete (Cannot Verify)");
        trl::register_en("级联体流长度", "Cascade Body Length");
        trl::register_en("级联断开", "Cascade Break");
        trl::register_en("声明长度 %1 越界/非法,级联流提前终止", "Declared length %1 out of range/illegal, cascade stream terminated early");
        trl::register_en("PB 大小无效(查表未命中)", "Invalid PB Size (Table Lookup Miss)");
        trl::register_en("OFDMA SACK 帧无数据物理块", "No Data PB in OFDMA SACK Frame");
        trl::register_en("OFDMA trigger 帧无数据物理块", "No Data PB in OFDMA Trigger Frame");
        trl::register_en("DL-OFDMA 帧被截断(长度不足以容纳 eFC+PB)", "DL-OFDMA Frame Truncated (Too Short for eFC + PB)");
        trl::register_en("训练帧无数据物理块", "No Data PB for Training Frame");
        trl::register_en("单站点数据帧 PBNum=0(保留值,表23 仅定义 1-4)", "Single-Station PBNum=0 (Reserved, Table 23 Defines 1-4 Only)");
        trl::register_en("保留(按选择确认帧解析)", "Reserved (parsed as selective ACK)");
        trl::register_en("应用报文 LID(优先级)", "App LID (priority)");
        trl::register_en("网络管理 LID(自定义 0-255)", "Network-mgmt LID (custom 0-255)");
        trl::register_en("载波接入网络传输", "HPLC access network");
        trl::register_en(" (信标时间戳, NTB)", " (beacon timestamp, NTB)");
        trl::register_en(" (信标周期计数, NTB)", " (beacon period count, NTB)");
        trl::register_en(" (源 TEI)", " (source TEI)");
        trl::register_en(" (目的 TEI)", " (destination TEI)");
        trl::register_en(" (载荷 PB 大小索引)", " (payload PB size index)");
        trl::register_en(" (TMI 调制编号)", " (TMI modulation index)");
        trl::register_en(" (OFDM 符号数)", " (OFDM symbol count)");
        trl::register_en(" (物理块个数)", " (physical block count)");
        trl::register_en(" (TMI 扩展编号)", " (TMI extended index)");
        trl::register_en(" (序列号)", " (sequence number)");
        trl::register_en(" (搜索 TEI)", " (search TEI)");
        trl::register_en(" (同步 TEI)", " (sync TEI)");
        trl::register_en(" (目的地址)", " (destination address)");
        trl::register_en(" (SNID 高位)", " (SNID high bits)");
        trl::register_en(" (时间戳, NTB)", " (timestamp, NTB)");
        trl::register_en(" (流数)", " (stream count)");
        trl::register_en(" (训练频段标识)", " (training band flag)");
        trl::register_en(" (RU 信噪比估计标志)", " (RU SNR estimate flag)");
        trl::register_en(" (PL 频段标识)", " (PL band flag)");
        trl::register_en(" (子载波分组大小)", " (subcarrier group size)");
        trl::register_en("BPLC版本", "BPLC version");
        trl::register_en("SPLC版本", "SPLC version");
        trl::register_en("未知相线", "Unknown Phase");
        trl::register_en("A相线", "Phase A");
        trl::register_en("B相线", "Phase B");
        trl::register_en("C相线", "Phase C");
        trl::register_en("选择确认帧", "Selective ACK Frame");
        trl::register_en("网络搜索帧(抄控器)", "Network Search Frame (Meter Reader)");
        trl::register_en("同步帧(抄控器)", "Sync Frame (Meter Reader)");
        trl::register_en("不携带SNR信息", "No SNR Info");
        trl::register_en("接收当前帧SNR信息", "Current Frame SNR Info");
        trl::register_en("反馈TF评估基础RU信息", "TF basic RU SNR info");
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
        // SPLC 版 SOF(表23-26)新字段释义
        trl::register_en("多站点帧(OFDMA)", "Multi-Station Frame (OFDMA)");
        trl::register_en("单站点帧", "Single-Station Frame");
        trl::register_en("训练帧", "Training Frame");
        trl::register_en("数据帧", "Data Frame");
        trl::register_en("Bitloading训练帧", "Bitloading training frame");
        trl::register_en("MIMO训练帧", "MIMO training frame");
        trl::register_en("DL-OFDMA", "DL-OFDMA");
        trl::register_en("DL-OFDMA SACK", "DL-OFDMA SACK");
        trl::register_en("UL-OFDMA 数据帧", "UL-OFDMA Data Frame");
        trl::register_en("UL-OFDMA 数据帧(需 trigger)", "UL-OFDMA Data Frame (Trigger Required)");
        trl::register_en("DL-OFDMA SACK/UL-OFDMA", "DL-OFDMA SACK / UL-OFDMA");
        trl::register_en("UL-OFDMA trigger", "UL-OFDMA trigger");
        trl::register_en("UL-OFDMA SACK", "UL-OFDMA SACK");
        trl::register_en("个站点", " stations");
        trl::register_en("符号", " symbols");
        trl::register_en("使用Bitloading", "Use Bitloading");
        trl::register_en("使用TMI", "Use TMI");
        trl::register_en("PB大小", "PB size");
        trl::register_en("聚合帧(含级联头)", "Aggregated Frame (with Cascade Header)");
        trl::register_en("单MAC帧", "Single MAC Frame");
        trl::register_en("聚合首块", "First Cascade Block");
        trl::register_en("聚合末块", "Last Cascade Block");
        trl::register_en("DL-OFDMA 数据帧的 SACK 帧", "SACK Frame of DL-OFDMA Data Frame");
        trl::register_en("Bitloading 扩展帧", "Bitloading extended frame");
        trl::register_en("训练指示", "Training Indication");
        trl::register_en("训练指示拒绝", "Training Indication Reject");
        trl::register_en("训练请求", "Training Request");
        trl::register_en("训练请求拒绝", "Training Request Reject");
        trl::register_en("训练取消请求", "Training Cancel Request");
        trl::register_en("训练取消确认", "Training Cancel Confirm");
        trl::register_en("站点正在训练", "Station Under Training");
        trl::register_en("训练站点已满", "Training Stations Full");
        trl::register_en("单流", "Single Stream");
        trl::register_en("双流", "Dual Stream");
        trl::register_en("1 个子载波一组", "1 subcarrier per group");
        trl::register_en("2 个子载波一组", "2 subcarriers per group");
        trl::register_en("4 个子载波一组", "4 subcarriers per group");
        trl::register_en("8 个子载波一组", "8 subcarriers per group");
        trl::register_en("全部校验失败", "All CRC Failed");
        // 无线 MCS 释义(第2部分表129:分集次数/调制方式/码率)
        trl::register_en("分集4次 BPSK 码率1/2", "Diversity 4, BPSK, Code Rate 1/2");
        trl::register_en("分集2次 BPSK 码率1/2", "Diversity 2, BPSK, Code Rate 1/2");
        trl::register_en("分集2次 QPSK 码率1/2", "Diversity 2, QPSK, Code Rate 1/2");
        trl::register_en("分集1次 QPSK 码率1/2", "Diversity 1, QPSK, Code Rate 1/2");
        trl::register_en("分集1次 QPSK 码率4/5", "Diversity 1, QPSK, Code Rate 4/5");
        trl::register_en("分集1次 16QAM 码率1/2", "Diversity 1, 16QAM, Code Rate 1/2");
        trl::register_en("分集1次 16QAM 码率4/5", "Diversity 1, 16QAM, Code Rate 4/5");
        trl::register_en("%1 (实际=%2)", "%1 (actual=%2)");
        trl::register_en("%1 (回退 %2dB)", "%1 (backoff %2dB)");
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

void NW_2026_TreeBuilder::build(QTreeWidgetItem* root, const PacketEntry& e) {
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
        // 标准版本号(表17):0=保留 1=BPLC版本 2=SPLC版本
        QString ver;
        if (e.mpdu.version == 1)
            ver = QStringLiteral("1 - %1").arg(trl::L("BPLC版本"));
        else if (e.mpdu.version == 2)
            ver = QStringLiteral("2 - %1").arg(trl::L("SPLC版本"));
        else
            ver = QStringLiteral("%1 - %2").arg(e.mpdu.version).arg(trl::L("保留"));
        tree_add_bit_field(mpdu_base, "Version", ver, 12, 4, 4);
    }
    const QString fch_txt = !e.mpdu.fch_crc_checked ? QStringLiteral("N/A")
                          : (e.mpdu.fch_crc_ok ? QStringLiteral("OK") : QStringLiteral("FAIL"));
    tree_add_bit_field(mpdu_base, "FCH CRC24", fch_txt, 13, 0, 24);

    switch (static_cast<NW_2026_FrameType>(e.mpdu.frame_type)) {
    case NW_2026_FrameType::BEACON: {
        auto* bcn = tree_add_item(root, "BEACON", "");
        tree_add_bit_field(bcn, "TimeStamp", QStringLiteral("0x%1")
            .arg(e.mpdu.beacon_timestamp, 8, 16, QChar('0'))
                + trl::L(" (信标时间戳, NTB)"), 1, 0, 32);
        tree_add_bit_field(bcn, "BeaconPeriodCount",
            QString::number(e.mpdu.beacon_period_cnt) + trl::L(" (信标周期计数, NTB)"), 5, 0, 32);
        tree_add_bit_field(bcn, "Source TEI",
            QString::number(e.mpdu.src_tei) + trl::L(" (源 TEI)"), 9, 0, 12);
        if (e.meta.is_rf) {
            // 无线(第2部分表128):MCS(10,4,4,释义见表129) + PBLen 载荷PB大小(11,0,4)
            tree_add_bit_field(bcn, "MCS", nw_mcs_text(e.mpdu.mcs), 10, 4, 4);
            tree_add_bit_field(bcn, "PBLen",
            QString::number(e.mpdu.pblen) + trl::L(" (载荷 PB 大小索引)"), 11, 0, 4);
            // 保留(表128:(11,4,4)+(12,0,4))
            const quint8 rsv_hi = (e.raw_bytes.size() > 11)
                ? (quint8)(((quint8)e.raw_bytes[11] >> 4) & 0x0F) : 0;
            tree_add_bit_field(bcn, "RSV", QStringLiteral("0x%1").arg(rsv_hi, 1, 16, QChar('0')), 11, 4, 4);
            // 无线信标 FCH:短网络标识高位(12,0,1)+保留(12,1,3)
            const quint8 snid_hi = (e.raw_bytes.size() > 12) ? ((quint8)e.raw_bytes[12] & 0x01) : 0;
            tree_add_bit_field(bcn, "SNID High",
                QString::number(snid_hi) + trl::L(" (SNID 高位)"), 12, 0, 1);
            const quint8 rsv_lo = (e.raw_bytes.size() > 12)
                ? (quint8)(((quint8)e.raw_bytes[12] >> 1) & 0x07) : 0;
            tree_add_bit_field(bcn, "RSV", QStringLiteral("0x%1").arg(rsv_lo, 1, 16, QChar('0')), 12, 1, 3);
        } else {
            // 载波:TMI(10,4,4) SymbolNum(11,0,9) 短网络标识高位(12,1,1) 相线(12,2,2)
            tree_add_bit_field(bcn, "TMI",
            QString::number(e.mpdu.tmi) + trl::L(" (TMI 调制编号)"), 10, 4, 4);
            tree_add_bit_field(bcn, "Symbol Num",
            QString::number(e.mpdu.symbol_num) + trl::L(" (OFDM 符号数)"), 11, 0, 9);
            {
                const quint8 b12 = (e.raw_bytes.size() > 12) ? (quint8)e.raw_bytes[12] : 0;
                const quint8 snid_hi = (b12 >> 1) & 0x01;
                tree_add_bit_field(bcn, "SNID High",
                    QString::number(snid_hi) + trl::L(" (SNID 高位)"), 12, 1, 1);
            }
            // 相线(表15):0=未知 1=A 2=B 3=C
            QString line;
            switch (static_cast<NW_2026_PhaseLine>(e.mpdu.beacon_line)) {
                case NW_2026_PhaseLine::ALL_LINES: line = trl::L("未知相线"); break;  // 表15:0=未知
                case NW_2026_PhaseLine::LINE_A:    line = trl::L("A相线"); break;
                case NW_2026_PhaseLine::LINE_B:    line = trl::L("B相线"); break;
                case NW_2026_PhaseLine::LINE_C:    line = trl::L("C相线"); break;
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
    case NW_2026_FrameType::SOF: {
        auto* sof = tree_add_item(root, "SOF", "");
        tree_add_bit_field(sof, "Source TEI",
            QString::number(e.mpdu.src_tei) + trl::L(" (源 TEI)"), 1, 0, 12);
        tree_add_bit_field(sof, "Destination TEI",
            QString::number(e.mpdu.dst_tei) + trl::L(" (目的 TEI)"), 2, 4, 12);
        // 链路标识符(LID)仅在无线(表131 byte4)与 BPLC 载波(表20 byte4)存在;
        // SPLC 载波(表23-26)byte4 是 multi/train/OFDMA-type,无 LID(见下方 else 分支)
        if (e.meta.is_rf || e.mpdu.version != 2) {
            // 链路标识符(LID)= 优先级/业务分类(表98/8.2.13):应用报文 LID 0-3,网络管理 LID 0-255 自定义
            tree_add_bit_field(sof, "Link ID",
                QStringLiteral("%1 - %2").arg(e.mpdu.link_id)
                    .arg(e.mpdu.link_id <= 3 ? trl::L("应用报文 LID(优先级)")
                                             : trl::L("网络管理 LID(自定义 0-255)")),
                4, 0, 8);
        }
        // SOF 可变域按介质/版本分表独立渲染:无线走表131、BPLC 载波走表20、SPLC 载波走表23-26
        // (源/目的 TEI 两介质同坐标,已在上方共用渲染;链路标识符仅无线/BPLC 载波存在)
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
            // SPLC 表45(§5.1.3.1.11.2 无线 SOF 帧可变域):短网络标识高位(12,0,1) + 保留(12,1,3)。
            // 注意与 BPLC 表131 不同(那里 byte12 低半字节整段保留、无 SNID 高位语义),
            // 不能沿用载波分支的"整段当 TMI_EXT"。高半字节(12,4,4):表45 与表131 的
            // 可变域表均止于 byte12 bit3,两表皆无定义,按保留位渲染,不参与 SNID/net_id 合并。
            const quint8 snid_hi_rf = (raw_sz > 12) ? (quint8)(d[12] & 0x01) : 0;
            tree_add_bit_field(sof, "SNID High",
                QString::number(snid_hi_rf) + trl::L(" (SNID 高位)"), 12, 0, 1);
            const quint8 rsv_12 = (raw_sz > 12) ? (quint8)((d[12] >> 1) & 0x07) : 0;
            tree_add_bit_field(sof, "RSV", QStringLiteral("0x%1").arg(rsv_12, 1, 16, QChar('0')), 12, 1, 3);
            const quint8 rsv_12_hi = (raw_sz > 12) ? (quint8)((d[12] >> 4) & 0x0F) : 0;
            tree_add_bit_field(sof, "RSV", QStringLiteral("0x%1").arg(rsv_12_hi, 1, 16, QChar('0')), 12, 4, 4);
        } else if (e.mpdu.version != 2) {
            // BPLC 版载波 SOF(表20):聚合 BPLC 帧(用户需求)由 NW_2026_Parser 本地解析
            // (非聚合 version=1 仍整帧委托 NW_2021_Parser,不会走到本分支)——
            // 字段坐标与 nw_2021_tree.cpp 载波 SOF 分支同源(LID/源目的 TEI 已在上方共用渲染)
            const quint8 snid_hi1 = (raw_sz > 5) ? (d[5] & 0x01) : 0;
            tree_add_bit_field(sof, "SNID High",
                QString::number(snid_hi1) + trl::L(" (SNID 高位)"), 5, 0, 1);
            const quint16 rsv0 = (raw_sz > 6)
                ? (quint16)(((quint8)d[5] >> 1) | ((quint16)(quint8)d[6] << 7)) : 0;
            tree_add_bit_field(sof, "RSV", QStringLiteral("0x%1").arg(rsv0, 4, 16, QChar('0')), 5, 1, 15);
            tree_add_bit_field(sof, "PB Num",
            QString::number(e.mpdu.pb_num) + trl::L(" (物理块个数)"), 7, 0, 4);
            tree_add_bit_field(sof, "TMI",
            QString::number(e.mpdu.tmi) + trl::L(" (TMI 调制编号)"), 7, 4, 4);
            tree_add_bit_field(sof, "Frame Length",
                QStringLiteral("%1 (x10us)").arg(e.mpdu.frame_len), 8, 0, 12);
            const quint16 rsv1 = (raw_sz > 10)
                ? (quint16)(((d[9] >> 4) & 0x0F) | ((d[10] & 0x1F) << 4)) : 0;
            tree_add_bit_field(sof, "RSV", QStringLiteral("0x%1").arg(rsv1, 3, 16, QChar('0')), 9, 4, 9);
            const quint8 tei_filter = (raw_sz > 10) ? ((d[10] >> 5) & 0x01) : 1;
            tree_add_bit_field(sof, "TEI Filter",
                tei_filter ? QStringLiteral("1 - %1").arg(trl::L("物理层不检查报文 TEI"))
                           : QStringLiteral("0 - %1").arg(trl::L("物理层检查报文 TEI")),
                10, 5, 1);
            tree_add_bit_field(sof, "ReSend",
                e.mpdu.re_send_flag ? QStringLiteral("1 - %1").arg(trl::L("重传报文"))
                                    : QStringLiteral("0 - %1").arg(trl::L("非重传报文")),
                10, 6, 1);
            tree_add_bit_field(sof, "Symbol Num",
            QString::number(e.mpdu.symbol_num) + trl::L(" (OFDM 符号数)"), 10, 7, 9);
            tree_add_bit_field(sof, "TMI_EXT",
            QString::number(e.mpdu.tmi_ext) + trl::L(" (TMI 扩展编号)"), 12, 0, 4);
        } else {
            // SPLC 版载波 SOF(表23-26):先判多站点帧标识(4,0,1),再在单站点分支内判训练帧标识(4,1,1)
            // (byte4 bit1 在多站点帧里是 OFDMA 帧类型 bit0,不是训练帧标识!)
            // (非聚合 BPLC version=1 仍整帧委托 NW_2021_Parser→NW_2021_TreeBuilder,不经此处)
            const bool multi = (raw_sz > 4) ? ((d[4] & 0x01) != 0) : false;
            tree_add_bit_field(sof, "MultiStationFlag",
                multi ? QStringLiteral("1 - %1").arg(trl::L("多站点帧(OFDMA)"))
                      : QStringLiteral("0 - %1").arg(trl::L("单站点帧")),
                4, 0, 1);
            if (multi) {
                // OFDMA 帧(表26):OFDMA帧类型(4,1,2)/频段标识(4,3,3)/站点数(4,6,2)/
                // eFC符号个数(5,0,2)/PL符号数(6,0,9)
                const quint8 oft = (raw_sz > 4) ? ((d[4] >> 1) & 0x03) : 0;
                const QString ofdma_name = [&]() -> QString {
                    switch (oft) {
                        case 0: return trl::L("DL-OFDMA");
                        case 1: return trl::L("DL-OFDMA SACK/UL-OFDMA");
                        case 2: return trl::L("UL-OFDMA trigger");
                        default: return trl::L("UL-OFDMA SACK");
                    }
                }();
                tree_add_bit_field(sof, "OFDMAFrameType",
                    QStringLiteral("%1 - %2").arg(oft).arg(ofdma_name), 4, 1, 2);
                tree_add_bit_field(sof, "BandFlag",
                    QString::number((raw_sz > 4) ? ((d[4] >> 3) & 0x07) : 0), 4, 3, 3);
                const quint8 sn = (raw_sz > 4) ? ((d[4] >> 6) & 0x03) : 0;
                tree_add_bit_field(sof, "StationNum",
                    QStringLiteral("%1 (%2%3)").arg(sn).arg(sn + 1).arg(trl::L("个站点")), 4, 6, 2);
                const quint8 es = (raw_sz > 5) ? (d[5] & 0x03) : 0;
                tree_add_bit_field(sof, "EFCSymbolNum",
                    QStringLiteral("%1 (%2%3)").arg(es).arg((es + 1) * 2).arg(trl::L("符号")), 5, 0, 2);
                const quint8 rsv52 = (raw_sz > 5) ? ((d[5] >> 2) & 0x3F) : 0;
                tree_add_bit_field(sof, "RSV", QStringLiteral("0x%1").arg(rsv52, 2, 16, QChar('0')), 5, 2, 6);
                const quint16 pl_sym = (raw_sz > 7)
                    ? (quint16)((quint8)d[6] | ((quint16)(d[7] & 0x01) << 8)) : 0;
                tree_add_bit_field(sof, "PL SymbolNum", QString::number(pl_sym), 6, 0, 9);
                const quint8 rsv71 = (raw_sz > 7) ? ((d[7] >> 1) & 0x7F) : 0;
                tree_add_bit_field(sof, "RSV", QStringLiteral("0x%1").arg(rsv71, 2, 16, QChar('0')), 7, 1, 7);
                // eFC(自 p[16] 起 16B):DL-OFDMA/DL-SACK 共用表27 布局(站点0 含 SACK RU);
                // UL-OFDMA trigger=表28(SACK RU 处改 TxPowerBackoff);UL-SACK=表29(4×[TEI+状态+保留])
                if ((oft == 0 || oft == 2) && raw_sz >= 32) {
                    const quint8* e = d + 16;
                    const int sn = (raw_sz > 4) ? ((d[4] >> 6) & 0x03) : 0;  // 站点数-1
                    int bp = 0;   // eFC 内位偏移(站点 0 前置 TF 个数 2b)
                    tree_add_bit_field(sof, "eFC TFNum",
                        trl::L("%1 (实际=%2)").arg(get_bits(e, 0, 0, 2))
                            .arg(oft == 2 ? (get_bits(e, 0, 0, 2) + 1) * 2
                                          : (get_bits(e, 0, 0, 2) + 1) * 2),
                        16, 0, 2);
                    bp = 2;
                    for (int s = 0; s <= sn; ++s) {
                        const int pb_bits = 1;
                        const int pb_num_s = get_bits(e, bp / 8, bp % 8, pb_bits);
                        // 表27/表28 同语义:字段值 0→1 个 PB 块、1→2 个 PB 块,统一 +1
                        tree_add_bit_field(sof, QString("eFC Sta%1 PBNum").arg(s),
                            QString::number(pb_num_s + 1), 16 + bp / 8, bp % 8, 1);
                        bp += pb_bits;
                        const int tei = get_bits(e, bp / 8, bp % 8, 12);
                        tree_add_bit_field(sof, QString("eFC Sta%1 TEI").arg(s),
                            QString::number(tei), 16 + bp / 8, bp % 8, 12);
                        bp += 12;
                        const int tmi = get_bits(e, bp / 8, bp % 8, 5);
                        tree_add_bit_field(sof, QString("eFC Sta%1 TMI").arg(s),
                            QString::number(tmi), 16 + bp / 8, bp % 8, 5);
                        bp += 5;
                        const int ru = get_bits(e, bp / 8, bp % 8, 4);
                        tree_add_bit_field(sof, QString("eFC Sta%1 RU").arg(s),
                            QString::number(ru), 16 + bp / 8, bp % 8, 4);
                        bp += 4;
                        // 表27 SACK RU / 表28 TxPowerBackoff(3b):每站都有,不是仅站0
                        // (原实现仅站0推进 3b,3站以上帧的站2/站3 eFC 字段整体错位 3b)
                        const int sr = get_bits(e, bp / 8, bp % 8, 3);
                        if (oft == 2) {
                            tree_add_bit_field(sof, QString("eFC Sta%1 TxPowerBackoff").arg(s),
                                trl::L("%1 (回退 %2dB)").arg(sr).arg(sr * 4),
                                16 + bp / 8, bp % 8, 3);
                        } else {
                            tree_add_bit_field(sof, QString("eFC Sta%1 SACK RU").arg(s),
                                QString::number(sr), 16 + bp / 8, bp % 8, 3);
                        }
                        bp += 3;
                    }
                } else if (oft == 3 && raw_sz >= 32) {
                    // UL-OFDMA SACK eFC(表29):4×[TEI 12b + 接收状态 4b + 保留 8b],每站点 3B
                    const quint8* e = d + 16;
                    for (int s = 0; s < 4; ++s) {
                        const int b = s * 3;
                        tree_add_bit_field(sof, QString("eFC Sta%1 TEI").arg(s),
                            QString::number(get_bits(e, b, 0, 12)), 16 + b, 0, 12);
                        const quint8 st = get_bits(e, b + 1, 4, 4);
                        QStringList oks;
                        for (int i = 0; i < 4; ++i)
                            if (st & (1u << i)) oks << QStringLiteral("PB%1").arg(i);
                        tree_add_bit_field(sof, QString("eFC Sta%1 RxStatus").arg(s),
                            QStringLiteral("0x%1 (%2)").arg(st, 1, 16, QChar('0'))
                                .arg(oks.isEmpty() ? trl::L("全部校验失败") : oks.join('+')),
                            16 + b + 1, 4, 4);
                        tree_add_bit_field(sof, QString("eFC Sta%1 RSV").arg(s),
                            QStringLiteral("0x%1").arg(get_bits(e, b + 2, 0, 8), 2, 16, QChar('0')),
                            16 + b + 2, 0, 8);
                    }
                }

            } else {
                const bool train = (raw_sz > 4) ? ((d[4] & 0x02) != 0) : false;
                tree_add_bit_field(sof, "TrainFrameFlag",
                    train ? QStringLiteral("1 - %1").arg(trl::L("训练帧"))
                           : QStringLiteral("0 - %1").arg(trl::L("数据帧")),
                    4, 1, 1);
                if (train) {
                // 训练帧(表24/25):PL符号数(4,2,6)/训练帧类型(5,0,1)/TF符号数(5,1,3)/
                // 子载波分组大小(5,4,2)/流数(5,6,2)/频段标识(6,0,3)/RU信噪比估计(6,3,1)
                const quint8 pl_sym = (raw_sz > 4) ? ((d[4] >> 2) & 0x3F) : 0;
                tree_add_bit_field(sof, "PL SymbolNum",
                    trl::L("%1 (实际=%2)").arg(pl_sym).arg(pl_sym * 2 + 1), 4, 2, 6);
                const quint8 tt = (raw_sz > 5) ? (d[5] & 0x01) : 0;
                tree_add_bit_field(sof, "TrainFrameType",
                    tt ? QStringLiteral("1 - %1").arg(trl::L("Bitloading训练帧"))
                       : QStringLiteral("0 - %1").arg(trl::L("MIMO训练帧")),
                    5, 0, 1);
                const quint8 tf_sym = (raw_sz > 5) ? ((d[5] >> 1) & 0x07) : 0;
                tree_add_bit_field(sof, "TF SymbolNum",
                    trl::L("%1 (实际=%2)").arg(tf_sym).arg((tf_sym + 1) * 2), 5, 1, 3);
                tree_add_bit_field(sof, "SubcarrierGroupSize",
                    QString::number((raw_sz > 5) ? ((d[5] >> 4) & 0x03) : 0)
                        + trl::L(" (子载波分组大小)"), 5, 4, 2);
                tree_add_bit_field(sof, "StreamNum",
                    QString::number((raw_sz > 5) ? ((d[5] >> 6) & 0x03) : 0)
                        + trl::L(" (流数)"), 5, 6, 2);
                tree_add_bit_field(sof, "BandFlag",
                    QString::number((raw_sz > 6) ? (d[6] & 0x07) : 0)
                        + trl::L(" (训练频段标识)"), 6, 0, 3);
                tree_add_bit_field(sof, "RUSNREstimateFlag",
                    QString::number((raw_sz > 6) ? ((d[6] >> 3) & 0x01) : 0)
                        + trl::L(" (RU 信噪比估计标志)"), 6, 3, 1);
                const quint8 rsv64 = (raw_sz > 6) ? ((d[6] >> 4) & 0x0F) : 0;
                tree_add_bit_field(sof, "RSV", QStringLiteral("0x%1").arg(rsv64, 1, 16, QChar('0')), 6, 4, 4);
                const quint8 rsv7 = (raw_sz > 7) ? d[7] : 0;
                tree_add_bit_field(sof, "RSV", QStringLiteral("0x%1").arg(rsv7, 2, 16, QChar('0')), 7, 0, 8);

                } else {
                // SPLC 数据帧(表23):物理块个数(4,2-5)/流数(4,6,2)/TF符号数(5,0,3)/
                // PL频段标识(5,3,3)/TF扩展频段(5,6,1)/Bitloading(6,0,1)/TMI编号(6,1,5)
                tree_add_bit_field(sof, "PB Num", QString::number(e.mpdu.pb_num), 4, 2, 4);
                tree_add_bit_field(sof, "StreamNum",
                    QString::number((raw_sz > 4) ? ((d[4] >> 6) & 0x03) : 0)
                        + trl::L(" (流数)"), 4, 6, 2);
                const quint8 tf_sym = (raw_sz > 5) ? (d[5] & 0x07) : 0;
                tree_add_bit_field(sof, "TF SymbolNum",
                    trl::L("%1 (实际=%2)").arg(tf_sym).arg((tf_sym + 1) * 2), 5, 0, 3);
                tree_add_bit_field(sof, "PLBandFlag",
                    QString::number((raw_sz > 5) ? ((d[5] >> 3) & 0x07) : 0)
                        + trl::L(" (PL 频段标识)"), 5, 3, 3);
                tree_add_bit_field(sof, "TFExtBandFlag",
                    QString::number((raw_sz > 5) ? ((d[5] >> 6) & 0x01) : 0), 5, 6, 1);
                const quint8 rsv57 = (raw_sz > 5) ? ((d[5] >> 7) & 0x01) : 0;
                tree_add_bit_field(sof, "RSV", QString::number(rsv57), 5, 7, 1);
                const bool bitload = (raw_sz > 6) ? ((d[6] & 0x01) != 0) : false;
                tree_add_bit_field(sof, "BitloadingFlag",
                    bitload ? QStringLiteral("1 - %1").arg(trl::L("使用Bitloading"))
                            : QStringLiteral("0 - %1").arg(trl::L("使用TMI")),
                    6, 0, 1);
                const quint8 tmi_idx = (raw_sz > 6) ? ((d[6] >> 1) & 0x1F) : 0;
                tree_add_bit_field(sof, "TMI_Index",
                    QStringLiteral("%1 (%2 %3B)").arg(tmi_idx).arg(trl::L("PB大小")).arg(e.mpdu.pb_size),
                    6, 1, 5);
                const quint8 rsv66 = (raw_sz > 6) ? ((d[6] >> 6) & 0x03) : 0;
                tree_add_bit_field(sof, "RSV", QString::number(rsv66), 6, 6, 2);
                const quint8 rsv7 = (raw_sz > 7) ? d[7] : 0;
                tree_add_bit_field(sof, "RSV", QStringLiteral("0x%1").arg(rsv7, 2, 16, QChar('0')), 7, 0, 8);
            }
            // 公共尾段(表23-26):帧长(8,0,12,×10µs)/保留(9,4,4)+(10,0,16)/SNID高位(12,0,1)+保留
            tree_add_bit_field(sof, "Frame Length",
                QStringLiteral("%1 (x10us)").arg(e.mpdu.frame_len), 8, 0, 12);
            const quint8 rsv94 = (raw_sz > 9) ? ((d[9] >> 4) & 0x0F) : 0;
            tree_add_bit_field(sof, "RSV", QStringLiteral("0x%1").arg(rsv94, 1, 16, QChar('0')), 9, 4, 4);
            const quint16 rsv10 = (raw_sz > 11)
                ? (quint16)((quint8)d[10] | ((quint16)(quint8)d[11] << 8)) : 0;
            tree_add_bit_field(sof, "RSV", QStringLiteral("0x%1").arg(rsv10, 4, 16, QChar('0')), 10, 0, 16);
            const quint8 snid_high = (raw_sz > 12) ? (d[12] & 0x01) : 0;
            tree_add_bit_field(sof, "SNID High",
                QString::number(snid_high) + trl::L(" (SNID 高位)"), 12, 0, 1);
            const quint8 rsv12 = (raw_sz > 12) ? ((d[12] >> 1) & 0x07) : 0;
            tree_add_bit_field(sof, "RSV", QStringLiteral("0x%1").arg(rsv12, 1, 16, QChar('0')), 12, 1, 3);
            }
        }
        tree_add_item(sof, "PB Size", QString::number(e.mpdu.pb_size));

        // 逐 PB 块渲染:南网 PB 头 4B + 数据 pb_size-8 B + 保留 1B + CRC24 3B
        {
            const int header_len = 4;
            const int body_len   = e.mpdu.pb_size - 8;
            const quint8* d = reinterpret_cast<const quint8*>(e.raw_bytes.constData());
            const int raw_sz = e.raw_bytes.size();
            // 训练帧(表24/25,训练帧标识 d[4] bit1=1,仅 SPLC 载波;RF 的 d[4] 为 LID 勿套用)
            // 无数据物理块(表26):pb_num 保持 0,不渲染 PB 头/CRC——此前强制按 1 渲染,
            // FCH 后字节被误当 PB 头报 CRC FAIL 并触发列表标红
            if (!e.mpdu.sof_stations.isEmpty()) {
                // 类型1 多站点(UL-OFDMA 数据 / DL-SACK):逐站 PB 分组(sof_stations)
                // DL-SACK 判别与 parser 一致:单站 + 单 16B PB + 体首 MsgID==0;
                // 仅站数+尺寸会把单站 16B UL 数据帧误标为 SACK 并按表 49/50 误读体
                const auto& st0 = e.mpdu.sof_stations[0];
                const bool dl_sack = (e.mpdu.sof_stations.size() == 1
                                      && st0.pb_size == 16
                                      && st0.msdu.size() >= 1 && (st0.msdu[0] & 0x0F) == 0);
                for (int si = 0; si < e.mpdu.sof_stations.size(); ++si) {
                    const auto& st = e.mpdu.sof_stations[si];
                    auto* snode = tree_add_item(sof,
                        dl_sack ? trl::L("DL-OFDMA SACK 物理块")
                                : trl::L("站点 %1 PB 分组 (TEI=%2, %3 块 × %4 B)")
                                      .arg(si).arg(st.tei).arg(st.pb_num).arg(st.pb_size),
                        QString(), st.block_base, st.pb_size);
                    for (int bi = 0; bi < st.pb_crc_oks.size(); ++bi) {
                        tree_add_item(snode, QStringLiteral("Block %1 CRC24").arg(bi),
                            st.pb_crc_oks[bi] ? trl::L("通过") : trl::L("失败"),
                            st.block_base + bi * st.pb_size, st.pb_size);
                    }
                    // 截断提示:实收块数 < 声明块数时标注(与均一 PB 循环的截断节点同口径)
                    if (st.pb_crc_oks.size() < st.pb_num)
                        tree_add_item(snode, trl::L("PB 块不完整"),
                            trl::L("声明 %1 块 / 实收 %2 块").arg(st.pb_num).arg(st.pb_crc_oks.size()));
                    if (dl_sack && st.msdu.size() >= 3) {
                        const quint8 msgid = st.msdu[0] & 0x0F;
                        tree_add_bit_field(snode, "MsgID",
                            (msgid == 0) ? QStringLiteral("0 - %1").arg(trl::L("DL-OFDMA 数据帧的 SACK 帧"))
                                         : QStringLiteral("%1 - %2").arg(msgid).arg(trl::L("保留")),
                            st.block_base + 4, 0, 4);
                        tree_add_bit_field(snode, "SrcTEI", QString::number(st.tei),
                            st.block_base + 4, 4, 12);
                        const quint8 rx = st.msdu[2] & 0x03;
                        tree_add_bit_field(snode, "RxStatus",
                            QStringLiteral("0b%1%2").arg((rx >> 1) & 1).arg(rx & 1),
                            st.block_base + 6, 0, 2);
                    }
                }
            } else if (e.mpdu.pb_num <= 0 || e.mpdu.pb_size <= 0) {
                // 无数据物理块情形，先按 pb_num 区分「合法无块」与「查表失败」，再按 multi/train 区分帧型
                // (byte4 bit1 在多站点帧里是 OFDMA 帧类型 bit0,不是训练帧标识!)
                // 结构化判据(与 UI 同口径,不再依赖 version):多站 = parser 已解析出站点列表;
                // 训练帧 = 非多站 + 表24/25 byte4 bit1。
                const bool multi = !e.mpdu.sof_stations.isEmpty();
                const bool train = (!multi) && !e.meta.is_rf
                                   && (raw_sz > 4) && ((d[4] & 0x02) != 0);
                QString why;
                if (e.mpdu.pb_size <= 0 && e.mpdu.pb_num > 0) {
                    why = trl::L("PB 大小无效(查表未命中)");          // C1:声明了块但 size 查不到
                } else if (multi) {
                    const quint8 ofdma_type = (raw_sz > 4) ? ((d[4] >> 1) & 0x03) : 0;
                    if (ofdma_type == 0) {
                        // 类型0(DL-OFDMA)本应有 eFC(表27)16B + 站点0 PB,截断时 parser 未能解析出块
                        why = trl::L("DL-OFDMA 帧被截断(长度不足以容纳 eFC+PB)");
                    } else if (ofdma_type == 1) {
                        // 类型1 双义:DL-SACK 成功时走 sof_stations 渲染(不在此);
                        // 此处为 UL-OFDMA 数据无 trigger 上下文(parser 已标 msdu.summary)
                        why = trl::L("UL-OFDMA 数据帧，需 trigger 上下文（未捕获到对应 trigger）");
                    } else if (ofdma_type == 3) {
                        why = trl::L("OFDMA SACK 帧无数据物理块");
                    } else {
                        why = trl::L("OFDMA trigger 帧无数据物理块");
                    }
                } else if (train) {
                    why = trl::L("训练帧无数据物理块");
                } else {
                    why = trl::L("单站点数据帧 PBNum=0(保留值,表23 仅定义 1-4)");
                }
                tree_add_item(sof, "PB", QStringLiteral("0 B (%1)").arg(why));
            } else {
            const int pb_num     = e.mpdu.pb_num;
            // DL-OFDMA 帧 PB 块自 32 起(FCH 16 + eFC 16B);普通帧自 16 起
            // 结构化判据:多站(DL-OFDMA)PB 自 32 起;单站帧 sof_stations 为空 → 16
            const bool ofdma_pb = !e.mpdu.sof_stations.isEmpty();
            int pb_received = 0;   // 完整容纳块数(截断提示"实收"依据)
            for (int bi = 0; bi < pb_num; ++bi) {
                const int blk_off = (ofdma_pb ? 32 : 16) + bi * e.mpdu.pb_size;
                const bool blk_incomplete = (blk_off + e.mpdu.pb_size > raw_sz);
                if (!blk_incomplete) ++pb_received;
                const bool multi = pb_num > 1;
                bool agg = false;   // 聚合标志(表47 byte2 bit0):1=体首含级联头(表48)
                // PB Header(4B:序列号 16b + 聚合标志 1b + 保留 15b,表47)
                {
                    quint16 seq = 0;
                    quint16 rsv = 0;
                    if (blk_off + 4 <= raw_sz) {
                        seq = (quint16)(d[blk_off] | (d[blk_off + 1] << 8));
                        rsv = (quint16)(d[blk_off + 2] | (d[blk_off + 3] << 8));
                        agg = (d[blk_off + 2] & 0x01) != 0;
                    }
                    auto* pbh = tree_add_item(sof,
                        multi ? QStringLiteral("PB Header (%1/%2)").arg(bi).arg(pb_num)
                              : QStringLiteral("PB Header"),
                        QStringLiteral("4 B"),
                        blk_off, header_len);
                    tree_add_bit_field(pbh, "SeqNum",
                        QString::number(seq) + trl::L(" (序列号)"), blk_off, 0, 16);
                    // 聚合标志(表47 byte2 bit0):1=物理块体含级联头(多 MAC 帧聚合),0=单 MAC 帧
                    tree_add_bit_field(pbh, "AggregationFlag",
                        agg ? QStringLiteral("1 - %1").arg(trl::L("聚合帧(含级联头)"))
                            : QStringLiteral("0 - %1").arg(trl::L("单MAC帧")),
                        blk_off + 2, 0, 1);
                    tree_add_bit_field(pbh, "RSV", QStringLiteral("0x%1").arg(rsv >> 1, 4, 16, QChar('0')),
                        blk_off + 2, 1, 15);
                }
                // PB Body
                if (body_len > 0 && blk_off + header_len < raw_sz) {
                    auto* pb = tree_add_item(sof,
                        multi ? QStringLiteral("PB Body (%1/%2)").arg(bi).arg(pb_num)
                              : QStringLiteral("PB Body"),
                        QStringLiteral("%1 B").arg(body_len),
                        blk_off + header_len, body_len);
                    // 16B 物理块(表49):体首 nibble=报文ID(0=DL-OFDMA SACK),报文内容(表50):
                    // 源TEI 12b + 接收状态 2b + 保留(不重组 MSDU,仅展示)
                    if (e.mpdu.pb_size == 16) {
                        const int b0 = blk_off + header_len;
                        const quint8 msg_id = (raw_sz > b0) ? (d[b0] & 0x0F) : 0;
                        tree_add_bit_field(pb, "MsgID",
                            (msg_id == 0) ? QStringLiteral("0 - %1").arg(trl::L("DL-OFDMA 数据帧的 SACK 帧"))
                                          : QStringLiteral("%1 - %2").arg(msg_id).arg(trl::L("保留")),
                            b0, 0, 4);
                        if (msg_id == 0 && raw_sz >= b0 + 3) {
                            const int tei = ((d[b0] >> 4) & 0x0F) | (d[b0 + 1] << 4);
                            tree_add_bit_field(pb, "SrcTEI", QString::number(tei), b0, 4, 12);
                            const quint8 rx = (raw_sz > b0 + 2) ? (d[b0 + 2] & 0x03) : 0;
                            tree_add_bit_field(pb, "RxStatus",
                                QStringLiteral("0b%1%2").arg((rx >> 1) & 1).arg(rx & 1), b0 + 2, 0, 2);
                            const quint8 rsv = (raw_sz > b0 + 2) ? (d[b0 + 2] >> 2) : 0;
                            tree_add_bit_field(pb, "RSV", QStringLiteral("0x%1").arg(rsv, 2, 16, QChar('0')),
                                b0 + 2, 2, 6);
                        }
                    }
                    // 级联头(表48,聚合标志=1 时体首 2B):级联数据块长度 12b+起始/结束标识+保留,
                    // 其后为级联的 MAC 帧
                    if (agg && raw_sz >= blk_off + header_len + 2) {
                        const int c0 = blk_off + header_len;
                        const int clen = d[c0] | ((d[c0 + 1] & 0x0F) << 8);
                        // 不完整块的级联头声明长度不可信(流在该块前已终止),标注提示
                        tree_add_bit_field(pb, "Cascade Len (12b)",
                            QStringLiteral("%1 B").arg(clen)
                                + (blk_incomplete
                                   ? trl::L(" (超出级联流范围, 已停止解析)") : QString()),
                            c0, 0, 12);
                        tree_add_bit_field(pb, "Cascade Start Flag",
                            ((d[c0 + 1] >> 4) & 0x01)
                                ? QStringLiteral("1 - %1").arg(trl::L("聚合首块"))
                                : QStringLiteral("0"), c0 + 1, 4, 1);
                        tree_add_bit_field(pb, "Cascade End Flag",
                            ((d[c0 + 1] >> 5) & 0x01)
                                ? QStringLiteral("1 - %1").arg(trl::L("聚合末块"))
                                : QStringLiteral("0"), c0 + 1, 5, 1);
                        tree_add_bit_field(pb, "RSV",
                            QStringLiteral("0x%1").arg((d[c0 + 1] >> 6) & 0x03, 1, 16, QChar('0')),
                            c0 + 1, 6, 2);
                    }
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
                // 块不完整时未计算 CRC,显式标注(勿误报 OK);不设 rel(避免高亮到不存在的字节)
                tree_add_item(sof,
                    multi ? QStringLiteral("PB CRC24 (block %1/%2)").arg(bi).arg(pb_num)
                          : QStringLiteral("PB CRC24"),
                    have ? QStringLiteral("0x%1 %2").arg(crc, 6, 16, QChar('0'))
                                 .arg(pb_checked ? (okb ? "OK" : "FAIL") : "N/A")
                         : trl::L("不完整(无法校验)"),
                    have ? (blk_off + e.mpdu.pb_size - 3) : -1, 3);
            }
            // 截断提示节点:声明块数 > 实收块数时在 PB 区末尾标注(不标红,仅提示)
            if (pb_received < pb_num)
                tree_add_item(sof, trl::L("PB 块不完整"),
                    trl::L("声明 %1 块 / 实收 %2 块").arg(pb_num).arg(pb_received));
            }   // 非训练帧 PB 渲染(训练帧走上方说明节点)
        }

        // MSDU 字段树挂载(聚合帧:cascade=true,msdu_body=级联体流,
        // Cascade MAC Frame 组已在 parser 侧挂入)
        if (e.msdu.present) {
            const bool cascade_only = e.msdu.cascade;
            auto* msdu = tree_add_item(root,
                cascade_only ? "MSDU (Cascade Frames)" : "MSDU (Reassembled)",
                cascade_only
                    ? trl::L("级联体流 %1 B · %2").arg(e.msdu.total_len).arg(e.msdu.summary)
                    : QStringLiteral("%1 B  %2").arg(e.msdu_body.size()).arg(e.msdu.summary));
            MsduRawMap rm;
            rm.base = e.msdu_raw_base;
            rm.pb_num = (e.msdu_raw_base >= 0) ? 1 : (e.mpdu.pb_num > 0 ? e.mpdu.pb_num : 1);
            rm.pb_size = e.mpdu.pb_size;
            rm.fch_size = 16;
            rm.header_len = 4;
            rm.body = e.mpdu.pb_size - 8;
            // 序列号重排后拼接序≠raw 块序:用槽位表定位(SPLC 表47 序列号)
            rm.slot_raw_offset = tree_slot_raw_offsets(e.mpdu, 16, 4, 0xFF);
            tree_apply_msdu_range(msdu, rm, 0, e.msdu.total_len, e.msdu_body);
            // 聚合:级联体流长度(级联记录流有效长度,非单个 MSDU 长度语义);
            // 非聚合保持 Length;两类长度节点同组节点口径挂高亮区间(rel 0..len)
            if (cascade_only) {
                auto* len_item = tree_add_item(msdu, trl::L("级联体流长度"),
                    QStringLiteral("%1 B").arg(e.msdu.total_len));
                tree_apply_msdu_range(len_item, rm, 0, e.msdu.total_len, e.msdu_body);
                if (e.msdu.cascade_break_len >= 0)
                    tree_add_item(msdu, trl::L("级联断开"),
                        trl::L("声明长度 %1 越界/非法,级联流提前终止").arg(e.msdu.cascade_break_len));
            } else {
                auto* len_item = tree_add_item(msdu, "Length",
                    QStringLiteral("%1 B").arg(e.msdu_body.size()));
                tree_apply_msdu_range(len_item, rm, 0, e.msdu.total_len, e.msdu_body);
            }
            tree_render_msdu(msdu, e.msdu.tree, rm, e.msdu_body);
        } else if (!e.msdu_body.isEmpty()) {
            // 兜底:MSDU 未解析出但 body 非空(如越界守卫拒析)——与主分支同口径
            // 挂高亮区间(组 + Length;total_len 未设,按 body.size())
            MsduRawMap rm;
            rm.base = e.msdu_raw_base;
            rm.pb_num = (e.msdu_raw_base >= 0) ? 1 : (e.mpdu.pb_num > 0 ? e.mpdu.pb_num : 1);
            rm.pb_size = e.mpdu.pb_size;
            rm.fch_size = 16;
            rm.header_len = 4;
            rm.body = e.mpdu.pb_size - 8;
            // 序列号重排后拼接序≠raw 块序:用槽位表定位(SPLC 表47 序列号)
            rm.slot_raw_offset = tree_slot_raw_offsets(e.mpdu, 16, 4, 0xFF);
            auto* msdu = tree_add_item(root, "MSDU (Reassembled)",
                QStringLiteral("%1 B").arg(e.msdu_body.size()));
            tree_apply_msdu_range(msdu, rm, 0, e.msdu_body.size(), e.msdu_body);
            auto* len_item = tree_add_item(msdu, "Length",
                QStringLiteral("%1 B").arg(e.msdu_body.size()));
            tree_apply_msdu_range(len_item, rm, 0, e.msdu_body.size(), e.msdu_body);
            tree_add_item(msdu, "Hex", QString(e.msdu_body.toHex(' ')));
        }
        break;
    }
    case NW_2026_FrameType::ACK: {
        auto* ack = tree_add_item(root, "ACK", "");
        // 扩展帧类型值释义(表21):0=选择确认帧 1=网络搜索帧 2=同步帧 其他=保留
        // (未知扩展帧类型默认按选择确认帧解析并给出警告)
        const quint8 et = e.mpdu.ack_ext_type;
        QString ext_ev;
        switch (static_cast<NW_2026_AckExtType>(et)) {
        case NW_2026_AckExtType::Normal:        ext_ev = QStringLiteral("0 - %1").arg(trl::L("选择确认帧")); break;
        case NW_2026_AckExtType::Search:        ext_ev = QStringLiteral("1 - %1").arg(trl::L("网络搜索帧(抄控器)")); break;
        case NW_2026_AckExtType::Sync:          ext_ev = QStringLiteral("2 - %1").arg(trl::L("同步帧(抄控器)")); break;
        case NW_2026_AckExtType::Bitloading:    ext_ev = QStringLiteral("3 - %1").arg(trl::L("Bitloading 扩展帧")); break;
        default: ext_ev = QStringLiteral("%1 - %2").arg(et).arg(trl::L("保留(按选择确认帧解析)")); break;
        }
        switch (static_cast<NW_2026_AckExtType>(et)) {
        case NW_2026_AckExtType::Search:
            tree_add_bit_field(ack, "DstAddr", QStringLiteral("0x%1")
                .arg(e.mpdu.ack_dst_addr, 12, 16, QChar('0'))
                + trl::L(" (目的地址)"), 1, 0, 48);
            tree_add_bit_field(ack, "SearchTEI",
                QString::number(e.mpdu.ack_search_tei) + trl::L(" (搜索 TEI)"), 7, 0, 12);
            // 保留(表C-2:(8,4,4)、字节9-10)与序号(字节11):解析器未存,按原始字节呈现
            {
                const quint8* d = reinterpret_cast<const quint8*>(e.raw_bytes.constData());
                const int raw_sz = e.raw_bytes.size();
                const quint8 rsv0 = (raw_sz > 8) ? (quint8)((d[8] >> 4) & 0x0F) : 0;
                tree_add_bit_field(ack, "Reserved", QStringLiteral("0x%1").arg(rsv0, 1, 16, QChar('0')), 8, 4, 4);
                const quint16 rsv1 = (raw_sz > 10) ? (quint16)(d[9] | (d[10] << 8)) : 0;
                tree_add_bit_field(ack, "Reserved", QStringLiteral("0x%1").arg(rsv1, 4, 16, QChar('0')), 9, 0, 16);
                const quint8 seq = (raw_sz > 11) ? (quint8)d[11] : 0;
                tree_add_bit_field(ack, "SeqNum",
                QString::number(seq) + trl::L(" (序列号)"), 11, 0, 8);
            }
            tree_add_bit_field(ack, "ExtType", ext_ev, 12, 0, 4);
            break;
        case NW_2026_AckExtType::Sync:
            tree_add_bit_field(ack, "Timestamp", QStringLiteral("0x%1")
                .arg(e.mpdu.ack_sync_timestamp, 8, 16, QChar('0'))
                + trl::L(" (时间戳, NTB)"), 1, 0, 32);
            tree_add_bit_field(ack, "SyncTEI",
                QString::number(e.mpdu.ack_sync_tei) + trl::L(" (同步 TEI)"), 5, 0, 12);
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
                tree_add_bit_field(ack, "SeqNum",
                QString::number(seq) + trl::L(" (序列号)"), 11, 0, 8);
            }
            tree_add_bit_field(ack, "ExtType", ext_ev, 12, 0, 4);
            break;
        case NW_2026_AckExtType::Bitloading: {
            // Bitloading 扩展帧(表34,可变区域按 Bitloading 帧类型细分 表35-40)
            const quint8* d = reinterpret_cast<const quint8*>(e.raw_bytes.constData());
            const int raw_sz = e.raw_bytes.size();
            tree_add_bit_field(ack, "SrcTEI",
                QString::number(e.mpdu.src_tei) + trl::L(" (源 TEI)"), 1, 0, 12);
            tree_add_bit_field(ack, "DstTEI",
                QString::number(e.mpdu.dst_tei) + trl::L(" (目的 TEI)"), 2, 4, 12);
            const quint8 snid = (raw_sz > 4) ? (d[4] & 0x01) : 0;
            tree_add_bit_field(ack, "SNID High",
                QString::number(snid) + trl::L(" (SNID 高位)"), 4, 0, 1);
            const quint8 blt = (raw_sz > 4) ? ((d[4] >> 1) & 0x07) : 0;
            static const char* blt_names[6] = {
                "训练指示", "训练指示拒绝", "训练请求", "训练请求拒绝", "训练取消请求", "训练取消确认" };
            tree_add_bit_field(ack, "Bitloading Type",
                (blt <= 5) ? QStringLiteral("%1 - %2").arg(blt).arg(trl::L(blt_names[blt]))
                           : QStringLiteral("%1 - %2").arg(blt).arg(trl::L("保留")), 4, 1, 3);
            // 类型相关子字段(表35-40:byte4 bit4-7;byte5-11 为 56b 保留)
            const quint8 sub = (raw_sz > 4) ? ((d[4] >> 4) & 0x0F) : 0;
            switch (blt) {
            case 1: {  // 训练指示拒绝(表36):拒绝原因 1 站点正在训练/2 训练站点已满/其他保留
                const char* rn = (sub == 1) ? "站点正在训练"
                                : (sub == 2) ? "训练站点已满" : "保留";
                tree_add_bit_field(ack, "Reject Reason",
                    QStringLiteral("%1 - %2").arg(sub).arg(trl::L(rn)), 4, 4, 4);
                break;
            }
            case 3: {  // 训练请求拒绝(表38):拒绝原因 1 训练站点已满/其他保留(0 值文案文档缺失)
                const char* rn = (sub == 1) ? "训练站点已满" : "保留";
                tree_add_bit_field(ack, "Reject Reason",
                    QStringLiteral("%1 - %2").arg(sub).arg(trl::L(rn)), 4, 4, 4);
                break;
            }
            case 2: {  // 训练请求(表37):流数 bit4(0 单流/1 双流)/子载波分组大小 bit5-6/保留 bit7
                tree_add_bit_field(ack, "StreamNum",
                    (sub & 0x01) ? QStringLiteral("1 - %1").arg(trl::L("双流"))
                                 : QStringLiteral("0 - %1").arg(trl::L("单流")), 4, 4, 1);
                const quint8 gs = (sub >> 1) & 0x03;
                static const char* gs_names[4] = { "1 个子载波一组", "2 个子载波一组",
                                                   "4 个子载波一组", "8 个子载波一组" };
                tree_add_bit_field(ack, "SubcarrierGroupSize",
                    QStringLiteral("%1 - %2").arg(gs).arg(trl::L(gs_names[gs])), 4, 5, 2);
                tree_add_bit_field(ack, "RSV",
                    QStringLiteral("0x%1").arg((sub >> 3) & 0x01, 1, 16, QChar('0')), 4, 7, 1);
                break;
            }
            default: {  // 类型 0/4/5(表35/39/40):byte4 bit4-7 保留
                tree_add_bit_field(ack, "RSV",
                    QStringLiteral("0x%1").arg(sub, 1, 16, QChar('0')), 4, 4, 4);
                break;
            }
            }
            const quint32 rsv32 = (raw_sz > 8)
                ? (quint32)d[5] | ((quint32)d[6] << 8) | ((quint32)d[7] << 16) | ((quint32)d[8] << 24) : 0;
            tree_add_bit_field(ack, "RSV", QStringLiteral("0x%1").arg(rsv32, 8, 16, QChar('0')), 5, 0, 32);
            const quint16 rsv16 = (raw_sz > 10) ? (quint16)(d[9] | (d[10] << 8)) : 0;
            tree_add_bit_field(ack, "RSV", QStringLiteral("0x%1").arg(rsv16, 4, 16, QChar('0')), 9, 0, 16);
            // 表34/35 保留段实为 5-11 共 56b,此前只渲染 48b,补 byte11(所有 Bitloading 子类型共用)
            const quint8 rsv8 = (raw_sz > 11) ? d[11] : 0;
            tree_add_bit_field(ack, "RSV", QStringLiteral("0x%1").arg(rsv8, 2, 16, QChar('0')), 11, 0, 8);
            tree_add_bit_field(ack, "ExtType", ext_ev, 12, 0, 4);
            const quint8 ver = (raw_sz > 12) ? ((d[12] >> 4) & 0x0F) : 0;
            tree_add_bit_field(ack, "Std Version", QString::number(ver), 12, 4, 4);
            break;
        }
        case NW_2026_AckExtType::Normal:
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
            // 短网络标识高位 + SNR类型 + 保留 + SNR评估信息 + 保留(表30)
            {
                const quint8* d = reinterpret_cast<const quint8*>(e.raw_bytes.constData());
                const int raw_sz = e.raw_bytes.size();
                const quint8 snid_high = (raw_sz > 4) ? (quint8)(d[4] & 0x01) : 0;
                tree_add_bit_field(ack, "SNID High",
                QString::number(snid_high) + trl::L(" (SNID 高位)"), 4, 0, 1);
                // SNR类型(表32):0不携带 / 1当前帧SNR / 2基础RU / 3保留
                const quint8 snr_type = (raw_sz > 4) ? (quint8)((d[4] >> 1) & 0x03) : 0;
                QString snr_desc;
                switch (snr_type) {
                case 0: snr_desc = trl::L("不携带SNR信息"); break;
                case 1: snr_desc = trl::L("接收当前帧SNR信息"); break;
                case 2: snr_desc = trl::L("反馈TF评估基础RU信息"); break;
                default: snr_desc = trl::L("保留"); break;
                }
                tree_add_bit_field(ack, "SNR Type",
                    QStringLiteral("%1 - %2").arg(snr_type).arg(snr_desc), 4, 1, 2);
                const quint8 rsv4 = (raw_sz > 4) ? (quint8)((d[4] >> 3) & 0x1F) : 0;
                tree_add_bit_field(ack, "Reserved",
                    QStringLiteral("0x%1").arg(rsv4, 2, 16, QChar('0')), 4, 3, 5);
                // SNR评估信息(表30:(5,0,30)):SNR类型1=当前帧5bit SNR,类型2=RU0-5各5bit
                quint32 snr = 0;
                if (raw_sz >= 9)
                    snr = (quint32)(quint8)d[5] | ((quint32)(quint8)d[6] << 8)
                        | ((quint32)(quint8)d[7] << 16) | ((quint32)((quint8)d[8] & 0x3F) << 24);
                tree_add_bit_field(ack, "SNR Info",
                    QStringLiteral("0x%1").arg(snr, 8, 16, QChar('0')), 5, 0, 30);
                const quint8 rsv8 = (raw_sz > 8) ? (quint8)((d[8] >> 6) & 0x03) : 0;
                tree_add_bit_field(ack, "Reserved",
                    QStringLiteral("0x%1").arg(rsv8, 1, 16, QChar('0')), 8, 6, 2);
                quint32 rsv9 = 0;
                if (raw_sz >= 12)
                    rsv9 = (quint32)(quint8)d[9] | ((quint32)(quint8)d[10] << 8)
                        | ((quint32)(quint8)d[11] << 16);
                tree_add_bit_field(ack, "Reserved",
                    QStringLiteral("0x%1").arg(rsv9, 6, 16, QChar('0')), 9, 0, 24);
            }
            // 扩展帧类型(表19:byte12 bit0-3)
            tree_add_bit_field(ack, "ExtType", ext_ev, 12, 0, 4);
            break;
        }
        }
        break;
    }
    case NW_2026_FrameType::COORD: {
        auto* coord = tree_add_item(root, "COORD", "");
        const quint8* d = reinterpret_cast<const quint8*>(e.raw_bytes.constData());
        const int raw_sz = e.raw_bytes.size();
        // 邻居网络比特图1(表41:1,0,16):bit0=SNID1 ... bit15=SNID16
        const quint16 bm1 = (raw_sz > 2) ? (quint16)((quint8)d[1] | ((quint8)d[2] << 8)) : 0;
        {
            QStringList heard;
            for (int i = 0; i < 16; ++i)
                if (bm1 & (1u << i)) heard << QStringLiteral("SNID %1").arg(i + 1);
            tree_add_bit_field(coord, "NeighbourNIDBitMap1",
                heard.isEmpty() ? QStringLiteral("0x%1").arg(bm1, 4, 16, QChar('0'))
                                : QStringLiteral("0x%1 (%2)").arg(bm1, 4, 16, QChar('0'))
                                      .arg(heard.join(QLatin1String(", "))),
                1, 0, 16);
        }
        // 本网络无线信道编号(表41:3,0,8,不分介质)
        const quint8 rf_ch = (raw_sz > 3) ? (quint8)d[3] : 0;
        tree_add_bit_field(coord, "RF Channel", QString::number(rf_ch), 3, 0, 8);
        // 邻居网络比特图2(表41:4,0,10):bit0=SNID17 ... bit9=SNID26
        const quint16 bm2 = (raw_sz > 5)
            ? (quint16)((quint8)d[4] | ((quint16)(d[5] & 0x03) << 8)) : 0;
        {
            QStringList heard;
            for (int i = 0; i < 10; ++i)
                if (bm2 & (1u << i)) heard << QStringLiteral("SNID %1").arg(i + 17);
            tree_add_bit_field(coord, "NeighbourNIDBitMap2",
                heard.isEmpty() ? QStringLiteral("0x%1").arg(bm2, 3, 16, QChar('0'))
                                : QStringLiteral("0x%1 (%2)").arg(bm2, 3, 16, QChar('0'))
                                      .arg(heard.join(QLatin1String(", "))),
                4, 0, 10);
        }
        tree_add_bit_field(coord, "TimeDuration", QStringLiteral("%1 (x40ms)").arg(e.mpdu.coord_duration), 5, 2, 14);
        // 邻居网络比特图3(表41:7,0,1):bit0=SNID27
        const quint8 bm3 = (raw_sz > 7) ? (quint8)(d[7] & 0x01) : 0;
        tree_add_bit_field(coord, "NeighbourNIDBitMap3", QString::number(bm3), 7, 0, 1);
        {
            // 带宽结束标志位(表41:7,1,1):1=上个带宽时隙已结束 0=未结束
            QString flag = (e.mpdu.coord_band_end_flag == 1)
                ? QStringLiteral("1 - %1").arg(trl::L("上个带宽时隙已结束"))
                : QStringLiteral("0 - %1").arg(trl::L("上个带宽时隙未结束"));
            tree_add_bit_field(coord, "BandSlotEndFlag", flag, 7, 1, 1);
        }
        // 本网络无线 option(表41:7,2,2,不分介质)
        const quint8 rf_opt = (raw_sz > 7) ? (quint8)((d[7] >> 2) & 0x03) : 0;
        tree_add_bit_field(coord, "RF Option", QString::number(rf_opt), 7, 2, 2);
        // 邻居网络比特图4(表41:7,4,4):bit0=SNID28 ... bit3=SNID31
        const quint8 bm4 = (raw_sz > 7) ? (quint8)((d[7] >> 4) & 0x0F) : 0;
        {
            QStringList heard;
            for (int i = 0; i < 4; ++i)
                if (bm4 & (1u << i)) heard << QStringLiteral("SNID %1").arg(i + 28);
            tree_add_bit_field(coord, "NeighbourNIDBitMap4",
                heard.isEmpty() ? QStringLiteral("0x%1").arg(bm4, 1, 16, QChar('0'))
                                : QStringLiteral("0x%1 (%2)").arg(bm4, 1, 16, QChar('0'))
                                      .arg(heard.join(QLatin1String(", "))),
                7, 4, 4);
        }
        tree_add_bit_field(coord, "BandSlotEndOffset", QStringLiteral("%1 (x4ms)").arg(e.mpdu.coord_band_end_offset), 8, 0, 16);
        tree_add_bit_field(coord, "BandSlotStartOffset", QStringLiteral("%1 (x4ms)").arg(e.mpdu.coord_band_start_offset), 10, 0, 16);
        // 短网络标识高位(表41:12,0,1) + 保留(12,1,3)
        const quint8 snid_high = (raw_sz > 12) ? (quint8)(d[12] & 0x01) : 0;
        tree_add_bit_field(coord, "SNID High", QString::number(snid_high), 12, 0, 1);
        const quint8 rsv12 = (raw_sz > 12) ? (quint8)((d[12] >> 1) & 0x07) : 0;
        tree_add_bit_field(coord, "RSV", QStringLiteral("0x%1").arg(rsv12, 1, 16, QChar('0')), 12, 1, 3);
        break;
    }
    }
}
