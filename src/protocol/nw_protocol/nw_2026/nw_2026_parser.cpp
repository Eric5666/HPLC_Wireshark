/// @file nw_2026_parser.cpp
/// @brief 南网 NW_2026 双模协议解析器实现(骨架:帧控制 + 各帧型 FCH 字段)
/// @details 字段坐标参考《通感一体化低压电力线宽带载波通信(SPLC)规约 第4部分:
///          数据链路层通信协议(试行)》表16/表20/表23-26/表41/表47 等。
///          标准版本号(表16:0=保留/1=BPLC/2=SPLC)决定分发:版本=2 走本解析器
///          SPLC 表23(单站点数据帧)/表24-25(训练帧)/表26(OFDMA 多站点帧);
///          版本=1(BPLC)与 0(保留)整帧委托旧解析器 NW_2021_Parser 解析展示
///          (nw_2021 是 nw_2026 的子集)。
///          物理头 [dlen2][ts4][phr_mcs][option][channel][isRF] 与国网一致。
#include "nw_2026_parser.h"
#include "nw_2026_pb_table.h"
#include "nw_2026_msdu_parser.h"
#include "nw_2026_beacon_parser.h"
#include "nw_2026_tree.h"
#include "../nw_2021/nw_2021_parser.h"   // 标准版本号==1(BPLC)委托旧解析器:nw_2021 是 nw_2026 的子集
#include "common/fieldtools.h"
#include "crc.h"
#include "pb_assembler.h"
#include "bcd.h"
#include "i18n.h"
#include <QDateTime>


NW_2026_Parser::NW_2026_Parser() {}

// 剥物理层头(与国网一致:[dlen2][ts4][phr_mcs][option][channel][isRF])
bool NW_2026_Parser::decode_envelope(const BplcFrame& in, Result& r) {
    r.meta = in.meta;
    r.arrival_us = in.arrival_us;
    r.raw_wire   = in.raw_wire;
    const QByteArray& d = in.data;

    if (in.meta.from_raw) {
        if (d.size() < 2) { r.reject_reason = trl::L("空帧"); return false; }
        r.meta.is_rf = (quint8(d[0]) != 0);
        r.payload_for_log = d.mid(1);
        // frame_time 已由 SerialReader 从文本头时间填充(r.meta 已拷贝)
        r.meta.epoch_ms = r.meta.frame_time.toMSecsSinceEpoch();
        return true;
    }

    int hdr = in.meta.has_time_tag ? 8 : 0;
    if (d.size() < 20 + hdr) {
        r.reject_reason = trl::L("帧长过短");
        return false;
    }

    if (in.meta.has_time_tag) {
        int y = bcd2dec((quint8)d[0]);
        int mo = bcd2dec((quint8)d[1]);
        int da = bcd2dec((quint8)d[2]);
        int hh = bcd2dec((quint8)d[3]);
        int mm = bcd2dec((quint8)d[4]);
        int ss = bcd2dec((quint8)d[5]);
        int ms_hi = bcd2dec((quint8)d[6]);
        int ms_lo = bcd2dec((quint8)d[7]);
        // bcd2dec 对非法半字节返回 -1(原 try/catch 从不触发,因它不抛异常);非法日期/时间亦回落当前时间
        QDateTime t(QDate(2000 + y, mo, da), QTime(hh, mm, ss, ms_hi * 100 + ms_lo));
        if (y < 0 || mo < 0 || da < 0 || hh < 0 || mm < 0 || ss < 0
            || ms_hi < 0 || ms_lo < 0 || !t.isValid()) {
            t = QDateTime::currentDateTime();
        } else {
            r.meta.has_time_tag = true;
        }
        r.meta.frame_time = t;
        r.meta.epoch_ms = t.toMSecsSinceEpoch();
    } else {
        // 无时间标签:frame_time 已由 SerialReader 填充
        r.meta.epoch_ms = r.meta.frame_time.toMSecsSinceEpoch();
    }

    int offset = hdr;
    quint32 ts = 0;
    ts |= (quint32)(quint8)d[offset + 2];
    ts |= (quint32)(quint8)d[offset + 3] << 8;
    ts |= (quint32)(quint8)d[offset + 4] << 16;
    ts |= (quint32)(quint8)d[offset + 5] << 24;
    r.meta.timestamp = ts;

    QByteArray payload = d.mid(offset + 6);
    if (payload.size() < 4) {
        r.reject_reason = trl::L("剥头后载荷过短(<4B)");
        return false;
    }
    r.meta.phr_mcs  = (quint8)payload[0];
    r.meta.option   = (quint8)payload[1];
    r.meta.channel  = (quint8)payload[2];
    quint8 media_id = (quint8)payload[3];
    r.meta.is_rf = (media_id != 0);

    payload.remove(0, 4);
    r.payload_for_log = payload;
    if (payload.isEmpty()) {
        r.reject_reason = trl::L("剥头后空载荷");
        return false;
    }
    return true;
}

// 南网 MPDU_BASE 帧控制(16B):FrameType + ConInd + ShortNID(4b) + VersionNum + FCCS
bool NW_2026_Parser::parse_mpdu_base(const QByteArray& body, MpduInfo& info, QString& err) {
    if (body.size() < 16) { err = trl::L("MPDU_BASE 长度不足 16B"); return false; }
    const quint8* p = reinterpret_cast<const quint8*>(body.constData());

    quint32 calc_crc = crc24_lsb(p, 16);
    quint32 fch_crc  = (quint32)p[13] | ((quint32)p[14] << 8) | ((quint32)p[15] << 16);
    info.fch_crc_ok = (calc_crc == fch_crc);
    info.fch_crc_checked = true;
    if (!info.fch_crc_ok) {
        err = trl::L("FCH CRC24 错(calc=%1 rx=%2)")
              .arg(calc_crc, 6, 16, QChar('0')).arg(fch_crc, 6, 16, QChar('0'));
        return false;
    }

    info.frame_type = (quint8)get_bits(p, 0, 0, 3);   // 定界符类型
    info.net_type   = (quint8)get_bits(p, 0, 3, 1);   // 接入指示 ConInd
    info.net_id     = (quint32)get_bits(p, 0, 4, 4);  // 短网络标识 SNID 4b
    info.version    = (quint8)get_bits(p, 12, 4, 4);  // 标准版本号
    return true;
}

namespace {
/// i18n 注册(本 TU 概要文本)
struct I18nReg {
    I18nReg() {
        trl::register_en("训练帧（MIMO训练帧）", "Training Frame (MIMO)");
        trl::register_en("PB 块数超上限(band=%1 tmi=%2 num=%3 max=%4)",
                         "PB Count Over Limit (band=%1 tmi=%2 num=%3 max=%4)");
        trl::register_en(" (截断: PB 块不完整, 声明 %1 块仅收到 %2 块)", " (truncated: %1 PB declared, %2 received)");
        trl::register_en("训练帧（Bitloading训练帧）", "Training Frame (Bitloading)");
        trl::register_en("聚合帧(%1 个级联 MAC 帧)", "Aggregated Frame (%1 cascade MAC frames)");
        trl::register_en("（%1 段因块 CRC 失败未解析）", "(%1 segments skipped: block CRC failed)");
        trl::register_en("块 CRC 失败未解析", "Block CRC failed, not parsed");
        trl::register_en("PB 序号异常未解析", "PB Sequence Error, Not Parsed");
        trl::register_en("聚合帧(%1 帧: %2)", "Aggregated Frame (%1 frames: %2)");
        trl::register_en("聚合帧(%1 帧: %2 ×%3)", "Aggregated Frame (%1 frames: %2 x%3)");
        trl::register_en(", ", ", ");
        trl::register_en(" 等", " etc.");
        trl::register_en("未识别", "Unrecognized");
        trl::register_en("UL-OFDMA 数据帧，需 trigger 上下文（未捕获到对应 trigger）",
                         "UL-OFDMA Data Frame, Requires Trigger Context (No Matching Trigger Captured)");
        trl::register_en("DL-OFDMA eFC CRC24 错(calc=%1 rx=%2)",
                         "DL-OFDMA eFC CRC24 Error (calc=%1 rx=%2)");
    }
};
const I18nReg g_i18n_reg_nw2026_parser;

/// 级联子树 rel 坐标平移:单条 MAC 帧系 → 级联体流系(rel_start>=0 才有字节映射)
void shift_msdu_rel(MsduFieldNode& n, int base) {
    if (n.rel_start >= 0) n.rel_start += base;
    for (auto& ch : n.children) shift_msdu_rel(ch, base);
}
}

/// @brief OFDMA SOF 完整 5bit SNID 分桶键(定义见 record_trigger_ctx 上方)
static quint32 ofdma_full_snid(quint32 net_id_low4, const quint8* p);

// 多段帧学习合并(级联/OFDMA 多站点共用):把一段已解析 MSDU 的学习信息并入帧级 MsduInfo。
// - tei_mac_pairs 全并(守卫同 update_tei_mac 的对循环:tei!=0 && mac);
// - 头对(src/dst)以对形式并入(单槽位装不下 N 段;守卫同 update_tei_mac 的头对门:tei>0 && mac;头对字段见 SPLC 第4部分 表1/表7);
// - topo 事件:首个非 Other 段事件进 topo_event,后续段事件进 topo_extra_events(消费时两者都读)。
static void merge_msdu_learn(MsduInfo& dst, const MsduInfo& cm) {
    for (const TeiMacPair& p : cm.tei_mac_pairs)
        if (p.tei != 0 && p.mac) dst.tei_mac_pairs.append(p);
    if (cm.msdu_src_tei > 0 && cm.msdu_src_mac)
        dst.tei_mac_pairs.append({(quint16)cm.msdu_src_tei, cm.msdu_src_mac});
    if (cm.msdu_dst_tei > 0 && cm.msdu_dst_mac)
        dst.tei_mac_pairs.append({(quint16)cm.msdu_dst_tei, cm.msdu_dst_mac});
    // 聚合/多站点源(前提条件:仅当帧级尚无原始 TEI 时收集;帧级已有源
    // 如 DL-OFDMA 站点 0 经通用路径已定,则不收集、不展示多源)。
    if (dst.msdu_src_tei <= 0) {
        // TEI-only 段(短头 MACAddrFlag=0)亦收集,mac==0,显示只出 STA-N;
        // 不进 tei_mac_pairs(铁律:TEI 单独出现不配对,上方的对仍守 mac!=0)。
        auto add_orig_src = [&](quint16 tei, quint64 mac) {
            if (tei == 0) return;
            for (const auto& p : dst.orig_srcs)
                if (p.tei == tei && p.mac == mac) return;
            dst.orig_srcs.append({tei, mac});
        };
        if (cm.msdu_src_tei > 0)
            add_orig_src((quint16)cm.msdu_src_tei, cm.msdu_src_mac);
        for (const auto& p : cm.orig_srcs) add_orig_src(p.tei, p.mac);
    }
    // 聚合/多站点目的(与源镜像:仅当帧级尚无原始目的 TEI 时收集;
    // 帧级已有目的则不收集、不展示多目的)。
    if (dst.msdu_dst_tei <= 0) {
        auto add_orig_dst = [&](quint16 tei, quint64 mac) {
            if (tei == 0) return;
            for (const auto& p : dst.orig_dsts)
                if (p.tei == tei && p.mac == mac) return;
            dst.orig_dsts.append({tei, mac});
        };
        if (cm.msdu_dst_tei > 0)
            add_orig_dst((quint16)cm.msdu_dst_tei, cm.msdu_dst_mac);
        for (const auto& p : cm.orig_dsts) add_orig_dst(p.tei, p.mac);
    }
    if (cm.topo_event.kind != TopoEventKind::Other) {
        if (dst.topo_event.kind == TopoEventKind::Other)
            dst.topo_event = cm.topo_event;
        else
            dst.topo_extra_events.append(cm.topo_event);
    }
    // 稳健性:cm 若本身已是合并结果,其 extras 一并传递(单段解析时恒空)。
    for (const auto& e : cm.topo_extra_events) dst.topo_extra_events.append(e);
}

NW_2026_Parser::Result NW_2026_Parser::parse(const BplcFrame& in, MsduState& msdu, const Filter& f) {
    Result r = parse_inner(in, msdu, f);
    m_time_anchor.apply(r, m_display_ctx);
    return r;
}

NW_2026_Parser::Result NW_2026_Parser::parse_inner(const BplcFrame& in, MsduState& msdu, const Filter& f) {
    Result r;
    ++m_frame_count;                        // 帧计数(trigger 上下文失效基准)
    r.protocol = ProtocolVariant::NW_2026;   // 协议身份由解析器标记
    if (!decode_envelope(in, r)) {
        r.accept = false;
        return r;
    }

    QString err;
    if (!parse_mpdu_base(r.payload_for_log, r.mpdu, err)) {
        r.reject_reason = err;
        r.accept = false;
        return r;
    }

    // 南网帧型分派策略(用户决策 2026-10):SPLC(2026) 是 BPLC(2021) 保留位启用补充、
    // 兼容旧帧——信标 表119→表18 保留(12,1,1)→SNID高位、ACK 表7→表30 保留(4-11)→
    // SNID高位+SNR类型+SNR评估信息、COORD 表15→表41 保留→邻居网络比特图,均为保留位
    // 启用无冲突。因此仅 SOF 判断标准版本号(新旧 PB/TMI 布局差异大):
    //   1) SOF:version!=2 → 整帧委托旧解析器 NW_2021_Parser(BPLC);
    //   2) BEACON/ACK/COORD:不判版本号,默认走 SPLC 解析(BPLC 旧帧的保留位在 SPLC
    //      布局下解析为启用的 SNID高位/SNR类型 等字段,展示无害);
    //   3) 非 SOF 帧 SPLC 结构性失败(信标载荷区不完整等,见各分支回退点)→ 回退 m_legacy
    //      BPLC 解析。ACK/COORD 为固定字段解析,FCH 解析成功后字段必然在界内,无失败路径。
    const bool is_sof = (r.mpdu.frame_type == 1);
    if (is_sof && r.mpdu.version != 2) {
        // 聚合 BPLC 帧例外(用户需求 2026-10):载波 SOF version=1 但 PB 头聚合标志=1
        // (表47 byte2 bit0)→ nw_2021 无聚合拆分能力,留在本解析器本地解析——走下方
        // BPLC 表20 兜底分支 + 公共 pb_assembler 级联拆分(字段树含 AggregationFlag/
        // 级联头/Cascade MAC Frame);非聚合 version=1 仍整帧委托 NW_2021_Parser(现状)。
        // 无线聚合 SOF(用户需求 2026-10-27):PB 头聚合标志媒介无关(表47 byte2 bit0),
        // 聚合帧留在本地做级联拆分;非聚合 version≠2 无线帧仍委托。纯本解析器内部分派,
        // 不涉 nw_2021→nw_2026 委托(用户禁止)。
        bool agg_bplc = false;
        if (r.payload_for_log.size() >= 16 + 3)          // 去掉 !r.meta.is_rf 门控
            agg_bplc = (quint8(r.payload_for_log.at(16 + 2)) & 0x01) != 0;
        if (!agg_bplc) {
            // SPLC 扩展 MMe 例外(用户需求):version=1 非聚合帧承载 SPLC 表77 扩展 MMe
            // (0x0080-0x0085,BPLC 第2部分无定义)→ 本地解析(nw_2026 已有 MME_RUSNR_INFO_IND
            // 等 0x0080-0x0085 实现)。预读 MSDU 头判别,坐标同 nw_2021_msdu_parser:
            // PB 体自 payload[20](FCH16+PB头4);MACHeadFlag=体[0] bit0 → MAC 头长 32B/短 12B;
            // MSDU 帧类型 16b LE:长头在体[mac+16..17]/短头在体[mac+0..1](0x88E1=管理消息);
            // 其后 MMe = [版本 1B][类型 2B LE]。越界/判别失败保持原委托(不因预读崩溃)。
            // 纯本解析器内部分派,不涉 nw_2021→nw_2026 委托。
            bool splc_ext_mme = false;
            const QByteArray& pl = r.payload_for_log;
            if (!r.meta.is_rf && pl.size() >= 20 + 32 + 16 + 5) {
                const quint8* body = reinterpret_cast<const quint8*>(pl.constData()) + 20;
                // MACHeadFlag(体[0] bit0):0=长头 32B / 1=短头 12B
                // (nw_2021_msdu_parser.h LONG_HEAD=0x0/SHORT_HEAD=0x1,实帧 7 验证)
                const bool long_head = (body[0] & 0x01) == 0;
                const int mac_len = long_head ? 32 : 12;
                const int type_off = 20 + mac_len + (long_head ? 16 : 0);
                if (pl.size() >= type_off + 5
                    && quint8(pl.at(type_off)) == 0xE1
                    && quint8(pl.at(type_off + 1)) == 0x88) {
                    const quint16 mme = quint16(quint8(pl.at(type_off + 3)))
                                      | (quint16(quint8(pl.at(type_off + 4))) << 8);
                    splc_ext_mme = (mme >= 0x0080 && mme <= 0x0085);
                }
            }
            if (!splc_ext_mme)
                return m_legacy.parse_inner(in, msdu, f);
        }
    }

    // SNID 共 5bit(试行规约 §5.1.2.2.1/表16):低位在 FCH(0,4,4),高位按帧型坐标合并:
    //   SOF 载波(表23)=(12,0,1) / SOF 无线(表45)=(12,0,1) /
    //   信标 载波(12,1,1) 无线(12,0,1) / ACK(表19/21)=(4,0,1) / COORD(表41)=(12,0,1)。
    //   注意 BPLC 版坐标不同:载波 SOF(表20)高位在 (5,0,1)、无线(表131)无高位——
    //   那是 NW_2021 的取值;NW_2026 走 SPLC 表23/表45,两种 SOF 都在 (12,0,1)。
    // 列显示统一用合并后的 5bit SNID(有效取值 1-31)。
    {
        const quint8* fch = reinterpret_cast<const quint8*>(r.payload_for_log.constData());
        quint8 snid_high = 0;
        switch (r.mpdu.frame_type) {
            case 0:  // 信标帧:载波(12,1,1) 无线(12,0,1)
                snid_high = (r.meta.is_rf ? ((fch[12] >> 0) & 0x01) : ((fch[12] >> 1) & 0x01));
                break;
            case 1: {  // SOF 载波:SPLC(表23)高位在 (12,0,1);BPLC(表20)高位在 (5,0,1);
                       // 无线两版本:表45 有 (12,0,1)/表131 无高位(本分支本地解析仅载波可达)
                snid_high = (r.mpdu.version == 2 || r.meta.is_rf)
                                ? (fch[12] & 0x01) : (fch[5] & 0x01);
                break;
            }
            case 2:  // ACK(4,0,1)
                snid_high = (fch[4] & 0x01);
                break;
            case 3:  // COORD(12,0,1)
                snid_high = (fch[12] & 0x01);
                break;
            default: break;
        }
        r.mpdu.net_id |= (quint32(snid_high) << 4);
    }

    const NW_2026_FrameType ftype = static_cast<NW_2026_FrameType>(r.mpdu.frame_type);


    const quint8* p = reinterpret_cast<const quint8*>(r.payload_for_log.constData());

    if (ftype == NW_2026_FrameType::SOF) {
        // SOF:源/目的 TEI(载波与无线同坐标)+ PB 大小(载波按标准版本号/无线 PBLen)
        // PB 块基址:普通帧 16(FCH 后);DL-OFDMA 帧 32(FCH 16 + eFC 16B,SPLC 第4部分 表27)
        int pb_base = 16;
        // DL-OFDMA 多站点(类型0 时填):站点1+ 的补解析用,见通用组装后的循环
        bool dl_ofdma = false;
        int dl_sta_count = 0;
        r.mpdu.src_tei = (quint16)get_bits(p, 1, 0, 12);
        r.mpdu.dst_tei = (quint16)get_bits(p, 2, 4, 12);
        if (r.meta.is_rf) {
            // 无线 SOF 可变域(SPLC 第4部分表45):帧长(5,0,12,单位100µs)/载荷PB大小(6,4,4)/
            // MCS(7,0,4)/TEI过滤(7,4,1)/重传(7,5,1);保留(7,6,2)+(8-11,32b)+
            // 短网络标识高位(12,0,1)+保留(12,1,3)(表45;表131 byte12 低半字节保留、无 SNID 高位语义),
            // 无 PB 个数与符号数字段。高半字节(12,4,4):表45/表131 均无定义,树与 Lua 按保留位
            // 渲染,不存入 tmi_ext(不参与 SNID/net_id 合并)
            r.mpdu.link_id = (quint8) get_bits(p, 4, 0, 8);
            r.mpdu.frame_len = (quint16)get_bits(p, 5, 0, 12);
            quint8 pblen = (quint8)get_bits(p, 6, 4, 4);
            r.mpdu.mcs     = (quint8)get_bits(p, 7, 0, 4);   // MCS(表131)
            r.mpdu.pblen   = pblen;                       // 载荷 PB 大小索引(表130)
            { const int sz = nw_2026_rf_pb_size(pblen); r.mpdu.pb_size = (quint16)(sz > 0 ? sz : 0); }
            r.mpdu.pb_num  = 1;                           // 无线信道仅 1 个物理块
            r.mpdu.re_send_flag = (get_bits(p, 7, 5, 1) != 0);    // 重传标志位(表131)
            r.mpdu.symbol_num   = 0;                              // 无线无符号数字段
            r.mpdu.tmi_ext      = (quint8) get_bits(p, 12, 0, 4); // 整段原样存:(12,0,1)=SNID 高位(表45),(12,1,3)=保留;高位由下方合并块并入 net_id
        } else if (r.mpdu.version == 2) {
            // SPLC 版载波 SOF(表23-26):先判多站点帧标识(4,0,1),再在单站点分支内判训练帧标识(4,1,1)
            // (byte4 bit1 在多站点帧里是 OFDMA 帧类型 bit0,不是训练帧标识!)
            const bool multi = (get_bits(p, 4, 0, 1) != 0);
            r.mpdu.frame_len = (quint16)get_bits(p, 8, 0, 12);   // 帧长(×10µs,表23-26)
            if (multi) {
                // OFDMA 多站点帧(SPLC 第4部分 表26):基字段 + eFC(DL-OFDMA SPLC 第4部分 表27,16B 独立结构) + 站点0 PB
                // byte4 bit1-2 = OFDMA 帧类型:0=DL-OFDMA 1=DL-OFDMA的SACK/UL-OFDMA 2=trigger 3=UL-SACK
                const quint8 ofdma_type  = (quint8)get_bits(p, 4, 1, 2);
                if (ofdma_type == 0 && r.payload_for_log.size() >= 32) {
                    // DL-OFDMA(SPLC 第4部分 表27):eFC 自 p[16] 起 16 字节,站点0 字段位于 eFC[0..3];
                    // PB 块自 p[32] 起(站点0),多站点其余站点 PB 依序随后
                    pb_base = 32;
                    const quint8* e = p + 16;
                    // SPLC 第4部分 表27 DL-OFDMA eFC 自带 CRC24(e[13..15]);FCH CRC 只覆盖前 16B,
                    // 坏 eFC 会读出错误的 PB 数与 TMI ⇒ 分段全错 + 假 CRC FAIL
                    {
                        const quint32 calc = crc24_lsb(e, 16);
                        const quint32 rx   = (quint32)e[13] | ((quint32)e[14] << 8) | ((quint32)e[15] << 16);
                        if (calc != rx) {
                            r.mpdu.pb_num  = 0;
                            r.mpdu.pb_size = 0;
                            r.reject_reason = trl::L("DL-OFDMA eFC CRC24 错(calc=%1 rx=%2)")
                                              .arg(calc, 6, 16, QChar('0')).arg(rx, 6, 16, QChar('0'));
                            r.accept = false;
                            return r;
                        }
                    }
                    const quint8 st0_pbn_field = (quint8)get_bits(e, 0, 2, 1);
                    const quint8 st0_tmi       = (quint8)get_bits(e, 1, 7, 5);
                    r.mpdu.pb_num  = st0_pbn_field + 1;   // SPLC 第4部分 表27/28:字段 0→1 块,1→2 块
                    { const int sz = nw_2026_splc_pb_size(st0_tmi); r.mpdu.pb_size = (quint16)(sz > 0 ? sz : 0); }
                    dl_ofdma = true;
                    dl_sta_count = ((p[4] >> 6) & 0x03) + 1;   // FCH byte4 bits 6-7:站点数码+1
                } else if (ofdma_type == 2 && r.payload_for_log.size() >= 32) {
                    // 类型2(trigger SPLC 第4部分 表28):记录 eFC 上下文供类型1 UL-OFDMA 数据帧取 TMI;
                    // trigger 本帧无数据物理块;分桶键用完整 5bit SNID(见 ofdma_full_snid)
                    record_trigger_ctx(ofdma_full_snid(r.mpdu.net_id, p), p,
                                       r.payload_for_log.size());
                    r.mpdu.pb_num  = 0;
                    r.mpdu.pb_size = 0;
                } else if (ofdma_type == 1) {
                    // 类型1 双义:DL-OFDMA 的 SACK 帧 / UL-OFDMA 数据帧,分派见 parse_ofdma_type1
                    parse_ofdma_type1(r, p, r.payload_for_log.size());
                } else {
                    // 类型3(UL-SACK):本站不重组 MSDU
                    r.mpdu.pb_num  = 0;
                    r.mpdu.pb_size = 0;
                }
            } else {
                // 单站点帧(表23/24/25):byte4 bit1 = 训练帧标识
                const bool train = (get_bits(p, 4, 1, 1) != 0);
                if (train) {
                    // 训练帧(表24/25):无数据物理块,不重组 MSDU;
                    // MSDU Type 列显示帧性质(用户需求):训练帧类型(5,0,1) 0=MIMO 1=Bitloading
                    r.mpdu.pb_num = 0;
                    r.mpdu.pb_size = 0;
                    const quint8 train_type = (quint8)get_bits(p, 5, 0, 1);
                    r.msdu.present = true;
                    r.msdu.summary = (train_type == 1)
                        ? trl::L("训练帧（Bitloading训练帧）")
                        : trl::L("训练帧（MIMO训练帧）");
                } else {
                    // SPLC 单站点数据帧(表23):物理块个数(4,2-5)/Bitloading(6,0)/TMI编号(6,1-5)/
                    // PL频段标识(5,3-5,物理层表17 通信频段)
                    r.mpdu.pb_num  = (quint8) get_bits(p, 4, 2, 4);
                    const bool bitload = (get_bits(p, 6, 0, 1) != 0);
                    const quint8 tmi_idx = (quint8)get_bits(p, 6, 1, 5);
                    r.mpdu.sof_band = (quint8)get_bits(p, 5, 3, 3);
                    { const int sz = bitload ? nw_2026_splc_bitload_pb_size(tmi_idx)
                                             : nw_2026_splc_pb_size(tmi_idx);
                      r.mpdu.pb_size = (quint16)(sz > 0 ? sz : 0); }
                }
            }
        } else {
            // BPLC 兜底分支:聚合 BPLC 例外帧(agg_bplc)落入此处;其余 SOF 且 version!=2 已在 parse() 顶部委托 NW_2021_Parser,
            // 走到此处的 SOF 为 version==2 或 agg_bplc:BPLC 版载波 SOF(表20):链路标识符(4,0,8)/SNID高位(5,0,1 由树渲染)/
            // PBNum(7,0,4)/TMI(7,4,4)/FrameLen(8,0,12)/TEI过滤/重传/符号数/TMI_EXT
            r.mpdu.link_id = (quint8) get_bits(p, 4, 0, 8);
            r.mpdu.pb_num    = (quint8) get_bits(p, 7, 0, 4);
            r.mpdu.tmi       = (quint8) get_bits(p, 7, 4, 4);
            r.mpdu.frame_len = (quint16)get_bits(p, 8, 0, 12);
            r.mpdu.re_send_flag = (get_bits(p, 10, 6, 1) != 0);   // 重传标志位(表18)
            r.mpdu.symbol_num   = (quint16)get_bits(p, 10, 7, 9);  // 符号数(表16)
            r.mpdu.tmi_ext   = (quint8) get_bits(p, 12, 0, 4);
            { const int sz = nw_2026_pb_size(r.mpdu.tmi, r.mpdu.tmi_ext); r.mpdu.pb_size = (quint16)(sz > 0 ? sz : 0); }
        }
        // PB 块逐块 CRC24 + 块体提取 + 聚合级联拆分(公共 pb_assembler;南网布局:
        // PB头4B 表47 + 块体 + 保留1B + CRC24 3B,聚合标志 byte2 bit0,§5.1.3.2.1)
        // SPLC 单站点载波:PBNum 上限按频段×TMI 编号查 nw_2026_max_pb_num
        // (band=PL频段标识(5,3,3),物理层表17;超限拒收,与国网 gw_2026 门限同口径)
        if (!r.meta.is_rf && r.mpdu.version == 2 && r.mpdu.pb_size > 8 && r.mpdu.pb_num > 0) {
            const int max_n = nw_2026_max_pb_num(r.mpdu.sof_band,
                (quint8)get_bits(p, 6, 1, 5));
            if (max_n >= 0 && r.mpdu.pb_num > max_n) {
                r.reject_reason = trl::L("PB 块数超上限(band=%1 tmi=%2 num=%3 max=%4)")
                    .arg(r.mpdu.sof_band)
                    .arg((quint8)get_bits(p, 6, 1, 5))
                    .arg(r.mpdu.pb_num).arg(max_n);
                r.accept = false;
                return r;
            }
        }
        if (r.mpdu.pb_size > 8 && r.mpdu.pb_num > 0) {
            pb_asm::PbLayout layout{/*head*/4, /*rsv*/1, /*crc*/3,
                                    /*agg_byte*/2, /*agg_bit*/0,
                                    /*base*/pb_base};
            // 序列号:SPLC 表47 byte0 bit0-7 + byte1 bit0-7 = 16bit LE(帧内重排)
            layout.seq_byte = 0;
            layout.seq_mask = 0xFFFF;
            const pb_asm::AssembleResult res =
                pb_asm::assemble_pb_blocks(r.payload_for_log, r.mpdu.pb_num,
                                           r.mpdu.pb_size, layout);
            // 逐块头/CRC 按到达序存(UI 序列判定依赖线序;体流按 seq 序)
            pb_asm::arrival_order_blocks(res, &r.mpdu.pb_heads, &r.mpdu.pb_crc_oks);
            // pb_crc_ok 语义:全部声明块都已收到且 CRC24 通过(不只是已收块全过);
            // 截断帧即使已收块全过也为 false,与红行谓词“含截断”意图一致;
            // NW_2021 同款口径(pb_crc_oks.size()==pb_num),GW 侧截断直接拒收。
            r.mpdu.pb_crc_ok = res.all_crc_ok && !res.truncated && res.reassembly_ok;
            // 聚合级联拆分必须先过统一判据:序号缺块/越界/冲突时体流字节序不确定,
            // 拆出的级联 MAC 帧列表会指向错误内容,只保留 msdu_body 供高亮映射。
            if (res.any_aggregated && pb_asm::body_parseable(res)) {
                // 聚合帧(SPLC 图11 多块聚合,用户决策:不参与 MSDU 拼接):级联 MAC 帧
                // 逐帧独立解析展示——级联记录可跨 PB 体边界(实测锚点:4 条记录
                // [2d 10]/[2d 00]/[2d 00]/[2d 20],首记录 Start=1、末记录 End=1)
                // 子树坐标平移:msdu parser 产出 rel 相对单条 MAC 帧,统一平移到
                // 级联体流(msdu_body)坐标系,树层 MsduRawMap 按块换算 raw 多段高亮
                int cas_cnt = 0;
                QStringList cas_sums;   // 各级联帧 MSDU 类型摘要(MSDU Type 列展示聚合内容)
                // topo 事件:首段事件进 topo_event,后续段事件进 topo_extra_events(见 merge_msdu_learn)
                for (const auto& c : res.cascade) {
                    const MsduInfo cm = NW_2026_MsduParser::parse(c.mac);
                    merge_msdu_learn(r.msdu, cm);
                    MsduFieldNode grp;
                    grp.name = QStringLiteral("Cascade MAC Frame[%1]").arg(cas_cnt);
                    grp.value = QStringLiteral("%1 B%2%3")
                                    .arg(c.mac_len)
                                    .arg(c.start_flag ? QStringLiteral(" (Start)") : QString())
                                    .arg(c.end_flag ? QStringLiteral(" (End)") : QString());
                    // 高亮映射:rel 相对级联体流(msdu_body=各块体依序拼接)
                    grp.rel_start = c.body_start + 2;   // 跳过级联头 2B
                    grp.rel_len   = c.mac_len;
                    const int base = grp.rel_start;
                    for (MsduFieldNode n : cm.tree) {
                        shift_msdu_rel(n, base);
                        grp.children.append(n);
                    }
                    r.msdu.tree.append(grp);
                    r.msdu.present = true;
                    ++cas_cnt;
                    cas_sums << (cm.summary.isEmpty() ? trl::L("未识别") : cm.summary);
                }
                // 摘要(用户需求):逐帧类型列表,让用户知道聚合了什么——
                // 全同型压缩 "T ×N";混合型列前 4 项(>4 截断加 " 等");空流保持计数式
                if (cas_sums.isEmpty()) {
                    r.msdu.summary = trl::L("聚合帧(%1 个级联 MAC 帧)").arg(cas_cnt);
                } else {
                    bool all_same = true;
                    for (const auto& s : cas_sums)
                        if (s != cas_sums.first()) { all_same = false; break; }
                    if (all_same) {
                        r.msdu.summary = trl::L("聚合帧(%1 帧: %2 ×%3)")
                                             .arg(cas_cnt).arg(cas_sums.first()).arg(cas_cnt);
                    } else {
                        const QStringList head =
                            cas_sums.mid(0, qMin(cas_sums.size(), 4));
                        QString list = head.join(trl::L(", "));
                        if (cas_sums.size() > 4) list += trl::L(" 等");
                        r.msdu.summary = trl::L("聚合帧(%1 帧: %2)")
                                             .arg(cas_cnt).arg(list);
                    }
                }
                // CRC 失败块剔除的记录数(assembler 已过滤):摘要里说明,避免
                // 段数悄悄变少;被剔记录不解析、不进树、不参与学习。
                if (res.cascade_crc_skipped > 0)
                    r.msdu.summary += trl::L("（%1 段因块 CRC 失败未解析）")
                                          .arg(res.cascade_crc_skipped);
                // msdu_body 保留为级联体流供树值/高亮映射,非重组 MSDU 语义(见 msdu.cascade);
                // total_len = 级联体流总长(树层 Length 子节点/区间高亮依据)
                r.msdu.cascade = true;
                r.msdu_body = res.msdu_body;   // 级联体流(含块体尾填充,高亮映射用)
                // total_len = 级联记录流有效长度(逐条 2+len 累加,不含尾填充;
                // 显示/高亮区间按协议语义取有效长度,msdu_body 保留全流)
                r.msdu.total_len = res.cascade_used;
                // 高亮:单块级联 = 首块块体起点(整段连续);多块级联跨块不连续 → -1(逐块换算)
                r.msdu_raw_base = (r.mpdu.pb_num == 1 && !res.blocks.isEmpty())
                                      ? res.blocks.first().body_raw_offset : -1;
            } else if (!res.msdu_body.isEmpty()) {
                r.msdu_body = res.msdu_body;
                // 表6:单跳帧协议(版本=2)仅无线信道支持;载波信道收到属异常(排查信道/串口错配)
                if (!r.meta.is_rf && (((quint8)res.msdu_body[0] >> 1) & 0x03) == 2)
                    qWarning("NW_2026: single-hop MAC version=2 on PLC channel (isRF=0)");
                // CRC 失败块不解析(用户 2026-10-29 定,多块补定:好块要解析):
                // 首帧 MSDU 完整落在好块内即解析(坏块在 span 之外不影响);
                // span 横跨坏块时仍整段不解析,仅留摘要说明(缺失字节会使
                // 体流错位成错误数据);pb_crc_ok=false 已标 FAIL/红行。
                // 先过统一判据 body_parseable(序号缺块/重复冲突/越界 → 不解析),
                // 因为 msdu_span_avoids_bad_blocks 只看块 CRC、不看序号完整性。
                if (pb_asm::body_parseable(res)
                    && (res.all_crc_ok
                        || pb_asm::msdu_span_avoids_bad_blocks(
                               res.msdu_body, res.blocks,
                               layout.body_len(r.mpdu.pb_size)))) {
                    r.msdu = NW_2026_MsduParser::parse(res.msdu_body);
                    // 高亮:单块连续 = 首块块体起点(块体在 raw_bytes 中的绝对偏移);
                    // 多块重组时各块体被 PB 头/保留/CRC 隔断,不连续 → -1(沿用国网约定)
                    r.msdu_raw_base = (r.mpdu.pb_num == 1 && !res.blocks.isEmpty())
                                          ? res.blocks.first().body_raw_offset : -1;
                } else {
                    r.msdu.summary = res.reassembly_ok
                        ? trl::L("块 CRC 失败未解析")
                        : trl::L("PB 序号异常未解析");
                }
            }
            // 截断提示(用户需求):声明块数 vs 实收块数,聚合/非聚合都标;FCH 声明 pb_num,
            // 实收 = 完整容纳块数(pb_assembler res.blocks)
            if (res.truncated)
                append_summary(r.msdu, trl::L(" (截断: PB 块不完整, 声明 %1 块仅收到 %2 块)")
                    .arg(r.mpdu.pb_num).arg(res.blocks.size()));
            r.msdu.cascade_break_len = res.cascade_break_declared_len;
            // DL-OFDMA 站点1+ 补解析:通用循环只跑了站点0 的块,站点1+ 的 PB 依序随后。
            // 逐站按 SPLC 第4部分 表27 eFC(每站 25b:PBNum 1b + TEI 12b + TMI 5b + RU 4b + SACK RU 3b)组装解析,
            // 只合并学习(对 + topo 事件首/余),不改站点0 的树/摘要/体流;eFC CRC 已在类型0 分支验过。
            if (dl_ofdma && dl_sta_count > 1) {
                const quint8* e = p + 16;   // eFC @16,16B(SPLC 第4部分 表27)
                int bp = 2 + 25;            // 跳过站点0 的 25b
                int base = 32 + (int)r.mpdu.pb_num * (int)r.mpdu.pb_size;   // 站点1 首块基址

                for (int s = 1; s < dl_sta_count; ++s) {
                    if (bp + 25 > 104) break;   // 超出 eFC CRC 保护区(13B),停止
                    const int pbn = (int)get_bits(e, bp / 8, bp % 8, 1); bp += 1;
                    bp += 12;   // eFC TEI 无 MAC,不配对
                    const int tmi = (int)get_bits(e, bp / 8, bp % 8, 5); bp += 5;
                    bp += 4 + 3;   // RU + SACK RU
                    const int psz = nw_2026_splc_pb_size(tmi);
                    const int pnum = pbn + 1;
                    // 尺寸非法则后续站点基址无法定位,整站停止(继续按错偏移解析会产垃圾对)
                    if (psz <= 8 || pnum <= 0) break;
                    if (base >= r.payload_for_log.size()) break;
                    pb_asm::PbLayout layout{/*head*/4, /*rsv*/1, /*crc*/3,
                                            /*agg_byte*/2, /*agg_bit*/0, base};
                    layout.seq_byte = 0;       // SPLC 表47 序列号 16bit LE
                    layout.seq_mask = 0xFFFF;
                    const pb_asm::AssembleResult ar =
                        pb_asm::assemble_pb_blocks(r.payload_for_log, pnum, psz, layout);
                    base += pnum * psz;
                    if (ar.msdu_body.isEmpty()) continue;
                    // 序列号缺块/越界/冲突(重排失败)→ 体流不可信,不参与学习;
                    // 块 CRC 状态照常记录(红行与 Info 粒度展示用)。
                    const bool learnable = ar.reassembly_ok;
                    if (ar.any_aggregated) {
                        if (learnable) {
                            for (const auto& c : ar.cascade) {
                                const MsduInfo cm = NW_2026_MsduParser::parse(c.mac);
                                merge_msdu_learn(r.msdu, cm);
                            }
                        }
                        // 记录聚合块的 CRC 状态
                        for (const auto& b : ar.blocks) {
                            r.mpdu.pb_crc_oks.append(b.crc_ok);
                        }
                    } else {
                        // CRC 失败块不解析(与主路同口径,用户 2026-10-29 定):
                        // 本站 PB 全好或 MSDU 完整落在好块内才解析学习;坏块
                        // 字节会使体流错位成错误数据,解析出的 MAC/TEI 对不可信。
                        // (聚合分支已由组装器剔除与坏块相交的记录,无需再验。)
                        if (learnable
                            && (ar.all_crc_ok
                                || pb_asm::msdu_span_avoids_bad_blocks(
                                       ar.msdu_body, ar.blocks, layout.body_len(psz)))) {
                            const MsduInfo cm = NW_2026_MsduParser::parse(ar.msdu_body);
                            merge_msdu_learn(r.msdu, cm);
                        }
                        // 记录本站 CRC 状态，以支持"任意块 CRC 失败即标红"
                        for (const auto& b : ar.blocks) {
                            r.mpdu.pb_crc_oks.append(b.crc_ok);
                        }
                    }
                }
            }
        }
    } else if (ftype == NW_2026_FrameType::BEACON) {
        // BEACON:信标时间戳/周期计数/源 TEI(载波与无线同坐标)
        r.mpdu.beacon_timestamp  = (quint32)get_bits(p, 1, 0, 32);
        r.mpdu.beacon_period_cnt = (quint32)get_bits(p, 5, 0, 32);
        r.mpdu.src_tei           = (quint16)get_bits(p, 9, 0, 12);
        if (r.meta.is_rf) {
            r.mpdu.mcs     = (quint8)get_bits(p, 10, 4, 4);   // MCS(表128)
            r.mpdu.pblen   = (quint8)get_bits(p, 11, 0, 4);   // 载荷 PB 大小索引(表130)
            { const int sz = nw_2026_rf_pb_size(r.mpdu.pblen); r.mpdu.pb_size = (quint16)(sz > 0 ? sz : 0); }
        } else {
            r.mpdu.tmi       = (quint8)get_bits(p, 10, 4, 4); // 载波映射表索引
            r.mpdu.symbol_num = (quint16)get_bits(p, 11, 0, 9);
            r.mpdu.beacon_line = (quint8)get_bits(p, 12, 2, 2);
            { const int sz = nw_2026_pb_size(r.mpdu.tmi, 0); r.mpdu.pb_size = (quint16)(sz > 0 ? sz : 0); }
        }
        // 信标帧载荷区(固定头 + 管理信息 + BPCS CRC32 + 保留字节 + PB CRC24)
        if (r.mpdu.pb_size > 0)
            r.beacon = NW_2026_BeaconParser::parse_beacon(r.payload_for_log, r.mpdu.pb_size, r.meta.is_rf);
        // 非 SOF 帧 SPLC 结构性失败(载荷不足/信标载荷区不完整,parse_beacon 置 present=false)
        // → 回退 BPLC 解析(分派策略第 3 条,用户决策)
        if (!r.beacon.present) {
            return m_legacy.parse_inner(in, msdu, f);
        }
    } else if (ftype == NW_2026_FrameType::ACK) {
        // ACK(南网 MPDU_ACK_FCH 坐标,表19/表21)
        r.mpdu.ack_ext_type = (quint8)get_bits(p, 12, 0, 4);
        switch (static_cast<NW_2026_AckExtType>(r.mpdu.ack_ext_type)) {
            case NW_2026_AckExtType::Search:  // 网络搜索帧(抄控器,表21)
                r.mpdu.ack_dst_addr   = get_bits(p, 1, 0, 48);
                r.mpdu.ack_search_tei = (quint16)get_bits(p, 7, 0, 12);
                break;
            case NW_2026_AckExtType::Sync:  // 同步帧(抄控器,表21)
                r.mpdu.ack_sync_timestamp = (quint32)get_bits(p, 1, 0, 32);
                r.mpdu.ack_sync_tei       = (quint16)get_bits(p, 5, 0, 12);
                break;
            case NW_2026_AckExtType::Bitloading:
                // Bitloading 扩展帧(表34):源/目的 TEI 落标量;Bitloading 帧类型与
                // 训练子字段(表35-40)由字段树按原始字节渲染(nw_2026_tree.cpp)
                r.mpdu.src_tei = (quint16)get_bits(p, 1, 0, 12);
                r.mpdu.dst_tei = (quint16)get_bits(p, 2, 4, 12);
                break;
            case NW_2026_AckExtType::Normal:
            default:
                // 选择确认帧(表19);未知扩展帧类型(表21"其他")默认按选择确认帧解析
                r.mpdu.ack_rx_res    = (quint8) get_bits(p, 1, 0, 4);
                r.mpdu.ack_rx_status = (quint8) get_bits(p, 1, 4, 4);
                r.mpdu.dst_tei       = (quint16)get_bits(p, 2, 0, 12);
                r.mpdu.ack_rx_pb_num = (quint8) get_bits(p, 3, 4, 4);
                break;
        }
    } else if (ftype == NW_2026_FrameType::COORD) {
        // COORD(南网 MPDU_COORD_FCH 坐标,表41):
        //   邻居网络比特图1(1,0,16)/无线信道(3,0,8)/比特图2(4,0,10)/持续时间(5,2,14)/
        //   比特图3(7,0,1)/带宽结束标志(7,1,1)/无线option(7,2,2)/比特图4(7,4,4)/
        //   带宽结束偏移(8,0,16)/带宽开始偏移(10,0,16)/SNID高位(12,0,1)+保留(12,1,3)
        // 注:31bit 邻居比特图 = 比特图1(16b)+比特图2(10b)+比特图3(1b)+比特图4(4b);
        //     MpduInfo 标量无 31bit 字段,树渲染直接读原始字节(见 nw_2026_tree)。
        r.mpdu.coord_neighbour_nid     = (quint32)get_bits(p, 1, 0, 16);  // 邻居网络比特图1
        r.mpdu.coord_duration          = (quint16)get_bits(p, 5, 2, 14);  // 持续时间(×40ms)
        r.mpdu.coord_band_end_flag     = (quint8) get_bits(p, 7, 1, 1);
        r.mpdu.coord_band_end_offset   = (quint16)get_bits(p, 8, 0, 16);  // ×4ms
        r.mpdu.coord_band_start_offset = (quint16)get_bits(p, 10, 0, 16); // ×4ms
        r.mpdu.coord_rsv1             = (quint16)get_bits(p, 4, 0, 10);   // 邻居网络比特图2(表41)
        r.mpdu.coord_rsv2             = (quint8) get_bits(p, 7, 0, 1);    // 邻居网络比特图3(表41)
        r.mpdu.coord_rsv3             = (quint8) get_bits(p, 7, 4, 4);    // 邻居网络比特图4(表41)
        r.mpdu.coord_rsv0             = (quint8) get_bits(p, 12, 0, 4);   // SNID高位(12,0,1)+保留(12,1,3)
    }

    r.accept = true;
    return r;
}

// 完整 5bit SNID:低 4bit=net_id(byte0 bits4-7),高 1bit=表 26 byte12 bit0
static quint32 ofdma_full_snid(quint32 net_id_low4, const quint8* p) {
    return (net_id_low4 & 0x0Fu) | (((p[12] & 0x01) != 0) ? 0x10u : 0u);
}

// ---- 类型2(trigger)记录 eFC 上下文(SPLC 第4部分 表28) ----
void NW_2026_Parser::record_trigger_ctx(quint32 snid, const quint8* p, int raw_sz) {
    if (raw_sz < 32) return;
    const quint8* e = p + 16;                       // eFC @16, 16B(SPLC 第4部分 表28)
    // eFC 自带 CRC24(e[13..15]):FCH CRC 只覆盖前 16B, eFC 损坏时该 SNID 旧上下文
    // 一并作废——保留旧值会让后续 UL 帧按"上一个有效 trigger"的布局解出看似合理的
    // 结果,用户看不出异常;明确"需 trigger 上下文"才是正确信号
    {
        const quint32 calc = crc24_lsb(e, 16);
        const quint32 rx   = (quint32)e[13] | ((quint32)e[14] << 8) | ((quint32)e[15] << 16);
        if (calc != rx) {
            m_trigger_ctx.remove(snid);
            return;
        }
    }
    const int sn = (p[4] >> 6) & 0x03;              // 站点数-1(0=1站..3=4站)
    TriggerCtx ctx;
    ctx.station_count = sn + 1;
    ctx.frame_index   = m_frame_count;
    int bp = 2;                                     // TF 个数 2b(SPLC 第4部分 表28 (0,0,2))
    for (int s = 0; s <= sn; ++s) {
        const quint8  pbn = (quint8)get_bits(e, bp / 8, bp % 8, 1);   // 0→1块,1→2块
        bp += 1;
        const quint16 tei = (quint16)get_bits(e, bp / 8, bp % 8, 12);
        bp += 12;
        const quint8  tmi = (quint8)get_bits(e, bp / 8, bp % 8, 5);
        bp += 5;
        bp += 4;                                    // RU 4b(记录用,当前无输出)
        bp += 3;                                    // Tx回退 3b(记录用,当前无输出)
        ctx.st[s].tei = tei;
        ctx.st[s].pb_num = pbn + 1;
        { const int sz = nw_2026_splc_pb_size(tmi); ctx.st[s].pb_size = (quint16)(sz > 0 ? sz : 0); }
    }
    m_trigger_ctx[snid] = ctx;                      // ①新 trigger 覆盖旧(最近一次语义)
}

// ---- 类型1 分派:DL-SACK / UL-OFDMA 数据 ----
void NW_2026_Parser::parse_ofdma_type1(Result& r, const quint8* p, int raw_sz) {
    // DL-SACK 判别(notes.md:81-84):总长 32B(FCH16+单16B PB) 且 PB@16 CRC24 通过
    // 且 体首 nibble MsgID==0。先试 DL-SACK,失败再走 UL-OFDMA 数据子项。
    bool dl_sack = false;
    if (raw_sz == 32) {
        const quint8* blk = p + 16;                  // PB @16, 16B(固定 TMI 26)
        const quint32 calc = crc24_lsb(blk, 16);
        const quint32 rx   = (quint32)blk[13] | ((quint32)blk[14] << 8) | ((quint32)blk[15] << 16);
        if (calc == rx && (p[20] & 0x0F) == 0)       // 体首低 nibble=MsgID(0=DL-OFDMA SACK)
            dl_sack = true;
    }

    if (dl_sack) {
        // DL-SACK:单 16B PB,体(表49/50)首 nibble=MsgID、源TEI 12b、接收状态 2b
        SofStationPb st;
        st.tei        = (quint16)(((p[20] >> 4) & 0x0F) | (p[21] << 4));  // 源 TEI 12b
        st.pb_num     = 1;
        st.pb_size    = 16;
        st.block_base = 16;
        st.pb_heads.append(p[16]);                    // PB 头首字节(seq 低 8b)
        st.pb_crc_oks.append(true);                   // 判别时已验 CRC 通过
        st.msdu       = QByteArray(reinterpret_cast<const char*>(p + 20), 8);  // 体 8B(MsgID/SrcTEI/RxStatus)
        r.mpdu.sof_stations.append(st);
        // 逐站 CRC 进帧级 pb_crc_oks(用户 2026-10-30 定,仅 PB 块 CRC):
        // DL-SACK 单 16B PB 的 CRC24 已在判别时验证通过,属 PB 块 CRC。
        for (bool ok : st.pb_crc_oks) r.mpdu.pb_crc_oks.append(ok);
        r.mpdu.pb_num  = 0;    // 不参与均一 pb_num/pb_size 组装,树侧按 sof_stations 渲染
        r.mpdu.pb_size = 0;
    } else {
        // UL-OFDMA 数据:查 trigger 上下文(按完整 5bit SNID 分桶,与记录侧同键)
        auto it = m_trigger_ctx.constFind(ofdma_full_snid(r.mpdu.net_id, p));
        const bool ctx_valid = (it != m_trigger_ctx.constEnd())
                               && (m_frame_count - it->frame_index <= kTriggerCtxMaxAge);
        if (ctx_valid && it->station_count >= 1) {
            int base = 16;                           // 类型1 无 eFC,站载荷自 byte16 起
            // topo 事件:首站事件进 topo_event,后续站事件进 topo_extra_events(见 merge_msdu_learn)
            for (int s = 0; s < it->station_count; ++s) {
                const auto& ts = it->st[s];
                SofStationPb st;
                st.tei        = ts.tei;
                st.pb_num     = ts.pb_num;
                st.pb_size    = ts.pb_size;
                st.block_base = base;
                if (ts.pb_size > 8 && ts.pb_num > 0) {
                    pb_asm::PbLayout layout{/*head*/4, /*rsv*/1, /*crc*/3,
                                            /*agg*/2, /*agg_bit*/0, base};
                    layout.seq_byte = 0;       // SPLC 表47 序列号 16bit LE
                    layout.seq_mask = 0xFFFF;
                    const pb_asm::AssembleResult res =
                        pb_asm::assemble_pb_blocks(r.payload_for_log, ts.pb_num, ts.pb_size, layout);
                    // 逐块头/CRC 按到达序存(UI 序列判定依赖线序;体流按 seq 序)
                    pb_asm::arrival_order_blocks(res, &st.pb_heads, &st.pb_crc_oks);
                    // 重组不可信(序号缺块/重复冲突/越界)时不把体流交给树层解析,
                    // 否则字段树显示的是错序体的内容(帧已按 pb_crc_ok=false 标红)
                    st.msdu = pb_asm::body_parseable(res) ? res.msdu_body : QByteArray();
                    // 学习:逐站 MSDU 解析并合并(头对+管理对进 tei_mac_pairs;topo 首站优先;头对字段见 SPLC 第4部分 表1/表7)。
                    // 注:r.msdu.present 保持 false(显示不变);对循环消费不以 present 为门,学习仍生效。
                    if (!st.msdu.isEmpty()) {
                        const bool learnable = res.reassembly_ok;   // 序列号缺块/越界/冲突则不学习
                        if (res.any_aggregated) {
                            // 级联记录已由 assembler 按 CRC 过滤,仅好块记录进合并
                            if (learnable) {
                                for (const auto& c : res.cascade) {
                                    const MsduInfo cm = NW_2026_MsduParser::parse(c.mac);
                                    merge_msdu_learn(r.msdu, cm);
                                }
                            }
                        } else if (learnable
                                   && (res.all_crc_ok
                                       || pb_asm::msdu_span_avoids_bad_blocks(
                                              st.msdu, res.blocks,
                                              layout.body_len(ts.pb_size)))) {
                            // 非级联整段:span 完整落在好块内即解析学习,横跨坏块
                            // 则不解析不学习(用户 2026-10-29 定 + 多块补定)
                            const MsduInfo cm = NW_2026_MsduParser::parse(st.msdu);
                            merge_msdu_learn(r.msdu, cm);
                        }
                    }
                }
                r.mpdu.sof_stations.append(st);
                // 逐站 CRC 进帧级 pb_crc_oks(用户 2026-10-30 定,仅 PB 块 CRC):
                // 各站 st.pb_crc_oks 皆为组装器逐块 CRC24 结果,站序即块序;
                // 类型1 通用路因 pb_num=0 跳过,无 double-append。
                for (bool ok : st.pb_crc_oks) r.mpdu.pb_crc_oks.append(ok);
                base += (int)ts.pb_num * (int)ts.pb_size;
            }
            r.mpdu.pb_num  = 0;    // 每站尺寸不同,不走均一组装,树侧按 sof_stations 渲染
            r.mpdu.pb_size = 0;
        } else {
            // 无 trigger 上下文:明确标记(不要静默当 SACK)
            r.mpdu.pb_num  = 0;
            r.mpdu.pb_size = 0;
            r.msdu.present = true;
            r.msdu.summary = trl::L("UL-OFDMA 数据帧，需 trigger 上下文（未捕获到对应 trigger）");
        }
    }
}
