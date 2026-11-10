/// @file nw_2021_parser.cpp
/// @brief 南网 NW_2021 双模协议解析器实现(骨架:帧控制 + 各帧型 FCH 字段)
/// @details 字段坐标以协议原文为准(各表号见对应实现处注释)。
///          南网与国网差异:SNID 4b、各帧型字段坐标、PB 头 4B。
///          物理头 [dlen2][ts4][phr_mcs][option][channel][isRF] 与国网一致。
#include "nw_2021_parser.h"
#include "nw_2021_pb_table.h"
#include "nw_2021_msdu_parser.h"
#include "nw_2021_beacon_parser.h"
#include "nw_2021_tree.h"
#include "common/fieldtools.h"
#include "common/pb_assembler.h"
#include "crc.h"
#include "bcd.h"
#include "i18n.h"
#include "common/msdu_crc_state.h"
#include <QDateTime>

// 本文件拒因文案的英文注册(nw_2026_parser 同款模式;存量拒因此前漏注册,
// 英文界面 trl::L 回退中文,一并补齐)
struct I18nRegNw2021Parser {
    I18nRegNw2021Parser() {
        trl::register_en("空帧", "Empty Frame");
        trl::register_en("帧长过短", "Frame Too Short");
        trl::register_en("剥头后载荷过短(<4B)", "Payload Too Short After Strip (<4B)");
        trl::register_en("剥头后空载荷", "Empty Payload After Strip");
        trl::register_en("PB 序号异常未解析", "PB Sequence Error, Not Parsed");
        trl::register_en("PB 块数超上限(band=%1 tmi=%2 ext=%3 num=%4 max=%5)",
                         "PB Count Over Limit (band=%1 tmi=%2 ext=%3 num=%4 max=%5)");
    }
};
const I18nRegNw2021Parser g_i18n_reg_nw2021_parser;

NW_2021_Parser::NW_2021_Parser() {}

// 剥物理层头(与国网一致:[dlen2][ts4][phr_mcs][option][channel][isRF])
bool NW_2021_Parser::decode_envelope(const BplcFrame& in, Result& r) {
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
bool NW_2021_Parser::parse_mpdu_base(const QByteArray& body, MpduInfo& info, QString& err) {
    if (body.size() < 16) { err = trl::L("MPDU_BASE 长度不足 16B"); return false; }
    const quint8* p = reinterpret_cast<const quint8*>(body.constData());

// crc24_lsb 内部遍历 len-3 字节;此处传 16(FCH 全长)即校验前 13B,
// 末 3B 为本 CRC 自身(crc.h 约定,勿传 13 否则少算 3B)
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

NW_2021_Parser::Result NW_2021_Parser::parse(const BplcFrame& in, MsduState& msdu, const Filter& f) {
    Result r = parse_inner(in, msdu, f);
    m_time_anchor.apply(r, m_display_ctx);
    return r;
}

NW_2021_Parser::Result NW_2021_Parser::parse_inner(const BplcFrame& in, MsduState& msdu, const Filter& f) {
    Result r;
    r.protocol = ProtocolVariant::NW_2021;   // 协议身份由解析器标记
    Q_UNUSED(msdu);
    Q_UNUSED(f);  // 解析时不过滤(仅显示过滤),过滤参数不再读取
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

    // SNID 共 5bit(试行规约 §5.1.2.2.1/表16):低位在 FCH(0,4,4),高位按帧型坐标合并:
    //   SOF 载波 BPLC(表20)=(5,0,1) / 信标 载波(12,1,1) 无线(12,0,1) /
    //   ACK(表19/21)=(4,0,1) / COORD(表41)=(12,0,1);无线 SOF(表131)byte12 为保留,无高位。
    // 列显示统一用合并后的 5bit SNID(有效取值 1-31)。
    {
        const quint8* fch = reinterpret_cast<const quint8*>(r.payload_for_log.constData());
        quint8 snid_high = 0;
        switch (r.mpdu.frame_type) {
            case 0:  // 信标帧:载波(12,1,1) 无线(12,0,1)
                snid_high = (r.meta.is_rf ? ((fch[12] >> 0) & 0x01) : ((fch[12] >> 1) & 0x01));
                break;
            case 1:  // SOF:BPLC 载波(5,0,1);无线 SOF 无 SNID 高位
                if (!r.meta.is_rf) snid_high = (fch[5] & 0x01);
                break;
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

    const NW_2021_FrameType ftype = static_cast<NW_2021_FrameType>(r.mpdu.frame_type);


    const quint8* p = reinterpret_cast<const quint8*>(r.payload_for_log.constData());

    if (ftype == NW_2021_FrameType::SOF) {
        // SOF:源/目的 TEI(载波与无线同坐标)+ PB 大小(载波 TMI / 无线 PBLen)
        r.mpdu.src_tei = (quint16)get_bits(p, 1, 0, 12);
        r.mpdu.dst_tei = (quint16)get_bits(p, 2, 4, 12);
        r.mpdu.link_id = (quint8) get_bits(p, 4, 0, 8);
        if (r.meta.is_rf) {
            // 无线 SOF 可变域(第2部分表131):帧长(5,0,12,单位100µs)/载荷PB大小(6,4,4)/
            // MCS(7,0,4)/TEI过滤(7,4,1)/重传(7,5,1);其余为保留(字节8-11 整段、
            // (7,6,2)、(12,0,4)),无 PB 个数与符号数字段
            r.mpdu.frame_len = (quint16)get_bits(p, 5, 0, 12);
            quint8 pblen = (quint8)get_bits(p, 6, 4, 4);
            r.mpdu.mcs     = (quint8)get_bits(p, 7, 0, 4);   // MCS(表131)
            r.mpdu.pblen   = pblen;                       // 载荷 PB 大小索引(表130)
            { const int sz = nw_2021_rf_pb_size(pblen); r.mpdu.pb_size = (quint16)(sz > 0 ? sz : 0); }
            r.mpdu.pb_num  = 1;                           // 无线信道仅 1 个物理块
            r.mpdu.re_send_flag = (get_bits(p, 7, 5, 1) != 0);    // 重传标志位(表131)
            r.mpdu.symbol_num   = 0;                              // 无线无符号数字段
            r.mpdu.tmi_ext      = (quint8) get_bits(p, 12, 0, 4); // (12,0,4) 保留,存原始值
        } else {
            r.mpdu.pb_num    = (quint8) get_bits(p, 7, 0, 4);
            r.mpdu.tmi       = (quint8) get_bits(p, 7, 4, 4);
            r.mpdu.frame_len = (quint16)get_bits(p, 8, 0, 12);
            r.mpdu.re_send_flag = (get_bits(p, 10, 6, 1) != 0);   // 重传标志位(表18)
            r.mpdu.symbol_num   = (quint16)get_bits(p, 10, 7, 9);  // 符号数(表16)
            r.mpdu.tmi_ext   = (quint8) get_bits(p, 12, 0, 4);
            { const int sz = nw_2021_pb_size(r.mpdu.tmi, r.mpdu.tmi_ext); r.mpdu.pb_size = (quint16)(sz > 0 ? sz : 0); }
            // PBNum 精确上限(用户拍板):meta.channel 即载波频段号(剥头 payload[2],
            // PLC=频段 0-2),按频段×TMI/TMI_EXT 查 nw_2021_max_pb_num;超限/组合无效拒收。
            // 前提说明:裸 hex 导入(from_raw)无媒介头,channel=默认 0 → 按 band0 上限校验
            //(错频段只会错严/错松,不会崩);channel>=3(媒介头异常)查表 -1 → 拒收。
            if (!r.meta.is_rf && r.mpdu.pb_num > 0) {
                const int ub = nw_2021_max_pb_num(r.meta.channel, r.mpdu.tmi, r.mpdu.tmi_ext);
                if (ub < 0 || r.mpdu.pb_num > ub) {
                    r.reject_reason = trl::L("PB 块数超上限(band=%1 tmi=%2 ext=%3 num=%4 max=%5)")
                        .arg(r.meta.channel).arg(r.mpdu.tmi).arg(r.mpdu.tmi_ext)
                        .arg(r.mpdu.pb_num).arg(ub);
                    r.accept = false;
                    return r;
                }
            }
            // 线 PBNum 留存:归一门会覆盖 pb_num,树“PB Num”位段节点显示线值用
            // (与 GW 解析器留存线字段口径一致)。
            r.mpdu.pb_num_field = r.mpdu.pb_num;
            // PBNum=0 实帧归一:载波 SOF 帧头 PBNum=0 但 TMI 查表得有效块长
            // (pb_size>8)时,块体确实存在于偏移 16(实证:PBNum=0/TMI=0 → 520B,
            // 整块 CRC24 通过);此时按 1 块组装,否则 :212 门与循环双重跳过,
            // MSDU 恒空且 pb_crc_ok 恒 false(误报 FAIL)。pb_size<=8 时不归一,
            // 保留 0 块语义(pb_size=0 的合法 0 块路径不受影响)。门与循环不动。
            if (r.mpdu.pb_num == 0 && r.mpdu.pb_size > 8) r.mpdu.pb_num = 1;
        }
        // PB 块重组 + CRC24 校验 + **帧内按序列号重排**
        // (南网:块 = PB头4B + 块体(pb_size-8) + 保留1B + CRC24 3B;
        //  序列号 = byte0 bit0-7 + byte1 bit0-7 = 16bit LE,BPLC 表133 / SPLC 表47)
        if (r.mpdu.pb_size > 8 && r.mpdu.pb_num > 0) {
            pb_asm::PbLayout lay{/*head*/4, /*rsv*/1, /*crc*/3,
                                 /*agg_byte*/-1, /*agg_bit*/-1,
                                 /*base*/16};
            lay.seq_byte = 0;
            lay.seq_mask = 0xFFFF;
            const pb_asm::AssembleResult res =
                pb_asm::assemble_pb_blocks(r.payload_for_log, r.mpdu.pb_num,
                                           r.mpdu.pb_size, lay);
            // 逐块头/CRC 按到达序存(UI 序列判定依赖线序;体流按 seq 序)
            pb_asm::arrival_order_blocks(res, &r.mpdu.pb_heads, &r.mpdu.pb_crc_oks);
            // 截断不空转:已校验块数必须等于声明块数,否则未校验块会被误报 CRC 通过。
            // 帧级 CRC 口径再叠加序列号重排成功(缺块/越界/冲突 → false)。
            r.mpdu.pb_crc_ok = res.all_crc_ok && !res.truncated
                               && (r.mpdu.pb_crc_oks.size() == r.mpdu.pb_num)
                               && res.reassembly_ok;
            const QByteArray msdu_body = res.msdu_body;
            if (!msdu_body.isEmpty()) {
                r.msdu_body = msdu_body;
                // BPLC 表107:单跳帧协议(版本=2)载波不支持、仅无线信道支持
                // (BPLC §8.1.2.4/表113;SPLC 第4部分 5.1.2.4/表12 同结论);
                // 载波信道收到属异常(排查信道/串口错配)。例外测试见
                // samples/gen_nw_bplc_frames.py build_singlehop_rfdl(载波外壳+is_rf=0)。
                if (!r.meta.is_rf && (((quint8)msdu_body[0] >> 1) & 0x03) == 2)
                    qWarning("NW_2021: single-hop MAC version=2 on PLC channel (isRF=0)");
                // 用户 2026-11 裁决(原话):「DROP 只有在 fc crc 就失败时标记,否则应先解析,
                // 存在 CRC 失败即标记红色」「MSDU CRC 正确即解析」「MSDU CRC32 FAIL 也标红」。
                // ⇒ PB 块 CRC 不再作为 MSDU 解析的前置门控:
                //   先按候选解析,再由 MSDU CRC32 三态决定是否采用(实现见 common/msdu_crc_state.h,
                //   与 packetlistmodel 的标红判据共用同一份);
                //   FAIL ⇒ 摘要清空、字段树只留 `MSDU CRC32 … FAIL` 证据节点(msdu_crc_gate)。
                // 序号完整性(body_parseable:缺块/重复冲突/越界)只在 MSDU CRC 缺失(N-A)时兜底,
                // 防止错位体流在没有校验证据的情况下被当成有效载荷。
                {
                    const MsduInfo cand = NW_2021_MsduParser::parse(msdu_body);
                    const MsduCrcState crc_state = msdu_crc_state(cand);
                    if (crc_state != MsduCrcState::NotAvailable || pb_asm::body_parseable(res)) {
                        r.msdu = msdu_crc_gate(cand);
                        r.msdu_raw_base = (r.mpdu.pb_num == 1) ? (16 + 4) : -1;
                    } else {
                        r.msdu.summary = trl::L("PB 序号异常未解析");
                    }
                }
            }
        }
    } else if (ftype == NW_2021_FrameType::BEACON) {
        // BEACON:信标时间戳/周期计数/源 TEI(载波与无线同坐标)
        r.mpdu.beacon_timestamp  = (quint32)get_bits(p, 1, 0, 32);
        r.mpdu.beacon_period_cnt = (quint32)get_bits(p, 5, 0, 32);
        r.mpdu.src_tei           = (quint16)get_bits(p, 9, 0, 12);
        if (r.meta.is_rf) {
            r.mpdu.mcs     = (quint8)get_bits(p, 10, 4, 4);   // MCS(表128)
            r.mpdu.pblen   = (quint8)get_bits(p, 11, 0, 4);   // 载荷 PB 大小索引(表130)
            { const int sz = nw_2021_rf_pb_size(r.mpdu.pblen); r.mpdu.pb_size = (quint16)(sz > 0 ? sz : 0); }
        } else {
            r.mpdu.tmi       = (quint8)get_bits(p, 10, 4, 4); // 载波映射表索引
            r.mpdu.symbol_num = (quint16)get_bits(p, 11, 0, 9);
            r.mpdu.beacon_line = (quint8)get_bits(p, 12, 2, 2);
            { const int sz = nw_2021_pb_size(r.mpdu.tmi, 0); r.mpdu.pb_size = (quint16)(sz > 0 ? sz : 0); }
        }
        // 信标帧载荷区(固定头 + 管理信息 + BPCS CRC32 + 保留字节 + PB CRC24)
        if (r.mpdu.pb_size > 0)
            r.beacon = NW_2021_BeaconParser::parse_beacon(r.payload_for_log, r.mpdu.pb_size, r.meta.is_rf);
    } else if (ftype == NW_2021_FrameType::ACK) {
        // ACK(南网 MPDU_ACK_FCH 坐标,表19/表21)
        r.mpdu.ack_ext_type = (quint8)get_bits(p, 12, 0, 4);
        switch (static_cast<NW_2021_AckExtType>(r.mpdu.ack_ext_type)) {
            case NW_2021_AckExtType::Search:  // 网络搜索帧(抄控器,表21)
                r.mpdu.ack_dst_addr   = get_bits(p, 1, 0, 48);
                r.mpdu.ack_search_tei = (quint16)get_bits(p, 7, 0, 12);
                break;
            case NW_2021_AckExtType::Sync:  // 同步帧(抄控器,表21)
                r.mpdu.ack_sync_timestamp = (quint32)get_bits(p, 1, 0, 32);
                r.mpdu.ack_sync_tei       = (quint16)get_bits(p, 5, 0, 12);
                break;
            case NW_2021_AckExtType::Normal:
            default:
                // 选择确认帧(表19);未知扩展帧类型(表21"其他")默认按选择确认帧解析
                r.mpdu.ack_rx_res    = (quint8) get_bits(p, 1, 0, 4);
                r.mpdu.ack_rx_status = (quint8) get_bits(p, 1, 4, 4);
                r.mpdu.dst_tei       = (quint16)get_bits(p, 2, 0, 12);
                r.mpdu.ack_rx_pb_num = (quint8) get_bits(p, 3, 4, 4);
                break;
        }
    } else if (ftype == NW_2021_FrameType::COORD) {
        // COORD(南网 MPDU_COORD_FCH 坐标)
        r.mpdu.coord_neighbour_nid     = (quint32)get_bits(p, 1, 0, 16);  // 邻居 NID 位图 16b
        r.mpdu.coord_duration          = (quint16)get_bits(p, 5, 2, 14);  // 时长(×40ms)
        r.mpdu.coord_band_end_flag     = (quint8) get_bits(p, 7, 1, 1);
        r.mpdu.coord_band_end_offset   = (quint16)get_bits(p, 8, 0, 16);  // ×4ms
        r.mpdu.coord_band_start_offset = (quint16)get_bits(p, 10, 0, 16); // ×4ms
        r.mpdu.coord_rsv1             = (quint16)get_bits(p, 4, 0, 10);   // 保留(4-5,10b)
        r.mpdu.coord_rsv2             = (quint8) get_bits(p, 7, 0, 1);    // 保留(7 bit0,1b)
        r.mpdu.coord_rsv3             = (quint8) get_bits(p, 7, 2, 6);    // 保留(7 bit2-7,6b)
        r.mpdu.coord_rsv0             = (quint8) get_bits(p, 12, 0, 4);   // 保留(12 bit0-3,4b)
    }

    r.accept = true;
    return r;
}
