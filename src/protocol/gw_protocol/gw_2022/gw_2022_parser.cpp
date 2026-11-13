/// @file bplcparser.cpp
/// @brief GW_2022_Parser 实现(总控):物理头剥取 + FCH 公共头 + 帧分发
/// @details 各帧型字段/载荷解析委托给独立模块:
///          BEACON -> GW_2022_BeaconParser(beacon/);SOF -> gw_2022_sof::assemble(sof/);
///          ACK -> gw_2022_ackp::parse_fch(ack/);COORD -> gw_2022_coordp::parse_fch(coord/)。
///          位域/CRC 公共工具见 fieldspec.h。
#include "gw_2022_parser.h"
#include "gw_2022_pb_table.h"
#include "gw_2022_tree.h"
#include "i18n.h"
#include "statistics.h"
#include "gw_2022_msdu_parser.h"
#include "gw_2022_beacon_parser.h"
#include "gw_2022_sof_parser.h"
#include "gw_2022_ack_parser.h"
#include "gw_2022_coord_parser.h"
#include "common/fieldtools.h"
#include "common/bcd.h"
#include "common/msdu_crc_state.h"
#include "crc.h"
#include "QsLog.h"
#include <QDateTime>
#include <QElapsedTimer>
#include <QtEndian>



GW_2022_Parser::GW_2022_Parser() {}

// 剥物理层头
bool GW_2022_Parser::decode_envelope(const BplcFrame& in, Result& r) {
    r.meta = in.meta;
    r.arrival_us = in.arrival_us;   // 实时串口帧起始 0x3C 高精度接收时刻
    r.raw_wire   = in.raw_wire;     // 原始串口帧原样(调试复制)
    const QByteArray& d = in.data;

    if (in.meta.from_raw) {
        // 裸 hex 文本(每行一帧):行首字节 = isRF,其后为纯 MPDU
        if (d.size() < 2) { r.reject_reason = trl::L("空帧"); return false; }
        r.meta.is_rf = (quint8(d[0]) != 0);
        r.payload_for_log = d.mid(1);
        // frame_time 已由 SerialReader 从文本头时间填充(r.meta 已拷贝)
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
        // 无时间标签:frame_time 已由 SerialReader 填充(回放时间轴/本地接收时刻)
        r.meta.epoch_ms = r.meta.frame_time.toMSecsSinceEpoch();  // 补 epoch_ms 缓存
    }

    int offset = hdr;
    quint16 data_len = (quint8)d[offset] | ((quint8)d[offset + 1] << 8);
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

    // 去掉 4 字节媒介头(phr_mcs/option/channel/isRF),payload_for_log = 纯 MPDU
    payload.remove(0, 4);
    r.payload_for_log = payload;
    if (payload.isEmpty()) {
        r.reject_reason = trl::L("剥头后空载荷");
        return false;
    }

    Q_UNUSED(data_len);
    return true;
}

// MPDU_BASE 公共头(FCH 前 16B:类型/网络/版本/FCH CRC24)
bool GW_2022_Parser::parse_mpdu_base(const QByteArray& body, MpduInfo& info, QString& err) {
    if (body.size() < 16) { err = trl::L("MPDU_BASE 长度不足 16B"); return false; }
    const quint8* p = reinterpret_cast<const quint8*>(body.constData());

// crc24_lsb 内部遍历 len-3 字节;此处传 16(FCH 全长)即校验前 13B,
// 末 3B 为本 CRC 自身(crc.h 约定,勿传 13 否则少算 3B)
    quint32 calc_crc = crc24_lsb(p, 16);
    // FCH CRC24 字段小端存储(字节 6c 13 2a → 0x2a136c)
    quint32 fch_crc  = (quint32)p[13]
                     | ((quint32)p[14] << 8)
                     | ((quint32)p[15] << 16);
    info.fch_crc_ok = (calc_crc == fch_crc);
    info.fch_crc_checked = true;
    if (!info.fch_crc_ok) {
        err = trl::L("FCH CRC24 错(calc=%1 rx=%2)")
              .arg(calc_crc, 6, 16, QChar('0')).arg(fch_crc, 6, 16, QChar('0'));
        return false;
    }

    info.frame_type = (quint8)get_bits(p, 0, 0, 3);
    info.net_type   = (quint8)get_bits(p, 0, 3, 5);
    info.net_id     = (quint32)get_bits(p, 1, 0, 24);
    info.version    = (quint8)get_bits(p, 12, 4, 4);
    return true;
}

// 主入口:帧分发
GW_2022_Parser::Result GW_2022_Parser::parse(const BplcFrame& in, MsduState& msdu, const Filter& f) {
    Result r = parse_inner(in, msdu, f);
    m_time_anchor.apply(r, m_display_ctx);
    return r;
}

GW_2022_Parser::Result GW_2022_Parser::parse_inner(const BplcFrame& in, MsduState& msdu, const Filter& f) {
    Q_UNUSED(f);  // 解析时不过滤(仅显示过滤),过滤参数不再读取
    Result r;
    r.protocol = ProtocolVariant::GW_2022;   // 协议身份由解析器标记
    QElapsedTimer pt;
    pt.start();
    if (!decode_envelope(in, r)) {
        r.accept = false;
        return r;
    }
    const qint64 us_env = pt.nsecsElapsed() / 1000;

    QString err;
    if (!parse_mpdu_base(r.payload_for_log, r.mpdu, err)) {
        r.reject_reason = err;
        r.accept = false;
        return r;
    }
    const qint64 us_mpdu = pt.nsecsElapsed() / 1000 - us_env;

    const GW_2022_FrameType ft = static_cast<GW_2022_FrameType>(r.mpdu.frame_type);

    const quint8* p =
        reinterpret_cast<const quint8*>(r.payload_for_log.constData());

    if (ft == GW_2022_FrameType::SOF) {
        // SOF:FCH 字段 + 多 PB 重组(sof 模块)
        bool msdu_span_clean = false;
        err = gw_2022_sof::assemble(r.payload_for_log, r.mpdu, msdu, r.msdu_body,
                                    r.meta.is_rf ? 0xFF : (quint8)r.meta.channel,
                                    r.meta.is_rf, &msdu_span_clean);
        if (!err.isEmpty()) { r.reject_reason = err; r.accept = false; return r; }
        // MSDU 重组完整:解析 MAC 层字段
        if (!r.msdu_body.isEmpty()) {
            r.msdu = GW_2022_MsduParser::parse(r.msdu_body);
            // MSDU CRC32 是拓扑学习的最终判据:有效 MSDU CRC 可覆盖 PB CRC 失败;
            // 仅当 MSDU CRC 不可用且首个 MSDU span 落在坏块上时,才剥离学习字段
            // (解析与展示保留;FAIL 仍走 parse 内 msdu_crc_gate 降级)。
            if (msdu_crc_state(r.msdu) == MsduCrcState::NotAvailable && !msdu_span_clean)
                r.msdu = msdu_crc_strip_learning(r.msdu);
            // MSDU body 起点在 payload_for_log 中的偏移:FCH 16B + 1B pb_head = 17。
            // 仅当单块(整条 MSDU 连续位于本帧 17..)时才能把字段映射到 raw 高亮;
            // 多块重组时各 pb_body 在 raw 中被 pb_head/CRC 隔断,不连续,置 -1。
            r.msdu_raw_base = (r.mpdu.pb_num == 1) ? 17 : -1;
        }
    } else if (ft == GW_2022_FrameType::BEACON) {
        // BEACON:FCH 摘要 + 载荷区解析(beacon 模块)
        r.mpdu.beacon_timestamp = (quint32)get_bits(p, 4, 0, 32);
        r.mpdu.src_tei          = (quint16)get_bits(p, 8, 0, 12);
        if (r.meta.is_rf) {
            // 无线信标(表27):(9,4,4) 为 MCS、(10,0,4) 为载荷 PB 大小码(表29),
            // 其余 (10,4,4)+(11,0,8)+(12,0,4) 为保留,无符号数/相线字段
            r.mpdu.mcs          = (quint8) get_bits(p, 9, 4, 4);
            r.mpdu.pb_num_field = (quint8) get_bits(p, 10, 0, 4);   // 载荷 PB 大小码
            const int sz = gw_2022_rf_pb_size(r.mpdu.pb_num_field);
            r.mpdu.pb_size    = (quint16)(sz > 0 ? sz : 0);
            r.mpdu.symbol_num = 0;
            r.mpdu.beacon_line = 0;
            r.mpdu.beacon_rsv = (quint16)get_bits(p, 10, 4, 16);    // 保留原始值(供字段树呈现)
        } else {
            // 载波信标(表17):PB 大小由分集拷贝基本模式(tmi)查表;无效 TMI 不再把 -1 铸成 65535
            r.mpdu.tmi          = (quint8) get_bits(p, 9, 4, 4);
            const int sz = gw_2022_pb_size(r.mpdu.tmi);
            r.mpdu.pb_size    = (quint16)(sz > 0 ? sz : 0);  // 单块帧块长
            r.mpdu.symbol_num = (quint16)get_bits(p, 10, 0, 9);
            r.mpdu.beacon_line = (quint8) get_bits(p, 11, 1, 2);
            r.mpdu.beacon_rsv = (quint16)get_bits(p, 11, 3, 9);     // 保留原始值(供字段树呈现)
        }
        r.beacon = GW_2022_BeaconParser::parse_beacon(r.payload_for_log);
        if (r.beacon.present) {
            const QByteArray& gb = r.payload_for_log;
            const quint8* gp = reinterpret_cast<const quint8*>(gb.constData());
            r.mpdu.beacon_type       = (quint8)get_bits(gp, 16 + 0, 0, 3);
            r.mpdu.beacon_netsn      = (quint8)get_bits(gp, 16 + 1, 0, 8);
            r.mpdu.beacon_cco_mac    = get_bits(gp, 16 + 2, 0, 48);
            r.mpdu.beacon_period_cnt = (quint32)get_bits(gp, 16 + 8, 0, 32);
            // 精简信标(51243 表56)无字节12 信道编号;管理区(条目数)位于
            // 字节12(精简)或 20(标准)
            const bool lite = ((quint8)gb.at(16) & 0x10) != 0;
            r.mpdu.beacon_rf_channel = lite ? 0
                                            : (quint8)get_bits(gp, 16 + 12, 0, 8);
            r.mpdu.beacon_rf_option  = 0;
            r.mpdu.beacon_item_num   = (quint8)gb.at(16 + (lite ? 12 : 20));
        }
    } else if (ft == GW_2022_FrameType::ACK) {
        // ACK(ack 模块)
        gw_2022_ackp::parse_fch(p, r.mpdu);
    } else if (ft == GW_2022_FrameType::COORD) {
        // 网间协调帧 COORD(coord 模块)
        gw_2022_coordp::parse_fch(p, r.mpdu);
    }

    // parse 细分统计(成功路径):env=物理头/FCH, mpdu=MPDU 基础, body=MSDU/BEACON 字段树
    const qint64 us_body = pt.nsecsElapsed() / 1000 - us_env - us_mpdu;
    static std::atomic<quint64> n{0}, env_us{0}, mpdu_us{0}, body_us{0};
    const quint64 c = n.fetch_add(1) + 1;
    env_us.fetch_add(quint64(us_env));
    mpdu_us.fetch_add(quint64(us_mpdu));
    body_us.fetch_add(quint64(us_body));
    if (c % 50000 == 0) {
        QLOG_DEBUG() << "parse breakdown:" << c << "frames: env total" << env_us.load() / 1000
                     << "ms, mpdu total" << mpdu_us.load() / 1000
                     << "ms, body total" << body_us.load() / 1000 << "ms";
    }
    r.accept = true;
    return r;
}

namespace {
// 解析拒绝/错误文案的中→英词典(显示于 Info 列/错误提示)
struct I18nRegParser {
    I18nRegParser() {
        trl::register_en("空帧", "Empty Frame");
        trl::register_en("帧长过短", "Frame Too Short");
        trl::register_en("剥头后载荷过短(<4B)", "Payload Too Short After Header (<4B)");
        trl::register_en("剥头后空载荷", "Empty Payload After Header");
        trl::register_en("MPDU_BASE 长度不足 16B", "MPDU_BASE shorter than 16B");
    }
};
const I18nRegParser g_i18n_reg_parser;
}  // namespace
