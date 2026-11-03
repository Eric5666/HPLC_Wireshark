/// @file bplcparser.cpp
/// @brief GW_2026_Parser 实现(总控):物理头剥取 + FCH 公共头 + 帧分发
/// @details 各帧型字段/载荷解析委托给独立模块:
///          BEACON -> GW_2026_BeaconParser(beacon/);SOF -> gw_2026_sof::assemble(sof/);
///          ACK -> gw_2026_ackp::parse_fch(ack/);COORD -> gw_2026_coordp::parse_fch(coord/)。
///          位域/CRC 公共工具见 fieldspec.h。
#include "gw_2026_parser.h"
#include "gw_2026_pb_table.h"
#include "gw_2026_tree.h"
#include "i18n.h"
#include "statistics.h"
#include "gw_2026_beacon_parser.h"
#include "gw_2026_sof_parser.h"
#include "gw_2026_ack_parser.h"
#include "gw_2026_coord_parser.h"
#include "common/fieldtools.h"
#include "common/bcd.h"
#include "crc.h"
#include "QsLog.h"
#include <QDateTime>
#include <QElapsedTimer>
#include <QtEndian>

namespace {

// ── parse 细分统计(env/mpdu/body 计时;委托帧以 delegate 口径计入)──
// 原为 parse() 内函数级 static;版本自适应委托(版本=0 帧)在统计段之前
// return,会把 HDC 1.0 帧漏出统计 → 提为文件级 helper,委托路径同样记账,
// 保证混合流量下 breakdown 日志的分母 = 全部成功解析帧(含委托帧)。
void stats_account(qint64 us_env, qint64 us_mpdu, qint64 us_body) {
    static std::atomic<quint64> n{0}, env_us{0}, mpdu_us{0}, body_us{0};
    const quint64 c = n.fetch_add(1) + 1;
    env_us.fetch_add(quint64(us_env));
    mpdu_us.fetch_add(quint64(us_mpdu));
    body_us.fetch_add(quint64(us_body));
    if (c % 50000 == 0) {
        QLOG_DEBUG() << "parse breakdown:" << c << "frames: env total"
                     << env_us.load() / 1000 << "ms, mpdu total"
                     << mpdu_us.load() / 1000 << "ms, body total"
                     << body_us.load() / 1000 << "ms";
    }
}

}  // namespace

GW_2026_Parser::GW_2026_Parser() {}

// 学习层合并(供 OFDMA/TDA 站点 MSDU 用):对全并、头对以对形式并入、topo 事件首个进 topo_event、其余进 topo_extra_events;
// 头对字段见 HDC2.0 4-2 表2 标准 MAC 帧头;不改 present/摘要/树显示(站点 MSDU 仅作学习源,不进包列表 MSDU 列)。
static void merge_msdu_learn(MsduInfo& dst, const MsduInfo& src) {
    for (const auto& p : src.tei_mac_pairs) dst.tei_mac_pairs.append(p);
    if (src.msdu_src_tei > 0 && src.msdu_src_mac != 0)
        dst.tei_mac_pairs.append({(quint16)src.msdu_src_tei, src.msdu_src_mac});
    if (src.msdu_dst_tei > 0 && src.msdu_dst_mac != 0)
        dst.tei_mac_pairs.append({(quint16)src.msdu_dst_tei, src.msdu_dst_mac});
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
        if (src.msdu_src_tei > 0)
            add_orig_src((quint16)src.msdu_src_tei, src.msdu_src_mac);
        for (const auto& p : src.orig_srcs) add_orig_src(p.tei, p.mac);
    }
    // 聚合/多站点目的(与源镜像:仅当帧级尚无原始目的 TEI 时收集)。
    if (dst.msdu_dst_tei <= 0) {
        auto add_orig_dst = [&](quint16 tei, quint64 mac) {
            if (tei == 0) return;
            for (const auto& p : dst.orig_dsts)
                if (p.tei == tei && p.mac == mac) return;
            dst.orig_dsts.append({tei, mac});
        };
        if (src.msdu_dst_tei > 0)
            add_orig_dst((quint16)src.msdu_dst_tei, src.msdu_dst_mac);
        for (const auto& p : src.orig_dsts) add_orig_dst(p.tei, p.mac);
    }
    if (src.topo_event.kind != TopoEventKind::Other) {
        if (dst.topo_event.kind == TopoEventKind::Other)
            dst.topo_event = src.topo_event;
        else
            dst.topo_extra_events.append(src.topo_event);
    }
    // 稳健性:src 若本身已是合并结果,其 extras 一并传递(单站解析时恒空)。
    for (const auto& e : src.topo_extra_events) dst.topo_extra_events.append(e);
}

// 剥物理层头
bool GW_2026_Parser::decode_envelope(const BplcFrame& in, Result& r) {
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

// MPDU_BASE 公共头(FCH 前 16B:类型/网络/版本/FCH CRC24;HDC 2.0 表4)
bool GW_2026_Parser::parse_mpdu_base(const QByteArray& body, MpduInfo& info, QString& err) {
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
    // HDC 2.0(表4):网络标识缩为 16bit(byte1-2,有效值 1-65535),
    // byte3 整字节改为保留(HDC 1.0 为 24bit NID)
    info.net_id     = (quint32)get_bits(p, 1, 0, 16);
    info.version    = (quint8)get_bits(p, 12, 4, 4);
    return true;
}

// 主入口:帧分发
GW_2026_Parser::Result GW_2026_Parser::parse(const BplcFrame& in, MsduState& msdu, const Filter& f) {
    Result r = parse_inner(in, msdu, f);
    m_time_anchor.apply(r, m_display_ctx);
    return r;
}

GW_2026_Parser::Result GW_2026_Parser::parse_inner(const BplcFrame& in, MsduState& msdu, const Filter& f) {
    Result r;
    r.protocol = ProtocolVariant::GW_2026;   // 协议身份由解析器标记
    QElapsedTimer pt;
    pt.start();
    if (!decode_envelope(in, r)) {
        r.accept = false;
        return r;
    }
    const qint64 us_env = pt.nsecsElapsed() / 1000;

    // ── HDC 版本自适应(表4 标准版本号 byte12 bit4-7)──
    // GW_2022(HDC 1.0)是 GW_2026 的字节序子集:FCH 校验通过且版本=0 的帧,
    // 委托 GW_2022 解析器按 HDC 1.0 布局解析展示(字段坐标/NID 24bit/表19 SOF 等),
    // 协议身份同步标记为 GW_2022(帧列表协议列/字段树/序列化一致);
    // 版本=1(HDC 2.0)走下方 GW_2026 新布局。直接透传 MsduState(重组状态跨协议共享)。
    {
        QString ver_err;
        if (parse_mpdu_base(r.payload_for_log, r.mpdu, ver_err)) {
            // P3:跨代重组隔离——MsduState 为会话级共享缓冲,在途分片携带代际标记,
            // 1.0/2.0 交替到达时丢弃旧代分片(半包跨代无重组意义,新 MSDU 自会重启重组),
            // 否则两代 PB 会混拼出一个校验必错的坏 MSDU。
            const int proto_tag =
                (static_cast<GW_2026_Version>(r.mpdu.version) == GW_2026_Version::HDC_1_0) ? 0 : 1;
            if (msdu.reasm_proto != -1 && msdu.reasm_proto != proto_tag) {
                msdu.buffer.clear();
                msdu.received_count = 0;
                msdu.expected_len   = 0;
                msdu.complete       = false;
            }
            msdu.reasm_proto = proto_tag;
            switch (static_cast<GW_2026_Version>(r.mpdu.version)) {
                case GW_2026_Version::HDC_1_0: {
                    // 版本号是帧内字段,委托后直接返回 GW_2022 的结果
                    //(含其自身的过滤/统计/协议标记)。
                    // 委托耗时计入本协议统计(delegate 口径,分母含 HDC 1.0 帧):
                    // env=共用剥头+版本探测,mpdu/body 由 legacy.parse_inner 全包
                    // (不做显示时间判定,外层 parse() 统一用本解析器锚点做)
                    const qint64 us_del = pt.nsecsElapsed() / 1000 - us_env;
                    stats_account(us_env, us_del, 0);
                    return m_legacy.parse_inner(in, msdu, f);
                }
                case GW_2026_Version::HDC_2_0:
                    break;  // 新协议,继续走 GW_2026 解析
                default:
                    // 保留版本值:按 HDC 2.0 布局尝试(版本字段树会显示 Reserved),
                    // 不拒收——保留值语义由编制方后续明确
                    break;
            }
        }
        // FCH 校验失败:不在此拒收,继续按 2.0 解析得到更具体的错误信息
    }

    QString err;
    if (!parse_mpdu_base(r.payload_for_log, r.mpdu, err)) {
        r.reject_reason = err;
        r.accept = false;
        return r;
    }
    const qint64 us_mpdu = pt.nsecsElapsed() / 1000 - us_env;

    const GW_2026_FrameType ft = static_cast<GW_2026_FrameType>(r.mpdu.frame_type);

    const quint8* p =
        reinterpret_cast<const quint8*>(r.payload_for_log.constData());

    if (ft == GW_2026_FrameType::SOF) {
        // SOF:FCH 字段 + 多 PB 重组(sof 模块)
        err = gw_2026_sof::assemble(r.payload_for_log, r.mpdu, msdu, r.msdu_body,
                                    r.meta.is_rf ? 0xFF : (quint8)r.meta.channel,
                                    r.meta.is_rf);
        if (!err.isEmpty()) { r.reject_reason = err; r.accept = false; return r; }
        // MSDU 重组完整:解析 MAC 层字段
        if (!r.msdu_body.isEmpty()) {
            r.msdu = GW_2026_MsduParser::parse(r.msdu_body);
            // MSDU body 起点在 payload_for_log 中的偏移:FCH 16B + 1B pb_head = 17。
            // 仅当单块(整条 MSDU 连续位于本帧 17..)时才能把字段映射到 raw 高亮;
            // 多块重组时各 pb_body 在 raw 中被 pb_head/CRC 隔断,不连续,置 -1。
            r.msdu_raw_base = (r.mpdu.pb_num == 1) ? 17 : -1;
        }
        // 多站点帧(OFDMA/TDA,HDC2.0 4-2 表10/11/12/13):各站 MSDU 只组装进 sof_stations,
        // 从未进通用解析;逐站解析仅合并学习(对 + 头对 + 首个 topo 事件),不改显示。
        // 注意:sof_parser 只在**站内序列号落位成功**时才填 st.msdu(否则留空),
        // 所以下面的 isEmpty() 门已同时覆盖「缺块/越界/重复冲突 → 不解析不学习」,
        // 与南网 body_parseable 口径一致。
        for (const auto& st : r.mpdu.sof_stations) {
            if (st.msdu.isEmpty()) continue;
            // CRC 失败块不解析(用户 2026-10-29 定,NW 同款多块补定):
            // 本站全好,或本站 MSDU span 避开坏块,才解析合并;否则该站
            // 不解析不学习,坏块字节不进 tei_mac_pairs/orig/topology。
            // 本站 MSDU 只用于学习,故无需摘要附注;块 CRC 失败仍由
            // pb_crc_oks/红行可见。单站点已由 assemble 的 seq 链等价
            // 覆盖(任一坏块即无完整 MSDU),此处不另设门。
            bool all_ok = true;
            for (bool ok : st.pb_crc_oks) all_ok = all_ok && ok;
            if (!all_ok
                && !gw_2026_sof::msdu_span_avoids_bad_blocks(
                       st.msdu, st.pb_crc_oks, int(st.pb_size) - 4))   // 块体长度 = 块长 - 头1B - CRC3B
                continue;
            merge_msdu_learn(r.msdu, GW_2026_MsduParser::parse(st.msdu));
        }
    } else if (ft == GW_2026_FrameType::BEACON) {
        // BEACON:FCH 摘要 + 载荷区解析(beacon 模块)
        r.mpdu.beacon_timestamp = (quint32)get_bits(p, 4, 0, 32);
        r.mpdu.src_tei          = (quint16)get_bits(p, 8, 0, 12);
        if (r.meta.is_rf) {
            // 无线信标(表18):(9,4,4) 为 MCS、(10,0,4) 为载荷 PB 大小码,
            // 其余 (10,4,4)+(11,0,8)+(12,0,4) 为保留,无符号数/相线字段
            r.mpdu.mcs          = (quint8) get_bits(p, 9, 4, 4);
            r.mpdu.pb_num_field = (quint8) get_bits(p, 10, 0, 4);   // 载荷 PB 大小码
            const int sz = gw_2026_rf_pb_size(r.mpdu.pb_num_field);
            r.mpdu.pb_size    = (quint16)(sz > 0 ? sz : 0);
            r.mpdu.symbol_num = 0;
            r.mpdu.beacon_line = 0;
            r.mpdu.beacon_rsv = (quint16)get_bits(p, 10, 4, 16);    // 保留原始值(供字段树呈现)
        } else {
            // 载波信标(表5):PB 大小由分集拷贝模式(tmi)查表;
            // 无效 TMI 不再把 -1 铸成 65535;FCH符号数(11,3,2) 跨字节
            r.mpdu.tmi          = (quint8) get_bits(p, 9, 4, 4);
            const int sz = gw_2026_pb_size(r.mpdu.tmi);
            r.mpdu.pb_size    = (quint16)(sz > 0 ? sz : 0);  // 单块帧块长
            r.mpdu.symbol_num = (quint16)get_bits(p, 10, 0, 9);
            r.mpdu.beacon_fch_sym = (quint8)((get_bits(p, 11, 3, 2)));
            r.mpdu.beacon_line = (quint8) get_bits(p, 11, 1, 2);
            r.mpdu.beacon_rsv = (quint16)get_bits(p, 11, 5, 7);     // 保留原始值(供字段树呈现)
        }
        r.beacon = GW_2026_BeaconParser::parse_beacon(r.payload_for_log, r.meta.is_rf);
        if (r.beacon.present) {
            const QByteArray& gb = r.payload_for_log;
            const quint8* gp = reinterpret_cast<const quint8*>(gb.constData());
            r.mpdu.beacon_type       = (quint8)get_bits(gp, 16 + 0, 0, 3);
            r.mpdu.beacon_netsn      = (quint8)get_bits(gp, 16 + 1, 0, 8);
            r.mpdu.beacon_cco_mac    = get_bits(gp, 16 + 2, 0, 48);
            r.mpdu.beacon_period_cnt = (quint32)get_bits(gp, 16 + 8, 0, 32);
            // 精简信标(表56)无字节12 信道编号;管理区(条目数)位于
            // 字节12(精简)或 20(标准)
            const bool lite = ((quint8)gb.at(16) & 0x10) != 0;
            r.mpdu.beacon_rf_channel = lite ? 0
                                            : (quint8)get_bits(gp, 16 + 12, 0, 8);
            // HDC 2.0(表38):字节13 bit2-3 新增 信标机制状态/发现信标发送使能
            // (13,0-1 本网络无线 option 模式);精简信标无字节13
            if (!lite) {
                r.mpdu.beacon_rf_option    = (quint8)get_bits(gp, 16 + 13, 0, 2);
                r.mpdu.beacon_mech_state   = (quint8)get_bits(gp, 16 + 13, 2, 1);
                r.mpdu.beacon_discover_en  = (quint8)get_bits(gp, 16 + 13, 3, 1);
            } else {
                r.mpdu.beacon_rf_option    = 0;
                r.mpdu.beacon_mech_state   = 0;
                r.mpdu.beacon_discover_en  = 0;
            }
            r.mpdu.beacon_item_num   = (quint8)gb.at(16 + (lite ? 12 : 20));
        }
    } else if (ft == GW_2026_FrameType::ACK) {
        // ACK(ack 模块)
        gw_2026_ackp::parse_fch(p, r.mpdu);
    } else if (ft == GW_2026_FrameType::COORD) {
        // 网间协调帧 COORD(coord 模块)
        gw_2026_coordp::parse_fch(p, r.mpdu);
    }

    // parse 细分统计(成功路径):env=物理头/FCH, mpdu=MPDU 基础, body=MSDU/BEACON 字段树
    stats_account(us_env, us_mpdu, pt.nsecsElapsed() / 1000 - us_env - us_mpdu);
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
        trl::register_en("FCH CRC24 错(calc=%1 rx=%2)", "FCH CRC24 Error (calc=%1 rx=%2)");
    }
};
const I18nRegParser g_i18n_reg_parser;
}  // namespace
