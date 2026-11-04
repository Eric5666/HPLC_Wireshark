/// @file packetlistmodel.cpp
/// @brief PacketListModel 实现(磁盘换页)
#include "packetlistmodel.h"
#include "packetentry_serialize.h"
#include "mac_format.h"  // 48-bit MAC 格式化唯一实现(src/common)
#include <algorithm>
#include <cstdint>
#include <QColor>
#include <QDataStream>
#include <QDir>
#include "i18n.h"
#include <QFile>
#include <QtConcurrent>
#include <QFutureWatcher>
#include <QThreadPool>

namespace {
// 南网 NW_2021 应用层帧类型域(表4)确认/否认帧 + 业务标识(表9)确认/否认取值
struct I18nReg {
    I18nReg() {
        trl::register_en("训练帧(MIMO)", "Training Frame (MIMO)");
        trl::register_en("训练帧(Bitloading)", "Training Frame (Bitloading)");
        trl::register_en("CRC 不完整（截断）", "CRC incomplete (truncated)");
        trl::register_en("CRC 不完整（重组失败）", "CRC incomplete (reassembly failed)");
        trl::register_en("CRC OK（乱序已重排）", "CRC OK (reordered)");
        trl::register_en("CRC FAIL(%1/%2)", "CRC FAIL(%1/%2)");
        trl::register_en("CRC OK", "CRC OK");
        trl::register_en("CRC 不完整（缺块 %1）", "CRC incomplete (missing PB %1)");
        trl::register_en("PB 序号异常", "PB Sequence Error");
        trl::register_en("MAC* = 由当前 TEI↔MAC 映射推断，TEI 易主后会变化；STA-N* 中的 * 同理", "MAC* = inferred from the current TEI↔MAC mapping and follows TEI reassignment; same for * in STA-N*");
        trl::register_en("UL-OFDMA 数据帧（需触发）", "UL-OFDMA Data Frame (Needs Trigger)");
    }
};
const I18nReg g_i18n_reg_pktlist;

constexpr quint8 kAppPacketAckNack = 0x0;   ///< 帧类型域=确认/否认
constexpr quint8 kBidConfirm       = 0x00;  ///< BID=确认(ACK)
constexpr quint8 kBidDeny          = 0x01;  ///< BID=否认(NACK)

// ── PB 序列号派生信息(全部由已持久化字段推导,不新增存储) ──────────
// pb_heads 按**到达序**保存块头原始字节:国网 pb_head 低 6 位 = 序列号
// (bit7=END / bit6=START);南网 PB 头 byte0 = 16bit 序列号的低 8 位
// (BPLC 表133 / SPLC 表47)。据此可重建「乱序/缺块/序号异常」,
// 会话文件重载后表现一致(无需新增序列化字段)。
constexpr quint8 kPbSeqMaskGw = 0x3F;   ///< 国网:pb_head 低 6 位
constexpr quint8 kPbSeqMaskNw = 0xFF;   ///< 南网:PB 头 byte0 全 8 位

/// 按协议取 PB 头序列号掩码
quint8 pb_seq_mask(const PacketEntry& e) {
    const quint8 p = quint8(e.protocol & 0x7F);
    return (p == kProtocolGw2022 || p == kProtocolGw2026) ? kPbSeqMaskGw : kPbSeqMaskNw;
}

/// pb_heads/pb_num 推导出的序列号分布
struct PbSeqInfo {
    int  dup = 0;             ///< 重复序列号块数
    int  oob = 0;             ///< 序列号越界(>= pb_num)块数
    int  missing = 0;         ///< 缺失槽位数
    int  first_missing = -1;  ///< 首个缺失槽位
    bool reordered = false;   ///< 乱序到达
    bool all_same = false;    ///< 全部块序列号相同(设备未填,退回按位置拼接)
};

/// 由「块头字节序列 + 声明块数」推导序列号分布(单站帧与多站帧逐站复用同一规则)
PbSeqInfo analyze_pb_seq_heads(const QVector<quint8>& heads, int pb_num, quint8 mask) {
    PbSeqInfo si;
    const int n = heads.size();
    if (pb_num <= 1 || n <= 0) return si;
    QVector<int> slot(pb_num, 0);
    int first = -1;
    bool same = true;
    for (int i = 0; i < n; ++i) {
        const int seq = int(quint8(heads[i]) & mask);
        if (i == 0) first = seq;
        else if (seq != first) same = false;
        if (seq < 0 || seq >= pb_num) { ++si.oob; continue; }
        ++slot[seq];
        if (i != seq) si.reordered = true;
    }
    si.all_same = same;
    // 全部块序列号相同 = 设备未填序列号(主流情形)。与 pb_assembler 的
    // `seq_uniform_fallback` 同口径:此时序列号不携带信息,按位置拼接,
    // 不得报「重复/缺块/乱序」,否则 UI 会与实际重组结果矛盾。
    // 仅在「收到的块数 == 声明块数」时成立(少于声明仍是截断,必须报缺块)。
    if (same && n == pb_num) {
        si.dup = 0;
        si.missing = 0;
        si.oob = 0;
        si.reordered = false;
        si.first_missing = -1;
        return si;
    }
    for (int s = 0; s < pb_num; ++s) {
        if (slot[s] == 0) ++si.missing, si.first_missing = (si.first_missing < 0 ? s : si.first_missing);
        else if (slot[s] > 1) si.dup += slot[s] - 1;
    }
    return si;
}

PbSeqInfo analyze_pb_seq(const MpduInfo& mpdu, quint8 mask) {
    return analyze_pb_seq_heads(mpdu.pb_heads, int(mpdu.pb_num), mask);
}

/// 多站(OFDMA/TDA)帧的 CRC/缺块/序号文案:逐站按序列号落位判定。
/// 优先级:CRC 失败 > 缺块 > 序号异常 > 乱序已重排 > CRC OK。
QString multi_station_crc_text(const MpduInfo& m, quint8 mask) {
    int fail_cnt = 0;
    for (bool ok : m.pb_crc_oks) if (!ok) ++fail_cnt;
    int first_missing = -1, oob = 0, dup = 0;
    bool reordered = false;
    for (const auto& st : m.sof_stations) {
        const PbSeqInfo si = analyze_pb_seq_heads(st.pb_heads, int(st.pb_num), mask);
        // 真截断:本站已收块数 < 声明块数(未收到的块无法判 seq)
        const int arrived_missing = int(st.pb_num) - st.pb_crc_oks.size();
        const int missing = qMax(si.missing, arrived_missing);
        if (missing > 0 && first_missing < 0)
            first_missing = (si.first_missing >= 0) ? si.first_missing : st.pb_crc_oks.size();
        oob += si.oob;
        dup += si.dup;
        if (si.reordered) reordered = true;
    }
    if (fail_cnt > 0)
        return trl::L("CRC FAIL(%1/%2)").arg(fail_cnt).arg(m.pb_crc_oks.size());
    // 序号越界/重复(冲突)优先于缺块:重复 seq 必然同时造成槽位空洞,
    // 但根因是序号异常,文案按「序号异常」报(与单站 pb_crc_incomplete_text 同序)。
    if (oob > 0 || dup > 0) return trl::L("PB 序号异常");
    if (first_missing >= 0)
        return trl::L("CRC 不完整（缺块 %1）").arg(first_missing);
    if (m.pb_crc_oks.isEmpty()) return QString();
    return reordered ? trl::L("CRC OK（乱序已重排）") : trl::L("CRC OK");
}

/// 乱序已重排提示(有序到达/全同兜底/序号异常时不显示)
QString pb_reordered_text(const MpduInfo& mpdu, quint8 mask) {
    const PbSeqInfo si = analyze_pb_seq(mpdu, mask);
    if (si.all_same || si.oob > 0 || si.dup > 0 || si.missing > 0) return QString();
    return si.reordered ? trl::L("CRC OK（乱序已重排）") : QString();
}

// pb_crc_ok=false 不仅表示抓包截断:也可能是缺块/序列号越界/重复冲突导致不重组。
// 只有已收块少于声明块时,才能确定是截断(块根本没到 / 被帧长截断)。
QString pb_crc_incomplete_text(const MpduInfo& mpdu, quint8 mask) {
    if (mpdu.pb_crc_oks.size() < mpdu.pb_num)
        return trl::L("CRC 不完整（截断）");
    const PbSeqInfo si = analyze_pb_seq(mpdu, mask);
    if (si.oob > 0 || si.dup > 0) return trl::L("PB 序号异常");
    if (si.missing > 0 && si.first_missing >= 0)
        return trl::L("CRC 不完整（缺块 %1）").arg(si.first_missing);
    return trl::L("CRC 不完整（重组失败）");
}

/// 帧级 PB CRC 状态文案(CRC OK / CRC OK（乱序已重排） / 失败原因)
QString pb_crc_state_text(const MpduInfo& mpdu, quint8 mask) {
    if (!mpdu.pb_crc_ok) return pb_crc_incomplete_text(mpdu, mask);
    const QString r = pb_reordered_text(mpdu, mask);
    return r.isEmpty() ? trl::L("CRC OK") : r;
}

/// @brief 48-bit MAC 帧内原始字节序 → "aa:bb:cc:dd:ee:ff"(唯一实现见 common/mac_format.h)
QString format_mac(quint64 v) { return format_mac_u64(v); }

/// @brief 管理消息 MMe 类型颜色:暖色系色相(20-179,避开 0-19 红色区),
///        与 APP 层冷色系(180-359)视觉区分;红色仅保留给异常报文
QColor mme_color(quint16 mme_type) {
    const int hue = 20 + int((quint64(mme_type) * 37) % 160);
    return QColor::fromHsv(hue, 190, 220);
}

/// @brief 应用层 BID 颜色:冷色系色相(180-339,避开 340-359 粉红区),
///        与管理消息暖色系区分;红色仅保留给异常报文
QColor bid_color(quint8 bid) {
    const int hue = 180 + int((quint64(bid) * 37) % 160);
    return QColor::fromHsv(hue, 190, 220);
}
}  // namespace

PacketListModel::PacketListModel(QObject* parent)
    : QAbstractTableModel(parent), m_block_count(0), m_total(0) {}

int PacketListModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid()) return 0;
    return m_visible.size();
}

int PacketListModel::columnCount(const QModelIndex& parent) const {
    if (parent.isValid()) return 0;
    return COL_COUNT;
}

/// MAC*/STA-N* 推断标注的说明文案(列头 ToolTip;中英成对,随语言切换)
QString mac_infer_tip() {
    return trl::L("MAC* = 由当前 TEI↔MAC 映射推断，TEI 易主后会变化；STA-N* 中的 * 同理");
}

QVariant PacketListModel::headerData(int section, Qt::Orientation orient, int role) const {
    if (role == Qt::ToolTipRole && orient == Qt::Horizontal) {
        // 「由当前映射推断」的标注说明:MAC* / STA-N* 均由此图例解释(需求 §4)
        switch (section) {
            case COL_ORIG_SRC: case COL_SOURCE: case COL_DEST:
            case COL_ORIG_DST: case COL_INFO:
                return mac_infer_tip();
            default: break;
        }
        return {};
    }
    if (role != Qt::DisplayRole) return {};
    if (orient == Qt::Horizontal) {
        switch (section) {
            case COL_INDEX:    return QStringLiteral("#");
            case COL_TIME:     return QStringLiteral("Time");
            case COL_DELTA:    return QStringLiteral("Delta");
            case COL_ORIG_SRC: return QStringLiteral("Orig Src");
            case COL_SOURCE:   return QStringLiteral("Source");
            case COL_DEST:     return QStringLiteral("Destination");
            case COL_ORIG_DST: return QStringLiteral("Orig Dst");
            case COL_DIR:      return QStringLiteral("Dir");
            case COL_PROTOCOL: return QStringLiteral("Protocol");
            case COL_FRAME_TYPE: return QStringLiteral("Frame Type");
            case COL_MSDU_TYPE: return QStringLiteral("MSDU Type");
            case COL_MSDU_SEQ: return QStringLiteral("MSDU Seq");
            case COL_LENGTH:   return QStringLiteral("Length");
            case COL_INFO:     return QStringLiteral("Info");
        }
    }
    return section + 1;
}

QVariant PacketListModel::data(const QModelIndex& idx, int role) const {
    if (!idx.isValid() || idx.row() >= m_visible.size()) return {};
    const PacketEntry& e = locate(m_visible[idx.row()]);

    if (role == Qt::DisplayRole) {
        switch (idx.column()) {
            case COL_INDEX:  return e.index;
            case COL_TIME: {
                if (e.meta.frame_time.isValid())
                    return e.meta.frame_time.toString("HH:mm:ss.zzz");
                return QStringLiteral("%1 s").arg(e.epoch_ms / 1000.0, 0, 'f', 6);
            }
            case COL_DELTA:
                return QStringLiteral("%1 s").arg(e.delta_us / 1e6, 0, 'f', 6);
            case COL_ORIG_SRC: {
                // 多源(聚合/多站点帧):前提条件是帧级无原始 TEI,此时才解析
                // 各段/各站头源;帧级已有源时走后方单源逻辑,不展示多源。
                // 合并帧 present=false 亦显示,故不以 present 为门。
                if (e.accepted && !e.msdu.simple_head && e.msdu.msdu_src_tei <= 0
                    && !e.msdu.orig_srcs.isEmpty()) {
                    QVector<TeiMacPair> srcs;
                    QVector<bool> src_backfilled;   // 该条目 MAC 来自"当前映射"(非抓包时刻快照)
                    for (const auto& p : e.msdu.orig_srcs) {
                        if (p.tei == 0) continue;
                        TeiMacPair f = p;
                        // 解析时能取到 MAC 的段已在 TeiMacPair.mac 快照(不随 TEI 易主漂移);
                        // 仅 TEI-only 段(mac==0)在绘制时按"当前映射"回填,UI 用
                        // [MAC*:..] 标注与快照 [..] 区分。
                        bool backfilled = false;
                        if (!f.mac && f.tei != kTeiBroadcast) {
                            f.mac = lookup_mac(e.mpdu.net_id, f.tei);
                            backfilled = (f.mac != 0);
                        }
                        bool dup = false;
                        for (int k = 0; k < srcs.size(); ++k)
                            if (srcs[k].tei == f.tei && srcs[k].mac == f.mac) { dup = true; break; }
                        if (!dup) { srcs.append(f); src_backfilled.append(backfilled); }
                    }
                    if (!srcs.isEmpty()) {
                        QStringList parts;
                        for (int k = 0; k < srcs.size(); ++k) {
                            const TeiMacPair& p = srcs[k];
                            QString s = (p.tei == kTeiCco) ? QStringLiteral("CCO")
                                                           : QStringLiteral("STA-%1").arg(p.tei);
                            // 解析时 mac==0 且绘制时仍未学到,才只出名,不带 MAC 括号
                            if (p.mac) s += src_backfilled[k]
                                ? QStringLiteral(" [MAC*:%1]").arg(format_mac(p.mac))
                                : QStringLiteral(" [%1]").arg(format_mac(p.mac));
                            parts.append(s);
                        }
                        return parts.join(QLatin1Char(','));
                    }
                }
                if (e.accepted && e.msdu.present && !e.msdu.simple_head
                    && e.msdu.msdu_src_tei > 0) {
                    const int tei = e.msdu.msdu_src_tei;
                    QString s = (tei == kTeiCco) ? QStringLiteral("CCO")
                                           : QStringLiteral("STA-%1").arg(tei);
                    // MACAddrFlag=1 → 扩展源 MAC(抓包时刻快照);否则按当前映射回填(标 *)
                    quint64 mac = e.msdu.msdu_src_mac;
                    const bool src_bf = (mac == 0);
                    if (!mac) mac = lookup_mac(e.mpdu.net_id, quint16(tei));
                    if (mac) s += src_bf
                        ? QStringLiteral(" [MAC*:%1]").arg(format_mac(mac))
                        : QStringLiteral(" [%1]").arg(format_mac(mac));
                    return s;
                }
                return QString();
            }
            case COL_ORIG_DST: {
                // 多目的(聚合/多站点帧):与 Orig Src 镜像,前提条件是帧级无原始
                // 目的 TEI,此时才展示各段/各站目的;帧级已有目的时走后方单目的
                // 逻辑,不展示多目的。合并帧 present=false 亦显示,故不以 present 为门。
                if (e.accepted && !e.msdu.simple_head && e.msdu.msdu_dst_tei <= 0
                    && !e.msdu.orig_dsts.isEmpty()) {
                    QVector<TeiMacPair> dsts;
                    QVector<bool> dst_backfilled;
                    for (const auto& p : e.msdu.orig_dsts) {
                        if (p.tei == 0) continue;
                        TeiMacPair f = p;
                        // 绘制时回填(同 Orig Src);广播不查表,与单目的分支一致。
                        bool backfilled = false;
                        if (!f.mac && f.tei != kTeiBroadcast) {
                            f.mac = lookup_mac(e.mpdu.net_id, f.tei);
                            backfilled = (f.mac != 0);
                        }
                        bool dup = false;
                        for (int k = 0; k < dsts.size(); ++k)
                            if (dsts[k].tei == f.tei && dsts[k].mac == f.mac) { dup = true; break; }
                        if (!dup) { dsts.append(f); dst_backfilled.append(backfilled); }
                    }
                    if (!dsts.isEmpty()) {
                        QStringList parts;
                        for (int k = 0; k < dsts.size(); ++k) {
                            const TeiMacPair& p = dsts[k];
                            QString s = (p.tei == kTeiBroadcast) ? QStringLiteral("BCAST")
                                       : (p.tei == kTeiCco) ? QStringLiteral("CCO")
                                       : QStringLiteral("STA-%1").arg(p.tei);
                            // 解析时 mac==0 且绘制时仍未学到,才只出名,不带 MAC 括号
                            if (p.mac) s += dst_backfilled[k]
                                ? QStringLiteral(" [MAC*:%1]").arg(format_mac(p.mac))
                                : QStringLiteral(" [%1]").arg(format_mac(p.mac));
                            parts.append(s);
                        }
                        return parts.join(QLatin1Char(','));
                    }
                }
                if (e.accepted && e.msdu.present && !e.msdu.simple_head
                    && e.msdu.msdu_dst_tei > 0) {
                    const int tei = e.msdu.msdu_dst_tei;
                    QString s = (tei == kTeiBroadcast) ? QStringLiteral("BCAST")
                               : (tei == kTeiCco) ? QStringLiteral("CCO")
                               : QStringLiteral("STA-%1").arg(tei);
                    if (tei == kTeiBroadcast) {
                        // 广播:MACAddrFlag=1 显示帧字段里的 MAC(不一定是 ff:ff:ff:ff:ff:ff);
                        // MACAddrFlag=0 不显示(不查映射表)
                        if (e.msdu.msdu_dst_mac)
                            s += QStringLiteral(" [%1]").arg(format_mac(e.msdu.msdu_dst_mac));
                    } else {
                        // 非广播:MACAddrFlag=1 → 扩展目的 MAC(抓包时刻快照);
                        // 否则按当前映射回填(标 * 区分,避免 TEI 易主后误读历史)
                        quint64 mac = e.msdu.msdu_dst_mac;
                        const bool dst_bf = (mac == 0);
                        if (!mac) mac = lookup_mac(e.mpdu.net_id, quint16(tei));
                        if (mac) s += dst_bf
                            ? QStringLiteral(" [MAC*:%1]").arg(format_mac(mac))
                            : QStringLiteral(" [%1]").arg(format_mac(mac));
                    }
                    return s;
                }
                // 原始目的 TEI=0 且下一跳 TEI=0:目的 STA 未分配 TEI,从报文体 STA MAC 填,
                // TEI 从映射表用 MAC 反查(查不到 STA-X)
                if (e.accepted && e.msdu.present && !e.msdu.simple_head
                    && e.msdu.msdu_dst_tei == 0 && e.mpdu.dst_tei == 0
                    && e.msdu.sta_mac) {
                    const quint64 mac = e.msdu.sta_mac;
                    const quint16 mac_tei = lookup_tei_by_mac(e.mpdu.net_id, mac);
                    // N 由当前映射表反查(推断)→ STA-N*;查不到保持 STA-X
                    const QString s = mac_tei
                        ? QStringLiteral("STA-%1*").arg(mac_tei)
                        : QStringLiteral("STA-X");
                    return s + QStringLiteral(" [%1]").arg(format_mac(mac));
                }
                return QString();
            }
            case COL_DIR:
                return dir_display(e);
            case COL_SOURCE: {
                if (!e.accepted) return QStringLiteral("DROP");
                const quint16 tei = e.mpdu.src_tei;
                // COORD 帧:CCO 发出(src_tei 未解析),用 NID 查 CCO MAC
                if (e.mpdu.frame_type == 3 && tei == 0) {
                    QString s = QStringLiteral("CCO");
                    const quint64 mac = lookup_mac(e.mpdu.net_id, 1);
                    // MAC 由当前映射表推出 → [MAC*:] 与帧内实证区分
                    if (mac) s += QStringLiteral(" [MAC*:%1]").arg(format_mac(mac));
                    return s;
                }
                if (tei != 0) {
                    QString s = (tei == kTeiCco) ? QStringLiteral("CCO")
                                                : QStringLiteral("STA-%1").arg(tei);
                    const quint64 mac = lookup_mac(e.mpdu.net_id, tei);
                    if (mac) s += QStringLiteral(" [MAC*:%1]").arg(format_mac(mac));
                    return s;
                }
                // 源 TEI 未知(0,如关联请求),用报文体 STAMACAddr 显示 STA-X [MAC]
                if (e.msdu.sta_mac)
                    return QStringLiteral("STA-X [%1]").arg(format_mac(e.msdu.sta_mac));
                return e.meta.is_rf ? QStringLiteral("RF") : QStringLiteral("PLC");
            }
            case COL_DEST: {
                if (!e.accepted) return e.reason;
                if (e.mpdu.dst_tei == kTeiBroadcast) return QStringLiteral("BROADCAST");
                const quint16 tei = e.mpdu.dst_tei;
                if (tei != 0) {
                    QString s = (tei == kTeiCco) ? QStringLiteral("CCO")
                                                : QStringLiteral("STA-%1").arg(tei);
                    const quint64 mac = lookup_mac(e.mpdu.net_id, tei);
                    if (mac) s += QStringLiteral(" [MAC*:%1]").arg(format_mac(mac));
                    return s;
                }
                return QStringLiteral("*");
            }
            case COL_PROTOCOL: {
                if (!e.accepted) return QStringLiteral("ERR");
                return e.meta.is_rf ? QStringLiteral("RF") : QStringLiteral("HPLC");
            }
            case COL_FRAME_TYPE: {
                if (!e.accepted) return QStringLiteral("-");
                return e.mpdu.frame_type_name();
            }
            case COL_MSDU_TYPE: {
                if (e.accepted && e.msdu.present) {
                    QString s = e.msdu.summary;
                    // 展示源 MMe 主体(便于与路由变更表核对):
                    // 有主体 MAC → MAC≠本跳发送方 MAC(msdu_src_mac)判代理转发;
                    // 仅主体 TEI(无 MAC)→ TEI≠本跳发送方 TEI(src_tei)判代理转发,
                    //   主体 MAC 自 TEI→MAC 映射表补,查不到只显示 STA-N
                    const quint64 body_mac = e.msdu.sta_mac;
                    quint16 body_tei = 0;
                    // 主体 TEI 优先按主体 MAC 反查映射表(多节点事件里首个非零 TEI
                    // 未必是主体);查不到再按本帧 nodes 匹配主体 MAC,最后才回落首个非零
                    bool body_tei_from_lookup = false;   // TEI 来自当前映射表反查(推断,非帧内实证)
                    if (body_mac) {
                        body_tei = lookup_tei_by_mac(e.mpdu.net_id, body_mac);
                        body_tei_from_lookup = (body_tei != 0);
                        if (!body_tei) {
                            for (const auto& p : e.msdu.topo_event.nodes)
                                if (p.mac == body_mac && p.tei) { body_tei = p.tei; break; }
                            // 多站点合并帧:首事件 nodes 未命中时续查 extras(保持首事件优先序)
                            for (const auto& extra : e.msdu.topo_extra_events) {
                                if (body_tei) break;
                                for (const auto& p : extra.nodes)
                                    if (p.mac == body_mac && p.tei) { body_tei = p.tei; break; }
                            }
                        }
                    }
                    if (!body_tei) {
                        for (const auto& p : e.msdu.topo_event.nodes)
                            if (p.tei) { body_tei = p.tei; break; }
                        // 多站点合并帧:首事件 nodes 无非零 TEI 时续查 extras(保持首事件优先序)
                        for (const auto& extra : e.msdu.topo_extra_events) {
                            if (body_tei) break;
                            for (const auto& p : extra.nodes)
                                if (p.tei) { body_tei = p.tei; break; }
                        }
                    }
                    const bool mac_relay = (body_mac != 0) && (body_mac != e.msdu.msdu_src_mac);
                    const bool tei_relay = (body_mac == 0) && (body_tei != 0)
                                           && (body_tei != e.mpdu.src_tei);
                    if (mac_relay || tei_relay) {
                        quint64 mac = body_mac;
                        bool mac_from_lookup = false;   // MAC 由映射表补(推断)
                        if (!mac && body_tei) {
                            mac = lookup_mac(e.mpdu.net_id, body_tei);   // 自映射表补 MAC
                            mac_from_lookup = (mac != 0);
                        }
                        // 推断值标注:* 只在"值本身来自映射表"时加,实证值不加
                        const QString body = body_tei
                            ? QStringLiteral("STA-%1%2").arg(body_tei)
                                  .arg(body_tei_from_lookup ? QStringLiteral("*") : QString())
                            : QStringLiteral("STA-X");
                        if (mac)
                            s += QStringLiteral(" %1 [MAC%2:%3]").arg(body)
                                     .arg(mac_from_lookup ? QStringLiteral("*") : QString())
                                     .arg(format_mac(mac));
                        else
                            s += QStringLiteral(" %1").arg(body);
                    }
                    return s;
                }
                return QString();
            }
            case COL_MSDU_SEQ: {
                if (e.accepted && e.msdu.present) {
                    // 单跳帧精简头(南网表113 4B/国网表3 4B)无 MSDU 序号字段(标准帧头才有
                    // MSDU_SEQ (5,0,16)/(10,0,16)),显示 "*" 避免误读为解析缺失
                    if (e.msdu.simple_head) return QStringLiteral("*");
                    return (int)e.msdu.msdu_seq;
                }
                return QString();
            }
            case COL_LENGTH: return e.raw_bytes.size();
            case COL_INFO: {
                if (!e.accepted) return e.reason;
                QString nid = QString::number(e.mpdu.net_id, 16).toUpper().rightJustified(6, QChar('0'));
                if (e.mpdu.frame_type == 0) {
                    // 信标帧 Info:载波(HPLC)显示 TMI + PBNum(单块恒 1,信标 FCH 无 PBNum 字段)
                    // + PBSize;无线(HRF)显示 MCS + PBSize(无线不显示 PBNum)。
                    // pb_size<=0(查表无效)时省略 PBSize 段,不占位瞎显。
                    // ts 保留:信标时间戳是网络基准时间,有业务意义。
                    QString info = QStringLiteral("NetID=0x%1 src=%2 ts=%3")
                                   .arg(nid).arg(e.mpdu.src_tei).arg(e.meta.timestamp);
                    if (e.meta.is_rf)
                        info += QStringLiteral(" MCS=%1").arg(e.mpdu.mcs);
                    else
                        info += QStringLiteral(" TMI=%1 PBNum=1").arg(e.mpdu.tmi);
                    if (e.mpdu.pb_size > 0)
                        info += QStringLiteral(" PBSize=%1B").arg(e.mpdu.pb_size);
                    return info;
                }
                if (e.mpdu.frame_type == 1) {
                    // 多站/训练帧判据**不再依赖 version**:国网 version 只有 0/1
                    // (GW_2022_Version::THIS_STANDARD=0;GW_2026_Version HDC_1_0=0/HDC_2_0=1),
                    // 旧判据 version==2 使国网多站成死代码,而 version==2 恰是南网 SPLC
                    // → 南网 SOF 帧反被误标 DL-OFDMA。现改结构化判据:
                    //   多站 = 已解析出站点列表(OFDMA/TDA 表10-13);
                    //   训练帧 = 单站点(无站点列表) + 表23 byte4 bit1。均限国网载波帧。
                    const quint8 proto = quint8(e.protocol & 0x7F);
                    const bool is_gw = (proto == kProtocolGw2022 || proto == kProtocolGw2026);
                    const bool is_multi = is_gw && !e.meta.is_rf
                                          && !e.mpdu.sof_stations.isEmpty();
                    if (is_multi) {
                        const quint8 ofdma_type = (quint8(e.raw_bytes.at(4)) >> 1) & 0x03;
                        QString kind;
                        switch (ofdma_type) {
                          // 缺块/截断不由 pb_num 判(多站恒 pb_num=0),统一由逐站
                          // 序列号判定出的 crc_str("缺块 k")表达
                          case 0: kind = trl::L("DL-OFDMA"); break;
                          case 1: {
                            // 类型 1 双义:DL-SACK 判别与 parser 一致 (单站 + 单 16B PB + 体首 MsgID==0);
                            // 仅看站 0 尺寸会把多站 UL(站 0 为 16B) 误标为 DL-SACK
                            const auto& sts = e.mpdu.sof_stations;
                            const bool dl_sack = (sts.size() == 1 && sts[0].pb_size == 16
                                                  && sts[0].msdu.size() >= 1 && (sts[0].msdu[0] & 0x0F) == 0);
                            if (dl_sack)
                                kind = trl::L("DL-OFDMA SACK");
                            else if (!sts.isEmpty())
                                kind = trl::L("UL-OFDMA 数据帧");
                            else
                                kind = trl::L("UL-OFDMA 数据帧（需触发）");
                            break;
                          }
                          case 2: kind = trl::L("UL-OFDMA trigger"); break;
                          default: kind = trl::L("UL-OFDMA SACK"); break;
                        }
                        // 逐站按序列号落位判定:CRC 失败 > 缺块(k) > 序号异常 > 乱序已重排 > OK
                        const QString crc_str = multi_station_crc_text(e.mpdu, pb_seq_mask(e));
                        return QStringLiteral("NetID=0x%1 src=%2 dst=%3 %4")
                               .arg(nid).arg(e.mpdu.src_tei).arg(e.mpdu.dst_tei)
                               .arg(kind)
                               + (crc_str.isEmpty() ? QString() : QStringLiteral(" ") + crc_str);
                    }
                    // 训练帧 (DL-OFDMA 单站点)
                    if (is_gw && !e.meta.is_rf && !is_multi
                        && e.raw_bytes.size() > 5 && (quint8(e.raw_bytes.at(4)) & 0x02)) {
                        const bool bitload = (quint8(e.raw_bytes.at(5)) & 0x01) != 0;
                        // CRC 状态:oks 为空不断言 CRC OK(避免与红行矛盾)。
                        // pb_crc_ok=false 还可能是 PB 序号乱序导致的重组失败，
                        // 只有已收块少于声明块时才标记为截断。
                        int fail_cnt = 0;
                        for (bool ok : e.mpdu.pb_crc_oks) if (!ok) ++fail_cnt;
                        QString crc_str = fail_cnt > 0
                            ? trl::L("CRC FAIL(%1/%2)").arg(fail_cnt).arg(e.mpdu.pb_crc_oks.size())
                            : (e.mpdu.pb_crc_oks.isEmpty() ? QString()
                               : pb_crc_state_text(e.mpdu, pb_seq_mask(e)));
                        return QStringLiteral("NetID=0x%1 src=%2 dst=%3 %4 PBNum=%5")
                               .arg(nid).arg(e.mpdu.src_tei).arg(e.mpdu.dst_tei)
                               .arg(bitload ? trl::L("训练帧(Bitloading)") : trl::L("训练帧(MIMO)"))
                               .arg(e.mpdu.pb_num)
                               + (crc_str.isEmpty() ? QString() : QStringLiteral(" ") + crc_str);
                    }
                    // 默认情况 (含其他 SOF 帧)
                    {
                        // CRC 状态:同训练分支，区分载荷截断和 PB 重组失败。
                        int fail_cnt = 0;
                        for (bool ok : e.mpdu.pb_crc_oks) if (!ok) ++fail_cnt;
                        QString crc_str = fail_cnt > 0
                            ? trl::L("CRC FAIL(%1/%2)").arg(fail_cnt).arg(e.mpdu.pb_crc_oks.size())
                            : (e.mpdu.pb_crc_oks.isEmpty() ? QString()
                               : pb_crc_state_text(e.mpdu, pb_seq_mask(e)));
                        QString msdu = e.msdu_body.isEmpty() ? QString() :
                                       QStringLiteral(" MSDU[%1B]").arg(e.msdu_body.size());
                        return QStringLiteral("NetID=0x%1 src=%2 dst=%3 %4=%5 PBNum=%6")
                               .arg(nid).arg(e.mpdu.src_tei).arg(e.mpdu.dst_tei)
                               .arg(e.meta.is_rf ? QStringLiteral("MCS") : QStringLiteral("TMI"))
                               .arg(e.meta.is_rf ? e.mpdu.mcs : e.mpdu.tmi)
                               .arg(e.mpdu.pb_num)
                               + (crc_str.isEmpty() ? QString() : QStringLiteral(" ") + crc_str)
                               + msdu;
                    }
                }
                return QStringLiteral("NetID=0x%1 src=%2 dst=%3")
                       .arg(nid).arg(e.mpdu.src_tei).arg(e.mpdu.dst_tei);
            }
        }
    } else if (role == Qt::ForegroundRole) {
        // 整行着色优先级:CRC 失败红(FCH/PB 物理层校验,最高) > 管理消息(MMe 暖色系)
        // > APP 层(BID 冷色系) > 帧类型(DROP灰/ACK校验失败红不变)
        // 仅 FCH CRC24 FAIL、任一 PB CRC24 FAIL 或已尝试组装而帧级未通过标红
        // (与 ACK 失败同色);MSDU CRC32 FAIL 不改颜色(应用层校验,常因抓包截断/
        // 设备异常,不掩盖业务着色)
        if (e.mpdu.fch_crc_checked && !e.mpdu.fch_crc_ok)
            return QColor(224, 64, 64);   // 仅"校验过且失败"才标红;未校验不标红
        if (std::any_of(e.mpdu.pb_crc_oks.cbegin(), e.mpdu.pb_crc_oks.cend(),
                        [](bool ok) { return !ok; }))
            return QColor(224, 64, 64);   // 任一物理块 CRC24 校验失败
        if (e.mpdu.pb_size > 8 && e.mpdu.pb_num > 0 && !e.mpdu.pb_crc_ok)
            return QColor(224, 64, 64);   // 已尝试组装且帧级未通过:含截断(oks 为空时上条不触发);合法 0 块帧 pb_size=0 不进此条
        if (e.msdu.present && e.msdu.mme_type != kMMeTypeNone)
            return mme_color(e.msdu.mme_type);
        if (e.msdu.present && e.msdu.business_id != 0xFF) {
            if (e.msdu.app_packet_type == kAppPacketAckNack) {
                if (e.msdu.business_id == kBidConfirm) return QColor(46, 214, 106);   // 确认(ACK)亮绿
                if (e.msdu.business_id == kBidDeny)    return QColor(224, 64, 64);    // 否认(NACK)红
            }
            return bid_color(e.msdu.business_id);
        }
        return data_color(e);
    } else if (role == Qt::TextAlignmentRole) {
        if (idx.column() == COL_INDEX || idx.column() == COL_LENGTH)
            return int(Qt::AlignRight | Qt::AlignVCenter);
        if (idx.column() == COL_TIME || idx.column() == COL_DELTA)
            return int(Qt::AlignRight | Qt::AlignVCenter);
    }
    return {};
}

QVariant PacketListModel::data_color(const PacketEntry& e) const {
    if (!e.accepted) return QColor(128, 128, 128);
    switch (e.mpdu.frame_type) {
        case 0: return QColor(86, 156, 214);
        case 1: return QColor(106, 153, 78);
        case 2:  // ACK 选择确认帧:校验失败(≥1 PB CRC 未过)红色显著指示
            // GW_2022(表25/36)/南网:byte4 bit0-3 = RxRes(0成功 1失败);
            // GW_2026(表14)该 4bit 拆为 BRU SNR/SAT ID/RxPBNum,无 RxRes,
            // 用 PB 位图 RxStatus 全 0 判失败(全失败=无任何块 CRC 通过)
            if ((e.protocol & 0x7F) == kProtocolGw2026)
                return (e.mpdu.ack_rx_status == 0 && e.mpdu.ack_rx_pb_num > 0)
                           ? QColor(224, 64, 64) : QColor(196, 181, 79);
            if (e.mpdu.ack_rx_res == 1) return QColor(224, 64, 64);
            return QColor(196, 181, 79);
        case 3: return QColor(140, 110, 190);   // COORD 协调帧:紫色(非异常,不用红)
        default: return QColor(170, 170, 170);
    }
}

namespace {
/// @brief MAC 模式 token 解析:2~6 组两位十六进制,冒号分隔,如 03:02 或完整 6 组
/// @details 调用方已将 token 小写+trim;字节序与 format_mac/m_mac_tei 的 u64 约定一致:
///          首组=模式首字节,次组=次字节,依此类推;掩码覆盖组数对应的低位,
///          匹配时模式可在 MAC 任意字节偏移处出现(前缀/中间/后缀)。
///          非 MAC 格式(组数不足 2 或超 6、组长非 2、含非十六进制字符)返回 false,
///          调用方按旧语义走 search_text 子串;单组 "03" 等不成 MAC。
bool parse_mac_pattern(const QString& t, quint64& pattern_val, quint64& mask,
                       int& group_count) {
    const QStringList parts = t.split(':');
    if (parts.size() < 2 || parts.size() > 6) return false;
    quint64 v = 0;
    for (int i = 0; i < parts.size(); ++i) {
        const QString& p = parts[i];
        if (p.size() != 2) return false;
        for (const QChar ch : p) {
            if (!((ch >= QLatin1Char('0') && ch <= QLatin1Char('9'))
                  || (ch >= QLatin1Char('a') && ch <= QLatin1Char('f'))))
                return false;
        }
        bool ok = false;
        const uint byte = p.toUInt(&ok, 16);
        if (!ok) return false;
        v |= quint64(byte) << (8 * i);
    }
    pattern_val = v;
    mask = (quint64(1) << (8 * parts.size())) - 1;
    group_count = parts.size();
    return true;
}

/// @brief MAC 模式反查:映射表(m_mac_tei,全 NID)中模式在任意字节偏移处出现的全部 TEI,去重后升序
/// @details 偏移 0=前缀、中间偏移=中间匹配、末偏移=后缀;完整 6 组时仅偏移 0,即精确匹配。
///          匹配谓词本身不带 NID,与 sta-<数字> 的跨 NID 语义一致;返回空即无命中。
QVector<int> lookup_teis_by_mac_pattern(
        const QHash<quint32, QHash<quint64, quint16>>& mac_tei,
        quint64 pattern_val, quint64 mask, int group_count) {
    QVector<int> out;
    for (auto it = mac_tei.constBegin(); it != mac_tei.constEnd(); ++it) {
        for (auto mit = it->constBegin(); mit != it->constEnd(); ++mit) {
            const quint64 mac = mit.key();
            bool hit = false;
            for (int off = 0; off + group_count <= 6; ++off) {
                if (((mac >> (8 * off)) & mask) == pattern_val) { hit = true; break; }
            }
            if (hit) out.append(int(mit.value()));
        }
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

/// @brief 过滤表达式预处理:split/trim/小写/关键词判定只做一次,逐条匹配零分配
/// @details 帧型关键词(beacon/sof/ack/coord/search/switch)按帧型字节比对;
///          sta-<纯数字> 解析为 TEI 等值谓词(比对 hop src/dst TEI 及
///          search_text 里的 sta- 词——后者除 hop TEI 外还含 Orig Src
///          (帧级源 + 聚合/多站点源)),整词比对,避免
///          sta-130 误命中 sta-1300;其余条件词仍按 search_text 子串比对,
///          空条件词永假。
///          MAC 格式 token 在准备时查映射表展开为命中 TEI 的或:模式可在
///          MAC 任意字节偏移处出现(前缀/中间/后缀),组内按 DNF 分配律扇出,
///          每组把 MAC token 换成一个 sta-<TEI> 等值谓词;
///          无命中则该组作废,整个表达式无组即永假(条件为空)。
PacketPreparedFilter prepare_filter(
        const QString& filter,
        const QHash<quint32, QHash<quint64, quint16>>& mac_tei) {
    PacketPreparedFilter pf;
    pf.empty = filter.isEmpty();
    if (pf.empty) return pf;
    auto type_byte_of = [](const QString& t) -> int {
        if (t == QLatin1String("beacon")) return 0;
        if (t == QLatin1String("sof"))    return 1;
        if (t == QLatin1String("ack"))    return 2;
        if (t == QLatin1String("coord"))  return 3;
        if (t == QLatin1String("search")) return 5;
        if (t == QLatin1String("switch")) return 6;
        return -1;
    };
    const QStringList or_groups = filter.split('|', Qt::SkipEmptyParts);
    for (const QString& g : or_groups) {
        // 组内展开用中间组:MAC token 命中多 TEI 时把本组扇出为多组,
        // 每组把 MAC token 换成一个 sta-<TEI> 等值谓词;无命中则整组作废。
        QVector<QVector<PacketFilterCond>> partials;
        partials.append(QVector<PacketFilterCond>());
        bool dead = false;
        for (const QString& c : g.split('&')) {
            const QString t = c.trimmed().toLower();
            PacketFilterCond cond;
            if (t.isEmpty()) {
                cond.type_byte = -2;          // 空条件永假(与旧语义一致)
            } else if (const int tb = type_byte_of(t); tb >= 0) {
                cond.type_byte = tb;
            } else if (t.startsWith(QLatin1String("sta-")) && t.size() > 4
                       && std::all_of(t.begin() + 4, t.end(), [](QChar ch) {
                              return ch >= QLatin1Char('0')
                                  && ch <= QLatin1Char('9');
                          })) {
                // sta-<纯数字> → TEI 等值谓词;TEI 是 quint16,超出
                // UINT16_MAX(或数字溢出 qlonglong)即超出取值域,永假
                bool ok = false;
                const qlonglong v = t.mid(4).toLongLong(&ok);
                if (ok && v <= UINT16_MAX) cond.tei = int(v);
                else                       cond.type_byte = -2;
            } else {
                // MAC 模式 → 映射表反查 TEI(前缀/中间/后缀任一偏移命中),
                // 隐式展开为多 TEI 的或(DNF 扇出);不成 MAC 则走子串
                quint64 pattern_val = 0, mask = 0;
                int group_count = 0;
                if (parse_mac_pattern(t, pattern_val, mask, group_count)) {
                    const QVector<int> teis = lookup_teis_by_mac_pattern(
                        mac_tei, pattern_val, mask, group_count);
                    if (teis.isEmpty()) { dead = true; break; }  // 无命中:本组为空
                    QVector<QVector<PacketFilterCond>> next;
                    for (const auto& p : partials) {
                        for (const int tei : teis) {
                            QVector<PacketFilterCond> copy = p;
                            PacketFilterCond sc;
                            sc.tei = tei;
                            copy.append(sc);
                            next.append(copy);
                        }
                    }
                    partials = next;
                    continue;
                }
                cond.type_byte = -1;
                cond.term = t;
            }
            for (auto& p : partials) p.append(cond);
        }
        if (!dead) {
            for (const auto& p : partials) pf.groups.append(p);
        }
    }
    return pf;
}

/// @brief 预处理后的 DNF 匹配:帧型字节 + src/dst TEI + Orig Src sta- 词 + search_text 即可判定
bool prepared_match(const PacketPreparedFilter& pf, quint8 frame_type,
                    quint16 src_tei, quint16 dst_tei,
                    int msdu_src_tei, int msdu_dst_tei,
                    const QVector<quint16>& orig_src_teis,
                    const QVector<quint16>& orig_dst_teis,
                    const QString& haystack) {
    if (pf.empty) return true;
    // sta- 条件纯 TEI 比对,不扫 search_text:命中集 = hop 源/目的
    // TEI ∪ (msdu 帧级 TEI>0 时取其值,否则取 orig 两列 TEI),与
    // make_search_text 的 sta- 词集合完全一致(含帧级有源时 orig 词
    // 缺席的前提条件,故 130/1300 边界与旧整词语义一致)。每条件只
    // 比对该行自身的 TEI 值(段数有界),与 search_text 长度无关;
    // 子串条件仍走 haystack.contains(固有 O(len))。orig 两列来自
    // 盘块索引 v20(盘块行)或条目字段(热区行),均已去重保序。
    auto has_tei = [&](int tei) {
        if (src_tei == tei || dst_tei == tei) return true;
        if (msdu_src_tei > 0) { if (msdu_src_tei == tei) return true; }
        else if (orig_src_teis.contains(quint16(tei))) return true;
        if (msdu_dst_tei > 0) { if (msdu_dst_tei == tei) return true; }
        else if (orig_dst_teis.contains(quint16(tei))) return true;
        return false;
    };
    for (const auto& conds : pf.groups) {
        bool all = true;
        for (const PacketFilterCond& c : conds) {
            const bool hit = (c.tei >= 0) ? has_tei(c.tei)
                           : (c.type_byte >= 0) ? (frame_type == c.type_byte)
                           : (c.type_byte == -1) ? haystack.contains(c.term)
                                                 : false;
            if (!hit) { all = false; break; }
        }
        if (all) return true;
    }
    return false;
}

// 条目 orig 两列抽 TEI(去重保序,tei==0 不入集,与索引写入口径一致)
static void entry_orig_teis(const PacketEntry& e,
                            QVector<quint16>& out_src,
                            QVector<quint16>& out_dst) {
    out_src.clear();
    out_dst.clear();
    for (const auto& p : e.msdu.orig_srcs)
        if (p.tei != 0 && !out_src.contains(p.tei)) out_src.append(p.tei);
    for (const auto& p : e.msdu.orig_dsts)
        if (p.tei != 0 && !out_dst.contains(p.tei)) out_dst.append(p.tei);
}

/// @brief 工作线程:遍历快照盘块(只读 v3 索引,不解码条目)+ 热区,
///        返回命中过滤器的全局行号
QVector<int> run_filter(const PacketListModel::ExportSnapshot& snap,
                        const QString& filter,
                        const QHash<quint32, QHash<quint64, quint16>>& mac_tei) {
    const PacketPreparedFilter pf = prepare_filter(filter, mac_tei);
    QVector<int> result;
    int g = 0;
    for (const QString& bp : snap.block_paths) {
        pser::BlockReader reader;
        if (!reader.open(bp)) {
            g += PacketListModel::kBlockSize;
            continue;
        }
        const int n = reader.count();
        for (int i = 0; i < n; ++i) {
            if (prepared_match(pf, reader.frame_type(i), reader.src_tei(i),
                                reader.dst_tei(i), reader.msdu_src_tei(i),
                                reader.msdu_dst_tei(i), reader.orig_src_teis(i),
                                reader.orig_dst_teis(i), reader.search_text(i)))
                result.append(g + i);
        }
        g += n;
    }
    for (const PacketEntry& e : snap.hot) {
        QVector<quint16> o_src, o_dst;
        entry_orig_teis(e, o_src, o_dst);
        if (prepared_match(pf, e.mpdu.frame_type, e.mpdu.src_tei,
                            e.mpdu.dst_tei, e.msdu.msdu_src_tei,
                            e.msdu.msdu_dst_tei, o_src, o_dst, e.search_text))
            result.append(g);
        ++g;
    }
    return result;
}
}  // namespace

bool PacketListModel::passes_filter(const PacketEntry& e) const {
    QVector<quint16> o_src, o_dst;
    entry_orig_teis(e, o_src, o_dst);
    return prepared_match(m_prepared, e.mpdu.frame_type, e.mpdu.src_tei,
                          e.mpdu.dst_tei, e.msdu.msdu_src_tei,
                          e.msdu.msdu_dst_tei, o_src, o_dst, e.search_text);
}

QString PacketListModel::block_path(int idx) const {
    return m_paging_dir.filePath(QStringLiteral("blk_%1.bin").arg(idx));
}

void PacketListModel::touch_lru(int idx) const {
    m_lru.removeAll(idx);
    m_lru.append(idx);
}

bool PacketListModel::load_block(int idx) const {
    if (m_block_cache.contains(idx)) { touch_lru(idx); return true; }
    pser::BlockReader reader;
    // 打开只解析头/池/索引,条目按需解码;条数必须 == kBlockSize,否则视为
    // 截断/损坏,拒收(成功落盘的块必为整块;残缺块不进缓存,避免越界)
    if (!reader.open(block_path(idx)) || reader.count() != kBlockSize)
        return false;
    // LRU 淘汰(先插入再淘汰,保证新块存活)
    m_block_cache.insert(idx, std::move(reader));
    touch_lru(idx);
    while (m_lru.size() > kMaxCacheBlocks) {
        int old = m_lru.takeFirst();
        if (old != idx) m_block_cache.remove(old);
    }
    return true;
}

const PacketEntry& PacketListModel::locate(int g) const {
    // 兜底空条目:任何越界/缺块都不返回野引用(只显示空白行,不崩溃)
    static const PacketEntry kNullEntry;
    if (g < 0) return kNullEntry;
    const int hot_start = m_block_count * kBlockSize;
    if (g >= hot_start) {
        const int hi = g - hot_start;
        if (hi < m_hot.size())
            return m_hot[hi];
        return kNullEntry;
    }
    const int bi = g / kBlockSize;
    const int off = g % kBlockSize;
    if (!load_block(bi)) return kNullEntry;
    auto it = m_block_cache.constFind(bi);
    if (it == m_block_cache.constEnd() || off < 0 || off >= it->count())
        return kNullEntry;
    bool ok = false;
    const PacketEntry& e = it->entry_ref(off, ok);   // 只解码这一条
    return ok ? e : kNullEntry;
}

void PacketListModel::flush_hot_block() {
    if (m_hot.size() < kBlockSize) return;
    const int idx = m_block_count;
    // move 前 kBlockSize 条到待落盘块,热区立即腾出(UI 线程只做 move,不阻塞)
    QVector<PacketEntry> blk;
    blk.reserve(kBlockSize);
    for (int i = 0; i < kBlockSize; ++i)
        blk.append(std::move(m_hot[i]));
    m_hot.remove(0, kBlockSize);
    m_block_count++;   // 块号立即可用;文件在后台落盘(完成前 load_block 返回空块)
    // 后台线程:序列化 + qCompress + 写盘。
    // 安全:只捕获 path(值) + blk(move),不捕获 this —— 模型析构/clear 后,
    // 后台只碰局部资源;临时目录被删则 open 失败安全返回,不悬空不崩溃。
    const QString path = block_path(idx);
    QThreadPool::globalInstance()->start([path, blk = std::move(blk)]() {
        const QByteArray data = pser::encode_block(blk);
        QFile f(path);
        if (!f.open(QIODevice::WriteOnly)) return;
        const bool ok = (f.write(data) == data.size());
        f.close();
        // 只有完整落盘才保留;残缺文件删除,load_block 读到空块返回 false(不崩溃)
        if (!ok || f.error() != QFile::NoError)
            f.remove();
    });
}

void PacketListModel::append_packets(QVector<PacketEntry> entries) {
    if (entries.isEmpty()) return;
    if (m_filtering) {                        // 过滤中:暂存,过滤完成后再补 append
        m_deferred += entries;
        return;
    }
    QVector<int> new_visible;
    new_visible.reserve(entries.size());
    const int first_new = m_visible.size();
    bool mac_mapping_changed = false;
    for (PacketEntry& e : entries) {
        if (e.search_text.isEmpty())          // 兜底:非 make_entry 路径(测试等)补生成
            e.search_text = make_search_text(e);
        const int g = int(m_total);
        ++m_total;
        m_hot.append(std::move(e));           // move 进热缓存,避免深拷贝
        mac_mapping_changed |= update_tei_mac(m_hot.last());
        if (passes_filter(m_hot.last())) new_visible.append(g);
        if (m_hot.size() >= kBlockSize) flush_hot_block();
    }
    if (mac_mapping_changed) notify_mac_mapping_changed();
    if (new_visible.isEmpty()) return;
    beginInsertRows(QModelIndex(), first_new, first_new + new_visible.size() - 1);
    m_visible += new_visible;
    endInsertRows();
}

void PacketListModel::append_packet(const PacketEntry& entry) {
    append_packets(QVector<PacketEntry>{entry});
}

void PacketListModel::clear_all() {
    ++m_filter_gen;          // 作废在跑的异步过滤(结果作废,不再回填)
    m_filtering = false;
    m_deferred.clear();
    beginResetModel();
    m_hot.clear();
    m_block_cache.clear();
    m_lru.clear();
    m_visible.clear();
    m_block_count = 0;
    m_total = 0;
    m_tei_mac.clear();
    m_mac_tei.clear();
    endResetModel();
    // 删除旧盘块文件:异步写盘的后台任务可能还在写,删掉后其 open 失败即安全;
    // 已被后台打开的文件(Windows 文件锁)删不掉,写盘完成后残留,由下次 clear 清理。
    const QDir dir(m_paging_dir.path());
    for (const QString& f : dir.entryList(QStringList() << QStringLiteral("blk_*.bin"),
                                          QDir::Files))
        QFile::remove(dir.filePath(f));
}

bool PacketListModel::learn_tei_mac(quint32 nid, quint16 tei, quint64 mac) {
    if (!tei || !mac) return false;
    auto& fwd = m_tei_mac[nid];
    auto& rev = m_mac_tei[nid];
    // TEI 易主:旧 MAC 的反向条目若仍指向本 TEI 则清除,避免 stale 反查
    // (正表行为保持原样:MAC 易 TEI 时旧 TEI→MAC 条目不主动清除)
    const quint64 old_mac = fwd.value(tei, 0);
    if (old_mac == mac) {
        // 早退也必须保证反向索引指向本 TEI:MAC 曾绑定到别的 TEI 后其 rev 条目
        // 被 erase(见下),同一 TEI 再次出现该 MAC 时不补 → MAC→TEI 反查与
        // MAC 模式过滤全部失效(实测:反查显示 STA-X、过滤 0 行)。
        if (rev.value(mac, 0) != tei) { rev[mac] = tei; return true; }
        return false;
    }
    if (old_mac && old_mac != mac) {
        auto rit = rev.find(old_mac);
        if (rit != rev.end() && rit.value() == tei) rev.erase(rit);
    }
    fwd[tei] = mac;
    rev[mac] = tei;
    return true;
}

bool PacketListModel::update_tei_mac(const PacketEntry& e) {
    if (!e.accepted) return false;
    const quint32 nid = e.mpdu.net_id;
    bool changed = false;
    // BEACON 帧:CCO 的 MAC(TEI=1),供 COORD 等 CCO 发出(src_tei 未解析),用 NID 查表
    if (e.mpdu.frame_type == 0 && e.mpdu.beacon_cco_mac)
        changed |= learn_tei_mac(nid, 1, e.mpdu.beacon_cco_mac);
    // 信标管理信息条目(站点能力/精简站点)携带的 TEI→SourceMAC 学习对
    for (const TeiMacPair& p : e.beacon.tei_mac_pairs)
        if (p.tei != 0 && p.mac) changed |= learn_tei_mac(nid, p.tei, p.mac);
    // 管理帧(发现列表等)携带的 TEI→MAC 学习对
    for (const TeiMacPair& p : e.msdu.tei_mac_pairs)
        if (p.tei != 0 && p.mac) changed |= learn_tei_mac(nid, p.tei, p.mac);
    if (e.msdu.present && !e.msdu.simple_head) {
        if (e.msdu.msdu_src_tei > 0 && e.msdu.msdu_src_mac)
            changed |= learn_tei_mac(nid, quint16(e.msdu.msdu_src_tei), e.msdu.msdu_src_mac);
        if (e.msdu.msdu_dst_tei > 0 && e.msdu.msdu_dst_mac)
            changed |= learn_tei_mac(nid, quint16(e.msdu.msdu_dst_tei), e.msdu.msdu_dst_mac);
    }
    return changed;
}

void PacketListModel::notify_mac_mapping_changed() {
    // data() 按当前映射表动态补 MAC。这里只发送列范围通知，不 locate/扫描历史条目；
    // Qt view 只会立即重绘当前可见单元格，未显示的行仍在之后按需调用 data()。
    const int last = rowCount() - 1;
    if (last < 0) return;
    const Qt::ItemDataRole role = Qt::DisplayRole;
    emit dataChanged(index(0, COL_ORIG_SRC), index(last, COL_ORIG_SRC), {role});
    emit dataChanged(index(0, COL_SOURCE),   index(last, COL_SOURCE),   {role});
    emit dataChanged(index(0, COL_DEST),     index(last, COL_DEST),     {role});
    emit dataChanged(index(0, COL_ORIG_DST), index(last, COL_ORIG_DST), {role});
}

quint64 PacketListModel::lookup_mac(quint32 nid, quint16 tei) const {
    auto it = m_tei_mac.constFind(nid);
    if (it == m_tei_mac.constEnd()) return 0;
    auto mit = it->constFind(tei);
    return (mit == it->constEnd()) ? 0 : mit.value();
}

quint16 PacketListModel::lookup_tei_by_mac(quint32 nid, quint64 mac) const {
    if (!mac) return 0;
    auto it = m_mac_tei.constFind(nid);
    if (it == m_mac_tei.constEnd()) return 0;
    return it->value(mac, 0);
}

void PacketListModel::activate_row(int visible_row) {
    if (visible_row < 0 || visible_row >= m_visible.size()) return;
    emit packet_activated(locate(m_visible[visible_row]));
}

bool PacketListModel::entry_at(int visible_row, PacketEntry& out) const {
    if (visible_row < 0 || visible_row >= m_visible.size()) return false;
    out = locate(m_visible[visible_row]);   // 深拷贝,盘块被换出后仍安全
    return true;
}

void PacketListModel::set_display_filter(const QString& expr) {
    if (m_filter == expr) return;
    m_filter = expr;
    m_prepared = prepare_filter(expr, m_mac_tei);  // 预处理与表达式同步重建
    const int gen = ++m_filter_gen;          // 换代,丢弃在跑的旧过滤结果
    if (expr.isEmpty()) {                    // 清空过滤:恢复全可见(同步)
        m_filtering = false;                 // 复位过滤中状态(在跑旧过滤结果已由 gen 作废)
        beginResetModel();
        m_visible.clear();
        const qint64 total = m_total;
        m_visible.reserve(int(qMin<qint64>(total, 1000000)));
        for (int g = 0; g < int(total); ++g) m_visible.append(g);
        endResetModel();
        if (!m_deferred.isEmpty()) {         // 过滤期间暂存的 append 补进来(空过滤全可见)
            QVector<PacketEntry> def;
            def.swap(m_deferred);
            append_packets(std::move(def));
        }
        return;
    }
    // 异步过滤:快照 + 工作线程遍历,完成后再更新 m_visible(不阻塞 GUI)
    const ExportSnapshot snap = make_export_snapshot();
    m_filtering = true;
    auto* watcher = new QFutureWatcher<QVector<int>>(this);
    connect(watcher, &QFutureWatcher<QVector<int>>::finished, this,
        [this, watcher, gen]() {
            const QVector<int> res = watcher->result();
            watcher->deleteLater();
            if (gen != m_filter_gen) return;  // 过期结果(期间又改了过滤),丢弃
            m_visible = res;
            m_filtering = false;
            if (!m_deferred.isEmpty()) {      // 过滤期间暂存的 append 补进来
                QVector<PacketEntry> def;
                def.swap(m_deferred);
                append_packets(std::move(def));
            }
            beginResetModel();
            endResetModel();
        });
    // 映射表快照按值进工作线程:只读 + COW,与 snap/expr 同款,无竞态
    const auto mac_tei = m_mac_tei;
    watcher->setFuture(QtConcurrent::run([snap, expr, mac_tei]() {
        return run_filter(snap, expr, mac_tei);
    }));
}

void PacketListModel::ensure_loaded(int visible_row) {
    if (visible_row < 0 || visible_row >= m_visible.size()) return;
    const int g = m_visible[visible_row];
    const int hot_start = m_block_count * kBlockSize;
    if (g >= hot_start) return;   // 热区无需加载
    const int bi = g / kBlockSize;
    load_block(bi);
    if (bi + 1 < m_block_count) load_block(bi + 1);
    if (bi - 1 >= 0)             load_block(bi - 1);
}

void PacketListModel::for_each_entry(const std::function<void(const PacketEntry&)>& fn) {
    for (int b = 0; b < m_block_count; ++b) {
        if (!load_block(b)) continue;
        auto it = m_block_cache.constFind(b);
        if (it == m_block_cache.constEnd()) continue;
        // 顺序访问:BlockReader 内分块只解压一次,逐条解码后回调(拷贝出参,
        // 避免回调期间缓存淘汰导致引用悬空)
        for (int j = 0; j < it->count(); ++j) {
            PacketEntry e;
            if (it->entry_at(j, e)) fn(e);
        }
    }
    for (const PacketEntry& e : m_hot) fn(e);
}

PacketListModel::ExportSnapshot PacketListModel::make_export_snapshot() const {
    ExportSnapshot s;
    s.hot = m_hot;   // 深拷贝(≤ kBlockSize 条)
    s.block_paths.reserve(m_block_count);
    for (int i = 0; i < m_block_count; ++i)
        s.block_paths << block_path(i);
    s.tei_mac = m_tei_mac;   // 深拷贝 TEI→MAC 映射表(CSV 导出显示 MAC 用)
    return s;
}
