/// @file iprotocolparser.h
/// @brief 协议解析器抽象接口 + 协议无关的解析结果/过滤条件
/// @details 国网/南网各实现一个 IProtocolParser 子类,工厂按 variant 实例化。
///          ParseResult/ParseFilter 是协议无关的展示结构(字段由公共
///          MpduInfo/MsduInfo 承载,南网仅多 snid/vlan_tag 等字段),UI/过滤/
///          导出/序列化统一消费,不感知具体协议。
#ifndef BPLC_IPROTOCOLPARSER_H
#define BPLC_IPROTOCOLPARSER_H

#include "bplcframe.h"
#include "common/protocolvariant.h"
#include <QDateTime>
#include <QList>
#include <QMetaType>
#include <algorithm>

/// @brief 协议无关的解析结果(展示层/过滤/导出统一消费)
struct ParseResult {
    ProtocolVariant protocol;   ///< 本帧由哪个协议解析(parser 填 variant();决定广播方向 0 值语义)
    PhysicalMeta meta;
    MpduInfo     mpdu;
    QByteArray   msdu_body;
    MsduInfo     msdu;          ///< MSDU/MAC 层解析结果(SOF 重组完整时填充)
    int          msdu_raw_base; ///< msdu_body[0] 在 payload_for_log 中的偏移;-1=跨帧
    MsduInfo     beacon;        ///< BEACON 载荷区解析结果(仅 BEACON 帧)
    qint64       arrival_us;    ///< 帧起始 0x3C 接收时刻(单调 µs,实时串口)
    QByteArray   raw_wire;      ///< 原始串口帧(0x3C...0x3E 原样,含转义)
    bool         accept;
    QString      reject_reason;
    QByteArray   payload_for_log;
    QVector<DissectField> dissect_fields; ///< 插件解析器返回的通用字段树(内置解析器恒为空)
    qint64       display_delta_us = -1;  ///< 本行显示 Delta(µs):内置解析器填,插件解析器留 -1(主界面沿用旧 NTB 差算法)

    ParseResult() : protocol(ProtocolVariant::GW_2022),
                    msdu_raw_base(-1), arrival_us(0), accept(false) {}
};

/// @brief 解析器向主界面提供本行显示时间/Delta 的上下文(分发器在 parse 前填:
///        行序号 + 本地时间,其中本地时间由 reader 成帧时采样、经分发器透传,
///        未带时分发器现取)
struct DisplayContext {
    qint64 row_index = 0;  ///< 该帧将填入 tableview 的行序号(分发器帧计数)
    qint64 now_ms = 0;     ///< parse 时本地时间(epoch ms),回退值
};

/// @brief 解析器侧显示时间锚点:上一个好帧(epoch + NTB),边解析边维护,无需往上找
/// @details 好帧 = accept 且 FCH 未失败且无 PB 失败。DROP 行不进解析器,故永不污染锚点;
///          CRC 错误帧显示链时间(若有效)或回退本地时间,但不更新锚点。
///          60s 门与 playbackwriter.h::kMaxNtbGapTicks 同值(NTB 25MHz,60s),两处须保持一致。
struct DisplayTimeAnchor {
    qint64  anchor_epoch_ms = 0;  ///< 上一个好帧的显示时间(epoch ms)
    quint32 anchor_ntb = 0;       ///< 上一个好帧的帧内 NTB(tick)
    qint64  anchor_row = 0;       ///< 上一个好帧的行序号(仅记录,不参与计算)
    bool    have_anchor = false;

    void apply(ParseResult& r, const DisplayContext& ctx) {
        const bool good = r.accept
            && !(r.mpdu.fch_crc_checked && !r.mpdu.fch_crc_ok)
            && std::none_of(r.mpdu.pb_crc_oks.cbegin(), r.mpdu.pb_crc_oks.cend(),
                            [](bool ok) { return !ok; });
        // 段首/时间标签/裸 hex:reader 时间已是权威(段标注/裸 hex 自有时间链),
        // 解析器不重算;好帧则成为锚点,坏帧不碰锚点
        if (r.meta.seg_start || r.meta.replay_time_tag || r.meta.from_raw) {
            r.display_delta_us = 0;
            if (good && r.meta.epoch_ms > 0) {
                anchor_epoch_ms = r.meta.epoch_ms;
                anchor_ntb = r.meta.timestamp;
                anchor_row = ctx.row_index;
                have_anchor = true;
            }
            return;
        }
        if (have_anchor) {
            const qint64 dn = qint32(r.meta.timestamp - anchor_ntb);  // 回绕安全
            if (dn > 0 && dn <= 25000000LL * 60) {
                const qint64 dus = dn * 40 / 1000;  // tick(40ns) → µs
                const qint64 epoch = anchor_epoch_ms + dus / 1000;
                r.meta.frame_time = QDateTime::fromMSecsSinceEpoch(epoch);
                r.meta.epoch_ms = epoch;
                r.display_delta_us = dus;
                if (good) {
                    anchor_epoch_ms = epoch;
                    anchor_ntb = r.meta.timestamp;
                    anchor_row = ctx.row_index;
                }
                return;
            }
        }
        // 回退:此前无好帧,或偏差超限(≤0 或 >60s)——用 reader 收帧时取的本地时间
        // (队列积压时比解析时现取更接近收帧时刻,回退误差更小)
        r.meta.frame_time = QDateTime::fromMSecsSinceEpoch(ctx.now_ms);
        r.meta.epoch_ms = ctx.now_ms;
        r.display_delta_us = 0;
        if (good) {
            anchor_epoch_ms = ctx.now_ms;
            anchor_ntb = r.meta.timestamp;
            anchor_row = ctx.row_index;
            have_anchor = true;
        }
    }
};

/// @brief ParseResult::protocol → PacketEntry::protocol 的唯一映射
/// @details 低 7 位映射到 kProtocolGw2022..kProtocolNw2026,**插件位原样保留**。
///          之所以收敛成函数:原先 mainwindow 用 switch(r.protocol) 重建 e.protocol,
///          插件帧的 0x80 位会在 default 分支被丢掉 → builder_for 看不到插件位,
///          show_packet 退回画内置布局(插件帧被误读),而按 PacketEntry 直接构造的
///          单元测试发现不了(绕过了本映射)。
inline quint8 entry_protocol_id(ProtocolVariant v) {
    const quint8 raw = quint8(v);
    quint8 id;
    switch (raw & 0x7F) {
        case quint8(ProtocolVariant::NW_2021): id = kProtocolNw2021; break;
        case quint8(ProtocolVariant::NW_2026): id = kProtocolNw2026; break;
        case quint8(ProtocolVariant::GW_2026): id = kProtocolGw2026; break;
        default:                              id = kProtocolGw2022; break;
    }
    return quint8(id | (raw & kProtocolPluginBit));
}

/// @brief 协议无关的过滤条件(帧类型/链路/NID/TEI)
struct ParseFilter {
    bool           enable_type_filter;
    bool           allow_beacon;
    bool           allow_sof;
    bool           allow_ack;
    bool           allow_coord;
    bool           link_hplc;
    bool           link_hrf;
    bool           nid_filter;
    quint32        nid_mask;
    QList<quint32> nid_list;
    bool           tei_filter;
    QList<quint16> tei_list;

    ParseFilter()
        : enable_type_filter(false),
          allow_beacon(true), allow_sof(true),
          allow_ack(true), allow_coord(true),
          link_hplc(true), link_hrf(true),
          nid_filter(false), nid_mask(0xFFFFFF),
          tei_filter(false) {}
};

/// @brief 协议解析器抽象接口(国网 GW_2022 / 南网 NW_2021 实现)
class IProtocolParser {
public:
    virtual ~IProtocolParser() = default;
    /// @brief 本解析器对应的协议变体
    virtual ProtocolVariant variant() const = 0;
    /// @brief 显示时间上下文(分发器在 parse 前调;内置解析器存下供显示时间判定用,
    ///        插件解析器默认忽略,主界面对其结果沿用旧 NTB 差算法)
    virtual void set_display_context(const DisplayContext&) {}
    /// @brief 解析一帧 BplcFrame → ParseResult
    virtual ParseResult parse(const BplcFrame& in, MsduState& msdu,
                              const ParseFilter& f) = 0;
};

Q_DECLARE_METATYPE(ParseResult)
Q_DECLARE_METATYPE(ParseFilter)

#endif  // BPLC_IPROTOCOLPARSER_H
