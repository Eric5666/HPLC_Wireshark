/// @file nw_2026_parser.h
/// @brief 南网 NW_2026 双模协议解析器头文件
/// @details 提供 NW_2026_Parser 类(IProtocolParser 实现)。南网 2021 报批版
///          链路层与国网 GW_2022 差异:FCH 网络标识为 SNID 4b(非 NID 24b),
///          各帧型字段坐标不同,MSDU 头用 MAC 48b + VLAN 标签。
///          字段坐标以协议原文为准。
#ifndef BPLC_NW_2026_PARSER_H
#define BPLC_NW_2026_PARSER_H

#include "bplcframe.h"
#include "iprotocolparser.h"
#include "../nw_2021/nw_2021_parser.h"   // BPLC 版本委托解析器(成员缓存)

class Statistics;

/// @brief 南网双模 2021 报批版协议解析器
class NW_2026_Parser : public IProtocolParser {
public:
    using Result = ParseResult;
    using Filter = ParseFilter;

    NW_2026_Parser();

    ProtocolVariant variant() const override { return ProtocolVariant::NW_2026; }

    Result parse(const BplcFrame& in, MsduState& msdu, const Filter& f) override;

    void set_display_context(const DisplayContext& ctx) override { m_display_ctx = ctx; }

private:
    Result parse_inner(const BplcFrame& in, MsduState& msdu, const Filter& f);
    bool decode_envelope(const BplcFrame& in, Result& r);
    bool parse_mpdu_base(const QByteArray& body, MpduInfo& info, QString& err);

    DisplayTimeAnchor m_time_anchor;  ///< 显示时间锚点(上一个好帧,含委托的 BPLC 版帧)
    DisplayContext m_display_ctx;     ///< 分发器给的行序号 + 本地时间

    /// @brief BPLC 版委托解析器(标准版本号≠2 帧整帧转交;见 parse() 版本自适应段)
    /// @details NW_2021_Parser 无状态,实例缓存免逐帧栈上构造;
    ///          解析器由 DispatcherWorker 单线程持有,成员缓存无并发问题。
    NW_2021_Parser m_legacy;

    // ---- UL-OFDMA trigger 上下文(A2 方案:按 SNID 分桶记录最近 trigger eFC) ----
    // 表26 类型 1 双义:DL-OFDMA 的 SACK 帧 / UL-OFDMA 数据帧。UL-OFDMA 数据帧的
    // 每站 TMI 不在本帧内(协议原文),必须取最近 trigger 帧(类型2) eFC 的每站 TMI。
    // 失效策略:①新 trigger 覆盖旧(最近一次语义)+ ②超过 kTriggerCtxMaxAge 帧未更新
    // 则丢弃(防脏数据)。解析器单线程持有(DispatcherWorker 成员缓存先例),无并发问题。
    struct TriggerSt { quint16 tei = 0; quint8 pb_num = 0; quint16 pb_size = 0; };
    struct TriggerCtx {
        quint8   station_count = 0;   ///< 站点数(1-4)
        TriggerSt st[4];
        quint64  frame_index = 0;     ///< 记录时的帧计数(失效基准)
    };
    static constexpr quint64 kTriggerCtxMaxAge = 1024;  ///< 超过 1024 帧未更新则失效
    QHash<quint32, TriggerCtx> m_trigger_ctx;   ///< 完整 5bit SNID → 最近 trigger 上下文
                                                ///< (低 4bit=net_id,高 1bit=OFDMA SOF byte12 bit0)
    quint64 m_frame_count = 0;                  ///< 递增帧计数(trigger 上下文失效基准)

    /// @brief 类型2(trigger)记录 eFC 上下文(表28:每站 PB数/TEI/TMI/RU/Tx回退)
    void record_trigger_ctx(quint32 snid, const quint8* p, int raw_sz);
    /// @brief 类型1 分派:DL-SACK(单16B PB) / UL-OFDMA 数据(需 trigger 上下文)
    void parse_ofdma_type1(Result& r, const quint8* p, int raw_sz);
};

#endif  // BPLC_NW_2026_PARSER_H
