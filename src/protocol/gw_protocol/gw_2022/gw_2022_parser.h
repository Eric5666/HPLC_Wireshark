/// @file gw_2022_parser.h
/// @brief 国网 GW_2022 双模协议解析器头文件
/// @details 提供 GW_2022_Parser 类(IProtocolParser 实现),把一帧 BplcFrame
///          解码为 MPDU/MAC 字段,并支持 SOF 多 PB 块的 MSDU 重组。
#ifndef BPLC_GW_2022_PARSER_H
#define BPLC_GW_2022_PARSER_H

#include "bplcframe.h"
#include "iprotocolparser.h"
#include "gw_2022_msdu_parser.h"

class Statistics;

/// @brief 国网双模标准 2022(202203)协议解析器
class GW_2022_Parser : public IProtocolParser {
public:
    // 向后兼容别名:Result/Filter 即协议无关的 ParseResult/ParseFilter
    using Result = ParseResult;
    using Filter = ParseFilter;

    GW_2022_Parser();

    ProtocolVariant variant() const override { return ProtocolVariant::GW_2022; }

    Result parse(const BplcFrame& in, MsduState& msdu, const Filter& f) override;

    void set_display_context(const DisplayContext& ctx) override { m_display_ctx = ctx; }

private:
    friend class GW_2026_Parser;  // 委托方调 parse_inner(不做显示时间判定,委托方统一做)
    Result parse_inner(const BplcFrame& in, MsduState& msdu, const Filter& f);
    bool decode_envelope(const BplcFrame& in, Result& r);
    bool parse_mpdu_base(const QByteArray& body, MpduInfo& info, QString& err);

    DisplayTimeAnchor m_time_anchor;  ///< 显示时间锚点(上一个好帧)
    DisplayContext m_display_ctx;     ///< 分发器给的行序号 + 本地时间
};

#endif  // BPLC_GW_2022_PARSER_H
