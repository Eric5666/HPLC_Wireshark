/// @file gw_2026_parser.h
/// @brief 国网 GW_2026 双模协议解析器头文件
/// @details 提供 GW_2026_Parser 类(IProtocolParser 实现),把一帧 BplcFrame
///          解码为 MPDU/MAC 字段,并支持 SOF 多 PB 块的 MSDU 重组。
#ifndef BPLC_GW_2026_PARSER_H
#define BPLC_GW_2026_PARSER_H

#include "bplcframe.h"
#include "iprotocolparser.h"
#include "gw_protocol/gw_2022/gw_2022_parser.h"   // HDC 1.0 委托解析器(成员缓存)
#include "gw_2026_msdu_parser.h"

class Statistics;

/// @brief 国网双模标准 2022(202203)协议解析器
class GW_2026_Parser : public IProtocolParser {
public:
    // 向后兼容别名:Result/Filter 即协议无关的 ParseResult/ParseFilter
    using Result = ParseResult;
    using Filter = ParseFilter;

    GW_2026_Parser();

    ProtocolVariant variant() const override { return ProtocolVariant::GW_2026; }

    Result parse(const BplcFrame& in, MsduState& msdu, const Filter& f) override;

    void set_display_context(const DisplayContext& ctx) override { m_display_ctx = ctx; }

private:
    Result parse_inner(const BplcFrame& in, MsduState& msdu, const Filter& f);
    bool decode_envelope(const BplcFrame& in, Result& r);
    bool parse_mpdu_base(const QByteArray& body, MpduInfo& info, QString& err);

    DisplayTimeAnchor m_time_anchor;  ///< 显示时间锚点(上一个好帧,含委托的 HDC 1.0 帧)
    DisplayContext m_display_ctx;     ///< 分发器给的行序号 + 本地时间

    /// @brief HDC 1.0 委托解析器(版本=0 帧整帧转交;见 parse() 版本自适应段)
    /// @details GW_2022_Parser 无状态,实例缓存免逐帧栈上构造;
    ///          解析器由 DispatcherWorker 单线程持有,成员缓存无并发问题。
    GW_2022_Parser m_legacy;
};

#endif  // BPLC_GW_2026_PARSER_H
