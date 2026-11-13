/// @file sofparser.cpp
/// @brief SOF 帧解析实现(独立帧解析模块,sofparser.pri)
/// @details 移植自 BPLCMonitor/MPDU_Class.py 的 MPDU_SOF 逻辑:
///          FCH 内业务字段位域 + 逐 PB 块 CRC24 校验与 MSDU 重组
///          (PB 头 START/END/seq 语义)。公共位域/CRC 工具见 fieldspec.h。
#include "gw_2022_sof_parser.h"
#include "gw_2022_pb_table.h"
#include "pb_assembler.h"
#include "crc.h"
#include "i18n.h"
#include "fieldtools.h"
#include <algorithm>

namespace {

// SOF PB 块长:TMI 主表 + TMI_EXT 扩展(与 Python MPDU_Class 一致)
int sof_pb_size(quint8 tmi, quint8 tmi_ext) {
    if (tmi == 0 || tmi == 1)                          return 520;
    if (tmi >= 2 && tmi <= 6)                          return 136;
    if (tmi >= 7 && tmi <= 10)                         return 520;
    if (tmi == 11 || tmi == 12)                        return 264;
    if (tmi == 13 || tmi == 14)                        return 72;
    if (tmi_ext >= 1 && tmi_ext <= 6)                  return 520;
    if (tmi_ext >= 10 && tmi_ext <= 14)                return 136;
    return -1;
}

// 无线 SOF 载荷PB大小(表29):索引 0-5 对应 16/40/72/136/264/520 字节
int sof_rf_pb_size(quint8 idx) {
    static const quint16 table[] = {16, 40, 72, 136, 264, 520};
    return (idx <= 5) ? int(table[idx]) : -1;
}

}  // namespace

namespace gw_2022_sof {

QString assemble(const QByteArray& body, MpduInfo& info, MsduState& msdu,
                 QByteArray& complete_msdu_body, quint8 band, bool is_rf,
                 bool* msdu_span_clean) {
    const quint8* p = reinterpret_cast<const quint8*>(body.constData());

    // FCH 业务字段(相对 FCH 起点)
    info.src_tei      = (quint16)get_bits(p, 4, 0, 12);
    info.dst_tei      = (quint16)get_bits(p, 5, 4, 12);
    info.link_id      = (quint8) get_bits(p, 7, 0, 8);
    info.frame_len    = (quint16)get_bits(p, 8, 0, 12);
    info.pb_num_field = (quint8) get_bits(p, 9, 4, 4);
    info.bc_flag      = (bool)   get_bits(p, 11, 1, 1);
    info.re_send_flag = (bool)   get_bits(p, 11, 2, 1);
    info.encryp_flag  = (bool)   get_bits(p, 11, 3, 1);
    int pb_size;
    if (is_rf) {
        // 无线 SOF(表30):无物理块个数字段,固定 1 块;字节9 bit4-7 为载荷PB大小(表29),
        // 字节10-11 bit0 与字节12 bit0-3 为保留(存原始值供呈现,不参与解析);
        // 字节11 bit4-7 为 MCS(表28)
        info.mcs         = (quint8) get_bits(p, 11, 4, 4);
        info.pb_num     = 1;
        info.symbol_num = (quint16)get_bits(p, 10, 0, 9);   // 保留(原始值)
        info.tmi_ext    = (quint8) get_bits(p, 12, 0, 4);   // 保留(原始值)
        pb_size         = sof_rf_pb_size(info.pb_num_field);
    } else {
        // 载波 SOF(表19):物理块个数/符号数/分集拷贝基本模式/扩展模式
        info.tmi         = (quint8) get_bits(p, 11, 4, 4);
        info.pb_num     = info.pb_num_field;
        info.symbol_num = (quint16)get_bits(p, 10, 0, 9);
        info.tmi_ext    = (quint8) get_bits(p, 12, 0, 4);
        pb_size         = sof_pb_size(info.tmi, info.tmi_ext);
    }

    const int max_pb_num = gw_2022_max_pb_num(band, info.tmi, info.tmi_ext);  // -1=频段/组合越界(查表自判)
    // 块数合法性只约束载波;RF 生效块数恒 1(见上);PB 大小非法(-1)对载波/无线均拒收
    if (pb_size <= 0
        || (!is_rf && (info.pb_num == 0 || info.pb_num > max_pb_num))) {
        return trl::L("PB 大小/数量非法(band=%1 tmi=%2 ext=%3 num=%4 max=%5)")
                   .arg(band).arg(info.tmi).arg(info.tmi_ext)
                   .arg(info.pb_num_field).arg(max_pb_num);
    }
    info.pb_size = (quint16)pb_size;

    // 逐块 CRC24 + 块体提取 + **帧内按序列号重排**(公共 pb_assembler)。
    // 国网布局:PB 头 1B(bit7=END / bit6=START / 低 6 位=序列号)+ 块体 + CRC24 3B。
    // 旧实现把"单帧多块重组"挂在会话级共享 MsduState(见 framedispatcher.h:33)上,
    // 会跨帧污染:一个缺 END 的异常帧之后,正常帧被判"序乱"整帧丢弃。
    // 现改为帧内局部状态,不再读写调用方 MsduState。
    Q_UNUSED(msdu);
    pb_asm::PbLayout lay{/*head*/1, /*rsv*/0, /*crc*/3,
                         /*agg_byte*/-1, /*agg_bit*/-1,
                         /*base*/16};
    lay.seq_byte  = 0;      // PB 头 byte0 低 6 位 = 序列号(HDC SOF PB 头)
    lay.seq_mask  = 0x3F;
    lay.start_bit = 6;      // bit6 = START
    lay.end_bit   = 7;      // bit7 = END
    const pb_asm::AssembleResult res =
        pb_asm::assemble_pb_blocks(body, info.pb_num, info.pb_size, lay);
    if (res.truncated)
        return trl::L("PB 块超出帧长");
    // 逐块头/CRC 按**到达序**存(UI 的「乱序已重排」判定依赖线序;体流按 seq 序)
    pb_asm::arrival_order_blocks(res, &info.pb_heads, &info.pb_crc_oks);
    if (!res.blocks.isEmpty()) info.pb_head = res.blocks.first().head_byte;
    // 帧级 CRC 口径:全部声明块到齐 + CRC 全过 + 序列号重排成功(缺块/越界/冲突→false)
    info.pb_crc_ok = res.all_crc_ok && !res.truncated && res.reassembly_ok;
    // 体流交付只要求序列号重组完整(缺块/越界/冲突仍不交付):
    // 首个 MSDU span 是否避开坏 CRC 块不再是交付门——MSDU CRC32 才是拓扑学习
    // 的最终判据,有效 MSDU CRC 可覆盖 PB CRC 失败(见 msdu_crc_allows_learning);
    // span 是否干净经出参透传调用方,仅在 MSDU CRC 不可用时作 PB 回退。
    // pb_crc_oks 保留原始逐块结果，帧仍会因坏块在 UI 标红。
    // span 口径必须用**国网**(SpanLayout::Gw):南网公式在国网头上两向都错。
    if (msdu_span_clean)
        *msdu_span_clean = pb_asm::msdu_span_avoids_bad_blocks(
            res.msdu_body, res.blocks, pb_size - 4, pb_asm::SpanLayout::Gw);
    if (pb_asm::body_parseable(res))
        complete_msdu_body = res.msdu_body;
    return QString();
}

}  // namespace gw_2022_sof

// ===== i18n:SOF 模块 中→英 词典 =====
namespace {
struct I18nRegSof {
    I18nRegSof() {
        trl::register_en("PB 块超出帧长", "PB block exceeds frame length");
        trl::register_en("PB 大小/数量非法(band=%1 tmi=%2 ext=%3 num=%4 max=%5)",
                         "Invalid PB Size/Count (band=%1 tmi=%2 ext=%3 num=%4 max=%5)");
    }
};
const I18nRegSof g_i18n_reg_sof;
}  // namespace
