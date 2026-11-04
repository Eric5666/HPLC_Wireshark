/// @file sofparser.cpp
/// @brief SOF 帧解析实现(独立帧解析模块,sofparser.pri)
/// @details HDC 2.0:SOF 按载波表7-表13/无线表19 分介质解析 FCH 可变区域,
///          载波再按帧子类型(表7 byte7 bit0-2)分派:数据帧/信道探测帧(表9)/
///          OFDMA 下行帧(表10/11)/TDA 下行帧(表12/13);链路标识符已移至
///          MAC 帧头 byte15(表2)。逐 PB 块 CRC24 校验与 MSDU 重组
///          (PB 头 START/END/seq 语义)。公共位域/CRC 工具见 fieldspec.h。
#include "gw_2026_sof_parser.h"
#include "gw_2026_pb_table.h"
#include "gw_2026_tree.h"
#include "crc.h"
#include "pb_assembler.h"
#include "i18n.h"
#include "fieldtools.h"
#include <algorithm>

namespace {

// 无线 SOF 载荷PB大小(HDC2.0 4-2 表19):索引 0-5 对应 16/40/72/136/264/520 字节
int sof_rf_pb_size(quint8 idx) {
    static const quint16 table[] = {16, 40, 72, 136, 264, 520};
    return (idx <= 5) ? int(table[idx]) : -1;
}

// 载波 PB 个数 2b 编码 → 块数(表7:0-3 = 1-4 个物理块)
inline int sof_pb_num_decode(quint8 code) { return code + 1; }

// 动态加载模式的调制参数 = 物理块类型编号(表8:0-3 = PB72/136/264/520)
int sof_dynamic_pb_size(quint8 type) {
    static const quint16 table[] = {72, 136, 264, 520};
    return (type <= 3) ? int(table[type]) : -1;
}

}  // namespace

namespace gw_2026_sof {

QString assemble(const QByteArray& body, MpduInfo& info, MsduState& msdu,
                 QByteArray& complete_msdu_body, quint8 band, bool is_rf) {
    const quint8* p = reinterpret_cast<const quint8*>(body.constData());

    // FCH 业务字段(相对 FCH 起点;载波/无线共用前段:源/目的 TEI + 帧长)
    info.src_tei      = (quint16)get_bits(p, 4, 0, 12);
    info.dst_tei      = (quint16)get_bits(p, 5, 4, 12);
    info.frame_len    = (quint16)get_bits(p, 8, 0, 12);
    // 链路标识符(HDC 2.0 移至 MAC 帧头 byte15,表2;FCH 内不再有此字段)
    info.link_id      = 0;

    int pb_size;
    if (is_rf) {
        // 无线 SOF(HDC2.0 4-2 表19,布局同 HDC 1.0 表30):固定 1 块;字节9 bit4-7 为
        // 载荷PB大小(表19),字节11 bit4-7 为 MCS(表18),其余保留(存原始值)
        info.pb_num_field = (quint8) get_bits(p, 9, 4, 4);
        info.bc_flag      = (bool)   get_bits(p, 11, 1, 1);
        info.re_send_flag = (bool)   get_bits(p, 11, 2, 1);
        info.encryp_flag  = (bool)   get_bits(p, 11, 3, 1);
        info.mcs          = (quint8) get_bits(p, 11, 4, 4);
        info.pb_num       = 1;
        info.symbol_num = (quint16)get_bits(p, 10, 0, 9);   // 保留(原始值)
        info.tmi_ext    = (quint8) get_bits(p, 12, 0, 4);   // 保留(原始值)
        pb_size         = sof_rf_pb_size(info.pb_num_field);
    } else {
        // 载波 SOF(表7 数据帧):帧子类型/TF描述/帧长后为 FCH 符号数(跨字节)/
        // 调制方式与参数/2b 编码 PB 个数/广播·加密·重传/频段标识/增益/加载表ID
        info.sof_data_type     = (quint8) get_bits(p, 7, 0, 3);
        // 载波 SOF 按帧子类型分派(表7 (7,0,3)):
        //   0=数据帧(表7) 1=信道探测帧(表9) 2=OFDMA下行(表10/11) 3=TDA下行(表12/13)
        const quint8 sof_dt = info.sof_data_type;
        if (sof_dt == 1) {
            // 表9(信道探测帧)无 PB/调制/PB个数字段:载荷为训练序列,不带数据物理块。
            // 表9 专属字段(子载波分组/训练序列频段/训练序列符号数/扩展目的TEI)由树层从 raw 直读,
            // 不进 MpduInfo。⇒ 跳过 PB 组装,避免按表7 坐标读出垃圾并误报 CRC FAIL。
            info.pb_num = 0; info.pb_size = 0; info.pb_num_field = 0;
            info.sof_stations.clear();
            return QString();
        }
        if (sof_dt == 2 || sof_dt == 3) {
            const bool is_ofdma = (sof_dt == 2);
            // 站点数(表10 (7,3,2) / 表12 (7,3,2)):0=保留 1=2站 2=3站 3=4站
            const quint8 sn_code = (quint8)get_bits(p, 7, 3, 2);
            const int n_sites = (sn_code >= 1 && sn_code <= 3) ? (sn_code + 1) : 0;
            if (n_sites == 0) {
                info.pb_num = 0; info.pb_size = 0; info.sof_stations.clear();
                return trl::L("OFDMA/TDA 站点数为保留值 0(表10/表12 仅定义 1-3)");
            }
            info.sof_stations.clear();
            int blk = 32;   // PB 起点:FCH 16B + eFC 16B(表11/13 固定 16 字节)
            bool any_reassembly_bad = false;   // 任一站序列号落位失败(缺块/越界/冲突)
            for (int si = 0; si < n_sites; ++si) {
                SofStationPb st;
                quint8 copy_mode = 0;
                quint8 st_pb_num = 1;
                if (si == 0) {
                    st.tei = info.dst_tei;                 // 表10 (5,4,12) 站点0 TEI = 目的 TEI
                    copy_mode = (quint8)get_bits(p, 11, 3, 5);           // 表10 (11,3,5)
                    if (is_ofdma) st_pb_num = (quint8)(get_bits(p, 11, 2, 1) + 1);  // 表10 (11,2,1):0→1块 1→2块
                } else {
                    const int b = is_ofdma ? (16 + (si - 1) * 3) : (16 + (si - 1) * 4);
                    st.tei = (quint16)get_bits(p, b, 0, 12);             // 表11/13 各站 TEI (b,0,12)
                    copy_mode = is_ofdma
                                ? (quint8)get_bits(p, b + 2, 0, 5)       // 表11 (b+2,0,5)
                                : (quint8)get_bits(p, b + 3, 0, 5);      // 表13 (b+3,0,5)
                    if (is_ofdma) st_pb_num = (quint8)(get_bits(p, b + 2, 5, 1) + 1);  // 表11 (b+2,5,1)
                }
                st.copy_mode = copy_mode;
                st.pb_num    = st_pb_num;

                // PB 大小:分集拷贝模式即 TMI 编号(协议「应符合 Q/GDW XXX.41 5.1.7.6 分集拷贝模式」)
                int sz = gw_2026_diversity_pb_size(copy_mode);
                if (is_ofdma && sz != 72 && sz != 136) {
                    return trl::L("OFDMA PB 大小越界(copy_mode=%1 → %2B，协议限 72/136)")
                               .arg(copy_mode).arg(sz);
                }
                if (sz <= 0)
                    return trl::L("OFDMA/TDA PB 大小非法(copy_mode=%1)").arg(copy_mode);
                st.pb_size    = (quint16)sz;
                st.block_base = blk;

                // 逐站 PB 组装:CRC24 + **帧内按序列号落位重排**(公共 pb_assembler)。
                // 国网布局:PB 头 1B(bit7=END / bit6=START / 低 6 位=序列号)+ 块体 + CRC24 3B。
                // 旧实现按到达位置切片(off = blk + j*sz),站内乱序时体序错,却仍会在
                // UI 显示「乱序已重排」并让学习解析错序体。
                pb_asm::PbLayout layout{/*head*/1, /*rsv*/0, /*crc*/3,
                                        /*agg_byte*/-1, /*agg_bit*/-1,
                                        /*base*/blk};
                layout.seq_byte  = 0;
                layout.seq_mask  = 0x3F;
                layout.start_bit = 6;
                layout.end_bit   = 7;
                const pb_asm::AssembleResult res =
                    pb_asm::assemble_pb_blocks(body, st_pb_num, sz, layout);
                // 逐块头/CRC 按**到达序**存(UI 的「乱序已重排」判定依赖线序;体流按 seq 序)
                pb_asm::arrival_order_blocks(res, &st.pb_heads, &st.pb_crc_oks);
                // 仅重组可信(编号到齐、无缺块/越界/冲突)时交付体流:
                // 否则 st.msdu 留空 → 树不显示该站 MSDU、学习门自然跳过。
                if (pb_asm::body_parseable(res))
                    st.msdu = res.msdu_body;
                if (!res.reassembly_ok) any_reassembly_bad = true;
                info.sof_stations.append(st);
                if (res.truncated) break;   // 后续站点已无字节可切,停止(已收站点保留)
                blk += st_pb_num * sz;
            }
            // 汇总字段(供 Info 列/树顶层显示)
            info.pb_num   = 0;
            info.pb_size  = 0;
            info.pb_num_field = sn_code;
            // 逐站 CRC 进帧级 pb_crc_oks(用户 2026-10-30 定,仅 PB 块 CRC):
            // 各站 st.pb_crc_oks 为**站内到达序**逐块 CRC24 结果(与 st.pb_heads 同序,
            // 供 UI 逐块显示与「乱序已重排」判定);st.msdu 是**序列号重排后的 seq 序**
            // 体流 —— 两者序不同,做 span/坏块判定前必须按 seq 归位
            // (见 gw_2026_sof::station_msdu_parseable)。
            // 此处仅按站序把各站 CRC 拼成帧级列表(整帧统计用)。
            // 单站点路径(info.pb_crc_oks 由组装段填)与此多站分支互斥,无 double-append。
            for (const auto& st : info.sof_stations)
                for (bool ok : st.pb_crc_oks) info.pb_crc_oks.append(ok);
            // 帧级 CRC 状态(多站):全部站点块到齐 + 各块 CRC 全过。
            // 旧实现从不设 pb_crc_ok(恒 false),导致完整 OFDMA 帧被 UI 误报
            // 「CRC 不完整(重组失败)」;现按逐站块数/CRC 汇总。
            {
                bool all_ok = true;
                for (const auto& st : info.sof_stations) {
                    if (st.pb_crc_oks.size() < int(st.pb_num)) all_ok = false;  // 本站缺块
                    for (bool ok : st.pb_crc_oks) all_ok = all_ok && ok;
                }
                info.pb_crc_ok = all_ok && !any_reassembly_bad;
            }
            // 多站点 PB 布局已通过协议仿真帧验证，尚未经实包确认。
            // 已验证(strong)：
            //   · 块边界 —— 帧长恰好等于 16(FCH) + 16(eFC) + Σ(站点块数 × 块长)：
            //     OFDMA 440B = 32 + 2×136 + 1×136；TDA 304B = 32 + 136 + 136
            //   · 每块 CRC24 校验通过（切错 1 字节必挂）⇒ 块起点 32、块长 136、
            //     站点间步进 136 全部自洽
            //   · PB 头 START/END/seq 时序合法（首块 0x40=START / 末块 0x81=END / 单块 0xC0）
            //   · 源码与 Python 独立复算、Lua tshark 三方 CRC 值一致
            // 未验证(weak) —— 只有实包能证伪：
            //   · eFC 是否恒为 16 字节（表11/13 内部字节号 0-15 是推断依据，
            //     「扩展帧控制符号数」是时序属性，不影响字节布局的判断尚待实包确认）
            //   · 分集拷贝模式(5bit) → PB 大小 的映射：已按分集拷贝模式表
            //     (gw_2026_diversity_pb_size,HDC 2.0 4-1 物理层 5.1.9.7 表18)
            //     实现,并用 5.2.5.7「只允许 PB72/PB136」做约束
            //   · 真实设备是否在 eFC 后插厂商私有字段
            // ⚠ 循环论证风险：仿真帧是按同一份协议文档构造的，两者一致只能排除
            //   「实现偏离文档」，不能排除「文档理解偏差」。真帧到位后应复核上述 weak 项。
            return QString();
        }
        if (sof_dt >= 4) {
            info.pb_num = 0; info.pb_size = 0;
            return trl::L("帧子类型为保留值(表7 仅定义 0-3)");
        }

        info.sof_tf_symbol_pos = (quint8) get_bits(p, 7, 3, 2);
        info.sof_tf_symbol_num = (quint8) get_bits(p, 7, 5, 3);
        // FCH符号数(9,7,2) 跨字节:byte9 bit7 + byte10 bit0(表7)
        info.sof_fch_sym_num   = (quint8)((get_bits(p, 9, 7, 1))
                                       | (get_bits(p, 10, 0, 1) << 1));
        info.sof_mod_mode      = (quint8) get_bits(p, 10, 1, 1);
        info.sof_mod_param     = (quint8) get_bits(p, 10, 2, 5);
        // PB 个数 2b 编码:(10,7)+(11,0) 跨字节 → 0-3 = 1-4 块
        // (68-bit 位流连续排布:…参数(10,2-6)|PB个数(10,7)+(11,0)|广播(11,1)…)
        const quint8 pb_code   = (quint8)((get_bits(p, 10, 7, 1))
                                       | (get_bits(p, 11, 0, 1) << 1));
        info.pb_num_field      = pb_code;
        info.pb_num            = sof_pb_num_decode(pb_code);
        info.bc_flag           = (bool)   get_bits(p, 11, 1, 1);
        info.encryp_flag       = (bool)   get_bits(p, 11, 2, 1);
        info.re_send_flag      = (bool)   get_bits(p, 11, 3, 1);
        info.sof_band          = (quint8) get_bits(p, 11, 4, 3);
        info.sof_gain          = (quint8)((get_bits(p, 11, 7, 1))
                                       | (get_bits(p, 12, 0, 3) << 1));
        info.sof_load_table_id = (quint8) get_bits(p, 12, 3, 1);
        info.symbol_num = 0;
        info.tmi = info.sof_mod_param;   // 分集拷贝模式编号 = 调制参数(表7 byte10 bit2-6)
        // HDC 2.0 无 TMI_EXT:载波不填扩展字段,info.tmi_ext 保持默认 0,不再参与查表。

        // PB 大小按调制方式分派(枚举驱动):分集拷贝=调制参数查分集拷贝模式表;
        // 动态加载=调制参数查物理块类型表(表8)
        switch (static_cast<GW_2026_ModMode>(info.sof_mod_mode)) {
            case GW_2026_ModMode::DIVERSITY_COPY:
                pb_size = gw_2026_diversity_pb_size(info.tmi);
                break;
            case GW_2026_ModMode::DYNAMIC_LOAD:
                pb_size = sof_dynamic_pb_size(info.sof_mod_param);
                break;
            default:
                pb_size = -1;
                break;
        }
        // 帧子类型非数据帧(信道探测/OFDMA/TDA)的字段布局不同(表9-表13),
        // 此处仍按数据帧完成 TEI/帧长提取,载荷区按通用 PB 逐块解析展示;
        // 子类型专属字段由字段树标注(见 gw_2026_tree.cpp SOF 分支)。
    }

    const int max_pb_num = gw_2026_max_pb_num(band, info.tmi);  // -1=频段/模式越界(查表自判)
    // 块数合法性只约束载波;RF 生效块数恒 1(见上);PB 大小非法(-1)对载波/无线均拒收。
    // max_pb_num==0(该频段+模式不支持,如 band3)时 pb_num>=1 即超限拒收。
    if (pb_size <= 0
        || (!is_rf && (info.pb_num == 0 || info.pb_num > max_pb_num))) {
        return trl::L("PB 大小/数量非法(band=%1 mod=%2 param=%3 num=%4 max=%5)")
                   .arg(band).arg(info.sof_mod_mode).arg(info.sof_mod_param)
                   .arg(info.pb_num).arg(max_pb_num);
    }
    info.pb_size = (quint16)pb_size;

    int block_offset = 16;
    // 逐块 CRC24 + 块体提取 + **帧内按序列号重排**(公共 pb_assembler)。
    // 国网布局:PB 头 1B(bit7=END / bit6=START / 低 6 位=序列号)+ 块体 + CRC24 3B,
    // 无聚合标志字段。旧实现把单帧多块重组挂在会话级共享 MsduState 上(跨帧污染),
    // 现改为帧内局部状态,不再读写调用方 MsduState。
    Q_UNUSED(msdu);
    pb_asm::PbLayout lay{/*head*/1, /*rsv*/0, /*crc*/3,
                         /*agg_byte*/-1, /*agg_bit*/-1,
                         /*base*/block_offset};
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
    // 仅交付完整重组且首个 MSDU span 完全避开坏 CRC 块的体流；
    // pb_crc_oks 保留原始逐块结果，帧仍会因坏块在 UI 标红。
    // 口径必须用**国网**(SpanLayout::Gw):南网公式在国网头上两向都错。
    if (pb_asm::body_parseable_with_good_msdu_span(
            res, pb_size - 4, pb_asm::SpanLayout::Gw))
        complete_msdu_body = res.msdu_body;
    return QString();
}

}  // namespace gw_2026_sof

// ===== i18n:SOF 模块 中→英 词典 =====
namespace {
struct I18nRegSof {
    I18nRegSof() {
        trl::register_en("PB 块超出帧长", "PB block exceeds frame length");
        trl::register_en("OFDMA/TDA 站点数为保留值 0(表10/表12 仅定义 1-3)",
                         "OFDMA/TDA Station Count Is Reserved Value 0 (Tables 10/12 Define 1-3 Only)");
        trl::register_en("帧子类型为保留值(表7 仅定义 0-3)",
                         "Frame Subtype Is Reserved Value (Table 7 Defines 0-3 Only)");
        trl::register_en("OFDMA PB 大小越界(copy_mode=%1 → %2B，协议限 72/136)",
                         "OFDMA PB Size Out of Range (copy_mode=%1 → %2B, Spec Allows 72/136 Only)");
        trl::register_en("OFDMA/TDA PB 大小非法(copy_mode=%1)",
                         "Invalid OFDMA/TDA PB Size (copy_mode=%1)");
        trl::register_en("PB 大小/数量非法(band=%1 mod=%2 param=%3 num=%4 max=%5)",
                         "Invalid PB Size/Count (band=%1 mod=%2 param=%3 num=%4 max=%5)");
    }
};
const I18nRegSof g_i18n_reg_sof;
}  // namespace
