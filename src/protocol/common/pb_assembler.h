/// @file pb_assembler.h
/// @brief 多物理块(PB)组装公共模块(国网/南网共用,协议无关)
/// @details 块级 mechanics 抽出共用:逐块 CRC24 校验、块体提取与 raw 偏移映射、
///          聚合级联记录拆分(南网 SPLC 表48)。重组策略由各协议 parser 自持,
///          行为与抽取前等价:
///            - 南网 SPLC:顺序拼接(分片重组)/ 聚合级联逐帧展示
///              (块 = PB头 4B(表47) + 块体 + 保留 1B + CRC24 3B,§5.1.3.2.1;
///               聚合标志 = PB头 byte2 bit0,表47)
///            - 国网 HDC 2.0:序列号状态机(START 0x40 / END 0x80 / seq 0x3F)
///              (块 = pb_head 1B + 块体 + CRC24 3B)
///          CRC24 恒覆盖块内前 pb_size-3 字节(块头+块体+尾保留),存储于末 3B
///          低字节在前(crc.h crc24_lsb)。
/// @note  header-only(同 crc.h/fieldtools.h 惯例:协议无关小工具免 .cpp,
///        手工枚举源文件的测试 .pro 无需逐一追加)。
#ifndef PROTOCOL_PB_ASSEMBLER_H
#define PROTOCOL_PB_ASSEMBLER_H

#include <QByteArray>
#include <QVector>
#include <cstring>
#include "crc.h"

namespace pb_asm {

/// @brief PB 块物理布局(块 = 块头 + 块体 + 尾保留 + CRC24)
struct PbLayout {
    int head_len;        ///< 块头长度(南网 4B 表47 / 国网 1B)
    int tail_rsv_len;    ///< 块尾保留长度(南网 1B / 国网 0)
    int crc_len;         ///< CRC24 长度(恒 3,低字节在前)
    int agg_flag_byte;   ///< 聚合标志块内字节(南网 2,表47;无聚合概念置 -1)
    int agg_flag_bit;    ///< 聚合标志位(南网 bit0,表47;无聚合概念置 -1)
    int block_base;      ///< 首块在 raw 中起点(普通/无线=FCH 16;DL-OFDMA=32)
    // ── 序列号坐标(规约;勿推定) ───────────────────────────────
    // 南网 BPLC 表133 §8.1.3.2.1.1 / SPLC 表47 §5.1.3.2.1.1:
    //   4B 头,序列号 = byte0 bit0-7 + byte1 bit0-7 = 16bit(LE),
    //   初始 0,表示 MPDU 载荷中物理块的序号(3 块依次 0/1/2)。
    // 国网 GW(HDC1.0/2.0):pb_head 1B,低 6 位 = 序列号,
    //   bit7=END、bit6=START。
    int seq_byte = -1;   ///< 序列号起始字节(块内;-1=该布局无序列号,退回按位置拼接)
    quint32 seq_mask = 0;///< 序列号掩码(南网 0xFFFF 表133/表47;国网 0x3F)
    int start_bit = -1;  ///< 起始标识位(国网 pb_head bit6;南网无,置 -1)
    int end_bit = -1;    ///< 结束标识位(国网 pb_head bit7;南网无,置 -1)
    /// 块体长度 = pb_size - 头 - 尾保留 - CRC
    int body_len(int pb_size) const
        { return pb_size - head_len - tail_rsv_len - crc_len; }
};

/// @brief 单块解析结果(块体 raw 偏移供高亮映射)
struct PbBlock {
    int    raw_offset;      ///< 块起点(raw 偏移)
    int    body_raw_offset; ///< 块体起点(raw 偏移 = 块起点 + 块头长度)
    int    body_len;        ///< 块体长度
    quint8 head_byte;       ///< 块头首字节(国网 pb_head 起始/结束/序号;南网序列号低 8b)
    bool   crc_ok;          ///< CRC24 校验结果
    bool   aggregated;      ///< 聚合标志(布局无聚合字段时恒 false)
};

/// @brief 级联 MAC 帧(南网 SPLC 表48:级联头 2B + 级联数据块)
struct CascadeMac {
    QByteArray mac;       ///< 级联 MAC 帧字节(独立帧,逐帧解析展示)
    int body_start;       ///< 级联头在级联体流(msdu_body)中的偏移
    int mac_len;          ///< 级联数据块长度 = MAC 帧长度(高亮 rel_len)
    bool start_flag;      ///< 级联块起始标识(表48 体1 bit4)
    bool end_flag;        ///< 级联块结束标识(表48 体1 bit5)
};

/// @brief 组装结果
struct AssembleResult {
    QVector<PbBlock> blocks;       ///< 完整容纳块的逐块结果(依序)
    bool truncated = false;        ///< 帧长不足以容纳全部声明块
    bool any_aggregated = false;   ///< 任一块聚合标志=1(表47)。
                                   ///< 现状口径(已文档化,语义未改):任一块 OR —— 只要
                                   ///< 有一块聚合标志=1,整帧即按聚合处理,msdu_body
                                   ///< 全体按表48 级联拆分,含混合帧中非聚合块的块体
                                   ///< (该块体亦被强制按级联记录切分)。与 Lua any_agg
                                   ///< (packet-nw_2026.lua:3098)同口径;多块聚合示意
                                   ///< 见 SPLC 第4部分 图11。"全块一致才级联"为另一
                                   ///< 候选口径,待决策;在此之前保持本语义。
    bool all_crc_ok = true;        ///< 全部完整块 CRC24 通过
    QByteArray msdu_body;          ///< 全部块体依序拼接(分片重组缓冲/级联体流)
    QVector<CascadeMac> cascade;   ///< 聚合级联拆分结果(any_aggregated 时有效;
                                   ///< 已剔除与 CRC 失败块体相交的记录,见下)
    int cascade_crc_skipped = 0;   ///< 聚合:因块 CRC 失败被剔除的级联记录数(用户
                                   ///< 2026-10-29 定:CRC 失败块数据不准确不解析,
                                   ///< 仅解析全部字节均来自 CRC 通过块的记录)
    int cascade_used = 0;          ///< 聚合:级联记录流有效长度(逐条 2+级联数据块长度
                                   ///< 累加,不含块体尾填充;非聚合=0)
    int cascade_break_declared_len = -1; ///< 聚合:级联 while 因"声明长度越界/非法"终止时,
                                        ///< 记录该条声明的级联数据块长度(截断/损坏线索;-1=正常结束,0 亦为非法声明值故不用 0 作哨兵)
    // ── 帧内重排(序列号)诊断:仅内存结构,不进持久化 ──────────────
    QVector<int> slot_block;       ///< 拼接序 → blocks 下标(重组成功时非平凡;
                                   ///< 未重组时为恒等映射,供调用方对齐)
    int  seq_reordered = 0;        ///< 乱序块数(到达序≠序列号序的块个数;0=顺序到达)
    int  seq_dup = 0;              ///< 重复序列号且内容一致的块数(容忍,保留首块)
    int  seq_conflict = 0;         ///< 重复序列号且内容不一致的块数(判冲突,不重组)
    int  seq_oob = 0;              ///< 序列号越界(>= pb_num)块数(整帧判异常,不重组)
    int  missing_blocks = 0;       ///< 缺失槽位数(0..pb_num-1 中无块填充的个数)
    int  first_missing_slot = -1;  ///< 首个缺失槽位(显示「缺块 k」用;-1=无缺块)
    int  pb_head_flag_mismatch = 0;///< 国网 START/END 与序列号交叉校验不符块数
                                   ///< (仅显示用,不影响按 seq 重组)
    bool reassembly_ok = false;    ///< 全部声明块到齐且序列号无越界/冲突 → 按 seq 重组成功
    bool seq_uniform_fallback = false; ///< 兼容兜底:全部块序列号相同且帧内块数>1
                                   ///< (设备未填序列号,如全 0),视为无序列号信息,
                                   ///< 退回按到达位置拼接(reassembly_ok 仍可为真)
};

/// @brief 逐块 CRC24 + 块体提取 + 聚合级联拆分
/// @details
/// - 块体依序拼接 → result.msdu_body(重组缓冲 = 级联体流;树层 MsduRawMap 按
///   块换算 rel→raw,跨块多段高亮,见 protocol_tree_builder.h)
/// - 任一块聚合标志=1 → 把 msdu_body 视为连续级联记录流(记录可跨块体边界;
///   实测锚点:3×64B 体流 4 条记录 [2d 10]/[2d 00]/[2d 00]/[2d 20],首记录
///   Start=1、末记录 End=1)按表48 逐条拆分:级联头 2B = 级联数据块长度 12b
///   (LSB 在前:体 o 全 + 体 o+1 低 nib)+ 起始标识(体 o+1 bit4)/结束标识
///   (bit5)/保留(bit6-7),其后为级联长度的独立 MAC 帧;截断/长度非法即停
inline AssembleResult assemble_pb_blocks(const QByteArray& raw, int pb_num,
                                         int pb_size, const PbLayout& layout) {
    AssembleResult res;
    if (pb_num <= 0
        || pb_size <= layout.head_len + layout.tail_rsv_len + layout.crc_len)
        return res;
    const int body_len = layout.body_len(pb_size);
    const int crc_at   = pb_size - layout.crc_len;
    for (int i = 0; i < pb_num; ++i) {
        const int block_start = layout.block_base + i * pb_size;
        if (block_start + pb_size > raw.size()) {
            res.truncated = true;
            break;
        }
        const quint8* blk = reinterpret_cast<const quint8*>(raw.constData())
                            + block_start;
// crc24_lsb 内部遍历 len-3 字节;此处传 pb_size(全长)即校验块头+块体+尾保留,
// 末 3B 为本 CRC 自身(crc.h 约定,勿传 pb_size-3 否则少算 3B)
        const quint32 calc = crc24_lsb(blk, pb_size);
        const quint32 rx   = (quint32)blk[crc_at]
                           | ((quint32)blk[crc_at + 1] << 8)
                           | ((quint32)blk[crc_at + 2] << 16);
        PbBlock b;
        b.raw_offset      = block_start;
        b.body_raw_offset = block_start + layout.head_len;
        b.body_len        = body_len;
        b.head_byte       = blk[0];
        b.crc_ok          = (calc == rx);
        b.aggregated      = (layout.agg_flag_byte >= 0 && layout.agg_flag_bit >= 0)
                                ? (((blk[layout.agg_flag_byte]
                                     >> layout.agg_flag_bit) & 0x01) != 0)
                                : false;
        res.all_crc_ok    = res.all_crc_ok && b.crc_ok;
        res.any_aggregated = res.any_aggregated || b.aggregated;  // 任一块 OR:现状口径,见 any_aggregated 字段注释
        res.blocks.append(b);
        res.msdu_body += raw.mid(b.body_raw_offset, body_len);
    }

    // ② 帧内按序列号落位重组(南网 表133/表47 16bit LE;国网 pb_head 低 6 位)
    //    规约(SPLC 第4部分 §5.1.3.2.1):「重组时,需要根据'物理块头'中的
    //    '序列号',将所有的'物理块体'进行有序的重组。」
    if (layout.seq_byte >= 0 && layout.seq_byte + 1 < pb_size
        && !res.blocks.isEmpty()) {
        const int n = res.blocks.size();
        QVector<int> seqs(n, 0);
        bool all_same = true;
        for (int i = 0; i < n; ++i) {
            const quint8* blk = reinterpret_cast<const quint8*>(raw.constData())
                                + res.blocks[i].raw_offset;
            const quint32 seq = ((quint32)blk[layout.seq_byte]
                                 | ((quint32)blk[layout.seq_byte + 1] << 8))
                                & layout.seq_mask;
            seqs[i] = (int)seq;
            if (i > 0 && seqs[i] != seqs[0]) all_same = false;
        }
        if (n > 1 && all_same) {
            // 兼容兜底:多块帧内序列号全同(设备未填该字段,常见全 0)→ 视为无
            // 序列号信息,退回按到达位置拼接;否则会被判「重复+冲突」把正常帧误判异常。
            res.seq_uniform_fallback = true;
            res.slot_block.resize(n);
            for (int i = 0; i < n; ++i) res.slot_block[i] = i;
            res.reassembly_ok = !res.truncated && n == pb_num;
        } else {
            QVector<int> slot(pb_num, -1);
            for (int i = 0; i < n; ++i) {
                const int s = seqs[i];
                if (s < 0 || s >= pb_num) { ++res.seq_oob; continue; }
                if (slot[s] < 0) { slot[s] = i; continue; }
                // 重复序列号:内容一致容忍,不一致判冲突(策略:冲突不重组)
                const quint8* a = reinterpret_cast<const quint8*>(raw.constData())
                                  + res.blocks[slot[s]].raw_offset;
                const quint8* c = reinterpret_cast<const quint8*>(raw.constData())
                                  + res.blocks[i].raw_offset;
                if (std::memcmp(a, c, (size_t)pb_size) == 0) ++res.seq_dup;
                else                                          ++res.seq_conflict;
            }
            // 国网 START/END 降级为交叉校验(只许 START 在 seq0 / END 在末块),
            // 违反仅记数供显示,不影响按 seq 重组。
            for (int i = 0; i < n; ++i) {
                const quint8 h = res.blocks[i].head_byte;
                const int    s = seqs[i];
                if (layout.start_bit >= 0
                    && ((((h >> layout.start_bit) & 1) != 0) != (s == 0)))
                    ++res.pb_head_flag_mismatch;
                if (layout.end_bit >= 0
                    && ((((h >> layout.end_bit) & 1) != 0) != (s == pb_num - 1)))
                    ++res.pb_head_flag_mismatch;
            }
            for (int s = 0; s < pb_num; ++s) {
                if (slot[s] >= 0) continue;
                ++res.missing_blocks;
                if (res.first_missing_slot < 0) res.first_missing_slot = s;
            }
            res.reassembly_ok = !res.truncated && n == pb_num
                                && res.missing_blocks == 0
                                && res.seq_oob == 0 && res.seq_conflict == 0;
            if (res.reassembly_ok) {
                // 按序列号升序重排:blocks 与 msdu_body 统一按拼接序暴露
                // (cascade 坏块区间判定用 i*body_len,必须与拼接序一致)
                QVector<PbBlock> ordered;
                ordered.reserve(pb_num);
                QByteArray body;
                body.reserve(pb_num * body_len);
                res.slot_block.clear();
                res.slot_block.reserve(pb_num);
                for (int s = 0; s < pb_num; ++s) {
                    const int bi = slot[s];
                    ordered.append(res.blocks[bi]);
                    body += raw.mid(res.blocks[bi].body_raw_offset, body_len);
                    res.slot_block.append(bi);
                    if (bi != s) ++res.seq_reordered;
                }
                res.blocks    = ordered;
                res.msdu_body = body;
            } else {
                res.slot_block.resize(n);
                for (int i = 0; i < n; ++i) res.slot_block[i] = i;
            }
        }
    } else {
        // 无序列号布局:保持按到达位置拼接(旧语义)
        res.slot_block.resize(res.blocks.size());
        for (int i = 0; i < res.blocks.size(); ++i) res.slot_block[i] = i;
        res.reassembly_ok = !res.truncated && res.blocks.size() == pb_num;
    }

    // ③ 聚合级联拆分(仅在数据可信时:重组成功,或无序列号布局)
    const bool body_trusted = res.reassembly_ok || layout.seq_byte < 0;
    if (res.any_aggregated && body_trusted) {
        int o = 0;
        while (o + 2 <= res.msdu_body.size()) {
            const int clen = (quint8)res.msdu_body[o]
                           | (((quint8)res.msdu_body[o + 1] & 0x0F) << 8);
            if (clen <= 0 || o + 2 + clen > res.msdu_body.size()) {
                res.cascade_break_declared_len = clen;   // 截断/长度非法:记录声明值供树层标注
                break;
            }
            CascadeMac c;
            c.body_start = o;
            c.mac_len    = clen;
            c.start_flag = (res.msdu_body[o + 1] & 0x10) != 0;
            c.end_flag   = (res.msdu_body[o + 1] & 0x20) != 0;
            c.mac        = res.msdu_body.mid(o + 2, clen);
            res.cascade.append(c);
            o += 2 + clen;
        }
        res.cascade_used = o;   // 级联记录流有效长度(块体尾填充不计,协议语义=逐条累加)
        // CRC 失败块不解析(用户 2026-10-29 定):记录 span=[body_start,
        // body_start+2+mac_len),只要与任一 CRC 失败块体区间
        // [i*body_len,(i+1)*body_len) 相交即剔除;msdu_body 本身不动
        // (高亮/块映射仍按原体流),cascade_used 亦保持原流长度。
        QVector<CascadeMac> kept;
        kept.reserve(res.cascade.size());
        for (const CascadeMac& c : res.cascade) {
            const int s = c.body_start, e = c.body_start + 2 + c.mac_len;
            bool bad = false;
            for (int i = 0; i < res.blocks.size() && !bad; ++i) {
                if (res.blocks[i].crc_ok) continue;
                const int bs = i * body_len, be = bs + body_len;
                if (s < be && e > bs) bad = true;
            }
            if (bad) ++res.cascade_crc_skipped;
            else kept.append(c);
        }
        res.cascade = kept;
    }
    return res;
}

/// @brief 重组体流是否可信到**可以解析 MSDU 字段**(国网/南网四协议统一口径)。
/// @details 仅当序列号落位成功(全部声明块到齐、无越界/重复冲突)且体流非空时可信。
///          注意 `msdu_span_avoids_bad_blocks` 只看"块 CRC 是否失败",不看序号完整性,
///          所以它不能单独作为解析门——序号重复/越界/缺块而各块 CRC 全过时它仍返回
///          true,此时体流字节顺序不确定,解析出来的字段是垃圾(帧本身已按
///          pb_crc_ok=false 标红)。级联拆分同样必须先过本判据。
inline bool body_parseable(const AssembleResult& r) {
    return r.reassembly_ok && !r.msdu_body.isEmpty();
}

/// @brief 按**到达序(线序)**回填块头与 CRC(供 UI/树按线序逐块展示)。
/// @details res.blocks 已按拼接序(seq 序)暴露,`slot_block[i]` 给出拼接序 i
///          的块在到达序中的下标,据此还原线序。体流(`msdu_body`)保持 seq 序;
///          两者分工:体流给"重组后内容",线序给"逐块 CRC/序列号判定"。
///          注意 UI 的「乱序已重排」判定依赖线序块头(拼接序恒等会看不出乱序)。
inline void arrival_order_blocks(const AssembleResult& r,
                                 QVector<quint8>* heads, QVector<bool>* oks) {
    if (heads) heads->clear();
    if (oks) oks->clear();
    const int n = r.blocks.size();
    QVector<quint8> h(n, 0);
    QVector<bool> k(n, false);
    for (int i = 0; i < n; ++i) {
        const int ai = (i < r.slot_block.size()) ? r.slot_block[i] : i;
        if (ai < 0 || ai >= n) continue;
        h[ai] = r.blocks[i].head_byte;
        k[ai] = r.blocks[i].crc_ok;
    }
    if (heads) *heads = h;
    if (oks) *oks = k;
}

/// @brief 首帧 MSDU span 是否避开全部 CRC 失败块(用户 2026-10-29 补定:
/// 多块帧中好块要解析——只要首帧 MSDU 完整落在好块内即解析,坏块在
/// span 之外时不影响;span 横跨坏块时仍不解析,因缺失字节会使体流
/// 错位成错误数据,而非“部分正确”)。
/// @details span 口径与 MSDU 解析器一致(nw_2026_msdu_parser.cpp):
/// msdu_len 在体[2..3]LE;版本(体[0] bit1-2)==2 为单跳帧 span=4+len+4,
/// 否则标准头 span=mac_hdr_len(体[0] bit0:0=32B/1=12B)+len+4(帧尾 CRC32)。
/// span 自体流 0 起,故与坏块 [i*body_len,(i+1)*body_len) 相交当且仅当
/// span > i*body_len。体 <4B 或 body_len<=0 时无法判定,返回 false。
inline bool msdu_span_avoids_bad_blocks(const QByteArray& body,
                                        const QVector<bool>& crc_oks,
                                        int body_len) {
    if (body.size() < 4 || body_len <= 0) return false;
    const quint8* p = reinterpret_cast<const quint8*>(body.constData());
    const quint16 msdu_len = (quint16)p[2] | ((quint16)p[3] << 8);
    int span = 0;
    if (((p[0] >> 1) & 0x03) == 2) {
        span = 4 + msdu_len + 4;
    } else {
        if (body.size() < 12) return false;
        const int mac_hdr_len = ((p[0] & 0x01) == 0) ? 32 : 12;
        span = mac_hdr_len + msdu_len + 4;
    }
    for (int i = 0; i < crc_oks.size(); ++i) {
        if (crc_oks[i]) continue;
        if (span > i * body_len) return false;
    }
    return true;
}

/// @brief 上述判定的 PbBlock 容器版(块序与体流拼接序一致)。
inline bool msdu_span_avoids_bad_blocks(const QByteArray& body,
                                        const QVector<PbBlock>& blocks,
                                        int body_len) {
    QVector<bool> crc_oks;
    crc_oks.reserve(blocks.size());
    for (const PbBlock& b : blocks) crc_oks.append(b.crc_ok);
    return msdu_span_avoids_bad_blocks(body, crc_oks, body_len);
}

/// @brief 重组体流是否可安全交付给 MSDU 解析器。
/// @details 先要求序列号重组完整，再要求首个 MSDU 的有效 span 不与坏 CRC 块相交。
///          块序必须与 msdu_body 的重组序一致；此函数不改变逐块 CRC 状态，
///          因而 UI 仍可按原始 CRC 结果将整帧标红。
inline bool body_parseable_with_good_msdu_span(const AssembleResult& r,
                                                int body_len) {
    return body_parseable(r)
        && msdu_span_avoids_bad_blocks(r.msdu_body, r.blocks, body_len);
}

}  // namespace pb_asm

#endif  // PROTOCOL_PB_ASSEMBLER_H
