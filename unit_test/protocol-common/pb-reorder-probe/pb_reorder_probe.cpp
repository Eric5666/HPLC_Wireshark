// PB 块按序列号重排 + 帧内重组 回归探针(规格 SPEC-PB-reorder §6 用例清单)。
// 覆盖:
//   ① 南网 SPLC/BPLC 4 块 0,2,1,3 → msdu_body 体序 0 1 2 3
//   ② 国网 2022 / 2026 单站同款(经 gw_2022_sof / gw_2026_sof)
//   ③ 缺块 0,2,3(缺 1) → 不重组 + first_missing=1
//   ④ 重复 seq 内容冲突 → seq_conflict + 不重组
//   ⑤ seq 越界(5 / pb_num 4) → seq_oob + 不重组
//   ⑥ 跨帧污染回归:无 END 帧后紧跟完整帧,必须正常重组(旧实现整帧被废)
//   ⑦ 聚合帧乱序重排后 cascade 拆分与坏块剔除仍正确
//   ⑧ 树层 rel→raw:乱序重排后落在正确块(用 blocks[i].raw_offset 校验)
// 构帧坐标:南网 BPLC 表133 / SPLC 表47(4B 头,序列号 16bit LE);
//           国网 PB 头 1B(低 6 位序列号,bit7=END / bit6=START)。
#include <QCoreApplication>
#include <QByteArray>
#include <QVector>
#include <cstdio>
#include <cstring>

#include "pb_assembler.h"
#include "protocol_tree_builder.h"
#include "gw_2022_sof_parser.h"
#undef SOFPARSER_H   // 2022/2026 两个 SOF 头共用同一 guard(隐患,探针内绕开)
#include "gw_2026_sof_parser.h"
#include "fieldtools.h"
#include "crc.h"

static int g_fails = 0;
static void check(const char* name, bool ok) {
    std::printf("%-52s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) ++g_fails;
}

static void put_crc24(quint8* blk, int len) {
    const quint32 calc = crc24_lsb(blk, len);
    blk[len - 3] = quint8(calc & 0xFF);
    blk[len - 2] = quint8((calc >> 8) & 0xFF);
    blk[len - 1] = quint8((calc >> 16) & 0xFF);
}

/// 单块规格:序列号 + 体首字节填充值(用于识别拼接顺序)
struct BlkSpec {
    int seq;
    quint8 fill;
    bool agg = false;
    QByteArray body{};  ///< 非空时直接作为块体(聚合级联流用例)
};

/// 构帧:16B 控制头(留空,直接调 assembler)+ n × pb_size 块。
/// head_len=4 → 南网(byte0-1 序列号 16bit LE,byte2 bit0 聚合);head_len=1 → 国网。
static QByteArray build(const QVector<BlkSpec>& blks, int pb_size, int head_len,
                        int rsv, int crc, bool startend_flags) {
    QByteArray f(16 + blks.size() * pb_size, 0);
    const int body_len = pb_size - head_len - rsv - crc;
    for (int i = 0; i < blks.size(); ++i) {
        quint8* p = reinterpret_cast<quint8*>(f.data()) + 16 + i * pb_size;
        if (head_len == 4) {
            p[0] = quint8(blks[i].seq & 0xFF);
            p[1] = quint8((blks[i].seq >> 8) & 0x0F);   // 序列号高 4 位(12b 足够)
            p[2] = blks[i].agg ? 0x01 : 0x00;           // 表47 聚合标志 bit0
        } else {
            quint8 h = quint8(blks[i].seq & 0x3F);
            if (startend_flags) {
                if (i == 0) h |= 0x40;                   // START
                if (i == blks.size() - 1) h |= 0x80;     // END
            }
            p[0] = h;
        }
        if (!blks[i].body.isEmpty()) {
            const int n = qMin(body_len, blks[i].body.size());
            std::memcpy(p + head_len, blks[i].body.constData(), size_t(n));
        } else {
            std::memset(p + head_len, blks[i].fill, size_t(body_len));
        }
        put_crc24(p, pb_size);
    }
    return f;
}

static pb_asm::PbLayout nw_layout(int base) {
    pb_asm::PbLayout l{/*head*/4, /*rsv*/1, /*crc*/3, /*agg_byte*/2, /*agg_bit*/0, base};
    l.seq_byte = 0;      // 表133/表47:序列号 byte0 bit0-7 + byte1 bit0-7(LE)
    l.seq_mask = 0xFFFF;
    return l;
}
static pb_asm::PbLayout gw_layout(int base) {
    pb_asm::PbLayout l{/*head*/1, /*rsv*/0, /*crc*/3, /*agg_byte*/-1, /*agg_bit*/-1, base};
    l.seq_byte  = 0;     // PB 头低 6 位序列号
    l.seq_mask  = 0x3F;
    l.start_bit = 6;
    l.end_bit   = 7;
    return l;
}

/// 体流拼接序(取每块体首字节)
static QByteArray body_order(const QByteArray& body, int body_len) {
    QByteArray o;
    for (int off = 0; off + body_len <= body.size(); off += body_len)
        o.append(body.at(off));
    return o;
}

// ── ①/② 4 块乱序 0,2,1,3:v南网(SPLC/BPLC)与国网布局都按序列号重排 ──
static void test_reorder_core() {
    const int seq[4] = {0, 2, 1, 3};
    QVector<BlkSpec> blks;
    for (int i = 0; i < 4; ++i) blks.append({seq[i], quint8(seq[i]), false, {}});

    {   // 南网布局(表133/表47)
        const int pbsz = 72, hd = 4, rsv = 1, crc = 3;
        const QByteArray f = build(blks, pbsz, hd, rsv, crc, false);
        const pb_asm::AssembleResult r =
            pb_asm::assemble_pb_blocks(f, 4, pbsz, nw_layout(16));
        check("NW  : reassembly_ok", r.reassembly_ok);
        check("NW  : all_crc_ok", r.all_crc_ok);
        check("NW  : seq_reordered>0", r.seq_reordered > 0);
        const QByteArray ord = body_order(r.msdu_body, pbsz - hd - rsv - crc);
        check("NW  : body order == 0 1 2 3",
              ord.size() == 4 && quint8(ord[0]) == 0 && quint8(ord[1]) == 1
              && quint8(ord[2]) == 2 && quint8(ord[3]) == 3);
        // ⑧ 树层槽位:拼接序 1(块体起点 rel=64)应落在"到达序第 2 块"(seq=1)
        MpduInfo mp;
        mp.pb_num = 4;
        mp.pb_size = quint16(pbsz);
        for (const auto& b : r.blocks) mp.pb_heads.append(b.head_byte);
        // pb_heads 是拼接序;树层按到达序重建,这里换成到达序头字节
        mp.pb_heads.clear();
        for (int i = 0; i < 4; ++i) mp.pb_heads.append(quint8(seq[i] & 0xFF));
        const QVector<int> slot_tbl = tree_slot_raw_offsets(mp, 16, hd, 0xFF);
        check("tree: slot table built", slot_tbl.size() == 4);
        MsduRawMap m{};
        m.base = -1; m.pb_num = 4; m.pb_size = pbsz; m.fch_size = 16;
        m.header_len = hd; m.body = pbsz - hd - rsv - crc;
        m.slot_raw_offset = slot_tbl;
        const int blen = m.body;
        const int raw_b1 = tree_msdu_raw_of(m, blen, 4);       // 拼接序 1 = seq 1
        const int expect_b1 = 16 + 2 * pbsz + hd;               // 到达序 2(seq=1)
        check("tree: rel->raw hits seq-1 block", raw_b1 == expect_b1);
        const int raw_b2 = tree_msdu_raw_of(m, 2 * blen, 4);    // 拼接序 2 = seq 2
        const int expect_b2 = 16 + 1 * pbsz + hd;               // 到达序 1(seq=2)
        check("tree: rel->raw hits seq-2 block", raw_b2 == expect_b2);
    }
    {   // 国网布局
        const int pbsz = 72, hd = 1, rsv = 0, crc = 3;
        const QByteArray f = build(blks, pbsz, hd, rsv, crc, true);
        const pb_asm::AssembleResult r =
            pb_asm::assemble_pb_blocks(f, 4, pbsz, gw_layout(16));
        check("GW  : reassembly_ok", r.reassembly_ok);
        check("GW  : pb_head_flag_mismatch==0", r.pb_head_flag_mismatch == 0);
        const QByteArray ord = body_order(r.msdu_body, pbsz - hd - crc);
        check("GW  : body order == 0 1 2 3",
              ord.size() == 4 && quint8(ord[0]) == 0 && quint8(ord[1]) == 1
              && quint8(ord[2]) == 2 && quint8(ord[3]) == 3);
    }
}

// ── ③ 缺块:0,2,3(缺 1)──
static void test_missing() {
    const int pbsz = 72, hd = 4, rsv = 1, crc = 3;
    QVector<BlkSpec> blks{{0, 0}, {2, 2}, {3, 3}};   // 只发 3 块,声明 4 块
    const QByteArray f = build(blks, pbsz, hd, rsv, crc, false);
    const pb_asm::AssembleResult r =
        pb_asm::assemble_pb_blocks(f, 4, pbsz, nw_layout(16));
    check("miss: !reassembly_ok", !r.reassembly_ok);
    check("miss: missing_blocks==1", r.missing_blocks == 1);
    check("miss: first_missing==1", r.first_missing_slot == 1);
}

// ── ④ 重复 seq 内容冲突 / 内容一致 ──
static void test_dup() {
    const int pbsz = 72, hd = 4, rsv = 1, crc = 3;
    {   // 冲突:seq 0,1,1(内容不同),3
        QVector<BlkSpec> blks{{0, 0}, {1, 0x11}, {1, 0x22}, {3, 3}};
        const QByteArray f = build(blks, pbsz, hd, rsv, crc, false);
        const pb_asm::AssembleResult r =
            pb_asm::assemble_pb_blocks(f, 4, pbsz, nw_layout(16));
        check("dup : conflict detected", r.seq_conflict == 1);
        check("dup : !reassembly_ok", !r.reassembly_ok);
    }
    {   // 一致:seq 0,1,1(内容相同),3 → 容忍,可重组
        QVector<BlkSpec> blks{{0, 0}, {1, 0x11}, {1, 0x11}, {3, 3}};
        const QByteArray f = build(blks, pbsz, hd, rsv, crc, false);
        const pb_asm::AssembleResult r =
            pb_asm::assemble_pb_blocks(f, 4, pbsz, nw_layout(16));
        check("dup : identical tolerated (seq_dup==1)", r.seq_dup == 1);
        check("dup : missing slot 2 -> !reassembly_ok", !r.reassembly_ok);
        check("dup : missing_blocks==1", r.missing_blocks == 1);
    }
}

// ── ⑤ seq 越界 ──
static void test_oob() {
    const int pbsz = 72, hd = 4, rsv = 1, crc = 3;
    QVector<BlkSpec> blks{{0, 0}, {1, 1}, {2, 2}, {5, 5}};   // seq=5 越界(pb_num=4)
    const QByteArray f = build(blks, pbsz, hd, rsv, crc, false);
    const pb_asm::AssembleResult r =
        pb_asm::assemble_pb_blocks(f, 4, pbsz, nw_layout(16));
    check("oob : seq_oob==1", r.seq_oob == 1);
    check("oob : !reassembly_ok", !r.reassembly_ok);
}

// ── 兼容兜底:多块序列号全同(设备未填)不得判异常 ──
static void test_uniform() {
    const int pbsz = 72, hd = 4, rsv = 1, crc = 3;
    QVector<BlkSpec> blks{{0, 0xA}, {0, 0xB}, {0, 0xC}, {0, 0xD}};
    const QByteArray f = build(blks, pbsz, hd, rsv, crc, false);
    const pb_asm::AssembleResult r =
        pb_asm::assemble_pb_blocks(f, 4, pbsz, nw_layout(16));
    check("unif: seq_uniform_fallback", r.seq_uniform_fallback);
    check("unif: reassembly_ok(按位置拼接)", r.reassembly_ok);
    const QByteArray ord = body_order(r.msdu_body, pbsz - hd - rsv - crc);
    check("unif: body order preserved (A B C D)",
          ord.size() == 4 && quint8(ord[0]) == 0xA && quint8(ord[3]) == 0xD);
}

// ── ⑦ 聚合帧乱序:级联拆分按 seq 序 + 坏块剔除 ──
static QByteArray cascade_body(int len, char c, bool start, bool end) {
    QByteArray b(2, '\0');
    b[0] = char(quint8(len & 0xFF));
    b[1] = char(quint8(((len >> 8) & 0x0F) | (start ? 0x10 : 0) | (end ? 0x20 : 0)));
    b += QByteArray(len, c);
    return b;
}
static void test_aggregate() {
    const int pbsz = 72, hd = 4, rsv = 1, crc = 3;
    const int blen = pbsz - hd - rsv - crc;      // 64
    // 两块各承载一条级联记录,记录占满整块体(2B 级联头 + 62B 数据 = 64B),
    // 这样拼接后记录流连续,级联循环才能拆出 2 条(否则填充 0 会使 clen=0 提前终止)
    QByteArray b0 = cascade_body(blen - 2, 'A', true, false);
    QByteArray b1 = cascade_body(blen - 2, 'B', false, true);
    // 到达序 = seq 1, seq 0(乱序),两块均标记聚合
    QVector<BlkSpec> blks{{1, 0, true, b1}, {0, 0, true, b0}};
    const QByteArray f = build(blks, pbsz, hd, rsv, crc, false);

    {   // 好 CRC:重排后 cascade 顺序应为 A(seq0) → B(seq1)
        const pb_asm::AssembleResult r =
            pb_asm::assemble_pb_blocks(f, 2, pbsz, nw_layout(16));
        check("agg : reassembly_ok", r.reassembly_ok);
        check("agg : any_aggregated", r.any_aggregated);
        check("agg : cascade count == 2", r.cascade.size() == 2);
        check("agg : cascade[0] is 'A' (seq0)",
              r.cascade.size() == 2 && r.cascade[0].mac.size() == blen - 2
              && r.cascade[0].mac.at(0) == 'A');
        check("agg : cascade[1] is 'B' (seq1)",
              r.cascade.size() == 2 && r.cascade[1].mac.size() == blen - 2
              && r.cascade[1].mac.at(0) == 'B');
    }
    {   // 翻转到达序第 0 块(seq=1,承载 'B')的 CRC → 只剔除与坏块相交的记录
        QByteArray bad = f;
        bad[16 + pbsz - 1] = char(quint8(bad.at(16 + pbsz - 1)) ^ 0xFF);
        const pb_asm::AssembleResult r =
            pb_asm::assemble_pb_blocks(bad, 2, pbsz, nw_layout(16));
        check("agg : !all_crc_ok", !r.all_crc_ok);
        check("agg : cascade_crc_skipped==1", r.cascade_crc_skipped == 1);
        check("agg : kept only 'A'",
              r.cascade.size() == 1 && r.cascade[0].mac.size() == blen - 2
              && r.cascade[0].mac.at(0) == 'A');
    }
}

// ── ②/⑥ 解析器级:国网 2022/2026 乱序重排 + 跨帧污染回归 ──
static QByteArray gw2022_frame(const int* seqs, int n, bool end_on_last) {
    const int pbsz = 72;
    QByteArray f(16 + n * pbsz, 0);
    quint8* p = reinterpret_cast<quint8*>(f.data());
    p[0] = 0x01;                       // SOF
    set_bits(p, 4, 0, 12, 5);          // src TEI(表19)
    set_bits(p, 5, 4, 12, 0xFFF);      // dst TEI
    set_bits(p, 8, 0, 12, 100);        // 帧长
    set_bits(p, 9, 4, 4, n);           // PB 个数
    set_bits(p, 11, 4, 4, 13);         // TMI=13 → 72B
    for (int i = 0; i < n; ++i) {
        quint8* blk = p + 16 + i * pbsz;
        quint8 h = quint8(seqs[i] & 0x3F);
        if (i == 0) h |= 0x40;                          // START
        if (end_on_last && i == n - 1) h |= 0x80;       // END
        blk[0] = h;
        std::memset(blk + 1, quint8(seqs[i] & 0xFF), size_t(pbsz - 4));
        put_crc24(blk, pbsz);
    }
    return f;
}

static void test_parsers() {
    const int order[4] = {0, 1, 2, 3};
    const int shuf[4]  = {0, 2, 1, 3};
    const int blen = 72 - 1 - 3;        // 国网块体 68B

    {   // GW2022:乱序 → 重排为 0 1 2 3
        MpduInfo info; MsduState msdu; QByteArray cp;
        const QString err = gw_2022_sof::assemble(gw2022_frame(shuf, 4, true),
                                                  info, msdu, cp, 0, false);
        check("gw22: no error", err.isEmpty());
        check("gw22: reordered -> body 272B", cp.size() == 4 * blen);
        const QByteArray ord = body_order(cp, blen);
        check("gw22: body order == 0 1 2 3",
              ord.size() == 4 && quint8(ord[0]) == 0 && quint8(ord[3]) == 3);
        check("gw22: pb_crc_ok true", info.pb_crc_ok);
    }
    {   // ⑥ 跨帧污染:无 END 帧之后紧跟完整帧(同一 MsduState)
        MsduState shared;
        { MpduInfo i1; QByteArray c1;
          const QString e1 = gw_2022_sof::assemble(gw2022_frame(order, 4, false),
                                                   i1, shared, c1, 0, false);
          check("gw22: A(no END) tolerated", e1.isEmpty() && c1.size() == 4 * blen); }
        { MpduInfo i2; QByteArray c2;
          const QString e2 = gw_2022_sof::assemble(gw2022_frame(order, 4, true),
                                                   i2, shared, c2, 0, false);
          check("gw22: B after A reassembles (no pollution)",
                e2.isEmpty() && c2.size() == 4 * blen && i2.pb_crc_ok); }
    }
    {   // 缺块(声明 4 块,帧只含 3 块)→ 判异常/不重组
        MpduInfo info; MsduState msdu; QByteArray cp;
        QByteArray f = gw2022_frame(order, 3, true);
        set_bits(reinterpret_cast<quint8*>(f.data()), 9, 4, 4, 4);   // 声明 4 块
        const QString err = gw_2022_sof::assemble(f, info, msdu, cp, 0, false);
        check("gw22: declared 4 / actual 3 -> rejected", !err.isEmpty());
    }
}

// ── GW2026 解析器同款(分集拷贝模式 3 → 72B,表18)──
static QByteArray gw2026_frame(const int* seqs, int n) {
    const int pbsz = 72;
    QByteArray f(16 + n * pbsz, 0);
    quint8* p = reinterpret_cast<quint8*>(f.data());
    set_bits(p, 4, 0, 12, 5);          // src TEI(表7)
    set_bits(p, 5, 4, 12, 0xFFF);      // dst TEI
    set_bits(p, 7, 0, 3, 0);           // 帧子类型 0 = 数据帧
    set_bits(p, 8, 0, 12, 100);        // 帧长
    set_bits(p, 10, 1, 1, 0);          // 调制方式 0 = 分集拷贝
    set_bits(p, 10, 2, 5, 3);          // 分集拷贝模式 3 → 72B(表18)
    set_bits(p, 10, 7, 1, (n - 1) & 1);        // PB 个数 2b 编码
    set_bits(p, 11, 0, 1, ((n - 1) >> 1) & 1);
    set_bits(p, 11, 4, 3, 0);          // 频段 band0
    for (int i = 0; i < n; ++i) {
        quint8* blk = p + 16 + i * pbsz;
        quint8 h = quint8(seqs[i] & 0x3F);
        if (i == 0) h |= 0x40;
        if (i == n - 1) h |= 0x80;
        blk[0] = h;
        std::memset(blk + 1, quint8(seqs[i] & 0xFF), size_t(pbsz - 4));
        put_crc24(blk, pbsz);
    }
    return f;
}
static void test_parser_2026() {
    const int shuf[4] = {0, 2, 1, 3};
    const int blen = 72 - 1 - 3;
    MpduInfo info; MsduState msdu; QByteArray cp;
    const QString err = gw_2026_sof::assemble(gw2026_frame(shuf, 4),
                                              info, msdu, cp, 0, false);
    check("gw26: no error", err.isEmpty());
    check("gw26: reordered -> body 272B", cp.size() == 4 * blen);
    const QByteArray ord = body_order(cp, blen);
    check("gw26: body order == 0 1 2 3",
          ord.size() == 4 && quint8(ord[0]) == 0 && quint8(ord[3]) == 3);
    check("gw26: pb_crc_ok true", info.pb_crc_ok);
}

static void test_single_bad_crc_span_gate() {
    const int seqs[2] = {0, 1};
    const int pb_size = 72;
    const int body_len = pb_size - 1 - 3;
    const auto make_frame = [&](bool gw2026, int bad_block) {
        QByteArray f = gw2026 ? gw2026_frame(seqs, 2)
                              : gw2022_frame(seqs, 2, true);
        quint8* p = reinterpret_cast<quint8*>(f.data());
        quint8* body = p + 16 + 1;
        // 国网简头(体[0] 低 nibble = 0x01):len 在体[2..3] 低 11bit;
        // len=8 → span = 4+8+4 = 16B,完整落在 PB0 内的好块区间。
        // 注:这里必须用**国网**布局造体流——国网 span 门按国网口径算,
        // 用南网布局(0x04 + 16bit len)构造会两向都判错(见 pb-batch2-probe ⑫)。
        body[0] = 0x01;
        body[1] = 0;
        body[2] = 8;
        body[3] = 0;
        for (int i = 0; i < 2; ++i)
            put_crc24(p + 16 + i * pb_size, pb_size);
        p[16 + bad_block * pb_size + pb_size - 1] ^= 0x01;
        return f;
    };
    const auto run_case = [&](bool gw2026, int bad_block, bool expect_delivery,
                              const char* label) {
        MpduInfo info; MsduState msdu; QByteArray complete;
        const QByteArray f = make_frame(gw2026, bad_block);
        const QString err = gw2026
            ? gw_2026_sof::assemble(f, info, msdu, complete, 0, false)
            : gw_2022_sof::assemble(f, info, msdu, complete, 0, false);
        check(QString("%1: assemble succeeds").arg(label).toUtf8().constData(), err.isEmpty());
        check(QString("%1: bad CRC still marks frame").arg(label).toUtf8().constData(),
              !info.pb_crc_ok && info.pb_crc_oks.size() == 2
              && !info.pb_crc_oks[bad_block]);
        check(QString("%1: delivery follows good-span gate").arg(label).toUtf8().constData(),
              expect_delivery ? complete.size() == 2 * body_len : complete.isEmpty());
    };
    run_case(false, 0, false, "gw22: bad CRC intersects MSDU");
    run_case(false, 1, true,  "gw22: bad CRC after MSDU span");
    run_case(true,  0, false, "gw26: bad CRC intersects MSDU");
    run_case(true,  1, true,  "gw26: bad CRC after MSDU span");
}

// 乱序到达 + 坏 CRC：CRC 状态按线序回填，MSDU span 则按 seq 重组序判断。
static void test_out_of_order_bad_crc_span() {
    const int seqs[2] = {1, 0};             // seq1 先到，seq0 后到
    const int pb_size = 72;
    const int body_len = pb_size - 1 - 3;
    const int seq0_arrival = 1;
    const auto make_frame = [&](bool gw2026, int bad_arrival, int msdu_len) {
        QByteArray f = gw2026 ? gw2026_frame(seqs, 2)
                              : gw2022_frame(seqs, 2, true);
        quint8* p = reinterpret_cast<quint8*>(f.data());
        quint8* body = p + 16 + seq0_arrival * pb_size + 1;
        // 国网简头(体[0] 低 nibble = 0x01):len 在体[2..3] 低 11bit。
        // len=8 的 span 为 16B；len=68 的 76B span 跨入逻辑 seq1 块。
        body[0] = 0x01;
        body[1] = 0;
        body[2] = quint8(msdu_len & 0xFF);
        body[3] = quint8((msdu_len >> 8) & 0x07);
        for (int i = 0; i < 2; ++i)
            put_crc24(p + 16 + i * pb_size, pb_size);
        p[16 + bad_arrival * pb_size + pb_size - 1] ^= 0x01;
        return f;
    };
    const auto run_case = [&](bool gw2026, int bad_arrival, int msdu_len,
                              bool expect_delivery, const char* label) {
        MpduInfo info; MsduState msdu; QByteArray complete;
        const QByteArray f = make_frame(gw2026, bad_arrival, msdu_len);
        const QString err = gw2026
            ? gw_2026_sof::assemble(f, info, msdu, complete, 0, false)
            : gw_2022_sof::assemble(f, info, msdu, complete, 0, false);
        check(QString("%1: assemble succeeds").arg(label).toUtf8().constData(), err.isEmpty());
        check(QString("%1: CRC result stays in arrival order").arg(label).toUtf8().constData(),
              info.pb_crc_oks.size() == 2
              && !info.pb_crc_oks[bad_arrival]
              && info.pb_crc_oks[1 - bad_arrival]);
        check(QString("%1: gate follows seq-order span").arg(label).toUtf8().constData(),
              expect_delivery ? complete.size() == 2 * body_len : complete.isEmpty());
    };
    run_case(false, 0, 8,  true,  "gw22: seq1 bad, seq0 span good");
    run_case(false, 0, 68, false, "gw22: bad seq1 intersects span");
    run_case(false, 1, 8,  false, "gw22: seq0 span bad");
    run_case(true,  0, 8,  true,  "gw26: seq1 bad, seq0 span good");
    run_case(true,  0, 68, false, "gw26: bad seq1 intersects span");
    run_case(true,  1, 8,  false, "gw26: seq0 span bad");
}

// 首 MSDU span 门的多 MSDU 边界：坏块只落在后续 MSDU 时仍交付首条；
// 首 MSDU 自身跨坏块则整条重组流拒交，即使更后面的 MSDU 位于好块。
static void test_multiple_msdu_bad_crc_boundary() {
    const int pb_size = 72;
    const int body_len = pb_size - 1 - 3;
    const int seqs2[2] = {1, 0};          // seq1 先到，seq0 后到
    const int seqs3[3] = {2, 0, 1};       // 先 seq2，后 seq0、seq1
    const auto set_short_header = [](quint8* body, int off, int len) {
        body[off] = 0x01;                 // 国网简头:低 nibble = 0x01 → span = 4+len+4
        body[off + 1] = 0;
        body[off + 2] = quint8(len & 0xFF);
        body[off + 3] = quint8((len >> 8) & 0x07);
    };
    const auto run_case = [&](bool gw2026, bool first_crosses_bad,
                              const char* label) {
        const int n = first_crosses_bad ? 3 : 2;
        const int* seqs = first_crosses_bad ? seqs3 : seqs2;
        QByteArray f = gw2026 ? gw2026_frame(seqs, n)
                              : gw2022_frame(seqs, n, true);
        quint8* p = reinterpret_cast<quint8*>(f.data());
        quint8* seq0_body = p + 16 + 1 * pb_size + 1;
        if (first_crosses_bad) {
            set_short_header(seq0_body, 0, 68); // span=76，跨入坏 seq1
            quint8* later_good_body = p + 16 + 0 * pb_size + 1; // 逻辑 seq2
            set_short_header(later_good_body, 0, 8); // 后续 MSDU 在好块
        } else {
            set_short_header(seq0_body, 0, 8); // 首 span=16，只覆盖好 seq0
            set_short_header(seq0_body, 60, 8); // 后续 MSDU span 76..92 跨坏 seq1
        }
        for (int i = 0; i < n; ++i)
            put_crc24(p + 16 + i * pb_size, pb_size);
        const int bad_arrival = first_crosses_bad ? 2 : 0;
        p[16 + bad_arrival * pb_size + pb_size - 1] ^= 0x01;

        MpduInfo info; MsduState msdu; QByteArray complete;
        const QString err = gw2026
            ? gw_2026_sof::assemble(f, info, msdu, complete, 0, false)
            : gw_2022_sof::assemble(f, info, msdu, complete, 0, false);
        check(QString("%1: assemble succeeds").arg(label).toUtf8().constData(), err.isEmpty());
        check(QString("%1: bad block remains marked").arg(label).toUtf8().constData(),
              info.pb_crc_oks.size() == n && !info.pb_crc_oks[bad_arrival]
              && !info.pb_crc_ok);
        check(QString("%1: first-span policy").arg(label).toUtf8().constData(),
              first_crosses_bad ? complete.isEmpty()
                                : complete.size() == n * body_len);
    };
    run_case(false, false, "gw22: later MSDU crosses bad block");
    run_case(false, true,  "gw22: first bad, later good MSDU discarded");
    run_case(true,  false, "gw26: later MSDU crosses bad block");
    run_case(true,  true,  "gw26: first bad, later good MSDU discarded");
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    test_reorder_core();
    test_missing();
    test_dup();
    test_oob();
    test_uniform();
    test_aggregate();
    test_parsers();
    test_parser_2026();
    test_single_bad_crc_span_gate();
    test_out_of_order_bad_crc_span();
    test_multiple_msdu_bad_crc_boundary();
    std::printf("\nRESULT: %s (%d failures)\n",
                g_fails ? "FAILURES" : "ALL PASS", g_fails);
    return g_fails ? 1 : 0;
}
