// L7(a) 探针:分集拷贝模式表逐项断言 + (频段 × 模式) 最大 PB 块数门断言。
// 不依赖 Qt 库,仅需 QtGlobal 类型头。
//
// 期望来源:gw_2026_pb_num_table（用户 2026-11 核对确认，权威，勿改）
//   旧期望 old_gate[4][15] 是用户 2026-10-28 的早期版本（4 频段 × 15 模式），已被取代
//   规约侧参考:HDC2.0 第4-1部分 5.1.9.7 表18「分集拷贝模式」只给"模式→物理块类型(字节)/分集次数/
//   调制/码率"，表下附注「子频段物理块数应不大于4，且同时保证载荷符号数不超过511」，
//   不含 band×mode 矩阵；该矩阵的权威性由用户裁决承担，故本探针按产品表逐格抄写，
//   且**不得**反过来修改 gw_2026_pb_table.h 去凑期望（那是自证）。
#include "gw_2026_pb_table.h"
#include <cstdio>

int main() {
    // 表18(印刷页 25-26):模式 0-28 → 物理块类型(字节)
    static const int expect[29] = {
        520, 264, 136, 72,  520, 264, 136, 72,  520, 264, 136, 72,  520, 264, 136,
        72,  520, 264, 136, 72,  520, 264, 136, 72,  520, 264, 136, 72,  520
    };
    int fail = 0;
    for (int m = 0; m <= 28; ++m) {
        int got = gw_2026_diversity_pb_size((quint8)m);
        if (got != expect[m]) { std::printf("FAIL mode %d: got %d expect %d\n", m, got, expect[m]); ++fail; }
    }
    if (gw_2026_diversity_pb_size(29) != -1) { std::puts("FAIL mode 29 should be -1"); ++fail; }
    if (gw_2026_diversity_pb_size(31) != -1) { std::puts("FAIL mode 31 should be -1"); ++fail; }

    // ---------------------------------------------------------------------
    // (频段 × 模式) → 最大 PB 块数：7 频段(0-6) × 29 模式(0-28)
    // 逐格抄自 gw_2026_pb_num_table（用户 2026-11 核对确认，权威，勿改）
    // ---------------------------------------------------------------------
    static const quint8 expect_gate[7][29] = {
        // mode:0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28
        { 1, 3, 4, 4, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 }, // band0
        { 0, 1, 2, 4, 1, 2, 4, 4, 2, 4, 4, 4, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 }, // band1
        { 0, 0, 1, 2, 0, 1, 2, 4, 1, 2, 4, 4, 2, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 }, // band2
        { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, // band3(保留)
        { 0, 1, 3, 4, 1, 3, 4, 4, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 }, // band4
        { 2, 4, 4, 4, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 }, // band5
        { 1, 2, 4, 4, 2, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 }, // band6
    };
    for (int b = 0; b < 7; ++b)
        for (int m = 0; m <= 28; ++m)
            if (gw_2026_max_pb_num((quint8)b, (quint8)m) != expect_gate[b][m]) {
                std::printf("FAIL gate band %d mode %d: got %d expect %d\n",
                            b, m, gw_2026_max_pb_num((quint8)b, (quint8)m), expect_gate[b][m]);
                ++fail;
            }

    // band3 = 表19「频段3 保留」⇒ 全 0(单列一条断言,便于定位)
    {
        int nz = 0;
        for (int m = 0; m <= 28; ++m)
            if (gw_2026_max_pb_num(3, (quint8)m) != 0) {
                std::printf("FAIL band3 not 0 at mode %d: got %d\n",
                            m, gw_2026_max_pb_num(3, (quint8)m));
                ++nz; ++fail;
            }
        if (nz == 0) std::puts("PASS band3 all-zero (29 modes)");
    }

    // 边界:频段 7 越界(表仅 0-6);模式 29/31 保留
    if (gw_2026_max_pb_num(7, 0) != -1)  { std::puts("FAIL gate band 7 should be -1"); ++fail; }
    if (gw_2026_max_pb_num(0, 29) != -1) { std::puts("FAIL gate mode 29 should be -1"); ++fail; }
    if (gw_2026_max_pb_num(0, 31) != -1) { std::puts("FAIL gate mode 31 should be -1"); ++fail; }
    // 频段 4 由旧表的"越界"变为合法(表已扩到 0-6)
    if (gw_2026_max_pb_num(4, 0) == -1)  { std::puts("FAIL gate band 4 should be valid now"); ++fail; }

    // 旧行为对照(锚点,不参与期望):旧 TMI 表仅 0/2/6/8 四模式与表18 一致
    static const int old_tmi[15] = {520,520,136,136,136,136,136,520,520,520,520,264,264,72,72};
    int same = 0;
    for (int m = 0; m <= 14; ++m) if (old_tmi[m] == expect[m]) ++same;
    std::printf("old-table matches new-table on %d/15 modes (expect 4: 0/2/6/8)\n", same);
    if (same != 4) ++fail;

    // 历史对照(仅打印,不断言):用户 2026-10-28 早期表 4 频段 × 15 模式,已被 expect_gate 取代
    static const quint8 old_gate[4][15] = {
        { 4, 4, 4, 4, 4, 4, 4, 3, 4, 4, 4, 4, 4, 4, 4 },
        { 3, 4, 4, 2, 4, 4, 4, 1, 1, 2, 3, 4, 2, 4, 4 },
        { 2, 4, 4, 1, 2, 3, 4, 0, 1, 1, 2, 2, 1, 4, 4 },
        { 1, 2, 3, 0, 1, 1, 2, 0, 0, 0, 1, 1, 0, 4, 2 },
    };
    int still = 0;
    for (int b = 0; b < 4; ++b)
        for (int m = 0; m <= 14; ++m)
            if (expect_gate[b][m] == old_gate[b][m]) ++still;
    std::printf("legacy 2026-10-28 table still matches %d/60 cells (info only)\n", still);

    std::printf(fail ? "PROBE FAIL (%d)\n" : "PROBE PASS\n", fail);
    return fail ? 1 : 0;
}
