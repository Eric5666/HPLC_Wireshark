// 渲染 GW_2022 RF SOF 字段树,打印并断言 MCS/Payload PB Size/Frame Length/Reserved 行
// 退出码:0 全部断言通过,1 有失败
#include <QApplication>
#include <QTreeWidget>
#include <QStringList>
#include <cstdio>
#include "bplcframe.h"
#include "gw_2022_tree.h"
#include "gw_2022_parser.h"

static QStringList g_lines;   // "名称 | 值",供断言
static void dump(QTreeWidgetItem* it, int depth) {
    std::printf("%*s%s | %s\n", depth * 2, "", qPrintable(it->text(0)), qPrintable(it->text(1)));
    g_lines << it->text(0) + QStringLiteral(" | ") + it->text(1);
    for (int i = 0; i < it->childCount(); ++i) dump(it->child(i), depth + 1);
}
static int g_fails = 0;
/// 断言存在一行以 prefix 开头(名称 + " | " + 值的前缀)
static void expect_line(const QString& prefix) {
    bool ok = false;
    for (const QString& l : g_lines) if (l.startsWith(prefix)) { ok = true; break; }
    std::printf("  %-44s %s\n", qPrintable(prefix), ok ? "PASS" : "FAIL");
    if (!ok) ++g_fails;
}

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    PacketEntry e;
    e.meta.is_rf = 1;
    e.mpdu.frame_type = (quint8)GW_2022_FrameType::SOF;
    e.mpdu.version = 1;
    e.mpdu.src_tei = 1; e.mpdu.dst_tei = 2; e.mpdu.link_id = 0;
    e.mpdu.frame_len = 0x100;
    e.mpdu.pb_num = 1; e.mpdu.pb_num_field = 3;      // 大小码 3 -> 136B
    e.mpdu.symbol_num = 0x1AB;                        // 保留原始值
    // 无线 SOF 字节11 bit4-7 = MCS(表28),解析器存 mpdu.mcs、树按 is_rf 读 mcs(tmi 只用于载波)。
    // 原 harness 写 e.mpdu.tmi = 7,树里 MCS 恒显示 0(归集前的旧字段口径)
    e.mpdu.mcs = 5;
    e.mpdu.tmi_ext = 5;                               // 保留原始值
    e.mpdu.pb_size = 136;
    QTreeWidget tw;
    auto* root = new QTreeWidgetItem(&tw);
    GW_2022_TreeBuilder builder; builder.build(root, e);
    dump(root, 0);
    std::printf("--- checks ---\n");
    expect_line(QStringLiteral("Frame Length [12b] | 256"));
    expect_line(QStringLiteral("Payload PB Size [4b] | 3 - 136B"));
    expect_line(QStringLiteral("Reserved [9b] | 427"));      // 0x1AB 保留原始值
    expect_line(QStringLiteral("MCS [4b] | 5 - "));
    expect_line(QStringLiteral("Reserved [4b] | 5"));        // 字节12 bit0-3 保留原始值
    expect_line(QStringLiteral("PB Size | 136"));
    std::printf("RESULT: %s (%d failures)\n", g_fails ? "FAIL" : "ALL PASS", g_fails);
    return g_fails ? 1 : 0;
}
