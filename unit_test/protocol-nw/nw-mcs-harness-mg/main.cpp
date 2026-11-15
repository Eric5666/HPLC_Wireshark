// 渲染南网 NW_2021 RF 信标 / RF SOF / 载波 SOF / ACK 扩展 / COORD 字段树并断言关键行
// (MCS 表129 释义、PBLen、载波无 MCS/PBLen、ACK 保留段与序号、COORD 无线 RF Channel/Option)
// 退出码:0 全部断言通过,1 有失败
#include <QApplication>
#include <QTreeWidget>
#include <QStringList>
#include <cstdio>
#include "bplcframe.h"
#include "nw_2021_tree.h"

static QStringList g_lines;   // 当前段的 "名称 | 值"
static void dump(QTreeWidgetItem* it, int depth) {
    std::printf("%*s%s | %s\n", depth * 2, "", qPrintable(it->text(0)), qPrintable(it->text(1)));
    g_lines << it->text(0) + QStringLiteral(" | ") + it->text(1);
    for (int i = 0; i < it->childCount(); ++i) dump(it->child(i), depth + 1);
}
static int g_fails = 0;
static bool has_line(const QString& prefix) {
    for (const QString& l : g_lines) if (l.startsWith(prefix)) return true;
    return false;
}
/// present=true:须有以 prefix 开头的行;false:不得有
static void expect(const char* section, const QString& prefix, bool present = true) {
    const bool ok = has_line(prefix) == present;
    std::printf("  [%s] %s%-40s %s\n", section, present ? "" : "no ", qPrintable(prefix), ok ? "PASS" : "FAIL");
    if (!ok) ++g_fails;
}

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    NW_2021_TreeBuilder builder;
    // RF 信标:字节10 高4位 MCS=5,字节11 低4位 PBLen=3
    {
        PacketEntry e;
        e.meta.is_rf = 1;
        e.mpdu.frame_type = (quint8)NW_2021_FrameType::BEACON;
        e.mpdu.version = 1;
        e.mpdu.pblen = 3; e.mpdu.mcs = 5; e.mpdu.pb_size = 136;
        e.raw_bytes = QByteArray(16, 0);
        e.raw_bytes[10] = (char)0x50;
        e.raw_bytes[11] = (char)0x53;
        e.raw_bytes[12] = (char)0x19;
        QTreeWidget tw; auto* root = new QTreeWidgetItem(&tw);
        g_lines.clear();
        builder.build(root, e);
        std::printf("=== RF BEACON ===\n"); dump(root, 0);
        expect("RF BEACON", QStringLiteral("MCS [4b] | 5 - "));
        expect("RF BEACON", QStringLiteral("PBLen [4b] | 3"));
    }
    // RF SOF:字节7 低4位 MCS=2
    {
        PacketEntry e;
        e.meta.is_rf = 1;
        e.mpdu.frame_type = (quint8)NW_2021_FrameType::SOF;
        e.mpdu.version = 1;
        e.mpdu.pb_num = 1; e.mpdu.pblen = 3; e.mpdu.mcs = 2; e.mpdu.pb_size = 136; e.mpdu.frame_len = 7;
        e.mpdu.re_send_flag = true; e.mpdu.tmi_ext = 9;
        e.raw_bytes = QByteArray(16, 0);
        e.raw_bytes[7] = (char)0xF2;   // MCS=2,TEI过滤=1,重传=1,保留=3
        e.raw_bytes[10] = (char)0x3E;  // 保留区
        e.raw_bytes[11] = (char)0xEF;
        QTreeWidget tw; auto* root = new QTreeWidgetItem(&tw);
        g_lines.clear();
        builder.build(root, e);
        std::printf("=== RF SOF ===\n"); dump(root, 0);
        expect("RF SOF", QStringLiteral("PBLen [4b] | 3 - 136B"));
        expect("RF SOF", QStringLiteral("MCS [4b] | 2 - "));
    }

    // 载波 SOF:应走表16 字段集(无 MCS/PBLen)
    {
        PacketEntry e;
        e.meta.is_rf = 0;
        e.mpdu.frame_type = (quint8)NW_2021_FrameType::SOF;
        e.mpdu.version = 1;
        e.mpdu.pb_num = 1; e.mpdu.tmi = 3; e.mpdu.pb_size = 136; e.mpdu.frame_len = 9;
        e.mpdu.re_send_flag = true; e.mpdu.symbol_num = 123; e.mpdu.tmi_ext = 0;
        e.raw_bytes = QByteArray(16, 0);
        e.raw_bytes[10] = (char)0x60;
        QTreeWidget tw; auto* root = new QTreeWidgetItem(&tw);
        g_lines.clear();
        builder.build(root, e);
        std::printf("=== PLC SOF ===\n"); dump(root, 0);
        expect("PLC SOF", QStringLiteral("TMI [4b] | 3"));
        expect("PLC SOF", QStringLiteral("MCS "), false);
        expect("PLC SOF", QStringLiteral("PBLen "), false);
    }

    // ACK 网络搜索帧(表C-2):保留两段 + 序号
    {
        PacketEntry e;
        e.mpdu.frame_type = (quint8)NW_2021_FrameType::ACK;
        e.mpdu.version = 1;
        e.mpdu.ack_ext_type = 1;
        e.mpdu.ack_dst_addr = 0xAABBCCDDEEFFULL;
        e.mpdu.ack_search_tei = 0x123;
        e.raw_bytes = QByteArray(16, 0);
        e.raw_bytes[8] = (char)0xA0; e.raw_bytes[9] = (char)0x34;
        e.raw_bytes[10] = (char)0x12; e.raw_bytes[11] = (char)0x77;
        QTreeWidget tw; auto* root = new QTreeWidgetItem(&tw);
        g_lines.clear();
        builder.build(root, e);
        std::printf("=== ACK Search ===\n"); dump(root, 0);
        expect("ACK Search", QStringLiteral("Reserved [4b] | 0xa"));
        expect("ACK Search", QStringLiteral("Reserved [16b] | 0x1234"));
        expect("ACK Search", QStringLiteral("SeqNum [8b] | 119"));
    }
    // ACK 同步帧(表C-3):保留两段 + 序号
    {
        PacketEntry e;
        e.mpdu.frame_type = (quint8)NW_2021_FrameType::ACK;
        e.mpdu.version = 1;
        e.mpdu.ack_ext_type = 2;
        e.mpdu.ack_sync_timestamp = 0x11223344;
        e.mpdu.ack_sync_tei = 0x456;
        e.raw_bytes = QByteArray(16, 0);
        e.raw_bytes[6] = (char)0xB0; e.raw_bytes[7] = (char)0xEF;
        e.raw_bytes[8] = (char)0xBE; e.raw_bytes[9] = (char)0xAD;
        e.raw_bytes[10] = (char)0xDE; e.raw_bytes[11] = (char)0x42;
        QTreeWidget tw; auto* root = new QTreeWidgetItem(&tw);
        g_lines.clear();
        builder.build(root, e);
        std::printf("=== ACK Sync ===\n"); dump(root, 0);
        expect("ACK Sync", QStringLiteral("SyncTEI [12b] | 1110"));
        expect("ACK Sync", QStringLiteral("Reserved [32b] | 0xdeadbeef"));
        expect("ACK Sync", QStringLiteral("SeqNum [8b] | 66"));
    }
    // COORD 无线(表127):RF Channel / RF Option
    {
        PacketEntry e;
        e.meta.is_rf = 1;
        e.mpdu.frame_type = (quint8)NW_2021_FrameType::COORD;
        e.mpdu.version = 1;
        e.mpdu.coord_neighbour_nid = 0x0003;
        e.mpdu.coord_duration = 25;
        e.mpdu.coord_band_end_flag = 1;
        e.mpdu.coord_rsv3 = 0x2D;
        e.mpdu.coord_band_end_offset = 100;
        e.mpdu.coord_band_start_offset = 200;
        e.raw_bytes = QByteArray(16, 0);
        e.raw_bytes[3] = (char)0x07;
        QTreeWidget tw; auto* root = new QTreeWidgetItem(&tw);
        g_lines.clear();
        builder.build(root, e);
        std::printf("=== COORD RF ===\n"); dump(root, 0);
        expect("COORD RF", QStringLiteral("RF Channel [8b] | 7"));
        expect("COORD RF", QStringLiteral("RF Option [2b] | 1"));
    }
    // COORD 载波(表22):同位置应为 RSV / RSV3
    {
        PacketEntry e;
        e.meta.is_rf = 0;
        e.mpdu.frame_type = (quint8)NW_2021_FrameType::COORD;
        e.mpdu.version = 1;
        e.mpdu.coord_neighbour_nid = 0x0003;
        e.mpdu.coord_duration = 25;
        e.mpdu.coord_band_end_flag = 1;
        e.mpdu.coord_rsv3 = 0x2D;
        e.mpdu.coord_band_end_offset = 100;
        e.mpdu.coord_band_start_offset = 200;
        e.raw_bytes = QByteArray(16, 0);
        e.raw_bytes[3] = (char)0x07;
        QTreeWidget tw; auto* root = new QTreeWidgetItem(&tw);
        g_lines.clear();
        builder.build(root, e);
        std::printf("=== COORD PLC ===\n"); dump(root, 0);
        expect("COORD PLC", QStringLiteral("RSV [8b] | 0x07"));
        expect("COORD PLC", QStringLiteral("RSV3 [6b] | 0x2d"));
        expect("COORD PLC", QStringLiteral("RF Channel "), false);
    }
    std::printf("RESULT: %s (%d failures)\n", g_fails ? "FAIL" : "ALL PASS", g_fails);
    return g_fails ? 1 : 0;
}
