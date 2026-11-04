// verify_rfdl_bitmap.cpp — 单跳帧 RFDL 位图版邻居信道信息(接收发现列表位图)字段树核查
// @details 构造 RFDL(单跳 MSDU):STA MAC + Seq + IE[type=3 位图版]:
//   组合类型=0(8b 接收率) + StartTEI=8 + 位图2B(bit0/2/5 置位→3 邻居)
//   + 3 条邻居条目(各 8bit 接收率)
// 断言字段树包含:Group 分组(StartTEI)、位图原始字节、逐邻居 TEI 推导、接收率
#include "bplcframe.h"
#include "gw_2026_msdu_parser.h"
#include <QCoreApplication>
#include <functional>
#include <string>
#include <cstdio>

static void dump(const QVector<MsduFieldNode>& ns, int depth) {
    for (const auto& n : ns) {
        std::printf("%*s%s = %s\n", depth * 2, "",
                    qPrintable(n.name), qPrintable(n.value));
        dump(n.children, depth + 1);
    }
}

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);

    // ── 构造 RFDL 载荷 ──
    QByteArray rfdl;
    rfdl.append(char(0x34)); rfdl.append(char(0x5A)); rfdl.append(char(0x11));
    rfdl.append(char(0x22)); rfdl.append(char(0x33)); rfdl.append(char(0x44));
    rfdl.append(char(0x09));            // 统计序号
    // IE[type=3 位图版]:头 1B(类型3|长度类型0) + 长度 1B + 内容
    QByteArray ie;
    ie.append(char(0x00));              // 组合类型 0 = 8bit 接收率(表137 combo 0)
    ie.append(char(0x08)); ie.append(char(0x00));  // StartTEI=8(12b LE)
    ie.append(char(0x01));              // 位图大小 = 1B(表76 位图[k]大小)
    ie.append(char(0x25));              // 位图: bit0/2/5 置位 → 3 个邻居(TEI 8/10/13)
    ie.append(char(90));                // Neighbor0: TEI=8  接收率 90%
    ie.append(char(75));                // Neighbor1: TEI=10 接收率 75%
    ie.append(char(60));                // Neighbor2: TEI=13 接收率 60%
    rfdl.append(char(0x03));            // IE 头:类型3(bit0-6)|长度类型0(bit7)
    rfdl.append(char(ie.size()));       // 长度 1B
    rfdl += ie;

    // 单跳头 4B:版本=1 / 消息类型=0(RFDL) / 长度 11bit
    QByteArray msdu(4, char(0));
    msdu[0] = 0x01;
    msdu[1] = 0x00;
    msdu[2] = char(rfdl.size() & 0xFF);
    msdu[3] = char((rfdl.size() >> 8) & 0x07);
    msdu += rfdl;

    const auto r = GW_2026_MsduParser::parse(msdu);
    std::printf("present=%d simple=%d summary=[%s]\n--- 字段树 ---\n",
                r.present, r.simple_head, qPrintable(r.summary));
    dump(r.tree, 0);

    // ── 断言 ──
    int fails = 0;
    auto expect = [&](bool ok, const char* what) {
        std::printf("  [%s] %s\n", ok ? "OK" : "FAIL", what);
        if (!ok) ++fails;
    };
    QString all;
    std::function<void(const QVector<MsduFieldNode>&)> collect =
        [&](const QVector<MsduFieldNode>& ns) {
        for (const auto& n : ns) {
            all += n.name + QLatin1Char('=') + n.value + QLatin1Char('\n');
            collect(n.children);
        }
    };
    collect(r.tree);

    expect(all.contains(QStringLiteral("Neighbor Ch Bitmap")), "IE 类型3 分组存在");
    expect(all.contains(QStringLiteral("StartTEI=8")), "位图组起始 TEI=8");
    expect(all.contains(QStringLiteral("0x25")), "位图原始字节 0x25 可见");
    expect(all.contains(QStringLiteral("RcvRate")) &&
           all.contains(QStringLiteral("90 (90%)")), "邻居接收率 8b→% 换算(90)");
    int neigh = all.count(QStringLiteral("Neighbor["));
    expect(neigh >= 3,
           (QStringLiteral("3 个置位 TEI 各一条邻居条目(实际 %1)").arg(neigh)).toStdString().c_str());

    // ══ 用例2:截断防护(P1)——位图声明 3 个置位但条目只有 1 个 ══
    {
        QByteArray r2;
        r2.append(char(0x34)); r2.append(char(0x5A)); r2.append(char(0x11));
        r2.append(char(0x22)); r2.append(char(0x33)); r2.append(char(0x44));
        r2.append(char(0x01));
        QByteArray ie2;
        ie2.append(char(0x00));             // combo 0 = 8b 接收率
        ie2.append(char(0x08)); ie2.append(char(0x00));
        ie2.append(char(0x01));             // 位图大小 1B
        ie2.append(char(0x07));             // bit0/1/2 置位 → nk=3,但只给 1 条条目
        ie2.append(char(80));               // 仅 1 条条目
        r2.append(char(0x03)); r2.append(char(ie2.size())); r2 += ie2;
        QByteArray m2(4, char(0));
        m2[0] = 0x01; m2[1] = 0x00;
        m2[2] = char(r2.size() & 0xFF); m2[3] = char((r2.size() >> 8) & 0x07);
        m2 += r2;
        const auto r = GW_2026_MsduParser::parse(m2);
        int n2 = 0;
        std::function<void(const QVector<MsduFieldNode>&)> c2 =
            [&](const QVector<MsduFieldNode>& ns) {
            for (const auto& n : ns) { n2 += n.name.count(QStringLiteral("Neighbor[")); c2(n.children); }
        };
        c2(r.tree);
        std::printf("用例2 截断防护: nk=3 实际条目=%d(应为 1,不越界不崩溃)\n", n2);
        expect(n2 == 1, "位图 nk 虚大时按实际内容截停(条目=1)");
    }

    // ══ 用例3:type=2 载波发现列表(表62/68/77)——BRU 变体 combo10/11 ══
    {
        QByteArray r3;
        r3.append(char(0x34)); r3.append(char(0x5A)); r3.append(char(0x11));
        r3.append(char(0x22)); r3.append(char(0x33)); r3.append(char(0x44));
        r3.append(char(0x02));
        // IE[type=2 非位图,combo=10]:TEI12+BRUSNR32(表68 combo10)
        // 位流布局:combo 1B + TEI 12b(byte1 全 + byte2 低半) → BRU 自 byte2 高半 nibble 起,
        // nibble 序(BRU0..7)=1,2,3,4,5,6,7,8 → dB = -7,-4,-1,2,5,8,11,14
        QByteArray ieA;
        ieA.append(char(0x0A));                       // combo 10
        ieA.append(char(0x14)); ieA.append(char(0x10));  // TEI=20(12b:0x14+byte2低半0);byte2 高半=BRU0=1
        ieA.append(char(0x32));                       // byte3: BRU1=2|BRU2=3<<4
        ieA.append(char(0x54));                       // byte4: BRU3=4|BRU4=5<<4
        ieA.append(char(0x76));                       // byte5: BRU5=6|BRU6=7<<4
        ieA.append(char(0x08));                       // byte6 低半=BRU7=8,高半=保留 0
        r3.append(char(0x02)); r3.append(char(ieA.size())); r3 += ieA;
        // IE[type=3 位图,combo=11]:BRUSNR32(表77 combo11);条目自位图后字节对齐起,
        // nibble 序(BRU0..7)=0..7 → dB = -10,-7,-4,-1,2,5,8,11
        QByteArray ieB;
        ieB.append(char(0x0B));                       // combo 11
        ieB.append(char(0x30)); ieB.append(char(0x00));  // StartTEI=48(12b LE)
        ieB.append(char(0x01));                       // 位图大小 1B
        ieB.append(char(0x01));                       // bit0 置位 → 1 邻居(TEI=48)
        ieB.append(char(0x10)); ieB.append(char(0x32));  // BRU0..3 = 0,1,2,3
        ieB.append(char(0x54)); ieB.append(char(0x76));  // BRU4..7 = 4,5,6,7
        r3.append(char(0x03)); r3.append(char(ieB.size())); r3 += ieB;
        QByteArray m3(4, char(0));
        m3[0] = 0x01; m3[1] = 0x02;                   // 消息类型 2 = 载波发现列表
        m3[2] = char(r3.size() & 0xFF); m3[3] = char((r3.size() >> 8) & 0x07);
        m3 += r3;
        const auto r = GW_2026_MsduParser::parse(m3);
        std::printf("用例3 载波发现列表: summary=[%s]\n", qPrintable(r.summary));
        dump(r.tree, 1);
        QString a3;
        std::function<void(const QVector<MsduFieldNode>&)> c3 =
            [&](const QVector<MsduFieldNode>& ns) {
            for (const auto& n : ns) { a3 += n.name + '=' + n.value + '\n'; c3(n.children); }
        };
        c3(r.tree);
        // 0x01234567 → BRU0=7→11dB, BRU1=6→8, BRU2=5→5, BRU3=4→2, BRU4=3→-1, BRU5=2→-4, BRU6=1→-7, BRU7=0→-10
        expect(a3.contains(QStringLiteral("Carrier Discovery List")),
               "消息类型2 摘要=载波发现列表");
        expect(a3.contains(QStringLiteral("BRUSNR")), "BRU 变体字段渲染(表68 combo10/表77 combo11)");
        expect(a3.contains(QStringLiteral("-7,-4,-1,2,5,8,11,14")),
               "表64 dB 换算 combo10 非位图 BRU0..7 = 1..8 → -7,-4,-1,2,5,8,11,14");
        expect(a3.contains(QStringLiteral("-10,-7,-4,-1,2,5,8,11")),
               "表64 dB 换算 combo11 位图 BRU0..7 = 0..7 → -10,-7,-4,-1,2,5,8,11");
    }

    // ══ 用例4:type=1 信道评估参数更新(表106-108) ══
    {
        QByteArray body4;
        // flag(1b LSB)+len(7b):flag=1, len=5 → byte0 = 1 | (5<<1) = 0x0B;
        // SAT 配置 5B(表106 固定头 2B) = [SAT ID=1|模式=0|组大小=01→0x05] + [TMI=1|增益=2→0x21] + 段数1B + 段位图 2B
        body4.append(char(0x0B));
        const quint32 bru = 0x76543210;      // BRU0=0→-10dB ... BRU7=7→11dB
        for (int b = 3; b >= 0; --b) body4.append(char((bru >> (8 * b)) & 0xFF));
        body4.append(char(0x05));            // SAT ID=1(bit0),模式=0(bit1),组大小=1(bits2-3,6个/组)
        body4.append(char(0x21));            // TMI=1(bits0-3), 增益=2(bits4-7)
        body4.append(char(0x01));            // 段个数=1 → 2 段
        body4.append(char(0xAA)); body4.append(char(0x55));  // 段位图 2B
        QByteArray m4(4, char(0));
        m4[0] = 0x01; m4[1] = 0x01;          // 消息类型 1 = 信道评估参数更新
        m4[2] = char(body4.size() & 0xFF); m4[3] = 0;
        m4 += body4;
        const auto r = GW_2026_MsduParser::parse(m4);
        std::printf("用例4 信道评估: summary=[%s]\n", qPrintable(r.summary));
        dump(r.tree, 1);
        QString a4;
        std::function<void(const QVector<MsduFieldNode>&)> c4 =
            [&](const QVector<MsduFieldNode>& ns) {
            for (const auto& n : ns) { a4 += n.name + '=' + n.value + '\n'; c4(n.children); }
        };
        c4(r.tree);
        expect(a4.contains(QStringLiteral("Channel Eval Param")), "消息类型1 分组渲染");
        expect(a4.contains(QStringLiteral("BRU SNR")), "BRU SNR 信息表(表64)渲染");
        expect(a4.contains(QStringLiteral("SAT Config")), "SAT 配置渲染");
        expect(a4.contains(QStringLiteral("Subcarrier Select")), "子载波选择表(表107)渲染");
    }

    std::printf("\n%s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 2;
}
