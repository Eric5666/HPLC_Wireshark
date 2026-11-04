// NW_2026 OFDMA 类型1 断言测试(trigger 上下文 / UL-OFDMA 数据 / DL-SACK /
// 无上下文 / 高位 SNID 分桶隔离 / eFC CRC 损坏不记录上下文)
//
// 前置:测试帧由 wireshark_support_plugins/build_nw2026_ul_ofdma.py 生成;
// 仓库 .gitignore 不收 *.bin(数据集一律由脚本确定性重建),跑测试前先跑脚本。
#include <QCoreApplication>
#include <QFile>
#include <cstdio>
#include "bplcframe.h"
#include "nw_2026_parser.h"

static int fails = 0;
static void check(bool ok, const char* what) {
    if (!ok) { printf("FAIL: %s\n", what); ++fails; }
    else printf("OK:   %s\n", what);
}

static BplcFrame load(const char* fn) {
    QFile f(QString::fromLocal8Bit(fn));
    if (!f.open(QIODevice::ReadOnly)) {
        // 测试帧由 wireshark_support_plugins/build_nw2026_ul_ofdma.py 生成,不入库
        // (仓库政策:数据集一律由脚本确定性重建);缺文件时明示原因,不要静默按空帧跑
        printf("FAIL: cannot open %s (regenerate with build_nw2026_ul_ofdma.py)\n", fn);
        exit(2);
    }
    QByteArray bin = f.readAll();
    BplcFrame fr;
    fr.data = QByteArray(1, '\x00') + bin;   // isRF=0 前缀 + MPDU(FCH byte0 起)
    fr.meta.from_raw = true;
    fr.meta.has_time_tag = false;
    return fr;
}

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    MsduState msdu;
    NW_2026_Parser::Filter flt;

    // 同一实例:trigger 先喂建立上下文
    NW_2026_Parser parser;
    auto rt = parser.parse(load("wireshark_support_plugins/nw2026_trigger.bin"), msdu, flt);
    check(rt.accept && rt.mpdu.pb_num == 0 && rt.mpdu.pb_size == 0, "trigger pb_num=0 pb_size=0");
    check(rt.mpdu.src_tei == 1 && rt.mpdu.dst_tei == 0xFFF, "trigger src=1 dst=0xFFF");

    auto ru = parser.parse(load("wireshark_support_plugins/nw2026_ul_ofdma_data.bin"), msdu, flt);
    check(ru.mpdu.sof_stations.size() == 2, "ul_data sof_stations=2");
    if (ru.mpdu.sof_stations.size() == 2) {
        const auto& s0 = ru.mpdu.sof_stations[0];
        const auto& s1 = ru.mpdu.sof_stations[1];
        check(s0.tei == 2 && s0.pb_num == 1 && s0.pb_size == 136 && s0.block_base == 16, "ul_data sta0 tei=2 1x136@16");
        check(s0.pb_crc_oks.size() == 1 && s0.pb_crc_oks[0], "ul_data sta0 crc=[true]");
        check(s1.tei == 3 && s1.pb_num == 2 && s1.pb_size == 72 && s1.block_base == 152, "ul_data sta1 tei=3 2x72@152");
        check(s1.pb_crc_oks.size() == 2 && s1.pb_crc_oks[0] && s1.pb_crc_oks[1], "ul_data sta1 crc=[true,true]");
    }

    auto rs = parser.parse(load("wireshark_support_plugins/nw2026_dl_sack.bin"), msdu, flt);
    check(rs.mpdu.sof_stations.size() == 1, "dl_sack sof_stations=1");
    if (rs.mpdu.sof_stations.size() == 1) {
        const auto& s0 = rs.mpdu.sof_stations[0];
        check(s0.tei == 2 && s0.pb_num == 1 && s0.pb_size == 16 && s0.block_base == 16, "dl_sack tei=2 1x16@16");
        check(s0.pb_crc_oks.size() == 1 && s0.pb_crc_oks[0], "dl_sack crc=[true]");
        check(s0.msdu.size() == 8, "dl_sack msdu 8B");
    }

    {   // 无上下文:新 parser 只喂 ul_data
        NW_2026_Parser p2;
        auto r = p2.parse(load("wireshark_support_plugins/nw2026_ul_ofdma_data.bin"), msdu, flt);
        check(r.mpdu.pb_num == 0 && r.mpdu.sof_stations.isEmpty(), "nocontext pb_num=0 sof_stations=0");
        check(r.msdu.present && r.msdu.summary.contains(QStringLiteral("需 trigger")), "nocontext summary 含「需 trigger」");
    }

    {   // 高位 SNID:同布局、byte12 bit0=1(完整 SNID 0x10),站 TEI 4/5
        NW_2026_Parser p3;
        auto rt3 = p3.parse(load("wireshark_support_plugins/nw2026_trigger_hisnid.bin"), msdu, flt);
        check(rt3.accept && rt3.mpdu.pb_num == 0, "trigger_hi accept pb_num=0");
        auto ru3 = p3.parse(load("wireshark_support_plugins/nw2026_ul_ofdma_data_hisnid.bin"), msdu, flt);
        check(ru3.mpdu.sof_stations.size() == 2, "ul_hi sof_stations=2");
        if (ru3.mpdu.sof_stations.size() == 2) {
            const auto& s0 = ru3.mpdu.sof_stations[0];
            const auto& s1 = ru3.mpdu.sof_stations[1];
            check(s0.tei == 4 && s0.pb_num == 1 && s0.pb_size == 136 && s0.block_base == 16, "ul_hi sta0 tei=4 1x136@16");
            check(s0.pb_crc_oks.size() == 1 && s0.pb_crc_oks[0], "ul_hi sta0 crc=[true]");
            check(s1.tei == 5 && s1.pb_num == 2 && s1.pb_size == 72 && s1.block_base == 152, "ul_hi sta1 tei=5 2x72@152");
            check(s1.pb_crc_oks.size() == 2 && s1.pb_crc_oks[0] && s1.pb_crc_oks[1], "ul_hi sta1 crc=[true,true]");
        }
    }

    {   // 分桶隔离:低位 SNID trigger 不能服务高位 SNID UL 帧(完整 5bit 键)
        NW_2026_Parser p4;
        p4.parse(load("wireshark_support_plugins/nw2026_trigger.bin"), msdu, flt);
        auto r = p4.parse(load("wireshark_support_plugins/nw2026_ul_ofdma_data_hisnid.bin"), msdu, flt);
        check(r.mpdu.sof_stations.isEmpty(), "xsnid low-trigger does not serve hi-ul");
        check(r.msdu.present && r.msdu.summary.contains(QStringLiteral("需 trigger")), "xsnid summary 含「需 trigger」");
    }

    {   // 单站 16B UL 数据(MsgID!=0):与 DL-SACK 同长,必须走 UL 路径而非 SACK 路径
        NW_2026_Parser p6;
        p6.parse(load("wireshark_support_plugins/nw2026_trigger_tmi26.bin"), msdu, flt);
        auto r = p6.parse(load("wireshark_support_plugins/nw2026_ul_single16.bin"), msdu, flt);
        check(r.mpdu.sof_stations.size() == 1, "ul16 sof_stations=1");
        if (r.mpdu.sof_stations.size() == 1) {
            const auto& s0 = r.mpdu.sof_stations[0];
            check(s0.tei == 6 && s0.pb_num == 1 && s0.pb_size == 16 && s0.block_base == 16, "ul16 sta0 tei=6 1x16@16");
            check(s0.pb_crc_oks.size() == 1 && s0.pb_crc_oks[0], "ul16 crc=[true]");
            check(s0.msdu.size() == 8 && (s0.msdu[0] & 0x0F) == 5, "ul16 body MsgID=5 (not SACK)");
        }
    }

    {   // B: 坏 trigger 使旧上下文作废(先有效 trigger 建立,再坏 trigger 作废,再 UL 帧)
        NW_2026_Parser p5;
        p5.parse(load("wireshark_support_plugins/nw2026_trigger.bin"), msdu, flt);   // 有效 trigger 建立上下文
        BplcFrame bad = load("wireshark_support_plugins/nw2026_trigger.bin");
        bad.data[1 + 20] = char(bad.data[1 + 20] ^ 0x01);   // isRF 前缀 1B + eFC 内字节
        auto rt5 = p5.parse(bad, msdu, flt);
        check(rt5.accept, "bad-efc trigger itself still accepted (FCH OK)");
        auto r = p5.parse(load("wireshark_support_plugins/nw2026_ul_ofdma_data.bin"), msdu, flt);
        check(r.mpdu.sof_stations.isEmpty(), "bad-efc invalidates old context (not 2-station)");
        check(r.msdu.present && r.msdu.summary.contains(QStringLiteral("需 trigger")), "bad-efc summary 含「需 trigger」");
    }

    {   // A: DL-OFDMA eFC CRC 错(翻 eFC 体 1bit,FCH CRC 正确) → 拒绝 + pb_num=0
        NW_2026_Parser pA;
        auto r = pA.parse(load("wireshark_support_plugins/nw2026_dl_ofdma_badefc.bin"), msdu, flt);
        check(!r.accept && r.reject_reason.contains(QStringLiteral("eFC CRC24")), "badefc DL-OFDMA reject 含 eFC CRC24");
        check(r.mpdu.pb_num == 0, "badefc DL-OFDMA pb_num=0");
    }

    {   // A 正向:好的 DL-OFDMA 必须通过 eFC CRC 校验
        // 目的:若 CRC 口径改错(crc24_lsb 覆盖长度 / e[13..15] 字节序 / poly),好帧会被误拒,
        //      而「只断言坏帧被拒」的测试仍全绿 ⇒ 必须有正向用例守门
        NW_2026_Parser pGood;
        auto r = pGood.parse(load("wireshark_support_plugins/nw2026_dl_ofdma.bin"), msdu, flt);
        check(r.accept, "dl_ofdma accept (good eFC CRC)");
        check(r.mpdu.pb_num == 1, "dl_ofdma pb_num=1 (PB 码 0 -> 1 块)");
        check(r.mpdu.pb_size == 136, "dl_ofdma pb_size=136 (TMI 18)");
    }

    printf(fails ? "RESULT: FAIL (%d)\n" : "RESULT: PASS\n", fails);
    return fails ? 1 : 0;
}
