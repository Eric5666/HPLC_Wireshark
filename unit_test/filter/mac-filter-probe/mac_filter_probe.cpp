// 主界面搜索过滤 MAC 展开回归探针(只读验证,不改产品代码)。
// 映射表(包列表模型自身,通过 append 的 tei_mac_pairs 学习):
//   NID 1: TEI 5 <-> 03:02:AA:BB:CC:DD, TEI 7 <-> 03:02:11:22:33:44,
//          TEI 9 <-> 04:05:66:77:88:99, TEI 3 <-> 03:FF:00:00:00:01,
//          TEI 13 <-> AA:03:02:BB:CC:DD(中间), TEI 15 <-> AA:BB:CC:DD:03:02(后缀),
//          TEI 17 <-> AA:BB:03:02:CC:DD(中间)
//   NID 2: TEI 11 <-> 03:02:FF:EE:DD:CC
// MAC 字节序:首组=低字节(与 format_mac/m_mac_tei 的 u64 约定一致)。
// 模式匹配:模式字节序列在 MAC 任意字节偏移处出现即命中(前缀/中间/后缀);
// 完整 6 组仅偏移 0,即精确匹配。
#include "packetlistmodel.h"
#include "common/msdu_crc_state.h"
#include <QCoreApplication>
#include <cstdio>

static int g_fail = 0;
#define CHECK(cond, ...) do { \
    if (cond) { printf("PASS: "); printf(__VA_ARGS__); printf("\n"); } \
    else { printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); ++g_fail; } } while (0)

static quint64 mac6(quint8 b0, quint8 b1, quint8 b2, quint8 b3, quint8 b4, quint8 b5) {
    return quint64(b0) | (quint64(b1) << 8) | (quint64(b2) << 16)
         | (quint64(b3) << 24) | (quint64(b4) << 32) | (quint64(b5) << 40);
}

static PacketEntry mk(quint16 src, quint16 dst, quint8 ft, const QString& text) {
    PacketEntry e;
    e.accepted = true;
    e.mpdu.frame_type = ft;
    e.mpdu.src_tei = src;
    e.mpdu.dst_tei = dst;
    e.search_text = text;
    return e;
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    PacketListModel model;

    // 学习映射表(公开路径 append -> update_tei_mac)
    {
        PacketEntry l1;
        l1.accepted = true;
        l1.mpdu.net_id = 1;
        l1.msdu.tei_mac_pairs.append({5, mac6(0x03, 0x02, 0xAA, 0xBB, 0xCC, 0xDD)});
        l1.msdu.tei_mac_pairs.append({7, mac6(0x03, 0x02, 0x11, 0x22, 0x33, 0x44)});
        l1.msdu.tei_mac_pairs.append({9, mac6(0x04, 0x05, 0x66, 0x77, 0x88, 0x99)});
        l1.msdu.tei_mac_pairs.append({3, mac6(0x03, 0xFF, 0x00, 0x00, 0x00, 0x01)});
        l1.msdu.tei_mac_pairs.append({13, mac6(0xAA, 0x03, 0x02, 0xBB, 0xCC, 0xDD)});
        l1.msdu.tei_mac_pairs.append({15, mac6(0xAA, 0xBB, 0xCC, 0xDD, 0x03, 0x02)});
        l1.msdu.tei_mac_pairs.append({17, mac6(0xAA, 0xBB, 0x03, 0x02, 0xCC, 0xDD)});
        PacketEntry l2;
        l2.accepted = true;
        l2.mpdu.net_id = 2;
        l2.msdu.tei_mac_pairs.append({11, mac6(0x03, 0x02, 0xFF, 0xEE, 0xDD, 0xCC)});
        model.append_packets(QVector<PacketEntry>{l1, l2});
    }

    auto t = [&](const char* name, const QString& expr, const PacketEntry& e, bool want) {
        model.set_display_filter(expr);
        const bool got = model.passes_filter(e);
        CHECK(got == want, "%s | filter='%s' src=%u dst=%u ft=%u -> %d (want %d)",
              name, expr.toUtf8().constData(), e.mpdu.src_tei, e.mpdu.dst_tei,
              e.mpdu.frame_type, got ? 1 : 0, want ? 1 : 0);
    };

    // 1. 前缀展开为多 TEI 的或(src 与 dst 均算;跨 NID 与 sta- 语义一致)
    t("prefix-or", "03:02", mk(5, 0, 1, "hello"), true);
    t("prefix-or", "03:02", mk(0, 7, 1, "hello"), true);
    t("prefix-or", "03:02", mk(9, 0, 1, "hello"), false);
    t("prefix-or", "03:02", mk(3, 0, 1, "hello"), false);
    t("prefix-or", "03:02", mk(11, 0, 1, "hello"), true);
    // 1b. 中间/后缀:同一模式在任意偏移处出现即命中
    t("mid", "03:02", mk(13, 0, 1, "hello"), true);   // 偏移 1:AA:03:02:...
    t("mid", "03:02", mk(17, 0, 1, "hello"), true);   // 偏移 2:AA:BB:03:02:...
    t("suffix", "03:02", mk(15, 0, 1, "hello"), true);  // 偏移 4:...:03:02
    t("mid", "02:aa", mk(5, 0, 1, "hello"), true);    // 偏移 1:03:02:AA:...
    t("mid", "02:aa", mk(7, 0, 1, "hello"), false);   // 02 后是 11 不是 AA
    t("mid", "02:aa", mk(13, 0, 1, "hello"), false);  // 02 后是 BB 不是 AA
    t("suffix", "cc:dd", mk(5, 0, 1, "hello"), true);   // 偏移 4:...:CC:DD
    t("mid", "cc:dd", mk(15, 0, 1, "hello"), true);     // 偏移 2:AA:BB:CC:DD:...
    t("suffix", "cc:dd", mk(11, 0, 1, "hello"), false);  // 末尾是 DD:CC,顺序反了
    t("suffix", "ee:dd:cc", mk(11, 0, 1, "hello"), true);  // 偏移 3:...:EE:DD:CC
    t("mid", "bb:cc:dd", mk(15, 0, 1, "hello"), true);     // 偏移 1:AA:BB:CC:DD:...
    t("suffix", "bb:cc:dd", mk(5, 0, 1, "hello"), true);   // 偏移 3:...:BB:CC:DD
    // 顺序敏感:字节序列不是集合,02:03 不等于 03:02
    t("order", "02:03", mk(5, 0, 1, "hello"), false);
    t("order", "02:03", mk(15, 0, 1, "hello"), false);
    // 2. 完整 6 组 = 精确匹配;大小写不敏感
    t("full-mac", "03:02:aa:bb:cc:dd", mk(5, 0, 1, "hello"), true);
    t("full-mac", "03:02:aa:bb:cc:dd", mk(7, 0, 1, "hello"), false);
    t("full-mac", "aa:03:02:bb:cc:dd", mk(13, 0, 1, "hello"), true);
    t("full-mac", "aa:03:02:bb:cc:dd", mk(5, 0, 1, "hello"), false);
    t("full-mac", "03:02:AA:BB:CC:DD", mk(5, 0, 1, "hello"), true);
    t("full-mac", "03:02:aa:bb:cc:de", mk(5, 0, 1, "hello"), false);
    // 3. 无命中 = 条件为空(永假,不是回落子串)
    t("no-match", "03:99", mk(5, 0, 1, "hello"), false);
    t("no-match", "03:99", mk(5, 0, 1, "x03:99y"), false);
    // 4. 与 & 的 DNF 分配:sof & 03:02 = (sof&5)|(sof&7)
    t("and-dist", "sof & 03:02", mk(5, 0, 1, "hello"), true);
    t("and-dist", "sof & 03:02", mk(9, 0, 1, "hello"), false);
    t("and-dist", "sof & 03:02", mk(5, 0, 0, "hello"), false);
    // 5. 双 MAC 与:03:02 & 04:05 需两边各中一个
    t("and-mac", "03:02 & 04:05", mk(5, 9, 1, "hello"), true);
    t("and-mac", "03:02 & 04:05", mk(5, 7, 1, "hello"), false);
    t("and-mac", "03:02 & 04:05", mk(9, 9, 1, "hello"), false);
    // 6. 与 | 组合:无命中组不贡献,其它组正常工作
    t("or-mix", "03:02 | sta-9", mk(5, 0, 1, "hello"), true);
    t("or-mix", "03:02 | sta-9", mk(9, 0, 1, "hello"), true);
    t("or-mix", "03:02 | sta-9", mk(3, 0, 1, "hello"), false);
    t("or-mix", "03:99 | sof", mk(9, 0, 1, "hello"), true);
    t("or-mix", "03:99 | sof", mk(9, 0, 0, "hello"), false);
    // 7. 不成 MAC 的仍走旧语义:单组无冒号 = 子串;尾冒号 = 子串
    t("not-mac", "03", mk(5, 0, 1, "hello"), false);
    t("not-mac", "03", mk(5, 0, 1, "x03y"), true);
    t("not-mac", "03:02:", mk(5, 0, 1, "hello"), false);
    t("not-mac", "03:02:", mk(5, 0, 1, "a03:02:b"), true);
    // 8. 旧语义回归
    t("regress", "sta-5", mk(5, 0, 1, "hello"), true);
    t("regress", "sta-5", mk(7, 0, 1, "hello"), false);
    t("regress", "beacon", mk(9, 0, 0, "hello"), true);
    t("regress", "beacon", mk(9, 0, 1, "hello"), false);
    t("regress", "", mk(9, 0, 1, "hello"), true);

    // 9. 剥离后的 MSDU 不得再学习映射(P1:msdu_crc_strip_learning 曾漏清目的方)
    //    真实路径:append -> update_tei_mac,断言用映射表快照而非 MsduInfo 字段。
    //    用独立 NID 99 与新 TEI,避免与上文 l1/l2 的映射互相干扰。
    {
        auto mk_stripped = [&]() {
            PacketEntry e;
            e.accepted = true;
            e.mpdu.net_id = 99;
            e.msdu.present = true;
            e.msdu.simple_head = false;
            e.msdu.msdu_src_tei = 21;
            e.msdu.msdu_src_mac = mac6(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
            e.msdu.msdu_dst_tei = 22;
            e.msdu.msdu_dst_mac = mac6(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
            e.msdu.tei_mac_pairs.append({23, mac6(0x01, 0x02, 0x03, 0x04, 0x05, 0x06)});
            e.msdu.topo_event.kind = TopoEventKind::AssocCnf;
            e.msdu.topo_event.nodes.append({21, e.msdu.msdu_src_mac});
            return e;
        };
        auto has_mapping = [](const PacketListModel& m, quint32 nid, quint16 tei) {
            const auto snap = m.make_export_snapshot();
            const auto it = snap.tei_mac.find(nid);
            return it != snap.tei_mac.end() && it.value().contains(tei);
        };
        // 9a. 剥离后 append:源/目的/学习对一律不得进映射表
        {
            PacketListModel m2;
            PacketEntry e = mk_stripped();
            e.msdu = msdu_crc_strip_learning(e.msdu);
            m2.append_packets(QVector<PacketEntry>{e});
            CHECK(!has_mapping(m2, 99, 21), "strip-no-learn | src TEI 21 must not be learned");
            CHECK(!has_mapping(m2, 99, 22), "strip-no-learn | dst TEI 22 must not be learned");
            CHECK(!has_mapping(m2, 99, 23), "strip-no-learn | pair TEI 23 must not be learned");
        }
        // 9b. 对照:不剥离时三者都应学到(反向验证,9a 不是恒假断言)
        {
            PacketListModel m3;
            m3.append_packets(QVector<PacketEntry>{mk_stripped()});
            CHECK(has_mapping(m3, 99, 21), "strip-control | src TEI 21 learned without strip");
            CHECK(has_mapping(m3, 99, 22), "strip-control | dst TEI 22 learned without strip");
            CHECK(has_mapping(m3, 99, 23), "strip-control | pair TEI 23 learned without strip");
        }
    }

    printf("RESULT: %d failures\n", g_fail);
    return g_fail ? 1 : 0;
}
