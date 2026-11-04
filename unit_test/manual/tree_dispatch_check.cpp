// tree_dispatch_check.cpp — 验证 ProtocolTree 按 PacketEntry::protocol 分派字段树构建器
// @details 构造四个 PacketEntry(每个协议各一个),送入 ProtocolTree::show_packet,
//          抽取渲染出的全部节点文本,按各协议布局的判别特征断言命中/未命中:
//            GW_2022 : 出现 "Net ID"         且 不出现 "(HDC"
//            GW_2026 : 出现 "(HDC 2.0)"
//            NW_2021 : 出现 "本标准版本号"     且 不出现 "BPLC版本"
//            NW_2026 : 出现 "BPLC版本"         且 不出现 "本标准版本号"
//          需要离屏平台:QT_QPA_PLATFORM=offscreen
#include <QApplication>
#include <QTreeWidgetItem>
#include <QTreeWidgetItemIterator>
#include <QByteArray>
#include <QString>
#include <QStringList>
#include <cstdio>

#include "bplcframe.h"
#include "protocolfactory.h"
#include "protocoltree.h"
#include "protocol/common/crc.h"
#include "packetlistmodel.h"
#include <QColor>

static void collect(QTreeWidgetItem* it, QStringList& out) {
    if (!it) return;
    out << it->text(0) + QLatin1Char('|') + it->text(1);
    for (int i = 0; i < it->childCount(); ++i) collect(it->child(i), out);
}

static QString dump_tree(ProtocolTree& t) {
    QStringList out;
    for (int i = 0; i < t.topLevelItemCount(); ++i)
        collect(t.topLevelItem(i), out);
    return out.join(QLatin1Char('\n'));
}

int main(int argc, char** argv) {
    QApplication app(argc, argv);

    struct Case {
        quint8      proto;
        const char* name;
        quint8      version;
        const char* want;      // 必须出现的判别特征
        const char* must_not;  // 必须不出现(空串=不检查)
    };
    static const Case cases[] = {
        { kProtocolGw2022, "GW_2022", 0, "Net ID",       "(HDC" },
        { kProtocolGw2026, "GW_2026", 1, "(HDC 2.0)",    "" },
        { kProtocolNw2021, "NW_2021", 1, "\u672C\u6807\u51C6\u7248\u672C\u53F7", "BPLC\u7248\u672C" },
        { kProtocolNw2026, "NW_2026", 2, "SPLC\u7248\u672C", "\u672C\u6807\u51C6\u7248\u672C\u53F7" },
    };

    const int n = int(sizeof(cases) / sizeof(cases[0]));
    int bad = 0;
    int total = 1 + n;   // 注册表 1 条 + 布局 n 条(后两阶段各自累加)

    // 协议下拉框的数据源:注册表必须已自注册(否则通讯设置对话框会下拉为空)
    {
        const QStringList ids = registered_protocol_ids();
        std::printf("[registry] registered_protocol_ids() = %s  (count=%d)\n",
                    ids.join(QLatin1Char(',')).toUtf8().constData(), int(ids.size()));
        if (ids.isEmpty()) { ++bad; std::printf("  -> FAIL: 注册表为空\n"); }
    }

    for (int i = 0; i < n; ++i) {
        const Case& c = cases[i];

        ProtocolTree tree;
        PacketEntry e;
        e.index      = 1;
        e.accepted   = true;
        e.protocol   = c.proto;        // ← 分派依据:帧自己的协议身份
        e.meta.is_rf = false;
        e.mpdu.frame_type = 0;         // BEACON
        e.mpdu.version    = c.version; // 版本标签随构建器不同而不同
        e.mpdu.fch_crc_ok = true;
        e.raw_bytes       = QByteArray(96, '\0');

        tree.show_packet(e);
        const QString d = dump_tree(tree);

        const bool hit_want = d.contains(QString::fromUtf8(c.want));
        const bool hit_not  = c.must_not[0]
                              ? d.contains(QString::fromUtf8(c.must_not)) : false;
        const bool pass = hit_want && !hit_not;

        std::printf("[%-7s] want \"%s\":%s   must_not \"%s\":%s   nodes=%lld  -> %s\n",
                    c.name,
                    c.want,     hit_want ? "hit" : "MISS",
                    c.must_not, hit_not  ? "HIT" : "ok",
                    static_cast<qlonglong>(d.count(QLatin1Char('\n')) + 1),
                    pass ? "PASS" : "FAIL");

        if (!pass) {
            ++bad;
            std::printf("---- dump begin ----\n%s\n---- dump end ----\n",
                        d.toUtf8().constData());
        }
    }

    // ── 第二阶段:同一个 ProtocolTree 实例反复切换协议 ──
    // 验证"逐帧实时判定":每次 show_packet 都按本帧 e.protocol 重新选构建器,
    // 不会因为第一帧判成某协议就锁定整包。构建器对象虽被缓存,判定不缓存。
    {
        struct Step { quint8 proto; quint8 ver; const char* want; };
        static const Step seq[] = {
            { kProtocolGw2022, 0, "Net ID" },
            { kProtocolGw2026, 1, "(HDC 2.0)" },
            { kProtocolGw2022, 0, "Net ID" },                                    // 回到旧版
            { kProtocolNw2026, 2, "SPLC\u7248\u672C" },                          // 跨族
            { kProtocolNw2021, 1, "\u672C\u6807\u51C6\u7248\u672C\u53F7" },
            { kProtocolGw2026, 1, "(HDC 2.0)" },                                 // 再跨回国网
        };
        ProtocolTree t;   // ← 全程同一个控件实例(模拟"一个会话看混合包")
        int bad2 = 0;
        const int m = int(sizeof(seq) / sizeof(seq[0]));
        total += m;
        for (int i = 0; i < m; ++i) {
            PacketEntry e;
            e.index    = i + 1;
            e.accepted = true;
            e.protocol = seq[i].proto;
            e.meta.is_rf = false;
            e.mpdu.frame_type = 0;
            e.mpdu.version    = seq[i].ver;
            e.mpdu.fch_crc_ok = true;
            e.raw_bytes       = QByteArray(96, '\0');

            t.show_packet(e);
            const QString d = dump_tree(t);
            const bool pass = d.contains(QString::fromUtf8(seq[i].want));
            std::printf("[seq %d] proto=%d  want \"%s\":%s -> %s\n",
                        i, int(seq[i].proto), seq[i].want,
                        pass ? "hit" : "MISS", pass ? "PASS" : "FAIL");
            if (!pass) ++bad2;
        }
        std::printf("SEQUENCE RESULT: %s  (%d/%d passed)\n",
                    bad2 == 0 ? "ALL PASS" : "FAILED", m - bad2, m);
        bad += bad2;
    }

    // ── 第三阶段:SOF 帧型的布局归属 ──
    // 验证被删掉的"BPLC 载波 SOF 复制段"确实已由 NW_2021_TreeBuilder 承接:
    //   BPLC SOF 专属标记 "TMI_EXT"(只在 nw_2021_tree.cpp 里存在)
    //   SPLC SOF 专属标记 "MultiStationFlag"(只在 nw_2026_tree.cpp 里存在)
    {
        struct SofCase { quint8 proto; quint8 ver; const char* want; const char* must_not; };
        static const SofCase sof_cases[] = {
            { kProtocolNw2021, 1, "TMI_EXT",          "MultiStationFlag" },
            { kProtocolNw2026, 2, "MultiStationFlag", "TMI_EXT" },
        };
        int bad3 = 0;
        const int k = int(sizeof(sof_cases) / sizeof(sof_cases[0]));
        total += k;
        for (int i = 0; i < k; ++i) {
            ProtocolTree t;
            PacketEntry e;
            e.index    = 1;
            e.accepted = true;
            e.protocol = sof_cases[i].proto;
            e.meta.is_rf = false;                 // 载波 SOF
            e.mpdu.frame_type = 1;                // SOF
            e.mpdu.version    = sof_cases[i].ver;
            e.mpdu.fch_crc_ok = true;
            e.mpdu.pb_num     = 1;
            e.mpdu.pb_size    = 32;
            e.mpdu.frame_len  = 100;
            e.raw_bytes       = QByteArray(96, '\0');

            t.show_packet(e);
            const QString d = dump_tree(t);
            const bool hit  = d.contains(QString::fromUtf8(sof_cases[i].want));
            const bool nott = sof_cases[i].must_not[0]
                              && d.contains(QString::fromUtf8(sof_cases[i].must_not));
            const bool pass = hit && !nott;
            std::printf("[SOF %s] want \"%s\":%s  must_not \"%s\":%s -> %s\n",
                        i == 0 ? "NW_2021" : "NW_2026",
                        sof_cases[i].want, hit ? "hit" : "MISS",
                        sof_cases[i].must_not, nott ? "HIT" : "ok",
                        pass ? "PASS" : "FAIL");
            if (!pass) { ++bad3; std::printf("---- dump ----\n%s\n----\n", d.toUtf8().constData()); }
        }
        std::printf("SOF RESULT: %s  (%d/%d passed)\n",
                    bad3 == 0 ? "ALL PASS" : "FAILED", k - bad3, k);
        bad += bad3;
    }

    // ── 第四阶段:插件通用字段树渲染(Step 1) ──
    // 内置解析器 dissect_fields 恒空 → 走协议构建器;插件帧非空 → 通用渲染。
    // 构造一棵含分组/类型字段/越界字段的树,验证:
    //   ① 通用渲染生效(不出现内置 GW_2022 特征 "Net ID")
    //   ② 分组与子字段都画出来
    //   ③ 越界坐标被降级为无映射(kRoleStart<0),不崩
    {
        ProtocolTree t;
        PacketEntry e;
        e.index     = 1;
        e.accepted  = true;
        e.protocol  = kProtocolGw2022;      // 借内置变体号,但应走通用渲染
        e.raw_bytes = QByteArray(64, '\0');

        DissectField grp(QStringLiteral("Payload"), QString(), 0, 64);
        grp.children.append(DissectField(QStringLiteral("MMe Type [8b]"),
                                         QStringLiteral("0x0C"), 4, 1));
        DissectField bad_f(QStringLiteral("Broken"), QStringLiteral("x"), 999, 8);
        bad_f.severity = 3;
        e.dissect_fields = { grp, bad_f };

        t.show_packet(e);
        const QString d = dump_tree(t);

        const bool no_builtin = !d.contains(QStringLiteral("Net ID"));
        const bool has_grp    = d.contains(QStringLiteral("Payload"));
        const bool has_child  = d.contains(QStringLiteral("MMe Type [8b]"));
        const bool has_bad    = d.contains(QStringLiteral("Broken"));

        int bad_start = -12345;
        for (QTreeWidgetItemIterator it(&t); *it; ++it) {
            if ((*it)->text(0) == QStringLiteral("Broken"))
                bad_start = (*it)->data(0, kRoleStart).toInt();
        }
        const bool degraded = (bad_start < 0);   // 越界 → 降级为 -1

        const int p4 = 5;
        const bool pass = no_builtin && has_grp && has_child && has_bad && degraded;
        std::printf("[dissect] no_builtin=%d group=%d child=%d field=%d degraded=%d -> %s\n",
                    int(no_builtin), int(has_grp), int(has_child), int(has_bad),
                    int(degraded), pass ? "PASS" : "FAIL");
        if (!pass) {
            std::printf("---- dump ----\n%s\n----\n", d.toUtf8().constData());
            bad += p4;
        }
        total += p4;
        std::printf("DISSECT RESULT: %s  (%d/%d passed)\n",
                    pass ? "ALL PASS" : "FAILED", pass ? p4 : 0, p4);
    }

    // ── 第五阶段:SPLC 无线 SOF 的 SNID 高位(表45 (12,0,1) / 保留 (12,1,3)) ──
    // 修复前:NW_2026 无线 SOF 沿用 BPLC 表131 的"byte12 整段保留",SNID 高位被吞,
    // 树里只有 RSV(12,0,4)、解析层 net_id 高位恒 0(SNID≥16 的帧过滤/列显示错)。
    {
        ProtocolTree t;
        PacketEntry e;
        e.index     = 1;
        e.accepted  = true;
        e.protocol  = kProtocolNw2026;
        e.meta.is_rf = true;          // 无线
        e.mpdu.frame_type = 1;        // SOF
        e.mpdu.version    = 2;        // SPLC
        e.mpdu.pb_num     = 1;
        e.mpdu.pblen      = 0;
        e.mpdu.pb_size    = 16;
        e.mpdu.fch_crc_ok = true;
        QByteArray raw(96, '\0');
        raw[12] = char(0x01);         // byte12 bit0 = SNID 高位 = 1
        e.raw_bytes = raw;

        t.show_packet(e);
        const QString d = dump_tree(t);
        const bool has_snid = d.contains(QStringLiteral("SNID High"));
        std::printf("[RF SOF SNID] want \"SNID High\":%s -> %s\n",
                    has_snid ? "hit" : "MISS", has_snid ? "PASS" : "FAIL");
        if (!has_snid) {
            std::printf("---- dump ----\n%s\n----\n", d.toUtf8().constData());
            bad += 1;
        }
        total += 1;
    }

    // ── 第六阶段:解析层合并 SNID 高位(SPLC 无线 SOF 表45 (12,0,1)) ──
    // 第五阶段只证明"树渲染对了";net_id 高位必须真走一遍 parser 的合并块才算验证。
    // decode_envelope 有 from_raw 快捷路径:data[0] 非 0 = 无线,其后即 payload,
    // 所以不必拼串口转义帧;FCH CRC24 = crc24_lsb(p,16)(覆盖前 13 字节,末 3B 小端)。
    {
        auto parser = make_parser_by_id(QStringLiteral("NW_2026"));
        if (!parser) {
            std::printf("[SNID merge] NW_2026 parser 缺失 -> FAIL\n");
            bad += 1;
            total += 1;
        } else {
            auto run = [&](quint8 bit0) -> quint32 {
                QByteArray payload(24, '\0');
                payload[0]  = char(0x01);                              // fch[0] bit0-2 = frame_type 1(SOF)
                payload[12] = char(quint8((0x02 << 4) | (bit0 & 0x01))); // 版本号=2(SPLC) | SNID 高位
                const quint32 crc = crc24_lsb(
                    reinterpret_cast<const quint8*>(payload.constData()), 16);
                payload[13] = char(quint8(crc & 0xFF));
                payload[14] = char(quint8((crc >> 8) & 0xFF));
                payload[15] = char(quint8((crc >> 16) & 0xFF));

                BplcFrame f;
                f.meta.from_raw = true;
                QByteArray d;
                d.append(char(1));      // 非 0 → is_rf = true
                d.append(payload);
                f.data = d;

                MsduState st;
                ParseFilter pf;         // 默认 link_hrf=true / allow_sof=true
                const ParseResult r = parser->parse(f, st, pf);
                return r.mpdu.net_id;
            };
            const quint32 hi1 = run(1);
            const quint32 hi0 = run(0);
            const bool pass = ((hi1 & 0x10) != 0) && ((hi0 & 0x10) == 0);
            std::printf("[SNID merge] byte12.bit0=1 -> net_id=0x%06X bit4=%d | "
                        "bit0=0 -> 0x%06X bit4=%d -> %s\n",
                        hi1, int((hi1 >> 4) & 1), hi0, int((hi0 >> 4) & 1),
                        pass ? "PASS" : "FAIL");
            if (!pass) bad += 1;
            total += 1;
        }
    }

    // ── 第七阶段:插件位帧换页后的三态分派(Step 2) ──
    // protocol 置 kProtocolPluginBit 且 dissect_fields 为空(换页后不落盘)→
    // 不画内置树(无内置特征 "Net ID"),挂"重新解剖"提示节点;
    // 同一帧补上 dissect_fields(点击行重新获取后的重新解剖结果)→ 通用渲染,仍无内置树。
    {
        ProtocolTree t;
        PacketEntry e;
        e.index     = 1;
        e.accepted  = true;
        e.protocol  = kProtocolGw2022 | kProtocolPluginBit;
        e.raw_bytes = QByteArray(64, '\0');

        t.show_packet(e);
        const QString d = dump_tree(t);
        const bool no_builtin = !d.contains(QStringLiteral("Net ID"));
        const bool has_hint   = d.contains(QStringLiteral("重新解剖"));
        const bool pass7a = no_builtin && has_hint;
        std::printf("[plugin page-out] no_builtin=%d hint=%d -> %s\n",
                    int(no_builtin), int(has_hint), pass7a ? "PASS" : "FAIL");
        if (!pass7a) {
            std::printf("---- dump ----\n%s\n----\n", d.toUtf8().constData());
            bad += 1;
        }
        total += 1;

        // 复用第四阶段的通用字段树构造(重新解剖结果) → 走通用渲染
        DissectField grp7(QStringLiteral("Plugin Payload"), QString(), 0, 64);
        grp7.children.append(DissectField(QStringLiteral("MMe Type [8b]"),
                                          QStringLiteral("0x0C"), 4, 1));
        e.dissect_fields = { grp7 };
        t.show_packet(e);
        const QString d2 = dump_tree(t);
        const bool no_builtin2 = !d2.contains(QStringLiteral("Net ID"));
        const bool has_generic = d2.contains(QStringLiteral("Plugin Payload"))
                              && d2.contains(QStringLiteral("MMe Type [8b]"));
        const bool pass7b = no_builtin2 && has_generic;
        std::printf("[plugin re-dissect] no_builtin=%d generic=%d -> %s\n",
                    int(no_builtin2), int(has_generic), pass7b ? "PASS" : "FAIL");
        if (!pass7b) {
            std::printf("---- dump ----\n%s\n----\n", d2.toUtf8().constData());
            bad += 1;
        }
        total += 1;
    }

    // ── 第八阶段:ParseResult→PacketEntry 的协议映射(插件位必须保留) ──
    // 这 4 条是"假绿"回归:此前 mainwindow 用 switch(r.protocol) 重建 e.protocol,
    // 插件帧的 0x80 会在 default 分支被丢 → builder_for 看不到插件位 → 照样画内置布局。
    // 第七阶段直接构造 PacketEntry,绕过了这个映射,所以测不出来。
    {
        const quint8 plugin_gw2026 = quint8(quint8(ProtocolVariant::GW_2026) | kProtocolPluginBit);
        struct MapCase { quint8 in; quint8 want; const char* what; };
        const MapCase mc[] = {
            { quint8(ProtocolVariant::GW_2022),              kProtocolGw2022,                   "GW_2022 内置" },
            { quint8(ProtocolVariant::NW_2026),              kProtocolNw2026,                   "NW_2026 内置" },
            { plugin_gw2026,           quint8(kProtocolGw2026 | kProtocolPluginBit),           "插件帧保留位" },
            { kProtocolPluginBit,                    kProtocolPluginBit,                        "插件位+默认编号" },
        };
        int bad8 = 0;
        const int m8 = int(sizeof(mc) / sizeof(mc[0]));
        total += m8;
        for (int i = 0; i < m8; ++i) {
            const quint8 got = entry_protocol_id(static_cast<ProtocolVariant>(mc[i].in));
            const bool pass = (got == mc[i].want);
            std::printf("[proto map] %s: in=0x%02X -> 0x%02X (want 0x%02X) -> %s\n",
                        mc[i].what, mc[i].in, got, mc[i].want, pass ? "PASS" : "FAIL");
            if (!pass) ++bad8;
        }
        bad += bad8;
    }

    // ── 第九阶段:PacketListModel 整行着色——CRC 失败红(用户需求) ──
    // 优先级:CRC 失败红(FCH CRC24 FAIL / 任一 PB CRC24 FAIL,最高) >
    // MMe 暖色 > APP BID 冷色 > data_color;MSDU CRC32 FAIL 不改颜色。
    {
        struct ColorCase {
            const char* what;
            bool   fch_ok;
            QVector<bool> pb_oks;
            quint8 frame_type;      // 1=SOF(走 data_color 绿,便于区分)
            int    want_r, want_g, want_b;  // -1 = 断言"非红"即可
        };
        const ColorCase cc[] = {
            { "FCH CRC24 FAIL -> 红",            false, {true},            1, 224, 64, 64 },
            { "PB CRC24 FAIL -> 红",             true,  {true, false},     1, 224, 64, 64 },
            { "FCH/PB 全 OK(MSDU CRC FAIL) -> 非红", true, {true, true},   1,  -1, -1, -1 },
        };
        PacketListModel model;
        int bad9 = 0;
        const int m9 = int(sizeof(cc) / sizeof(cc[0]));
        total += m9;
        for (int i = 0; i < m9; ++i) {
            PacketEntry e;
            e.accepted = true;
            e.protocol = kProtocolNw2026;
            e.mpdu.frame_type = cc[i].frame_type;
            e.mpdu.fch_crc_ok = cc[i].fch_ok;
            e.mpdu.pb_crc_oks = cc[i].pb_oks;
            model.append_packet(e);
            const QVariant v = model.data(model.index(i, 0), Qt::ForegroundRole);
            const QColor got = v.value<QColor>();
            bool pass;
            if (cc[i].want_r < 0) {
                // 非红:不应命中 CRC 失败红(224,64,64)
                pass = !(got == QColor(224, 64, 64));
            } else {
                pass = (got == QColor(cc[i].want_r, cc[i].want_g, cc[i].want_b));
            }
            std::printf("[crc color] %s: got rgb(%d,%d,%d) -> %s\n",
                        cc[i].what, got.red(), got.green(), got.blue(),
                        pass ? "PASS" : "FAIL");
            if (!pass) ++bad9;
        }
        bad += bad9;
    }

    std::printf("RESULT: %s  (%d/%d passed)\n",
                bad == 0 ? "ALL PASS" : "FAILED", total - bad, total);
    return bad == 0 ? 0 : 1;
}
