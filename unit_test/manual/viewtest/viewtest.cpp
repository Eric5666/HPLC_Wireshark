/// @file viewtest.cpp
/// @brief 验证 ProtocolTree/HexView 在 show_packet/set_data 后确实填充内容
/// @details 用真实 PacketEntry(SOF 帧)调用两个视图,检查:
///          - ProtocolTree::topLevelItemCount > 0(修复 addTopLevelItem)
///          - HexView 文档非空
#include "protocoltree.h"
#include "hexview.h"
#include "io/playbackwriter.h"
#include "i18n.h"
#include "gw_2022_parser.h"
#include "packetlistmodel.h"
#include <QApplication>
#include <QFile>
#include <QDir>
#include <QFileInfo>
#include <cstdio>
#include <functional>

// 仓库根:从可执行文件位置向上找含 .git 的目录(最多 5 级),避免硬编码本机绝对路径。
// viewtest.exe 通常位于 <repo>/unit_test/manual/viewtest/release/ 或 build 输出目录下。
static QString repoRoot()
{
    QDir d(QCoreApplication::applicationDirPath());
    for (int i = 0; i < 5; ++i) {
        if (QFileInfo::exists(d.filePath(".git")))
            return d.path();
        if (!d.cdUp())
            break;
    }
    return QDir::currentPath();   // 兜底:当前工作目录
}

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    // kSamples 必须在 QApplication 构造后才能用 applicationDirPath() 推导
    const QString kSamples = repoRoot() + QStringLiteral("/samples");

    PacketEntry e;
    e.index    = 1;
    e.accepted = true;
    e.epoch_ms = 0;
    e.meta.is_rf  = false;
    e.meta.channel = 2;
    e.mpdu.frame_type = 1;          // SOF
    e.mpdu.net_id  = 0xCDA1D5;
    e.mpdu.net_type = 0;
    e.mpdu.version = 0;
    e.mpdu.src_tei = 3;
    e.mpdu.dst_tei = 0x0FFF;
    e.mpdu.link_id = 0;
    e.mpdu.frame_len = 979;
    e.mpdu.pb_num   = 1;
    e.mpdu.symbol_num = 182;
    e.mpdu.bc_flag  = true;
    e.mpdu.re_send_flag = false;
    e.mpdu.encryp_flag = false;
    e.mpdu.tmi = 4;
    e.mpdu.tmi_ext = 0;
    e.mpdu.pb_size = 136;
    e.mpdu.fch_crc_ok = true;
    e.mpdu.pb_crc_ok  = true;
    e.raw_bytes = QByteArray::fromHex(
        "01d5a1cd03f0ff00d313b64200bee7cec03000ff2f016b0000296011"
        "08001e0000014464518514ffffffffffff0800000003100012014464"
        "51851400002974775682185064020054013500010050efbe02013006");

    // 构造 MSDU 解析结果(模拟真实 GW_2022_MsduParser 输出:MMeDiscoverNodeList)
    e.msdu.present = true;
    e.msdu.summary = QStringLiteral("MMeDiscoverNodeList");
    e.msdu_body = QByteArray(41, char(0));
    {
        MsduFieldNode mbase;
        mbase.name  = QStringLiteral("Version [4b]");
        mbase.value = QStringLiteral("0");
        e.msdu.tree.append(mbase);
        MsduFieldNode st;
        st.name  = QStringLiteral("SourceTEI [12b]");
        st.value = QStringLiteral("3");
        e.msdu.tree.append(st);
        MsduFieldNode mme;
        mme.name  = QStringLiteral("MMe: MMeDiscoverNodeList");
        mme.value = QString();
        {
            MsduFieldNode statei;
            statei.name  = QStringLiteral("STATEI [12b]");
            statei.value = QStringLiteral("3");
            mme.children.append(statei);
            MsduFieldNode list;
            list.name  = QStringLiteral("DiscoveredNodeList [2]");
            list.value = QString();
            {
                MsduFieldNode n0;
                n0.name  = QStringLiteral("DiscoveredSTATEI[0]");
                n0.value = QStringLiteral("TEI=1 ReceivedDiscoverCount=57");
                list.children.append(n0);
            }
            mme.children.append(list);
        }
        e.msdu.tree.append(mme);
    }

    ProtocolTree tree;
    tree.resize(600, 400);
    tree.show();
    tree.show_packet(e);

    // 模拟用户点击字段:验证 range_selected 信号携带的字节范围
    struct Range { int s = -1, l = 0; } got;
    QObject::connect(&tree, &ProtocolTree::range_selected,
                     [&](int s, int l) { got.s = s; got.l = l; });
    tree.expandAll();
    app.processEvents();

    // "Frame" -> child "MPDU Base"(index 1) -> child "Net ID"(index 2)
    QTreeWidgetItem* root = tree.topLevelItem(0);
    QTreeWidgetItem* base = root ? root->child(1) : nullptr;
    QTreeWidgetItem* nid  = base ? base->child(2) : nullptr;
    if (nid) {
        tree.clearSelection();
        tree.setCurrentItem(nid);   // 模拟鼠标点击:current+selection 同步
        app.processEvents();
    }
    std::printf("clicked 'Net ID' -> range_selected(%d, %d)  expected (1, 3)\n",
                got.s, got.l);
    bool range_ok = (got.s == 1 && got.l == 3);

    // 验证 HexView 高亮:highlight_range(1,3) 应产生 3 个字节的 extra selection
    HexView hex;
    hex.resize(600, 300);
    hex.show();
    hex.set_data(e.raw_bytes);
    app.processEvents();
    hex.highlight_range(1, 3);
    app.processEvents();
    int nsel = hex.extraSelections().size();
    std::printf("HexView highlight_range(1,3) -> %d extra selections, expected 3\n", nsel);

    // 字符级验证:第 1-3 字节应高亮 0xd5 0xa1 0xcd 的 hex 字符
    // (raw_bytes[0]=0x01 FrameType,故字节 1-3 = d5 a1 cd)
    // 行格式 "0000  01 d5 a1 cd ...",字节 j 的 hex 起点 = 6 + j*3
    QString doc = hex.toPlainText();
    QString picked;
    for (int b = 1; b <= 3; ++b) {
        int row = b / 16, col = b % 16;
        int pos = row * 73 + 6 + col * 3 + (col >= 8 ? 1 : 0);
        picked += doc.mid(pos, 2);
    }
    std::printf("picked hex chars: '%s' (expect 'd5a1cd')\n", qPrintable(picked));
    bool hl_pos_ok = (nsel == 3 && picked == "d5a1cd");

    // 多区间高亮(跨块字段)+ 复制字节:highlight_ranges 两段 + set_copy_bytes
    hex.highlight_ranges({{1, 3}, {8, 2}});
    app.processEvents();
    int nsel2 = hex.extraSelections().size();
    hex.set_copy_bytes(QByteArray::fromHex("0102030405"));
    QByteArray cpy = hex.copy_bytes();
    std::printf("HexView highlight_ranges(2段) -> %d selections (expect 5), copy=%dB (expect 5)\n",
                nsel2, (int)cpy.size());
    bool hl_multi_ok = (nsel2 == 5 && cpy.size() == 5);

    bool hl_ok = hl_pos_ok && hl_multi_ok;

    int top = tree.topLevelItemCount();
    int all = 0;
    auto count_all = [&](auto&& self, QTreeWidgetItem* it) -> void {
        ++all;
        for (int i = 0; i < it->childCount(); ++i)
            self(self, it->child(i));
    };
    for (int i = 0; i < top; ++i) count_all(count_all, tree.topLevelItem(i));

    std::printf("ProtocolTree topLevel=%d totalItems=%d\n", top, all);
    if (top > 0) {
        std::printf("  root[0]: '%s' = '%s'\n",
                    qPrintable(tree.topLevelItem(0)->text(0)),
                    qPrintable(tree.topLevelItem(0)->text(1)));
    }
    // 验证 MSDU 字段树已渲染(SOF 分组下应有 MSDU 节点及其 MMe 子字段)
    bool msdu_ok = false;
    bool mme_ok  = false;
    if (root) {
        for (int i = 0; i < root->childCount(); ++i) {
            QTreeWidgetItem* c = root->child(i);
            if (c && c->text(0).startsWith("MSDU")) {
                for (int j = 0; j < c->childCount(); ++j) {
                    QTreeWidgetItem* g = c->child(j);
                    if (g && g->text(0).contains("MMeDiscoverNodeList")) mme_ok = true;
                }
                msdu_ok = true;
            }
        }
    }
    std::printf("MSDU node rendered: %s, MMe child rendered: %s\n",
                msdu_ok ? "yes" : "NO", mme_ok ? "yes" : "NO");
    bool ok = (top >= 1 && all >= 10 && range_ok && hl_ok && msdu_ok && mme_ok);
    std::printf(ok ? "PASS\n" : "FAIL\n");

    // ---- 第二段:真实链路验证 ----
    // 读 replay_test.bin,逐帧 GW_2022_Parser::parse,SOF 帧经 make_entry 同款
    // 拷贝(PacketEntry.msdu = r.msdu)后渲染,断言协议树出现 MSDU 字段。
    std::printf("\n--- 真实链路:replay_test.bin -> parse -> PacketEntry -> ProtocolTree ---\n");
    QFile f(kSamples + QStringLiteral("/replay_test.bin"));
    bool real_ok = false;
    int msdu_hl_ok = -1;   // -1=未测 0=无高亮 1=高亮区间有效
    if (f.open(QIODevice::ReadOnly)) {
        QByteArray buf = f.readAll();
        GW_2022_Parser parser;
        MsduState  msdu_state;
        GW_2022_Parser::Filter f0;
        f0.allow_beacon = f0.allow_sof = f0.allow_ack = f0.allow_coord = true;
        f0.link_hplc = f0.link_hrf = true;

        // 哨兵切帧 + 反转义
        int sof_found = 0;
        bool rendering_ok = true;
        while (!buf.isEmpty()) {
            int idx = buf.indexOf(char(0x3C));
            if (idx < 0) break;
            buf.remove(0, idx + 1);
            idx = buf.indexOf(char(0x3E));
            if (idx < 0) break;
            QByteArray esc = buf.left(idx);
            buf.remove(0, idx + 1);
            QByteArray unesc;
            for (int i = 0; i < esc.size(); ++i) {
                quint8 b = (quint8)esc[i];
                if (b == 0x3D && i + 1 < esc.size()) {
                    ++i;
                    unesc.append(char(0xFF ^ (quint8)esc[i]));
                } else {
                    unesc.append(char(b));
                }
            }
            BplcFrame fr;
            fr.data = unesc;
            fr.meta.has_time_tag = false;
            auto r = parser.parse(fr, msdu_state, f0);
            if (!r.accept || r.mpdu.frame_type != 1) continue;
            if (!r.msdu.present) continue;

            // 与 MainWindow::make_entry 相同的字段拷贝路径
            PacketEntry pe;
            pe.index     = ++sof_found;
            pe.accepted  = true;
            pe.meta      = r.meta;
            pe.mpdu      = r.mpdu;
            pe.msdu_body = r.msdu_body;
            pe.msdu      = r.msdu;
            pe.msdu_raw_base = r.msdu_raw_base;
            pe.raw_bytes = r.payload_for_log;

            ProtocolTree t2;
            t2.resize(700, 500);
            t2.show();
            t2.show_packet(pe);
            app.processEvents();

            // 深度扫描整棵协议树,查找 MSDU 字段行(如 "STATEI [12b]" / "MMe:")
            bool has_msdu_node = false, has_mme_field = false;
            auto scan = [&](auto&& self, QTreeWidgetItem* it) -> void {
                if (it->text(0).startsWith(QStringLiteral("MSDU"))) has_msdu_node = true;
                if (it->text(0).contains(QStringLiteral("MMe:"))
                    || it->text(0).contains(QStringLiteral("StateTEI"))
                    || it->text(0).contains(QStringLiteral("STATEI"))
                    || it->text(0).startsWith(QStringLiteral("MSDUType"))) has_mme_field = true;
                for (int i = 0; i < it->childCount(); ++i) self(self, it->child(i));
            };
            for (int i = 0; i < t2.topLevelItemCount(); ++i) scan(scan, t2.topLevelItem(i));
            if (!has_msdu_node || !has_mme_field) rendering_ok = false;

            // MSDU 高亮验证:首帧点 MMe 叶子字段(如 STATEI)置 msdu_hl_ok=2,
            // 之后若遇到 APP 帧则点 EventPacket Payload,成功置 1(全通过)。
            auto click_first = [&](const QStringList& patterns,
                                   ProtocolTree* tree) -> bool {
                struct { int s = -1, l = 0; } hl;
                QObject::connect(tree, &ProtocolTree::range_selected,
                                 [&](int s, int l) { hl.s = s; hl.l = l; });
                QTreeWidgetItem* target = nullptr;
                auto find_leaf = [&](auto&& self, QTreeWidgetItem* it) -> QTreeWidgetItem* {
                    if (!target && it->data(0, Qt::UserRole).toInt() >= 0
                        && !it->text(0).startsWith(QStringLiteral("MSDU"))
                        && !it->text(0).isEmpty()) {
                        for (const auto& p : patterns)
                            if (it->text(0).contains(p)) { target = it; return it; }
                    }
                    for (int i = 0; i < it->childCount(); ++i) {
                        QTreeWidgetItem* r = self(self, it->child(i));
                        if (r) return r;
                    }
                    return nullptr;
                };
                for (int i = 0; i < tree->topLevelItemCount() && !target; ++i)
                    target = find_leaf(find_leaf, tree->topLevelItem(i));
                if (!target) return false;
                tree->clearSelection();
                tree->setCurrentItem(target);
                app.processEvents();
                return (hl.s >= 17 && hl.l > 0);
            };

            bool is_app = r.msdu.summary.startsWith(QStringLiteral("APP"));
            if (msdu_hl_ok == -1 || is_app) {
                if (msdu_hl_ok == -1) {
                    // 第一帧:先验证点击 MSDU 分组 → 高亮整个 MSDU 帧
                    {
                        struct { int s = -1, l = 0; } hl2;
                        QObject::connect(&t2, &ProtocolTree::range_selected,
                                         [&](int s, int l) { hl2.s = s; hl2.l = l; });
                        QTreeWidgetItem* mi = nullptr;
                        std::function<void(QTreeWidgetItem*)> find_msdu =
                            [&](QTreeWidgetItem* it) {
                                if (mi) return;
                                if (it->text(0)
                                        .startsWith(QStringLiteral("MSDU"))) {
                                    mi = it;
                                    return;
                                }
                                for (int c = 0; c < it->childCount(); ++c)
                                    find_msdu(it->child(c));
                            };
                        for (int i = 0; i < t2.topLevelItemCount() && !mi; ++i)
                            find_msdu(t2.topLevelItem(i));
                        bool ok2 = false;
                        if (mi) {
                            t2.setCurrentItem(mi);
                            app.processEvents();
                            ok2 = (hl2.s == pe.msdu_raw_base
                                   && hl2.l == r.msdu.total_len
                                   && hl2.l > 0);
                            std::printf("  MSDU 分组点击 -> range(%d,%d) 期望(%d,%d) %s\n",
                                        hl2.s, hl2.l, pe.msdu_raw_base,
                                        r.msdu.total_len,
                                        ok2 ? "OK" : "FAIL");
                        }
                        if (!ok2) msdu_hl_ok = 0;
                        if (ok2) {
                            // 分组点击通过后再点 MMe 叶子字段
                            bool ok = click_first({QStringLiteral("STATEI"),
                                                   QStringLiteral("NetID")}, &t2);
                            std::printf("  MSDU 字段点击(MMe) -> %s\n",
                                        ok ? "range 有效" : "无高亮");
                            msdu_hl_ok = ok ? 2 : 0;   // 2 = MMe 已过,等 APP

                            // 校验 PB Body / PB Padding / PB CRC24 行存在(含高亮区间)
                            {
                                bool has_body=false, has_pad=false, has_crc=false;
                                std::function<void(QTreeWidgetItem*)> scan_pb =
                                    [&](QTreeWidgetItem* it) {
                                        QString t = it->text(0);
                                        if (t.startsWith(QStringLiteral("PB Body")))
                                            has_body = true;
                                        if (t.startsWith(QStringLiteral("PB Padding")))
                                            has_pad = true;
                                        if (t.startsWith(QStringLiteral("PB CRC24")))
                                            has_crc = true;
                                        for (int c = 0; c < it->childCount(); ++c)
                                            scan_pb(it->child(c));
                                    };
                                for (int i = 0; i < t2.topLevelItemCount(); ++i)
                                    scan_pb(t2.topLevelItem(i));
                                std::printf("  PB 行: Body=%s Padding=%s CRC24=%s\n",
                                            has_body ? "yes" : "NO",
                                            has_pad ? "yes" : "NO",
                                            has_crc ? "yes" : "NO");
                                if (!has_body || !has_pad || !has_crc) {
                                    msdu_hl_ok = 0;
                                    rendering_ok = false;
                                }
                            }
                        }
                    }
                } else if (is_app && msdu_hl_ok == 2) {
                    // 遇到 APP 帧:点 EventPacket Payload
                    bool ok = click_first({QStringLiteral("Payload")}, &t2);
                    std::printf("  EventPacket Payload 点击 -> %s\n",
                                ok ? "range 有效" : "无高亮");
                    msdu_hl_ok = ok ? 1 : 0;   // 1 = MMe+APP 全通过
                }
            }
            // 首帧已点(msdu_hl_ok 2/0)。结论未定则继续找 APP 帧点 Payload;
            // 上限 40 个 SOF 防无 APP 数据时全量解析过久。
            if (msdu_hl_ok == 1 || msdu_hl_ok == 0 || sof_found >= 40) break;
        }
        real_ok = (sof_found >= 1 && rendering_ok && msdu_hl_ok == 1);
        std::printf("真实链路:解析出 %d 个 SOF(含完整 MSDU),渲染 %s,MSDU 高亮 %s\n",
                    sof_found, rendering_ok ? "正常" : "异常",
                    msdu_hl_ok == 1 ? "生效" : (msdu_hl_ok == 0 ? "无" : "未测"));
    } else {
        std::printf("无法打开 replay_test.bin(跳过真实链路验证)\n");
        real_ok = true;   // 文件缺失不判 FAIL(离屏部分已覆盖)
    }

    // ---- 第三段:显示过滤器验证 ----
    // 全量解析 replay_test.bin(全部帧类型)填入 PacketListModel,
    // 依次应用若干过滤词,断言 rowCount 与期望一致。
    std::printf("\n--- 显示过滤器验证 ---\n");
    bool filter_ok = true;
    {
        QFile ff(kSamples + QStringLiteral("/replay_test.bin"));
        if (ff.open(QIODevice::ReadOnly)) {
            QByteArray buf = ff.readAll();
            GW_2022_Parser parser;
            MsduState  msdu_state;
            GW_2022_Parser::Filter f0;
            f0.allow_beacon = f0.allow_sof = f0.allow_ack = f0.allow_coord = true;
            f0.link_hplc = f0.link_hrf = true;

            PacketListModel model;
            int n_all = 0;
            while (!buf.isEmpty()) {
                int idx = buf.indexOf(char(0x3C));
                if (idx < 0) break;
                buf.remove(0, idx + 1);
                idx = buf.indexOf(char(0x3E));
                if (idx < 0) break;
                QByteArray esc = buf.left(idx);
                buf.remove(0, idx + 1);
                QByteArray unesc;
                for (int i = 0; i < esc.size(); ++i) {
                    quint8 b = (quint8)esc[i];
                    if (b == 0x3D && i + 1 < esc.size()) {
                        ++i;
                        unesc.append(char(0xFF ^ (quint8)esc[i]));
                    } else {
                        unesc.append(char(b));
                    }
                }
                BplcFrame fr;
                fr.data = unesc;
                fr.meta.has_time_tag = false;
                auto r = parser.parse(fr, msdu_state, f0);
                if (!r.accept) continue;
                PacketEntry pe;
                pe.index     = ++n_all;
                pe.accepted  = true;
                pe.meta      = r.meta;
                pe.mpdu      = r.mpdu;
                pe.msdu_body = r.msdu_body;
                pe.msdu      = r.msdu;
                pe.msdu_raw_base = r.msdu_raw_base;
                pe.raw_bytes = r.payload_for_log;
                model.append_packet(pe);
            }
            int total_rows = model.rowCount();
            auto rows_with = [&](const QString& expr) -> int {
                model.set_display_filter(expr);
                while (model.filtering()) app.processEvents();  // 等待异步过滤完成
                return model.rowCount();
            };
            // 期望值基于 Python 权威分布(871/347/170/1069)
            struct { const char* f; int expect; const char* why; } cases[] = {
                {"beacon", 871, "帧类型名"},
                {"sof",    347, "帧类型名"},
                {"ack",    170, "帧类型名"},
                {"coord", 1069, "帧类型名"},
                {"0xcda1d5", 2457, "NetID(0x 前缀)"},
                {"cda1d5", 2457, "NetID(裸 hex)"},
                {"discoverynodelist", 117, "MSDU 类型名"},
                {"heartbeat",       189, "MSDU 类型名"},
                {"hplc",  2457, "链路名"},
                {"cccc", 0, "无匹配"},
                {"sof | coord", 347 + 1069, "OR 多条件"},
            };
            for (const auto& c : cases) {
                int got = rows_with(QLatin1String(c.f));
                bool okc = (got == c.expect);
                std::printf("  filter '%-14s' -> %5d (expect %5d) %s [%s]\n",
                            c.f, got, c.expect, okc ? "OK" : "FAIL", c.why);
                if (!okc) filter_ok = false;
            }
            // 验证 MSDU Type 列:SOF 行非空、BEACON 行为空
            rows_with(QString());   // 清除过滤
            {
                bool sof_has_msdu = false, bcn_empty = true;
                for (int row = 0; row < model.rowCount(); ++row) {
                    QString ft = model.data(model.index(row, PacketListModel::COL_FRAME_TYPE)).toString();
                    QString mt = model.data(model.index(row, PacketListModel::COL_MSDU_TYPE)).toString();
                    if (ft == "SOF" && !mt.isEmpty()) sof_has_msdu = true;
                    if (ft == "BEACON" && !mt.isEmpty()) bcn_empty = false;
                }
                std::printf("  MSDU Type 列: SOF 行有值=%s, BEACON 行为空=%s\n",
                            sof_has_msdu ? "yes" : "NO",
                            bcn_empty ? "yes" : "NO");
                if (!sof_has_msdu || !bcn_empty) filter_ok = false;
            }
            std::printf("  总帧数=%d\n", total_rows);
        } else {
            std::printf("  无法打开 replay_test.bin(跳过过滤验证)\n");
        }
    }

    // ---- 第四段:多 PB 块重组验证(合成 2 块 SOF 帧) ----
    // 回放样本全部 PBNum=1;此处合成一条跨 2 块(136B×2)的 SOF,
    // 验证 parse_sof_and_assemble 的 START/END/seq 重组与 Python 权威逻辑一致。
    std::printf("\n--- 多 PB 块重组验证 ---\n");
    bool multi_ok = true;
    {
        // 与 GW_2022_Parser 内部同款 CRC24(0xC60001 poly,遍历 len-3)
        auto crc24 = [](const quint8* d, int len) -> quint32 {
            quint32 reg = 0;
            const quint32 poly = 0xC60001;
            for (int i = 0; i < len - 3; ++i)
                for (int j = 0; j < 8; ++j) {
                    quint32 b = ((d[i] >> j) & 1) ^ (reg & 1);
                    reg = b ? ((reg >> 1) ^ poly) : (reg >> 1);
                }
            return reg;
        };
        auto crc32 = [](const quint8* d, int len) -> quint32 {
            quint32 reg = 0xFFFFFFFF;
            const quint32 poly = 0xEDB88320;
            for (int i = 0; i < len - 4; ++i)
                for (int j = 0; j < 8; ++j) {
                    quint32 b = ((d[i] >> j) & 1) ^ (reg & 1);
                    reg = b ? ((reg >> 1) ^ poly) : (reg >> 1);
                }
            return ~reg;
        };
        auto set_bits = [](quint8* d, int byte, int bit, int len, quint64 v) {
            for (int i = 0; i < len; ++i)
                if ((v >> i) & 1) d[byte] |= quint8(1u << (bit + i));
        };

        // ---- 构造 MSDU 帧:28B MSDU_BASE 头 + 150B 数据 + 4B CRC32 = 182B ----
        QByteArray msdu(182, 0);
        quint8* m = reinterpret_cast<quint8*>(msdu.data());
        set_bits(m, 0, 0, 4, 0);              // Version
        set_bits(m, 0, 4, 12, 3);             // SourceTEI
        set_bits(m, 2, 0, 12, 4095);          // DestinationTEI
        set_bits(m, 3, 4, 4, 0);              // SendType 单播
        set_bits(m, 5, 0, 16, 0x5566);        // MSDU Seq
        set_bits(m, 7, 0, 8, 0);              // MSDUType = 0(Net Mgmt)
        set_bits(m, 8, 0, 11, 150);           // MSDULen
        set_bits(m, 9, 3, 1, 0);              // RestartCount
        set_bits(m, 11, 3, 1, 1);             // MACAddrFlag=1(头 28B)
        set_bits(m, 13, 0, 8, 0x1E);          // NetSN
        for (int i = 28; i < 28 + 150; ++i)   // 数据区:伪 MMe 内容
            m[i] = quint8(0xA0 + (i % 16));
        quint32 c32 = crc32(m + 28, 150 + 4);
        m[28 + 150 + 0] = quint8(c32);
        m[28 + 150 + 1] = quint8(c32 >> 8);
        m[28 + 150 + 2] = quint8(c32 >> 16);
        m[28 + 150 + 3] = quint8(c32 >> 24);

        // ---- 构造 MPDU:FCH 16B + PB0 136B + PB1 136B = 288B ----
        // tmi=4 → pbsize 136,每块数据 132B;MSDU 182B 跨两块(132+50)
        const int pbsize = 136;
        QByteArray mpdu(16 + 2 * pbsize, 0);
        quint8* fch = reinterpret_cast<quint8*>(mpdu.data());
        set_bits(fch, 0, 0, 3, 1);            // FrameType = SOF
        set_bits(fch, 1, 0, 24, 0xCDA1D5);    // NetID
        set_bits(fch, 4, 0, 12, 3);           // SourceTEI
        set_bits(fch, 5, 4, 12, 4095);        // DestinationTEI
        set_bits(fch, 9, 4, 4, 2);            // PBNum = 2(两物理块)
        set_bits(fch, 11, 4, 4, 4);           // TMI = 4(136B)
        set_bits(fch, 12, 0, 4, 0);           // TMI_EXT
        quint32 fcr = crc24(fch, 16);         // FCH CRC24 → byte13..15
        fch[13] = quint8(fcr);
        fch[14] = quint8(fcr >> 8);
        fch[15] = quint8(fcr >> 16);

        // 块 0:START seq0;块 1:END seq1
        quint8* blk0 = reinterpret_cast<quint8*>(mpdu.data()) + 16;
        blk0[0] = 0x40;                        // START, seq=0
        std::copy(msdu.constData(), msdu.constData() + 132, blk0 + 1);
        quint32 b0 = crc24(blk0, pbsize);
        blk0[133] = quint8(b0);
        blk0[134] = quint8(b0 >> 8);
        blk0[135] = quint8(b0 >> 16);

        quint8* blk1 = blk0 + pbsize;
        blk1[0] = 0x80 | 1;                    // END, seq=1
        std::copy(msdu.constData() + 132, msdu.constData() + 182, blk1 + 1);
        std::fill(blk1 + 1 + 50, blk1 + 133, 0x00);   // 余下 82B 填充
        quint32 b1 = crc24(blk1, pbsize);
        blk1[133] = quint8(b1);
        blk1[134] = quint8(b1 >> 8);
        blk1[135] = quint8(b1 >> 16);

        // ---- 封装为输入帧(media 头 4B:phr/opt/ch/isRF=0)+MPDU ----
        BplcFrame fr;
        fr.meta.has_time_tag = false;
        QByteArray body;
        quint16 dlen = quint16(mpdu.size() + 6);
        body.append(char(dlen & 0xFF));
        body.append(char(dlen >> 8));
        body.append(char(0)); body.append(char(0));
        body.append(char(0)); body.append(char(0));
        body.append(char(0));                  // phr
        body.append(char(0));                  // opt
        body.append(char(0));                  // ch
        body.append(char(0));                  // isRF = 0(PLC)
        body += mpdu;
        fr.data = body;

        GW_2022_Parser parser;
        MsduState  st;
        GW_2022_Parser::Filter f0;
        f0.allow_beacon = f0.allow_sof = f0.allow_ack = f0.allow_coord = true;
        f0.link_hplc = f0.link_hrf = true;
        auto rr = parser.parse(fr, st, f0);
        bool ok1 = rr.accept && rr.msdu.present
                   && rr.msdu.total_len == 182
                   && rr.msdu_body.size() == 2 * 132
                   && rr.msdu_raw_base == -1;   // 多块不连续 → 不高亮
        // 重组数据前 182B 必须与构造 MSDU 逐字节一致
        bool body_ok = rr.accept
            && rr.msdu_body.left(182) == msdu;
        // MSDU CRC32 应 OK(树节点值含 "OK")
        bool crc_ok = false;
        if (rr.msdu.present) {
            std::function<void(const MsduFieldNode&)> scan_crc =
                [&](const MsduFieldNode& nd) {
                    if (nd.name.startsWith(QStringLiteral("MSDU CRC32"))
                        && nd.value.contains(QStringLiteral("OK")))
                        crc_ok = true;
                    for (const auto& c : nd.children) scan_crc(c);
                };
            for (const auto& n : rr.msdu.tree) scan_crc(n);
        }
        multi_ok = ok1 && body_ok && crc_ok;
        std::printf("  合成 2 块 SOF: accept=%d present=%d total_len=%lld "
                    "msdu_body=%lld raw_base=%d\n",
                    rr.accept, rr.msdu.present, (long long)rr.msdu.total_len,
                    (long long)rr.msdu_body.size(), rr.msdu_raw_base);
        std::printf("  重组字节一致=%s, MSDU CRC32 OK=%s, PB CRC24=%s\n",
                    body_ok ? "yes" : "NO",
                    crc_ok ? "yes" : "NO",
                    rr.mpdu.pb_crc_ok ? "yes" : "NO");
        if (!multi_ok) { filter_ok = false; }

        // ---- 负例:乱序(块1 先于块0)→ 应判定重组失败 ----
        {
            QByteArray mpdu2(16 + 2 * pbsize, 0);
            quint8* f2 = reinterpret_cast<quint8*>(mpdu2.data());
            set_bits(f2, 0, 0, 3, 1);
            set_bits(f2, 1, 0, 24, 0xCDA1D5);
            set_bits(f2, 9, 4, 4, 2);
            set_bits(f2, 11, 4, 4, 4);
            quint32 f2c = crc24(f2, 16);
            f2[13] = quint8(f2c); f2[14] = quint8(f2c >> 8);
            f2[15] = quint8(f2c >> 16);
            quint8* a = reinterpret_cast<quint8*>(mpdu2.data()) + 16;
            quint8* b = a + pbsize;
            std::memcpy(a, blk1, pbsize);   // 块 1(END seq1)在前
            std::memcpy(b, blk0, pbsize);   // 块 0(START)在后
            BplcFrame fr2;
            fr2.meta.has_time_tag = false;
            QByteArray body2;
            quint16 d2 = quint16(mpdu2.size() + 6);
            body2.append(char(d2 & 0xFF));
            body2.append(char(d2 >> 8));
            body2.append(char(0)); body2.append(char(0));
            body2.append(char(0)); body2.append(char(0));
            body2.append(char(0)); body2.append(char(0));
            body2.append(char(0)); body2.append(char(0));
            body2 += mpdu2;
            fr2.data = body2;
            GW_2022_Parser p2;
            MsduState st2;
            auto r2 = p2.parse(fr2, st2, f0);
            // 乱序块被丢弃 → MSDU 未完成(不 present)
            bool neg_ok = !r2.msdu.present;
            std::printf("  乱序负例(END 块在前): present=%d(期望 0) %s\n",
                        r2.msdu.present, neg_ok ? "OK" : "FAIL");
            if (!neg_ok) { filter_ok = false; }
        }
    }

    // ---- 第五段:改造报文(multi72_2pb.bin)双 PB 72B 解析验证 ----
    // 由 unit_test/manual/rework_two_pb.py 生成:单块 136B 原帧去掉 padding 后
    // 改造为两块 72B(TMI=13),MSDU 帧 73B 跨块;验证字段可完整解析。
    std::printf("\n--- 改造报文(两块72B)解析验证 ---\n");
    {
        QFile ff(kSamples + QStringLiteral("/multi72_2pb.bin"));
        bool f72_ok = false;
        if (ff.open(QIODevice::ReadOnly)) {
            QByteArray buf = ff.readAll();
            int idx = buf.indexOf(char(0x3C));
            buf.remove(0, idx + 1);
            idx = buf.indexOf(char(0x3E));
            QByteArray esc = buf.left(idx);
            QByteArray unesc;
            for (int i = 0; i < esc.size(); ++i) {
                quint8 b = (quint8)esc[i];
                if (b == 0x3D && i + 1 < esc.size()) {
                    ++i;
                    unesc.append(char(0xFF ^ (quint8)esc[i]));
                } else {
                    unesc.append(char(b));
                }
            }
            GW_2022_Parser parser;
            MsduState  msdu_state;
            GW_2022_Parser::Filter f0;
            f0.allow_beacon = f0.allow_sof = f0.allow_ack = f0.allow_coord = true;
            f0.link_hplc = f0.link_hrf = true;
            BplcFrame fr;
            fr.data = unesc;
            fr.meta.has_time_tag = false;
            auto r = parser.parse(fr, msdu_state, f0);
            // MSDU CRC32 校验
            bool crc_ok = false;
            if (r.msdu.present) {
                std::function<void(const MsduFieldNode&)> sc =
                    [&](const MsduFieldNode& nd) {
                        if (nd.name.startsWith(QStringLiteral("MSDU CRC32"))
                            && nd.value.contains(QStringLiteral("OK")))
                            crc_ok = true;
                        for (const auto& c : nd.children) sc(c);
                    };
                for (const auto& n : r.msdu.tree) sc(n);
            }
            f72_ok = r.accept && r.mpdu.pb_num == 2 && r.msdu.present
                     && r.msdu.total_len == 73
                     && r.msdu.summary == QStringLiteral("MMeDiscoveryNodeList")
                     && crc_ok;
            // 字段内容完整性:统计树中关键字段行是否存在
            int n_nodes = 0;
            bool has_mmtype=false, has_statei=false, has_uproute=false,
                 has_bmp=false, has_rcv=false, has_rsv1=false;
            std::function<void(const MsduFieldNode&)> walk =
                [&](const MsduFieldNode& nd) {
                    ++n_nodes;
                    if (nd.name.contains(QStringLiteral("MMType"))) has_mmtype = true;
                    if (nd.name.contains(QStringLiteral("STATEI")))  has_statei = true;
                    if (nd.name.contains(QStringLiteral("UpRoute"))) has_uproute = true;
                    if (nd.name.contains(QStringLiteral("BitMap")))  has_bmp = true;
                    if (nd.name.contains(QStringLiteral("ReceivedDiscoveryInfo")))
                        has_rcv = true;
                    if (nd.name == QStringLiteral("RSV1 [24b]"))    has_rsv1 = true;
                    for (const auto& c : nd.children) walk(c);
                };
            for (const auto& n : r.msdu.tree) walk(n);
            f72_ok = f72_ok && has_mmtype && has_statei && has_uproute
                     && has_bmp && has_rcv && has_rsv1 && n_nodes > 40;
            std::printf("  字段树: 节点数=%d MMType=%s STATEI=%s UpRoute=%s "
                        "BitMap=%s ReceivedInfo=%s RSV1[24b]=%s\n",
                        n_nodes, has_mmtype ? "yes" : "NO",
                        has_statei ? "yes" : "NO",
                        has_uproute ? "yes" : "NO",
                        has_bmp ? "yes" : "NO",
                        has_rcv ? "yes" : "NO",
                        has_rsv1 ? "yes" : "NO");
            // UI 树渲染:两块 Header/Body/CRC24 均应出现
            {
                ProtocolTree t5;
                PacketEntry pe5;
                pe5.index = 1;
                pe5.accepted = true;
                pe5.meta = r.meta;
                pe5.mpdu = r.mpdu;
                pe5.msdu_body = r.msdu_body;
                pe5.msdu = r.msdu;
                pe5.msdu_raw_base = r.msdu_raw_base;
                pe5.raw_bytes = r.payload_for_log;
                t5.show_packet(pe5);
                bool hdr0=false,hdr1=false,crc0=false,crc1=false,pad1=false;
                std::function<void(QTreeWidgetItem*)> walk5 =
                    [&](QTreeWidgetItem* it) {
                        QString t = it->text(0);
                        if (t.startsWith(QStringLiteral("PB Header (0/2)"))) hdr0 = true;
                        if (t.startsWith(QStringLiteral("PB Header (1/2)"))) hdr1 = true;
                        if (t == QStringLiteral("PB CRC24 (block 0/2)")) crc0 = true;
                        if (t == QStringLiteral("PB CRC24 (block 1/2)")) crc1 = true;
                        if (t == QStringLiteral("PB Padding")) pad1 = true;
                        for (int c = 0; c < it->childCount(); ++c)
                            walk5(it->child(c));
                    };
                for (int i = 0; i < t5.topLevelItemCount(); ++i)
                    walk5(t5.topLevelItem(i));
                std::printf("  UI 树: Header(0/2)=%s Header(1/2)=%s "
                            "CRC24(0/2)=%s CRC24(1/2)=%s Padding=%s\n",
                            hdr0 ? "yes" : "NO", hdr1 ? "yes" : "NO",
                            crc0 ? "yes" : "NO", crc1 ? "yes" : "NO",
                            pad1 ? "yes" : "NO");
                f72_ok = f72_ok && hdr0 && hdr1 && crc0 && crc1 && pad1;
            }
            std::printf("  accept=%d PBNum=%d pbsize=%d pb_crc_ok=%s\n",
                        r.accept, r.mpdu.pb_num, r.mpdu.pb_size,
                        r.mpdu.pb_crc_ok ? "yes" : "NO");
            std::printf("  MSDU: present=%d summary=%s total_len=%lld "
                        "msdu_body=%lld raw_base=%d MSDU CRC=%s\n",
                        r.msdu.present,
                        qPrintable(r.msdu.summary),
                        (long long)r.msdu.total_len, (long long)r.msdu_body.size(),
                        r.msdu_raw_base, crc_ok ? "OK" : "FAIL");
        } else {
            std::printf("  无法打开 multi72_2pb.bin(跳过)\n");
        }
        if (!f72_ok) { filter_ok = false; }
    }

    // ---- 第六段:PB 字段点击后再点其它字段的高亮连续性 ----
    // 复现"点击 PB 字段后,再点其它字段不高亮"的场景
    std::printf("\n--- PB 点击后连续高亮验证 ---\n");
    {
        QFile ff(kSamples + QStringLiteral("/replay_test.bin"));
        bool seq_ok = false;
        if (ff.open(QIODevice::ReadOnly)) {
            QByteArray buf = ff.readAll();
            GW_2022_Parser parser;
            MsduState  msdu_state;
            GW_2022_Parser::Filter f0;
            f0.allow_beacon = f0.allow_sof = f0.allow_ack = f0.allow_coord = true;
            f0.link_hplc = f0.link_hrf = true;
            BplcFrame fr;
            QByteArray first_sof;
            while (!buf.isEmpty()) {
                int i0 = buf.indexOf(char(0x3C));
                if (i0 < 0) break;
                buf.remove(0, i0 + 1);
                int i1 = buf.indexOf(char(0x3E));
                if (i1 < 0) break;
                QByteArray esc = buf.left(i1);
                buf.remove(0, i1 + 1);
                QByteArray unesc;
                for (int i = 0; i < esc.size(); ++i) {
                    quint8 b = (quint8)esc[i];
                    if (b == 0x3D && i + 1 < esc.size()) {
                        ++i;
                        unesc.append(char(0xFF ^ (quint8)esc[i]));
                    } else {
                        unesc.append(char(b));
                    }
                }
                fr.data = unesc;
                fr.meta.has_time_tag = false;
                auto r0 = parser.parse(fr, msdu_state, f0);
                if (r0.accept && r0.mpdu.frame_type == 1) {
                    // 首帧单块 SOF → 渲染并模拟点击序列
                    ProtocolTree t6;
                    PacketEntry pe6;
                    pe6.index = 1;
                    pe6.accepted = true;
                    pe6.meta = r0.meta;
                    pe6.mpdu = r0.mpdu;
                    pe6.msdu_body = r0.msdu_body;
                    pe6.msdu = r0.msdu;
                    pe6.msdu_raw_base = r0.msdu_raw_base;
                    pe6.raw_bytes = r0.payload_for_log;
                    t6.show_packet(pe6);
                    // 收集连续 range_selected
                    struct R { int s = -2, l = -2; bool fired = false; };
                    R last;
                    QObject::connect(&t6, &ProtocolTree::range_selected,
                                     [&](int s, int l) {
                                         last.s = s; last.l = l; last.fired = true;
                                     });
                    // 目标字段序列:名称前缀 → 期望名称
                    struct T { const char* prefix; int exp_s; int exp_l; };
                    std::function<QTreeWidgetItem*(QTreeWidgetItem*)> find_any =
                        [&](QTreeWidgetItem* it) -> QTreeWidgetItem* {
                            for (int c = 0; c < it->childCount(); ++c) {
                                QTreeWidgetItem* r = find_any(it->child(c));
                                if (r) return r;
                            }
                            return nullptr;
                        };
                    auto find_first = [&](const QString& prefix) -> QTreeWidgetItem* {
                        QTreeWidgetItem* found = nullptr;
                        std::function<void(QTreeWidgetItem*)> dfs =
                            [&](QTreeWidgetItem* it) {
                                if (found) return;
                                if (it->text(0).startsWith(prefix)) {
                                    found = it;
                                    return;
                                }
                                for (int c = 0; c < it->childCount(); ++c)
                                    dfs(it->child(c));
                            };
                        for (int i = 0; i < t6.topLevelItemCount(); ++i)
                            dfs(t6.topLevelItem(i));
                        return found;
                    };
                    bool all_ok = true;
                    QStringList clicks = {
                        QStringLiteral("PB Header"),
                        QStringLiteral("PB CRC24"),
                        QStringLiteral("PB Body"),
                        QStringLiteral("MSDU (Reassembled)"),
                        QStringLiteral("MSDU CRC32"),
                        QStringLiteral("STATEI"),
                        QStringLiteral("RSV1 [12b]"),
                        QStringLiteral("Net ID"),
                    };
                    for (const QString& pfx : clicks) {
                        last.fired = false;
                        QTreeWidgetItem* it = find_first(pfx);
                        if (!it) {
                            std::printf("  click '%-20s' 未找到节点\n",
                                        qPrintable(pfx));
                            continue;
                        }
                        t6.clearSelection();
                        t6.setCurrentItem(it);
                        app.processEvents();
                        QString ok = (!last.fired)
                            ? "NO-SIGNAL" : "range(" +
                                QString::number(last.s) + "," +
                                QString::number(last.l) + ")";
                        if (!last.fired || last.l <= 0) all_ok = false;
                        std::printf("  click '%-20s' -> %s\n",
                                    qPrintable(pfx), qPrintable(ok));
                    }
                    seq_ok = all_ok;
                    break;
                }
            }
            // 双块帧:PB(1/2) 行与后续 MMe 字段点击
            {
                QFile f2(kSamples + QStringLiteral("/multi72_2pb.bin"));
                if (f2.open(QIODevice::ReadOnly)) {
                    QByteArray b2 = f2.readAll();
                    int i0 = b2.indexOf(char(0x3C));
                    b2.remove(0, i0 + 1);
                    int i1 = b2.indexOf(char(0x3E));
                    QByteArray esc2 = b2.left(i1);
                    QByteArray un2;
                    for (int i = 0; i < esc2.size(); ++i) {
                        quint8 bb = (quint8)esc2[i];
                        if (bb == 0x3D && i + 1 < esc2.size()) {
                            ++i;
                            un2.append(char(0xFF ^ (quint8)esc2[i]));
                        } else {
                            un2.append(char(bb));
                        }
                    }
                    GW_2022_Parser p6b;
                    MsduState s6b;
                    GW_2022_Parser::Filter f0b;
                    f0b.allow_beacon = f0b.allow_sof = f0b.allow_ack = f0b.allow_coord = true;
                    f0b.link_hplc = f0b.link_hrf = true;
                    BplcFrame fr6;
                    fr6.data = un2;
                    fr6.meta.has_time_tag = false;
                    auto r6b = p6b.parse(fr6, s6b, f0b);
                    if (r6b.accept) {
                        ProtocolTree t6b;
                        PacketEntry pe6b;
                        pe6b.index = 1;
                        pe6b.accepted = true;
                        pe6b.meta = r6b.meta;
                        pe6b.mpdu = r6b.mpdu;
                        pe6b.msdu_body = r6b.msdu_body;
                        pe6b.msdu = r6b.msdu;
                        pe6b.msdu_raw_base = r6b.msdu_raw_base;
                        pe6b.raw_bytes = r6b.payload_for_log;
                        t6b.show_packet(pe6b);
                        struct R2 { int s = -2, l = -2; bool fired = false; };
                        R2 last2;
                        QObject::connect(&t6b, &ProtocolTree::range_selected,
                                         [&](int s, int l) {
                                             last2.s = s; last2.l = l; last2.fired = true;
                                         });
                        QStringList clicks2 = {
                            QStringLiteral("PB Header (0/2)"),
                            QStringLiteral("PB CRC24 (block 1/2)"),
                            QStringLiteral("PB Body (1/2)"),
                            QStringLiteral("PB Padding"),
                            QStringLiteral("MSDU CRC32"),
                        };
                        bool okb = true;
                        for (const QString& pfx : clicks2) {
                            last2.fired = false;
                            QTreeWidgetItem* it = nullptr;
                            std::function<void(QTreeWidgetItem*)> dfs =
                                [&](QTreeWidgetItem* nd) {
                                    if (it) return;
                                    if (nd->text(0).startsWith(pfx)) {
                                        it = nd;
                                        return;
                                    }
                                    for (int c = 0; c < nd->childCount(); ++c)
                                        dfs(nd->child(c));
                                };
                            for (int i = 0; i < t6b.topLevelItemCount(); ++i)
                                dfs(t6b.topLevelItem(i));
                            if (!it) {
                                std::printf("  双块 click '%-24s' 未找到\n",
                                            qPrintable(pfx));
                                okb = false;
                                continue;
                            }
                            t6b.clearSelection();
                            t6b.setCurrentItem(it);
                            app.processEvents();
                            if (!last2.fired || last2.l <= 0) okb = false;
                            std::printf("  双块 click '%-24s' -> range(%d,%d)%s\n",
                                        qPrintable(pfx), last2.s, last2.l,
                                        (last2.fired && last2.l > 0) ? "" : " NO-SIGNAL");
                        }
                        if (!okb) seq_ok = false;
                    }
                }
            }
            std::printf("  连续点击序列: %s\n", seq_ok ? "全部有高亮" : "存在缺失");
        } else {
            std::printf("  无法打开 replay_test.bin(跳过)\n");
        }
        if (!seq_ok) { filter_ok = false; }
    }

    // ---- 导出回放 bin 往返验证:build_playback_bin → 重读 → 逐帧比对 ----
    std::printf("\n--- 导出回放 bin 往返验证 ---\n");
    bool export_ok = true;
    {
        QFile ff(kSamples + QStringLiteral("/replay_test.bin"));
        if (ff.open(QIODevice::ReadOnly)) {
            QByteArray src = ff.readAll();
            GW_2022_Parser parser;
            MsduState  msdu_state;
            GW_2022_Parser::Filter f0;
            f0.allow_beacon = f0.allow_sof = f0.allow_ack = f0.allow_coord = true;
            f0.link_hplc = f0.link_hrf = true;

            QVector<PacketEntry> entries;
            qint64 t0 = 1700000000000LL;
            QByteArray walk = src;
            while (!walk.isEmpty() && entries.size() < 150) {
                int i = walk.indexOf(char(0x3C));
                if (i < 0) break;
                walk.remove(0, i + 1);
                i = walk.indexOf(char(0x3E));
                if (i < 0) break;
                QByteArray esc = walk.left(i);
                walk.remove(0, i + 1);
                QByteArray unesc;
                for (int k = 0; k < esc.size(); ++k) {
                    quint8 b = (quint8)esc[k];
                    if (b == 0x3D && k + 1 < esc.size()) {
                        ++k;
                        unesc.append(char(0xFF ^ (quint8)esc[k]));
                    } else {
                        unesc.append(char(b));
                    }
                }
                BplcFrame fr;
                fr.data = unesc;
                fr.meta.has_time_tag = false;
                auto r = parser.parse(fr, msdu_state, f0);
                if (!r.accept) continue;
                PacketEntry pe;
                pe.meta      = r.meta;
                pe.raw_bytes = r.payload_for_log;
                pe.epoch_ms  = t0 + entries.size() * 37;
                entries.append(pe);
            }
            const int n_src = entries.size();
            QByteArray outbin = playback::build_playback_bin(entries);
            std::printf("  源帧 %d,导出字节 %lld\n", n_src, (long long)outbin.size());

            // 以与 SerialReader 相同方式重读导出文件
            GW_2022_Parser parser2;
            MsduState  msdu_state2;
            int n_back = 0;
            int n_mismatch = 0;
            QByteArray walk2 = outbin;
            while (!walk2.isEmpty()) {
                int i = walk2.indexOf(char(0x3C));
                if (i < 0) break;
                walk2.remove(0, i + 1);
                i = walk2.indexOf(char(0x3E));
                if (i < 0) break;
                QByteArray esc = walk2.left(i);
                walk2.remove(0, i + 1);
                QByteArray unesc;
                for (int k = 0; k < esc.size(); ++k) {
                    quint8 b = (quint8)esc[k];
                    if (b == 0x3D && k + 1 < esc.size()) {
                        ++k;
                        unesc.append(char(0xFF ^ (quint8)esc[k]));
                    } else {
                        unesc.append(char(b));
                    }
                }
                BplcFrame fr2;
                fr2.data = unesc;
                // 模拟 SerialReader 回放自动识别导出文件的时间标签
                fr2.meta.has_time_tag = playback::looks_like_bcd_time(unesc);
                auto r2 = parser2.parse(fr2, msdu_state2, f0);
                if (!r2.accept) break;                       // 导出帧必须可解析
                if (n_back < n_src) {
                    if (r2.payload_for_log != entries[n_back].raw_bytes) ++n_mismatch;
                    // 时间标签应还原原始捕获时刻
                    if (!r2.meta.frame_time.isValid() ||
                        r2.meta.frame_time.toMSecsSinceEpoch() !=
                            entries[n_back].epoch_ms) ++n_mismatch;
                }
                ++n_back;
            }
            export_ok = (n_back == n_src && n_mismatch == 0);
            std::printf("  回放解析 %d 帧,字节不一致 %d → %s\n",
                        n_back, n_mismatch, export_ok ? "一致" : "不一致");
        } else {
            export_ok = false;
        }
    }

    // ---- 信标帧 PB Padding 验证(replay_test.bin 中 BEACON 载荷尾区) ----
    std::printf("\n--- 信标帧 PB Padding 验证 ---\n");
    bool bea_ok = false;
    {
        QFile fb(kSamples + QStringLiteral("/replay_test.bin"));
        if (fb.open(QIODevice::ReadOnly)) {
            QByteArray buf = fb.readAll();
            GW_2022_Parser bp;
            MsduState  bs;
            GW_2022_Parser::Filter bf0;
            bf0.allow_beacon = bf0.allow_sof = bf0.allow_ack = bf0.allow_coord = true;
            bf0.link_hplc = bf0.link_hrf = true;
            int n_bcn = 0, n_pad = 0, n_zero = 0, n_crc_last = 0, n_pb24 = 0, n_pb24_ok = 0;
            int n_rsv0 = 0, n_rsv1 = 0, n_rfch = 0, n_flag = 0, n_mgmt = 0, n_head = 0, n_len = 0;
            BplcFrame fbr;
            while (!buf.isEmpty()) {
                int i0 = buf.indexOf(char(0x3C));
                if (i0 < 0) break;
                buf.remove(0, i0 + 1);
                int i1 = buf.indexOf(char(0x3E));
                if (i1 < 0) break;
                QByteArray esc = buf.left(i1);
                buf.remove(0, i1 + 1);
                QByteArray unesc;
                for (int i = 0; i < esc.size(); ++i) {
                    quint8 b = (quint8)esc[i];
                    if (b == 0x3D && i + 1 < esc.size()) {
                        ++i;
                        unesc.append(char(0xFF ^ (quint8)esc[i]));
                    } else {
                        unesc.append(char(b));
                    }
                }
                fbr.data = unesc;
                fbr.meta.has_time_tag = false;
                auto rb = bp.parse(fbr, bs, bf0);
                if (!rb.accept || rb.mpdu.frame_type != 0 || !rb.beacon.present) continue;
                ++n_bcn;
                // 字段顺序(按字节流):…固定头/条目/PB Padding/载荷CRC32/PB CRC24,
                // 即组内最后两个子节点 = BeaconCRC32 与 PB CRC24
                for (const auto& n : rb.beacon.tree) {
                    const int nc = n.children.size();
                    if (nc >= 2 &&
                        n.children.at(nc - 2).name == QStringLiteral("BeaconCRC32 [32b]") &&
                        n.children.last().name == QStringLiteral("PB CRC24"))
                        ++n_crc_last;
                }
                std::function<void(const MsduFieldNode&)> wk =
                    [&](const MsduFieldNode& nd) {
                        if (nd.name == QStringLiteral("PB Padding")) {
                            ++n_pad;
                            if (nd.value.contains(QStringLiteral("0x00 fill"))) ++n_zero;
                        }
                        if (nd.name == QStringLiteral("PB CRC24")) {
                            ++n_pb24;
                            if (nd.value.contains(QStringLiteral("OK"))) ++n_pb24_ok;
                        }
                        // 51242 表38 字段齐全性:字节0 bit5 保留/字节13-19 保留/
                        // 无线信道编号/标志位含义注释
                        if (nd.name == QStringLiteral("RSV0 [1b]")) ++n_rsv0;
                        if (nd.name == QStringLiteral("RSV1 [56b]")) ++n_rsv1;
                        if (nd.name == QStringLiteral("NetRfChannel [8b]")) ++n_rfch;
                        if (nd.name.startsWith(QStringLiteral("NetWorkingFlag"))
                            && nd.value.contains(QLatin1String(" - "))) ++n_flag;
                        // 信标管理信息(表44):分组 + 每条目的 ItemHead/ItemLen 行
                        if (nd.name == QStringLiteral("Beacon Mgmt Info")) ++n_mgmt;
                        if (nd.name == QStringLiteral("ItemHead [8b]")) ++n_head;
                        if (nd.name.startsWith(QStringLiteral("ItemLen"))) ++n_len;
                        for (const auto& c : nd.children) wk(c);
                    };
                for (const auto& n : rb.beacon.tree) wk(n);
            }
            // 期望:每条信标载荷尾部都有 padding 节点(实测 871 帧全有,40~47B),
            // CRC32 行位于字段列表末尾,PB CRC24 紧随其后且校验通过
            bea_ok = (n_bcn > 0 && n_pad == n_bcn && n_crc_last == n_bcn
                      && n_pb24 == n_bcn && n_pb24_ok == n_bcn
                      && n_rsv0 == n_bcn && n_rsv1 == n_bcn
                      && n_rfch == n_bcn && n_flag == n_bcn
                      && n_mgmt == n_bcn && n_head >= n_bcn && n_len >= n_bcn);
            std::printf("  信标帧=%d 含 PB Padding=%d 全0x00=%d CRC32居末=%d "
                        "PB CRC24=%d(OK=%d) RSV0=%d RSV1[56b]=%d "
                        "RfChannel=%d Flag注释=%d Mgmt=%d Head=%d Len=%d → %s\n",
                        n_bcn, n_pad, n_zero, n_crc_last, n_pb24, n_pb24_ok,
                        n_rsv0, n_rsv1, n_rfch, n_flag, n_mgmt, n_head, n_len,
                        bea_ok ? "OK" : "FAIL");
        }
    }

    // ---- i18n 中→英翻译命中检查(内置表 + 各文件注册表) ----
    std::printf("\n--- i18n 翻译命中检查 ---\n");
    bool i18n_ok = true;
    {
        trl::set_enabled(true);
        const struct { const char* zh; const char* en; } checks[] = {
            { "开始", "Start" },
            { "捕获(&C)", "&Capture" },
            { "终端主动抄表", "Terminal" },          // msduparser 注册
            { "空帧", "empty frame" },                // bplcparser 注册
            { "复制 Hex(%1 字节)", "Copy Hex" },      // i18n 内置表(带占位)
            { "%1 (内容 %2B)", "%1 (%2B content)" },  // msduparser 信标条目长
            { "时隙分配条目(TSA,标准信标必选)", "Time Slot Allocation Item" },
            { "发现信标", "Discovery Beacon" },        // NonCCO 槽内 Beacon Type
            { "代理信标", "Proxy Beacon" },
            { "中央信标", "Central Beacon" },          // 载荷头 BeaconType(表39)
        };
        for (const auto& c : checks) {
            const QString got = trl::L(c.zh);
            if (!got.startsWith(QString::fromUtf8(c.en))) {
                i18n_ok = false;
                std::printf("  MISMATCH zh=%s -> got=%s\n", c.zh, qPrintable(got));
            }
        }
        trl::set_enabled(false);
        if (trl::L("开始") != QStringLiteral("开始")) i18n_ok = false;  // 中文回退
        std::printf("  i18n 检查 → %s\n", i18n_ok ? "OK" : "FAIL");
    }

    bool final_ok = ok && real_ok && filter_ok && multi_ok && export_ok && bea_ok && i18n_ok;
    std::printf(final_ok ? "PASS\n" : "FAIL\n");
    return final_ok ? 0 : 1;
}
