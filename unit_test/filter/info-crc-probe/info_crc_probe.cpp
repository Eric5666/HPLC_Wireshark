// Info 列 CRC 状态探针(截断误报 CRC OK 回归)。
// 截断帧(已收块全过、pb_crc_ok=false 且实收块少于声明块)的 Info 不得报
// CRC OK,须报 CRC 不完整(截断);PB 序号乱序导致的重组失败不得误报截断;
// 完整全好仍报 CRC OK;失败仍报 CRC FAIL(n/m);
// oks 为空不报任何 CRC 文案。OFDMA 多站分支 pb_crc_ok 未定义,
// 故不在此探针断言(另案:多站 pb_crc_ok 语义 + 截断检测)。
// Exit 0 iff every check passes.
#include <cstdio>
#include <QCoreApplication>
#include <QByteArray>
#include <QString>
#include <QVector>
#include "bplcframe.h"
#include "packetlistmodel.h"

static int g_fails = 0;
static void check(bool ok, const char* what) {
    std::printf("%s: %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++g_fails;
}

// 合成 SOF 条目:version=1 走默认分支;version=2 + raw4=0x02 走训练分支。
static PacketEntry sof_entry(int pb_num, QVector<bool> oks, bool pb_crc_ok,
                             quint8 version, quint8 raw4) {
    PacketEntry e;
    e.accepted = true;
    e.mpdu.frame_type = 1;  // SOF
    e.mpdu.version = version;
    e.meta.is_rf = false;
    e.mpdu.net_id = 1;
    e.mpdu.src_tei = 5;
    e.mpdu.dst_tei = 0xFFF;
    e.mpdu.tmi = 9;
    e.mpdu.pb_num = pb_num;
    e.mpdu.pb_crc_oks = oks;
    e.mpdu.pb_crc_ok = pb_crc_ok;
    e.raw_bytes = QByteArray(16, 0);
    e.raw_bytes[4] = (char)raw4;
    return e;
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    PacketListModel model;
    model.append_packets(QVector<PacketEntry>{
        sof_entry(2, {true}, false, 1, 0x00),        // 0: 截断全好(默认分支)
        sof_entry(2, {true, true}, true, 1, 0x00),   // 1: 完整全好
        sof_entry(2, {true, false}, false, 1, 0x00), // 2: 块 CRC 失败
        sof_entry(2, {}, false, 1, 0x00),            // 3: oks 为空
        sof_entry(2, {true, true}, false, 1, 0x00),  // 4: PB 序号乱序/重组失败
        sof_entry(2, {true}, false, 2, 0x02),        // 5: 训练分支截断
        sof_entry(2, {true}, true, 2, 0x02),         // 6: 训练分支完整
    });
    model.set_display_filter(QString());
    const auto info = [&](int row) {
        return model.data(model.index(row, PacketListModel::COL_INFO), Qt::DisplayRole).toString();
    };
    const QString trunc = info(0);
    check(trunc.contains(QStringLiteral("CRC 不完整")) && !trunc.contains(QStringLiteral("CRC OK")),
          "info truncated all-good reports incomplete, not CRC OK");
    check(info(1).contains(QStringLiteral("CRC OK")), "info complete all-good CRC OK unchanged");
    check(info(2).contains(QStringLiteral("CRC FAIL(1/2)")) && !info(2).contains(QStringLiteral("CRC OK")),
          "info block fail CRC FAIL unchanged");
    check(!info(3).contains(QStringLiteral("CRC")), "info empty oks no CRC claim");
    check(info(4).contains(QStringLiteral("CRC 不完整（重组失败）"))
              && !info(4).contains(QStringLiteral("截断"))
              && !info(4).contains(QStringLiteral("CRC OK")),
          "info PB reassembly failure is not reported as truncation");
    check(info(5).contains(QStringLiteral("CRC 不完整（截断）"))
              && !info(5).contains(QStringLiteral("CRC OK")),
          "info training branch truncated reports incomplete");
    check(info(6).contains(QStringLiteral("CRC OK")), "info training branch complete CRC OK");

    std::printf("RESULT: %s (%d failures)\n", g_fails == 0 ? "ALL PASS" : "FAIL", g_fails);
    return g_fails == 0 ? 0 : 1;
}
