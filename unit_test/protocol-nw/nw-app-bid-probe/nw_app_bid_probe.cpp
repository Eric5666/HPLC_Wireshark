/// 探针:南网应用层业务标识按 (报文端口号, 业务标识) 联合判定 + 传输方向显示
/// 依据:《SPLC 规约 第5部分 应用层》6.3.2 表9(业务标识)、6.3.1.6 表8(传输方向位)
///   表9「数据传输」四个合法组合:0x11/0x00 数据透传至设备、0x13/0x01 数据透传至模块、
///                              0x11/0x02 并发抄读端设备、0x13/0x03 站点间通信;
///   其余"端口+业务标识"组合表9 标"-"=保留 ⇒ 只能显示裸 BID。
/// 覆盖:nw_2026(SPLC) 与 nw_2021 各跑一遍(两者 parse_app 同构)。
/// 另断言:业务数据单元**不被拆解** —— 载荷仍只有单个 "APP Data" 节点。
/// 用法:./build/nw_app_bid_probe ; exit 0 = 全部断言通过
#include "nw_2021_msdu_parser.h"
#include "nw_2026_msdu_parser.h"

#include <QCoreApplication>
#include <QString>
#include <QVector>
#include <cstdio>

static int g_fail = 0;
#define CHECK(name, expr) do { \
    const bool ok_ = (expr); \
    std::printf("%s %s\n", ok_ ? "PASS" : "FAIL", name); \
    if (!ok_) ++g_fail; } while (0)

/// @brief 构造单跳帧 MSDU 体(表113):4B 单跳 MAC 头 + APP 载荷(表1 4B + 表2 8B + 数据) + 4B CRC32 占位
/// @details 走 parse_single_hop 的 msdu_type==1 分支 —— 与真实单跳应用帧同一条路径,
///          parse_app 不被旁路,断言才有意义(probe 不校验 CRC,末 4B 填 0)。
static QByteArray make_body(quint8 port, quint8 packet_type, quint8 bid, bool uplink) {
    QByteArray app;
    app.append(char(port));                              // 表1 报文端口号
    app.append(char(0x01)); app.append(char(0x01));      // 表1 报文标识符 0x0101
    app.append(char(0x00));                              // 表1 保留
    app.append(char(packet_type & 0x0F));                // 表5 帧类型域(低 4 位)
    app.append(char(uplink ? 0x80 : 0x00));              // 表8 传输方向位(bit7:0=下行 1=上行)
    app.append(char(bid));                               // 表9 业务标识
    app.append(char(0x01));                              // 6.3.3 应用版本号(固定 1)
    app.append(char(0x00)); app.append(char(0x00));      // 6.3.4 帧序号
    app.append(char(0x08)); app.append(char(0x00));      // 6.3.5 帧长
    for (int i = 0; i < 8; ++i) app.append(char(0xA0 + i));  // 业务数据单元内容

    QByteArray body;
    body.append(char(0x04));                             // 表113 Version(bits1-2)=2 → 单跳帧
    body.append(char(0x01));                             // 表114 MSDU Type=1 应用层报文
    body.append(char(app.size() & 0xFF));                // MSDULength(低字节在前)
    body.append(char((app.size() >> 8) & 0xFF));
    body.append(app);
    body.append(4, '\0');                                // CRC32 占位
    return body;
}

static const MsduFieldNode* find_node(const QVector<MsduFieldNode>& nodes, const QString& prefix) {
    for (const MsduFieldNode& n : nodes) {
        if (n.name.startsWith(prefix)) return &n;
        if (const MsduFieldNode* r = find_node(n.children, prefix)) return r;
    }
    return nullptr;
}

static int count_nodes(const QVector<MsduFieldNode>& nodes, const QString& prefix) {
    int n = 0;
    for (const MsduFieldNode& c : nodes) {
        if (c.name.startsWith(prefix)) ++n;
        n += count_nodes(c.children, prefix);
    }
    return n;
}

static QString hex2(quint8 v) { return QStringLiteral("0x%1").arg(v, 2, 16, QChar('0')); }

/// @brief 合法组合:业务名 + 方向都必须在 summary / MSDU Type / BusinessID 三处出现
template <typename Parser>
static void check_valid(const char* tag, quint8 port, quint8 bid, const char* name,
                        bool uplink) {
    const MsduInfo out = Parser::parse(make_body(port, 0x01, bid, uplink));  // 0x01=数据转发
    const QString dir = uplink ? QStringLiteral("↑") : QStringLiteral("↓");
    const QString want_in_paren =
        QStringLiteral("(%1 %2 %3)").arg(QStringLiteral("BID=") + hex2(bid),
                                         QString::fromUtf8(name), dir);
    const QString summary = out.summary;
    const MsduFieldNode* mt = find_node(out.tree, QStringLiteral("MSDU Type"));
    const MsduFieldNode* bnode = find_node(out.tree, QStringLiteral("BusinessID"));
    std::printf("  [%s] port=0x%02X bid=0x%02X -> summary=%s\n", tag, port, bid,
                qPrintable(summary));
    CHECK(QStringLiteral("%1 0x%2/0x%3 解析成功").arg(tag).arg(port, 2, 16, QChar('0'))
              .arg(bid, 2, 16, QChar('0')).toUtf8().constData(), out.present);
    CHECK(QStringLiteral("%1 0x%2/0x%3 summary 含业务名+方向").arg(tag)
              .arg(port, 2, 16, QChar('0')).arg(bid, 2, 16, QChar('0')).toUtf8().constData(),
          summary.contains(want_in_paren));
    CHECK("  summary 以「应用层报文」开头(派单口径)",
          summary.startsWith(QStringLiteral("应用层报文")));
    CHECK("  MSDU Type 节点含业务名+方向",
          mt && mt->value.contains(want_in_paren));
    CHECK("  BusinessID 节点含业务名+方向",
          bnode && bnode->value.contains(
              QStringLiteral("%1 - %2 %3").arg(hex2(bid), QString::fromUtf8(name), dir)));
    CHECK("  载荷仍是单个 APP Data 节点(未拆业务数据单元)",
          count_nodes(out.tree, QStringLiteral("APP Data")) == 1);
}

/// @brief 非法(保留)组合:端口与业务标识不匹配 ⇒ 只显示裸 BID,不带业务名与方向
template <typename Parser>
static void check_reserved(const char* tag, quint8 port, quint8 bid) {
    const MsduInfo out = Parser::parse(make_body(port, 0x01, bid, false));
    const QString bare = QStringLiteral("(%1)").arg(QStringLiteral("BID=") + hex2(bid));
    std::printf("  [%s] port=0x%02X bid=0x%02X -> summary=%s\n", tag, port, bid,
                qPrintable(out.summary));
    CHECK(QStringLiteral("%1 0x%2/0x%3 保留组合只显示裸 BID").arg(tag)
              .arg(port, 2, 16, QChar('0')).arg(bid, 2, 16, QChar('0')).toUtf8().constData(),
          out.summary.contains(bare));
    CHECK("  保留组合不带方向符号",
          !out.summary.contains(QStringLiteral("↑")) && !out.summary.contains(QStringLiteral("↓")));
}

/// @brief 端口门逐组合校验:expect_name 非空 ⇒ 必须出现"业务名 + ↓";传空串 ⇒ 视为保留
///        (只显示裸 BID,且不带任何方向箭头)
template <typename Parser>
static void check_gate(const char* tag, quint8 port, quint8 type, quint8 bid,
                       const char* expect_name) {
    const MsduInfo out = Parser::parse(make_body(port, type, bid, false));
    const QString bare = QStringLiteral("(%1)").arg(QStringLiteral("BID=") + hex2(bid));
    const QByteArray label = QStringLiteral("%1 gate port=0x%2 type=%3 bid=0x%4")
                                 .arg(QString::fromUtf8(tag))
                                 .arg(port, 2, 16, QChar('0'))
                                 .arg(type)
                                 .arg(bid, 2, 16, QChar('0')).toUtf8();
    if (expect_name && *expect_name) {
        const QString want = QStringLiteral("(%1 %2 ↓)")
                                 .arg(QStringLiteral("BID=") + hex2(bid),
                                      QString::fromUtf8(expect_name));
        CHECK(label.constData(), out.summary.contains(want));
    } else {
        CHECK(label.constData(), out.summary.contains(bare)
                                    && !out.summary.contains(QStringLiteral("↑"))
                                    && !out.summary.contains(QStringLiteral("↓")));
    }
}

template <typename Parser>
static void run_all(const char* tag) {
    // 表9「数据传输」四个合法组合
    check_valid<Parser>(tag, 0x11, 0x00, "数据透传至设备", false);
    check_valid<Parser>(tag, 0x13, 0x01, "数据透传至模块", false);
    check_valid<Parser>(tag, 0x11, 0x02, "并发抄读端设备", true);   // 同时验证上行箭头
    check_valid<Parser>(tag, 0x13, 0x03, "站点间通信", false);
    // 端口不匹配 ⇒ 表9 标 "-" = 保留
    check_reserved<Parser>(tag, 0x11, 0x01);
    check_reserved<Parser>(tag, 0x13, 0x00);
    check_reserved<Parser>(tag, 0x13, 0x02);
    check_reserved<Parser>(tag, 0x11, 0x03);

    // ---- 表9 其余帧类型端口门(正反两侧;type: 0 确认/否认 2 命令 3 主动上报 4 抄控器 5 广播 6 数据订阅) ----
    // 确认/否认(仅 0x11)
    check_gate<Parser>(tag, 0x11, 0x00, 0x00, "确认");
    check_gate<Parser>(tag, 0x13, 0x00, 0x00, "");
    // 命令:0x11 组
    check_gate<Parser>(tag, 0x11, 0x02, 0x00, "查询终端搜索结果");
    check_gate<Parser>(tag, 0x11, 0x02, 0x01, "下发搜索终端列表");
    check_gate<Parser>(tag, 0x11, 0x02, 0x02, "文件传输");
    check_gate<Parser>(tag, 0x11, 0x02, 0x03, "允许/禁止从节点事件");
    check_gate<Parser>(tag, 0x11, 0x02, 0x04, "从节点重启");
    check_gate<Parser>(tag, 0x11, 0x02, 0x05, "从节点信息查询");
    check_gate<Parser>(tag, 0x11, 0x02, 0x06, "下发通信地址映射表列表");
    check_gate<Parser>(tag, 0x11, 0x02, 0x10, "台区户变关系/相位识别");
    check_gate<Parser>(tag, 0x11, 0x02, 0xF0, "测试帧");
    // 命令:0x13 组
    check_gate<Parser>(tag, 0x13, 0x02, 0x07, "查询从节点运行状态信息");
    check_gate<Parser>(tag, 0x13, 0x02, 0x08, "查询从节点信道信息");
    check_gate<Parser>(tag, 0x13, 0x02, 0x09, "查询模块运行参数");
    // 命令:错端口 ⇒ 保留
    check_gate<Parser>(tag, 0x11, 0x02, 0x07, "");
    check_gate<Parser>(tag, 0x11, 0x02, 0x09, "");
    check_gate<Parser>(tag, 0x13, 0x02, 0x00, "");
    check_gate<Parser>(tag, 0x13, 0x02, 0x02, "");
    check_gate<Parser>(tag, 0x13, 0x02, 0x04, "");
    check_gate<Parser>(tag, 0x13, 0x02, 0xF0, "");
    // 广播命令:0x11 组 / 0x13 组 / 错端口
    check_gate<Parser>(tag, 0x11, 0x05, 0x04, "从节点重启");
    check_gate<Parser>(tag, 0x11, 0x05, 0x05, "从节点信息查询");
    check_gate<Parser>(tag, 0x13, 0x05, 0x07, "查询从节点运行状态信息");
    check_gate<Parser>(tag, 0x13, 0x05, 0x08, "查询从节点信道信息");
    check_gate<Parser>(tag, 0x13, 0x05, 0x04, "");
    check_gate<Parser>(tag, 0x13, 0x05, 0x00, "");
    check_gate<Parser>(tag, 0x11, 0x05, 0x07, "");
    check_gate<Parser>(tag, 0x11, 0x05, 0x08, "");
    // 主动上报
    check_gate<Parser>(tag, 0x11, 0x03, 0x00, "电表事件主动上报");
    check_gate<Parser>(tag, 0x13, 0x03, 0x01, "停上电事件上报");
    check_gate<Parser>(tag, 0x11, 0x03, 0x02, "设备事件主动上报");
    check_gate<Parser>(tag, 0x13, 0x03, 0x02, "通信模块事件上报");
    check_gate<Parser>(tag, 0x13, 0x03, 0x00, "");
    check_gate<Parser>(tag, 0x11, 0x03, 0x01, "");
    // 抄控器协议(仅 0x11)
    check_gate<Parser>(tag, 0x11, 0x04, 0x00, "抄控器-CCO协议");
    check_gate<Parser>(tag, 0x11, 0x04, 0x01, "数据透传串口转发");
    check_gate<Parser>(tag, 0x13, 0x04, 0x00, "");
    check_gate<Parser>(tag, 0x13, 0x04, 0x01, "");
    // 数据订阅业务(仅 0x11/0x00)
    check_gate<Parser>(tag, 0x11, 0x06, 0x00, "数据订阅业务");
    check_gate<Parser>(tag, 0x13, 0x06, 0x00, "");
    check_gate<Parser>(tag, 0x11, 0x06, 0x01, "");
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    std::printf("== nw_2026 (SPLC) ==\n");
    run_all<NW_2026_MsduParser>("2026");
    std::printf("== nw_2021 ==\n");
    run_all<NW_2021_MsduParser>("2021");
    std::printf("\n%s (%d failures)\n", g_fail ? "RESULT: FAIL" : "RESULT: ALL PASS", g_fail);
    return g_fail ? 1 : 0;
}
