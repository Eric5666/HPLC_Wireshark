/// 探针:南网应用层业务标识按 (报文端口号, 业务标识) 联合判定 + 传输方向显示
/// 依据:《SPLC 规约 第5部分 应用层》6.3.2 表9(业务标识)、6.3.1.6 表8(传输方向位)
///   表9「数据传输」四个合法组合:0x11/0x00 数据透传至设备、0x13/0x01 数据透传至模块、
///                              0x11/0x02 并发抄读端设备、0x13/0x03 站点间通信;
///   其余"端口+业务标识"组合表9 标"-"=保留 ⇒ 只能显示裸 BID。
/// 覆盖:nw_2026(SPLC) 与 nw_2021 各跑一遍(两者 parse_app 同构)。
/// 另断言:业务数据单元**不被拆解** —— 载荷仍只有单个 "APP Data" 节点。
/// 例外:停上电事件上报(0x13/0x03/0x01)体被解出事件字段 + TopoEvent(见 check_power_event),
/// APP Data 节点仍保留一个。
/// 用法:./build/nw_app_bid_probe ; exit 0 = 全部断言通过
#include "nw_2021_msdu_parser.h"
#include "nw_2026_msdu_parser.h"
#include "common/fieldtools.h"

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
static QByteArray make_body(quint8 port, quint8 packet_type, quint8 bid, bool uplink,
                            const QByteArray& app_data = QByteArray()) {
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
    if (app_data.isEmpty())
        for (int i = 0; i < 8; ++i) app.append(char(0xA0 + i));  // 业务数据单元内容
    else
        app.append(app_data);

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

/// @brief 停上电事件上报体解析:位图/地址两种格式都产 TopoEvent(首节点主事件、其余 extra)
/// @details 用 make_body 造单跳应用帧(0x13 端口、0x03 主动上报、BID 0x01、上行),
///          体字节按规约 §9.6.3 表340/341 填;断言 kind/nodes/leaves/extra 与字段树。
///          单跳帧无源 MAC,sender_mac 留 0(TopoState 回落到事件 nodes 首条)。
static void append_mac_le(QByteArray& body, quint64 mac) {
    for (int i = 0; i < 6; ++i)
        body.append(char((mac >> (8 * i)) & 0xFF));   // get_bits LSB:低字节在前
}

template <typename Parser>
static void check_power_event(const char* tag) {
    std::printf("  [%s] 停上电事件上报解析\n", tag);
    const quint64 MAC_A = 0xAABBCCDDEEFFULL;
    const quint64 MAC_B = 0x112233445566ULL;
    // 位图断电:类型 1,起始 TEI=5,位图 0x06(bit1/2 → TEI 6/7)
    {
        QByteArray body;
        body.append(char(0x01));
        body.append(char(0x05)); body.append(char(0x00));   // 起始 TEI=5(低字节在前)
        body.append(char(0x06));                            // 位图:TEI 6/7
        const MsduInfo out = Parser::parse(make_body(0x13, 0x03, 0x01, true, body));
        CHECK("  位图断电解析成功", out.present);
        CHECK("  位图断电主事件 kind=PowerOff", out.topo_event.kind == TopoEventKind::PowerOff);
        CHECK("  位图断电主事件节点 TEI=6/MAC=0",
              out.topo_event.nodes.size() == 1 && out.topo_event.nodes[0].tei == 6
              && out.topo_event.nodes[0].mac == 0);
        CHECK("  位图断电主事件说明含断电", out.topo_event.desc.contains(QStringLiteral("断电")));
        CHECK("  位图断电主事件无 leaves", out.topo_event.leaves.isEmpty());
        CHECK("  位图断电 extra 1 条 TEI=7",
              out.topo_extra_events.size() == 1
              && out.topo_extra_events[0].kind == TopoEventKind::PowerOff
              && out.topo_extra_events[0].nodes.size() == 1
              && out.topo_extra_events[0].nodes[0].tei == 7);
        CHECK("  位图断电仍保留单个 APP Data 节点",
              count_nodes(out.tree, QStringLiteral("APP Data")) == 1);
        CHECK("  位图断电字段树有 Power On/Off Event 组",
              find_node(out.tree, QStringLiteral("Power On/Off Event")) != nullptr);
    }
    // 地址断电:类型 3,1 只表 MAC_A,带电状态 0
    {
        QByteArray body;
        body.append(char(0x03));
        body.append(char(0x01)); body.append(char(0x00));   // 电表个数=1
        append_mac_le(body, MAC_A);
        body.append(char(0x00));                            // 带电状态 0=停电
        const MsduInfo out = Parser::parse(make_body(0x13, 0x03, 0x01, true, body));
        CHECK("  地址断电主事件 kind=PowerOff", out.topo_event.kind == TopoEventKind::PowerOff);
        CHECK("  地址断电主事件节点 {0,MAC_A}",
              out.topo_event.nodes.size() == 1 && out.topo_event.nodes[0].tei == 0
              && out.topo_event.nodes[0].mac == MAC_A);
        CHECK("  地址断电主事件 leaves 含 MAC_A",
              out.topo_event.leaves.size() == 1 && out.topo_event.leaves[0] == MAC_A);
        CHECK("  地址断电无 extra", out.topo_extra_events.isEmpty());
    }
    // 地址上电:类型 4,1 只表 MAC_A,带电状态 1
    {
        QByteArray body;
        body.append(char(0x04));
        body.append(char(0x01)); body.append(char(0x00));
        append_mac_le(body, MAC_A);
        body.append(char(0x01));                            // 带电状态 1=未停电
        const MsduInfo out = Parser::parse(make_body(0x13, 0x03, 0x01, true, body));
        CHECK("  地址上电主事件 kind=PowerOn", out.topo_event.kind == TopoEventKind::PowerOn);
        CHECK("  地址上电主事件节点 {0,MAC_A}",
              out.topo_event.nodes.size() == 1 && out.topo_event.nodes[0].mac == MAC_A);
        CHECK("  地址上电主事件无 leaves", out.topo_event.leaves.isEmpty());
        CHECK("  地址上电主事件说明含上电", out.topo_event.desc.contains(QStringLiteral("上电")));
    }
    // 地址混合:类型 3,2 只表 MAC_A 停电 + MAC_B 未停电(逐只表状态为准)
    {
        QByteArray body;
        body.append(char(0x03));
        body.append(char(0x02)); body.append(char(0x00));   // 电表个数=2
        append_mac_le(body, MAC_A);
        body.append(char(0x00));
        append_mac_le(body, MAC_B);
        body.append(char(0x01));
        const MsduInfo out = Parser::parse(make_body(0x13, 0x03, 0x01, true, body));
        CHECK("  地址混合主事件 kind=PowerOff/MAC_A",
              out.topo_event.kind == TopoEventKind::PowerOff
              && out.topo_event.nodes.size() == 1
              && out.topo_event.nodes[0].mac == MAC_A);
        CHECK("  地址混合 extra 1 条 kind=PowerOn/MAC_B",
              out.topo_extra_events.size() == 1
              && out.topo_extra_events[0].kind == TopoEventKind::PowerOn
              && out.topo_extra_events[0].nodes.size() == 1
              && out.topo_extra_events[0].nodes[0].mac == MAC_B);
    }
    // 未知事件类型 0x02:不产事件
    {
        QByteArray body;
        body.append(char(0x02));
        body.append(char(0x00)); body.append(char(0x00));
        body.append(char(0x00));
        const MsduInfo out = Parser::parse(make_body(0x13, 0x03, 0x01, true, body));
        CHECK("  未知事件类型不产 TopoEvent", out.topo_event.kind == TopoEventKind::Other
              && out.topo_extra_events.isEmpty());
    }
    // 截断体:位图类型只有 2B(缺起始 TEI 高字节):不产事件
    {
        QByteArray body;
        body.append(char(0x01));
        body.append(char(0x05));
        const MsduInfo out = Parser::parse(make_body(0x13, 0x03, 0x01, true, body));
        CHECK("  截断体不产 TopoEvent", out.topo_event.kind == TopoEventKind::Other
              && out.topo_extra_events.isEmpty());
    }
    // 截断地址:个数 2 但第 2 只表只有 3B:只解第 1 只
    {
        QByteArray body;
        body.append(char(0x03));
        body.append(char(0x02)); body.append(char(0x00));
        append_mac_le(body, MAC_A);
        body.append(char(0x00));
        body.append(char(0x11)); body.append(char(0x22)); body.append(char(0x33));
        const MsduInfo out = Parser::parse(make_body(0x13, 0x03, 0x01, true, body));
        CHECK("  截断地址只解完整表项",
              out.topo_event.kind == TopoEventKind::PowerOff
              && out.topo_extra_events.isEmpty());
    }
}

/// @brief 构造 MMe 关联请求数据(MMe 头 6B + 体):[0]=版本 1、[1..2]=类型 0x0030(LE)、
///        [6..11]=STA MAC(低字节在前)、[52]=BootReason(版本信息首字节)。
/// @details 完整 AssocReq 体固定 74B(mme_body_complete 门);截断体用更短的 mme_len。
static QByteArray make_assoc_req_mme(quint64 mac, int boot_reason, int mme_len) {
    QByteArray mme(mme_len, char(0));
    if (mme_len > 0) mme[0] = char(1);
    if (mme_len > 1) mme[1] = char(0x30);
    if (mme_len > 2) mme[2] = char(0x00);
    for (int i = 0; i < 6 && 6 + i < mme_len; ++i)
        mme[6 + i] = char((mac >> (8 * i)) & 0xFF);
    if (mme_len > 52 && boot_reason >= 0)
        mme[52] = char(boot_reason & 0xFF);
    return mme;
}

/// @brief 构造标准帧 MMe 关联请求(32B 长 MAC 头 + 18B MSDU 长头 + MMe 数据 + 4B CRC 占位)。
/// @details 照 unit_test/ci/nw-mme-test 的 frame() 写法;CRC 只上报 OK/FAIL 不拦截解析,填 0。
static QByteArray make_assoc_req_frame(const QByteArray& mme_data) {
    QByteArray payload(18, char(0));
    payload.replace(0, 6, QByteArray::fromHex("102030405060"));
    payload.replace(6, 6, QByteArray::fromHex("aabbccddeeff"));
    set_bits(reinterpret_cast<quint8*>(payload.data()), 12, 0, 32, 0x8100);
    set_bits(reinterpret_cast<quint8*>(payload.data()), 16, 0, 16, 0x88e1);
    payload += mme_data;
    QByteArray header(32, char(0));
    header[0] = 2; // 标准帧、长 MAC 头
    set_bits(reinterpret_cast<quint8*>(header.data()), 2, 0, 16, quint64(payload.size()));
    QByteArray crc(4, char(0));
    return header + payload + crc;
}

template <typename Parser>
static void check_assoc_req_boot_reason(const char* tag) {
    std::printf("  [%s] 关联请求系统启动原因进事件记录\n", tag);
    const quint64 MAC_A = 0xAABBCCDDEEFFULL;
    // 完整帧 + BootReason 0 → desc 含“正常重启”
    {
        const MsduInfo out = Parser::parse(make_assoc_req_frame(make_assoc_req_mme(MAC_A, 0, 74)));
        CHECK("  完整 AssocReq kind=AssocReq", out.topo_event.kind == TopoEventKind::AssocReq);
        CHECK("  BootReason 0 desc 含正常重启", out.topo_event.desc.contains(QStringLiteral("正常重启")));
        CHECK("  BootReason 0 desc 带全角括号后缀",
              out.topo_event.desc.contains(QStringLiteral("（正常重启）")));
    }
    // 保留值 1(NW 未定义)→ 无后缀,原 desc 不变
    {
        const MsduInfo out = Parser::parse(make_assoc_req_frame(make_assoc_req_mme(MAC_A, 1, 74)));
        CHECK("  保留值 AssocReq 仍产事件", out.topo_event.kind == TopoEventKind::AssocReq);
        CHECK("  保留值 desc 无后缀", !out.topo_event.desc.contains(QStringLiteral("（")));
    }
    // 截断帧(无版本区,mme 40B)→ 完整性门挡住,不产事件
    {
        const MsduInfo out = Parser::parse(make_assoc_req_frame(make_assoc_req_mme(MAC_A, 0, 40)));
        CHECK("  截断 AssocReq 不产事件", out.topo_event.kind == TopoEventKind::Other);
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

    // 停上电事件上报体解析(位图/地址两种格式)
    check_power_event<Parser>(tag);

    // 关联请求系统启动原因进事件记录
    check_assoc_req_boot_reason<Parser>(tag);
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
