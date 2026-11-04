// gw_rfdl_probe:单跳帧(MSDU_BASE_S)消息类型0 = 无线发现列表(RFDL)字段解析验证
// 直接调用 GW_2022_MsduParser::parse() 喂入合成的单跳 MSDU 载荷,打印字段树。
#include <QCoreApplication>
#include <QByteArray>
#include <QDebug>
#include "gw_2022_msdu_parser.h"

static QByteArray hex(const QString& s) {
    QByteArray out;
    QString t = s; t.remove(' '); t.remove('\n'); t.remove('\t');
    for (int i = 0; i + 1 < t.size(); i += 2)
        out.append(char(t.mid(i, 2).toInt(nullptr, 16)));
    return out;
}

static void dump(const QVector<MsduFieldNode>& nodes, int depth) {
    for (const auto& n : nodes) {
        const QString ind = QString(depth * 2, QLatin1Char(' '));
        qDebug().noquote() << ind + n.name + QStringLiteral(" = ") + n.value;
        dump(n.children, depth + 1);
    }
}

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    if (argc < 2) {
        qDebug() << "usage: gw_rfdl_probe <hex>";
        return 1;
    }
    const QByteArray body = hex(QString::fromLocal8Bit(argv[1]));
    auto info = GW_2022_MsduParser::parse(body);
    qDebug().noquote() << "summary:" << info.summary
                       << "| simple_head:" << info.simple_head
                       << "| present:" << info.present;
    qDebug() << "topo_event: kind=" << (int)info.topo_event.kind
             << "rssi_entries=" << info.topo_event.rssi_entries.size()
             << "link_type=" << info.topo_event.link_type;
    for (const auto& pr : info.topo_event.rssi_entries)
        qDebug() << "  rssi: TEI=" << pr.first << "->" << pr.second << "dBm";
    dump(info.tree, 0);
    return 0;
}
