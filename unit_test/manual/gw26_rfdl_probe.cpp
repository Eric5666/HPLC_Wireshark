// gw26_rfdl_probe:HDC 2.0 单跳帧(消息类型0 无线/2 载波发现列表)RFDL 解析验证
// 直接调用 GW_2026_MsduParser::parse() 喂入合成的单跳 MSDU 载荷,打印 topo_event.rssi_entries。
// (与 gw_rfdl_probe.cpp 同构,gw_2026 侧载波/无线两簇 RSSI 映射)
#include <QCoreApplication>
#include <QByteArray>
#include <QDebug>
#include <cstdio>
#include "gw_2026_msdu_parser.h"

static QByteArray hex(const QString& s) {
    QByteArray out;
    QString t = s; t.remove(' '); t.remove('\n'); t.remove('\t');
    for (int i = 0; i + 1 < t.size(); i += 2)
        out.append(char(t.mid(i, 2).toInt(nullptr, 16)));
    return out;
}

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    if (argc < 2) {
        qDebug() << "usage: gw26_rfdl_probe <hex>";
        return 1;
    }
    const QByteArray body = hex(QString::fromLocal8Bit(argv[1]));
    auto info = GW_2026_MsduParser::parse(body);
    fprintf(stderr, "summary: %s | simple_head: %d | present: %d\n",
            info.summary.toLocal8Bit().constData(), (int)info.simple_head, (int)info.present);
    fprintf(stderr, "topo_event: kind=%d link_type=%d rssi_entries=%d\n",
            (int)info.topo_event.kind, info.topo_event.link_type,
            (int)info.topo_event.rssi_entries.size());
    fprintf(stderr, "  无线 proxy_up=%d proxy_down=%d\n",
            info.topo_event.proxy_up_rate, info.topo_event.proxy_down_rate);
    fprintf(stderr, "  载波 proxy_comm=%d proxy_down_comm=%d min_comm=%d\n",
            info.topo_event.proxy_comm_rate, info.topo_event.proxy_down_comm_rate,
            info.topo_event.min_comm_rate);
    fprintf(stderr, "  邻居 neighbor_teis_present=%d neighbor_teis=%d\n",
            (int)info.topo_event.neighbor_teis_present,
            (int)info.topo_event.neighbor_teis.size());
    for (quint16 t : info.topo_event.neighbor_teis)
        fprintf(stderr, "    nb TEI=%u\n", (unsigned)t);
    for (const auto& pr : info.topo_event.neighbor_rates)
        fprintf(stderr, "  rate: TEI=%u -> %u%%\n", (unsigned)pr.first, (unsigned)pr.second);
    for (const auto& pr : info.topo_event.neighbor_snrs)
        fprintf(stderr, "  snr: TEI=%u -> %d dB\n", (unsigned)pr.first, pr.second);
    for (const auto& pr : info.topo_event.rssi_entries)
        fprintf(stderr, "  rssi: TEI=%u -> %d dBm\n", (unsigned)pr.first, pr.second);
    return 0;
}
