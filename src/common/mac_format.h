/// @file mac_format.h
/// @brief 48-bit MAC u64 格式化唯一实现(低字节在前,小写 2 位十六进制,冒号分隔)
/// @details 主程序侧四处旧拷贝均委托于此,格式改动只改一处:
///          - src/ui/packetlistmodel.cpp::format_mac(列表 Orig 列)
///          - src/common/bplcframe.h::make_search_text(搜索文本源/目的两处循环)
///          - src/protocol/common/fieldtools.h::mac_str(字段树)
///          - src/topo/topo_state.cpp::topo_mac_str(拓扑事件说明)
///          u64 约定:低字节为帧内首字节(见 AGENTS.md MAC u64 约定)。
///          插件侧另有同式拷贝(js/lua 后端)与大写式拷贝(coverage 示例),
///          属插件组件、构建独立,不在此统一之列。
#ifndef BPLC_MAC_FORMAT_H
#define BPLC_MAC_FORMAT_H

#include <QString>

inline QString format_mac_u64(quint64 v) {
    QString s;
    for (int i = 0; i < 6; ++i) {
        s += QStringLiteral("%1").arg((v >> (8 * i)) & 0xFF, 2, 16, QChar('0'));
        if (i < 5) s += QLatin1Char(':');
    }
    return s;
}

#endif  // BPLC_MAC_FORMAT_H
