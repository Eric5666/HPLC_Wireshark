/// @file fieldspec.h
/// @brief 字段树构建公共工具(各帧解析模块共用)
/// @details 字段说明表(FieldSpec)/字段节点树(add_fields/group)/单位注释。
///          位域取值/格式化见 fieldtools.h,CRC 见 crc.h(已抽取,勿在本文件重复定义)。
/// @note 头文件常驻 inline,无 .cpp;改动本文件后依赖模块需重编。
#ifndef BPLC_FIELDSPEC_H
#define BPLC_FIELDSPEC_H

#include "bplcframe.h"
#include "fieldtools.h"
#include <QByteArray>
#include <QString>
#include <QVector>

/// 一个位域字段说明:名 / 相对字节 / 位偏移 / 位长 / 格式化
enum class Fmt { DEC, HEX6, HEX8, HEX12, HEX4, MAC, BOOL_Y };

struct FieldSpec {
    const char* name;
    int  byte;
    int  bit;
    int  len;
    Fmt  fmt;
};

inline QString fmt_val(Fmt f, quint64 v) {
    switch (f) {
        case Fmt::DEC:    return QString::number(v);
        case Fmt::HEX6:   return hex6(v);
        case Fmt::HEX8:   return hex8(v);
        case Fmt::HEX12:  return hex12(v);
        case Fmt::HEX4:   return hex4(v);
        case Fmt::MAC:    return mac_str(v);
        case Fmt::BOOL_Y: return v ? QStringLiteral("Yes") : QStringLiteral("No");
    }
    return QString::number(v);
}

/// 按 FieldSpec 表批量生成字段节点;rel 坐标相对 rel_base(供 UI 高亮换算)
inline void add_fields(QVector<MsduFieldNode>& out, const QByteArray& d, int base,
                       const FieldSpec* specs, int n, int rel_base = 0) {
    for (int i = 0; i < n; ++i) {
        const FieldSpec& s = specs[i];
        const int start_byte = base + s.byte;
        const int end_byte   = start_byte + (s.bit + s.len - 1) / 8;
        // 越界保护:数据不足时停止(错位/跨协议解析避免 get_bits 越界读)
        if (start_byte < 0 || end_byte >= d.size()) break;
        MsduFieldNode node;
        node.name = QStringLiteral("%1 [%2b]").arg(QLatin1String(s.name)).arg(s.len);
        // 宽字段(len>64)不走 get_bits:1ULL<<i 在 i>=64 时移位 UB,分支守卫又会
        // 直接返 0 恒显 0;直接给覆盖字节的十六进制(字节序与原值一致)。
        // 位序 LSB 在前:字段从 s.bit 起连续向高位走;首字节去掉低 s.bit 位
        // (属于前一个字段),末字节只留本字段占的低 tail 位(tail=(s.bit+s.len)%8,
        // tail 为 0 表示整字节都属于本字段)。例如 125 位 bit=3 的 RSV3:
        // CarrierFreq=1、保留位全 0 时首字节 01 会被屏掉,不再误显"保留位非零"。
        // (b) 不再走 fmt_val,丢了各字段的 fmt 区分(HEX4 的 0x 前缀、DEC 的
        // 十进制),统一显 hex,接受的格式变化。
        QString val;
        if (s.len > 64) {
            QByteArray raw = d.mid(start_byte, end_byte - start_byte + 1);
            raw[0] = char(quint8(raw[0]) & quint8(0xFF << s.bit));
            const int tail = (s.bit + s.len) % 8;
            if (tail)
                raw[raw.size() - 1] =
                    char(quint8(raw[raw.size() - 1]) & quint8((1u << tail) - 1));
            val = QString::fromLatin1(raw.toHex(' ').toUpper());
        } else
            val = fmt_val(s.fmt, get_bits(d, start_byte, s.bit, s.len));
        node.value = val;
        // 位域覆盖的字节区间(相对数据起点;供 UI 高亮换算)
        int first_bit = (rel_base + base + s.byte) * 8 + s.bit;
        int last_bit  = first_bit + s.len - 1;
        node.rel_start = first_bit / 8;
        node.rel_len   = last_bit / 8 - node.rel_start + 1;
        out.append(node);
    }
}

/// 追加一个分组节点并返回其子容器引用
inline MsduFieldNode& group(QVector<MsduFieldNode>& out, const QString& name,
                            const QString& val = QString()) {
    MsduFieldNode g;
    g.name = name;
    g.value = val;
    out.append(g);
    return out.last();
}

/// 字段单位注释:命中 name 的节点 value 追加单位后缀(如 % / ms / s)
/// starts=true 时按前缀匹配;false 时按整名精确匹配
inline void annotate_unit(QVector<MsduFieldNode>& nodes, const char* field,
                          const QString& unit, bool starts = true) {
    for (auto& n : nodes) {
        if (starts ? n.name.startsWith(QLatin1String(field))
                   : (n.name == QLatin1String(field)))
            n.value += unit;
    }
}

#endif  // BPLC_FIELDSPEC_H
