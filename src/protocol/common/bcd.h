/// @file bcd.h
/// @brief BCD 编解码工具(协议无关公共)
/// @details 帧时间标签 8B BCD(yy/mm/dd/hh/mm/ss/ms 十位/ms 个位)解码用。
#ifndef BPLC_BCD_H
#define BPLC_BCD_H

#include <QtGlobal>

/// 单字节 BCD → 十进制(0x59 → 59);任一半字节 >9 返回 -1(非法 BCD)
inline int bcd2dec(quint8 b) {
    const int hi = (b >> 4) & 0x0F, lo = b & 0x0F;
    if (hi > 9 || lo > 9) return -1;
    return hi * 10 + lo;
}

#endif  // BPLC_BCD_H
