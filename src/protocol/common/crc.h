/// @file crc.h
/// @brief 协议公共 CRC(CRC32 / CRC24),国网南网共用(协议无关)
/// @details 从原 fieldspec.h 抽取。算法:
///   - crc32_le:poly=0xEDB88320,init=0xFFFFFFFF,LSB 先行,末取反;遍历前 len-4 字节
///   - crc24_lsb:poly=0xC60001,init=0,LSB 先行;遍历前 len-3 字节,存储末 3B(低字节在前)
#ifndef BPLC_CRC_H
#define BPLC_CRC_H

#include <QtGlobal>

/// 通用 CRC32(poly=0xEDB88320, init=0xFFFFFFFF, LSB 先行, 末取反);
/// 遍历前 len-4 字节,存储值为末 4B(小端)——MSDU/信标载荷 CRC32 同算法
inline quint32 crc32_le(const quint8* d, int len) {
    const quint32 poly = 0xEDB88320;
    quint32 crc = 0xFFFFFFFF;
    for (int i = 0; i < len - 4; ++i) {
        for (int j = 0; j < 8; ++j) {
            quint32 bit_in  = (d[i] >> j) & 0x1;
            quint32 bit_lsb = crc & 0x1;
            crc >>= 1;
            if (bit_in ^ bit_lsb) crc ^= poly;
        }
    }
    return (~crc) & 0xFFFFFFFF;
}

/// 通用 CRC24(poly=0xC60001, init=0, LSB 先行);遍历前 len-3 字节,
/// 存储值为末 3B(低字节在前)——FCH/PB 物理块检查序列同算法
inline quint32 crc24_lsb(const quint8* d, int len) {
    const quint32 poly = 0xC60001;
    quint32 crc = 0;
    for (int i = 0; i < len - 3; ++i) {
        for (int j = 0; j < 8; ++j) {
            quint32 bit_in  = (d[i] >> j) & 0x1;
            quint32 bit_lsb = crc & 0x1;
            crc >>= 1;
            if (bit_in ^ bit_lsb) crc ^= poly;
        }
    }
    return crc & 0xFFFFFF;
}

#endif  // BPLC_CRC_H
