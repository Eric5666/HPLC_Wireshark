#!/usr/bin/env python3
"""Craft GW_2026 SOF frames for the TEI-MAC learning probe.

Bit order: LSB-first continuous bitstream (matches get_bits()).
CRC: crc24_lsb poly=0xC60001, init=0, LSB-first, over len-3 bytes, LE store.
FCH FCS: over bytes 0..12, stored 13..15. PB CRC: over head+body, last 3B.
MAC u64: low byte = first frame byte (frame order), display high-byte-first.

Frames (all carrier, isRF=0):
 1 G0-long  AssocCnf, long MSDU header (MACAddrFlag=1): header pair covers.
 2 G0-short AssocCnf, short MSDU header (MACAddrFlag=0): body pair is the hole.
 3 G1       GatherInd, 2 listed STAs (TEI 7, 8): pairs missing before fix.
 4 G3       Carrier discover, single-hop MSDU, sender TEI 9 + sender MAC.
 5 G2-ofdma OFDMA 2 stations (TEI 2, 3), station MSDUs with long headers.
 6 G2-tda   TDA 2 stations (TEI 2, 3), station MSDUs with long headers.
Output: crafted.bin ([u32 len][isRF][MPDU] records) + manifest on stdout.
"""
import os
import zlib
import struct

CCO_MAC = 0xAABBCCDDEE01


def mac_bytes(m):
    return bytes([(m >> (8 * i)) & 0xFF for i in range(6)])


def set_bits(buf, byte, bit, length, value):
    for i in range(length):
        pos = byte * 8 + bit + i
        if (value >> i) & 1:
            buf[pos // 8] |= (1 << (pos % 8))
        else:
            buf[pos // 8] &= ~(1 << (pos % 8))


def crc24_lsb(d, length):
    poly = 0xC60001
    crc = 0
    for i in range(length - 3):
        for j in range(8):
            bit_in = (d[i] >> j) & 1
            bit_lsb = crc & 1
            crc >>= 1
            if bit_in ^ bit_lsb:
                crc ^= poly
    return crc & 0xFFFFFF


def store_crc24(buf, start, length):
    c = crc24_lsb(buf[start:start + length], length)
    buf[start + length - 3] = c & 0xFF
    buf[start + length - 2] = (c >> 8) & 0xFF
    buf[start + length - 1] = (c >> 16) & 0xFF


def build_pb_block(head, body, pb_size):
    """body padded with zeros to pb_size-4; returns full pb_size block."""
    assert len(body) <= pb_size - 4
    blk = bytearray(pb_size)
    blk[0] = head
    blk[1:1 + len(body)] = body
    store_crc24(blk, 0, pb_size)
    return bytes(blk)


def msdu_base(src_tei, dst_tei, src_mac, dst_mac, msdu_type, payload, long_head=True):
    """MSDU_BASE 16B (short) or 28B (long, MACAddrFlag=1) + payload."""
    hlen = 28 if long_head else 16
    h = bytearray(hlen)
    set_bits(h, 0, 4, 12, src_tei)
    set_bits(h, 2, 0, 12, dst_tei)
    set_bits(h, 5, 0, 16, 1)  # seq
    set_bits(h, 7, 0, 8, msdu_type)
    set_bits(h, 8, 0, 11, len(payload))
    set_bits(h, 11, 3, 1, 1 if long_head else 0)
    if long_head:
        h[16:22] = mac_bytes(src_mac)
        h[22:28] = mac_bytes(dst_mac)
    # MSDU 帧尾 4B CRC32(与 crc.h::crc32_le 同语义 = zlib.crc32,末 4B 小端)
    # 用户 2026-11 裁决「MSDU CRC 正确才采信」后,msdu_crc_allows_learning() 以 MSDU
    # CRC32 门控拓扑学习;fixture 不写 CRC32 会被判坏载荷 ⇒ 摘要清空、TEI↔MAC 学不到。
    return bytes(h) + payload + struct.pack("<I", zlib.crc32(payload) & 0xFFFFFFFF)


def fch_base(dst_tei, sof_dt, src_tei=1):
    f = bytearray(16)
    set_bits(f, 0, 0, 3, 1)       # SOF
    set_bits(f, 1, 0, 16, 0x1234)  # NID
    set_bits(f, 4, 0, 12, src_tei)
    set_bits(f, 5, 4, 12, dst_tei)
    set_bits(f, 7, 0, 3, sof_dt)
    set_bits(f, 8, 0, 12, 0x200)   # frame length x10us
    set_bits(f, 12, 4, 4, 1)       # std version = HDC 2.0
    return f


def data_sof(msdu, dst_tei, src_tei=1):
    """Single-PB DATA SOF (diversity mode 2 -> PB 136, payload 132)."""
    f = fch_base(dst_tei, 0, src_tei)
    set_bits(f, 10, 1, 1, 0)   # mod_mode = diversity
    set_bits(f, 10, 2, 5, 2)   # mod_param (TMI) = 2 -> 136
    set_bits(f, 10, 7, 1, 0)   # PB code bit0
    set_bits(f, 11, 0, 1, 0)   # PB code bit1 -> 1 block
    store_crc24(f, 0, 16)
    pb = build_pb_block(0xC0, msdu, 136)
    return bytes(f) + pb


def assoc_cnf_body(sta_tei, sta_mac):
    b = bytearray(41)
    b[0:6] = mac_bytes(sta_mac)
    b[6:12] = mac_bytes(CCO_MAC)
    b[12] = 0  # result: success
    b[13] = 2  # level
    set_bits(b, 14, 0, 12, sta_tei)
    set_bits(b, 15, 4, 1, 0)  # link_type carrier
    set_bits(b, 16, 0, 12, 2)  # proxy TEI
    return bytes(b)


def gather_body():
    b = bytearray(32)
    b[0] = 0  # gar: success
    b[1] = 2  # level
    b[2:8] = mac_bytes(CCO_MAC)
    set_bits(b, 8, 0, 12, 2)  # proxy TEI
    b[11] = 2  # sta_num
    for i, (tei, mac) in enumerate(((7, 0xAABBCCDDEE07), (8, 0xAABBCCDDEE08))):
        off = 16 + i * 8
        b[off:off + 6] = mac_bytes(mac)
        set_bits(b, off + 6, 0, 12, tei)
    return bytes(b)


def discover_body():
    # single-hop header: version 1 (byte0 low 4b), type 2 (carrier), len 11b
    disc = bytearray()
    disc += mac_bytes(0xAABBCCDDEE09)  # sender MAC
    disc.append(1)  # seq
    ie = bytearray(23)
    set_bits(ie, 0, 0, 12, 9)   # sender TEI (表63)
    set_bits(ie, 1, 4, 12, 2)   # proxy TEI
    ie[4:10] = mac_bytes(CCO_MAC)
    disc.append(0x00)  # IE type 0, len-type 0 (1B length)
    disc.append(23)
    disc += ie
    hdr = bytearray(4)
    hdr[0] = 0x01
    hdr[1] = 2
    set_bits(hdr, 2, 0, 11, len(disc))
    return bytes(hdr) + bytes(disc)


def app_msdu(dst_tei, dst_mac):
    return msdu_base(1, dst_tei, CCO_MAC, dst_mac, 48,
                     bytes([0x01, 0x00, 0x00, 0x00]), long_head=True)


def ofdma_frame():
    total = 16 + 16 + 3 * 136
    f = bytearray(total)
    f[0:16] = fch_base(2, 2)
    set_bits(f, 7, 3, 2, 1)   # 2 stations
    set_bits(f, 7, 5, 3, 2)   # TF symbol num
    set_bits(f, 9, 4, 2, 1)   # FCH symbol num
    set_bits(f, 9, 6, 9, 212)
    set_bits(f, 10, 7, 3, 2)  # eFC symbol num
    set_bits(f, 11, 2, 1, 1)  # sta0 PB num bit -> 2 blocks
    set_bits(f, 11, 3, 5, 2)  # sta0 DivCopy -> 136
    set_bits(f, 12, 0, 4, 5)  # sta0 RU
    set_bits(f, 12, 4, 4, 1)  # std version
    store_crc24(f, 0, 16)
    set_bits(f, 16, 0, 12, 3)  # sta1 TEI
    set_bits(f, 17, 4, 4, 6)   # sta1 RU
    set_bits(f, 18, 0, 5, 2)   # sta1 DivCopy -> 136
    set_bits(f, 18, 5, 1, 0)   # sta1 PB num -> 1 block
    store_crc24(f, 16, 16)     # eFC FCS
    sta0 = app_msdu(2, 0xAABBCCDDEE02)
    sta1 = app_msdu(3, 0xAABBCCDDEE03)
    off = 32
    for head, chunk in ((0x40, sta0[:132]), (0x81, sta0[132:264]),
                        (0xC0, sta1)):
        f[off:off + 136] = build_pb_block(head, chunk, 136)
        off += 136
    assert off == total
    return bytes(f)


def tda_frame():
    total = 16 + 16 + 2 * 136
    f = bytearray(total)
    f[0:16] = fch_base(2, 3)
    set_bits(f, 7, 3, 2, 1)   # 2 stations
    set_bits(f, 7, 5, 3, 2)
    set_bits(f, 9, 4, 2, 1)
    set_bits(f, 9, 6, 9, 212)
    set_bits(f, 10, 7, 3, 0)
    set_bits(f, 11, 2, 1, 0)
    set_bits(f, 11, 3, 5, 2)  # sta0 DivCopy -> 136
    set_bits(f, 12, 0, 3, 0)
    set_bits(f, 12, 3, 1, 0)
    set_bits(f, 12, 4, 4, 1)
    store_crc24(f, 0, 16)
    set_bits(f, 16, 0, 12, 3)  # sta1 TEI
    set_bits(f, 17, 4, 9, 50)
    set_bits(f, 18, 5, 3, 0)
    set_bits(f, 19, 0, 5, 2)   # sta1 DivCopy -> 136
    store_crc24(f, 16, 16)     # eFC FCS(与 ofdma_frame() 同款;无 FCS 会被 eFC CRC24 门整帧拒收)
    sta0 = app_msdu(2, 0xAABBCCDDEE02)
    sta1 = app_msdu(3, 0xAABBCCDDEE03)
    off = 32
    for chunk in (sta0, sta1):
        f[off:off + 136] = build_pb_block(0xC0, chunk, 136)
        off += 136
    assert off == total
    return bytes(f)


def main():
    frames = [
        ("G0-long", data_sof(msdu_base(1, 5, CCO_MAC, 0xAABBCCDDEE05, 0,
                                        b"\x01\x00\x00\x00" +
                                        assoc_cnf_body(5, 0xAABBCCDDEE05)), 5)),
        ("G0-short", data_sof(msdu_base(1, 5, 0, 0, 0,
                                         b"\x01\x00\x00\x00" +
                                         assoc_cnf_body(5, 0xAABBCCDDEE05),
                                         long_head=False), 5)),
        ("G1", data_sof(msdu_base(1, 2, CCO_MAC, 0xAABBCCDDEE02, 0,
                                   b"\x02\x00\x00\x00" + gather_body()), 2)),
        ("G3", data_sof(discover_body(), 1, src_tei=9)),
        ("G2-ofdma", ofdma_frame()),
        ("G2-tda", tda_frame()),
    ]
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "crafted.bin"), "wb") as f:
        for name, mpdu in frames:
            body = b"\x00" + mpdu
            f.write(struct.pack("<I", len(body)))
            f.write(body)
            print(f"{name}: mpdu={len(mpdu)}B")
    print("wrote crafted.bin, 6 frames")


if __name__ == "__main__":
    main()
