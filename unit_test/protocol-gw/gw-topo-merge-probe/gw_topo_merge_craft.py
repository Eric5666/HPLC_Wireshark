#!/usr/bin/env python3
"""Craft GW_2026 multi-station frames for the topo-event merge regression probe.

Purpose: one frame carrying MULTIPLE topo events, to confirm merge_msdu_learn
semantics (pairs fully merged, topo event first-non-Other wins, rest dropped).

Bit order: LSB-first continuous bitstream (matches get_bits()).
CRC: crc24_lsb poly=0xC60001, init=0, LSB-first, over len-3 bytes, LE store.
FCH FCS: over bytes 0..12, stored 13..15. OFDMA eFC FCS: over eFC 0..12,
stored eFC 13..15. PB CRC: over head+body, last 3B. PB head 0xC0 = single block.
MAC u64: low byte = first frame byte.

Frames (all carrier, isRF=0, 2 stations x 1 PB block of 136B):
 F1 OFDMA: sta0 AssocCnf success (TEI 11, proxy 2)
           sta1 AssocCnf success (TEI 12, proxy 3)
           -> merged topo must be sta0's AssocCnf; sta1's event dropped.
 F2 TDA:   sta0 AssocCnf success (TEI 21, proxy 2)
           sta1 GatherInd ok (sender TEI 24, proxy 24, listed TEI 22, 23)
           -> merged topo must be sta0's AssocCnf (cross-kind first wins);
              GatherInd listed pairs must still merge.
 F3 OFDMA: sta0 app-data MSDU (TEI 31, no topo event)
           sta1 AssocCnf success (TEI 32, proxy 2)
           -> merged topo must be sta1's AssocCnf (first NON-Other wins,
              a station without an event does not consume the slot).

Output: gw_topo_merge.bin ([u32 len][isRF][MPDU] records) + manifest on stdout.
Helpers copied from ~/workspace/gw_learn_probe/gw_craft.py (proven builders).
"""
import os
import struct
import zlib

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
    # The MSDU CRC32 covers the MSDU data area (payload), not the MAC header.
    # Keep generated station records valid so CRC32-gated topology learning is exercised.
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


def assoc_cnf_body(sta_tei, sta_mac, proxy_tei, link_type=0):
    b = bytearray(41)
    b[0:6] = mac_bytes(sta_mac)
    b[6:12] = mac_bytes(CCO_MAC)
    b[12] = 0  # result: success
    b[13] = 2  # level
    set_bits(b, 14, 0, 12, sta_tei)
    set_bits(b, 15, 4, 1, link_type)
    set_bits(b, 16, 0, 12, proxy_tei)
    return bytes(b)


def assoc_cnf_msdu(sta_tei, sta_mac, proxy_tei, link_type=0):
    # msdu_type 0 = NET_MANAGEMENT, MMe_BASE first byte 0x01 = MME_ASSOC_CNF
    return msdu_base(1, sta_tei, CCO_MAC, sta_mac, 0,
                     b"\x01\x00\x00\x00" + assoc_cnf_body(sta_tei, sta_mac, proxy_tei, link_type),
                     long_head=True)


def gather_body(proxy_tei, entries):
    b = bytearray(32)
    b[0] = 0  # gar: success
    b[1] = 2  # level
    b[2:8] = mac_bytes(CCO_MAC)
    set_bits(b, 8, 0, 12, proxy_tei)
    b[11] = len(entries)  # sta_num
    for i, (tei, mac) in enumerate(entries):
        off = 16 + i * 8
        b[off:off + 6] = mac_bytes(mac)
        set_bits(b, off + 6, 0, 12, tei)
    return bytes(b)


def gather_msdu(sender_tei, sender_mac, proxy_tei, entries):
    # MMe_BASE first byte 0x02 = MME_ASSOC_GATHER_IND
    return msdu_base(1, sender_tei, CCO_MAC, sender_mac, 0,
                     b"\x02\x00\x00\x00" + gather_body(proxy_tei, entries),
                     long_head=True)


def app_msdu(dst_tei, dst_mac):
    return msdu_base(1, dst_tei, CCO_MAC, dst_mac, 48,
                     bytes([0x01, 0x00, 0x00, 0x00]), long_head=True)


def uplink_app_msdu(sta_tei, sta_mac):
    # 站点上行应用数据:MSDU 头源 = 站点自身(TEI+MAC),目的 = CCO。
    # 供多源帧用——各站头源 TEI/MAC 不同,触发 orig_srcs 多源收集分支。
    return msdu_base(sta_tei, 1, sta_mac, CCO_MAC, 48,
                     bytes([0x01, 0x00, 0x00, 0x00]), long_head=True)


def ofdma_frame_11(sta0_tei, sta0_msdu, sta1_tei, sta1_msdu):
    total = 16 + 16 + 2 * 136
    f = bytearray(total)
    f[0:16] = fch_base(sta0_tei, 2)
    set_bits(f, 7, 3, 2, 1)   # 2 stations
    set_bits(f, 7, 5, 3, 2)   # TF symbol num
    set_bits(f, 9, 4, 2, 1)   # FCH symbol num
    set_bits(f, 9, 6, 9, 212)
    set_bits(f, 10, 7, 3, 2)  # eFC symbol num
    set_bits(f, 11, 2, 1, 0)  # sta0 PB num bit -> 1 block
    set_bits(f, 11, 3, 5, 2)  # sta0 DivCopy -> 136
    set_bits(f, 12, 0, 4, 5)  # sta0 RU
    set_bits(f, 12, 4, 4, 1)  # std version
    store_crc24(f, 0, 16)
    set_bits(f, 16, 0, 12, sta1_tei)  # sta1 TEI
    set_bits(f, 17, 4, 4, 6)   # sta1 RU
    set_bits(f, 18, 0, 5, 2)   # sta1 DivCopy -> 136
    set_bits(f, 18, 5, 1, 0)   # sta1 PB num -> 1 block
    store_crc24(f, 16, 16)     # eFC FCS
    off = 32
    for chunk in (sta0_msdu, sta1_msdu):
        f[off:off + 136] = build_pb_block(0xC0, chunk, 136)
        off += 136
    assert off == total
    return bytes(f)


def tda_frame_11(sta0_tei, sta0_msdu, sta1_tei, sta1_msdu):
    total = 16 + 16 + 2 * 136
    f = bytearray(total)
    f[0:16] = fch_base(sta0_tei, 3)
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
    set_bits(f, 16, 0, 12, sta1_tei)  # sta1 TEI
    set_bits(f, 17, 4, 9, 50)
    set_bits(f, 18, 5, 3, 0)
    set_bits(f, 19, 0, 5, 2)   # sta1 DivCopy -> 136
    off = 32
    for chunk in (sta0_msdu, sta1_msdu):
        f[off:off + 136] = build_pb_block(0xC0, chunk, 136)
        off += 136
    assert off == total
    return bytes(f)


def main():
    frames = [
        ("F1-OFDMA",
         ofdma_frame_11(11, assoc_cnf_msdu(11, 0xAABBCCDDEE0B, 2),
                        12, assoc_cnf_msdu(12, 0xAABBCCDDEE0C, 3))),
        ("F2-TDA",
         tda_frame_11(21, assoc_cnf_msdu(21, 0xAABBCCDDEE15, 2),
                      24, gather_msdu(24, 0xAABBCCDDEE18, 24,
                                      ((22, 0xAABBCCDDEE16), (23, 0xAABBCCDDEE17))))),
        ("F3-OFDMA",
         ofdma_frame_11(31, app_msdu(31, 0xAABBCCDDEE1F),
                        32, assoc_cnf_msdu(32, 0xAABBCCDDEE20, 2))),
    ]
    out_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(out_dir, "gw_topo_merge.bin"), "wb") as f:
        for name, mpdu in frames:
            body = b"\x00" + mpdu
            f.write(struct.pack("<I", len(body)))
            f.write(body)
            print(f"{name}: mpdu={len(mpdu)}B")
    print("wrote gw_topo_merge.bin, 3 frames")

    # 多源帧:两站上行应用数据,MSDU 头源 TEI/MAC 均不同(41/42),
    # 帧级无原始 TEI → orig_srcs 收集两个不同源(触发多源分支)
    multi_frames = [
        ("F4-OFDMA-multi",
         ofdma_frame_11(41, uplink_app_msdu(41, 0xAABBCCDDEE29),
                        42, uplink_app_msdu(42, 0xAABBCCDDEE2A))),
    ]
    with open(os.path.join(out_dir, "gw_topo_merge_multi.bin"), "wb") as f:
        for name, mpdu in multi_frames:
            body = b"\x00" + mpdu
            f.write(struct.pack("<I", len(body)))
            f.write(body)
            print(f"{name}: mpdu={len(mpdu)}B")
    print("wrote gw_topo_merge_multi.bin, 1 frame")


if __name__ == "__main__":
    main()
