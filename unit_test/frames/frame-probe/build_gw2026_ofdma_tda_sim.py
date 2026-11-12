#!/usr/bin/env python3
"""Build simulated GW_2026 OFDMA / TDA downlink MPDU frames for field-tree testing.

Bit order: LSB-first continuous bitstream, matching get_bits() in the C++ code
(field bit i -> byte (bit+i)//8, bit (bit+i)%8).

CRC: crc24_lsb from protocol/common/crc.h (poly=0xC60001, init=0, LSB-first,
computed over len-3 bytes, stored in the last 3 bytes little-endian).
FCH FCS: crc over bytes 0..12, stored at 13..15.
PBCS: crc over head+body, stored in the last 3 bytes of each PB block.
eFC FCS (OFDMA 表 11 / TDA 表 13):same convention over eFC bytes 0..12, stored 13..15.

Design notes (see gw2026_ofdma_tda_sim_notes.md):
- Frames are spec-correct at FCH/eFC/station-PB level (tables 10/11 for OFDMA,
  table 12 + tree's table-13 reading for TDA).
- Parser's generic (table-7) reads land on subtype-specific bits, so it derives
  garbage pb_size/pb_num -- steered here to a NON-rejecting range so the frame
  still reaches the tree: OFDMA -> pb_size 72, pb_num 3 (needs 232B <= 440B);
  TDA -> pb_size 72, pb_num 1 (needs 88B <= 304B). The generic blocks' CRCs
  will FAIL (red PB nodes) -- that is the known bug symptom, not a bad frame.
- Tree's "FCH Symbol Num" for non-data subtypes renders the parser's table-7
  position value (9,7)+(10,0), NOT the subtype position (9,4,2): both frames
  set spec FCH sym = 1 (Standard) while the parser reads 2 (Long), so the
  discrepancy is visible in the tree.
"""

import os

# ---------- bit helpers ----------
def set_bits(buf, byte, bit, length, value):
    for i in range(length):
        pos = byte * 8 + bit + i
        if (value >> i) & 1:
            buf[pos // 8] |= (1 << (pos % 8))
        else:
            buf[pos // 8] &= ~(1 << (pos % 8))


def get_bits(buf, byte, bit, length):
    v = 0
    for i in range(length):
        pos = byte * 8 + bit + i
        v |= ((buf[pos // 8] >> (pos % 8)) & 1) << i
    return v


def crc24_lsb(d, length):
    """d: bytes-like; length = full length incl. 3 CRC bytes; crc over first len-3."""
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
    """Compute crc over buf[start:start+length] (first len-3 bytes) and store LE
    in the last 3 bytes of that range."""
    calc = crc24_lsb(buf[start:start + length], length)
    buf[start + length - 3] = calc & 0xFF
    buf[start + length - 2] = (calc >> 8) & 0xFF
    buf[start + length - 1] = (calc >> 16) & 0xFF
    return calc


# ---------- GW_2026 tables (gw_2026_pb_table.h) ----------
def tmi_pb_size(tmi):
    if tmi in (0, 1):
        return 520
    if 2 <= tmi <= 6:
        return 136
    if 7 <= tmi <= 10:
        return 520
    if tmi in (11, 12):
        return 264
    if tmi in (13, 14):
        return 72
    return -1


PB_NUM_TABLE = [
    [4, 4, 4, 4, 4, 4, 4, 3, 4, 4, 4, 4, 4, 4, 4, 0,
     4, 4, 4, 4, 4, 4, 0, 0, 0, 4, 4, 4, 4, 4],
    [3, 4, 4, 2, 4, 4, 4, 1, 1, 2, 3, 4, 2, 4, 4, 0,
     4, 4, 4, 4, 4, 4, 0, 0, 0, 4, 4, 4, 4, 4],
    [2, 4, 4, 1, 2, 3, 4, 0, 1, 1, 2, 2, 1, 4, 4, 0,
     4, 4, 4, 4, 4, 4, 0, 0, 0, 4, 4, 4, 4, 4],
    [1, 2, 3, 0, 1, 1, 2, 0, 0, 0, 1, 1, 0, 4, 2, 0,
     4, 4, 4, 4, 2, 4, 0, 0, 0, 4, 4, 4, 4, 4],
]


def max_pb_num(band, tmi, tmi_ext=0):
    if band >= 4:
        return -1
    if tmi <= 14:
        col = tmi
    elif 1 <= tmi_ext <= 14:
        col = 16 + (tmi_ext - 1)
    else:
        return -1
    return PB_NUM_TABLE[band][col]


def pb_num_decode(code):
    return code + 1


# ---------- PB block ----------
def build_pb_block(head, body):
    blk = bytearray(1 + len(body) + 3)
    blk[0] = head
    blk[1:1 + len(body)] = body
    store_crc24(blk, 0, len(blk))
    return blk


def pattern_body(tag, length):
    body = bytearray()
    seed = tag + "-"
    i = 0
    while len(body) < length:
        body.append(ord(seed[i % len(seed)]))
        i += 1
    return bytes(body[:length])


# ---------- OFDMA frame ----------
def build_ofdma():
    # FCH 16 + eFC 16 + station payloads: sta0 2x136 + sta1 1x136 = 440
    total = 16 + 16 + 3 * 136
    f = bytearray(total)
    set_bits(f, 0, 0, 3, 1)          # delimiter type = SOF
    set_bits(f, 1, 0, 16, 0x1234)    # NID
    set_bits(f, 4, 0, 12, 1)         # src TEI = CCO 1
    set_bits(f, 5, 4, 12, 2)         # dst TEI = sta0 2
    set_bits(f, 7, 0, 3, 2)          # frame type = OFDMA downlink
    set_bits(f, 7, 3, 2, 1)          # station num code 1 = 2 stations
    set_bits(f, 7, 5, 3, 2)          # TF symbol num code 2 = 6 symbols
    set_bits(f, 8, 0, 12, 0x200)     # frame length (x10us)
    set_bits(f, 9, 4, 2, 1)          # FCH symbol num (table 10) = 1 Standard
    set_bits(f, 9, 6, 9, 212)        # payload symbol num = 212 (steers parser)
    set_bits(f, 10, 7, 3, 2)         # eFC symbol num code 2 = 8 symbols
    set_bits(f, 11, 2, 1, 1)         # sta0 PB num bit = 1 -> 2 blocks
    set_bits(f, 11, 3, 5, 2)         # sta0 DivCopy (TMI) = 2 -> PB 136
    set_bits(f, 12, 0, 4, 5)         # sta0 RU = 5
    set_bits(f, 12, 4, 4, 1)         # std version = HDC 2.0
    store_crc24(f, 0, 16)            # FCH FCS -> bytes 13..15
    # eFC (table 11): sta1 entry at 16..18, rest reserved, FCS at 29..31
    set_bits(f, 16, 0, 12, 3)        # eFC sta1 DstTEI = 3
    set_bits(f, 17, 4, 4, 6)         # eFC sta1 RU = 6
    set_bits(f, 18, 0, 5, 2)         # eFC sta1 DivCopy (TMI) = 2 -> PB 136
    set_bits(f, 18, 5, 1, 0)         # eFC sta1 PB num bit = 0 -> 1 block
    set_bits(f, 18, 6, 2, 0)         # RSV
    store_crc24(f, 16, 16)           # eFC FCS -> bytes 29..31
    # station payloads from byte 32: sta0 PB0/PB1, sta1 PB0 (each 136)
    off = 32
    for head, tag in ((0x40, "OFDMA-STA0-PB0"), (0x81, "OFDMA-STA0-PB1"),
                      (0xC0, "OFDMA-STA1-PB0")):
        blk = build_pb_block(head, pattern_body(tag, 132))
        f[off:off + 136] = blk
        off += 136
    assert off == total
    return bytes(f)


# ---------- TDA frame ----------
def build_tda():
    # FCH 16 + eFC region 16 (sta1 entry 4B + pad) + station payloads 2x136 = 304
    total = 16 + 16 + 2 * 136
    f = bytearray(total)
    set_bits(f, 0, 0, 3, 1)          # delimiter type = SOF
    set_bits(f, 1, 0, 16, 0x1234)    # NID
    set_bits(f, 4, 0, 12, 1)         # src TEI = CCO 1
    set_bits(f, 5, 4, 12, 2)         # dst TEI = sta0 2
    set_bits(f, 7, 0, 3, 3)          # frame type = TDA downlink
    set_bits(f, 7, 3, 2, 1)          # station num code 1 = 2 stations
    set_bits(f, 7, 5, 3, 2)          # TF symbol num code 2 = 6 symbols
    set_bits(f, 8, 0, 12, 0x200)     # frame length (x10us)
    set_bits(f, 9, 4, 2, 1)          # frame control symbol num (table 12) = 1
    set_bits(f, 9, 6, 9, 212)        # sta0 payload symbol num = 212 (steers parser)
    set_bits(f, 10, 7, 3, 0)         # eFC symbol num code 0 = 2 symbols
    set_bits(f, 11, 2, 1, 0)         # Encrypted (TDA) = 0
    set_bits(f, 11, 3, 5, 2)         # sta0 DivCopy (TMI) = 2 -> PB 136
    set_bits(f, 12, 0, 3, 0)         # sta0 TF & payload band = 0
    set_bits(f, 12, 3, 1, 0)         # sta0 TF flag = 0 Carried
    set_bits(f, 12, 4, 4, 1)         # std version = HDC 2.0
    store_crc24(f, 0, 16)            # FCH FCS -> bytes 13..15
    # eFC sta1 (tree's table-13 reading, 4B at 16..19); 20..31 padded 0.
    # NOTE: table 13 md text is suspect (looks like ACK fields); the 4B layout
    # follows gw_2026_tree.cpp's TDA eFC branch, pending PDF verification.
    set_bits(f, 16, 0, 12, 3)        # eFC sta1 DstTEI = 3
    set_bits(f, 17, 4, 9, 50)        # eFC sta1 payload symbol num = 50
    set_bits(f, 18, 5, 3, 0)         # eFC sta1 band = 0
    set_bits(f, 19, 0, 5, 2)         # eFC sta1 DivCopy (TMI) = 2 -> PB 136
    set_bits(f, 19, 5, 3, 0)         # RSV
    store_crc24(f, 16, 16)           # eFC FCS -> bytes 29..31(与 OFDMA 同款;
                                     # 旧版生成器漏写,帧尾 CRC 全 0,带 eFC CRC
                                     # 校验的解析器会整帧拒收)
    # station payloads from byte 32: sta0 PB, sta1 PB (each 136, single block)
    off = 32
    for head, tag in ((0xC0, "TDA-STA0-PB0"), (0xC0, "TDA-STA1-PB0")):
        blk = build_pb_block(head, pattern_body(tag, 132))
        f[off:off + 136] = blk
        off += 136
    assert off == total
    return bytes(f)


# ---------- verification mimicking parser + tree reads ----------
def verify(name, f, expect):
    print(f"== {name}: len={len(f)} ==")
    # FCH FCS
    calc = crc24_lsb(f[0:16], 16)
    stored = f[13] | (f[14] << 8) | (f[15] << 16)
    print(f"  FCH FCS calc=0x{calc:06x} stored=0x{stored:06x} ok={calc == stored}")
    assert calc == stored
    # parser generic reads (table 7 positions)
    dtype = get_bits(f, 7, 0, 3)
    mod_mode = get_bits(f, 10, 1, 1)
    mod_param = get_bits(f, 10, 2, 5)
    pb_code = get_bits(f, 10, 7, 1) | (get_bits(f, 11, 0, 1) << 1)
    pb_num = pb_num_decode(pb_code)
    pb_size = tmi_pb_size(mod_param) if mod_mode == 0 else (
        {0: 72, 1: 136, 2: 264, 3: 520}.get(mod_param, -1))
    band = get_bits(f, 11, 4, 3)
    mx = max_pb_num(band, mod_param, 0)
    fch_sym_parser = get_bits(f, 9, 7, 1) | (get_bits(f, 10, 0, 1) << 1)
    print(f"  parser: type={dtype} mod_mode={mod_mode} mod_param={mod_param} "
          f"pb_code={pb_code} pb_num={pb_num} pb_size={pb_size} band={band} "
          f"max_pb={mx} fch_sym(parser pos)={fch_sym_parser}")
    print(f"  parser: needs {16 + pb_num * pb_size}B, truncated="
          f"{16 + pb_num * pb_size > len(f)}, rejected="
          f"{pb_size <= 0 or pb_num == 0 or pb_num > mx}")
    assert pb_size > 0 and 1 <= pb_num <= mx and 16 + pb_num * pb_size <= len(f)
    for i in range(pb_num):
        blk = f[16 + i * pb_size:16 + (i + 1) * pb_size]
        c = crc24_lsb(blk, pb_size)
        s = blk[pb_size - 3] | (blk[pb_size - 2] << 8) | (blk[pb_size - 1] << 16)
        print(f"  parser block {i}: head=0x{blk[0]:02x} crc_ok={c == s} "
              f"(expected False = bug symptom)")
    # station PB CRCs (spec level)
    for off, tag in expect["station_pbs"]:
        blk = f[off:off + 136]
        c = crc24_lsb(blk, 136)
        s = blk[133] | (blk[134] << 8) | (blk[135] << 16)
        print(f"  station PB @{off} ({tag}): head=0x{blk[0]:02x} crc_ok={c == s}")
        assert c == s
    # tree reads
    print(f"  tree: srcTEI={get_bits(f, 4, 0, 12)} dstTEI={get_bits(f, 5, 4, 12)} "
          f"frame_len={get_bits(f, 8, 0, 12)} type={dtype} "
          f"sta_num_code={get_bits(f, 7, 3, 2)} tf_num={get_bits(f, 7, 5, 3)} "
          f"fch_sym(spec pos)={get_bits(f, 9, 4, 2)}")
    for line in expect["tree"]:
        print(f"  tree: {line}")
    return True


def main():
    ofdma = build_ofdma()
    tda = build_tda()
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "gw2026_ofdma_sim.bin"), "wb") as fh:
        fh.write(ofdma)
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "gw2026_tda_sim.bin"), "wb") as fh:
        fh.write(tda)
    verify("OFDMA", ofdma, {
        "station_pbs": [(32, "sta0 PB0"), (168, "sta0 PB1"), (304, "sta1 PB0")],
        "tree": [
            "Frame Type = 2 - OFDMA Downlink",
            "Station Num = 1 - 2 stations; TF Symbol Num = 2 - 6",
            "FCH Symbol Num displayed = 2 - Long FCH (parser table-7 pos; "
            "spec table-10 pos says 1 - Standard -> visible discrepancy)",
            "Payload Symbol Num = 212; eFC Symbol Num = 2 - 8 symbols",
            "Sta0 PB Num = 2; Sta0 DivCopy = 2; Sta0 RU = 5",
            "eFC Sta1: DstTEI = 3; RU = 6; DivCopy = 2; PBNum = 1",
            "eFC FCS (29..31) = crc24 over eFC bytes 16..28",
            "PB Size (parser) = 72; PB loop from byte 16, 3 blocks, all CRC FAIL",
        ],
    })
    verify("TDA", tda, {
        "station_pbs": [(32, "sta0 PB0"), (168, "sta1 PB0")],
        "tree": [
            "Frame Type = 3 - TDA Downlink",
            "Station Num = 1 - 2 stations; TF Symbol Num = 2 - 6",
            "FCH Symbol Num displayed = 2 - Long FCH (parser table-7 pos; "
            "spec table-12 pos says 1 - Standard -> visible discrepancy)",
            "Sta0 Payload Symbol Num = 212; eFC Symbol Num = 0 - 2 symbols",
            "Encrypted (TDA) = 0; Sta0 DivCopy = 2",
            "Sta0 TF & Payload Band = 0 - 1.953~11.96 MHz; Sta0 TF Flag = 0 - Carried",
            "eFC Sta1: DstTEI = 3; Payload Symbol Num = 50; Band = 0; DivCopy = 2",
            "PB Size (parser) = 72; PB loop from byte 16, 1 block, CRC FAIL",
        ],
    })
    print("OK: both frames written.")


if __name__ == "__main__":
    main()
