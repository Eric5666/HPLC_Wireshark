#!/usr/bin/env python3
# Craft NW_2026 (SPLC) test MPDUs with known TEI-MAC pairs for the learn probe.
# Layouts verified against nw_2026_parser.cpp / nw_2026_msdu_parser.cpp.
# All CRCs: crc24_lsb (poly 0xC60001, init 0, LSB-first), stored LE.
import struct, os, zlib

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crafted")
os.makedirs(OUT, exist_ok=True)

def crc24(data):
    poly = 0xC60001
    crc = 0
    for b in data:
        for j in range(8):
            bit_in = (b >> j) & 1
            bit_lsb = crc & 1
            crc >>= 1
            if bit_in ^ bit_lsb:
                crc ^= poly
    return crc & 0xFFFFFF

def set_bits(buf, byte, bit, n, value):
    for k in range(n):
        pos = byte * 8 + bit + k
        if (value >> k) & 1:
            buf[pos // 8] |= (1 << (pos % 8))
        else:
            buf[pos // 8] &= ~(1 << (pos % 8))

def mac_bytes(mac_hex):
    # frame order: first byte = low byte of the u64 convention
    parts = mac_hex.split(":")
    return bytes(int(x, 16) for x in parts)

CCO = (1, "02:00:00:00:00:01")
STA_A = (2, "02:00:00:00:00:02")
STA_B = (3, "02:00:00:00:00:03")
STA_C = (5, "02:00:00:00:00:05")

def fch(src_tei, dst_tei, byte4, byte6, frame_len=0x200):
    f = bytearray(16)
    f[0] = 0x01  # SOF, SNID low 0
    set_bits(f, 1, 0, 12, src_tei)
    set_bits(f, 2, 4, 12, dst_tei)
    f[4] = byte4
    f[6] = byte6
    set_bits(f, 8, 0, 12, frame_len)
    set_bits(f, 12, 4, 4, 2)  # version 2
    c = crc24(bytes(f[:13]))
    f[13], f[14], f[15] = c & 0xFF, (c >> 8) & 0xFF, (c >> 16) & 0xFF
    return bytes(f)

def msdu(src, dst, portion):
    # src/dst: (tei, mac_hex). portion: MSDU-header+payload bytes (after 32B MAC header).
    m = bytearray(32)
    m[0] = 0x00  # MACHeadFlag 0 = LONG (32B), version bits 0
    struct.pack_into("<H", m, 2, len(portion))
    set_bits(m, 4, 0, 12, dst[0])
    set_bits(m, 5, 4, 12, src[0])
    body = bytes(m) + portion
    return body

def msdu_header(dst, src, mgmt):
    h = bytearray(18)
    h[0:6] = mac_bytes(dst[1])
    h[6:12] = mac_bytes(src[1])
    if mgmt:
        h[12:16] = bytes([0x00, 0x81, 0x00, 0x00])  # VLAN u32 == 0x8100 (LE)
        h[16:18] = bytes([0xE1, 0x88])              # type 0x88E1 (LE)
    return bytes(h)

def pb(seq, agg, body, pb_size):
    assert len(body) == pb_size - 8, (len(body), pb_size)
    head = bytearray(4)
    struct.pack_into("<H", head, 0, seq)
    head[2] = 0x01 if agg else 0x00
    blk = bytes(head) + body + b"\x00"
    c = crc24(blk)
    return blk + bytes([c & 0xFF, (c >> 8) & 0xFF, (c >> 16) & 0xFF])

def data_msdu(src, dst, total):
    # total: full MSDU bytes (32 + portion). portion = 18 header + payload.
    portion = msdu_header(dst, src, False) + bytes(total - 32 - 18)
    return msdu(src, dst, portion)

def mme_msdu(src, dst, mme_type, body, pad_to):
    mme = bytes([0x01, mme_type & 0xFF, (mme_type >> 8) & 0xFF, 0, 0, 0]) + body
    portion = msdu_header(dst, src, True) + mme
    # MSDU 帧尾 4B CRC32(载荷区 = MAC 头 32B 之后 MSDULength 字节;与 crc.h::crc32_le 同语义 =
    # zlib.crc32,小端)。旧版不写 CRC、后面直接补零:补的 0 被当成 CRC32 ⇒ FAIL ⇒ MSDU CRC 门控
    # 清空摘要、不学习(TEI 列表 / Gather 两帧学不到),属夹具过时而非解析器回归。
    full = msdu(src, dst, portion) + struct.pack("<I", zlib.crc32(portion) & 0xFFFFFFFF)
    assert len(full) <= pad_to
    return full + bytes(pad_to - len(full))

def teilist_body(entries):
    b = bytearray(8)
    b[7] = len(entries)
    for tei, mac in entries:
        b += mac_bytes(mac)
        b += bytes([tei & 0xFF, (tei >> 8) & 0x0F])
    return bytes(b)

def gather_body(cco_mac, proxy_tei, entries):
    b = bytearray(28)
    b[0] = 0  # AssocResult 0 = allowed
    b[2:8] = mac_bytes(cco_mac)
    set_bits(b, 8, 0, 12, proxy_tei)
    b[11] = len(entries)
    for tei, mac in entries:
        b += mac_bytes(mac)
        b += bytes([tei & 0xFF, (tei >> 8) & 0x0F])
    return bytes(b)

# 1. TEI_LIST_CNF (0x0084): CCO -> STA_C, entries STA_A, STA_B
m = mme_msdu(CCO, STA_C, 0x0084, teilist_body([STA_A, STA_B]), 512)
sof = fch(1, 5, 0x04, 0x00) + pb(0, False, m, 520)
open(f"{OUT}/craft_teilist.bin", "wb").write(sof)

# 2. GatherInd (0x003A): CCO -> STA_C, proxy 1, entries STA_A, STA_B
m = mme_msdu(CCO, STA_C, 0x003A, gather_body(CCO[1], 1, [STA_A, STA_B]), 512)
sof = fch(1, 5, 0x04, 0x00) + pb(0, False, m, 520)
open(f"{OUT}/craft_gather.bin", "wb").write(sof)

# 3. Cascade: 1 PB (TMI 9 -> 264B), 2 segments x 126B MSDU, exact-fit stream 256B
#    (CCO 下行级联:两段目的 STA 不同,验证每段独立学习)
mac1 = data_msdu(CCO, STA_A, 126)
mac2 = data_msdu(CCO, STA_B, 126)
def cas_hdr(length, start, end):
    return bytes([length & 0xFF, ((length >> 8) & 0x0F) | (0x10 if start else 0) | (0x20 if end else 0)])
stream = cas_hdr(126, True, False) + mac1 + cas_hdr(126, False, True) + mac2
assert len(stream) == 256
sof = fch(1, 0xFFF, 0x04, 0x12) + pb(0, True, stream, 264)
open(f"{OUT}/craft_cascade.bin", "wb").write(sof)

# 4. DL-OFDMA type 0, 2 stations: sta0 1x136 (TEI 2, TMI 18), sta1 1x72 (TEI 3, TMI 21)
efc = bytearray(16)
bp = 2
for pbn, tei, tmi, ru in [(0, 2, 18, 5), (0, 3, 21, 6)]:
    set_bits(efc, bp // 8, bp % 8, 1, pbn); bp += 1
    set_bits(efc, bp // 8, bp % 8, 12, tei); bp += 12
    set_bits(efc, bp // 8, bp % 8, 5, tmi); bp += 5
    set_bits(efc, bp // 8, bp % 8, 4, ru); bp += 4
    set_bits(efc, bp // 8, bp % 8, 3, 0); bp += 3
c = crc24(bytes(efc[:13]))
efc[13], efc[14], efc[15] = c & 0xFF, (c >> 8) & 0xFF, (c >> 16) & 0xFF
sta0 = data_msdu(CCO, STA_A, 128)
sta1 = data_msdu(CCO, STA_B, 64)
sof = fch(1, 0xFFF, 0x41, 0x00) + bytes(efc) + pb(0, False, sta0, 136) + pb(0, False, sta1, 72)
open(f"{OUT}/craft_dl_ofdma.bin", "wb").write(sof)

# 5. UL-OFDMA data (feeds AFTER real trigger: sta0 1x136 TEI 2, sta1 2x72 TEI 3)
sta0 = data_msdu(STA_A, CCO, 128)
s1a = data_msdu(STA_B, CCO, 128)[:64]
s1b = data_msdu(STA_B, CCO, 128)[64:]
sof = fch(2, 1, 0x43, 0x00) + pb(0, False, sta0, 136) + pb(0, False, s1a, 72) + pb(1, False, s1b, 72)
open(f"{OUT}/craft_ul_data.bin", "wb").write(sof)

for f in sorted(os.listdir(OUT)):
    print(f, os.path.getsize(f"{OUT}/{f}"))
