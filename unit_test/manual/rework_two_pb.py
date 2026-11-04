"""改造单块136B SOF 报文 → 两块 72B(TMI=13),去掉 padding,保留 MSDU 帧。
交付:改造后 log-hex 行(与 log 同款:isRF+MPDU) + 单帧回放 bin(0x3C..0x3E 转义封装)。
"""
import sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

line = ("0x00 0x01 0xd5 0xa1 0xcd 0x03 0xf0 0xff 0x00 0xd3 0x13 0xb6 0x42 0x00 0xbe 0xe7 0xce 0xc0 0x30 0x00 0xff 0x2f 0x01 0x6b 0x00 0x00 0x29 0x60 0x11 0x08 0x00 0x1e 0x00 0x00 0x01 0x44 0x64 0x51 0x85 0x14 0xff 0xff 0xff 0xff 0xff 0xff 0x08 0x00 0x00 0x00 0x03 0x10 0x00 0x12 0x01 0x44 0x64 0x51 0x85 0x14 0x00 0x00 0x29 0x74 0x77 0x56 0x82 0x18 0x50 0x64 0x02 0x00 0x54 0x01 0x35 0x00 0x01 0x00 0x50 0xef 0xbe 0x02 0x01 0x30 0x06 0x39 0x22 0x66 0xcc 0x95 0x1b 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x95 0x33 0x8e")
raw = bytes(int(x, 16) for x in line.split())
print("输入长度:", len(raw), "(首字节=isRF 0x%02x)" % raw[0])

# MPDU = 去掉 isRF;MPDU 结构: FCH16 + PB136(单块,tmi4)
mpdu = raw[1:]
assert len(mpdu) == 16 + 136, f"MPDU 长度异常 {len(mpdu)}"
fch, pb = mpdu[:16], mpdu[16:16+136]
pb_head = pb[0]
assert pb_head == 0xC0, f"pb_head=0x{pb_head:02x}"
# MSDU 帧 = pb 数据区前 73B(28B 头+41B MMe+4B CRC32),其后 59B 是 padding(移除);
# pb 结构: [0]=PB头, [1:133)=数据区, [133:136)=PB CRC24
msdu_frame = pb[1:1+73]
padding    = pb[1+73:133]
print("MSDU 帧 73B: 头28+MMe41+CRC4; padding 移除 %d B" % len(padding))
assert all(b == 0 for b in padding), "padding 区存在非 0x00 字节,请复核"

def crc24(data):
    reg, poly = 0, 0xC60001
    for i in range(len(data) - 3):
        for j in range(8):
            b = ((data[i] >> j) & 1) ^ (reg & 1)
            reg = (reg >> 1) ^ poly if b else (reg >> 1)
    return reg

def set_bits(buf, byte, bit, length, value):
    mask = ((1 << length) - 1) << bit
    buf[byte] = (buf[byte] & ~mask) | ((value << bit) & mask)

# ---- 新 FCH:改 PBNum=2、TMI=13(72B),其余字段保持,CRC24 重算 ----
fch_new = bytearray(fch)
set_bits(fch_new, 9, 4, 4, 2)    # PBNum = 2
set_bits(fch_new, 11, 4, 4, 13)  # TMI = 13 → pbsize 72
c = crc24(bytes(fch_new))
fch_new[13:16] = bytes([c & 0xFF, (c >> 8) & 0xFF, (c >> 16) & 0xFF])
# FrameLength(8,0,12) 保留原值(上位机不校验),如需可在此更新

# ---- 两块 PB,每块 72B:1B 头 + 68B 数据 + 3B CRC24 ----
# MSDU 帧 73B > 68B → 块0 装前 68B,块1 装余 5B + 补 63B 0x00
pb0_head = 0x40                    # START, seq=0
pb1_head = 0x80 | 1                # END,   seq=1
def build_pb(head, data):
    blk = bytearray([head]) + bytearray(data)
    assert len(blk) == 69
    blk += bytearray(72 - 69)      # 对齐72:69=1+68? 1+68=69 → 再+3 CRC=72
    blk = bytearray([head]) + bytearray(data) + bytearray(72 - 1 - len(data))
    blk = bytearray(72)
    blk[0] = head
    blk[1:1+len(data)] = data
    cc = crc24(bytes(blk))    # 遍历前 72-3=69B(head+68 数据)
    blk[69:72] = bytes([cc & 0xFF, (cc >> 8) & 0xFF, (cc >> 16) & 0xFF])
    return bytes(blk)

blk0 = build_pb(pb0_head, msdu_frame[:68])
blk1 = build_pb(pb1_head, msdu_frame[68:73] + bytes(68 - (73 - 68)))  # 余5B + 63B 填充
assert len(blk0) == 72 and len(blk1) == 72

new_mpdu = bytes(fch_new) + blk0 + blk1
print("新 MPDU 长度:", len(new_mpdu), "= FCH16+PB72×2")
new_line = " ".join(f"0x{x:02x}" for x in b"\x00" + new_mpdu)   # isRF 0x00 前缀(log 同款)
print("\n==== 改造后报文(两块72B,可直接对照 log hex 格式) ====")
print(new_line)

# ---- 封装为单帧回放 bin(viewtest 同款:0x3C + 转义(unesc) + 0x3E) ----
# unesc = [dlen2 LE][ts4=0][phr][opt][ch][isRF=0][MPDU]
unesc = bytearray()
dlen = len(new_mpdu) + 6
unesc += bytes([dlen & 0xFF, (dlen >> 8) & 0xFF])   # 长度(含 media4+MPDU? len+6 视作:2len+4ts+4media? 见下)
# 依据 viewtest 解码:前 2B len → 之后 ts4 + media4 + MPDU;len 字段不参与强校验
unesc += bytes(4)                                    # timestamp 4B
unesc += bytes([0, 0, 0, 0])                         # phr/opt/ch/isRF=0
unesc += new_mpdu
def esc(b):
    out = bytearray()
    for x in b:
        if x in (0x3C, 0x3E, 0x3D):
            out += bytes([0x3D, 0xFF ^ x])
        else:
            out.append(x)
    return bytes(out)
frame = b"\x3C" + esc(bytes(unesc)) + b"\x3E"
outbin = r"D:\code\gitlab\HPLC_HRF_GW\monitor\BPLC_STA_QtMonitor\samples\multi72_2pb.bin"
with open(outbin, "wb") as f:
    f.write(frame)
print("\n回放 bin 已写:", outbin, f"({len(frame)} B)")
print("期望: 主程序回放该文件 → SOF PBNum=2, 两块均 CRC24 OK,")
print("       MMeDiscoveryNodeList 字段(MMType/STATEI/ProxyTEI/Role/LinePhase/成功率/RSV1/UpRoute/DiscoveredNodeList...) 完整解析")
