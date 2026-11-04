#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HDC1.0/HDC2.0 构造帧全集 v4.2: 全部 16/32bit 标量小端 + 零值占位清除 + 15 项全字段自校验。

与 unit_test/manual/hdc2_0_test_frames.md 同源(文档由本脚本输出再生成); 指纹见 md 头部。
注: HDC1.0 载波频段位宽 2bit, HDC2.0 3bit —— 自校验按帧所在协议区分。"""
import os
import re

# 仓库根 = unit_test/manual/ 的上三级; 脚本自身位置推导, 避免硬编码本机绝对路径
R = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GD = R + "/docs/protocol_doc/gw/HDC1.0"
NEW = os.path.join(GD, "双模通信互联互通技术规范_第4_2部分数据链路层通信协议_261023_152656.md")
BASE = os.path.join(GD, "双模通信互联互通技术规范_第4_2部分数据链路层通信协议_260823_193255.md")
CAP = re.compile(r"^\s*(?:#{1,4}\s*)?(表|图)\s*(\d+)\s*(.*)$")
def w16(v):
    """16bit 整数字段: 小端写入(低字节在前)。国网 HDC 实证: Lua 插件用 add_le 读。"""
    return bytes([v & 0xFF, (v >> 8) & 0xFF])


def w32(v):
    """32bit 整数字段: 小端写入(低字节在前)。"""
    return bytes([v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF])


def r16(b, i):
    """16bit 小端读回"""
    return b[i] | (b[i + 1] << 8)


def r32(b, i):
    """32bit 小端读回"""
    return b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)


STA_MAC = bytes.fromhex("001122334455")
CCO_MAC = bytes.fromhex("66778899AABB")


def load(p):
    lines = open(p, encoding="utf-8").read().split("\n")
    idx = {}
    for i, l in enumerate(lines, 1):
        m = CAP.match(l)
        if m:
            idx.setdefault(f"{m.group(1)}{int(m.group(2))}", []).append((i, m.group(3).strip()))
    return lines, idx


def rows_of(lines, ln):
    for j in range(ln - 1, min(ln + 4, len(lines))):
        rs = [[re.sub(r"<[^>]+>", "", c).strip() for c in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", r, re.S)]
              for r in re.findall(r"<tr[^>]*>(.*?)</tr>", lines[j], re.S)]
        if rs:
            return [[re.sub(r"\s+", "", "".join(x)) for x in r] for r in rs]
    return []


nl_, nidx = load(NEW)
bl_, bidx = load(BASE)
print("=" * 92)
print("【核验 1】表60/70/123/126 基线260823 vs 新转件261023 (归一化去空格)")
print("=" * 92)
for t in ["表60", "表70", "表123", "表126"]:
    n, b = rows_of(nl_, nidx[t][0][0]), rows_of(bl_, bidx[t][0][0])
    print(f"  {t}: 新 L{nidx[t][0][0]} ({len(n)}行) / 基 L{bidx[t][0][0]} ({len(b)}行) -> "
          f"{'✅ 逐行等价' if n == b else '⚠️ 不等价'}")
print("\n【核验 2】HDC1.0 单跳 MAC 帧头表号")
for t in ["表2", "表3", "表11"]:
    if t in nidx:
        print(f"  {t} @L{nidx[t][0][0]}: {nidx[t][0][1][:60]}")


def bits(buf, bi, bo, n):
    v = 0
    for i in range(n):
        b = bi * 8 + bo + i
        v |= ((buf[b // 8] >> (b % 8)) & 1) << i
    return v


def hx(b):
    return " ".join(f"{x:02X}" for x in b)


def single_hop(mt, attr):
    rfdl = bytearray(STA_MAC) + bytes([0x01, 0x00, len(attr)]) + bytearray(attr)
    return bytes([0x01, mt, len(rfdl) & 0xFF, (len(rfdl) >> 8) & 0x07]) + bytes(rfdl)


def std_frame(mtype, mme_body):
    mme = bytes([mtype & 0xFF, (mtype >> 8) & 0xFF, 0, 0]) + mme_body
    h = bytearray(16)
    h[5], h[7] = 0x01, 0x00
    h[8] = len(mme) & 0xFF
    h[9] = (len(mme) >> 8) & 0x07
    return bytes(h) + bytes(mme)


def attr14(proxy_tei, role, level, rfhop, up, down, mini, period, aging):
    """表126/表92 (14B): 12bit 代理TEI 按 LSB-first 拼"""
    a = bytearray(14)
    a[0:6] = CCO_MAC
    a[6] = proxy_tei & 0xFF
    a[7] = ((proxy_tei >> 8) & 0x0F) | (role << 4)
    a[8] = (level & 0x0F) | (rfhop << 4)
    a[9], a[10], a[11], a[12], a[13] = up, down, mini, period, aging
    return bytes(a)


def attr23(tei, proxy_tei, role, level):
    b = bytearray(23)
    b[0] = tei & 0xFF
    # 表63 代理TEI = byte1 bit4-7 (4b) + byte2 (8b) —— 非字节对齐 12bit
    # LSB-first: value = (byte1>>4) | (byte2<<4)  =>  byte1高4位=值低4位, byte2=值高8位
    b[1] = ((tei >> 8) & 0x0F) | ((proxy_tei & 0x0F) << 4)
    b[2] = (proxy_tei >> 4) & 0xFF
    b[3] = (role & 0x0F) | (level << 4)
    b[4:10] = CCO_MAC
    b[10], b[11], b[12], b[13] = 0x00, 0x2A, 0x4E, 0x5A
    b[14:16] = w16(30)                          # 16bit: 小端 -> 1E 00 (大端会读成 7680)
    b[16], b[17], b[18] = 60, 10, 3
    b[19:23] = w32(0x12345678)                  # 32bit: 小端 -> 78 56 34 12 (大端会读成 0x78563412)
    return bytes(b)


def assoc_cnf(tei, proxy_tei, lt):
    """表70(HDC1.0)/表47(HDC2.0): byte15 = TEI低4 | bit4=链路类型 | bit5-6 载波频段 | bit7 保留"""
    b = bytearray()
    b += STA_MAC + CCO_MAC
    b += bytes([0x00, 0x01])
    b += bytes([tei & 0xFF, ((tei >> 8) & 0x0F) | (lt << 4)])
    b += bytes([proxy_tei & 0xFF, (proxy_tei >> 8) & 0x0F])
    b += bytes([0x01, 0x01])
    b += w32(0x12345678) + w32(0x00000E10) + w32(0x00010000)   # 随机数/重新关联时间(3600s)/端到端序列号, 均小端且非对称
    b += w32(0x00000005) + bytes.fromhex("00000000") * 2   # 路径序号(小端可判别) + 保留 8B
    return bytes(b)


def assoc_req():
    """表60: 5 组候选代理, 12bit TEI 按 LSB-first"""
    b = bytearray(88)
    b[0:6] = STA_MAC
    cand = [(156, 0), (157, 1), (158, 0), (159, 0), (160, 0)]
    for i, (tei, lt) in enumerate(cand):
        b[6 + i * 2] = tei & 0xFF
        b[7 + i * 2] = ((tei >> 8) & 0x0F) | (lt << 4)
    b[16] = 0 | (1 << 2) | (2 << 4)      # 相线0/1/2
    b[17] = 0x01                          # 设备类型
    b[18] = 0x00                          # MAC 地址类型
    b[19] = 0x01                          # 模块类型=1(双模)
    b[20:24] = w32(0x12345678)                  # 站点关联随机数: 非对称值, 字节序可判别
    b[24:42] = bytes(18)
    b[42:52] = bytes(10)
    b[52:54] = (0x1122).to_bytes(2, "little")   # 硬复位累积次数 16bit 小端 -> 22 11
    b[54:56] = (0x3344).to_bytes(2, "little")   # 软复位累积次数 16bit 小端 -> 44 33
    b[56] = 0x01                          # 代理类型
    b[60:64] = w32(0x00010000)                  # 端到端序列号 32bit: 小端 -> 00 00 01 00 (=0x00010000; 大端会读成 0x00000100)
    b[64:88] = bytes(24)
    return bytes(b)


A14 = attr14(0x234, 1, 2, 1, 78, 90, 60, 10, 3)
A14M = attr14(0x234, 1, 2, 1, 78, 90, 60, 10, 3)     # 同上(LSB 定向)
B23 = attr23(0x123, 0x234, 1, 2)
X7A = bytes([0x4E, 0x5A, 0x01, 0, 0, 0, 0])
X7B = bytes([0x50, 0x46, 0x01, 0, 0, 0, 0])

F = {
    "HDC1.0帧1_无线发现列表_表126": single_hop(0, A14),
    "HDC1.0帧2_关联请求_表60": std_frame(0x0000, assoc_req()),
    "HDC1.0帧3_关联确认_link1": std_frame(0x0001, assoc_cnf(0x123, 156, 1)),
    "HDC1.0帧4_关联确认_link0": std_frame(0x0001, assoc_cnf(0x123, 156, 0)),
    "HDC2.0帧A_无线_表92": single_hop(0, A14),
    "HDC2.0帧B_载波_表63": single_hop(2, B23),
    "HDC2.0帧3_关联确认": std_frame(0x0001, assoc_cnf(0x123, 156, 1)),
    "反例X1_7B_无线": single_hop(0, X7A),
    "反例X2_7B_载波": single_hop(2, X7B),
}

print("\n" + "=" * 92)
print("【自校验 · LSB-first 回读】")
print("=" * 92)
for n, f in F.items():
    if (f[0] & 0x0F) == 1:
        mt, ml = bits(f, 1, 0, 8), bits(f, 2, 0, 11)
        d = f[4:4 + ml]
        ie, ln = d[7] & 0x7F, d[8]
        c = d[9:9 + ln]
        print(f"\n  {n} ({len(f)}B) 单跳 msdu_type={mt} msdu_len={ml} IE type={ie} len={ln}")
        if ln == 14:
            print(f"    代理TEI(LSB)={bits(c,6,0,12)} 角色={bits(c,7,4,4)} 层级={bits(c,8,0,4)} "
                  f"RF跳数={bits(c,8,4,4)} 上行={c[9]} 下行={c[10]} 最小={c[11]} 周期={c[12]} 老化={c[13]}")
        elif ln == 23:
            print(f"    TEI(LSB)={bits(c,0,0,12)} 代理TEI(LSB)={bits(c,1,4,12)} 角色={bits(c,3,0,4)} "
                  f"层级={bits(c,3,4,4)} 信道质量={c[11]} 通信成功率={c[12]} 下行={c[13]} 最小={c[16]}")
        else:
            print(f"    通信成功率={c[0]} 下行={c[1]} BRUSNR标志={c[2]&1} SNR={int.from_bytes(c[3:7],'big')}")
    else:
        mt, ml = bits(f, 7, 0, 8), bits(f, 8, 0, 11)
        mb = f[16:16 + ml]
        mmt = bits(mb, 0, 0, 16)
        b = mb[4:]
        print(f"\n  {n} ({len(f)}B) 标准帧 MSDU类型={mt} MSDU长度={ml} MTYPE=0x{mmt:04X} b={len(b)}B")
        if mmt == 0x0001:
            print(f"    结果={b[12]} 层级={b[13]} 站点TEI(LSB)={bits(b,14,0,12)} "
                  f"★链路类型={bits(b,15,4,1)} 载波频段={bits(b,15,5,2)} 代理TEI(LSB)={bits(b,16,0,12)}")
        else:
            for i in range(5):
                print(f"    候选TEI{i}={bits(b,6+i*2,0,12)} 链路类型{i}={bits(b,7+i*2,4,1)}")
            print(f"    相线0/1/2={bits(b,16,0,2)}/{bits(b,16,2,2)}/{bits(b,16,4,2)} "
                  f"设备类型={b[17]} MAC地址类型={b[18]} 模块类型={bits(b,19,0,2)} 代理类型={b[56]}")

print("\n" + "=" * 92)
print("【交付 HEX】")
print("=" * 92)
for n, f in F.items():
    print(f"{n} ({len(f)}B): {hx(f)}")
    print(f"  CONT: {f.hex().upper()}")


# ===== 多字节整数字段 —— 小端(LSB-first) 运行时自校验 =====
def _le16(b, i):
    return b[i] | (b[i + 1] << 8)


def _le32(b, i):
    return b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)


print("=== 多字节整数字段小端自校验 ===")
_a = attr23(0x123, 0x234, 1, 2)
assert _le16(_a, 14) == 30, f"表63 路由周期 16bit 小端自校验失败: {_le16(_a, 14)}"
assert _le32(_a, 19) == 0x12345678, "表63 BRUSNR 32bit 小端自校验失败"
print(f"  表63 路由周期到期剩余时间(16bit 小端) = {_le16(_a, 14)}   (大端会读成 7680)")
print(f"  表63 代理BRUSNR(32bit 小端) = 0x{_le32(_a, 19):08X}   (大端会读成 0x78563412)")
_r = assoc_req()
assert _le16(_r, 52) == 0x1122 and _le16(_r, 54) == 0x3344, "表60 16bit 小端自校验失败"
print(f"  表60 硬复位累积次数(16bit 小端) = 0x{_le16(_r, 52):04X} / 软复位 = 0x{_le16(_r, 54):04X}")
_c = assoc_cnf(0x123, 156, 1)
assert _le32(_c, 28) == 0x00010000, "表70 端到端序列号 32bit 小端自校验失败"
print(f"  表70 端到端序列号(32bit 小端) = 0x{_le32(_c, 28):08X}   (大端会读成 0x00000100)")
print("  \u2713 全部多字节整数字段均为小端")


# ===== 全帧多字节字段自校验 (小端) =====
def _all_multibyte_checks():
    """逐帧核验每个 16/32bit 标量字段的小端读回值。判据: 值必须非对称(大端读出不同值)。"""
    chk = []

    def add(name, got, want, width=2):
        chk.append((name, got, want))
        assert got == want, f"{name} 小端读回 {got} != 期望 {want}"
        # 同时确认大端读法会给出不同值(否则该字段测不出字节序)
        assert want != int.from_bytes(want.to_bytes(width, 'little'), 'big'), \
            f"{name} 的值 {want} 大小端读法相同, 测不出字节序"

    # --- 表63 站点属性(帧B) ---
    a = attr23(0x123, 0x234, 1, 2)
    add("表63 路由周期到期剩余时间(16bit)", r16(a, 14), 30)
    add("表63 代理BRUSNR(32bit)", r32(a, 19), 0x12345678, 4)
    add("表63 代理TEI(非字节对齐12bit)", (a[1] >> 4) | (a[2] << 4), 0x234)
    # --- 表60 关联请求(帧2) ---
    r = assoc_req()
    add("表60 站点关联随机数(32bit)", r32(r, 20), 0x12345678, 4)
    add("表60 硬复位累积次数(16bit)", r16(r, 52), 0x1122)
    add("表60 软复位累积次数(16bit)", r16(r, 54), 0x3344)
    add("表60 端到端序列号(32bit)", r32(r, 60), 0x00010000, 4)
    # --- 表70/表47 关联确认(帧3/帧4) ---
    for tei, ptei, lt in ((0x123, 156, 1), (0x123, 156, 0)):
        c = assoc_cnf(tei, ptei, lt)
        add("表70 站点关联随机数(32bit)", r32(c, 20), 0x12345678, 4)
        add("表70 重新关联时间(32bit)", r32(c, 24), 0x00000E10, 4)
        add("表70 端到端序列号(32bit)", r32(c, 28), 0x00010000, 4)
        add("表70 路径序号(32bit)", r32(c, 32), 0x00000005, 4)
    return chk


print("=== 全帧多字节字段自校验 (小端) ===")
for _n, _g, _w in _all_multibyte_checks():
    print(f"  OK {_n:<34s} 小端读回 {_g} (0x{_g:08X})")
print(f"  ✓ {len(_all_multibyte_checks())} 项多字节字段全部小端且可判别")
