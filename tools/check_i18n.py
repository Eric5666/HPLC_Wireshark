#!/usr/bin/env python3
"""i18n 配对与裸中文字符串自查。

用法:
    py -3 tools/check_i18n.py [--strict] [--list]

三类问题:
  ① 裸中文字符串: QString("中文") / QStringLiteral("中文") 未走 trl::L
     —— 英文界面会直接显示中文
     —— 排除「中英成对」结构(同一行或相邻行紧跟一个纯英文串)
     —— 排除示例插件目录 (src/plugin/examples/)
  ② 未配对键: trl::L("X") 的 X 不在任何 register_en 第一参数集合中
  ③ 死键: register_en("X", ...) 的 X 没有任何 trl::L("X") 使用

退出码: --strict 且有 ①/②/③ 任一问题时返回 1，否则 0。
"""
from __future__ import annotations

import argparse
import os
import re
import sys

CJK = re.compile(r'[\u4e00-\u9fff]')
# QString("...") / QStringLiteral("...") —— 只取第一个字符串字面量参数
STR_LIT = re.compile(r'(?P<kind>QString|QStringLiteral)\s*\(\s*"(?P<s>(?:[^"\\]|\\.)*)"')
REGISTER_EN = re.compile(
    r'register_en\s*\(\s*"(?P<zh>(?:[^"\\]|\\.)*)"\s*,\s*"(?P<en>(?:[^"\\]|\\.)*)"\s*\)'
)
TRL_L = re.compile(r'trl::L\s*\(\s*"(?P<zh>(?:[^"\\]|\\.)*)"')

# 示例插件：中英混排是 demo 语义，不参与生产文案门禁
EXCLUDE_DIRS = (
    'plugin/examples/',
)

SRC_EXT = ('.cpp', '.h')


def rel_posix(path: str, root: str) -> str:
    return os.path.relpath(path, root).replace('\\', '/')


def collect(root: str):
    """返回 {rel: text}"""
    out = {}
    for dp, _, fs in os.walk(root):
        for fn in fs:
            if not fn.endswith(SRC_EXT):
                continue
            p = os.path.join(dp, fn)
            rel = rel_posix(p, root)
            if any(rel.startswith(d) or '/' + d in '/' + rel for d in EXCLUDE_DIRS):
                continue
            try:
                out[rel] = open(p, encoding='utf-8', errors='replace').read()
            except OSError:
                pass
    return out


def is_wrapped_by_trl(txt: str, pos: int) -> bool:
    """该位置是否已被 trl::L( 包裹(前 16 字符内出现)"""
    return 'trl::L(' in txt[max(0, pos - 16):pos]


def has_sibling_english(txt: str, start: int, end: int) -> bool:
    """成对结构识别: 在本串所在行及相邻行内, 是否存在另一个 QString/QStringLiteral
    且其内容为纯英文(含字母、无中文)。这种情况下中文串视为双语对的一半, 跳过。

    典型形态:
        {QStringLiteral("BPLC_APP_VERSION"),
         QStringLiteral("宿主程序版本"), QStringLiteral("Host app version"), ...}
    """
    # 取本位置所在行 + 上下各一行
    lo = txt.rfind('\n', 0, start)
    lo = 0 if lo < 0 else lo
    prev_nl = txt.rfind('\n', 0, lo)
    if prev_nl >= 0:
        lo = prev_nl + 1
    hi = txt.find('\n', end)
    hi = len(txt) if hi < 0 else hi
    nxt = txt.find('\n', hi + 1)
    if nxt >= 0:
        hi = nxt

    window = txt[lo:hi]
    for m in STR_LIT.finditer(window):
        s = m.group('s')
        if CJK.search(s):
            continue
        if re.search(r'[A-Za-z]{2,}', s):     # 有连续英文单词
            return True
    return False


def scan(root: str):
    files = collect(root)

    reg_keys = {}
    for rel, txt in files.items():
        for m in REGISTER_EN.finditer(txt):
            reg_keys.setdefault(m.group('zh'), []).append(
                (rel, txt[:m.start()].count('\n') + 1)
            )

    used_keys = set()
    dynamic_files = set()   # 存在 trl::L(<非字面量>) 调用的文件 —— 其键可能被值表动态使用
    dyn_l = re.compile(r'trl::L\s*\(\s*(?!")')
    bare = []
    for rel, txt in files.items():
        for m in TRL_L.finditer(txt):
            used_keys.add(m.group('zh'))
        if dyn_l.search(txt):
            dynamic_files.add(rel)

        for m in STR_LIT.finditer(txt):
            s = m.group('s')
            if not CJK.search(s):
                continue
            if is_wrapped_by_trl(txt, m.start()):
                continue
            if has_sibling_english(txt, m.start(), m.end()):
                continue
            bare.append((rel, txt[:m.start()].count('\n') + 1, s))

    unpaired = []
    for rel, txt in files.items():
        for m in TRL_L.finditer(txt):
            zh = m.group('zh')
            if zh not in reg_keys:
                unpaired.append((rel, txt[:m.start()].count('\n') + 1, zh))

    dead = []
    for k, v in reg_keys.items():
        if k in used_keys:
            continue
        # 若注册点所在文件存在 trl::L(<非字面量>) 调用，则该键可能是值表被动态使用
        if any(rel in dynamic_files for rel, _ in v):
            continue
        dead.append((k, v))

    return bare, unpaired, dead, len(reg_keys)


def main() -> int:
    ap = argparse.ArgumentParser(description='i18n 配对与裸中文自查')
    ap.add_argument('--strict', action='store_true', help='有裸中文、未配对键或死键时返回非 0')
    ap.add_argument('--list', action='store_true', help='列出全部明细')
    ap.add_argument('--root', default='src', help='源码根目录(默认 src)')
    args = ap.parse_args()

    if not os.path.isdir(args.root):
        print(f'错误: 目录不存在 {args.root}', file=sys.stderr)
        return 2

    bare, unpaired, dead, nkeys = scan(args.root)

    print(f'register_en 键: {nkeys}')
    print(f'  ① 裸中文未走 trl::L : {len(bare)}')
    print(f'  ② trl::L 未配对键   : {len(unpaired)}')
    print(f'  ③ register_en 死键  : {len(dead)}')
    print()

    if bare:
        print('=== ① 裸中文(英文界面会显示中文, 必须修)===')
        for rel, ln, s in bare:
            print(f'  {rel}:{ln}')
            print(f'      {s!r}')
        print()

    if unpaired:
        print('=== ② trl::L 未配对 ===')
        for rel, ln, s in unpaired:
            print(f'  {rel}:{ln}  {s!r}')
        print()

    if dead:
        print('=== ③ register_en 死键(无人使用) ===')
        for k, locs in sorted(dead):
            where = ', '.join(f'{r}:{l}' for r, l in locs)
            print(f'  {k!r}  @ {where}')
        print()

    if not bare and not unpaired and not dead:
        print('✅ 全部通过')

    return 1 if (args.strict and (bare or unpaired or dead)) else 0


if __name__ == '__main__':
    sys.exit(main())
