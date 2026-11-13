# mac-filter-probe

主界面 MAC 过滤探针：MAC 形状 token（2~6 组两位十六进制冒号分隔，
如 `03:02`，大小写不敏感）在包列表模型自身的 TEI↔MAC 映射表上
按 DNF 展开为命中 TEI 的或；无命中则该组作废、整表达式无组即永假
（不回落子串）；模式可在 MAC 任意字节偏移处出现（顺序敏感，
完整 6 组仍精确）。

## 构建与运行

```
./build.sh
./build/mac_filter_probe
```

## 状态：main 源码下全过

MAC 过滤特性已合入 main（合并提交 `12d1cbc`，分支
`feat/main-filter-mac-search` d5d4629）。对合入后 main 源码构建运行：
**47/47，`RESULT: 0 failures`，exit 0**。
合入前 main（`39e6e42`）源码为 28/47（19 项 MAC 展开断言失败，
属预期内缺特性，非探针缺陷）；若今后对 main 再有失败，
先查特性实现而非探针。

## 第 9 节：剥离后的 MSDU 不得学习映射

`msdu_crc_strip_learning()`（MSDU CRC32 不可用且首个 MSDU span
命中坏 PB CRC 块时用）曾只清发送方 TEI/MAC，漏清目的方，
`PacketListModel::update_tei_mac()` 仍会从目的方学走全局映射。
第 9 节用真实路径验证（`append` → `update_tei_mac`，断言走
`make_export_snapshot().tei_mac` 映射表快照，而非只查 MsduInfo 字段）：
9a 剥离后源/目的/学习对一律不得进映射表；9b 对照组不剥离时三者
都应学到（反向验证，9a 不是恒假断言）。6 项，合计 **53/53**。
反向验证：只回退 `msdu_crc_state.h` 的修复、探针不动时，
9a 的目的方断言恰好失败（`RESULT: 1 failures`），其余全过。
