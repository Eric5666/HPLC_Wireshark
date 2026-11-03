# info-crc-probe

Info 列 CRC 状态探针（截断误报 CRC OK 回归）。

## 构建与运行

```
QT_ROOT=/path/to/6.11.2/gcc_64 ./build.sh
./build/info_crc_probe
```

`QT_ROOT` 可省略，默认使用 `$HOME/qt/6.11.2/gcc_64`。

全合成条目，无输入文件。

## 检查内容

- 截断帧（已收块全过、`pb_crc_ok=false` 且实收块少于声明块）的 Info 不报 `CRC OK`，报
  `CRC 不完整（截断）`（默认分支；此前误报 `CRC OK`，与红行矛盾）。
- PB 序号乱序导致的重组失败（已收块全过但实收块数已齐）不误报为截断，报
  `CRC 不完整（重组失败）`。
- 完整全好仍报 `CRC OK`；块 CRC 失败仍报 `CRC FAIL(1/2)`；`oks` 为空
  不报任何 CRC 文案（此前行为不变）。
- 训练分支同门（人为 `oks` 非空，真实训练帧无块、`oks` 为空故无文案）。

## 不覆盖

OFDMA 多站分支：`pb_crc_ok` 在多站路未定义（恒 false），故不套用
此门；多站截断检测与 `pb_crc_ok` 语义另案。

## 预期结果

`RESULT: ALL PASS`，exit 0。
