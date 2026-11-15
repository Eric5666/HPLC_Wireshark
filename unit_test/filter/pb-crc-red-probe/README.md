# pb-crc-red-probe

PB 块 CRC 失败时的解析/标红口径回归，覆盖四个内置解析器（NW_2021 / NW_2026 / GW_2022 / GW_2026）。

用户 2026-11 裁决：

| FC(FCH) CRC | PB 块 CRC | MSDU CRC32 | 期望 |
|---|---|---|---|
| FAIL | — | — | DROP（accept=0） |
| OK | FAIL | OK | 帧解析（FC 字段不变）+ MSDU 解析（摘要/学习对与好帧一致），行红 |
| OK | FAIL | FAIL | 帧解析；MSDU 不采信（摘要空、只留 CRC 证据、无 TEI↔MAC 学习对/拓扑事件），行红 |

国网修复前（GW_2022/GW_2026 的 `sof assemble` 只在
`body_parseable_with_good_msdu_span` 为真时交付 MSDU），第二行在国网恒为「MSDU 缺失」。

## 方法

从入库 fixture 为每个解析器挑「好」单块 SOF 帧（FCH OK、PB CRC 全过、MSDU CRC32 OK），定点变异后用全新解析器重解析：

- **P**：只翻块尾 CRC24 的 3 个字节之一（MSDU 字节含 CRC32 完好）
- **M**：翻块尾 CRC24 一字节 + 翻 MSDU 帧尾 CRC32 一字节
- **F**：翻 FCH 一字节

行色经真实 `PacketListModel` 的 `ForegroundRole` 读回（`QColor(224,64,64)`）。

fixture：`frames/frame-probe/nw_log_tail_pb_crc_fail.bin`、`nw_frame_20261021.bin`、
`nw_frame_20261022_full.bin`、`protocol-gw/gw-learn-probe/crafted.bin`、`ci/roundtrip/roundtrip_test.bin`。

## 构建与运行

```sh
bash build.sh                 # qmake: $QMAKE → $QT_ROOT/bin/qmake → PATH
./build/pb_crc_red_probe      # 可选参数: 仓库根目录;exit 0 = 全部断言通过
```
