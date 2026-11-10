# frame-probe（原名 frame_probe）

NW_2021 帧探针本体 + GW/NW 构造帧生成脚本与输入。
本目录的 .bin 同时是其他用例的输入（gw2026-tree-probe、
nw2026-ul-probe、nextgen-probe、frame-probe-variant3），
不要只看本目录的构建状态。

## 状态：构建失败（已记录，未改源码）

与 coord-probe 同因：`main.cpp:67` 读 `MpduInfo.coord_option`，
现为 `coord_duration`。原样记录，待另行修复。

## 输入（10 个小 .bin，已入库）

- `gw2026_ofdma_sim.bin`（440B）、`gw2026_tda_sim.bin`（304B）：
  GW_2026 OFDMA/TDA 下行 2 站构造帧（裸 MPDU，供 gw2026-tree-probe）。
- `nw2026_trigger.bin`（32B）、`nw2026_ul_ofdma_data.bin`（296B）、
  `nw2026_dl_sack.bin`（32B）：nw2026-ul-probe 三件套。
- `nw_frame_20261021.bin`（548B）、`nw_frame_20261022.bin`（544B）、
  `nw_frame_20261022_full.bin`（554B）、`nw_frame_20261022b.bin`（558B）、
  `nw_frame_20261022c.bin`（244B）：0x3C…0x3E 容器格式单帧，
  供 nextgen-probe、frame-probe-variant3。

## 生成脚本

本目录不再保留生成脚本副本，唯一来源为 `wireshark_support_plugins/`（CI 用的那份）：

- `wireshark_support_plugins/build_gw2026_ofdma_tda_sim.py`：生成上面两个 GW 构造帧
  `gw2026_ofdma_sim.bin`、`gw2026_tda_sim.bin`；
- `wireshark_support_plugins/build_nw2026_ul_ofdma.py`：生成 NW UL-OFDMA 相关帧
  （`nw2026_trigger.bin`、`nw2026_ul_ofdma_data.bin`、`nw2026_dl_sack.bin` 及更多变体）。

两个脚本都写到脚本所在目录（`wireshark_support_plugins/`）；重建本目录的帧时把同名
`.bin` 拷过来。2026-11 核对：上述 5 个文件与本目录已入库的 `.bin` 逐字节相同
（原先这里的 GW 脚本副本缺 `import os`，已无法运行）。

## 原运行形式（恢复构建后）

```
./build.sh
./build/probe/nw_frame_probe <帧.bin>   # NW_2021 解析 + MSDU 树打印
```
