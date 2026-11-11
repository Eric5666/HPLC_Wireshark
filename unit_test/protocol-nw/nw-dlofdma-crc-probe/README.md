# nw-dlofdma-crc-probe

NW_2026 DL-OFDMA 站点 1+ 非聚合分支 PB CRC 门回归用例。

## 测什么

载波 SOF version=2、DL-OFDMA（类型 0）2 站点合成帧，每站 1 块 264B
（TMI 9），站点 PB 体为 NW AssocReq MSDU：

- 好 CRC：站点 0 对（TEI 27）与站点 1 对（TEI 42）都学到；
- 站点 1 块 CRC24 翻转、但 MSDU CRC32 有效：站点 1 对仍应学到；MSDU CRC32
  是拓扑学习的最终判据，不能因 PB CRC24 失败而误拒。
- MSDU CRC32 失败、PB CRC24 全通过：站点 1 对必须被阻断，分别覆盖非聚合和聚合路径。

以上为非聚合分支（PB 头 byte2 bit0=0）。另含聚合分支用例
（站点 1 块换为聚合 PB，byte2 bit0=1，级联记录流 1 条 AssocReq）：

- 聚合好 CRC：站点 1 的级联记录被学到（站点 1 对入 `tei_mac_pairs`）；
- 聚合站点 1 块 CRC 翻转、MSDU CRC32 有效：仍允许学习站点 1 对；帧本身仍 accept，
  且任意 PB 块 CRC 失败会令整帧标红、Info 列显示 `CRC FAIL`。

此探针同时锁定 PB CRC24 与 MSDU CRC32 的优先级，确保坏 MSDU 不进入拓扑学习、
而有效 MSDU 不因 PB CRC24 单独失败被丢弃。

## 构建与运行

```
./build.sh
QT_QPA_PLATFORM=offscreen LD_LIBRARY_PATH=$HOME/workspace/build_deps/libfix:$HOME/qt/6.11.2/gcc_64/lib ./build/nw_dlofdma_crc_probe/nw_dlofdma_crc_probe
```

无输入文件（全合成帧）。预期：`RESULT: ALL PASS`，exit 0。

## 说明

- 站点 0 的对走帧级 `msdu_src` 字段，不进 `tei_mac_pairs`；
  站点 1 的对走 `tei_mac_pairs` 合并，探针断言据此区分。
- 聚合与非聚合站点均检查 MSDU CRC32；PB 块 CRC 仅作为 MSDU CRC 不可用时的回退依据。
