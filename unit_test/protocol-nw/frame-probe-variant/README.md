# frame-probe-variant（原名 frame_probe/variant）

NW_2021 帧变体探针（`nw_2021_parser.h` + `nw_2021_msdu_parser.h`）。

## 状态：构建失败（已记录，未改源码）

与 coord-probe 同因：`main.cpp:68` 读 `MpduInfo.coord_option`，
现为 `coord_duration`。原样记录，待另行修复。

## 原运行形式（恢复构建后）

```
./build.sh
./build/probe/nw_frame_probe_variant <帧.bin>
```

帧输入见 `../../frames/frame-probe/`（如 `nw_frame_20261022.bin`）。

## 2026-11 修复构建（接入 CI）

- `MpduInfo` 已无 `coord_option`（字节 7 bit2-3 并入保留位，NW_2021 `coord_rsv3` = bit2-7），
  coord 行改为打印 `rsv0..rsv3`；
- `.pro` 补 `3rdparty/qslog`（`parse_anomaly.h` 依赖 QsLog，与 frame-probe-variant3 相同）；
- 无参数运行打印用法并 exit 2（原先直接解引用 `argv[1]`）。

CI：`ci/probe_suite.sh` 用本目录（`frames/frame-probe/`）的 `nw_frame_*.bin` / `nw_log_tail_*.bin` 运行，
断言 `accept=1` 及各帧 MSDU 结果（`present=1`、BID）。
