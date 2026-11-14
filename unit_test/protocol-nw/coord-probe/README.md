# coord-probe（原名 coord_probe）

NW_2021 协调（COORD）字段 / FCH 版本 / MSDU 版本分布统计探针（研究用，经 `SerialReader` 回放抓包）。

## 构建与运行

```
./build.sh
./build/probe_coord/probe_coord <capture.txt|capture.bin>   # 无参打印用法并 exit 2
```

## 状态

2026-11 修复构建：`MpduInfo` 已无 `coord_option`——原字节 7 bit2-3 的"选项"字段并入保留位
（NW_2021 `coord_rsv3` = 字节 7 bit2-7），探针改按 `coord_rsv3` 统计，`coord_joint` 键改为
`ch<信道>/rsv3_<值>`。

CI（`ci/probe_suite.sh`）用入库抓包 `unit_test/ci/roundtrip/roundtrip_test.bin` 运行，断言
`total=2457 accepted=2429`、`COORD total=1069 rf=0`。
