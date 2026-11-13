# gw-beacon-crc-probe

信标载荷 CRC32（国网称 BeaconCRC32、南网称 BPCS）与 PB CRC24 的三态回归探针。

## 口径（用户 2026-11 裁决）

| 情形 | CRC 状态 | 标红 | 学习 |
| --- | --- | --- | --- |
| 载荷 CRC32 正确 | Ok | 否 | 学（条目对 + CCO MAC） |
| 载荷 CRC32 篡改 | Fail | 是 | 不学 |
| PB CRC24 坏、载荷 CRC32 正确 | Ok | 是 | 仍学（与 MSDU CRC 覆盖 PB CRC 同口径） |

Fail 时摘要**不清空**：信标摘要本身就是“信标载荷 CRC32:失败”这句失败通知，
不存在误报解析成功的问题（与 MSDU FAIL 清空不同，见 packetlistmodel 注释）；
字段树也完整保留，只阻断学习 + 标红。

## 覆盖

- GW2022 / GW2026：走完整解析器（载波信标，TMI=2、PB 136B，STA Cap 条目
  TEI 5 / MAC aa:bb:cc:dd:ee:05，CCO MAC aa:bb:cc:dd:ee:01）。
- NW2026 / NW2021：直测 `parse_beacon`（南网完整 MPDU 另需 FCH 规约，信标
  解析器入口等价；南网不设 `mpdu.beacon_cco_mac`，故只断言条目对；
  NW2021 不产生学习对，只断言状态 + 标红 + 无对）。

## 运行

```sh
./build/gw_beacon_crc_probe   # 需 QT_ROOT，见 build.sh；有 FAIL 即 exit 1
```

反向验证：探针对修前代码应 exit 1（Fail 用例全部失败——旧代码状态为 N/A、
不标红、照常学）。
