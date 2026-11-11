# H1 get_bits 边界检查探针

验证 H1 修复（`fix/h1-getbits-bounds-check`）的三项改动：

1. `src/protocol/common/fieldtools.h`：QByteArray 版 `get_bits` 加边界检查，越界返回 0。
2. `src/protocol/gw_protocol/gw_2026/sof/gw_2026_sof_parser.cpp`：`assemble()` 进 OFDMA/TDA 分支前先判 32B 门，截断整帧拒收；再校验 eFC CRC24，错整帧拒收（照南网 `nw_2026_parser.cpp:351/359` 的做法）。
3. `src/protocol/gw_protocol/gw_2026/gw_2026_tree.cpp`：`rsz < 32` 时跳过 eFC 站点循环（纵深防御）。

## 用例

| 用例 | 输入 | 期望 |
|---|---|---|
| `ofdma-trunc-16/24/31B` | 截断 OFDMA 帧（FCH CRC 有效） | 拒收，原因含“eFC 截断” |
| `ofdma-32B-bad-efc-crc` | 32B，eFC CRC 错 | 拒收，原因含“eFC CRC24 错” |
| `ofdma-32B-good-efc-crc` | 32B，eFC CRC 对（无 PB） | 接受 |
| `ofdma-304B-full` | 完整 304B OFDMA 帧（2 站 ×136B，PB CRC 有效） | 接受，PB CRC 全过，2 站 |
| `tda-304B-full` | 完整 304B TDA 帧 | 接受，2 站 |
| `tree-trunc-ofdma-20B` | 20B 截断 OFDMA 帧进字段树 | 拒收且树正常渲染（eFC 循环被跳过） |
| `gw2022-beacon-stacap-5B` | GW2022 信标 STA Cap 条目截到 5B（旧引用 beacon:349-350） | 解析不崩，`tei_mac_pairs` 为空（MAC 读 0） |
| `gw2022-msdu-rfdl-elen8` | GW2022 MSDU RFDL IE elen=8（旧引用 msdu:847-852） | 解析不崩，走到 Station Attribute 分支 |
| `gw2022-msdu-assocreq-5B` | GW2022 MSDU AssocReq b=5B（旧引用 msdu:1166） | 解析不崩，`sta_mac` 为 0 |
| `gw2026-msdu-rfdl-elen8` | GW2026 MSDU RFDL IE elen=8（旧引用 msdu:836-856） | 解析不崩，走到 Station Attribute 分支 |
| `nw2026-beacon-stacap-5B` | NW2026 信标 STA Cap 条目截到 5B（旧引用 beacon:382） | 解析不崩，`tei_mac_pairs` 为空 |

## 运行

```bash
./build.sh        # 构建（ASan）并运行
```

Qt 路径走环境变量 `QT_ROOT`，未设时默认 `~/Qt/6.11.3/6.11.3/gcc_64`。构建产物在 `build/` 下（git-ignored）。
