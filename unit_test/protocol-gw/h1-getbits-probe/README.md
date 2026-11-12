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
| `gw2022-msdu-rfdl-elen8` | GW2022 MSDU RFDL IE elen=8（旧引用 msdu:843-856；IE 头在 body[11..12]，原探针误写在 body[4..5] 只测了 elen=0 空 IE，已修正） | 解析不崩，摘要含“ (站点属性截断)”，`proxy_tei`=0xFFFF、成功率均为 -1（不采拓扑） |
| `gw2022-msdu-assocreq-5B` | GW2022 MSDU AssocReq b=5B（旧引用 msdu:1166） | 解析不崩，`sta_mac` 为 0 |
| `gw2026-msdu-rfdl-elen8` | GW2026 MSDU RFDL IE elen=8（旧引用 msdu:836-856；IE 头位置同上，已修正） | 解析不崩，摘要含“ (站点属性截断)”，`proxy_tei`=0xFFFF、成功率均为 -1（不采拓扑） |
| `gw2026-carrier-rfdl-elen8` | GW2026 载波发现列表 RFDL IE elen=8（msdu:826-870） | 解析不崩，摘要含“ (站点属性截断)”，`tei_mac_pairs` 为空、载波成功率均为 -1 |
| `gw2022-msdu-assoccnf-12B` | GW2022 MSDU AssocCnf b=12B（msdu:1232-1255） | 解析不崩，摘要含“ (关联确认截断)”，无事件、CCO 不更新、节点/路由为空 |
| `gw2026-msdu-assoccnf-12B` | GW2026 MSDU AssocCnf b=12B（msdu:1370-1395） | 同上，另 `tei_mac_pairs` 为空 |
| `wide-field-hex-dump` | `add_fields` 用 80 位 DEC 与 125 位 bit=3 的保留字段喂 26B 数据 | 两字段均显覆盖字节十六进制（不再恒 0） |
| `getbits-qint64-guard` | `get_bits` 喂 `start_byte=INT_MAX-2` / `start_bit=INT_MAX` / `bit_len=65` | 均返 0，不崩（旧守卫 int 溢出会绕过检查） |
| `nw2026-beacon-stacap-5B` | NW2026 信标 STA Cap 条目截到 5B（旧引用 beacon:382） | 解析不崩，`tei_mac_pairs` 为空 |

共 18 个用例。另有 H1 后续修复（`fix/h1-followup-truncation-gates`）：

4. `src/protocol/gw_protocol/gw_2022/gw_2022_msdu_parser.cpp` 与 `gw_2026/gw_2026_msdu_parser.cpp`：站点属性 IE 不足 12B（无线）/17B（载波）时跳过拓扑采集与 TEI→MAC 学习，摘要追加“(站点属性截断)”；关联确认体不足 18B 时跳过事件与 CCO 更新，摘要追加“(关联确认截断)”；字段树渲染不受影响。
5. `src/protocol/common/fieldspec.h`：`add_fields` 对 len>64 的字段直接给覆盖字节十六进制，不再走 `get_bits`（旧语义恒显 0）；DEC 字段改后统一显 hex，接受的格式变化。
6. `src/protocol/common/fieldtools.h`：`get_bits` 守卫改用 qint64 算 `last_byte`，堵 int 加法溢出。

## 运行

```bash
./build.sh        # 构建（ASan）并运行
```

Qt 路径走环境变量 `QT_ROOT`，未设时默认 `~/Qt/6.11.3/6.11.3/gcc_64`。构建产物在 `build/` 下（git-ignored）。
