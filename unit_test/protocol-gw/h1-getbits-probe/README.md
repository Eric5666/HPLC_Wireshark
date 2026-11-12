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
| `wide-field-hex-dump` | `add_fields` 用 80 位 DEC 与 125 位 bit=3 的保留字段喂 26B 数据 | 两字段均显覆盖字节十六进制（不再恒 0）；125 位字段首字节邻位被屏蔽（`0x0A`→`0x08`） |
| `getbits-qint64-guard` | `get_bits` 喂 `start_byte=INT_MAX-2` / `start_bit=INT_MAX` / `bit_len=65` | 均返 0，不崩（旧守卫 int 溢出会绕过检查） |
| `nw2026-beacon-stacap-5B` | NW2026 信标 STA Cap 条目截到 5B（旧引用 beacon:382） | 解析不崩，`tei_mac_pairs` 为空 |
| `rsv3-mask-cf1-zero` / `rsv3-mask-top-bit` / `rsv3-mask-low-bit` | RSV3 屏蔽（CarrierFreq=1 保留位全 0 / 仅最高位 / 仅最低位） | 全 00 / 末字节 80 / 首字节 08 |
| `discover-rates-16/18/19/20/28/29B` | GW2022 发现列表 MMe 体长六档（陷阱真值上行 85、下行 77、最小 66） | 分档：上行 ≥19B、下行 ≥20B、最小 ≥29B 才读；`comm_rates` 整条 ≥20B 才发；任一缺失摘要追加“ (成功率截断)” |
| `discover-topostate-min-kept` | 先 29B 体、再 20B 体喂 TopoState | 20B 体不洗掉节点原先的 min 真值（逐项覆盖） |
| `gw2022/gw2026-assocreq-0/5/6B` | AssocReq 体 0/5/6B | <6B 不生成事件、摘要追加“ (关联请求截断)”；6B 正常生成 |
| `gw2022/gw2026-chgproxy-0/19/20B` | ChangeProxyCnf 体 0/19/20B | <20B 不生成事件、摘要追加“ (代理变更确认截断)”；20B 正常生成 |
| `gw2022/gw2026-assocgather-0/15/16B` | AssocGatherInd 体 0/15/16B | <16B 不生成事件、摘要追加“ (关联汇总截断)”；16B 正常生成 |
| `gw2022/gw2026-chgpxreq-0/1/2/3/13/14/16/24B`、`tei0-24B` | ChangeProxyReq 体 0–24B（陷阱 STA TEI=9、新代理 7、旧代理 5） | <14B 仍记一条截断事件（只进事件表），说明“消息截断：期望至少 14 字节，实际 M 字节”+“ (STA TEI=9)”（≥2B 时）、摘要追加“ (代理变更请求截断)”、字段树末节点“(消息截断)”、TopoState 事件 1 条节点 0 个；14/16/24B 正常显示“代理变更请求: STA TEI=9 5→7”；STA TEI=0 的 24B 不出事件 |
| `gw2022/gw2026-leaveind-0/3/15B-n2`、`22B-n2`、`16B-n1`、`16B-n0`、`22B-n1`、`28B-n2` | LeaveInd 体 0/3/15B（n=2）、22B n=2、16B n=1、16B n=0、22B n=1、28B n=2 | M<16 只写截断原因、不标任何站点离线；16≤M<16+6n 已读 MAC 照常标离线、说明写实际个数并标注截断；16B n=0 完整帧仍是空说明记录（本次不改，钉死现状）；22B n=1 / 28B n=2 正常 |
| `gw2022/gw2026-leaveind-partial-mark` | 22B n=2 喂进预置两个在线节点的 TopoState | 只读到的 1 个 MAC 标离线，另一个仍在线，事件 1 条 |

共 79 个用例。另有 H1 后续修复（`fix/h1-getbits-bounds-check`）：

4. `src/protocol/gw_protocol/gw_2022/gw_2022_msdu_parser.cpp` 与 `gw_2026/gw_2026_msdu_parser.cpp`：站点属性 IE 不足 12B（无线）/17B（载波）时跳过拓扑采集与 TEI→MAC 学习，摘要追加“(站点属性截断)”；关联确认体不足 18B 时跳过事件与 CCO 更新，摘要追加“(关联确认截断)”；字段树渲染不受影响。
5. `src/protocol/common/fieldspec.h`：`add_fields` 对 len>64 的字段直接给覆盖字节十六进制，不再走 `get_bits`（旧语义恒显 0）；DEC 字段改后统一显 hex，接受的格式变化。
6. `src/protocol/common/fieldtools.h`：`get_bits` 守卫改用 qint64 算 `last_byte`，堵 int 加法溢出。
7. 第四份复核的后续修复（`fix/h1-getbits-bounds-check`，d237e88 之后一提交）：`fieldspec.h` 宽字段屏蔽首尾邻位；`gw_2026_sof_parser.cpp` 的 eFC 16B 注释按“文档类推、仍待实包确认”收紧措辞（拒收行为不动）；GW2022 发现列表成功率分档门（19/20/29B）+ `topo_state.cpp` 逐项覆盖；AssocReq/ChangeProxyCnf/AssocGatherInd 三处截断门（6B/20B/16B）。
8. 截断帧保留并标注（`fix/h1-getbits-bounds-check`，10e599f 之后一提交）：`gw_2022/gw_2026_msdu_parser.cpp` 的 ChangeProxyReq 体不足 14B、LeaveInd 固定头不足 16B / MAC 列表不足 16+6n 时仍记一条事件（只进事件表，不改拓扑），说明写截断原因、摘要追加“ (代理变更请求截断)”/“ (离线指示截断)”、字段树末尾加“(消息截断)”节点、各调一次 `pa::warn`；LeaveInd 说明按实际读到的 MAC 数写（不再写声明的 n）；16B n=0 的完整离线指示帧仍是空说明记录，本次不改。

## 运行

```bash
./build.sh        # 构建（ASan）并运行
```

Qt 路径走环境变量 `QT_ROOT`，未设时默认 `~/Qt/6.11.3/6.11.3/gcc_64`。构建产物在 `build/` 下（git-ignored）。
