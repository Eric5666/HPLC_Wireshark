# gw-learn-probe（原名 gw_learn_probe）

GW_2026 TEI↔MAC 学习探针：AssocCnf 体对、Gather 所列站、
OFDMA/TDA 全站、载波发现发送方对。

## 构建与运行

```
./build_probe.sh
./build/gw_learn_probe crafted.bin build/out.txt
```

- 构造输入 `crafted.bin`（2795B，15 帧）已入库；再生脚本 `gw_craft.py`
  （输出已改为脚本所在目录）。
- 完整扫描需长度前缀 MPDU 数据集 `gw_mpdus.bin`（39M，**未入库**），
  原位置 `~/workspace/gw_learn_probe/gw_mpdus.bin`；
  再生脚本 `split_gw_capture.py`（输入为
  `~/workspace/your_files/BPLC_20260914_105445.bin`，输出回原位置；
  因输出超 1MB，路径故意未改，见主 README）。

## 预期结果

构造输入：exit 0，
`total=15 accepted=15 msdu_pairs=16`，
`ofdma=1 tda=1 stations=4 gather=1 assoc_cnf=5 discover=5`。

### 新增帧（MSDU CRC 覆盖 PB CRC + 单跳简头 ICV，fix/msdu-icv-simple-header）

| 帧 | 内容 | 期望 |
| --- | --- | --- |
| FRAME 7 G4-2026-badpbcrc | HDC 2.0 AssocCnf，只翻 PB CRC24 末字节 1 bit，MSDU CRC32 仍有效 | 学：`topo=AssocCnf pairs=[5:…05]` |
| FRAME 8 G5-2026-na-dirty | HDC 2.0 单跳简头载波发现，PB CRC 坏但 ICV 有效 | 学：`sum=[载波发现列表消息] pairs=[9:…09]` |
| FRAME 9 G6-2026-na-clean | 同上，PB CRC 好 | 学：`pairs=[9:…09]` |
| FRAME 10 G7-2022 | HDC 1.0 AssocCnf（经 GW2026 m_legacy 委托），全好 | 学：`proto=0 topo=AssocCnf nodes=[5:…05]` |
| FRAME 11 G8-2022-badpbcrc | 同上，只翻 PB CRC24 末字节 1 bit | 学：`proto=0 topo=AssocCnf` |
| FRAME 12 G9-2022-na-dirty | HDC 1.0 单跳简头无线发现，PB CRC 坏但 ICV 有效 | 解析保留：`msdu=1 sum=[发现列表消息]` |
| FRAME 13 G10-2022-na-clean | 同上，PB CRC 好 | 解析保留：`msdu=1 sum=[发现列表消息]` |
| FRAME 14 G11-2026-icv-fail | HDC 2.0 单跳简头载波发现，篡改 ICV 1 bit | Fail：`sum=[] pairs=[-]`（摘要清空不学） |
| FRAME 15 G12-2022-icv-fail | HDC 1.0 单跳简头无线发现，篡改 ICV 1 bit | Fail：`sum=[] pairs=[-]`（摘要清空不学） |

说明：
- 单跳简头 ICV 三态（用户 2026-11 裁决：简头也要验证 ICV）：正确 ⇒ Ok（学）、
  篡改 ⇒ Fail（摘要清空、只留 CRC 证据、不学）、截断 ⇒ N/A（不标红、PB span 回退）。
  整链路（SOF→PB→MSDU）只测 Ok/Fail；N/A（ICV 字节截断）在 PB 块 132B 零填充下
  会被掩盖成 4B 伪 ICV 判 FAIL，故改由 `gw-icv-probe` 直测 MSDU body。
- 2022 的发现帧在 clean 档也不产生学习信号：GW2022 的 parse_rfdl 不像 2026 版那样
  把发送方对 append 进 `tei_mac_pairs`（既有差异，非本次改动）；所以 G9/G10 只断言
  解析/展示保留，Ok 的学与不学之差由 2026 对（FRAME 8 vs 9）示范；2022 的“坏 PB CRC
  仍学”由 FRAME 11 示范。
- 2022 的 AssocCnf 不填 `tei_mac_pairs`（`pairs=[-]`），学习经
  `topo_event.nodes`（`nodes=[5:…05]`）。

**这组数值已进 CI 门禁**（`protocol-regression.yml` 步骤
`GW TEI-MAC learning regression (CRC32-gated learning, gw-learn-probe)`），
断言的是报告文件而不是 stdout：

- `AGG total=15 accepted=15 msdu_pairs=16`
- `AGG ofdma_frames=1 tda_frames=1 ofdma_tda_stations=4 gather=1 assoc_cnf=5 discover=5`
- `FRAME 2 … pairs=[5:aa:bb:cc:dd:ee:05]`（短 MSDU 头 AssocCnf 的"洞"）
- `FRAME 7 … topo=AssocCnf pairs=[5:aa:bb:cc:dd:ee:05]`（坏 PB CRC 但 MSDU CRC 有效 ⇒ 学）
- `FRAME 8 … pairs=[9:…09]` 且 `FRAME 9 … pairs=[9:…09]`（单跳 ICV 有效 ⇒ 学）
- `FRAME 14/15 … sum=[] pairs=[-]`（单跳 ICV 篡改 ⇒ Fail 不学）

另有一个直接测 MSDU 解析器的探针 `gw-icv-probe`（4B 单跳简头 + 标准 16B 头 ×
Ok/Fail/N-A 三态，表驱动跑 gw_2026/gw_2022），已进同一 CI 门禁
（步骤 `GW single-hop 4B-header ICV regression (gw-icv-probe)`）。

改 `gw_craft.py` 造帧逻辑或改解析器语义后，这三条会直接红。历史坑：
fixture 曾经不写 MSDU 帧尾 CRC32，`msdu_crc_allows_learning()` 把三个
AssocCnf/GatherInd 帧判成坏载荷 ⇒ 摘要清空、`msdu_pairs=1 gather=0
assoc_cnf=0`，探针**违背自己上面的预期值却没人发现**（当时它不在 CI 里）。
