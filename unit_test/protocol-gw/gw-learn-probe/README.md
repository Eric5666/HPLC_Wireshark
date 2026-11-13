# gw-learn-probe（原名 gw_learn_probe）

GW_2026 TEI↔MAC 学习探针：AssocCnf 体对、Gather 所列站、
OFDMA/TDA 全站、载波发现发送方对。

## 构建与运行

```
./build_probe.sh
./build/gw_learn_probe crafted.bin build/out.txt
```

- 构造输入 `crafted.bin`（2481B，13 帧）已入库；再生脚本 `gw_craft.py`
  （输出已改为脚本所在目录）。
- 完整扫描需长度前缀 MPDU 数据集 `gw_mpdus.bin`（39M，**未入库**），
  原位置 `~/workspace/gw_learn_probe/gw_mpdus.bin`；
  再生脚本 `split_gw_capture.py`（输入为
  `~/workspace/your_files/BPLC_20260914_105445.bin`，输出回原位置；
  因输出超 1MB，路径故意未改，见主 README）。

## 预期结果

构造输入：exit 0，
`total=13 accepted=13 msdu_pairs=15`，
`ofdma=1 tda=1 stations=4 gather=1 assoc_cnf=5 discover=5`。

### 新增帧（MSDU CRC 覆盖 PB CRC，fix/gw-msdu-crc-override）

| 帧 | 内容 | 期望 |
| --- | --- | --- |
| FRAME 7 G4-2026-badpbcrc | HDC 2.0 AssocCnf，只翻 PB CRC24 末字节 1 bit，MSDU CRC32 仍有效 | 学：`topo=AssocCnf pairs=[5:…05]` |
| FRAME 8 G5-2026-na-dirty | HDC 2.0 单跳简头载波发现（无 MSDU CRC32 ⇒ N/A），PB CRC 坏 | 不学但解析保留：`msdu=1 sum=[载波发现列表消息] pairs=[-]` |
| FRAME 9 G6-2026-na-clean | 同上，PB CRC 好 | 学：`pairs=[9:…09]` |
| FRAME 10 G7-2022 | HDC 1.0 AssocCnf（经 GW2026 m_legacy 委托），全好 | 学：`proto=0 topo=AssocCnf nodes=[5:…05]` |
| FRAME 11 G8-2022-badpbcrc | 同上，只翻 PB CRC24 末字节 1 bit | 学：`proto=0 topo=AssocCnf` |
| FRAME 12 G9-2022-na-dirty | HDC 1.0 单跳简头无线发现（类型 0；HDC 1.0 简头表 12 无载波类型），PB CRC 坏 | 解析保留：`msdu=1 sum=[发现列表消息]` |
| FRAME 13 G10-2022-na-clean | 同上，PB CRC 好 | 解析保留：`msdu=1 sum=[发现列表消息]` |

说明：
- N/A 的构造依据：单跳简头 MSDU 在 MSDU 解析器里提前返回，从不产生
  MSDU CRC32 节点，故 `msdu_crc_state` 为 NotAvailable；span 由简头算
  （4+len+4）。不要用“去掉标准头 MSDU 尾部 4B CRC32”造 N/A——PB 块零填充
  会让解析器在该位置读到 0x00000000，判成 CRC32 **FAIL** 而非 N/A。
- 2022 的发现帧在 clean 档也不产生学习信号：GW2022 的 parse_rfdl 不像
  2026 版那样把发送方对 append 进 `tei_mac_pairs`（既有差异，非本次
  改动）；所以 G9/G10 只断言解析/展示保留，N/A 的学与不学之差由 2026
  对（FRAME 8 vs 9）示范；2022 的“坏 PB CRC 仍学”由 FRAME 11 示范。
- 2022 的 AssocCnf 不填 `tei_mac_pairs`（`pairs=[-]`），学习经
  `topo_event.nodes`（`nodes=[5:…05]`）。

**这组数值已进 CI 门禁**（`protocol-regression.yml` 步骤
`GW TEI-MAC learning regression (CRC32-gated learning, gw-learn-probe)`），
断言的是报告文件而不是 stdout：

- `AGG total=13 accepted=13 msdu_pairs=15`
- `AGG ofdma_frames=1 tda_frames=1 ofdma_tda_stations=4 gather=1 assoc_cnf=5 discover=5`
- `FRAME 2 … pairs=[5:aa:bb:cc:dd:ee:05]`（短 MSDU 头 AssocCnf 的"洞"）
- `FRAME 7 … topo=AssocCnf pairs=[5:aa:bb:cc:dd:ee:05]`（坏 PB CRC 但 MSDU CRC 有效 ⇒ 学）
- `FRAME 8 … pairs=[-]` 且 `FRAME 9 … pairs=[9:aa:bb:cc:dd:ee:09]`（N/A 时 span 脏不学、干净学）

改 `gw_craft.py` 造帧逻辑或改解析器语义后，这三条会直接红。历史坑：
fixture 曾经不写 MSDU 帧尾 CRC32，`msdu_crc_allows_learning()` 把三个
AssocCnf/GatherInd 帧判成坏载荷 ⇒ 摘要清空、`msdu_pairs=1 gather=0
assoc_cnf=0`，探针**违背自己上面的预期值却没人发现**（当时它不在 CI 里）。
