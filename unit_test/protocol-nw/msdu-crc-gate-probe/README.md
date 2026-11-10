# msdu-crc-gate-probe — MSDU CRC32 三态门控

用户 2026-11 裁决的验收探针：

> 「DROP 只有在 fc crc 就失败时标记，否则应先解析，存在 CRC 失败即标记红色」
> 「MSDU CRC 正确即解析，PB 块校验失败信息显示在 Info 列」
> 「MSDU CRC 正确就显示原摘要，否则为空」
> 「MSDU CRC32 FAIL 也标红（与 PB 同等待遇）」

## 逐层三态

| FCH(FC) CRC | PB 块 CRC | MSDU CRC32 | 期望行为 |
|---|---|---|---|
| **FAIL** | — | — | **DROP**（唯一 DROP 条件） |
| OK | OK | OK | 解析，原摘要，不红 |
| OK | **FAIL** | **OK** | **解析**，原摘要；Info 列仍 `CRC FAIL(n/m)`，**行红** |
| OK | FAIL | FAIL | `present=1`、摘要空、字段树只留 `MSDU CRC32 … FAIL`、**行红** |
| OK | OK | FAIL | 同上 |
| OK | 任意 | N-A（无该字段/不足 4B） | 维持现状（摘要保留 `(CRC 缺失)`，不因缺失标红） |

## 实现位置（单一实现，UI 与 parser 共用）

- `src/protocol/common/msdu_crc_state.h`（header-only）
  - `MsduCrcState msdu_crc_state(const MsduInfo&)` —— 从**已序列化的字段树**派生三态
    （`MSDU CRC32` 节点值 `0x… OK/FAIL`），**不新增 MsduInfo 字段**（块版本严格相等、不迁移）
  - `MsduInfo msdu_crc_gate(const MsduInfo&)` —— FAIL ⇒ 摘要清空 + 只留 CRC 证据节点
  - `bool frame_crc_red(const PacketEntry&)` —— 整行标红唯一判据
    （FCH CRC FAIL ∥ 任一 PB CRC FAIL ∥ 帧级组装未通过 ∥ MSDU CRC32 FAIL）
- 调用点：`nw_2021_parser.cpp` / `nw_2026_parser.cpp`（PB 块 CRC 不再作为 MSDU 解析前置门控）、
  `gw_2022_msdu_parser.cpp` / `gw_2026_msdu_parser.cpp`（`return msdu_crc_gate(out);`）、
  `packetlistmodel.cpp`（`if (frame_crc_red(e)) return QColor(224,64,64);`）

## fixture

`unit_test/frames/frame-probe/nw_log_tail_pb_crc_fail.bin`（766 字节，原样入库）

用户线上帧：`0x3C@0 … 0x3E@764`，反转义后 755 字节。模块发完帧后紧接往同一串口打印调试日志
（`01244c87:Debug Is Opened.` 起于反转义后 `body[128]`），被同一对 `3C…3E` 吞进同一帧 ⇒
PB 块（16+136）跨进日志文本 ⇒ **块 CRC24 FAIL**；而真正的 MSDU（前 118 字节，含 CRC32
`87 38 81 5d`）**完好**。这正是"FC CRC 正确却整段不解析"的真实成因。

## 用例（35 条断言）

| 用例 | 内容 |
|---|---|
| **A** | 原帧：`accept=1`、FCH CRC OK、`pb_crc_oks=[false]`、`present=1`、摘要含 `应用层报文` / `BID=0x03` / `站点间通信`、树中 `MSDU CRC32 = 0x5d813887 OK`、行红 |
| **D** | 好帧回归（只重算块尾 CRC24 ⇒ PB OK）：摘要/字段树与改前一致、不红 |
| **C** | PB OK + MSDU FAIL（改块体一字节后重算块 CRC）：`present=1`、摘要空、字段树仅 1 个 CRC 证据节点、值为 FAIL、行红、不产拓扑事件 |
| **E** | FC CRC FAIL ⇒ `accept=0`（唯一 DROP）、不解析 MSDU |
| **F** | N-A（无 CRC 节点/字节不足）⇒ 原样返回、不因缺失标红 |
| **G** | 国网同款 C 场景（国网两条 MSDU 解析路径末尾统一 `msdu_crc_gate`，用国网形态字段树断言） |

> 国网样本 `gw2026_ofdma_sim.bin` 是 OFDMA/TDA 多站帧（帧级 `msdu_body` 为空），不适用于该断言，故未引入。

## 用法

```bash
QT_ROOT=C:/Qt/6.11.3/mingw_64 bash build.sh     # Windows
QT_ROOT=/usr/lib/qt6 bash build.sh              # Linux / CI
./build/msdu_crc_gate_probe                      # exit 0 = 全部断言通过
```
