# pb-batch2-probe

第 2 批修复回归探针（规格 `SPEC-batch2`）：OFDMA 多站 CRC/截断状态、TEI↔MAC 反向索引、
历史条目 MAC 快照。

## 构建与运行

```
QT=C:/Qt/6.11.2/mingw_64 ./build.sh          # Windows
./build/pb_batch2_probe/release/pb_batch2_probe.exe
```

无输入文件（合成帧 + 合成条目）。预期：`RESULT: ALL PASS (0 failures)`，exit 0。

## 用例清单

### ① 完整 2 站 OFDMA（表7 帧子类型=2，表10/表11）

| 断言 | 说明 |
|---|---|
| 不拒收 | `assemble()` 返回空串（旧实现无错，但…） |
| 2 站解析 | `sof_stations.size()==2` |
| 站点 0 数据保留 | `pb_crc_oks.size()==声明块数` |
| 帧级 `pb_crc_ok==true` | 旧实现恒 false（从不设），本轮修复点 |
| Info 无「截断 / 重组失败 / PB 块超出帧长」 | `version=0`(HDC1.0) 与 `1`(HDC2.0) 都要过 |
| Info 含 `CRC OK` 且含 `DL-OFDMA` | 完整帧不得出现「(截断)」 |

> 旧判据用 `version==2` 判多站，而国网 version 只有 0/1（`GW_2022_Version::THIS_STANDARD=0`、
> `GW_2026_Version{HDC_1_0=0,HDC_2_0=1}`），多站分支对国网是死代码。现改结构化判据
> `!sof_stations.isEmpty()`，与 `version` 无关。

### ② 多站真截断（最后一站的最后一块不在帧内）

- `assemble()` **不拒收**（旧实现 `return "多站点 PB 块超出帧长"` → accept=0，整帧连已完整的站 0 一起丢弃）
- 站点 0 的已校验块保留
- 帧级 `pb_crc_ok==false`
- Info 显示「缺块 k」（而不是拒收原因）

### ③ 南网 SPLC SOF 不得被误标

`version=2`（南网 SPLC 的真实取值，旧判据的陷阱）+ `raw_bytes[4]` bit0/bit1 四种组合：
Info 均不得出现 `DL-OFDMA` / `训练帧`，且应显示 `CRC OK`。

### ④ `learn_tei_mac` 早退修复

序列 `1→A`、`2→A`、`2→B`、`1→A` 后：

- 报文体 `sta_mac=A`、原始目的 TEI=0 的行 → `STA-1 [aa:...]`（旧实现显示 `STA-X`）
- MAC 模式过滤 `aa:aa:aa:aa:aa:aa` → 命中（旧实现经反向索引展开为空 → 0 行）
- 等价的 `sta-1` 过滤同样命中

### ⑤ 历史条目 MAC 快照 vs 回填

| 行 | 数据 | 断言 |
|---|---|---|
| 行 0 | `orig_dsts={7, A}`（解析时快照） | 初次 `STA-7 [aa:...]`；TEI7 易主给 B 后**仍为 `aa`**（不漂移） |
| 行 1 | `orig_dsts={7, 0}`（仅 TEI，绘制时回填） | 显示 `STA-7 [MAC*:aa:...]`；易主后变 `[MAC*:bb:...]`（**带 `*` 标注，与快照可区分**） |

### ⑥ 跳数列（Source / Destination）

`COL_SOURCE` 与 `COL_DEST` 的 MAC 一律来自 `lookup_mac`（映射表），故必须带星：
`STA-7 [MAC*:aa:aa:aa:aa:aa:aa]`。

### ⑦ MAC→TEI 推断（`STA-N*`）

- 反查命中：`COL_ORIG_DST` 显示 `STA-1* [aa:...]`（N 由映射表推出）
- 反查落空：`STA-X [5a:...]`（`STA-X` 本身即未知，不加星）

### ⑧ MMe 主体（MSDU Type 列）来源区分

| 主体 TEI 来源 | TEI 显示 | MAC 显示 |
|---|---|---|
| `lookup_tei_by_mac` | `STA-1*`（推断） | 帧内实证 → `[MAC:aa:...]`（**无星**） |
| `topo_event.nodes` / `topo_extra_events` | `STA-7`（实证） | `[MAC:c0:...]`（无星） |

### ⑨ 落盘 / 重载一致

追加超过一个盘块（`kBlockSize=1000`）的填充条目迫使头部落盘，等 `QThreadPool::waitForDone()`
后读回：快照行仍无星、回填行仍带星。

> 落盘是后台线程执行的（`flush_hot_block`），读回前必须等线程池完成，否则读到空块。

### ⑩ 南网解析闸门（重组不可信则不解析）

NW_2021 载波 SOF（TMI=3 → 136B，块 = PB头4B 表133 + 体 + 保留 1B + CRC24 3B）：

| 帧 | `pb_crc_ok` | MSDU |
|---|---|---|
| 顺序 `0,1,2,3` | true | 正常解析（回归） |
| 重复 seq `0,1,1,3`（内容不同 → 冲突） | false | **不解析**，摘要 `PB 序号异常未解析`，树为空 |
| 越界 seq `0,1,2,9` | false | 同上 |
| 缺块 `0,2,3`（声明 4） | false | 同上 |

> 关键点：`msdu_span_avoids_bad_blocks` 只看「块 CRC 是否失败」，不看序号完整性；
> 上面三类各块 CRC 全过时该函数仍返回 true，若单独用它做门会把**错序体**解析成字段
> （帧已标红但树里是垃圾）。四协议统一改用 `pb_asm::body_parseable(res)`
> （= `reassembly_ok && !msdu_body.isEmpty()`）。

### ⑪ GW 多站逐站序列号落位（P2 修复）

国网 OFDMA 多站帧（表10/表11）此前按到达位置切片（`off = blk + j*sz`），
`st.pb_heads` 存了序列号却只用于展示 → 站内乱序时体序错，UI 仍显示「乱序已重排」，
学习还会解析错序体。现改为逐站 `pb_asm::assemble_pb_blocks` 落位。

| 用例 | 帧 | 断言 |
|---|---|---|
| `reorder` | 站 0 按 `seq[1,0]` 到达（体填充 = 序列号），站 1 顺序 | 不拒收、2 站；**站 0 体首字节 = 0（seq0 在前）**；站 1 仍 0；Info 含「乱序已重排」且**与实际体序一致**；帧级 `pb_crc_ok=true` |
| `uniform-seq` | 站 0 `seq[0,0]` | 命中「全同 → 按位置拼接」兜底：体保留（2×68B）、帧级 `pb_crc_ok=true`、Info **不报**「PB 序号异常」 |
| `oob` | 站 0 `seq[0,9]`（越界） | 不拒收（保留已完整站点）；**坏站 `msdu` 为空 → 学习门跳过**；好站体保留；帧级 `pb_crc_ok=false`；Info 报「PB 序号异常」 |

> `st.pb_heads` / `st.pb_crc_oks` 按**到达序（线序）**保存（`pb_asm::arrival_order_blocks`），
> 体流按 **seq 序**。UI 的「乱序已重排」判定依赖线序块头——若两者都用拼接序，
> 重排后 `pb_heads[i]==i` 将看不出乱序，提示永久失效（本轮实测踩到）。
>
> 「重复 seq」在 GW 多站**不可构造**：站内 PB 个数只有 1 bit（表10/表11 → 最多 2 块），
> 2 块时「重复」必然同时是「全同」，命中兜底。故用 `uniform-seq` 断言兜底语义，
> 序号异常由 `oob` 覆盖。
>
> 同类修正：`analyze_pb_seq_heads` 在「收到的块数 == 声明块数 且序列号全同」时
> 清空 `dup/missing/oob/reordered`，与 `seq_uniform_fallback` 同口径——否则设备未填
> 序列号的正常帧会被 UI 误标「PB 序号异常」而树里正常解析。

## 说明

- 标注符 `MAC*` / `STA-N*` 只用 ASCII `*`，本身不翻译；图例说明文案已
  `trl::register_en` 中英成对，挂在 Orig Src / Source / Destination / Orig Dst / Info
  五列的**列头 ToolTip**（`headerData(ToolTipRole)`），中英文界面都会显示。
- 未新增持久化字段、未改块版本：`[MAC*:]` 由「解析时 `TeiMacPair.mac==0`」这一既有事实推导。
