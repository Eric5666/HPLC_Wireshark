# orig-src-probe

聚合/多站点帧 Orig Src 多源列探针。

## 构建与运行

```
./build.sh
./build/orig_src_probe ../../protocol-gw/gw-topo-merge-probe/gw_topo_merge.bin \
                       ../../protocol-gw/gw-topo-merge-probe/gw_topo_merge_multi.bin
```

输入复用 gw-topo-merge-probe 的构造帧（不复制文件）：
- `gw_topo_merge.bin`（3 帧，每帧单源 [1:CCO]）
- `gw_topo_merge_multi.bin`（1 帧，两站上行、源 TEI 41/42 不同）
模型/过滤检查使用探针内合成条目。

## 检查内容

- 解析不变量：GW 多站点帧合并后的 `orig_srcs` 等于**写死的期望序列**
  （不反推）——单源帧期望 `[1:CCO_MAC]`，多源帧期望
  `[41:...EE29, 42:...EE2A]`，验证「该收集却没收集」的场景。
  每 bin 读满期望帧后断言 EOF，尾部多余记录/残字节判失败。
- 模型列：多源显示 `STA-11 [aa:bb:cc:dd:ee:0b],STA-12 [01:02:03:04:05:06]`
 （逗号分隔、重复源去重）；单帧回退不变；拒收帧为空；TEI 1 显示 CCO。
 前提条件：仅当帧级无原始 TEI 时才用多源；帧级已有源时只显示单源，
 且过滤时不含各段/各站源的词。
- Dir 列：合并帧原始源只有 CCO 时显示下行标志 ↓（与 Orig Src 多源同门：
 帧级无原始 TEI 且 orig_srcs 非空，present 门之前判定）；其余行 Dir 不变
 （多源非 CCO、单帧、拒收帧、帧级已有源仍为 *）。NW 级联端到端：
 单站点 SOF v2、2 块聚合 PB、2 条 CCO 记录（本跳为中继 PCO），解析得
 cascade=true、present=true（每解析一条记录即置位）、orig_srcs 仅 CCO，
 Dir 列即为 ↓R（CCO 原始源与本跳 PCO 发送方不一致）。
- Dir 列 R 标记（F 节）：原始源 ≠ 本跳发送方且原始源非空时加 R；发送方
 为 0 不比较（不算不一致）；CCO 原点被转发仍标 ↓R。方向未知且中继时
 显示 *R：合并帧 present=false（中继/混合源）、P2P 方向标志未填、广播
 方向未知/保留、NW 广播方向保留；原始源等于发送方、发送方为 0 时不加 R。
 广播方向未知且中继时，剩余跳数已知且>1 显示 RN→（还要继续转发）；
 剩余跳数 0xFF 为未知哨兵、≤1 或不中继时不显示右箭头。
- 绘制时 MAC 回填：短头/TEI-only 段解析时无 MAC，多源/多目的分支此前只
 显示条目自带 MAC（与单源/单目的分支会查映射表不同），学到 MAC 后也不
 补；现绘制时 mac==0 的条目从学习到的 TEI→MAC 表回填（data() 每次重绘
 都重算，换页/翻看历史时新学到的 MAC 即生效，无需重解析）；仍未学到
 的 TEI 仍只出名；广播不查表（与单目的分支一致）。
- 过滤：`sta-12`/`sta-11` 命中（search_text 整词匹配，非 hop TEI）；
  `sta-1` 不误命中 `sta-11`；`sta-99` 不命中；MAC 模式 `01:02`/`aa:bb`
  经映射表展开后命中；子串 `dd:ee:0` 命中；单帧帧级源 `sta-5` 可搜。
- MAC 来源标注（第 2 批）：解析时已带 MAC 的段显示 `STA-N [aa:bb:...]`（抓包时刻快照，
  TEI 易主后不漂移）；仅 TEI 的段在绘制时按**当前映射**回填，显示
  `STA-N [MAC*:aa:bb:...]`，与快照可区分。

## 预期结果

`RESULT: ALL PASS`，exit 0。
