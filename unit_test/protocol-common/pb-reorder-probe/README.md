# pb-reorder-probe

PB 块**按序列号重排 + 帧内重组**回归探针（规格 `SPEC-PB-reorder`）。

## 规约依据

| 协议 | 表号 | PB 头 | 序列号 |
|---|---|---|---|
| 南网 BPLC | 表133 §8.1.3.2.1.1 | 4B | byte0 bit0-7 + byte1 bit0-7 = 16bit LE |
| 南网 SPLC | 表47 §5.1.3.2.1.1 | 4B | 同上；聚合标志 byte2 bit0 |
| 国网 GW | HDC SOF PB 头 | 1B | 低 6 位；bit7=END、bit6=START |

SPLC 第 4 部分明文要求「根据物理块头中的序列号，将所有的物理块体进行有序的重组」，
故重组按序列号落位，而不是按字节流位置切片。

## 构建与运行

```
QT=C:/Qt/6.11.2/mingw_64 ./build.sh          # Windows
./build/pb_reorder_probe/release/pb_reorder_probe.exe
```

无输入文件（全合成帧）。预期：`RESULT: ALL PASS (0 failures)`，exit 0。

## 用例清单

| 用例 | 断言 |
|---|---|
| NW 4 块 `0,2,1,3` | `reassembly_ok`、体序 `0 1 2 3`、`seq_reordered>0` |
| GW 4 块 `0,2,1,3` | 同上；`pb_head_flag_mismatch==0`（START/END 交叉校验通过） |
| 树层 `rel→raw` | 拼接序 1 落在 seq=1 的真实块（`16 + 2*pb_size + header`），拼接序 2 落在 seq=2 的块 |
| 缺块 `0,2,3`（声明 4） | `!reassembly_ok`、`missing_blocks==1`、`first_missing_slot==1` |
| 重复 seq 内容冲突 `0,1,1',3` | `seq_conflict==1`、`!reassembly_ok` |
| 重复 seq 内容一致 `0,1,1,3` | `seq_dup==1` 容忍，但槽位 2 空洞 → `!reassembly_ok` |
| seq 越界 `0,1,2,5` | `seq_oob==1`、`!reassembly_ok` |
| 序列号全同 `0,0,0,0` | `seq_uniform_fallback`（设备未填序列号）→ 按到达位置拼接且 `reassembly_ok` |
| 聚合帧乱序 `seq 1,0` | 重排后 `cascade[0]='A'(seq0)`、`cascade[1]='B'(seq1)` |
| 聚合帧坏块 | 翻转 seq=1 块 CRC → 两条 cascade 候选均保留；CRC32 不可用时回退门仅接受未跨坏块的 'A' |
| GW2022/GW2026 乱序 4 块 | 解析器经 `assemble()` 输出体 272B、体序 `0 1 2 3`、`pb_crc_ok` |
| GW2022/GW2026 单站坏 CRC | 体流一律交付（重组完整）；坏块与首 MSDU span 相交时 `span_clean=false`，在 span 后时 `span_clean=true`；CRC 状态保留以供标红 |
| GW2022/GW2026 乱序到达 + 坏 CRC | `seq1` 坏块不污染 `seq0` 首 span（`span_clean=true`）；`seq0` 坏块使 `span_clean=false`；体流一律交付；逐块 CRC 仍按到达序回填 |

> 国网用例的体流一律按**国网头布局**构造：简头 = 体[0] 低 nibble `0x01`、长度在体[2..3]
> 低 11bit；标准头 = 长度在体[8..9] 低 11bit、体[11] bit3 控制 16/28B。
> 早前版本误用南网布局（体[0]=`0x04` + 16bit LE 长度）造体流，与国网 span 门口径不一致，
> 错口径也照样全 PASS；口径回归用例见 `unit_test/protocol-common/pb-batch2-probe` ⑫。
| GW2022/GW2026 后续 MSDU 坏块边界 | 后续跨度坏块不影响首 span（`span_clean=true`）；首 MSDU 跨坏块时体流仍交付（重组完整），`span_clean=false` 供 N/A 回退 |
| 跨帧污染回归 | 无 END 帧之后紧跟完整帧（同一 `MsduState`）仍正常重组 272B |

## 说明

- GW2022/GW2026 顶层对每个重组体流只调用一次 MSDU 解析器；解析器按首个 MSDU 头声明长度切片，不会继续遍历后续 MSDU。交付口径（用户 2026-11-13 定）：体流交付只要求序列号重组完整，首 MSDU span 是否避开坏块不再是交付门——`span_clean` 经出参透传调用方，仅在 MSDU CRC32 不可用时作 PB 回退；学习取舍由解析器按 MSDU CRC 三态决定（见 `msdu_crc_allows_learning` / `msdu_crc_strip_learning`）。

- 单帧多块重组的帧内状态**不再挂在会话级 `MsduState`** 上；`MsduState` 参数仅为签名兼容，
  函数内 `Q_UNUSED`。旧实现下「无 END 帧 → 后续正常帧整帧被废」的跨帧污染已消除。
- 国网 START/END 降级为交叉校验（只许 START 在 seq0、END 在末块），违反只记
  `pb_head_flag_mismatch`（显示用），不影响按 seq 重组，也不拒收帧。
- 帧级 `pb_crc_ok` 口径 = 全部声明块到齐 + CRC 全过 + `reassembly_ok`。
