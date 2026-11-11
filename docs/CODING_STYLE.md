# 编码风格与文案规范（CODING STYLE）

> **本文件是 UI 文案与 i18n 的强制规范，编码/复核前必读。**
> 违反本规范的改动不予合入。
>
> 适用范围：`src/` 下全部 C++ 代码、`wireshark_support_plugins/` 下全部 Lua 插件。

---

## 一、命名规范（NAMING）

> 规则来源：对仓库现有 170 个 C++ 文件的实测统计（类/结构体 268、函数 422、常量 309 唯一、结构体字段 174、`m_` 成员 322）。**新代码必须与既有风格一致**，不得引入新风格。

### 1.1 总表

| 类别 | 风格 | 实例（取自仓库） | 实测占比 |
|---|---|---|---|
| **类 / 结构体 / 枚举类型名** | `PascalCase` | `MpduInfo` `TopoEvent` `FieldSpec` `CommRateInfo` `CascadeMac` `ByteRingBuffer` | 180/268 |
| **函数 / 方法** | `snake_case` | `get_bits` `tree_add_bit_field` `assemble_pb_blocks` `app_type_name` `annotate_flag` | 300/422 |
| **常量（编译期/文件级）** | `k` + `PascalCase` | `kAppVersion` `kApiVersion` `kLiteStaSlotSpec` `kAppBaseSpecN` `kAssocCnfSpec` | 309 个唯一 |
| **结构体字段 / 局部变量 / 参数** | `snake_case` | `pb_num` `pb_size` `fch_crc_ok` `received_count` `neighbor_teis_present` | 174/174 合规 |
| **Qt 类成员变量** | `m_` + `snake_case` | `m_abort` `m_btn_apply_filter` `m_block_cache` `m_pending` | 322 个 |
| **include guard 宏** | `BPLC_` + 全大写文件名 + `_H`（`#pragma once` 不用） | `BPLC_BPLCFRAME_H` `BPLC_APPCONFIG_H` `BPLC_GW_2026_SOF_PARSER_H` | 全部项目头文件（3rdparty/ 与 src/updater/ 上游代码除外） |
| **其他宏（IID 等）** | 全大写 + `_` | `BPLC_PLUGIN_IID` `BPLC_PARSER_PLUGIN_IID` `BPLC_IPLUGIN_H` | 483 含下划线 / 70 纯 snake |
| **枚举项（值表/列号）** | 全大写 + `_` | `COL_INFO` `COL_LENGTH` `COL_FRAME_TYPE` `COL_DEST` | 34 |
| **枚举项（业务类型）** | `PascalCase` | `AssocReq` `AssocCnf` `AssocInd` `AssocGatherInd` | 18 |
| **布尔字段/变量** | `snake_case`，语义前缀可选 | `is_rf` `has_time_tag` `fch_crc_ok` `pb_crc_checked` `neighbor_teis_present` `complete` | 22 个（`is_` 3 / `has_` 1 / 无前缀 18）|

### 1.2 细则

#### （1）函数一律 snake_case，**禁止 camelCase**

```cpp
// ✅ 正确
quint32 get_bits(const quint8* p, int byte_idx, int bit_off, int width);
bool tree_add_bit_field(...);
void assemble_pb_blocks(...);
QString app_type_name(quint8 t);

// ❌ 禁止
quint32 getBits(...);
bool treeAddBitField(...);
void assemblePbBlocks(...);
```

**例外**：Qt 框架虚函数的覆盖实现必须保持 Qt 原名（`paintEvent` / `showEvent` /
`sizeHint` / `keyPressEvent` / `eventFilter` / `mousePressEvent` …），因为它们
是**接口实现**不是自有命名。

```cpp
// ✅ 正确 —— Qt 虚函数保持原样
void paintEvent(QPaintEvent* e) override;
bool eventFilter(QObject* obj, QEvent* ev) override;

// ✅ 自有辅助函数仍用 snake_case
void paint_frame_markers(QPainter& p);
```

#### （2）常量一律 `k` + PascalCase

```cpp
// ✅ 正确
static const int kLiteStaSlotSpecN = ...;
inline quint32 block_version() { return 12u; }
constexpr int kMaxFrames = 100000;

// ❌ 禁止
static const int LITE_STA_SLOT_N = ...;   // 宏风格
static const int liteStaSlotN = ...;      // camelCase
static const int lite_sta_slot_n = ...;   // 全小写看不出是常量
```

#### （3）结构体字段一律 snake_case，**禁止 `m_` 前缀**

`m_` 前缀**只用于 QObject 派生类的成员变量**（因为要和局部变量区分）；
**纯数据结构（struct / POD）的字段不加前缀**。

```cpp
// ✅ 正确 —— 纯数据结构
struct MpduInfo {
    quint16 pb_num  = 0;
    quint16 pb_size = 0;
    bool fch_crc_ok      = false;
    bool fch_crc_checked = false;
};

// ✅ 正确 —— QObject 子类成员
class MainWindow : public QMainWindow {
    QPushButton* m_btn_apply_filter = nullptr;
    QTimer*      m_autotest_timer   = nullptr;
};

// ❌ 禁止
struct MpduInfo {
    quint16 m_pb_num;      // 数据结构不加 m_
    quint16 PBNum;         // PascalCase 字段
    quint16 pbSize;        // camelCase 字段
    int     nPbNum;        // 匈牙利前缀
};
```

#### （4）布尔命名：语义清晰优先，前缀可选

```cpp
// ✅ 仓库既有风格（推荐）
bool is_rf;                  // 是 RF 链路
bool has_time_tag;           // 带时间标签
bool fch_crc_ok;             // FCH CRC 通过
bool fch_crc_checked;        // FCH CRC 已校验过  ← 与 _ok 区分「未校验 vs 失败」
bool neighbor_teis_present;  // 邻居 TEI 位图存在
bool complete;               // 完整（无需前缀，语义已明确）

// ⚠️ 可读性差 —— 尽量避免
bool flag;    bool b1;    bool temp;
```

**关键**：**「否定」语义必须用正向词 + 判断**，不要用 `not_xxx` / `no_xxx`：

```cpp
// ✅ 正确
if (!fch_crc_ok) { ... }

// ❌ 禁止
bool not_ok = ...;   if (not_ok) { ... }
```

#### （5）枚举项：值表/列号用全大写，业务类型用 PascalCase

```cpp
// ✅ 值表 / 列号 —— 全大写
enum Column {
    COL_INDEX, COL_DELTA, COL_SOURCE, COL_DEST,
    COL_PROTOCOL, COL_FRAME_TYPE, COL_INFO, COL_LENGTH
};
enum Fmt { DEC, HEX8, HEX16, MAC, ASCII };

// ✅ 业务类型 —— PascalCase
enum class NwFrameType { Sof, Beacon, Ack, Coord };
struct AssocReq { ... };   // 或 enum class MMeKind { AssocReq, AssocCnf, ... };

// ❌ 禁止
enum Column { colIndex, col_index, ColumnIndex };   // 三种混用
```

#### （6）宏：全大写 + 下划线，且**优先用 `constexpr` / `inline` 替代**

```cpp
// ✅ include guard
#ifndef BPLC_BPLCFRAME_H
#define BPLC_BPLCFRAME_H
...
#endif  // BPLC_BPLCFRAME_H

// ✅ 宏常量（必要时）
#define BPLC_PLUGIN_IID "com.bplc.plugin/1.0"

// ✅ 更好 —— 能用编译期常量就不用宏
inline constexpr int kMaxBlockCount = 100000;

// ❌ 禁止
#define maxFrames 1000
#define MAX_FRAMES_LIMIT_VALUE 1000   // 冗余词
```

#### （7）命名禁止事项

| 禁止 | 原因 | 正确做法 |
|---|---|---|
| 匈牙利前缀（`nPbNum` / `strName` / `pBuffer` / `bFlag`） | 现代 IDE 可看类型 | `pb_num` / `name` / `buf` |
| 单字母（除循环变量 `i` `j` `k`） | 不可搜索 | `idx` / `pos` / `len` |
| 拼音命名 | 中英混杂 | `pbCount` → `pb_num`；`tiaozhuan` → `jump` |
| 缩写无解释（`mti` / `bdl`） | 只有作者懂 | 协议字段名沿用协议缩写（`tmi` / `pblen` 可，因为协议就叫这个）；**自有概念不要缩写** |
| 类型/变量同名（`int frame_type; int frame_type = ...`） | 遮蔽 | `record_type` / `t` |
| 名称与协议字段不一致 | 查表对不上 | 协议叫 `PBNum` 就写 `pb_num`，叫 `TMI` 就写 `tmi` |

#### （8）协议字段命名：沿用协议原文的拼音/英文，不意译

```cpp
// ✅ 正确 —— 协议叫 PBNum / TMI / TEI / SNID，代码就沿用
quint8 pb_num;      // 协议「物理块个数 PBNum」
quint8 tmi;         // 协议「TMI 编号」
quint16 src_tei;    // 协议「源 TEI」
quint8 snid_hi;     // 协议「短网络标识高位」

// ❌ 禁止 —— 意译后与协议表对不上
quint8 block_count;    // 协议里没有 block_count 这个词
quint8 modulation_idx; // 协议叫 TMI
```

**理由**：复核时要拿代码名去协议表里找字段，**名字一致才能在表里 grep 到**。

#### （9）文件命名

```
snake_case.h / .cpp           ← 协议解析器、工具类
nw_2026_parser.cpp
nw_2026_tree.cpp
nw_2021_beacon_parser.cpp
gw_2026_sof_parser.cpp
packetentry_serialize.h
pb_assembler.h

PascalCase.cpp                ← 主要 UI 类（与类名一致）
MainWindow.cpp / mainwindow.cpp   ← 既有两种都有，新文件统一 snake_case

packet-<proto>.lua            ← Wireshark 插件固定前缀
packet-nw_2026.lua
packet-gw_2022.lua
```

**新文件统一 `snake_case`**（与 `src/protocol/` 下的既有主体一致）。

#### （10）头文件 include guard 必须全库唯一

```cpp
// ✓ 对：把「目录路径」压进 guard，天然不会撞
// src/protocol/gw_protocol/gw_2026/sof/gw_2026_sof_parser.h
#ifndef BPLC_GW_2026_SOF_PARSER_H
#define BPLC_GW_2026_SOF_PARSER_H
...
#endif  // BPLC_GW_2026_SOF_PARSER_H

// ✗ 错：只用文件名去重 —— 两个同名的 sof_parser.h 会拿到同一个 guard
// gw_2022_sof_parser.h 与 gw_2026_sof_parser.h 都写 SOFPARSER_H
#ifndef SOFPARSER_H
#define SOFPARSER_H
```

**规则**：

1. guard 名 = **大写下划线化的路径关键段**，从 `src/` 下一级目录开始带上族/版本/模块，
   例如 `NW_2026_MSDU_PARSER_H`、`GW_2022_SOFPARSER_H`、`PROTOCOL_COMMON_PB_ASSEMBLER_H`。
2. **不许只用 `文件名大写 + _H`**：`sof_parser.h` / `parser.h` / `tree.h` 这类通用名在不同族里必然重名。
3. 一个 TU 里同时 `#include` 多个同族头是**正常需求**（探针、聚合解析器、跨族对照探针都会这么干）。
   guard 撞名的后果是第二个头被**整体静默吃掉**（不报错、不警告，只是类型"不存在"），
   症状往往是 `'gw_2026_sof' has not been declared` 这类**看起来像漏了 `-I` 的假象**。
4. `#endif` 后面写注释回指 guard 名，便于审查时一眼看出边界。
5. 全仓统一规则，**不要混用 `#pragma once`**（目前仅 3 个历史文件用，新文件一律 `#ifndef` 守卫）。

### 1.3 自查

```bash
# ① 函数命名（应全部 snake_case，Qt 虚函数除外）
grep -rn '^\s*\(static \)\?\(inline \)\?[A-Za-z_][\w:<>,\s\*&]*\s\+[a-z][A-Za-z0-9_]*\s*(' src/ --include='*.cpp' --include='*.h'

# ② 常量命名（应全部 k 前缀）
grep -rn 'static const \|constexpr ' src/ --include='*.h' | grep -v '\bk[A-Z]'

# ③ camelCase 字段（应为 0）
grep -rnE '^\s+(bool|quint(8|16|32|64)|int|double|QString|QByteArray)\s+[a-z][a-z0-9]*[A-Z]' src/ --include='*.h'

# ④ 匈牙利前缀（应为 0）
grep -rnE '\b(n[A-Z][a-z]+\w*|str[A-Z]\w*|p[A-Z]\w*|b[A-Z]\w*)\b' src/ --include='*.h' | grep -v '^\s*//'

# ⑤ include guard 重复（应无输出；排除 release/debug/build 等生成目录）
#    只扫 src/：3rdparty/ 里的 vendored 副本天然重复（crashpad 同时存在于
#    3rdparty/install/crashpad/include/ 与 3rdparty/sentry-native/external/crashpad/），
#    那是上游原样代码，不适用本规则，扫进来只会得到上百条噪音。
HDRS=$(find src -name '*.h' -not -path '*/release/*' -not -path '*/debug/*' -not -path '*/build/*' -not -path '*/build_*/*')
for f in $HDRS; do awk '/^#ifndef /{print $2; exit}' "$f" | sed "s|^|$f |"; done \
  | awk '{c[$2]++; p[$2]=p[$2]" "$1} END{for(k in c) if(c[k]>1) print "重复 "k":"p[k]}'

# ⑥ 缺守卫的头（应无输出；同样排除生成目录）
for f in $HDRS; do grep -qE '^#(ifndef|pragma once)' "$f" || echo "无守卫: $f"; done
```

---

## 二、英文文案必须 Title Case

### 2.1 为什么

界面中英双语，英文侧必须风格统一。混用 `broadcast frame` 与 `Broadcast Frame`
会让同一棵字段树里出现两种风格。

### 2.2 核心规则

| # | 规则 | 例子 |
|---|---|---|
| 1 | **首词首字母大写**（无论词性） | `In Bitmap (Byte %1)` |
| 2 | **实词首字母大写**：名词/动词/形容词/副词/代词/数词 | `Empty Frame` / `All CRC Failed` / `Frame Too Short` |
| 3 | **虚词小写**（非首词时） | `Sent on the Detection Band` 里的 `on` / `the` |
| 4 | **缩写全大写保持** | `PB` / `CRC` / `TEI` / `SNR` / `RSSI` / `MAC` / `MMe` / `SACK` / `OFDMA` / `DL` / `UL` / `TMI` / `MCS` / `RU` / `LID` / `SNID` / `BPSK` / `QPSK` / `OK` / `ID` |
| 5 | **含数字的型号原样不动** | `16QAM` / `1/2` / `4/5` / `4B` / `0-255` / `2000-01-01` / `0x02` |
| 6 | **连字符复合词各段首字母大写** | `Non-Bitmap` / `Single-Hop` / `Power-Line` / `Upper-Upper` / `Mgmt-Message` / `Service-Class` |
| 7 | **括号内按同样规则** | `(Smaller = Lower)` / `(Meter Reader)` / `(Byte %1)` / `(Optional)` |
| 8 | **占位符原样不动** | `%1` `%2` `%3` / `<4B>` / `0x%1` / `→` / `·` |

### 2.3 小写虚词清单

```
a  an  the  and  or  but  nor  for  of  in  on  at  to  from  by
with  as  than  that  this  these  those  per  via  vs  not  does
```

### 2.4 容易判错的例子

| 原文 | 正确 | 说明 |
|---|---|---|
| `not in authentication list` | `Not in Authentication List` | `in` 虚词小写 |
| `sent on the detection band` | `Sent on the Detection Band` | `on`/`the` 小写 |
| `physical layer does not check TEI` | `Physical Layer Does Not Check TEI` | `does`/`not` 是动词/否定词 → **大写** |
| `update OK` | `Update OK` | `OK` 缩写 |
| `incl. parse errors` | `Incl. Parse Errors` | `Incl.` 缩写保留句点 |
| `app multi-frame reading supported` | `App Multi-Frame Reading Supported` | `App` = Application |
| `SACK frame of DL-OFDMA data frame` | `SACK Frame of DL-OFDMA Data Frame` | `of` 小写，其余实词大写 |
| `UL-OFDMA trigger` | `UL-OFDMA trigger` | `trigger` 是 MMe 类型名，保持小写 |

### 2.5 🔴 例外：这些不改

#### （A）前置空格的单位/说明后缀

**判据**：英文串以**空格开头** ⇒ 它是拼在数值后面的单位或后缀，**小写正确**。

```cpp
trl::register_en(" 周期", " cycle(s)");        // 显示 "100 cycle(s)"
trl::register_en(" 级",   " level(s)");        // 显示 "4 level(s)"
trl::register_en("个站点", " stations");        // 显示 "5 stations"
trl::register_en("",       " (truncated)");     // 显示 "12B (truncated)"
trl::register_en("",       " (high confidence)");
trl::register_en("小时",   " s (since 2000-01-01 00:00:00)");
```

**完整清单**（64 条，约 40 个唯一串）：
`" cycle(s)"` / `" level(s)"` / `" stations"` / `" symbols"` / `" etc."` /
`" s (since 2000-01-01 00:00:00)"` / `" (40ns/tick)"` / `" (fixed 77)"` /
`" (truncated)"` / `" (CRC missing)"` / `" (fields missing)"` /
`" (high confidence)"` / `" (medium confidence)"` / `" (low confidence)"` /
`" (RF DiscoverNodeList truncated)"` / `" (RFDL truncated)"` /
`" (unsupported MMe version %1)"` / `" (x discovery-list period)"` /
`" (payload PB size index)"` / `" (physical block count)"` / `" (training band flag)"` /
`" (beacon timestamp, NTB)"` / `" (source TEI)"` / `" (destination TEI)"` /
`" (TMI modulation index)"` / `" (OFDM symbol count)"` / `" (sequence number)"` /
`" (search TEI)"` / `" (sync TEI)"` / `" (destination address)"` / `" (SNID high bits)"` /
`" (timestamp, NTB)"` / `" (stream count)"` / `" (RU SNR estimate flag)"` /
`" (PL band flag)"` / `" (subcarrier group size)"` / `" (carrier %1-%2)"` /
`" (beyond cascade stream, parsing stopped)"` / `" (truncated: %1 PB declared, %2 received)"` /
`" (beacon period count, NTB)"` / `" (TMI extended index)"`

#### （B）唯一例外：前置空格但是 UI 标签

```cpp
// src/app/mainwindow.cpp —— 2 空格是排版缩进，不是单位后缀
trl::register_en("  显示过滤器:", "  Display Filter:");   // ✅ 要 Title Case
trl::register_en("  跳转帧:",     "  Goto Frame:");       // ✅ 要 Title Case
```

#### （C）调试/统计格式串

含 **≥2 个 `=`** 且含 `%` 的键值对格式串，视为调试输出，不做 Title Case：

```cpp
// src/topo/topo_window.cpp
"base=%1 activity=%2 signal norm=%3 · weights 0.50/0.30/0.20"
"symmetry=%1 activity=%2 · weights 0.60/0.40"
```

#### （D）协议专有名词

```
trigger        // MMe 类型名，不是英文单词 → 保持小写
Bitloading     // 协议术语 → 只首字母大写（不是 BitLoading）
Mgmt           // 缩写 → 不是 Management
```

---

## 三、i18n 必须成对

### 3.1 规则

**每一个用户可见字符串都必须中英配对注册**，禁止只写中文或只写英文。

### 3.2 两种写法（都要用）

```cpp
// ① 静态文案：register_en + trl::L
trl::register_en("空帧", "Empty Frame");
...
QString s = trl::L("空帧");

// ② 动态/拼接文案：同样成对
trl::register_en("训练帧无数据物理块", "No Data PB for Training Frame");
why = trl::L("训练帧无数据物理块");
```

### 3.3 注册位置

**必须与使用在同一文件**，优先放在文件级静态注册块（匿名命名空间里的
`struct I18nRegXxx { I18nRegXxx() { trl::register_en(...); } }` 静态对象），
保证启动时即已注册、切换语言时不会漏注册。不要分散到别的文件。

运行期注册（如设置对话框里的协议显示名、插件名）是线程安全的（词典有读写锁，
`trl::L` 可在解析线程并发调用），但不要放在逐帧/逐字段的热路径里反复注册。

### 3.4 中文侧规则

- 中文文案保持中文，**不混合英文**（除协议缩写如 TEI/PB/CRC）
- 中文界面下，**列值、摘要、MMe 名称都必须显示中文**
- 中文标点用全角（`（）` / `，` / `：`），英文标点用半角

### 3.5 检查方法

```bash
# 扫全项目，列出小写开头的英文（应为 0，或仅是单位后缀）
grep -rn 'register_en("[^"]*", *"[a-z]' src/ --include='*.cpp'
```

---

## 四、注释必须带协议文档名 + 表号

### 4.1 规则

任何从协议文档推导出的字段坐标、位域、枚举值，**注释里必须同时写明「文档名（分册）」和「表号」**。

**为什么必须写文档名**：本项目同时存在多份表号重复的规约（南网 SPLC / BPLC 两册、国网 HDC 1.0 / 2.0 两册），
`表20`、`表128`、`表130` 在不同册子里是完全不同的表 —— 只写表号等于没写，读者无法定位。

**文档名简写（统一使用，不得自创）**：

| 简写 | 全称 | 文件 |
|---|---|---|
| `SPLC-4` | 南网 通感一体化低压电力线宽带载波通信（SPLC）规约 第4部分 数据链路层 | `docs/protocol_doc/nw/SPLC/` |
| `BPLC-2` | 南网 计量自动化系统双模通信技术规范 第2部分 无线通信接入协议 | `docs/protocol_doc/nw/BPLC/` |
| `HDC2.0-4.2` | 国网 双模通信互联互通技术规范 第4.2部分 数据链路层（HDC 2.0） | `docs/protocol_doc/gw/HDC2.0/` |
| `HDC1.0-4.1` | 国网 双模通信互联互通技术规范 第4.1部分 数据链路层（HDC 1.0） | `docs/protocol_doc/gw/HDC1.0/` |

```cpp
// ✅ 好
{"RFLinkHop", 10, 0, 4, Fmt::DEC},   // 链路上 RF 跳数(BPLC-2 表155 byte12,内容坐标=12-2)
{"LinkType",  14, 0, 1, Fmt::DEC},   // 链路类型(SPLC-4 表108 字节14 bit0,0=载波 1=无线)
// 无线信标载荷 PB 大小码(HDC2.0-4.2 表18 字节10 bit0-3;0-5=16/40/72/136/264/520)

// ❌ 差（无法定位是哪一册）
{"RFLinkHop", 10, 0, 4, Fmt::DEC},   // RF 跳数(表155)
{"LinkType",  14, 0, 1, Fmt::DEC},   // 链路类型(表108)
```

### 4.2 字段树（FieldSpec / spec 数组）是重点对象

字段树 spec 数组**每一条**都要能被追溯：表号写在「该 spec 数组的块注释」或「逐条行尾注释」均可，
但**同一 spec 数组内若字段来自不同表，必须逐条标注**。

```cpp
// ✅ spec 数组块注释注明文档名 + 表号
/// 代理变更确认报文(SPLC-4 表108;字段字节号 0-based)
static const FieldSpec kMMeChangeProxyCnfSpec[] = {
    { "Result",  0, 0, 32, Fmt::DEC },   // 表108 结果
    { "LinkType", 14, 0, 1, Fmt::DEC },  // 表108 链路类型(1bit;余 7bit 为 RSV0)
    ...
};
```

### 4.3 生效方式：增量补齐（每动一处补一处）

**不做历史批量重写**（133 个 spec 数组、463 处表号注释存量不动），但**任何一次改动触及的字段/注释，必须当场把该处补成「文档名 + 表号」**。

判定口径：

| 情形 | 要求 |
|---|---|
| 新增 spec 条目 / 新增字段读取 | **必须**当场写全文档名 + 表号 |
| 修改某字段的坐标、位宽、含义 | **必须**把该行注释补全 |
| 修改某 spec 数组里任何一条 | **该数组块注释**须补文档名 + 表号 |
| 只改数组外的逻辑、未触及字段 | 不强制 |
| 顺手看到的旧注释无文档名 | 鼓励补，不作硬性要求 |

```cpp
// 场景：修一行 LinkType 位宽 —— 注释必须补全，不能只写「表108」
-{"LinkType", 14, 0, 8, Fmt::DEC},   // 链路类型(表108)
+{"LinkType", 14, 0, 1, Fmt::DEC},   // 链路类型(SPLC-4 表108 字节14 bit0,0=载波链路 1=无线链路)
+{"RSV0",    14, 1, 7, Fmt::HEX4},   // 保留(SPLC-4 表108 字节14 bit1-7)
```

### 4.4 位域坐标写清字节+比特+宽度

```cpp
// ✅ 好
const quint8 ofdma_type = (quint8)get_bits(p, 4, 1, 2);   // 表26:byte4 bit1-2

// ❌ 差
const quint8 ofdma_type = (quint8)get_bits(p, 4, 1, 2);
```

---

## 五、协议字段映射必须硬编码

**禁止只写「映射见表N」** —— 含义必须直接查表得出，写进程序。

```cpp
// ✅ 好：查表得含义，直接硬编码
const quint8 train_type = (quint8)get_bits(p, 5, 0, 1);   // 表24:0=MIMO 1=Bitloading
r.msdu.summary = (train_type == 1)
    ? trl::L("训练帧（Bitloading训练帧）")
    : trl::L("训练帧（MIMO训练帧）");

// ❌ 差
r.msdu.summary = trl::L("训练帧");   // 不区分类型，用户看不出是 MIMO 还是 Bitloading
```

---

## 六、位域坐标一律以原始 PDF 为准

### 6.1 禁止用 MinerU 转出的 .md 直接下结论

**已知问题**：MinerU 的 `<table>` 转 markdown 会把 **rowspan/colspan 摊平**，
导致字节号列与比特位列错位（例如 `1011` 是 `10`+`11` 被吞成一格，
`4-7` 可能是比特位被误读成字节范围）。

### 6.2 正确做法

1. **优先读 PDF 原件**（有文本层就直接抽）
2. **无文本层或结构复杂时** → `get_pixmap(dpi=300)` 渲染成图片用 vision 看
3. **判据**：字节号列**空白** = rowspan 继承上一行；比特位是 `0-7` / `4-7` 这种范围
4. **交叉验证**：字段跨度必须自洽
   （例：表155 精简信标「条目长度 19 = 条目头 1 + 长度 1 + 内容 17」，
     字段跨度必须正好 136 bit = 17B）

### 6.3 遇到矛盾的处置

若两个字段「占同一字节区间但位宽矛盾」：
**不要直接改代码** → 先渲染原表确认 → 拿不准报「待定」等用户裁定。

---

## 七、字段树展示约定

| 项 | 约定 |
|---|---|
| 位图字段 | **仅列 bit=1**，值显示 `在位图(第%1字节)`，条目节点加 `(位图 byte N bit M)` 定位 |
| 纯位标记 | 用 `SNID[k]` / `Segment[k]` 形式 |
| 数值字段 | 带上单位/含义，如 `100 cycle(s)` / `4 (high confidence)` |
| 训练帧 | 必须在 MSDU Type/Info 列显示帧性质（MIMO / Bitloading），不得只显空 |
| 列标题 | **统一英文硬编码**，不走 `T()`：`Original Source Address` / `Original Destination Address` |
| 列值 | 中文界面必须中文化，如 `T("广播 (TEI 4095)", "Broadcast (TEI 4095)")` |

---

## 八、CRC / 校验显示三态

**未校验 ≠ 失败 ≠ 通过**，必须三态显示：

| 状态 | 显示 | 列表着色 |
|---|---|---|
| 未校验（无块可校验 / 训练帧 / SACK 类 / 查表失败） | `N/A` | **不标红** |
| 校验通过 | `OK` | 不标红 |
| 校验失败 | `FAIL` | 标红 |

**实现要点**：
- FCH CRC：`MpduInfo.fch_crc_checked` 为 false 时显示 `N/A`
- PB CRC：用 `pb_crc_oks` 数组是否覆盖该块索引判断（`bi < pb_crc_oks.size()`）
- 着色门控：`if (fch_crc_checked && !fch_crc_ok) 标红`

---

## 九、位域布局禁类推

**同一个字段名在不同 MMe/帧类型下位域可以完全不同**，必须逐表查。

实例（SPLC 载波）：

| 表 | 链路类型 | 载波频段 |
|---|---|---|
| 表92 / 表99 | byte15/18 **bit0**（1bit） | **bit1-3**（3bit） |
| 表102 | **无此字段** | **bit0-2**（3bit） |

**⇒ 不能假设「链路类型都在 bit0、载波都在 bit1-3」。**

另一个实例（NW_2026 SPLC SOF）：

| 帧类型 | byte4 bit1 含义 |
|---|---|
| 单站点帧（multi=0，表23） | **训练帧标识** |
| 多站点帧（multi=1，表26） | **OFDMA 帧类型的 bit0** |

**⇒ 同一位在不同帧类型下含义不同，判断顺序必须「先判大类型，再判子类型」。**

---

## 十、TTL 检查清单（提交前自查）

```
命名
□ 函数 snake_case（Qt 虚函数除外）
□ 常量 k + PascalCase
□ 结构体字段 snake_case，无 m_ 前缀
□ QObject 成员 m_ + snake_case
□ 宏全大写 + 下划线，能用 constexpr 就不用宏
□ 无匈牙利前缀 / 无拼音 / 无单字母（i/j/k 除外）
□ 协议字段名与协议原文一致（PBNum→pb_num / TMI→tmi / TEI→tei）

文案
□ 新增/修改的英文文案全部 Title Case（单位后缀除外）
□ 每个用户可见字符串都有 register_en 中英配对
□ 中文标点全角、英文标点半角

协议
□ 协议相关注释写了表号
□ 协议字段含义已硬编码，不是「见表N」
□ 位域坐标用原始 PDF 核对过（不是只看 MinerU md）
□ 位域布局没有跨表类推

数据
□ 新增字段进了 block_version 序列化（换页不丢）
□ CRC 类显示用三态（N/A / OK / FAIL）

构建
□ 编译 0 warning
```

## 十一、自动检查脚本

```python
import os, re

MINOR = {'a','an','the','and','or','but','nor','for','of','in','on','at','to','from','by',
         'with','as','than','that','this','these','those','per','via','vs','not','does'}

pat = re.compile(r'register_en\s*\(\s*"((?:[^"\\]|\\.)*)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*\)')

def check(en):
    if not en: return True, ''
    if en.startswith(' '): return True, ''            # 单位/说明后缀
    if en.count('=') >= 2 and '%' in en: return True, ''  # 调试格式串
    if en.isupper(): return True, ''                  # 纯缩写
    if re.match(r'[a-z]', en): return False, '首字母小写'
    bad = []
    for i, t in enumerate(en.split(' ')):
        w = re.sub(r'^[^\w]+|[^\w]+$', '', t)
        if not w or len(w) <= 1: continue
        if w.isupper() or re.search(r'\d', w): continue
        if w.lower() in MINOR: continue
        if '-' in w: continue
        if i == 0: continue
        if w[0].islower(): bad.append(w)
    if bad: return False, f'内部实词小写: {bad}'
    return True, ''

for dp, _, fs in os.walk('src'):
    for fn in fs:
        if not fn.endswith(('.cpp','.h')): continue
        p = os.path.join(dp, fn)
        s = open(p, encoding='utf-8', errors='replace').read()
        for m in pat.finditer(s):
            ok, why = check(m.group(2))
            if not ok:
                line = s[:m.start()].count('\n')+1
                print(f'{p}:{line}  {m.group(2)!r}  ← {why}')
```

保存为 `tools/check_title_case.py`，CI 里可加一步。

---

## 十二、工具链陷阱（TOOLCHAIN PITFALLS）

这些坑不影响编译，但会让「代码改对了、用户拿到的却是坏的」—— 比编译错误更危险。

### 12.1 `QString("中文")` 不走 `trl::L` ⇒ 英文界面显示中文

```cpp
// ✗ 错：英文界面这一格会直接显示中文，且 check_title_case 查不到
return QString("PB 大小非法(copy_mode=%1)").arg(cm);

// ✓ 对
return trl::L("PB 大小非法(copy_mode=%1)").arg(cm);
```

**判定标准**：任何**用户可见**的中文字符串，要么走 `trl::L(...)` + `register_en(...)`，要么明确是「双语成对结构」或「协议术语/单位」。

**合法的「裸中文字面量」只有三类**：

```cpp
// ① 双语成对结构（中文旁边紧跟英文，界面自行按语言选）
{QStringLiteral("BPLC_APP_VERSION"),
 QStringLiteral("宿主程序版本"), QStringLiteral("Host app version"),
 QStringLiteral("当前运行的上位机版本号,如 1.3.0"),
 QStringLiteral("Version of the running host app, e.g. 1.3.0")}

// ② 协议术语（中英同显，不翻译）
QStringLiteral("TEI")  QStringLiteral("MAC")  QStringLiteral("NID")
QStringLiteral("SNR (dB)")

// ③ 动态注册（值来自运行时，由提供方自带中英两版）
trl::register_en(p->display_name_zh().toUtf8().constData(),
                 p->display_name_en().toUtf8().constData());
```

**自查**：`py -3 tools/check_i18n.py --strict`（① 裸中文必须为 0，已自动排除上述三类误报）。

### 12.2 `core.autocrlf=true` + 缺 `.gitattributes` ⇒ 工作区/CI 检出成 CRLF

**症状**：仓库对象库里存的明明是 LF（`git cat-file blob HEAD:<path>` 权威读取为 LF），
但工作区是 CRLF（`git ls-files --eol` 显示 `i/lf  w/crlf`），
于是 `release/` 与安装包里的文件也是 CRLF。

**危害：不是「工具加载失败」，而是「验证口径分裂」。**

>
> **实测订正（2026-10）**：曾误判为「CRLF 导致 Wireshark Lua 加载失败」，实测否定：
> 同一份 CRLF 插件放在 `release/`、用户安装目录、任意新建目录，tshark 均正常加载且
> 解析结果与 LF 版逐帧一致（Lua 把 `\r` 当空白）。仓库某目录下有未定位的异常现象
> （同名文件在该目录 FAIL、复制到别处 OK），但与部署无关，不据此下结论。
> **结论：CRLF 影响的是「比对」，不是「运行」。**

具体的比对困扰：

```bash
# 包内插件 vs 工作区：逐字节一致 ✓
# 包内插件 vs HEAD blob：4/4 不一致 ✗  ← 因为 blob 是 LF、包内是 CRLF
#                        必须先归一化（tr -d '\r'）才能比
```

**危害 2：历史记录噪音** —— 任何「包与仓库源一致性」的断言都得先做行尾归一化，
一旦有人漏了归一化，就会得到假报警或假通过。

**真实的工具侧崩溃点（另一类问题，别混淆）**：

| 文件类型 | 工具 | CRLF 下的报错 |
|---|---|---|
| `*.nsi` | NSIS 3.09 | `Bad text encoding ... on line 1`（打包中止）—— **这个是实测的** |
| `*.lua` | Wireshark Lua | **不会崩**（见上方订正） |

`*.nsi` 的崩溃是 NSIS 自身的编码嗅探缺陷，与 Lua 无关 —— `.gitattributes` 里
`*.nsi text eol=lf` 就是为此而加，那一条是**修 bug**，不是卫生。

**修法**：`.gitattributes` 强制 LF

```gitattributes
*.lua text eol=lf      # 一致性（避免包/blob 比对需归一化）
*.nsi text eol=lf      # 修 bug（NSIS 读 CRLF 报 Bad text encoding）
```

**`text` 和 `eol` 两个关键字必须都写** —— 只写 `eol=lf` 时很多 git 版本不生效（`eol` 依赖 `text` 属性）。

**生效顺序（重要）**：

```bash
# ① 先加规则（让 eol=lf 生效）
# ② 再转工作区（不能用 git checkout，会覆盖未提交改动）
for f in wireshark_support_plugins/packet-*.lua; do
    tr -d '\r' < "$f" > /tmp/x && mv /tmp/x "$f"
done
# ③ 最后 add
#    注意：git add --renormalize 单独做是 no-op —— blob 本来就是 LF，
#    索引不会有变化；真正变的是工作区文件
git add .gitattributes wireshark_support_plugins/packet-*.lua
```

**验收**：

```bash
git ls-files --eol wireshark_support_plugins/packet-*.lua
# 期望：i/lf  w/lf  attr/text eol=lf
```

**打包前断言**（`scripts/package.sh`）—— 推荐写成「与仓库源逐字节一致」，
同时守住行尾与内容两层，比单查 `\r` 更强：

```bash
# 注: 必须 -U（binary 模式）—— MSYS/cygwin 的 grep 默认会剥离行尾 CR，不加 -U 永远检不到
for f in release/wireshark_support_plugins/*.lua; do
    src="wireshark_support_plugins/$(basename "$f")"
    cmp -s "$f" "$src" || { echo "错误: 包内插件与仓库源不一致: $f" >&2; exit 1; }
done
```

### 12.3 「仿真帧验证」不等于「实包验证」

用自己按协议文档构造的帧去验自己按同一份文档写的解析器，**只能排除「实现偏离文档」，不能排除「文档理解偏差」** —— 这是循环论证。

```cpp
// 标 true 表示「实现层已验证」，注释必须写清 weak 项，否则后人会误以为协议理解也被证实
info.sof_multi_site_verified = true;
// 已验证：块边界、CRC24、START/END 时序、C++/Python/Lua 三方一致
// 未验证：eFC 是否恒 16B、分集拷贝→PB 大小映射（协议指向外部文档）、厂商私有字段
// ⚠ 循环论证风险：真帧到位后应复核 weak 项
```

**规则**：凡是「用构造数据验证」的结论，注释里必须列出 `已验证(strong)` / `未验证(weak)` 两栏，并注明数据来源是仿真实测。

### 12.4 `src/updater/updater.pri` 的 `QSU_INCLUDE_MOC` 保持原样，不要改

`src/updater/` 是 QSimpleUpdater 上游原样代码（见该 `.pri` 文件头说明与 `LICENSE.md`），
`updater.pri:24` 的 `DEFINES += QSU_INCLUDE_MOC=1` 让各 `.cpp` 在文件尾部 `#include "moc_*.cpp"`，
moc 符号直接编进对应的 `.o`。**这是既定方案，属于第三方模块的自包含约束，不要"优化"它。**

```text
# ✗ 不要做：改 QSU_INCLUDE_MOC=0 / 把头从 HEADERS 移出 / 加 QMAKE_MOC_SKIP /
#           手写 moc 规则把产物落进 src/updater/ / 改写上游源码
# ✓ 要做：重新编译（干净重编）
```

遇到下列症状时的正确处置是**清掉构建目录里的生成物后重新 qmake + 编译**，不是改 `updater.pri`：

| 症状 | 处置 |
|---|---|
| 链接报 `multiple definition of AuthenticateDialog::metaObject()` / `QSimpleUpdater::staticMetaObject` 等（实测 32 条，4 个类 × 8 个符号） | 删掉构建目录里的生成物（`Makefile*`、`mocinclude.opt`、`debug/`、`release/`、`ui_*.h`、`*_resource.rc`）→ 重新 `qmake` → 全量编译 |
| 全新/复制出来的构建目录报 `fatal error: moc_Updater.cpp: No such file or directory`（`-j4` 与串行都会） | 同上：在既有构建目录里清掉生成物并重跑 qmake；不要靠 `git worktree`（它会在 qmake 阶段联网克隆 `3rdparty/sentry-native` 卡住） |

**机理（2026-11 实测更正，勿再沿用"配置自相矛盾"的旧说法）**：`updater.pri` 本身是自洽的 ——
qmake 的 mocinclude 探测（产物是构建目录里的 `mocinclude.opt`）**能够识别**源码里
`#if QSU_INCLUDE_MOC → #include "moc_*.cpp"` 的写法，并把对应的 `moc_X.o` 从 `OBJECTS` 里剔除，
于是"内联 moc 的 `X.o`"是唯一提供符号者，不会重复。实测：清空生成物重新 qmake 后
`grep -c 'debug/moc_QSimpleUpdater\.o' Makefile.Debug` = **0**，而 `-DQSU_INCLUDE_MOC=1` 仍在。
只有当构建目录里残留**上一轮的 `moc_*.cpp`/`moc_*.o`** 时，探测结果被污染，`X.o` 与 `moc_X.o`
同时进链接才会撞 32 条 `multiple definition`。

**理由**：`src/updater/` 是上游原样代码，本地只允许两处改动（`Updater.cpp` 的 `clipped_changelog` 裁剪与
`downloadUrl` 镜像前缀，均有「本地修改」标注）。为构建便利去改它的 moc 方案，会让下一次同步上游时冲突面扩大，
且历史上已出现过"改回去→干净构建链接失败→再改回来"的反复（`c281e27`）。**构建产物问题用"清生成物 + 重跑 qmake"解决，不要动第三方配置。**

---

## 十三、通用枚举与常量登记表（禁止裸值）

### 13.1 原则

**业务语义值一律不得裸写。** 任何在代码里出现 ≥2 次的语义值（链路类型、TEI 特殊值、协议号、MMe 类型、哨兵值），
必须在 `src/common/bplcframe.h` 定义枚举/`constexpr`，**并在本表登记**，然后才可使用。

**判定顺序**：
1. 先查本表有没有现成的 → 有就直接用
2. 没有 → 在 `bplcframe.h` 定义（common 层，不依赖协议层）+ 注释写协议文档名与表号 → **同时在本表补一行**
3. 只在单个函数内用一次的局部魔数（如循环上界）→ 可不定义，但注释要写清含义

### 13.2 登记表（`src/common/bplcframe.h`）

| 枚举 / 常量 | 值 | 含义 | 协议依据 |
|---|---|---|---|
| `enum LinkTypeValue : quint8` | | 链路类型 | SPLC-4 表79 / BPLC-2 表160；HDC1.0 表61、表72 / HDC2.0 表56、表58（两家一致） |
| `LinkTypeHplc` | 0 | 高速载波链路 | 同上 |
| `LinkTypeRf` | 1 | 无线链路 | 同上 |
| `LinkTypeUnknown` | 0xFF | 未定（⚠️ **本机约定**，协议该域仅 1bit） | — |
| `constexpr quint16 kTeiCco` | 1 | CCO 的 TEI | SPLC-4「TEI 固定为 1」/ HDC2.0 5.3.3.1 |
| `constexpr quint16 kTeiBroadcast` | 0xFFF | 广播报文 TEI | SPLC-4「广播报文 TEI 为 0xFFF」/ HDC2.0 5.3.3.1 |
| `constexpr quint16 kTeiInvalid` | 0xFFFF | 无效/未分配（⚠️ **本机哨兵**，超出 12bit 域） | — |
| `constexpr quint8 kRestartCountInvalid` | 0xFF | 重启次数无效（⚠️ **本机哨兵**；协议该域仅 4bit 0-15） | 国网 MSDU 头 / 南网 MAC 帧头重启次数字段 |
| `constexpr quint16 kMMeTypeNone` | 0xFFFF | 非管理消息的 `mme_type` 标记（⚠️ **本机约定**） | — |
| `enum NwCcoInitiatedMme : quint16` | | CCO 作为发起者/回应者的管理消息（中继判定排除用） | SPLC-4 表92 / 表99 / 表108 |
| `NwCcoInitMmeAssocCnf` | 0x0031 | 关联确认 | 表92 |
| `NwCcoInitMmeAssocInd` | 0x0034 | 关联指示 | 表99 |
| `NwCcoInitMmeChangeProxyCnf` | 0x0037 | 代理变更确认 | 表108 |
| `enum class TopoEventKind` | — | 拓扑事件类型 | 见 `bplcframe.h` 逐项注释 |
| `constexpr quint8 kProtocolGw2022` | 0 | 国网 HDC 1.0（2022） | 协议选择 |
| `constexpr quint8 kProtocolNw2021` | 1 | 南网 BPLC 2021 报批版 | 协议选择 |
| `constexpr quint8 kProtocolGw2026` | 2 | 国网 HDC 2.0（2026） | 协议选择 |
| `constexpr quint8 kProtocolNw2026` | 3 | 南网 SPLC 2026 | 协议选择 |
| `constexpr quint8 kProtocolPluginBit` | 0x80 | 协议号插件位（低 7bit 为协议号） | 本机约定 |

### 13.3 待补登记（已知裸值，尚未定义）

**当前为空** —— 原登记的两项已于 2026-10 补齐并移入 13.2：

| 裸值 | 含义 | 建议名 | 出处 |
|---|---|---|---|
| ~~`0xFF`~~ | ~~重启次数无效~~ | ~~`kRestartCountInvalid`~~ | ✅ 已定义 |
| ~~`0xFFFF`~~ | ~~非管理消息 `mme_type` 哨兵~~ | ~~`kMMeTypeNone`~~ | ✅ 已定义 |

> 新发现通用值为裸值时，先在本节登记（写明值/含义/建议名/出处），
> 定义落地后移入 13.2 登记表。

### 13.4 审查判据（代码复核时逐条 grep）

```bash
# ① 判 CCO 的裸值（应为 0）—— 注意同时覆盖十进制 1 与十六进制 0x1/0x01/0x0001/0x00000001
grep -rnE '(tei|parent|src_tei|dst_tei|old_tei|msdu_src_tei|msdu_dst_tei) *[=!]= *(1|0[xX]0*1)\b' src/ | grep -v kTeiCco

# ② 广播 TEI 裸值（应为 0）—— 覆盖 4095 / 0xFFF / 0x0FFF
grep -rnE '(tei|dst_tei) *[=!]= *(4095|0[xX]0*FFF)\b' src/ | grep -v kTeiBroadcast

# ③ 链路类型裸值（应为 0）
grep -rnE 'link_type *[=!]= *(1|0|0[xX]0*[01]|0[xX]0*FF)\b' src/ | grep -vE 'LinkType(Rf|Hplc|Unknown)'

# ④ 无效 TEI 哨兵裸值（应为 0）—— 覆盖 65535 / 0xFFFF
grep -rnE '(tei|parent_tei|proxy_tei|reporter_tei|ctei) *[=!]= *(65535|0[xX]0*FFFF)\b' src/ | grep -v kTeiInvalid

# ⑤ 新增枚举后是否登记进 13.2
grep -nE '^enum |^constexpr ' src/common/bplcframe.h   # 逐项与本文档 13.2 表比对
```

**审查口径**：以上 ①～④ 命中即**不合入**（除注释/字符串字面量）；⑤ 缺登记项要求补齐文档。

> **⚠️ 教训（2026-10 实测）**：初版判据只写 `== 1`，漏掉了 `== 0x0001` 的写法
> （实测残留于 `bplcframe.h:458/462`、`packetlistmodel.cpp:168/184` 的 CCO 显示判断）。
> 写正则时**必须同时覆盖十进制与各种十六进制零填充**（`0x1` / `0x01` / `0x0001` / `0x00000001`）。

---

## 附：待清理的历史遗留

截至本规范建立时，代码库中还有 **399 条**「首字母大写但内部实词小写」的历史文案
（如 `Terminal meter reading` / `Install failed` / `Time sync`）。

这些**不属于硬伤**（首字母已大写），已决定留到 v2.0.1 做专项统一。
**新增代码必须严格符合本规范。**
