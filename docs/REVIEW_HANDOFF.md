# 文档侧移交台账（REVIEW HANDOFF）

> 本文件是 **@office-review-bot 文档侧复核的唯一入口**。
> 所有交付物、指纹、复核重点、状态都记在这里 —— 消息可能因 `target_busy` 投递失败，
> **本文件落盘即视为已移交**，请直接读盘。

## 一、交付物索引

| # | 文件 | 说明 | 字节 | 行数 | sha256 |
|---|---|---|---|---|---|
| 1 | `docs/TEST_FRAME_CATALOG.md` | **四协议全帧类型清单** — 每协议一章：★帧类型总表 / 帧相关章节索引 / 类型标识符清单 / 帧报文字段表 / ⚠同名表索引 | 587,039 B | 12129 | `6137c5943d241333eed7f8a30c991a041e04e0838ce6b1b416cc40816303c569` |
| 2 | `docs/TEST_FRAME_CROSSREF.md` | **跨协议帧类型对照表** — 13 类横跨四协议，每格给 表号+取值+归属章节 | 15,385 B | 183 | `75f6b8bddcbbdc2bed6839cb369fc4f741e2c958241f0887224b44a294e618e9` |
| 3 | `docs/TEST_FRAME_ROWSPAN_AUDIT.md` | **⚠rowspan 矛盾筛查** — 回源核对前的机器预筛：(A)262 (B)67 (C)0 (C2)79 | 34,880 B | 335 | `e7edc6e0c5286456f5c92810ca6466944d46d87c83ef0cd40ab8869a6f111119` |
| 4 | `docs/TEST_TIER3_FRAME_MATRIX.md` | **3 级帧型矩阵** — 34 项 MMe 语义 × 层级 × 方向 × 四协议表号标识符 | 29,651 B | 325 | `d328818d5bf3c9fb15ca113451114743e3279963982362ae6cbe87ae9c3bd385` |
| 5 | `unit_test/manual/hdc2_0_test_frames.md` | **构造帧 9 帧 + 逐字节说明** — 含 16bit/32bit 小端专节、同名表归属、源表核验 | 15,954 B | 282 | `4d5bea64aa17b367101d6091279ddd4b93cf2151481db1317d40d61cd583a1c0` |
| 6 | `unit_test/manual/hdc2_0_build_frames.py` | **帧生成脚本（带运行时自校验）** — 9 帧全打印 + 4 个多字节整数字段小端 assert | 12,219 B | 281 | `0c8cc2c61a3f376d041f64184b70eb22755c4f0cd8417ce474a5da49be8ab9d8` |
| 7 | `tools/gen_frame_catalog.py` | **四协议目录生成器** — rowspan/colspan 网格展开 + 固定头长度 + 跨字节标注 | 11,568 B | 263 | `c6effc39dc21a595da8ce55426810ea2b5391ceef5281ec61c43caef8f86d980` |
| 8 | `tools/gen_frame_crossref.py` | **对照表生成器** — | 3,831 B | 101 | `327f94a64477797ceb6475df176d64de5a1152ba4579fb77292e398d25ca80a6` |
| 9 | `tools/gen_tier3_matrix.py` | **3 级矩阵生成器** — | 15,053 B | 252 | `91ac834782c568baf01e686f0f6974a4e53fd48a1d8d2b692789475db2b4b0ea` |
| 10 | `docs/TEST_TOPOLOGY_FRAME_MATRIX.md` | **3 级帧型矩阵（拓扑命名版）** — 与第 4 项同源，另加「合成 vs 实包提取建议」一节；为 3 级拓扑数据集提供帧型/层级/方向/四协议表号标识符 | 31,406 B | 355 | `85ed1ee6b1179cb53b9340d6fb6d69bfe78f5ee4519b667f1409fe36797e8b80` |
| 11 | `docs/TEST_FRAME_SELFTEST.md` | **扩展自校验报告** — 固定头长度 + rowspan 继承值：独立算法全表交叉比对，从源 HTML 独立重建期望网格与生成器网格逐格比对 | 9,039 B | 132 | `1b6a168fbb3d66f37d1b5033b59741d8ca497ab5f68a2ae2a4cf768a3bef8de2` |

> **本表覆盖范围**：上表 11 件即文档侧复核的全部交付物。
> 仓库另有在库文档但**不属于文档侧复核范围**（故不列，各自归属与责任人不同）：
> `docs/USER_MANUAL_zh-CN.md` / `docs/USER_MANUAL_en.md`（用户手册，发布产物）、
> `docs/TEST_TOPOLOGY_NW_BPLC.md`（南网拓扑验收记录）、
> `docs/TOPO_NEIGHBOR_SCORE.md`（拓扑评分算法说明）。

## 二、复核重点（四条，务必逐项核）

### （1）同名表归属 —— 上一轮栽过的坑

| 表号 | 长度 | 归属章节 | 适用 |
|---|---|---|---|
| 表39 | **7B** | §5.1.2.4.2 **标准信标数据载荷** 的 IE | **不是**发现列表报文 |
| 表63 | **23B** | §5.1.3.10.1 载波发现列表报文 的 IE | HDC2.0 msg_type 2 |
| 表92 | **14B** | §5.1.3.17.1 无线发现列表报文 的 IE | HDC2.0 msg_type 0 |
| 表126 | **14B** | HDC1.0 站点属性信息格式（≡表92） | HDC1.0 msg_type 0 |

管理消息类型另有**四组同名表** —— HDC1.0 表59 / HDC2.0 表43 / SPLC 表77+表242 / BPLC 表38+表158，**取值集合不同**。

### （2）字节序

| 类型 | 填法 |
|---|---|
| 8bit | 直接 |
| **16bit / 32bit 整数字段** | **小端**（`byteN \| (byteN+1<<8)`）|
| 12bit 位域（字节对齐） | `byteN \| ((byteN+1 & 0x0F) << 8)` |
| **12bit 位域（非字节对齐，表63 代理TEI）** | **方向相反**：`(byte1>>4) \| (byte2<<4)` |

### （3）成功率字段精确字节

- 表92 / 表126（无线 14B）：**byte9** 代理上行 78 / **byte10** 代理下行 90 / **byte11** 最小 60
- 表63（载波 23B）：**byte12** 78 / **byte13** 90 / **byte16** 60

### （4）关联确认「结果」字段必须 = 0**（表70 byte12 = 0x00，byte13 = 站点层级）

## 三、跨协议 MMe 标识符号段分裂（🔴 静默失效风险）

| 语义 | 南网BPLC | 南网SPLC | 国网HDC1.0 | 国网HDC2.0 |
|---|---|---|---|---|
| 关联请求 | **0x0030** | **0x0030** | **0x0000** | **0x0000** |
| 关联确认 | 0x0031 | 0x0031 | 0x0001 | 0x0001 |
| 代理变更请求 | 0x0032 | 0x0032 | 0x0003 | 0x0003 |
| 关联汇总指示 | 0x003A | 0x003A | 0x0002 | 0x0002 |
| 离线指示 | 0x0049 | 0x0049 | 0x0006 | 0x0006 |
| 心跳检测 | 0x0051 | 0x0051 | 0x0007 | 0x0007 |

> **南网用 0x0030+ 号段，国网用 0x0000+ 号段。** 跨协议复制 MMe 值 → 国网解析器判为「未知 MMe」**静默跳过**。
> @code-review-bot 已 grep 代码证实实现正确（`nw_2021_msdu_parser.h:75 MME_ASSOCREQ = 0x0030` / gw_2026 关联请求 0x0000）。

## 四、已知限制（请在结论里标注）

1. **字段表是自动提取的** —— rowspan 折叠造成的空白已用展开网格修复结构性丢失，含继承格的行标 `⚠rowspan`，但**空白仍需回源核对**。
2. **物理层帧的字段多数在图里**（SOF/信标位域画在图上）→ 目录只到图题与章节，**未逐字段展开**。
3. **层级/方向是按语义推断的**（3 级矩阵），非源表字段，已标「推断」。
4. 目录是**结构索引**（定位+章节归属+跨字节警示+固定头长度），**不替代源表**做编码依据。

## 五、需要复核方判断、我自己判不了的

1. **ROWSPAN_AUDIT 的 (A) 262 处字节号回退 / (B) 67 处同字节比特区间重叠** —— 有多少是源表本身字段乱序或字节复用（合法），有多少是 rowspan 展开真错位？
2. **3 级矩阵的「发现列表」层级方向** —— 我按语义定为 2→1（代理向 CCO 上报），需确认。
3. **HDC2.0 的「发现列表」在矩阵里显示「—」** —— 我怀疑是**归一化漏配**而非该协议没有。
4. **HDC1.0 表59 的 `代理变更确认(MMeChangeProxyBitMapCnf)`(0x0005 位图版)** 与 `代理变更确认(MMeChangeProxyCnf)`(0x0004) 归一后同名被合并，位图版应独立成行。
5. **物理层帧逐字段**是否需要（当前只有图题与章节）。

## 六、构造帧自校验状态

- `unit_test/manual/hdc2_0_build_frames.py` 运行即 assert 4 个多字节整数字段的小端读值
- **md ↔ 脚本同源校验 9/9**，md 中陈旧 hex 孤儿 0 个
- 帧A/HDC1.0帧1 byte9=78 byte10=90 byte11=60；帧B byte12=78 byte13=90 byte16=60；帧3/4 link_type=1/0 —— @code-review-bot 已逐字节验证通过


## 八、构造帧的唯一版本锚点（v4.2）

| 项 | 值 |
|---|---|
| **帧集指纹** | `a6ff30799847f169ea75d28c89ca11e207fff0e23d8092a4552f2951065da99f` |
| **帧集指纹旧值** | `cdbd0981e70c973d65e4e3a1f2341b09ed48816f2490caffbe4f1f183fe209b8`（89423fc 前大端/清零版，勿用） |
| **帧集指纹作废值** | `556cb263a53f5f33a077cdf48899b319176a2ae1f0796a15ee9b9d7344ab0aa6`（939efe1 帧序重排前小写正文 join 的中间态产物，office-review-bot 终裁 2026-10-24：作废勿用；v2.3.3 台账口径由其登记） |
| **帧数** | 9 |
| **生成脚本** | `unit_test/manual/hdc2_0_build_frames.py` sha256 `0c8cc2c61a3f376d041f64184b70eb22755c4f0cd8417ce474a5da49be8ab9d8` |
| **帧文档** | `unit_test/manual/hdc2_0_test_frames.md` sha256 `4d5bea64aa17b367101d6091279ddd4b93cf2151481db1317d40d61cd583a1c0`（15,954 B） |

**帧集指纹算法**：`sha256("".join(九帧的连续 hex))` —— 重跑生成脚本即可复算比对。
> 这是**唯一的版本锚点**。任何副本（含聊天消息里贴的 hex）若与此指纹不符，即为旧版，勿用。
> v3 与 v4 的差别就在这里：v3 的帧B byte14-15 是大端 `00 1E`（读成 7680），v4.1 是小端 `1E 00`（读成 30）。


## 七、状态（2026-10-24 23:0x 更新 · 含口径终裁）

- **本批已全部提交并同步**（提交链：`939efe1` office-bot 修 4 处 → `15c9a3c` 台账订正 → `610865b/13a8dfc` bin_to_pcap 注释等；@git-release-bot 以 merge commit `3ef3cfd` 线性化早期 amend 分叉，base = `88296eb` = origin，0/0）。
- **数据集入库口径终裁（用户裁定，`88296eb` + `bbe1db8`）**：三个数据集 bin（`nw_bplc_3frames.bin` / `test_topology_nw.bin` / `test_topology_nw_p2.bin`）、两个 manifest json（`test_topology_nw.json` / `test_topology_nw_p2.json`，`bbe1db8` 移出）与 pcap **均不入库**（工作区文件保留，由 `gen_nw_bplc_*.py` 生成器确定性重建）；唯一保留在库的 `.bin` 是 CI 夹具 `unit_test/ci/roundtrip/roundtrip_test.bin`。第八节版本锚点（帧集指纹 / 生成脚本 / 帧文档 md）不受此口径影响。
- **office-review-bot 裁定「修 4 处」已全部落地**（`939efe1` + 本提交）：
  ① 5 个过期 pretty 块（帧2/3/4/帧B/帧3′）已按脚本重生成，删 1 条陈旧「连续：」双行残留；
  ② md 头部 L10 指纹算法改「连续：`HEX`（NNB）」格式 + 说明与 python 复核片段；
  ③ 帧集指纹 = `a6ff3079…`（9 条、文档序 = 脚本序），旧值 `cdbd0981…` 已注记勿用；
  ④ P2 位图字节：`docs/TEST_TOPOLOGY_NW_BPLC.md` 早已 `80 03`/`E0`（无 `c0 01` 残留），无需再改。
- **复核方一次性核验（office-bot 已做，结果在此）**：重跑 `py unit_test/manual/hdc2_0_build_frames.py`（rc=0、15 项自校验全过）→ 9 条 CONT 与 md「连续：」行逐条相等 ✓；md 9 个 pretty hex 块 == 脚本逐帧输出 ✓；第八节帧集指纹 == `sha256(9 条 hex 文档序)` = `a6ff3079…` ✓；py sha = `0c8cc2c6…` ✓。
- **vibe-coding 的 `docs/TOPO_NEIGHBOR_SCORE.md` 与 `unit_test/manual/gw26_rfdl_probe.*` 仍不属本批**。

## 九、v2.3.3 微补丁登记（office-bot 侧 · 2026-10-24）

> 目的：把 office-review-bot 复核结论第二节「核完定案、无需动作」的 5 项 + 位图 TEI 裁决**登记**入账。全部已有双源/像素证据，本段只登记、不重裁；登记措辞按其建议。

| # | 定案项 | 登记措辞 | 证据锚点 |
|---|---|---|---|
| ① | HDC2.0 表92「rowspan 退化」 | **NULL：疑似缺陷经核查不成立** —— 基线 260823 与新转件 261023 的表92 byte7 单元格逐字相同、均带 `rowspan="2"`；对方所见「无 rowspan 2 处」为另外两张字节号列本就逐行书写的表 | `A6_ROWSPAN_VERIFICATION.md`（反证）+ M7 全量 741 表 0 命中 + 矢量 PDF P73 像素终裁 |
| ② | 16/32bit 整数字节序 | **实现互操作约定（小端），非规范结论** —— 规范全文唯一字节序条款只约束 MAC 地址；实包 MSDU 序列号严格 +1 与 Lua `add_le` 背书 | code-review-bot 实包判据（国网 5MB 切片）+ `packet-gw_2022.lua` |
| ③ | CATALOG 固定头片段缺口 | **已闭环** —— 口径收窄到 ★帧类型总表 177 张：帧/报文类受影响 **0 张**；7 张命中全为南网 BPLC 枚举/取值类表（固定头无意义，不应用）；表126 固定头 14B 已登记。生成器跨片段合并列为低优先工具健壮性项，不影响现有交付物 | `FIXED_HEADER_CORRECTIONS.md` §5 + CATALOG §6 L6450 |
| ④ | 3 级矩阵发现列表方向 | **3→2→1 逐级上行**（2 级网退化 2→1），与第5部分 L2458「发现列表信息随心跳逐级上报至 CCO」一致 | `docs/TEST_TIER3_FRAME_MATRIX.md` §① |
| ⑤ | HDC2.0 发现列表「—」 | 表43 `0x0008`=保留（1.0 发现列表 2.0 改经单跳帧/信标承载）：单跳帧 msg 0=无线发现列表（表91/92 14B）、msg 2=载波发现列表（表62/63 23B） | 矩阵 §① 注 + `gw_2026_msdu_parser.cpp`（topo_event 无 DiscoverList，仅单跳帧路径） |
| ⑥ | 位图 TEI 基线裁决 | **0-based（TEI=8i+j，无 +1）** —— 四规约同句码字且「第 1 字节第 0 比特=TEI8」直接排除 1-based；C++/Lua 解码器零改动，改的是生成器 wire（帧4 `80 03`）；office-review-bot 的「+1」附注已正式撤回 | code-review-bot 定案 + office-review-bot 复核背书（2026-10-24） |

**⑦ 556cb263 指纹注记**：已登记于第八节「帧集指纹作废值」行（939efe1 帧序重排前小写正文 join 的中间态产物，作废勿用）—— office-review-bot 要求的「顺手补一行」已落，v2.3.3 台账口径由其登记时引用本行。
- **bin 移出执行与复核（2026-10-24 晚，收口闭环）**：`88296eb`（git-release-bot 执行三 bin rm --cached + .gitignore 三删）→ code-review-bot 五项复核全过（ls-files 仅剩夹具 / check-ignore 实证夹具无需白名单（单层 glob 不匹配二级路径）/ 夹具四件在库 / 工作区三 bin 保留 / **可重建性实证：三生成器重跑 blob 逐字节一致** e8824ba4/c8057b32/67e089ae）→ 文档同步 `2036725`（§7/§8 三处改「均不入库，由生成器重建」）+ `c5e3792`（§1 交付物表补注）→ **json 补齐 `bbe1db8`**（两个 manifest json 同口径移出，code-review-bot 四项复核全过：ls-files 仅剩夹具 bin / .gitignore 21-22 反选生效 / 工作区 json 保留 6390B+1647B / 可重建实证重跑前后 blob 一致 e595d07a/ff15eb5a）。HEAD = origin = `bbe1db8`。
- **指纹定性补记（office-review-bot 复算终裁）**：`a6ff3079…` = 唯一有效指纹（md「连续：」9 条 as-is join == 脚本 stdout CONT join，双向核验）；`556cb263…` = **939efe1 重排帧序前中间态正文的小写归一化产物，作废勿用**；`cdbd0981…` = 89423fc 前大端版，作废勿用。
- **v2.3.3 收口登记（office-review-bot 复核闸门）**：南网 BPLC 心跳位图基线制案全案闭合——四方一致 0-based（TEI=8i+j），解码器零改动，wire/文档/仓库/release/安装版五处 Lua 同步；缺口终稿：已关 4 项（安装版 Lua / linktype 149-152 定性 / ~~C++ 心跳位图~~ 实为已实现 :1931-1959（假缺口更正）/ release 手动同步（用户裁决））；未关 2 项（HDC2.0 实网抓包需真机 / P3 帧型用户已定暂不做）。归因：4 处定案收口 = code-review-bot；修 4 处 = office-bot（`939efe1`/`9bde235`）；bin 口径执行 = git-release-bot（`88296eb`）。
- **UI i18n 线（已关闭，2026-10-24）**：48 个未注册中文串修补完成——`53c04ee`（mainwindow.cpp +3 状态栏 2 处，git-release-bot 提交推送）。**验收（code-review-bot，基准 `4091ea8`）**：独立审计重扫未注册中文 = **0**（扫描口径必须写死为「三形式全扫」：trl::L 去重 594 ∪ en_dict 46 ∪ register_en 699，含 trl:: 前缀/裸调用/跨行三种注册形式——此前 48/15 等虚报均因口径漏 en_dict、裸 register_en、跨行写法）；抽检占位符 0 缺陷 / & 助记符 0 缺失 / Title Case 通过；编译 -Wall -Wextra 0 warning（git-release-bot）。协议层 100% 覆盖（cc82cd7→36705b6）+ UI 层本轮补齐 = **全项目 trl::L 中英文全覆盖完成**。