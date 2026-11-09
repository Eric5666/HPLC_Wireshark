# BPLC STA Monitor

BPLC/HRF(HPLC) 协议 STA 报文监控上位机(Windows,Qt 6 / C++17)。

原为 Python 版 `BPLCMonitor`,本项目为 Qt6/C++ 重写版:解析 STA 固件经调试串口
输出的 `0x3C … 0x3E` 封装帧,并以字段树 + 十六进制字节联动高亮展示各层协议
结构。

## 📋 编码风格规范（必读）

**任何改动前请先读 [docs/CODING_STYLE.md](docs/CODING_STYLE.md)** —— 其中规定了：

**命名**
- **函数 `snake_case`**（`get_bits` / `tree_add_bit_field`；Qt 虚函数除外）
- **常量 `k` + PascalCase**（`kAppVersion` / `kLiteStaSlotSpecN`）
- **结构体字段 `snake_case`，无 `m_` 前缀**；**QObject 成员 `m_` + `snake_case`**
- **宏全大写 + 下划线**，能用 `constexpr` 就不用宏
- **禁匈牙利前缀 / 拼音 / 单字母**（`i`/`j`/`k` 循环变量除外）
- **协议字段名沿用协议原文**（`PBNum`→`pb_num`、`TMI`→`tmi`、`TEI`→`tei`）

**文案**
- **英文文案必须 Title Case**（`Empty Frame` 不是 `empty frame`；64 条单位后缀例外）
- **每个用户可见字符串必须 `register_en` 中英配对**

**协议**
- **协议相关注释必须写表号**
- **协议字段含义必须硬编码**（禁止只写「见表N」）
- **位域坐标以原始 PDF 为准**（MinerU 转的 md 会摊平 rowspan，不可直接下结论）
- **位域布局禁类推**（同一 bit 在不同帧类型下含义可不同）

**数据/显示**
- **CRC 显示三态**（`N/A` 未校验 / `OK` 通过 / `FAIL` 失败）
- **新增字段必须进 block_version 序列化**

自查脚本：`python tools/check_title_case.py`（扫全项目英文文案合规性）

## 使用说明书 / User Manual

- [中文使用说明书](docs/USER_MANUAL_zh-CN.md)
- [English User Manual](docs/USER_MANUAL_en.md)

## 功能特性

- **四类帧解析**:SOF(数据)、BEACON、ACK、COORD,含 FCH 位域逐字段拆分、
  FCH CRC24 / PB CRC24 / MSDU CRC32 / BEACON 载荷 CRC 校验与 OK/FAIL 显示
- **多 PB 块重组**:支持分片 MSDU 跨多物理块(PB)重组,树中逐块展示
  `PB Header / PB Body(+Padding) / PB CRC24`,字段可点选高亮到原始字节
- **MSDU 消息解析**:标准头 / 简头 MSDU_BASE,MMe 头(MMType 2B + RSV 2B,
  实测 16bit 宽)、8 类 MMe 消息 + APP EventPacket 事件上报,含
  DiscoveryNodeList(位图 TEI + 发现计数)、UpRouteEntryList(路由类型含义)、
  SuccessRateReport、Beacon Load(STA/PCO/CCO 信标载荷)等字段级展示
- **字段语义注解**:MSDUType / SendType / 路由类型 / Link ID / 报文优先级等
  枚举中文含义,周期/超时(s/ms)、信道质量(dB)、成功率(%)等单位齐全,
  保留字段按协议补全并标注位宽
- **帧列表**:`# | Time | Delta | Source | Destination | Protocol | Frame Type |
  MSDU Type | MSDU Seq | Length | Info`,支持表达式过滤(协议/类型/源目地址)
- **数据来源**:串口捕获或离线日志/二进制回放(log 行 `isRF+MPDU` 与
  `0x3C…0x3E` bin 两种)
- **界面语言**:中文 / English,默认跟随系统语言;`设置` 对话框可选语言
  (动态文本立即生效,窗口框架重启后完全生效)
- **界面主题**:深色(QDarkStyleSheet,默认)/ 浅色,`设置` 对话框即切即生效;
  主题资源在 `src/app/qdarkstyle/`(MIT,见其 LICENSE.rst)
- **双协议解析**:国网 GW_2022 与南网 NW_2021 双协议栈,`设置`/`开始` 对话框
  下拉切换,`config.ini` 的 `[general] protocol` 持久化;字段树、枚举、数值
  解释随协议整体切换
- **TOPO 拓扑窗口**:独立窗口(工具栏 `拓扑` 按钮),按 NID 动态绘制 CCO/STA
  树形拓扑,四态图标(CCO 路由器/STA 在线/入网中/离线),节点三行标签(标题/
  MAC/接入方式 载波·RF),拖拽平移/滚轮缩放,悬浮显示上下行通讯成功率;
  右侧路由变更记录表 + TEI→MAC 映射表,约 200ms 节流刷新。NID 下拉框显示
  CCO MAC 地址与该网络首次识别时间(帧时间戳,区分同 MAC 新旧网络)。
  拓扑事件来源(国网/南网各自独立解析,仅成功结果更新拓扑):
  关联请求/关联确认/关联指示(南网)/关联汇总指示/发现节点列表/
  代理变更确认/批量代理变更确认/离线指示/延迟离线指示(南网,直接按离线标)/
  CCO 重启警告(发现列表重启次数变化)/STA 重启警告(关联请求重启次数变化)
- **TOPO 历史回放调试**:点击帧列表任意历史帧,TOPO 路由状态冻结并重放
  到该帧(图/路由变更表/TEI→MAC 表均为该时刻快照),顶部显示
  `历史回放 @ #帧号`;点击最新帧或 `回到实时` 按钮恢复实时跟随。
  **双击任意帧**(含最新帧)强制进入历史追溯并冻结在该帧,不再跟随实时。
  TOPO 底部路由变更表首列为 **序号**(对应主界面帧列表的帧号),
  双击表中某行直接追溯到该行对应的帧,主界面帧列表同步选中并居中到该帧
- **CSV 导出 / 拖放导入**:报文列表导出 CSV(本地编码,Excel 直接打开);
  拖放 `.bin`/裸 hex 文件到窗口直接导入回放
- **两行时间差**:帧列表选中两行,状态栏中间显示两帧时间差(NTB 优先,
  偏差大时降级本地时间)
- **行颜色分系**:管理消息(MMe)暖色、应用数据(APP)冷色、COORD 紫色;
  红色仅保留异常报文(ACK 校验失败 / APP NACK)
- **崩溃转储**:崩溃时自动生成 minidump(`*.dmp`)到 exe 同级 `crashpad_db/` 下;
  默认 crashpad 后端,`config.ini` `[crash] dsn` 填 Sentry DSN 后崩溃自动上报,
  不填只本地落盘;`--self-crash-test` 触发确定性崩溃自测,`symbolize.sh`
  符号化定位到崩溃函数名与源码行

## 显示过滤器

帧列表上方的过滤器输入框支持多条件表达式,语法如下:

- **`&`** → 与(AND):左右条件须同时满足;
- **`|`** → 或(OR):任一满足即通过;
- **优先级** `&` 高于 `|`(先按 `|` 分组、组内按 `&` 全命中)。例:
  `a & b | c` 等价 `(a 且 b) 或 c`;暂不支持括号嵌套。

可匹配的关键字(子串匹配,不区分大小写):

| 内容 | 写法 | 示例 |
|------|------|------|
| 帧类型(精确) | `beacon` `sof` `ack` `coord` `search` `switch` | `sof` |
| NetID | `cda1d5` 或 `0xcda1d5` | `cda1d5` |
| 源 / 目的 | `cco`、`sta-N`、`broadcast` | `sta-2` |
| 媒介 | `hplc` / `hrf` | `hplc` |
| 帧索引 | 十进制序号 | `42` |
| MSDU 概要 | MMe / 事件报文文本 | `assoc` |

示例:

```
beacon & cda1d5        仅 NetID cda1d5 的信标帧
sof & sta-2 | ack      (sof 且源/目含 sta-2) 或所有 ack
coord & 0xcda1d5       指定网络的协调帧
hplc & beacon          HPLC 信标(排除 HRF)
```

## 环境与构建

| 组件   | 版本 |
|--------|------|
| Qt     | 6.11.3(mingw_64) |
| 编译器 | MinGW 13.1.0 |
| 构建   | qmake + mingw32-make(非 shadow 构建) |

```bash
export PATH="/c/Qt/Tools/mingw1310_64/bin:/c/Qt/6.11.3/mingw_64/bin:$PATH"
qmake BPLC_STA_Monitor.pro
mingw32-make -j4
# 产物:release/BPLC_STA_Monitor.exe
```

> 注:工程代码采用 clangd/LSP 时对 Qt 头会有假阳性报错,以本机
> mingw32-make 编译结果为准。

## 使用

1. **串口模式**:工具栏选择 COM 口与波特率后开始捕获(停止/暂停/清空)
2. **回放模式**:打开 log/bin 回放文件离线分析;`samples/log2bin.py` 可把
   Python 上位机 log(hex 行)转成 bin
3. 点帧列表行 → 上方协议字段树 → 点字段行 → 下方十六进制区对应字节高亮;
   多 PB 报文每块 Header/Body/CRC24 均逐块可点
4. **检查更新**:菜单 `帮助 → 检查更新`,更新清单地址见
   `config.ini` 的 `app/update_url`(默认指向 GitHub
   `aron566/HPLC_Wireshark` 仓库 `main` 分支的 `update.json`,当前版本 2.0.0)。
   检查前会按出口 IP 区域自动选路:中国 IP 时从 `app/mirror_list`
   镜像前缀中探活选第一个可用者,清单与安装包下载同走该代理,探活
   失败自动回退直连;`app/mirror_mode` 可设 `auto`(默认)/
   `native`/`proxy`,详见用户手册 §9.1
5. **配置文件 `config.ini`**(exe 同目录,首次启动自动生成带注释模板):
   更新检查地址、语言、串口参数、过滤条件等均可在其中修改(也可在
   `开始` 对话框修改串口/语言/主题——自动写回)。删除该文件后下次启动
   重建默认配置。

## 帧封装格式(串口 0x3C/0x3E 与回放 .bin)

监控器对串口/设备输入与回放文件采用同一套帧封装,由
`src/io/serialreader.cpp`(读取/反转义)与 `src/io/playbackwriter.h`(导出)实现。

### 设置指令(串口下行:上位机 → 设备)

上位机向设备下发协议/频段/波特率/无线信道等配置,与数据帧同用 0x3C/0x3E 哨兵封装:

```
3C 80 [协议] [频段] 03 [波特率] [无线信道] [无线option] 3E
```

| 字段 | 取值 | 说明 |
|---|---|---|
| `0x3C` | 固定 | 起始哨兵 |
| `0x80` | 固定 | 设置指令字(`0x80` = 设置) |
| `[协议]` | `01`=南网 / `0`=国网 | 网络协议 |
| `[频段]` | `0`-`3` | 载波频段(示例 `00`=频段 0) |
| `03` | 固定 `03` | 波特率变更标志(仅用于国网) |
| `[波特率]` | `0`=115200 / `1`=256000 / `2`=460800 / `3`=1500000 | 波特率档位 |
| `[无线信道]` | 如 `01` | 无线信道号 |
| `[无线option]` | `0`-`3` | 无线 option |
| `0x3E` | 固定 | 结束哨兵 |

示例 — 南网、频段 0、波特率 1500000、无线信道 1、option 2:

```
3C 80 01 00 03 03 01 02 3E
```

#### 跟随 TEI / 跟随 NID 设置指令(现场常用)

现场让设备锁定目标站点的 TEI 或网络 NID 时使用,同样走 0x3C/0x3E 哨兵封装
(下面四条为**抓包实录**,字节均未触发 0x3D 转义):

| 功能 | 指令 |
|---|---|
| 开启跟随 TEI | `3C 06 01 01 00 00 93 03 3E` |
| 关闭跟随 TEI | `3C 06 00 01 00 00 93 03 3E` |
| 开启跟随 NID | `3C 05 01 0E 00 00 93 03 3E` |
| 不跟随 NID | `3C 05 00 00 00 00 93 03 3E` |

字节剖面(以「开启跟随 TEI」为例):

| 偏移 | 取值 | 说明 |
|---|---|---|
| 0 | `3C` | 起始哨兵(封装层,与固件功能码 `0x3C` 无关) |
| 1 | `06` / `05` | 命令字:`06`=跟随 TEI、`05`=跟随 NID |
| 2 | `01` / `00` | 使能:`01`=开启跟随、`00`=关闭/不跟随 |
| 3 | TEI 或 NID | 目标值:跟随 TEI 例 `01`、跟随 NID 例 `0E` |
| 4 | `00` | 无线信道(示例 00,按现场改) |
| 5 | `00` | 无线 option(示例 00,按现场改) |
| 6-7 | `93 03` | **固定尾**,四条指令完全一致;具体含义未在文档/固件中确认,勿擅改 |
| 8 | `3E` | 结束哨兵 |

> **注意两处不对称(按抓包原样记录,勿"顺手对齐")**
>
> - 关闭跟随 TEI 时第 3 字节仍为 `01`(与开启相同);而不跟随 NID 时第 3 字节为 `00`
> - 跟随 TEI 用命令字 `06`、跟随 NID 用命令字 `05`,两者不是同一命令的开关位
>
> 本小节仅记录现场下发报文格式,不追固件实现;若与后续固件版本不符,以实测为准。

> **⚠️ 0x3C 语义区分（排查时勿混淆）**
>
> 本指令的 `0x3C` 是**上位机串口封装层的帧起始哨兵**，与设备固件 698 帧里的
> `0x3C`（`pdata[10]` 位置的「串口波特率」功能码）**毫无关系** —— 两者只是字节值巧合相同。
> 同理 `0x3E` 在本封装是结束哨兵，在固件里是「查询发射功率」功能码。
>
> 另：本条指令目前仅在本文件约定（上位机不发送、固件未实现该解析）；
> 若后续落地实现或存在第三方工具发送，须统一采用 `0x80` 作设置指令字。

### 帧边界与转义

```
串口/文件帧: 0x3C <数据> 0x3E
```

- 以 `0x3C` 起始、`0x3E` 结束,读取端按这两个哨兵切帧
- 数据内的保留字符用 **0x3D 转义**:`0x3D` + `(0xFF ^ 原字节)`

| 原字节 | 转义后 | 反转义规则 |
|--------|--------|-----------|
| 0x3C   | `0x3D 0xC3` | 0x3D 后一字节 `0xFF - b` 还原 |
| 0x3E   | `0x3D 0xC1` | 同上 |
| 0x3D   | `0x3D 0xC2` | 同上 |

### 帧内数据布局(实时串口帧)

反转义后的数据(去掉 0x3C/0x3E)为:

```
[dlen 2B LE][ts 4B LE][phr_mcs 1B][option 1B][channel 1B][isRF 1B][MPDU...]
  offset 0-1     2-5        6           7            8          9      10..
```

| 字段 | 长度 | 含义 |
|------|------|------|
| dlen | 2B LE | 数据长度,见下方说明 |
| ts   | 4B LE | 时间戳(固件计数/ms;BEACON Info 列展示) |
| phr_mcs | 1B | 物理层 MCS/调制(HRF) |
| option | 1B | 物理层选项 |
| channel | 1B | 信道(HRF 信道号 / PLC 频段) |
| isRF | 1B | 0=PLC 载波,非 0=HRF 无线(media_id) |
| MPDU | 变长 | 完整 MPDU:MPDU_BASE(FCH 16B + PB...)或 BEACON/ACK/COORD |

**dlen 数据长度字段**(2B 小端,位于反转义后偏移 0-1):
- **定义**:从 `phr_mcs` 字段(偏移 6)到帧末(MPDU 结束)的字节数,
  即 `物理元数据 4B(phr_mcs/option/channel/isRF)+ MPDU 长度`;
  等价于 `dlen = MPDU 长 + 4`(实测固件帧即此值,如 152B MPDU → dlen=156)。
- **范围约定**:`dlen` **不含自身与 ts 字段**,也不含 `0x3C`/`0x3E`
  哨兵,且按**反转义后**的字节数计(转义展开的 `0x3D xx` 不计入)。
- **校验**:监控器读取端**不校验** dlen——切帧只依赖 `0x3C`/`0x3E`
  哨兵;因此该字段主要供对端/日志工具参考。程序导出回放 bin 时按
  同一规则填写(`MPDU 长 + 4`),与固件帧一致。

固件侧输出示例(单块 SOF 152B MPDU):`0x3C` + [dlen=0x9C 0x00] + [ts 4B] +
[phr] [option] [channel] [isRF] + [MPDU 152B] + `0x3E`(0x9C00 = 156 =
152+4)。

### 回放 .bin 文件格式

导出(菜单 `捕获 → 导出...`)与回放使用**实时串口原始帧(raw_wire)**:
文件**头部先写一次 8 字节 BCD 时间标注**(首帧本地时刻,独立于帧、不参与
切帧),随后各帧 = `0x3C` + 转义(data) + `0x3E`,data = `[dlen 2B][ts 4B]
[phr_mcs][option][channel][isRF][MPDU]`(与实时捕获**逐字节一致**,无任何
逐帧附加值):

```
[BCD 时间标注 8B](仅文件一次)
0x3C [dlen 2B][ts 4B][phr_mcs][option][channel][isRF][MPDU] 0x3E   ← 帧1
0x3C ... 0x3E                                                    ← 帧2
…
```

**时间**:帧内 NTB 为 **u32,40 ns/tick(25 MHz),约 171 s 回绕**。时间轴按 NTB 差
推进:首帧(或每段)frame_time = 其前 8B BCD 标注时刻,后续帧 = 上一帧
frame_time + (本帧 NTB − 上一帧 NTB)×40 ns。**帧间 NTB 差超出合理范围
(≤60 s,长时间无报文/跨 u32 回绕)时,导出端在此帧前再写入一次 8B BCD
标注开启新段**;导入端支持文件中出现**多个 8B 标注**(帧间/头部均可),
断段后首帧用新标注、丢弃上一帧 NTB。

BCD 时间标签布局(本地时间,与解码器 `has_time_tag` 头同构):

| 字节 | 内容 | 取值(BCD) |
|------|------|-----------|
| 0 | 年-2000 | 00-99 |
| 1 | 月 | 01-12 |
| 2 | 日 | 01-31 |
| 3 | 时 | 00-23 |
| 4 | 分 | 00-59 |
| 5 | 秒 | 00-59 |
| 6 | 毫秒百位 | 0-9 |
| 7 | 毫秒低两位 | 00-99 |

回放时 `serialreader` 用 `looks_like_bcd_time()` **自动识别**该字段:带时间
标签的 bin 恢复每帧原始捕获时刻(Time 列);无该字段的旧 bin 自动回退本地
时间,无需手动配置。文件回放 Delta 一律为 **epoch ms 差**(文件时间戳精度
毫秒)。串口实时帧不含 BCD 标签,帧 ts 为设备 NTB tick:同网络(网号一致且
非 0,即已入网)帧间 Delta 用 tick 差(40 µs 分辨);未入网/跨网络自动回退
本地接收毫秒差。

### 裸 hex 数据(raw 模式)

`RawHex` 模式与「导出为裸 hex 文本」使用**同一裸数据格式**:纯 hex 文本,
每行一**完整 0x3C 原始帧**(与串口/回放 bin 同构,含 0x3C/0x3E 哨兵与
0x3D 转义),行分隔即帧边界(支持 `0x01 0xd5 …` 与 `01 d5 …` 写法);
文件**首行为显式首帧本地时间戳** `TIME: yyyy-MM-dd HH:mm:ss.zzz`(首次
本地时间戳机制),随后每行一帧:

```
[0x3C][esc(data)][0x3E]
data = [dlen 2B LE][ts 4B LE][phr_mcs 1B][option 1B][channel 1B][isRF 1B][MPDU...]
```

| 字段 | 字节 | 说明 |
|------|------|------|
| 0x3C / 0x3E | 首位/末位 | 帧哨兵(0x3D 按 0x3D+补码转义) |
| dlen | data 0-1 | MPDU+4(与固件一致,读取端不校验) |
| ts | data 2-5 | 帧捕获时刻,epoch ms 的**低 32 位**,小端序 |
| phr_mcs/option/channel/isRF | data 6-9 | 物理元数据 |
| MPDU | data 10.. | 纯 MPDU(CRC 校验,坏帧 dropped) |

**起始时间戳**:ts 是 epoch 低 32 位,回放时按当前时刻取最近候选还原
**原始捕获时刻**(±约 24.8 天窗口内正确),Time 列/Delta 以原始捕获时刻为
基准(Delta 精度=文件毫秒);仅支持本 0x3C 帧格式(旧版无哨兵行不再兼容,
直接忽略)。导出路径:菜单 `捕获 → 导出...` → 文件类型选「裸 hex 文本 (*.txt)」。

## 打包发布(安装包制作)

### 需要的工具软件

| 工具 | 用途 | 获取方式 |
|------|------|----------|
| Qt 6.11.3 mingw_64 + MinGW 13.1.0 | 编译(qmake/mingw32-make) | Qt 在线安装器 |
| `windeployqt`(Qt 自带) | 收集 Qt 运行库 DLL 到 release/ | 随 Qt 安装,`<Qt>\6.11.3\mingw_64\bin\windeployqt.exe` |
| NSIS 3.x | 安装包制作 | <https://nsis.sourceforge.io/Download>(便携 zip 解压到工程 `tools/nsis-3.09/` 即可,免安装) |
| Python 3 + Pillow | 重新生成应用图标(可选) | `pip install pillow` |
| GitHub 账号 + PAT | 发布 release / 上传安装包(仓库需公开才能被免鉴权拉取) | GitHub Settings → Developer settings |

> NSIS 脚本里含中文字符串,文件必须以 **UTF-8 BOM** 编码保存(否则报
> `Bad text encoding`)。脚本文件已被 `tools/` 目录加入 `.gitignore`,
> NSIS 便携包无需随仓库提交。

### 打包步骤

```bash
# 1.(可选)重新生成图标:icons/app.ico 与 icons/app.png
python scripts/make_icon.py

# 2.一键打包:全量构建 → windeployqt → NSIS 生成安装包
bash scripts/package.sh 1.3.0
#   产物:dist/BPLC_STA_Monitor_Setup_v1.3.0.exe

# 3.安装包验证(静默安装/升级,免 UAC)
dist/BPLC_STA_Monitor_Setup_v1.3.0.exe /S                 # 静默安装到默认目录
dist/BPLC_STA_Monitor_Setup_v1.3.0.exe /S /D=C:\my\dir    # 静默装到指定目录
"%LOCALAPPDATA%\Programs\BPLC_STA_Monitor\uninstall.exe" /S  # 静默卸载
```

安装器特性:per-user 安装(免 UAC)、升级前自动关闭运行中的程序、覆盖式更新
(旧的 exe/DLL 直接替换)、生成开始菜单/桌面快捷方式与卸载项。

### 发布与更新流程

1. **版本号**:改 `src/app/mainwindow.cpp` 顶部 `kAppVersion` 与
   `BPLC_STA_Monitor.pro` 的 `VERSION`(两者保持一致)
2. `bash scripts/package.sh <新版本>` 得到安装包
3. **推代码 + 建 release**:在 GitHub 仓库建 tag/release(如 `v1.3.0`),
   上传安装包为 release asset
4. **改 `update.json`**(仓库根,提交推送):
   `latest-version` 抬高新版本号,`download-url` 指向 release asset 地址
   (形如 `https://github.com/<owner>/<repo>/releases/download/<tag>/<文件名>.exe`),
   `sha256` 填该安装包的 `sha256sum`(必填:内置下载器缺少或不匹配时拒绝打开安装包)
5. 用户端:程序内 `帮助 → 检查更新` → 发现新版本 → 下载安装包 → 运行
   即覆盖安装(自动关闭旧进程,完成后即可用新版本)

## 更新清单格式

`update.json`(放仓库根或发布服务器):

```json
{
  "updates": {
    "windows": {
      "latest-version": "1.3.0",
      "download-url": "https://example.com/BPLC_STA_Monitor.exe",
      "sha256": "<安装包 sha256sum,64 位小写 hex>",
      "changelog": "修复 xxx",
      "mandatory-update": false
    }
  }
}
```

程序发现远端版本高于本地版本即弹窗询问下载。

## 目录结构

```
├── main.cpp                    入口(qMain)
├── src/
│   ├── common/                 帧/消息数据结构(含位域节点、高亮坐标)
│   ├── protocol/               帧解析器(BPLC MPDU/MSDU/BEACON)+ 统计
│   ├── io/                     串口读取与帧分发
│   ├── ui/                     帧列表模型、协议字段树、十六进制视图
│   ├── app/                    主窗口、配置持久化
│   └── updater/                QSimpleUpdater(第三方,MIT)
├── icons/                      应用图标(app.ico / app.png)
├── scripts/                    打包与辅助脚本(package.sh / installer.nsi / make_icon.py)
├── dist/                       安装包产物(本地,不入库)
├── samples/                    回放转换/校验脚本、无头回归测试
└── BPLC_STA_Monitor.pro
```

## 第三方组件

- **QSimpleUpdater**(`src/updater/`,MIT License):Qt6 兼容的软件更新检查/
  下载库,来自 <https://github.com/alex-spataru/QSimpleUpdater>;许可副本
  见 `src/updater/LICENSE.md`,上游文件保持原样未改动。

## 许可

本仓库代码以 **Apache License 2.0** 授权,完整条款见根目录
[LICENSE](LICENSE)(http://www.apache.org/licenses/LICENSE-2.0);
第三方组件按其各自许可(见上,如 QSimpleUpdater 为 MIT)。
