# unit_test/ — 站外探针归集

本目录收容历史上散落在仓库之外的探针/测试用例（2026-10-29 归集，
分支 `chore/unit-test-layout`）。归集只做**移动 + 构建脚本路径适配**，
不改探针源码逻辑（唯一的例外见“搬迁改动清单”：6 处纯路径字面量，
0 处逻辑改动）。

运行环境约定（全部用例通用）：

- Qt 用 `$HOME/qt/6.11.2/gcc_64`，libfix 用
  `$HOME/workspace/build_deps/libfix`（本机环境路径，不属于仓库相对路径）。
- 构建产物一律进各用例下的 `./build/`（shadow 构建，git-ignored），
  用例目录本身保持干净；不要把构建目录放 `/tmp`（512M tmpfs，链接会炸）。
- 运行 Qt 程序前设置：
  `QT_QPA_PLATFORM=offscreen LD_LIBRARY_PATH=$HOME/workspace/build_deps/libfix:$HOME/qt/6.11.2/gcc_64/lib`。
- 每个用例目录的构建命令均为 `./build.sh`（gw-learn-probe 为
  `./build_probe.sh`）；g++ 直编用例的构建脚本会现场用
  `$QT/libexec/moc` 生成 moc 文件，**绝不提交 `moc_*.cpp`**。

## 0. CI 与人工测试分区

从 `samples/` 迁入的可执行测试已经按用途分区：

- `unit_test/ci/`：GitHub Actions 直接执行的稳定回归门禁，必须可在干净环境中无交互构建和运行；详见 [`unit_test/ci/README.md`](ci/README.md)。
- `unit_test/manual/`：开发探针、问题复现和需要人工准备输入的测试，不作为 CI 门禁；详见 [`unit_test/manual/README.md`](manual/README.md)。

`samples/` 仅保留示例数据、格式转换工具和数据集生成脚本，不再放置 Qt/C++ 测试程序。

## 1. 分类规则

按**被测子系统**分一级目录；一个用例只属于一个主责分类，
跨子系统的情况在用例 README 与下表“目的”列注明。

- `topo/`：拓扑状态、拓扑窗口、拓扑事件相关的探针。
- `filter/`：主界面包列表过滤相关的探针。
- `protocol-gw/`：国网（GW_2022 / GW_2026）解析器、树、学习相关的探针。
- `protocol-nw/`：南网（NW_2021 / NW_2026）解析器、树、学习相关的探针。
- `frames/`：跨协议或与帧构造/批量解析本身相关的探针
  （帧构造器、跨四协议批量跑器）。
- `app/`：应用层工具（非协议解析）的探针。
- `storage/`：块序列化/存储格式的 golden 用例。

新用例放哪：看它主要测什么子系统，就进哪个一级目录；
目录名用小写连字符，尽量保留原探针名以便追溯
（如 `gw_topo_merge_probe` → `gw-topo-merge-probe`，
`frame_probe/variant` → `frame-probe-variant`，
`frame_probe/variant3` → `frame-probe-variant3`）；
跨子系统的放主责分类，并在 README 里注明另一侧。

## 2. 目录索引表

构建命令均在用例目录下执行；运行命令假设已设置上文的环境变量。

| 用例 | 目的 | 构建 | 运行 | 输入 | 预期结果（2026-10-29 实测） |
|---|---|---|---|---|---|
| topo/topo-pco-probe | 邻居明细弹窗 PCO 行加粗+琥珀色标记 | ./build.sh | ./build/pco_probe | 无（合成数据） | PASS 17/17，`RESULT: 0 failures`，exit 0 |
| topo/topo-nid-probe | NID 下拉 refresh/set_current_nid 逻辑的 Qt  standalone 复刻 | ./build.sh | ./build/probe/nid_probe | 无（合成数据） | `RESULT: ALL PASS`，exit 0。注意：它是独立复刻，不链接仓库源码；其与当前 `set_current_nid` 实现的保真度此前曾被标记需同步，见本用例 README |
| topo/topo-online-count-probe | TOPO 在网节点数 `TopoState::online_counts()`（仅 Online 的 STA，不含 CCO/入网中/离线） | ./build.sh | ./build/online_count_probe | 无（合成数据） | 11 组断言（T1–T11），`RESULT: ALL PASS`，exit 0。只链 `topo_state.cpp`，不链 `topo_window.cpp` |
| topo/topo-restart-probe | TopoState 重启检测、弱路径、双模认定等 12 个探针程序 | ./build.sh | ./build/\<probe\>（12 个，见本用例 README） | 无（合成数据） | 12/12 构建通过，运行 exit 0；其中 10 个打印 `ALL PASS`/`PROBE PASS`，`m2_probe` 打印 CCO 介质状态行，`pb0_gate_probe` 静默 |
| topo/topo-route-verify | NW_2026 拓扑路由扫描：对 MPDU 流逐帧打印 topo 事件 | ./build.sh | ./build/probe/topo_scan \<mpdus.bin\> [verbose_idx] | 长度前缀 MPDU 流；大文件 `mpdus.bin`（8.3M）未入库，见原位置 `~/workspace/topo-route-verify/mpdus.bin`；另有单帧 `user_frame_container.bin` / `user_frame_mpdu.bin`（已入库） | exit 0，stderr `scanned 45827 frames`（以原数据集实测） |
| filter/mac-filter-probe | 主界面 MAC 形状过滤 token 展开为 TEI 或 | ./build.sh | ./build/mac_filter_probe | 无（合成数据 + 模型内建映射表） | 特性已合入 main（合并提交 `12d1cbc`）：对 main 源码构建运行 **47/47，`RESULT: 0 failures`，exit 0**（合入前 main 为 28/47，缺特性所致） |
| filter/orig-src-probe | 聚合/多站点帧 Orig Src 多源列（显示格式、去重）与过滤（sta- 整词、MAC 模式、子串） | ./build.sh | ./build/orig_src_probe ../../protocol-gw/gw-topo-merge-probe/gw_topo_merge.bin | 复用 gw-topo-merge-probe 构造帧（不复制）+ 合成条目 | RESULT: ALL PASS，exit 0 |
| filter/info-crc-probe | Info 列 CRC 状态（截断全好不报 CRC OK，报 CRC 不完整） | ./build.sh | ./build/info_crc_probe | 无（合成条目） | RESULT: ALL PASS，exit 0 |
| protocol-gw/gw-topo-merge-probe | 多站点 GW 帧的 topo 事件合并语义（首个非 Other 事件获胜、pairs 全并、present=false） | ./build.sh | ./build/gw_topo_merge_probe gw_topo_merge.bin build/topo_merge_out.txt | 构造输入 `gw_topo_merge.bin`（927B，已入库）；再生脚本 `gw_topo_merge_craft.py` | `AGG frames=3 PASS=3 FAIL=0`，exit 0。每帧 6 项检查（首事件、pairs 全并、present=false、summary 空、extras 顺序、TopoState 全站点）；`fix/topo-events-list` 已合入 main（bf5918e），断言为 Shape J 新语义 |
| protocol-gw/gw-learn-probe | GW_2026 TEI↔MAC 学习（AssocCnf/Gather/发现/OFDMA/TDA） | ./build_probe.sh | ./build/gw_learn_probe crafted.bin build/out.txt | 构造输入 `crafted.bin`（1382B，已入库）；完整抓包 `gw_mpdus.bin`（39M）未入库，见原位置 `~/workspace/gw_learn_probe/gw_mpdus.bin`，再生脚本 `split_gw_capture.py`（路径仍指向原位置，见下） | exit 0，总计 `total=6 accepted=6 msdu_pairs=13`，`ofdma=1 tda=1 stations=4 gather=1 assoc_cnf=2 discover=1`，与归集前验证一致 |
| protocol-gw/gw-beacon-harness | GW_2022 信标解析 harness（合成信标帧 → 树节点断言） | ./build.sh | ./build/harness/gw_beacon_harness | 无（合成帧） | `RESULT: PASS`，exit 0 |
| protocol-gw/gw-beacon-harness-mg | 同上（_mg 变体） | ./build.sh | ./build/harness/gw_beacon_harness | 无（合成帧） | `RESULT: PASS`，exit 0。**注意 _mg 陷阱**：本目录的 `harness.pro` 编译的是**原版** `gw-beacon-harness/main.cpp`，本目录的 `main.cpp` 从不被编译；改断言必须改原版，见本用例 README |
| protocol-gw/gw-mcs-harness | GW MCS/信标字段 harness（树转储） | ./build.sh | ./build/harness/gw_mcs_harness | 无（合成帧） | exit 0，打印字段树（无显式 RESULT 行的转储型 harness） |
| protocol-gw/gw-rsv-harness | GW_2022 RF SOF 保留位原值保留验证 | ./build.sh | ./build/harness/gw_rsv_harness | 无（合成帧） | **exit 1，单用例 FAIL**：保留位本身正确（sym=427、ext=5、pb_size=72、无错误），但 `tmi` 读到 0 而非设置的 MCS 3。探针与当前解析器实现存在分歧，归集时未改逻辑，原样记录 |
| protocol-gw/gw2026-tree-probe | GW_2026 OFDMA/TDA 帧 → ProtocolTree 全节点打印 | ./build.sh | ./build/probe/gw2026_tree_probe \<mpdu.bin\> | 裸 MPDU；OFDMA/TDA 构造帧在 `../../frames/frame-probe/gw2026_ofdma_sim.bin`（440B）与 `gw2026_tda_sim.bin`（304B） | OFDMA 构造帧 accept=1，exit 0 |
| protocol-gw/gw-multi-crc-probe | GW_2026 OFDMA/TDA 多站逐站 CRC 进 mpdu.pb_crc_oks（直接调 assemble，全好/翻转站 0/站 1/双站、TDA） | ./build.sh | ./build/gw_multi_crc_probe/gw_multi_crc_probe | 无（全合成帧） | `RESULT: ALL PASS`，exit 0 |
| protocol-nw/learn-probe | NW_2026 TEI↔MAC 学习（级联/OFDMA/TEI 列表/Gather 等） | ./build.sh | ./build/learn_probe files crafted/*.bin（或 `scan <mpdus.bin>`，数据集不入库） | `crafted/` 下 5 个构造帧（已入库）；再生脚本 `craft_frames.py` | exit 0，stderr `scanned 5 frames`，打印 4 条 FRAME 行（`craft_ul_data.bin` 按探针的 interesting 规则不打印 FRAME 行，属探针设计而非失败） |
| protocol-nw/nw-trunc-pbcrc-probe | NW_2026 截断帧 pb_crc_ok 语义（定法 a：全声明块收到且通过才为 true） | ./build.sh | ./build/nw_trunc_pbcrc_probe/nw_trunc_pbcrc_probe | 无（全合成帧） | `RESULT: ALL PASS`，exit 0；未修复代码上截断 2 用例失败 |
| protocol-nw/nw-dlofdma-crc-probe | NW_2026 DL-OFDMA 站点 1+ 非聚合分支 PB CRC 门（好 CRC 学习、坏 CRC 不学习） | ./build.sh | ./build/nw_dlofdma_crc_probe/nw_dlofdma_crc_probe | 无（全合成帧） | `RESULT: ALL PASS`，exit 0。对应修复 fix/nw-dlofdma-pbcrc（9832d1b）→ fix/remove-parse-filter（11afa31） |
| protocol-nw/nw-ul-crc-probe | NW_2026 UL-OFDMA 类型 1 逐站 CRC 进 mpdu.pb_crc_oks（无 trigger 为空、UL 全好/翻转/聚合、DL-SACK） | ./build.sh | ./build/nw_ul_crc_probe/nw_ul_crc_probe | 无（全合成帧） | `RESULT: ALL PASS`，exit 0 |
| protocol-nw/nw2026-frame-test | NW_2026 帧解析（容器 + isRF 标志） | ./build.sh | ./build/probe/frame_test \<container\> \<isRF 0\|1\> | 本用例无自带输入；可用 `../../topo/topo-route-verify/user_frame_container.bin`（reader 容器格式） | 该容器 isRF=0 时 accept=1，exit 0 |
| protocol-nw/main-nw-probe | NW 帧批量探针（argv 文件列表） | ./build.sh | ./build/probe/main_nw_probe [文件…] | 外部文件（未入库）；无参运行 exit 0 静默 | 构建通过；无参 exit 0 静默；有意义的运行需外部抓包文件 |
| protocol-nw/main-nw-mme-probe | NW MME 系列探针（7 个 .pro：probe / audit / cnf / cnf_sf / ind_sf / req_sf / sof） | ./build.sh | ./build/\<name\>/\<target\>（7 个二进制，见构建目录） | 外部文件（未入库）；无参运行 exit 0 静默 | 7/7 构建通过；7 个二进制无参均 exit 0 静默。注意：4 个 .pro 共用 TARGET `probe_cnf`，靠各自 `build/<name>/` 子目录隔离，不冲突 |
| protocol-nw/nw-mcs-harness | NW MCS 字段 harness（树转储） | ./build.sh | ./build/harness/nw_mcs_harness | 无（合成帧） | exit 0，打印字段树（转储型，无显式 RESULT 行） |
| protocol-nw/nw-mcs-harness-mg | 同上（_mg 变体） | ./build.sh | ./build/harness/nw_mcs_harness | 无（合成帧） | exit 0，打印字段树。**_mg 陷阱同 gw-beacon-harness-mg**：编译的是原版 main.cpp |
| protocol-nw/nw-rf-harness | NW RF/PLC SOF harness（合成帧断言） | ./build.sh | ./build/harness/nw_rf_harness | 无（合成帧） | `SYNTH RESULT: PASS`，exit 0 |
| protocol-nw/nw-rf-harness-mg | 同上（_mg 变体） | ./build.sh | ./build/harness/nw_rf_harness | 无（合成帧） | `SYNTH RESULT: PASS`，exit 0。**_mg 陷阱同上** |
| protocol-nw/coord-probe | NW 协调（coord）字段探针 | ./build.sh | —（构建失败，无二进制） | 外部 `capture.txt`（未入库） | **构建失败**：探针读 `MpduInfo.coord_option`，当前仓库 `src/common/bplcframe.h` 该字段已为 `coord_duration`（“协调时隙占用时长 16-bit(ms)”）。属探针与仓库 API 漂移，归集时未改探针源码，原样记录 |
| protocol-nw/mg-probe | NW MSDU 解析探针（合成 0x9999/不支持版本帧 → 树转储） | ./build.sh | ./build/mg_probe/mg_probe | 无（合成帧） | 构建通过（经 3 处构建脚本补齐，见搬迁改动清单），exit 0，打印 MSDU 树 |
| protocol-nw/trunc-stats-probe | NW 截断/统计探针（3 个 .pro，共用 TARGET `trunc_stats_probe`） | ./build.sh | ./build/\<name\>/trunc_stats_probe [文件…] | 外部文件（未入库） | 3/3 构建通过；无参 + stdin 关闭时 exit 0 静默。注意：无参且 stdin 打开时，首个二进制会阻塞等待 stdin（实测挂起后 kill），无参运行请重定向 `</dev/null` |
| protocol-nw/frame-probe-variant | NW_2021 帧变体探针 | ./build.sh | —（构建失败，无二进制） | 帧 .bin（见 `frames/frame-probe/`） | **构建失败**：与 coord-probe 同因，`main.cpp:68` 读 `MpduInfo.coord_option`，现为 `coord_duration`。原样记录，未改源码 |
| protocol-nw/frame-probe-variant3 | NW_2021 MSDU 变体探针 | ./build.sh | ./build/probe/nw_msdu_probe \<帧.bin\> | 帧 .bin（见 `frames/frame-probe/`，如 `nw_frame_20261022.bin`） | 构建通过（经 qslog 构建脚本补齐），该帧 present=1，exit 0 |
| protocol-nw/nw2026-ul-probe | NW_2026 UL-OFDMA 三件套探针（trigger + UL 数据 + SACK） | ./build.sh | ./build/probe/nw2026_ul_probe \<trigger\> \<ul\> \<sack\> | `../../frames/frame-probe/nw2026_trigger.bin`（32B）、`nw2026_ul_ofdma_data.bin`（296B）、`nw2026_dl_sack.bin`（32B） | trigger 与 UL 数据均 accept=1，exit 0 |
| frames/frame-probe | NW_2021 帧探针 + GW/NW 构造帧生成脚本与输入 | ./build.sh | —（构建失败，无二进制） | 本目录 10 个小 .bin（已入库，见下表注）；生成脚本 `build_gw2026_ofdma_tda_sim.py`、`build_nw2026_ul_ofdma.py` | **构建失败**：与 coord-probe 同因，`main.cpp:67` 读 `MpduInfo.coord_option`，现为 `coord_duration`。原样记录，未改源码。注意：本目录的 .bin 仍是其他用例（gw2026-tree-probe、nw2026-ul-probe、nextgen-probe、frame-probe-variant3）的输入 |
| frames/nextgen-probe | 跨四协议批量跑器：对抓包逐帧跑指定解析器，统计接受/拒绝 | ./build.sh | ./build/probe/nextgen_probe \<nw2021\|nw2026\|gw2022\|gw2026\> \<抓包文件\> [detail] | 0x3C…0x3E 容器格式抓包；本用例无自带输入，可用 `../frame-probe/nw_frame_20261022.bin`（单帧容器） | 该单帧 nw2021：`total=1 accepted=1 sof=1 pb_crc_ok=1`，exit 0 |
| frames/nextgen-probe-verify | 同上（verify 变体；main.cpp 与 nextgen-probe 相同，.pro 不同） | ./build.sh | ./build/probe/nextgen_probe \<which\> \<抓包文件\> [detail] | 同上 | 以 `topo-route-verify/user_frame_container.bin`（reader 容器格式，非 0x3C 串口格式）运行：`total=0`——输入格式不匹配所致，不是探针失败；二进制本身与 nextgen-probe 同源已验证 |
| app/mirror-probe | UpdateMirrorResolver 探针：写 config.ini mirror_mode 再解析真实 update.json | ./build.sh | 在 `build/probe/` 目录下运行 `./mirror_probe [auto\|…]`；另有 `build/probe_fb/mirror_probe_fb`（fb 变体，见本用例 README） | 无（联网解析默认 update.json） | 构建通过；实测 `RESOLVED effective=https://raw.githubusercontent.com/aron566/HPLC_Wireshark/main/update.json prefix=(native)`，exit 0。注意：它把 `config.ini` 写到二进制同目录（即忽略的 `build/probe/` 内），不要在用例根目录运行；无网时 30 秒后 TIMEOUT exit 2 |
| storage/golden | PacketEntry 块序列化 golden：生成 4 档条目块并打印 sha256 | ./build.sh | 在 scratch 目录运行 `../golden/golden`（不要在用例根目录运行，以免覆盖已入库的 golden 文件） | 生成物 `v3_n1/n57/n250/n1000.bin`（已入库，系参考输出） | 构建通过，运行 exit 0，打印 4 行 sha256；但**再生字节与已入库文件全部不匹配**（330 vs 312、5802 vs 5514、24207 vs 22720、95505 vs 90080 字节，约每条目 +5 字节）——序列化格式自 golden 录制后已漂移，golden 已过期。已入库文件原样保留未覆盖；是否重录 golden 需另行决定，归集时不擅自覆盖 |

注：`frames/frame-probe/` 的 10 个 .bin 为
`gw2026_ofdma_sim.bin`（440B）、`gw2026_tda_sim.bin`（304B）、
`nw2026_dl_sack.bin`（32B）、`nw2026_trigger.bin`（32B）、
`nw2026_ul_ofdma_data.bin`（296B）、`nw_frame_20261021.bin`（548B）、
`nw_frame_20261022.bin`（544B）、`nw_frame_20261022_full.bin`（554B）、
`nw_frame_20261022b.bin`（558B）、`nw_frame_20261022c.bin`（244B）。

## 3. 排除规则与跳过清单

**什么不进仓库：**

- 构建产物：二进制、可执行文件、`.o`/`.a`/`.so`、生成的 `Makefile`、
  `moc_*.cpp`（构建时现场生成）。
- 单个文件超过 1MB（含抓包、数据集、扫描输出）。
- 已在 `src/` 内的测试（`src/common/tests/`、`src/plugin/tests/` 等）：
  它们接 `.pro` 构建，归集不动它们（见第 5 节分工）。
- 仅供调试的运行输出（`*_out.txt`、`RESULTS_*.md`、`parse_*.txt`、
  扫描 `.txt`、`.err`）与独立笔记 `.md`（用例自带的 README 除外）。

**被跳过的目录/文件及原因：**

- `~/workspace/topo-route-probe/`（248M）、`~/workspace/nw2026-test-4396cd6/`（191M）：
  完整仓库检出副本（非探针目录），其 `samples/` 下的类探针文件属于旧快照，
  不单独 cherry-pick。
- `~/workspace/hplc-*`（`hplc-main-latest`、`hplc-main-review`、`hplc-mh-fix`、
  `hplc-nextgen` 等）：检出副本，跳过。
- `~/workspace/build_*`、`crash-test-build`、`fix-1-4-build`、`gw-build`、
  `build_qt6112`、`build_deps`：纯构建产物或工具链，跳过。
- `~/workspace/topo-review/`：`compare.json` + `full.patch`，评审产物而非可运行探针。
- `~/workspace/plugin_test/`（`test_all_plugins.py`）：驱动冻结工作区
  `~/workspace/HPLC_Wireshark` 的 `bplc-plugin-host` 与插件示例，路径写死且需
  完整应用构建，无法重定向到仓库构建，跳过。
- `~/workspace/rf_frame_test/`（`user_rf_frame.bin`）：只有输入数据，无探针源码。
- `~/workspace/filter-analysis-20261010/`、`~/workspace/plugin-pkg-staging-20261011/`：
  分析输出 / 打包 staging，非探针。
- `~/workspace/EOL_CAN_Tool/`、`~/workspace/QtPluginFramework/`：其他项目仓库。
- `~/workspace/goals/`、`memory/`、`agents/`、`your_files/`、`user/`、
  `custom-skills/`、`custom-connectors/`：agent 基础设施或用户文件。
- `~/workspace` 根散文件：`abort_test.cpp`（自注“仓库外测试程序，不入库”）、
  `block_bench.cpp`（自注 throwaway benchmark，不入库）、
  `make_test_dumps.py`（目标 helper 不在仓库内）、`stress_switch.sh`
  （仅循环跑另一棵树的 `src/crash/tests/`，非独立用例）。
- 归集后新出现的探针目录（不在本次清点内，未移动，待父代理决定是否后续归集）：
  `~/workspace/pb0-risk-probe/`、`~/workspace/pb0-red-probe/`（NW_2021 截断修复
  线程的探针，修复已合入 main `1fe1cf9`）。
- 每个已移入用例的原目录里其余文件（编译产物、运行输出、生成 moc、大文件）
  全部原地保留，未删除任何目录，未 `rm -rf`。

**大文件留置清单（原位置 + 用途 + 再生方式）：**

| 原位置 | 大小 | 用途 | 再生方式 |
|---|---|---|---|
| `~/workspace/gw_learn_probe/gw_mpdus.bin` | 39M | GW_2026 提取 MPDU 数据集（gw-learn-probe 完整扫描输入） | `gw-learn-probe/split_gw_capture.py`（输入 `~/workspace/your_files/BPLC_20260914_105445.bin`，路径仍指向原位置，见下） |
| `~/workspace/gw_learn_probe/before_scan.txt`、`after_scan.txt` | 各 47M | gw-learn-probe 完整扫描输出 | 用 gw-learn-probe 对 `gw_mpdus.bin` 跑 scan 模式 |
| `~/workspace/topo-route-verify/mpdus.bin` | 8.3M | topo-route-verify 长度前缀 MPDU 流（45827 帧） | `topo-route-verify/extract.py`（输入 `~/workspace/user/files/TOPO_SPLC_20261027_095658.bin`，输出回原位置） |
| `~/workspace/topo-route-verify/frames_meta.json` | 4M | 上述数据集的帧元数据 | 同上 |
| `~/workspace/topo-route-verify/scan.tsv`、`frame45558_tree.txt` | 3.3M + 小 | 扫描输出 / 单帧树 | 用 topo-route-verify 重跑 |
| `~/workspace/learn_probe/` 内扫描输出（scan/masked/m2/topo `.txt`） | 0.2–3M 各 | learn-probe 完整扫描输出 | 用 learn-probe 对相应数据集跑 scan 模式 |
| 各原目录的二进制、`.o`、`build_before/`、`build_after/`、`pb0_build/` | 不等 | 旧构建产物 | 各用例 `./build.sh` 重建 |

**搬迁改动清单（构建脚本与路径字面量 only，探针逻辑 0 改动）：**

- 33 个 `.pro`：把死掉的 `~/workspace` 树根（`hplc-*`、`*review*` 等）
  换成 `$$PWD/../../..`（`mirror-probe/fb/probe_fb.pro` 因深一层用
  `$$PWD/../../../..`）；`_mg` 三个 harness 的 main 指向同级原版用例
  （`unit_test/protocol-*/<原版>/main.cpp`）；4 个 `.pro` 的 SOURCES
  曾残留旧子目录段（`gw2026_tree_probe/main.cpp` 等），已纠为 `main.cpp`。
- `mac-filter-probe/build.sh`、`topo-restart-probe/build.sh`：补
  `-I$QT/include/QtConcurrent`（`packetlistmodel.cpp` 的 `#include <QtConcurrent>` 否则编不过）。
- `mg-probe`、`nw-rf-harness`、`nw-rf-harness-mg`、`frame-probe-variant3`
  的 `.pro`：补 `3rdparty/qslog` 的 INCLUDEPATH + 5 个 qslog SOURCES +
  QsLog HEADERS（moc 用）。原因：当前仓库的 `nw_2021_msdu_parser.cpp`
  经 `src/common/parse_anomaly.h` 用到 QsLog，旧 `.pro` 没列这些依赖。
- `gw-topo-merge-probe/build.sh`、`gw-learn-probe/build_probe.sh`：仓库根默认
  为用例目录上三层，输出默认 `./build/`，moc 现场生成（不再引用旧
  `build_before/moc_*.cpp`）。
- 生成脚本输出路径（纯路径字面量，逻辑不动；不改则新位置运行会把文件
  写回旧目录）：`storage/golden/main.cpp` 的输出由绝对旧路径改为
  CWD 相对 `v3_n%1.bin`；`gw_topo_merge_craft.py`、
  `gw-learn-probe/gw_craft.py`、`learn-probe/craft_frames.py`、
  `build_gw2026_ofdma_tda_sim.py` 的输出改为脚本所在目录。
  故意**没改**的两处（输出本身超 1MB，改了就进仓库禁区）：
  `topo-route-verify/extract.py`、`gw-learn-probe/split_gw_capture.py`
  仍指向原位置数据集，见大文件留置清单。

## 4. 新增用例规范

- 目录：`unit_test/<一级分类>/<小写连字符名>/`，源码/脚本/小数据
  （单个 < 1MB）直接放用例根目录；生成脚本的输出若是小文件，放同目录。
- 构建脚本：每个用例必须有 `build.sh`（g++ 直编）或 `build.sh`
 （qmake wrapper，二者选一；gw-learn-probe 沿用 `build_probe.sh` 旧名）。
  仓库根用 `REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"`
  （`.pro` 内用 `$$PWD/../../..`），不要写死本机绝对路径。
  qmake 用例用 shadow 构建（`build/<pro-basename>/`），不要在用例根目录
  生成 Makefile/`.o`/二进制；g++ 用例把 moc 生成到 `./build/`。
- **`build.sh` 必须同时能在 Windows(git-bash) 与 Linux CI 上跑**（CI 见
  `.github/workflows/protocol-regression.yml` 的「… regression probes」步骤，
  它把 `$QT_ROOT/{bin,libexec,include,lib}` 软链到 `qmake6 -query` 的各路径后
  `bash build.sh`）。四条硬约定：
  1. **make**：`MAKE` → `make` → `mingw32-make`（Windows 只有后者）；
  2. **qmake**：`$QT/bin/` 下逐个探测 `qmake.exe` → `qmake` → `qmake6` →
     `qmake6.exe` → `qmake-qt6`。**Ubuntu/Debian 的 `QT_HOST_BINS` 里常常只有
     `qmake6`**，只试 `qmake` 会让 CI 直接挂；
  3. **moc**：`$QT/bin/moc.exe` → `$QT/bin/moc` → `$QT/libexec/moc` →
     `$QT/libexec/moc.exe`。**Debian/Ubuntu 的 moc 在 `libexec/`**，
     Windows 的在 `bin/`，两边都要试；
  4. **路径形式**：传给 g++/moc/qmake 的一律用原生形式（`C:/…`；
     MSYS 下用 `cygpath -m` 转换）。bash 习惯的 `/c/…` 会被原生程序**静默忽略**，
     表现为「找不到头文件」。
  Qt 查找顺序 `QT_ROOT` → `QT` → `C:/Qt/6.11.2/mingw_64` →
  `$HOME/qt/6.11.2/gcc_64`；Windows 下不链 `-lEGL -lGL` 与
  `$HOME/workspace/build_deps/libfix`（仅 Linux 需要）。
  **这 5 个已接入 CI 的用例是参考实现**：`protocol-common/pb-reorder-probe`、
  `protocol-common/pb-batch2-probe`、`filter/info-crc-probe`、
  `filter/orig-src-probe`、`filter/mac-filter-probe`。其余用例若将来接进 CI，
  须先按上述四条补齐探测，否则会在 CI 上因 `qmake6`/`libexec/moc` 命不中而失败。
- README 条目：主 README 索引表加一行（目的、构建、运行、输入、预期结果）；
  输入非 obvious（argv 形式、外部大文件、跨用例输入、特殊运行目录）的，
  在用例目录另放简短 README.md 说明。
- 大小/二进制规则：单个文件 > 1MB、二进制、可执行文件、`.o`/`.a`/`.so`、
  `moc_*.cpp`、运行输出，一律不提交；大输入留在原位置并在 README 写清
  路径与再生方法。
- 探针源码只改路径，不改逻辑；断言失败先记录（注明原因），不要为“让它变绿”
  改断言或被测行为；确需改探针逻辑的，另走正常修复流程。

## 5. 与 src 内测试的分工边界

- `src/` 内测试（`src/common/tests/`、`src/plugin/tests/` 等）是仓库的正式测试，
  接 `.pro` 构建、随主程序演进，原地不动；本目录不收容、不替代它们。
- `unit_test/` 是**历史探针的归档与复跑场**：它们来自具体问题排查
  （某次 review、某次修复验证），断言口径可能滞后于当前源码
  （如 coord-probe 的 `coord_option`、golden 的过期 sha、gw-rsv-harness 的
  tmi 分歧、mac-filter-probe 的未合入特性）——这种滞后本身就是信息，
  归集时原样保留并在上表注明，不为了“全绿”去改写历史断言。
- 新功能优先写 `src/` 内测试；只有“针对某次具体排查、希望长期保留复跑
  证据”的探针才进 `unit_test/`，并按第 4 节规范建目录。
