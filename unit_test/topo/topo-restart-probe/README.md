# topo-restart-probe（原名 topo_restart_probe）

TopoState 相关探针合集，一次构建出 12 个二进制：

```
./build.sh
./build/<name>   # 每个程序无参运行，打印 ok/PASS 行，exit 0 为通过
```

| 程序 | 测什么 |
|---|---|
| anomaly_probe | 同一在线 MAC/TEI 冲突、重启次数往返、双链路计数不一致 |
| cpc37_probe | NW_2026 0x0037 link_type 1bit（0x03 → 1）与树节点 |
| cpc_auth_probe | ChangeProxyCnf 权威锁定（弱路径 0xFF → 成功确认锁定） |
| diversity_probe | GW_2026 分集拷贝新表（旧表仅 0/2/6/8 四模式一致） |
| dual_probe | 双模认定（无线链路 / RF 帧 → 双模） |
| m2_probe | 重启检测 sender_mac 回退（打印 CCO 介质状态行，exit 0） |
| m2m7_probe | 非权威 kind 不写 link_type，权威 kind 写 + 锁定 |
| m6beacon_probe | GW_2026 信标载波 TMI 门（2 通过 / 15 拒收） |
| main_probe | TopoState 重启检测探针本体（B3 中继描述用发送方 MAC） |
| model_probe | 包列表模型 MAC 易 TEI 后反查（需 QtConcurrent） |
| module_probe | 关联请求 module_type 双模认定与重关联保留 |
| pb0_gate_probe | NW_2021 PB 门（静默，exit 0） |

源文件按 `#include` 分链接集：topo_state 系只链 `topo_state.cpp`，
cpc37 链 NW_2026/NW_2021 MSDU 解析器，diversity 只用
`gw_2026_pb_table.h`（inline，无额外链接），m6beacon 链 GW_2026 信标解析器，
model 链 `packetlistmodel.cpp`，pb0_gate 链 NW_2021 全组。

## 判定标准（示例）

下例均与探针断言一致（NID 0x0E；MAC 显示为低字节在前的小写冒号分隔，
如 MAC `0x001122334455` 显示为 `55:44:33:22:11:00`）。

### 1. NidConflict 异常显示（D17u）

第 1 帧 CCO（MAC `55:44:33:22:11:00`）重启计数 3 只建基线，不报重启；
第 2 帧第二台 CCO（MAC `66:55:44:33:22:11`）计数也是 3。异常/冲突页签多一行：

| 首次帧 | 类别 | TEI | MAC | 介质 | 次数 | 最近变化 | 最近帧 |
|---|---|---|---|---|---|---|---|
| 2 | 同一 NID 多 CCO MAC | - | 55:44:33:22:11:00→66:55:44:33:22:11 | - | 1 | 同一 NID 下出现不同 CCO MAC | 2 |

第三个 CCO MAC 出现则同一行次数变 2、MAC 列变“首个→最新”；多 NID 各占一行
（按工具栏 NID 切换查看）；双击首列跳首次冲突帧、双击其他列跳最近冲突帧。

### 2. CCO 基线按 MAC 独立（D17u-h）

同一 NID 下两台 CCO 各自 3→4 各报 1 条 CcoRestart，共 2 条，事件保留真实 MAC
与帧号；无 MAC 样本不借用单值 cco_mac 猜身份，只用 (NID,0) 占位键。

### 3. 离线复活（D29，B2 已定）

LeaveInd 后节点离线；普通业务数据帧（kind=Other，应用层 128 / IPv4 129）可复活；
AssocReq 不复活、只建入网中 pending；ChangeProxyReq 可复活。复活时在 topo 事件里
留一条记录：kind=证据帧的 kind，说明为“节点恢复在线（<原因词>）”（普通数据帧
复活记“节点恢复在线（普通数据帧）”，代理变更请求复活记“节点恢复在线（代理变更请求）”），
节点、帧号、时刻与发送方 MAC 与复活帧一致；只在离线→在线跃迁时记一条，已在线帧
不重复记。路由变更表里该行类型列显示帧 kind 名，变更说明列显示上述说明。

### 4. 先学后判（D26a，B3 已定）

同一 MAC 先 DiscoverList 学成 CCO（计数 2），再 AssocCnf 以 STA TEI=5 出现
（计数 8）时不报 CcoRestart 2→8，只记 1 条角色冲突；随后同 STA 计数 9 报
StaRestart 8→9。
