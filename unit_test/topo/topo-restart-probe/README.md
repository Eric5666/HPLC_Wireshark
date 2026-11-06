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
