# topo-online-count-probe

TOPO 在网节点数 `TopoState::online_counts()` 的探针（用户 2026-11-06 定稿口径）。

```bash
./build.sh
./build/online_count_probe   # 打印 ok/FAIL 行，exit 0 为通过
```

## 口径（锁定，不可更改）

主数 `online` 仅统计 `status == Online` 的 STA：不含 CCO（TEI 固定为 1，
`kTeiCco`）、不含入网中（`OnlineGoing` / `pending`）、不含离线；入网中和
离线另行给出，窗口显示 `在网节点：N（入网中 X / 离线 Y）`。TEI 复用等
异常按 TEI 数计，不去重、不扣减（与拓扑图图标数一致）。

## 用例

| 用例 | 测什么 |
|---|---|
| T1 | 空状态全 0 |
| T2 | 只有 CCO 时主数仍为 0 |
| T3 | 关联请求（TEI 未分配）→ `pending` 计入网中 |
| T4 | 关联请求（TEI 已知）→ `nodes` 计入网中 |
| T5 | 关联确认晋升在线（`pending` 移除，不重复计） |
| T6 | 两 STA 在线 + CCO 不计 |
| T7 | 离网指示 → 在线减 1、离线加 1 |
| T8 | 切 NID 不串数（两 `TopoState` 实例，同 MAC/TEI 各自独立） |
| T9 | 历史回放冻结（快照拷贝后 live 再演进，快照计数不变） |
| T10 | TEI 复用异常按 TEI 数计（同一 MAC 先后占两个在线 TEI，主数计 2） |
| T11 | `has_topology_content()` 边界：空状态 false（窗口显示 —）、首帧后 true（窗口显示数字） |

源文件按 `#include` 分链接集：本探针只链 `topo_state.cpp`（+ `i18n.cpp`、
QsLog），不链 `topo_window.cpp`（窗口计数标签的刷新逻辑与 `view_states()`
的回放口径由 `rebuild_all()` → `update_count_label()` 保证，与探针 T9
的快照语义一致）。
