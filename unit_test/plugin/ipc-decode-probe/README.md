# ipc-decode-probe

插件 IPC 反序列化防护回归探针（审查 M2 + Qt 容器计数 reserve）。插件宿主进程不可信，
它发来的 `ParseResponse` 在主程序 worker 线程里用 `plugin_serialization.cpp` 的 `operator>>` 解码。

修复前：

- `MsduFieldNode` / `DissectField` 递归无深度上限：1 MiB 帧里嵌套约 5 万层 ⇒ 栈溢出（SIGSEGV，ASan 报 stack-overflow）；
- 所有 `QVector`/`QList` 字段走 Qt 6.11 默认 `readArrayBasedContainer`，对流里读出的计数直接 `reserve(n)`：
  声明 `0xFFFFFFFD` 个元素 ⇒ `std::bad_alloc`（worker 线程未捕获 ⇒ 主程序 abort）或数 GB 分配；
- 主程序不看 `ds.status()`，截断/损坏响应照收（半棵树）。

修复后：所有容器自读（先读计数，按剩余字节 × 每元素最小线上字节校验，小步 reserve 后逐个 append），
字段树深度上限 64（同 `pser::kMaxFieldDepth`）、单棵树节点上限 10000，超限置 `ReadCorruptData`；
`PluginManager::parse_via_plugin` 在 `status() != Ok` 时视为协议错误，丢弃结果并停用插件
（状态 `protocol-error-disabled`）；异步渲染/事件响应损坏同样停用。线上布局不变（写端仍是 Qt 默认格式）。

用例：

1. 单元（每例 fork 子进程解码；非 ASan 构建子进程 `RLIMIT_AS=1 GiB`，让旧代码的巨额 reserve 以 `bad_alloc` 显形）：
   完整往返逐字段相等；64 层 / 10000 节点接受，65 层 / 10001 节点拒绝；1 MiB 内 5 万层嵌套拒绝；
   13 个容器计数改成 `0xFFFFFFFD` / `0x100000` 拒绝；`ParseFilter.nid_list` 计数；任意截断拒绝。
2. 端到端：探针把自己复制成 `bplc-plugin-host` 充当恶意宿主（对每个 ParseRequest 原样回插件目录里的
   `response.bin`），`PluginManager` 真实收包：合法响应照常；巨大计数 / 深嵌套 / 10001 节点 / 截断 ⇒
   parse 失败、无半棵树、插件停用、主程序不崩，其他插件不受影响。

```
bash build.sh                    # QT_ROOT=<Qt 前缀>
./build/ipc_decode_probe/ipc_decode_probe   # 期望 RESULT: ALL PASS (0 failures)
```

ASan 复现旧行为：`qmake ... CONFIG+=sanitizer CONFIG+=sanitize_address`，
`ASAN_OPTIONS=max_allocation_size_mb=2048` 下旧代码报 `allocation-size-too-big`（含主程序 QThread）与 `stack-overflow`。
CI：`unit_test/ci/probe_suite.sh plugin/ipc-decode-probe`（protocol-regression.yml runtime-probes-linux）。
