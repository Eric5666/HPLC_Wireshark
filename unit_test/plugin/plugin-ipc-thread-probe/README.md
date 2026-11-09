# plugin-ipc-thread-probe

`PluginManager` 跨线程 IPC 回归探针（H6）。真实启动 `bplc-plugin-host` 子进程加载
`src/plugin/examples/lua_echo` 与 `lua_graphics`：

1. worker 线程连续 1500 次 `parse_via_plugin`，GUI 线程同时空跑事件循环；
2. worker 线程对 lua-graphics 连续 3000 次解析，GUI 线程同时对**同一连接**反复 `send_graphics_event`；
3. `stop_all()` 之后的迟到请求必须立即失败返回。

要求全部请求拿到响应、插件不被禁用、不出现 `QSocketNotifier ... another thread` 告警。
修复前：阶段 1 为 0/1500（首个响应被 GUI 线程读走 → 5 s 超时 → 插件被禁用），阶段 2 卡死。

## 构建与运行

```
QT_ROOT=/path/to/Qt/6.11.3/gcc_64 bash build.sh
QT_QPA_PLATFORM=offscreen ./build/plugin_ipc_thread_probe/plugin_ipc_thread_probe \
    --host /path/to/bplc-plugin-host     # 宿主须与探针同目录,--host 会复制过来
```

预期：`RESULT: ALL PASS (0 failures)`，exit 0。
