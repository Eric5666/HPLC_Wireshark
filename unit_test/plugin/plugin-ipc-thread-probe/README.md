# plugin-ipc-thread-probe

`PluginManager` 跨线程 IPC 回归探针（H6）。真实启动 `bplc-plugin-host` 子进程加载
`src/plugin/examples/lua_echo` 与 `lua_graphics`：

1. worker 线程连续 1500 次 `parse_via_plugin`，GUI 线程同时空跑事件循环；
2. worker 线程对 lua-graphics 连续 3000 次解析，GUI 线程同时对**同一连接**反复 `send_graphics_event`；
3. GUI 延迟/吞吐测量：2 个 worker × 5000 次 `parse_via_plugin`（lua_echo），GUI 线程用
   1 ms `PreciseTimer` 记录事件循环迟到量（max / p99 / p50）、GUI 线程 CPU 时间与解析吞吐；
   分“纯解析”与“解析 + GUI 每 5 ms 一次图形事件”两轮，输出 `LATENCY ...` 行，
   `--bench-json <path>` 另存 JSON（用于新旧设计对比，源码可直接在旧提交上编译）；
4. （Unix）解析途中 SIGKILL lua_echo 的 host：在途请求须 < 1 s 返回，GUI 线程收到 `disabled: ...` 状态；
5. `stop_all()` 之后的迟到请求必须立即失败返回；随后重新 `loadAll` 可再次解析（插件市场更新流程）；
6. 走 `aboutToQuit` 正常退出路径（停插件、在 IPC 线程关 socket、停 IPC 线程）。

要求全部请求拿到响应、插件不被禁用；探针安装 `qInstallMessageHandler`，全程出现任何含
`another thread` / `different thread` 的 Qt 告警（如 `QSocketNotifier ... another thread`、
`Cannot create children for a parent in a different thread`）即判失败。
修复前：阶段 1 为 0/1500（首个响应被 GUI 线程读走 → 5 s 超时 → 插件被禁用），阶段 2 卡死。

## 构建与运行

```
QT_ROOT=/path/to/Qt/6.11.3/gcc_64 bash build.sh
QT_QPA_PLATFORM=offscreen ./build/plugin_ipc_thread_probe/plugin_ipc_thread_probe \
    --host /path/to/bplc-plugin-host     # 宿主须与探针同目录,--host 会复制过来
```

预期：`RESULT: ALL PASS (0 failures)`，exit 0。
