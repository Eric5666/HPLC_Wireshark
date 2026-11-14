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
5. `stop_all()` 之后的迟到请求必须立即失败返回；随后重新 `load_all` 可再次解析（插件市场更新流程）；
6. 走 `aboutToQuit` 正常退出路径（停插件、在 IPC 线程关 socket、停 IPC 线程）。
7. （异步图形 API，Unix）原版 `lua_graphics`（`set_font`/`draw_text`）经真实 host 渲染出图，
   host 不崩、插件仍启用（host 为 QGuiApplication + offscreen 平台）；
   另生成 `lua_gfx_nofont`（lua_graphics 去掉画字、换协议 id），用真实 `PluginGraphicsView` 做异步渲染往返：
   - host `SIGSTOP` 2 s：GUI 每 5 ms 发图形事件、每 60 ms 要求重绘，GUI 1 ms 定时器最大迟到须 < 20 ms
     （扣除 GUI 线程在运行队列上等 CPU 的时间，见下“迟到量口径”）；
     旧图保持；卡死期间最多 1 个渲染在途（合并），恢复后补发 1 次并应用；全部事件 ack；
   - host `SIGSTOP` 5.6 s：异步请求 5 s 超时以失败回调（不早于 4.9 s），GUI 不卡；
     回调上下文已销毁的请求不回调；迟到 ack 被丢弃，无残留登记；恢复后插件可用。

阶段 2、3 的图形事件在有异步 API 的版本（`BPLC_PLUGIN_ASYNC_GRAPHICS`）上走
`send_graphics_event_async`，在旧提交上回落到同步 `send_graphics_event`，因此同一源码可在
f01697d / 013d9a8 上编译做对比；`--bench-only` 只跑握手 + 阶段 3。
探针同时捕获 `wait_response called on the GUI thread` 告警（GUI 线程阻塞等插件 IPC）并判失败。

要求全部请求拿到响应、插件不被禁用；探针安装 `qInstallMessageHandler`，全程出现任何含
`another thread` / `different thread` 的 Qt 告警（如 `QSocketNotifier ... another thread`、
`Cannot create children for a parent in a different thread`）即判失败。
修复前：阶段 1 为 0/1500（首个响应被 GUI 线程读走 → 5 s 超时 → 插件被禁用），阶段 2 卡死。

## 迟到量口径（负载下偶发失败的根因与修复）

阶段 ④ 的 “GUI max lateness < 20 ms” 原先用墙钟：相邻两次 1 ms tick 的间隔 − 1 ms。负载高时
（fullcheck 并行构建、CI runner 2 核被占满）GUI 线程可运行却排不上 CPU，CFS 一次排队就 20~30 ms，
fullcheck 多次记到 timeout 段 28~32 ms 而单跑 < 2 ms——这是测试的时序假设（独占 CPU）错了，
不是被测代码阻塞 GUI。

现在每个 tick 读 `/proc/thread-self/schedstat` 第 2 列（`run_delay`，可运行但在运行队列上等 CPU 的累计
时间），判定值 = 墙钟间隔 − 本间隔内的 run_delay 增量 − 1 ms：被调度器抢占/排队的时间不计；GUI 线程
阻塞在锁、条件变量、系统调用（真正要抓的回归，如同步 `wait_response`）或在 GUI 线程做重活，仍全额
计入。输出同时给出墙钟值与单 tick 最长等 CPU 时间，例如：

```
stall 5.6s: ... GUI max lateness 3.69 ms excl. run-queue wait (wall 17.37 ms, max run-queue wait/tick 17.28 ms)
```

（4 个 `yes` 占满 2 核时连跑 4 次：墙钟 9~17 ms 几乎全是等 CPU，扣除后 0.5~3.7 ms。）
schedstat 不可用（非 Linux / 内核未开 `SCHED_INFO`）时退回墙钟口径。2 s 段 “ticks > 1000” 只是证明
定时器在跑，负载下 tick 数会少，门槛降为 > 500。

## 构建与运行

```
QT_ROOT=/path/to/Qt/6.11.3/gcc_64 bash build.sh
QT_QPA_PLATFORM=offscreen ./build/plugin_ipc_thread_probe/plugin_ipc_thread_probe \
    --host /path/to/bplc-plugin-host     # 宿主须与探针同目录,--host 会复制过来
```

预期：`RESULT: ALL PASS (0 failures)`，exit 0。

CI：`protocol-regression.yml` 的 `runtime-probes-linux` job 经 `unit_test/ci/probe_suite.sh` 构建运行（宿主与探针复制到
本地临时目录、300 s 超时防挂死，不重试）。
