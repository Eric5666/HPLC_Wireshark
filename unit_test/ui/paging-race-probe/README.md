# paging-race-probe

`PacketListModel` 盘块换页竞态探针（M2/M3，M4 部分见下）。用阻塞任务占满全局线程池，
让后台落盘任务排队不执行，稳定复现“块号已分配、文件尚未写完”的窗口：

1. 未落盘块的行由内存副本提供，`data()` 不出现空行；
2. 导出快照（`make_export_snapshot`）带未就绪块的内存副本，条数与顺序完整；
3. 在落盘前发起的异步过滤覆盖全部行；
4. 落盘完成后从已发布（`.tmp` → rename）的块文件读回；
5. `clear_all()` 之后旧会话迟到的写不会混进新会话（文件名带会话号）；
6. M4：异步过滤完成时先 `beginResetModel`/改 `m_visible`/`endResetModel`，再补过滤期间暂存的条目——
   只凭信号维护行数的观察方看到的插入位置与行数一致（旧顺序在此失败）。

```bash
bash build.sh && QT_QPA_PLATFORM=offscreen ./build/paging_race_probe/paging_race_probe
```

CI：`protocol-regression.yml` 的 `runtime-probes-linux` job 经 `unit_test/ci/probe_suite.sh` 构建运行。
