# frame-credit-probe

帧流背压探针（M7）。`FrameCredit` 是 Reader → 解析线程 → GUI 之间的在途帧上限（默认 4096）：
Reader 每发一帧取一个额度，GUI 线程在 `FrameDispatcher::on_parsed` 收到该帧解析结果时归还。

1. 未接入消费者时不限流；
2. 在途达到上限时 `acquire` 阻塞；中止标志置位后 500 ms 内放弃（实际 ≤ 50 ms 分片）；
3. `release` / `reset` / `set_enabled(false)` 都能解除阻塞；
4. 真实 `ReaderWorker` 回放：慢消费者下在途帧不超过上限，Reader 被限流；`abort()` 能打断阻塞中的 Reader。

```bash
bash build.sh && ./build/frame_credit_probe/frame_credit_probe
```
