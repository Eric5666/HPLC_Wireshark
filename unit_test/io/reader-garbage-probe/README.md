# reader-garbage-probe

回放切帧探针（M5）。直接驱动 `ReaderWorker`：

1. 4 MB 无 `0x3C` 垃圾 + 样本（`unit_test/ci/roundtrip/roundtrip_test.bin`）：旧实现每丢 1 字节就全量
   `indexOf` 一次，每个 1 MB 读块约 10¹² 次比较；新实现整段丢弃，要求 < 5 s 且样本帧数不变；
2. 整个读块都无 `0x3C` 的垃圾中夹 8B BCD 段标注：标注仍生效（首帧时间 = 标注时刻），与逐字节滑窗语义一致；
3. 串口模式 2 MB 垃圾一次清空；
4. 回放中途 `abort()`（与 `SerialReader::stop()` 相同的跨线程置位）1 s 内返回。

```bash
bash build.sh && ./build/reader_garbage_probe/reader_garbage_probe
```
