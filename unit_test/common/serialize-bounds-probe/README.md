# serialize-bounds-probe

盘块反序列化边界探针（L8，`src/common/packetentry_serialize.h`）：

- 计数字段（字段树子节点、拓扑事件 nodes、MPDU pb_heads 等）超过剩余字节数时，流标记
  `ReadCorruptData`、计数置 0，不再按损坏计数 `reserve` 数 GB；
- 字段树嵌套上限 64 层（65 层判损坏，20 万层不栈溢出）；
- 条目载荷的每种截断都被 `deserialize_entry` 拒收；2 万次随机 4 字节变异不崩溃；
- 字符串池计数超出池字节数的块被 `BlockReader` 拒收。

Linux 下探针把地址空间限制为 2 GB：修复前的代码在这里以 `std::bad_alloc` 终止。

## 构建与运行

```
QT_ROOT=/path/to/Qt/6.11.3/gcc_64 bash build.sh
./build/serialize_bounds_probe/serialize_bounds_probe
```

预期：`RESULT: ALL PASS (0 failures)`，exit 0。
