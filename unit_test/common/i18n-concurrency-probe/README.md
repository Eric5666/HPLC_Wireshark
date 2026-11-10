# i18n-concurrency-probe

i18n 词典并发探针（M6）。4 个线程持续 `trl::L` 查找（模拟解析线程），主线程运行期
`register_en` 20 万个新键（多次触发 QHash rehash，模拟采集中打开设置对话框/加载插件）。

- 查找结果必须始终正确，不崩溃；
- 用 `CONFIG+=tsan` 构建、`TSAN_OPTIONS=halt_on_error=1` 运行时无数据竞争报告
  （旧实现在 `QHash::findOrInsert` 处报 data race）。

```bash
mkdir -p /tmp/i18n-tsan && cd /tmp/i18n-tsan
qmake <repo>/unit_test/common/i18n-concurrency-probe/i18n_concurrency_probe.pro CONFIG+=tsan && make
TSAN_OPTIONS=halt_on_error=1 ./i18n_concurrency_probe
```
