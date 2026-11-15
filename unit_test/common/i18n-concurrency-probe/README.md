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

CI：`protocol-regression.yml` 的 `runtime-probes-linux` job 经 `unit_test/ci/probe_suite.sh` 构建运行（先 `sysctl vm.mmap_rnd_bits=28`；先跑故意数据竞争的自检程序确认 TSan 生效、再确认探针二进制带 TSan 运行时，然后 `TSAN_OPTIONS=halt_on_error=1` 运行，输出不得含 ThreadSanitizer 报告）。
