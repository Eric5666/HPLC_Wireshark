# plugin-autotest — 插件面板自动化截图

原 `MainWindow::run_plugin_autotest` / `autotest_shoot_tabs`(QTimer 截图脚本)
已从产品代码移到这里,只在测试构建中编译。

## 构建

```bash
qmake BPLC_STA_Monitor.pro CONFIG+=release CONFIG+=crash_no_default CONFIG+=plugin_autotest
make -j2
```

`CONFIG+=plugin_autotest` 引入 `plugin_autotest.pri`(定义 `BPLC_PLUGIN_AUTOTEST`)。
产品构建不含该代码,`--plugin-autotest` 参数会被忽略并打印告警。

## 运行

```bash
QT_QPA_PLATFORM=offscreen ./BPLC_STA_Monitor \
    --plugins-dir <plugins> --replay <capture.bin> --plugin-autotest <shot_dir>
```

流程:加载插件 → 回放 bin → 等 Reader 结束、插件线程空闲、背压在途帧归零
(最长 10 min)→ 每 1.5 s 切一个插件 tab 截 `plugin_<id>.png` → 选中首个带 MSDU
的帧再截 `main.png` → 退出。

驱动只经 `MainWindow` 的公开测试接口(`capture()` / `plugin_engine()` /
`plugin_tabs()` / `packet_model()` / `plugin_id_of()` / `jump_packet_to_frame()`)。
