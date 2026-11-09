# market-safety-probe

插件市场安全回归探针（`src/plugin/market/plugin_market.cpp`）：

- H2：插件名白名单 `plugin_name_is_safe`、安装目录一级子目录约束 `PluginMarket::plugin_dir_path`
  （`..`、分隔符、盘符、逃出安装根的符号链接均拒绝），离线安装 `name=".."` 的包必须失败且不删目录。
- H3：zip 条目名 `PluginMarket::safe_extract_path`（绝对路径、盘符 `C:/x` `C:x`、UNC `\\srv\s`、
  反斜杠、`..` 组件全部拒绝），含恶意条目的包整体拒绝且不落盘；解包上限：条目数 4096、单条目 64 MB、总量 256 MB。

## 构建与运行

```
QT_ROOT=/path/to/Qt/6.11.3/gcc_64 bash build.sh
./build/market_safety_probe/market_safety_probe
```

无输入文件（zip 用 miniz 现场合成）。预期：`RESULT: ALL PASS (0 failures)`，exit 0。
