# market-safety-probe

插件市场安全回归探针（`src/plugin/market/plugin_market.cpp`）：

- H2：插件名白名单 `plugin_name_is_safe`、安装目录一级子目录约束 `PluginMarket::plugin_dir_path`
  （`..`、分隔符、盘符、逃出安装根的符号链接均拒绝），离线安装 `name=".."` 的包必须失败且不删目录。
- H3：zip 条目名 `PluginMarket::safe_extract_path`（绝对路径、盘符 `C:/x` `C:x`、UNC `\\srv\s`、
  反斜杠、`..` 组件全部拒绝），含恶意条目的包整体拒绝且不落盘；解包上限：条目数 4096、单条目 64 MB、总量 256 MB。

- H4：市场安装（`install_market_plugin`）必须带 64 位 hex `sha256`：缺失/格式错/不匹配一律拒装，正确值可安装
  （用 `file://` 包地址，不访问网络）。

## 构建与运行

```
QT_ROOT=/path/to/Qt/6.11.3/gcc_64 bash build.sh
./build/market_safety_probe/market_safety_probe
```

无输入文件（zip 用 miniz 现场合成）。预期：`RESULT: ALL PASS (0 failures)`，exit 0。

## L6（fix/medium-low）

- 同一 `PluginMarket` 上两个市场安装同时在途：各自的名字/sha256/来源按请求值捕获，两个都安装成功
  （旧实现共享 `m_pending_*`，先完成的安装会拿到后一个的 sha256）；
- sha256 不符的包被拒绝时不调用 `unload_cb`（卸载推迟到真正改动安装目录前一刻）；
- 卸载之后删旧版失败（目录不可写）时调用 `reload_cb` 恢复加载。
