# lua-sandbox-probe

Lua 插件沙箱回归探针（`src/plugin/host/lua_backend.cpp` 的 `open_sandboxed_libs`）：

- 合成插件在 `get_info()` 中自检：无 `io`/`debug`、无 `os.execute/exit/getenv/remove/rename/tmpname`、
  无 `package.loadlib` 与 C 搜索器；`require`/`dofile`/`loadfile` 只能读插件目录内文件；
  `load` 拒绝字节码；入口脚本为字节码时拒绝加载。
- 仓库自带 Lua 示例插件（`src/plugin/examples/lua_*`）在沙箱下仍能加载。

## 构建与运行

```
QT_ROOT=/path/to/Qt/6.11.3/gcc_64 bash build.sh
QT_QPA_PLATFORM=offscreen ./build/lua_sandbox_probe/lua_sandbox_probe
```

预期：`RESULT: ALL PASS (0 failures)`，exit 0。
