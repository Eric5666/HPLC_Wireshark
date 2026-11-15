# script-budget-probe

脚本插件执行预算回归探针（M10，`src/plugin/host/lua_backend.cpp` 指令预算 hook、
`src/plugin/host/js_backend.cpp` 的 `JsWatchdog`）：

- Lua：`parse()` 里 `while true do end`、被 `pcall` 包裹的死循环、`pcall` + 协程里的死循环、
  入口脚本顶层死循环，都在预算内以 `instruction budget exceeded` 结束；超限后下一次调用正常。
- JS：`parse()` 里 `for(;;){}` 与入口脚本顶层死循环被看门狗打断（`time limit`）；
  打断后中断标志复位，随后 200 次正常调用均不被误打断。

探针把预算缩短为 2000 万条指令 / 500 ms 以加快运行（`BPLC_LUA_INSTR_BUDGET`、
`BPLC_JS_CALL_TIMEOUT_MS`，已设置时不覆盖）；产品默认 2 亿条 / 3000 ms。

## 构建与运行

```
QT_ROOT=/path/to/Qt/6.11.3/gcc_64 bash build.sh
QT_QPA_PLATFORM=offscreen ./build/script_budget_probe/script_budget_probe
```

预期：`RESULT: ALL PASS (0 failures)`，exit 0。
