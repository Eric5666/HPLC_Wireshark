# lang-path-test

Wireshark Lua 插件（`wireshark_support_plugins/packet-{gw_2022,gw_2026,nw_2021,nw_2026}.lua`）加载期
语言文件路径回归测试，不需要安装 Wireshark。

旧代码 `os.getenv("APPDATA") .. "\\Wireshark\\language"`：Linux/macOS 没有 `APPDATA`，拼接 nil 抛错，
插件整体加载失败。修复后四个插件共用同一个 `wireshark_language_file()`：

- Windows：`%APPDATA%\Wireshark\language`（无 `APPDATA` 时尝试 Wireshark API，再取不到返回 nil）；
- 其他平台：`Dir.personal_config_path("language")`（pcall 包住，存在才用）→ `$XDG_CONFIG_HOME/wireshark/language`
  → `$HOME/.config/wireshark/language`（macOS 相同）→ nil；
- nil 时不打开文件，回退系统语言；`HPLC_RF_LANG` / `NW_2021_LANG` 环境变量覆盖仍最优先。

测试用万能 stub 顶替 `Proto`/`ProtoField`/`Field`/`DissectorTable` 等 Wireshark 全局，替换 `os.getenv`、
`package.config`、`io.open`、`io.popen`、`Dir` 模拟 11 种环境，逐个加载四个插件，检查：不报错、打开的
language 文件路径正确、`Proto` 描述的语言与文件内容一致。

```bash
bash run.sh            # 或 LUA=/path/to/lua bash run.sh
```

预期 `RESULT: ALL PASS (44/44 passed, 0 failures)`，exit 0。修复前为 8/44（只有 Windows+APPDATA 与环境变量覆盖两类通过）。
