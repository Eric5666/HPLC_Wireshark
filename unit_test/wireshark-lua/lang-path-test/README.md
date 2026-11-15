# lang-path-test

Wireshark Lua 插件（`wireshark_support_plugins/packet-{gw_2022,gw_2026,nw_2021,nw_2026}.lua`）加载期
语言文件路径回归测试，不需要安装 Wireshark。

旧代码 `os.getenv("APPDATA") .. "\\Wireshark\\language"`：Linux/macOS 没有 `APPDATA`，拼接 nil 抛错，
插件整体加载失败。修复后四个插件共用同一个 `wireshark_language_file()`：

- Windows：`%APPDATA%\Wireshark\language`（无 `APPDATA` 时尝试 Wireshark API，再取不到返回 nil）；
- 其他平台：`Dir.personal_config_path("language")`（pcall 包住，存在才用）→ `$XDG_CONFIG_HOME/wireshark/language`
  → `$HOME/.config/wireshark/language`（macOS 相同）→ nil；
- nil 时不打开文件，回退系统语言；`HPLC_RF_LANG` / `NW_2021_LANG` 环境变量覆盖仍最优先。

回退系统语言的 `system_is_chinese()`（四个插件逐字一致）：

- 先看 `LC_ALL` > `LC_MESSAGES` > `LANG`（首个非空者决定），都没设再看 GNU `LANGUAGE`；
- **仅 Windows**（`package.config:sub(1,1) == "\\"`）且上述变量都没设时才 `io.popen('reg query ... 2>nul')` 查注册表
  `LocaleName`（pcall 包住，`io.popen` 不存在也不报错）；
- 旧代码在 Linux/macOS 也执行该命令：没有 `reg`，而 POSIX shell 把 `2>nul` 当成重定向到当前目录下名为
  `nul` 的文件——每次加载插件都在 Wireshark 的 cwd 里留下一个 `nul` 文件；用不带 POSIX 的 Lua 构建时
  `io.popen` 还会直接抛 `'popen' not supported` 让插件加载失败。

测试用万能 stub 顶替 `Proto`/`ProtoField`/`Field`/`DissectorTable` 等 Wireshark 全局，替换 `os.getenv`、
`package.config`、`io.open`、`io.popen`、`Dir` 模拟 18 种环境，逐个加载四个插件，检查：不报错、打开的
language 文件路径正确、`Proto` 描述的语言与文件内容一致、**非 Windows 不调用 `io.popen`**、Windows 无区域
变量时恰好查一次注册表。另有一组用**真实** `io.popen` 加载四个插件，检查 cwd 不出现 `nul` 文件；`run.sh`
因此在 `mktemp -d` 的空目录里运行，结束后再检查一次该目录。

```bash
bash run.sh            # 或 LUA=/path/to/lua bash run.sh
```

预期 `RESULT: ALL PASS (76/76 passed, 0 failures)`，exit 0。

- 语言文件路径修复前为 8/44（只有 Windows+APPDATA 与环境变量覆盖两类通过）；
- `system_is_chinese()` 修复前（e3cd720）为 48/76：非 Windows 场景调用了 `reg query`、真实 popen 组在 cwd
  生成 `nul`、`LC_ALL=C` 覆盖 `LANG=zh` 判错。

CI：`.github/workflows/protocol-regression.yml` 的 `wireshark-lua-linux` job 用 `apt-get install lua5.4` 后运行
`bash run.sh`（`3rdparty/lua-5.4.*` 不入库，CI 里没有）。
