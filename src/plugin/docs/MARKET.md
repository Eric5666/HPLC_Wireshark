# Plugin Marketplace

VS Code-style extension marketplace for BPLC STA Monitor.
Source: `src/plugin/market/` (`plugin_market.*` backend, `market_dialog.*` UI).

## Layout

```
+---------------------------------------------------------------+
| [search............]  [filter: All/Installed/Not installed]    |
+------------------------------+------------------------------+
| INSTALLED                    |  (icon) Display Name         |
|  card: name, author,          |  Author / version / category |
|  version, badge              |  [Install|Update] [Uninstall]|
| MARKETPLACE                  |  [x] Enabled                 |
|  card ...                    |  full description            |
|                              |  available versions          |
+------------------------------+------------------------------+
| status line                                               |
+---------------------------------------------------------------+
| [Install from file...] [Refresh]                  [Close] |
+---------------------------------------------------------------+
```

Entry point: **Plugins → Plugin marketplace** menu in the main window.

## Market feed

`market.json` (see `BPLC_Plugin_Market` repo):

```json
{
  "version": 1,
  "plugins": [{
    "name": "js-topo",
    "display_name": "...", "display_name_en": "...",
    "description": "...",  "description_en": "...",
    "category": "diagnosis | report | graphics | protocol",
    "author": "bplc",
    "readme_url": "https://raw.githubusercontent.com/.../readme/js-topo.md",
    "versions": [{
      "version": "1.1.0",
      "url": "https://.../js-topo-1.1.0.zip",
      "size": 2400,
      "min_app_version": "1.3.0",
      "updated_at": "2026-10-02",
      "platforms": ["linux-x86_64"]
    }]
  }]
}
```

- `readme_url`: README markdown rendered in the dialog's *README* tab
  (markdown via `QTextDocument`). For installed plugins the dialog prefers
  `<plugin-dir>/README.md` shipped inside the package, then falls back to
  this URL, then to the plain description.
- `updated_at`: per-version update date (ISO), shown as 更新时间/Updated.
- `sha256`: no longer used. The app does not verify package SHA-256; a
  `sha256` key left in an older feed is parsed past and ignored.
- `platforms`: optional list of platform IDs this version supports
  (`linux-x86_64`, `linux-arm64`, `windows-x86_64`, `windows-arm64`,
  `macos-arm64`, `macos-x86_64`). The ID is `<os>-<arch>` of the host
  **build** (`plugin_host_platform()` in `plugin_api/plugin_manifest.h`):
  arch is `x86_64` or `arm64` (other architectures fall back to
  `QSysInfo::buildCpuArchitecture()`), so an x64 build running under
  emulation on Windows on ARM still reports `windows-x86_64`. The same
  key selects the per-platform `abi` entry below.
  Absent or empty = all platforms (script plugins). The client only
  offers/installs the newest version compatible with the running
  platform, shows the platform list in the detail panel, and hides
  market entries that have no compatible version at all. The plugin
  count reflects the filtered list.
  Native plugins ship one binary per platform inside the zip and use a
  platform-neutral manifest `entry` (bare library name); the native
  backend resolves it to `lib<entry>.so` (Unix) or `<entry>.dll`
  (Windows). An explicit filename entry (`*.so`/`*.dll`) still works
  as before.
- The dialog records the feed URL as the plugin's *source* (来源/Source)
  in `meta.json` at install time (`"file"` for install-from-file).

Default feed URL: `https://raw.githubusercontent.com/aron566/BPLC_Plugin_Market/main/market.json`.
Override for dev/test: env var `BPLC_MARKET_FEED_URL` (supports `file://`).

Market feed requests use the same `app/mirror_mode` and `app/mirror_list` strategy as application updates. In `auto` mode, China egress selects the first mirror that returns a valid feed (`plugins` JSON key); other regions use the origin URL, and failures fall back to the origin. The selected prefix also rewrites feed-provided README and package URLs for that feed. Non-HTTP(S) feeds (for example local `file://` test feeds) bypass mirror resolution.

## Plugin settings

`plugin.json` may declare a `"settings"` array; the dialog generates a
*Settings* tab form from it and persists values to
`<plugin-dir>/settings.json`. Scripts read them via
`host.getSetting(key, default)` (see `HOST_API.md`).

```json
"settings": [
  {"key": "max_nodes", "type": "integer", "default": 200,
   "minimum": 10, "maximum": 2000,
   "title": "最大节点数", "title_en": "Max nodes",
   "description": "...", "description_en": "..."},
  {"key": "show_labels", "type": "boolean", "default": true,
   "title": "显示节点标签", "title_en": "Show node labels"},
  {"key": "layout", "type": "string", "enum": ["auto", "circular", "grid"],
   "default": "auto", "title": "布局方式", "title_en": "Layout"}
]
```

- `type`: `boolean` | `integer` | `number` | `string`;
  `type: string` + `"enum"` renders a drop-down.
- Unknown types or entries without `key` are skipped by the manifest
  parser.

## Common environment variables

The host exposes a fixed set of environment variables to every script
plugin via `host.getEnv(name)` (see `HOST_API.md` §2); the dialog's
*Environment* tab lists them with live values. Defined in
`plugin_api/plugin_env.h`: `BPLC_APP_VERSION`, `BPLC_API_VERSION`,
`BPLC_PLUGIN_DIR`, `BPLC_DATA_DIR`, `BPLC_LANG`.

## Package format

A plugin package is a zip containing at minimum:

```
plugin.json   # manifest, see plugin_api/plugin_manifest.h
<entry>       # entry script named by manifest "entry"
```

## Install flow

1. Market install: download zip (size-capped) → unzip to temp dir → validate `plugin.json`
   (manifest + entry file must exist) → check `min_app_version` against the
   running app version → check `platforms` against the running platform
   → copy to the install dir.
2. Offline install (`Install from file...`): same chain without the feed
   checks — manifest validity and entry-file existence are still enforced.
3. Zip-slip guard (`PluginMarket::safe_extract_path`): entries with absolute
   paths, drive letters (`C:/x`, `C:x`), UNC paths, backslashes or any `..`
   component are rejected, and the whole package is refused before anything
   is written. Limits: at most 4096 entries, 64 MB per entry, 256 MB total.

Install dir: `<applicationDirPath>/plugins/<name>/` (next to the executable).
On Linux, if the dir is not writable, installation requests elevation via
pkexec(1).
Each installed plugin gets `meta.json`: `{ "enabled": bool, "installed_at" }`.
Re-installing the same name replaces it (= update). `uninstall(name)`
deletes the dir. The plugin `name` (manifest and feed) must match
`[A-Za-z0-9][A-Za-z0-9._-]{0,63}` (`plugin_name_is_safe`, enforced by
`read_plugin_manifest`); install / uninstall / enable all resolve the
directory through `PluginMarket::plugin_dir_path()`, which also requires a
direct child of the install root and refuses entries (incl. symlinks)
whose real path leaves it.

## Enable / disable

`meta.json` `enabled=false` plugins are silently skipped by
`PluginWorker::start_load` (no error panel). Toggling in the dialog takes
effect after plugins are reloaded (dialog close triggers a reload of all
plugin dirs).

## Native (C++) plugin ABI compatibility

Native (C++) plugins are compiled binaries linked against a specific Qt
version + compiler toolchain. Their binary ABI must match the host app's;
a mismatch (plugin built with a different Qt version, or MSVC vs MinGW)
corrupts the QMetaObject layout and **crashes the host on load**.

Each native plugin declares its ABI in `plugin.json`, either as a single
string (single-platform package) or per-platform (multi-platform package):

    "abi": {
        "windows-x86_64": "qt6-mingw-x64",
        "linux-x86_64": "qt6-gcc-x64",
        "linux-arm64": "qt6-gcc-arm64"
    }

The host computes its own ABI at startup as `qt<major>-<compiler>-<arch>`
(`plugin_host_abi()` in `plugin_api/plugin_manifest.h`; compiler is
`msvc`/`mingw`/`gcc`/`clang` — note Linux GCC reports `gcc`, not `mingw`;
Qt 6.x ABI is stable, so only the major version is checked — 6.10 and 6.11
are compatible) and filters native plugins whose `abi` is missing or differs —
marked incompatible in the market and skipped at load. The market feed carries
the same per-version `abi`; `update_market_json.py` copies it from the
package's `plugin.json`, and the packager (`make_packages.sh`) injects the
build's ABI at package time. Script plugins (js/lua) are ABI-independent
and need no `abi` field.

## Verification chain (current)

- Package size cap on download; zip-slip guard and unzip limits.
- No SHA-256 verification of packages (removed; a feed `sha256` key is ignored).
- Manifest + entry-file validation for every install.
- `min_app_version` compatibility check before market installs.
- `platforms` compatibility check before market installs.

**Not yet implemented:** Ed25519 official-signature verification of
packages (per the plugin-system interface draft). The feed and the
transport are not trusted; the local checks above are the trust anchor
for now. Signature verification is the next step before shipping
non-test plugins.

## Script sandbox (Lua)

Lua plugins run with a restricted standard library
(`open_sandboxed_libs` in `host/lua_backend.cpp`, used by both the
in-process backend and `bplc-plugin-host`):

- available: base, `string`, `table`, `math`, `utf8`, `coroutine`,
  `package`/`require`, and `os.clock/date/difftime/time`;
- removed: `io`, `debug`, `os.execute/exit/getenv/remove/rename/tmpname/setlocale`,
  `package.loadlib`, C module loading (`package.cpath` is empty, C searchers
  removed) — use `host.getEnv(name)` for environment values;
- `require`, `dofile` and `loadfile` only load files inside the plugin
  directory (relative paths are resolved against it);
- `load`/`loadfile`/`dofile`/`require` and the entry script accept **text
  chunks only** (precompiled bytecode is rejected).

## Script time limits (Lua and JS)

Every call into a script plugin (loading the entry script, `get_info`,
`parse`, `render`, `on_event`, `on_frame_selected`, text functions) has a
budget:

- **Lua**: 200 million VM instructions per call (an instruction-count hook).
  On overrun the call fails with the Lua error
  `instruction budget exceeded (...)`; catching it with `pcall`/`xpcall` or
  running the loop in a coroutine does not help, the error is raised again
  at the next instruction until it leaves the entry point. The next call
  starts with a fresh budget. Override for tests with
  `BPLC_LUA_INSTR_BUDGET=<instructions>`.
- **JS**: 3 s wall clock per call. A watchdog calls
  `QJSEngine::setInterrupted(true)`; the call fails with
  `<entry>: script exceeded 3000 ms time limit, interrupted` and the engine
  is reset for the next call. Override with `BPLC_JS_CALL_TIMEOUT_MS=<ms>`.

A plugin whose `parse()` hits the limit gets that frame rejected with the
error as the reason; the plugin keeps running.

This is defence in depth, not a security boundary: there is no memory
limit, and JS/native plugins are not sandboxed (native plugins are fully
trusted code).

## API notes

- `PluginMarket` lives on the GUI thread; downloads are async via
  `QNetworkAccessManager` (`feed_ready`/`feed_error`,
  `install_progress`/`install_finished`).
- Static helpers (`parse_feed`, `unzip_to_dir`,
  `compare_version`, `app_version_ok`) are unit-testable without a GUI.
- The main window loads plugin dirs in order: CLI `--plugins-dir`
  (or `<app>/plugins`) first, then the market install dir. Same plugin
  name in both: the later load wins (worker map keyed by manifest name).
