# ipc-frame-probe

M1 回归探针：`plugin_ipc::try_take_frame`（主程序与 bplc-plugin-host 共用的收包函数）。

- 合法帧、半帧、半个长度头按预期取出或等待；
- 帧长 `0`、`0xFFFFFFFC`（旧代码 `4 + len` 回绕为 0 导致 GUI 线程死循环）、`0x80000000`、
  `0x7FFFFFFF`、`kMaxIpcFrame + 1` 一律返回 `Bad`，调用方据此断开连接并停用插件；
- 帧长等于 `kMaxIpcFrame`（16 MB）仍按合法帧等待数据。

```bash
bash build.sh && ./build/ipc_frame_probe/ipc_frame_probe
```
