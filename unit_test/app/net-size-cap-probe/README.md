# net-size-cap-probe

下载大小上限探针（CVE-2026-116337 缓解）。本地 `QTcpServer` 充当 HTTP 服务器，验证
`netcap::cap_reply_size`（插件市场 feed/文本/插件包、更新镜像探活共用）：

- 512 KB 响应在 1 MB 上限下完整通过；
- 声明 `Content-Length: 5 GB` 的响应在响应头到达时立即中止；
- 无限 chunked 流在超过上限时中止；
- gzip 编码、解压后 4 MB 的响应按解压后字节中止；
- 中止后 `netcap::size_exceeded()` 为 true，`error()` 为 `OperationCanceledError`。

更新器（`src/updater`，上游第三方代码）用同样的规则内联实现：update.json 1 MB、安装包 512 MB。

```bash
bash build.sh && ./build/net_size_cap_probe/net_size_cap_probe
```
