# `unit_test/ci` — CI 回归用例

本目录只放由 GitHub Actions 直接执行的稳定回归用例。它们应保持无交互、可在干净 checkout 中构建，并且失败时以非零退出码结束。

| 用例 | 作用 | CI 入口 |
|---|---|---|
| `nw-mme-test/` | NW MSDU/MME 截断边界回归 | Linux ASan/UBSan、Linux Release、Windows Release |
| `roundtrip/` | bin/裸 hex 无损往返与 Reader/Playback 回归 | Linux、Windows |
| `nw2026-type1-test/` | NW2026 OFDMA Type-1 trigger/UL/DL-SACK 回归 | Linux |
| `update-json-release/` | `scripts/update_json_release.py`(发版时改 update.json 的 latest-version/download-url,不写 sha256)自测,纯 Python stdlib:`python3 unit_test/ci/update-json-release/test_update_json_release.py` | build.yml `release-manifest`(tag 触发) |

本目录中的 `.pro` 使用相对仓库根目录的路径，不依赖开发机绝对路径。执行方式以 `.github/workflows/protocol-regression.yml` 和 `.github/workflows/build.yml` 为准。Qt 6 构建示例：

```bash
mkdir -p build/nw-mme
cd build/nw-mme
qmake6 ../../unit_test/ci/nw-mme-test/nw_mme_test.pro CONFIG+=release CONFIG-=debug
make -j2
./nw_mme_test
```

`nw2026-type1-test` 的输入由 `wireshark_support_plugins/build_nw2026_ul_ofdma.py` 生成；生成的测试帧不提交到仓库。
