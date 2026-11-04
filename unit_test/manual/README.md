# `unit_test/manual` — 非 CI 测试与开发探针

本目录收容从原 `samples/` 迁入的 Qt/C++ 测试程序、协议探针、调试 harness 以及它们的构造脚本。它们用于开发、问题复现和人工回归，不属于 GitHub Actions 的必跑门禁，因此与 `unit_test/ci/` 明确分开。

目录中的 `.pro` 和源码均使用相对仓库根目录的路径。多数用例可在自身目录运行 qmake；构建产物应放在未跟踪的 `build/` 目录中。具体输入、运行参数和已知限制以各用例 README 或源码注释为准。

已迁入的原 samples 测试包括：GW/NW 协议探针、头部/span 检查、ProtocolTree/UI 检查、存储/分段/零点测试、更新器和窗口测试，以及 `hdc2_0_build_frames.py`、`rework_two_pb.py` 等测试数据辅助脚本。

`unit_test/ci/` 才是 CI 的稳定回归集合；不要把需要人工输入、外部抓包、联网或历史行为可能漂移的探针加入 CI 目录。
