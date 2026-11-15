# golden

PacketEntry 块序列化 golden（盘块换页格式 `pser::encode_block` / `decode_block`）：合成 1/57/250/1000
条目块，与入库的 `v<block_version>_n<N>.bin` 比对。

## 构建与运行

```
./build.sh
mkdir -p build/run && cd build/run
../golden/golden --check ../..      # CI 门禁
```

`--check <dir>` 逐档检查：

1. 编码 → `decode_block` → 再编码，逐字节一致（无损往返、条目数正确）；
2. 当前读取器能解 `<dir>/v<ver>_n<N>.bin`（`<ver>` = `pser::block_version()`）；
3. 解出的 golden 用当前编码器重编码 == 本次编码（按内容比对：块内字符串池经 `qCompress`
   用系统 zlib，不同 zlib 实现压缩字节可能不同而内容相同；字节不同但内容相同时只打印 note）。

预期 `RESULT: ALL PASS (0 failures)`，exit 0。CI：`protocol-regression.yml` 的 `protocol-probes-linux` job。

## 格式有意变更时

`packetentry_serialize.h` 改了块格式就必须 bump `block_version()`（读取器拒绝其他版本），
然后重录 golden 并删除旧版本文件：

```
cd build/run && ../golden/golden --record ../.. && git rm ../../v<旧版本>_n*.bin
```

格式变了却没 bump 版本 ⇒ 第 2/3 项失败（golden 解不出或内容不同）；bump 了没重录 ⇒
`golden v<新版本>_n<N>.bin present` 失败。

无参数运行保持旧行为：在 CWD 写 `v<ver>_n<N>.bin` 并打印 sha256，**不要在用例根目录无参运行**。

## 历史

归集时入库的是 v3 格式 golden（`v3_n*.bin`），格式已演进到 v20，旧文件早已无法被读取器解码、
再生字节也全部不同（README 记为"已过期"）。2026-11 起改为按 `block_version` 命名并重录 v20、
删除 v3 文件，同时加 `--check` 模式接入 CI。
