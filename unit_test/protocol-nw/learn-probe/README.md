# learn-probe（原名 learn_probe）

NW_2026 TEI↔MAC 学习探针：信标、TEI 列表、Gather、级联、
DL/UL-OFDMA 等学习点的对账。

## 构建与运行

```
./build.sh
./build/learn_probe files crafted/*.bin
./build/learn_probe scan <length-prefixed-mpdus.bin>   # 数据集不入库
```

`crafted/` 下 5 个构造帧已入库；再生脚本 `craft_frames.py`
（输出已改为脚本所在目录的 `crafted/`）。

## 预期结果

`files` 模式 exit 0，stderr `scanned 5 frames`，打印 4 条 FRAME 行。
`craft_ul_data.bin` 不打印 FRAME 行是探针设计：
FRAME 行只打印给 interesting 帧（学到对、级联、有站点、
mme 0x0084/0x003A、或非 Other topo），UL 数据帧 5 项全无，
故无行、无对——不是失败。

## 2026-11：TEI 列表 / Gather 夹具补 MSDU CRC32

`craft_teilist.bin` / `craft_gather.bin` 原来不写 MSDU 帧尾 CRC32、后面直接补零到 512B：
补的 0 被当成 CRC32 ⇒ FAIL ⇒ MSDU CRC 门控清空摘要、不学习，`files` 模式只剩 2 条 FRAME 行。
`craft_frames.py` 的 `mme_msdu()` 现在写正确的 CRC32（`zlib.crc32` = `crc.h::crc32_le`，覆盖 MAC 头后
`MSDULength` 字节，小端）并重新生成两帧；恢复 4 条 FRAME 行：Gather（mme=0x003a）、TEI 列表（mme=0x0084）
各学到 TEI 2/3。级联 / DL-OFDMA 两帧载荷恰好填满 PB、无 CRC 字段（"CRC 缺失"三态 N/A），照常学习。

CI（`ci/probe_suite.sh`）断言 `scanned 5 frames`、4 条 FRAME 行与各帧学到的 TEI↔MAC 对。
