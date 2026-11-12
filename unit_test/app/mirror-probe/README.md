# mirror-probe（原名 mirror_probe）

UpdateMirrorResolver 探针：按 argv[1] 写 `config.ini` 的
`mirror_mode`，再对真实 update.json 跑一次解析，
打印最终生效地址与前缀。

## 构建与运行

```
./build.sh
cd build/probe && ./mirror_probe [auto|…]     # 必须在二进制所在目录运行
./build.sh                                     # 同时构建 fb 变体
cd build/probe_fb && ./mirror_probe_fb [auto|…]
```

- `config.ini` 写到**二进制同目录**（`appcfg::ini_path()` =
  applicationDirPath + `/config.ini`），即忽略的 `build/probe/` 内；
  不要在用例根目录运行，以免在仓库里留下 config.ini。
- 默认 update.json 是
  `https://raw.githubusercontent.com/aron566/HPLC_Wireshark/main/update.json`，
  需要联网；无网时 30 秒后打印 TIMEOUT，exit 2。
- `fb/` 子目录是第二种构建配置：编译**仓库里真实的** `src/app/updatemirror.cpp`
  （不再维护分叉副本），只通过 `DEFINES` 把前两个区域识别源
  （cloudflare trace / country.is）指向不可达地址，强制走 ipwho.is 回退链路；
  二进制为 `mirror_probe_fb`，stderr 应出现 `region source ipwho.is reports …`。
  `fb/probe_fb.pro` 的路径按其深度用 4 层 `$$PWD/../../../../src/app`，
  不要改回 3 层。

## 预期结果（有网时）

`mode=auto url=…` + `RESOLVED effective=… prefix=(native)`，exit 0。
