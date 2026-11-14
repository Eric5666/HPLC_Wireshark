#!/usr/bin/env bash
# unit_test 探针 CI 驱动:按目录逐个 构建 → 运行 → 断言,全部跑完再汇总(一个失败不挡后面的)。
#
# 用法(在仓库任意位置):
#   QT_ROOT=<Qt 前缀或 symlink farm> bash unit_test/ci/probe_suite.sh <探针目录>...
#   探针目录相对 unit_test/,如 protocol-gw/gw-rsv-harness;未登记的目录直接判失败。
#
# 环境变量:
#   QT_ROOT       必需。含 bin/ include/ lib/ libexec/ 的 Qt 前缀(CI 用 $RUNNER_TEMP/qt-root symlink farm)
#   JOBS          make 并行数(默认 nproc)
#   PLUGIN_HOST   plugin/plugin-ipc-thread-probe 与 app/plugin-autotest 用的 bplc-plugin-host
#                 (不给则在 $WORK/plugin-host 现场构建)
#   WORK          运行/构建临时目录(默认 ${RUNNER_TEMP:-/tmp}/probe-suite),须在本地盘:
#                 部分探针在运行目录建删子目录,FUSE 盘上 removeRecursively 偶发失败
#
# 退出码:0 全部通过;1 有失败(末尾列出失败项)。每项输出存 $WORK/logs/<名字>.log。
# 镜像:.github/workflows/protocol-regression.yml 各 probe job;本地 /workspace/work/build_hplc.sh 同样调用。
set -u
cd "$(dirname "$0")/../.."
REPO="$PWD"
UT="$REPO/unit_test"
: "${QT_ROOT:?QT_ROOT 未设置(Qt 前缀或 symlink farm)}"
export QT_ROOT
export JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"
export QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}"
export LD_LIBRARY_PATH="$QT_ROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PATH="$QT_ROOT/bin:$PATH"
WORK="${WORK:-${RUNNER_TEMP:-/tmp}/probe-suite}"
LOGD="$WORK/logs"
mkdir -p "$LOGD"
RT="$UT/ci/roundtrip/roundtrip_test.bin"   # 入库的 GW 抓包(2457 帧),各抓包型探针共用
FP="$UT/frames/frame-probe"                # 入库的构造帧 / 单帧

gh() { [ -n "${GITHUB_ACTIONS:-}" ] && echo "$@"; return 0; }
OUT=""   # 最近一次 run 的输出文件

# build <dir> [script]:在探针目录执行其构建脚本
build() { (cd "$UT/$1" && bash "${2:-build.sh}"); }
# run <tag> <timeout_s> <cmd...>:运行并把 stdout+stderr 存到 $LOGD/<tag>.out;非 0 退出即失败
run() {
    local tag="$1" to="$2"; shift 2
    OUT="$LOGD/$tag.out"
    timeout "$to" "$@" > "$OUT" 2>&1 < /dev/null
    local rc=$?
    if [ $rc -ne 0 ]; then echo "  FAIL: $tag 退出码 $rc"; tail -n 30 "$OUT" | sed 's/^/    | /'; return 1; fi
    echo "  ok: $tag 退出码 0"
}
# has <固定串>...:最近一次输出须包含每个串
has() {
    local s ok=0
    for s in "$@"; do
        if grep -qF -- "$s" "$OUT"; then echo "  ok: 含 '$s'"; else echo "  FAIL: 缺 '$s'"; ok=1; fi
    done
    return $ok
}
# lacks <固定串>:最近一次输出不得包含
lacks() { if grep -qF -- "$1" "$OUT"; then echo "  FAIL: 不应出现 '$1'"; grep -F -- "$1" "$OUT" | head -3 | sed 's/^/    | /'; return 1; fi; echo "  ok: 无 '$1'"; }
# count <固定串> <N>:最近一次输出中含该串的行数须为 N
count() { local n; n=$(grep -cF -- "$1" "$OUT"); if [ "$n" = "$2" ]; then echo "  ok: '$1' ×$n"; else echo "  FAIL: '$1' 期望 $2 行,实际 $n"; return 1; fi; }
# same_as_original <dir-mg> <dir>:_mg 变体的 harness.pro 编译原版 main.cpp(本目录 main.cpp 从不编译);
# 守住"两份 main.cpp 一致、.pro 指向原版",防止有人只改 _mg 副本以为改了断言
same_as_original() {
    local ok=0
    if cmp -s "$UT/$1/main.cpp" "$UT/$2/main.cpp"; then echo "  ok: $1/main.cpp 与 $2/main.cpp 一致"; else echo "  FAIL: $1/main.cpp 与 $2/main.cpp 不一致(_mg 只编译原版,改断言须改原版并同步)"; ok=1; fi
    if grep -qF "unit_test/$2/main.cpp" "$UT/$1/harness.pro"; then echo "  ok: $1/harness.pro 编译 $2/main.cpp"; else echo "  FAIL: $1/harness.pro 未指向 $2/main.cpp"; ok=1; fi
    return $ok
}
# rundir <name>:本地盘上的干净运行目录
rundir() { local d="$WORK/run/$1"; rm -rf "$d"; mkdir -p "$d"; echo "$d"; }

plugin_host() {
    if [ -n "${PLUGIN_HOST:-}" ] && [ -x "$PLUGIN_HOST" ]; then echo "$PLUGIN_HOST"; return 0; fi
    local d="$WORK/plugin-host"
    if [ ! -x "$d/bplc-plugin-host" ]; then
        mkdir -p "$d"
        (cd "$d" && qmake "$REPO/src/plugin/host/bplc-plugin-host.pro" CONFIG+=release CONFIG-=debug && make -j"$JOBS") >&2 || return 1
    fi
    echo "$d/bplc-plugin-host"
}

# ======================= 各探针:构建 + 运行 + 断言 =======================
# 函数名 = p_ + 目录名(/ 与 - 换成 _)

# ---- frames ----
p_frames_frame_probe() {   # NW_2021 单帧解析 + 构造帧输入目录
    build frames/frame-probe || return 1
    local B="$UT/frames/frame-probe/build/probe/nw_frame_probe" f=0
    run fp-1021 30 "$B" "$FP/nw_frame_20261021.bin" && has "accept=1" "msdu: present=1" || f=1
    run fp-1022 30 "$B" "$FP/nw_frame_20261022.bin" && has "accept=1" || f=1
    run fp-1022full 30 "$B" "$FP/nw_frame_20261022_full.bin" && has "accept=1" "msdu: present=1" "BID=0x02" || f=1
    run fp-1022b 30 "$B" "$FP/nw_frame_20261022b.bin" && has "accept=1" "msdu: present=1" "BID=0x02" || f=1
    run fp-1022c 30 "$B" "$FP/nw_frame_20261022c.bin" && has "accept=1" || f=1
    run fp-tail-crc 30 "$B" "$FP/nw_log_tail_pb_crc_fail.bin" && has "accept=1" "msdu: present=1" "BID=0x03" || f=1
    run fp-tail-esc 30 "$B" "$FP/nw_log_tail_wire_escaped.bin" && has "accept=1" "msdu: present=1" "BID=0x03" || f=1
    return $f
}
nextgen_checks() {   # <tag> <bin>:四个解析器批量跑入库抓包,统计须与入库样本一致
    local t="$1" B="$2" f=0
    run "$t-nw2021" 120 "$B" nw2021 "$RT" && has "== nw2021: total=2457 accepted=2429 msdu=0 sof=319" || f=1
    run "$t-nw2026" 120 "$B" nw2026 "$RT" && has "== nw2026: total=2457 accepted=2429 msdu=0 sof=319" || f=1
    run "$t-gw2022" 120 "$B" gw2022 "$RT" && has "== gw2022: total=2457 accepted=2457 msdu=347 sof=347 pb_crc_ok=347 beacon=871" || f=1
    run "$t-gw2026" 120 "$B" gw2026 "$RT" && has "== gw2026: total=2457 accepted=2457 msdu=347 sof=347 pb_crc_ok=347 beacon=871" || f=1
    run "$t-single" 30 "$B" nw2021 "$FP/nw_frame_20261022.bin" && has "== nw2021: total=1 accepted=1" || f=1
    return $f
}
p_frames_nextgen_probe() { build frames/nextgen-probe && nextgen_checks nextgen "$UT/frames/nextgen-probe/build/probe/nextgen_probe"; }
p_frames_nextgen_probe_verify() {   # 与 nextgen-probe 同源(main.cpp/.pro 相同),照样构建运行
    local f=0
    if cmp -s "$UT/frames/nextgen-probe-verify/main.cpp" "$UT/frames/nextgen-probe/main.cpp"; then echo "  ok: main.cpp 与 nextgen-probe 一致"; else echo "  note: main.cpp 与 nextgen-probe 已分叉"; fi
    build frames/nextgen-probe-verify || return 1
    nextgen_checks nextgen-verify "$UT/frames/nextgen-probe-verify/build/probe/nextgen_probe" || f=1
    return $f
}

# ---- protocol-gw ----
p_protocol_gw_gw_beacon_harness() { build protocol-gw/gw-beacon-harness && run gw-beacon 60 "$UT/protocol-gw/gw-beacon-harness/build/harness/gw_beacon_harness" && has "RESULT: PASS"; }
p_protocol_gw_gw_beacon_harness_mg() {
    same_as_original protocol-gw/gw-beacon-harness-mg protocol-gw/gw-beacon-harness || return 1
    build protocol-gw/gw-beacon-harness-mg && run gw-beacon-mg 60 "$UT/protocol-gw/gw-beacon-harness-mg/build/harness/gw_beacon_harness" && has "RESULT: PASS"
}
p_protocol_gw_gw_mcs_harness() { build protocol-gw/gw-mcs-harness && run gw-mcs 60 "$UT/protocol-gw/gw-mcs-harness/build/harness/gw_mcs_harness" && has "RESULT: ALL PASS (0 failures)"; }
p_protocol_gw_gw_multi_crc_probe() { build protocol-gw/gw-multi-crc-probe && run gw-multi-crc 60 "$UT/protocol-gw/gw-multi-crc-probe/build/gw_multi_crc_probe/gw_multi_crc_probe" && has "RESULT: ALL PASS"; }
p_protocol_gw_gw_rsv_harness() { build protocol-gw/gw-rsv-harness && run gw-rsv 60 "$UT/protocol-gw/gw-rsv-harness/build/harness/gw_rsv_harness" && has "=> PASS"; }
p_protocol_gw_gw_topo_merge_probe() {   # 多站点 GW 帧 topo 事件合并(首事件 + extras + pairs 全并);其 .bin 也是 orig-src-probe 的输入
    build protocol-gw/gw-topo-merge-probe || return 1
    local d; d=$(rundir gw-topo-merge)
    run gw-topo-merge 60 "$UT/protocol-gw/gw-topo-merge-probe/build/gw_topo_merge_probe" \
        "$UT/protocol-gw/gw-topo-merge-probe/gw_topo_merge.bin" "$d/topo_merge_out.txt" \
        && has "AGG frames=3 PASS=3 FAIL=0" && lacks "=> FAIL"
}
p_protocol_gw_gw2026_tree_probe() {
    build protocol-gw/gw2026-tree-probe || return 1
    local B="$UT/protocol-gw/gw2026-tree-probe/build/probe/gw2026_tree_probe" f=0
    run gw2026-tree-ofdma 60 "$B" "$FP/gw2026_ofdma_sim.bin" && has "mpdu bytes: 440" "accept=1 reject_reason=" "PB CRC24 [24b] = OK" || f=1
    run gw2026-tree-tda 60 "$B" "$FP/gw2026_tda_sim.bin" && has "mpdu bytes: 304" "accept=1 reject_reason=" "PB CRC24 [24b] = OK" || f=1
    return $f
}

# ---- protocol-nw ----
p_protocol_nw_coord_probe() {   # NW_2021 COORD/版本分布统计(入库抓包)
    build protocol-nw/coord-probe && run coord 120 "$UT/protocol-nw/coord-probe/build/probe_coord/probe_coord" "$RT" \
        && has "total=2457 accepted=2429" "COORD total=1069 rf=0" "coord_joint:"
}
p_protocol_nw_frame_probe_variant() {   # 同 frame-probe + 绕过 pb_num 门控直喂 MSDU
    build protocol-nw/frame-probe-variant || return 1
    local B="$UT/protocol-nw/frame-probe-variant/build/probe/nw_frame_probe_variant" f=0
    run fpv-1021 30 "$B" "$FP/nw_frame_20261021.bin" && has "accept=1" "msdu: present=1" || f=1
    run fpv-1022full 30 "$B" "$FP/nw_frame_20261022_full.bin" && has "accept=1" "msdu: present=1" "BID=0x02" || f=1
    run fpv-tail-crc 30 "$B" "$FP/nw_log_tail_pb_crc_fail.bin" && has "accept=1" "msdu: present=1" "BID=0x03" || f=1
    run fpv-1022c 30 "$B" "$FP/nw_frame_20261022c.bin" && has "accept=1" || f=1
    return $f
}
p_protocol_nw_frame_probe_variant3() {
    build protocol-nw/frame-probe-variant3 || return 1
    local B="$UT/protocol-nw/frame-probe-variant3/build/probe/nw_msdu_probe" f=0 x
    for x in 20261021 20261022 20261022_full 20261022b 20261022c; do
        run "fpv3-$x" 30 "$B" "$FP/nw_frame_$x.bin" && has "present=1" "MAC Header [4B]" || f=1
    done
    return $f
}
p_protocol_nw_learn_probe() {   # NW_2026 TEI↔MAC 学习:级联 / DL-OFDMA / Gather / TEI 列表
    build protocol-nw/learn-probe || return 1
    local C="$UT/protocol-nw/learn-probe/crafted"
    run learn 60 "$UT/protocol-nw/learn-probe/build/learn_probe" files \
        "$C/craft_cascade.bin" "$C/craft_dl_ofdma.bin" "$C/craft_gather.bin" "$C/craft_teilist.bin" "$C/craft_ul_data.bin" || return 1
    has "scanned 5 frames" \
        "FRAME idx=1 accept=1 ftype=1 ver=2 beacon=0 b_pairs=0 msdu_pairs=4" \
        "PAIR idx=1 cat=msdu tei=3 mac=02:00:00:00:00:03" \
        "PAIR idx=2 cat=src tei=1 mac=02:00:00:00:00:01" "PAIR idx=2 cat=dst tei=2 mac=02:00:00:00:00:02" \
        "mme=0x003a" "PAIR idx=3 cat=msdu tei=2 mac=02:00:00:00:00:02" "PAIR idx=3 cat=msdu tei=3 mac=02:00:00:00:00:03" \
        "mme=0x0084" "PAIR idx=4 cat=msdu tei=2 mac=02:00:00:00:00:02" "PAIR idx=4 cat=msdu tei=3 mac=02:00:00:00:00:03" \
        && count "FRAME idx=" 4 && lacks "FRAME idx=5"
}
p_protocol_nw_main_nw_mme_probe() {   # 7 个 MME 系列程序(抓包驱动;入库样本无 MME 帧,验证构建 + 全流程跑通 + 计数)
    build protocol-nw/main-nw-mme-probe || return 1
    local D="$UT/protocol-nw/main-nw-mme-probe/build" f=0 b
    for b in probe/main_nw_mme_probe probe_cnf/probe_cnf probe_cnf_sf/probe_cnf probe_ind_sf/probe_cnf probe_req_sf/probe_cnf; do
        run "mme-${b%%/*}" 120 "$D/$b" "$RT" && has "total 2457, accepted 2429" || f=1
    done
    run mme-sof 120 "$D/probe_sof/main_nw_mme_sof_probe" "$RT" && has "total 2457, accepted 2429" "--- PLC SOF tree" || f=1
    run mme-audit 120 "$D/probe_audit/probe_audit" "$RT" && has "class ft0/PLC" "class ft1/PLC" "class ft2/PLC" "class ft3/PLC" || f=1
    return $f
}
p_protocol_nw_main_nw_probe() {
    build protocol-nw/main-nw-probe && run main-nw 120 "$UT/protocol-nw/main-nw-probe/build/probe/main_nw_probe" "$RT" \
        && has "total 2457, accepted 2429, rf accepted 0" "--- PLC SOF tree" "PB Size | 520"
}
p_protocol_nw_mg_probe() {   # 合成 MMe 0x9999 / 不支持版本 255 → 保留类型照常出树、CRC32 OK
    build protocol-nw/mg-probe && run mg 30 "$UT/protocol-nw/mg-probe/build/mg_probe/mg_probe" \
        && has "MMe 0x9999" "255" "tree.size=9" "node: MSDU CRC32 = 0x" " OK"
}
p_protocol_nw_nw_mcs_harness() { build protocol-nw/nw-mcs-harness && run nw-mcs 60 "$UT/protocol-nw/nw-mcs-harness/build/harness/nw_mcs_harness" && has "RESULT: ALL PASS (0 failures)"; }
p_protocol_nw_nw_mcs_harness_mg() {
    same_as_original protocol-nw/nw-mcs-harness-mg protocol-nw/nw-mcs-harness || return 1
    build protocol-nw/nw-mcs-harness-mg && run nw-mcs-mg 60 "$UT/protocol-nw/nw-mcs-harness-mg/build/harness/nw_mcs_harness" && has "RESULT: ALL PASS (0 failures)"
}
p_protocol_nw_nw_rf_harness() { build protocol-nw/nw-rf-harness && run nw-rf 60 "$UT/protocol-nw/nw-rf-harness/build/harness/nw_rf_harness" && has "SYNTH RESULT: PASS"; }
p_protocol_nw_nw_rf_harness_mg() {
    same_as_original protocol-nw/nw-rf-harness-mg protocol-nw/nw-rf-harness || return 1
    build protocol-nw/nw-rf-harness-mg && run nw-rf-mg 60 "$UT/protocol-nw/nw-rf-harness-mg/build/harness/nw_rf_harness" && has "SYNTH RESULT: PASS"
}
p_protocol_nw_nw2026_frame_test() {
    build protocol-nw/nw2026-frame-test && run nw2026-frame 30 "$UT/protocol-nw/nw2026-frame-test/build/probe/frame_test" \
        "$UT/topo/topo-route-verify/user_frame_container.bin" 0 && has "frame 1 accept=1 fch_ok=1" "msdu_present=1"
}
p_protocol_nw_nw2026_ul_probe() {
    build protocol-nw/nw2026-ul-probe && run nw2026-ul 30 "$UT/protocol-nw/nw2026-ul-probe/build/probe/nw2026_ul_probe" \
        "$FP/nw2026_trigger.bin" "$FP/nw2026_ul_ofdma_data.bin" "$FP/nw2026_dl_sack.bin" \
        && has "[trigger type2] len=32 accept=1" "[ul_data type1] len=296 accept=1" "[dl_sack type1] len=32 accept=1"
}
p_protocol_nw_trunc_stats_probe() {   # 3 个 .pro 共用 TARGET,各自 build/<name>/
    build protocol-nw/trunc-stats-probe || return 1
    local f=0 b
    for b in probe probe_merged probe_sf; do
        run "trunc-$b" 120 "$UT/protocol-nw/trunc-stats-probe/build/$b/trunc_stats_probe" "$RT" && has "total 2457 accepted 2429" || f=1
    done
    return $f
}

# ---- storage ----
p_storage_golden() {   # 盘块序列化:无损往返 + 与入库 v<block_version> golden 内容一致
    build storage/golden || return 1
    local d; d=$(rundir golden)
    (cd "$d" && run golden 60 "$UT/storage/golden/build/golden/golden" --check "$UT/storage/golden") && OUT="$LOGD/golden.out" && has "RESULT: ALL PASS (0 failures)"
}

# ---- 运行期 / 线程 / UI ----
p_io_reader_garbage_probe() {   # 回放切帧 + Reader 生命周期(M5/L4/L5)
    build io/reader-garbage-probe || return 1
    local d; d=$(rundir reader-garbage)
    cp "$UT/io/reader-garbage-probe/build/reader_garbage_probe/reader_garbage_probe" "$d/" || return 1
    (cd "$d" && run reader-garbage 180 ./reader_garbage_probe) && OUT="$LOGD/reader-garbage.out" && has "reader_garbage_probe: OK (0 failures)" && lacks "FAIL "
}
p_ui_paging_race_probe() {   # PacketListModel 盘块换页竞态(M2/M3/M4)
    build ui/paging-race-probe || return 1
    local d; d=$(rundir paging-race)
    cp "$UT/ui/paging-race-probe/build/paging_race_probe/paging_race_probe" "$d/" || return 1
    (cd "$d" && run paging-race 180 ./paging_race_probe) && OUT="$LOGD/paging-race.out" \
        && has "paging_race_probe: OK (0 failures)" && lacks "FAIL "
}
p_plugin_plugin_ipc_thread_probe() {   # PluginManager 跨线程 IPC + 异步图形(真实 host 子进程)
    local host; host=$(plugin_host) || { echo "  FAIL: bplc-plugin-host 构建失败"; return 1; }
    build plugin/plugin-ipc-thread-probe || return 1
    local d; d=$(rundir plugin-ipc-thread)
    cp "$UT/plugin/plugin-ipc-thread-probe/build/plugin_ipc_thread_probe/plugin_ipc_thread_probe" "$host" "$d/" || return 1
    # 迟到量判定已扣除等 CPU 的调度排队时间(见探针 README),无需重试;300 s 只防挂死
    (cd "$d" && run plugin-ipc-thread 300 ./plugin_ipc_thread_probe) && OUT="$LOGD/plugin-ipc-thread.out" \
        && has "RESULT: ALL PASS (0 failures)" && lacks "wait_response called on the GUI thread"
}
p_common_i18n_concurrency_probe() {   # i18n 词典并发(M6),ThreadSanitizer
    local d; d=$(rundir i18n-tsan) f=0
    # ① TSan 自检:故意有数据竞争的程序必须被报出来,证明本 runner 上 TSan 真的生效
    #   (ubuntu-24.04 内核 mmap_rnd_bits=32 时 TSan 直接 FATAL,CI 先把它调到 28)
    printf '#include <thread>\nint g;\nint main(){std::thread t([]{for(int i=0;i<100000;++i)++g;});for(int i=0;i<100000;++i)++g;t.join();return g==1;}\n' > "$d/race.cpp"
    g++ -std=c++17 -fsanitize=thread -g -O1 "$d/race.cpp" -o "$d/race" -pthread || { echo "  FAIL: TSan 自检程序编译失败"; return 1; }
    OUT="$LOGD/tsan-selfcheck.out"
    TSAN_OPTIONS=halt_on_error=1 timeout 60 "$d/race" > "$OUT" 2>&1
    if grep -qF "WARNING: ThreadSanitizer: data race" "$OUT"; then echo "  ok: TSan 自检报出数据竞争(TSan 生效)"; else echo "  FAIL: TSan 自检未报竞争"; tail -20 "$OUT" | sed 's/^/    | /'; return 1; fi
    # ② 探针用 CONFIG+=tsan(-fsanitize=thread)构建,确认二进制确实带 TSan 运行时
    (cd "$d" && qmake "$UT/common/i18n-concurrency-probe/i18n_concurrency_probe.pro" CONFIG+=tsan && make -j"$JOBS") || return 1
    if nm "$d/i18n_concurrency_probe" 2>/dev/null | grep -q "__tsan_init" || ldd "$d/i18n_concurrency_probe" | grep -q libtsan; then
        echo "  ok: i18n_concurrency_probe 链接了 TSan 运行时"
    else echo "  FAIL: i18n_concurrency_probe 未带 -fsanitize=thread"; return 1; fi
    # ③ halt_on_error=1:任何数据竞争报告即非 0 退出
    (cd "$d" && export TSAN_OPTIONS="halt_on_error=1 second_deadlock_stack=1" && run i18n-tsan 300 ./i18n_concurrency_probe) || f=1
    OUT="$LOGD/i18n-tsan.out"
    lacks "WARNING: ThreadSanitizer" || f=1
    has "i18n_concurrency_probe: OK" "wrong=0" || f=1
    return $f
}
p_wireshark_lua_lang_path_test() {   # Wireshark Lua 插件语言文件路径 + system_is_chinese(不需要 Wireshark)
    run lang-path 120 bash "$UT/wireshark-lua/lang-path-test/run.sh" && has "RESULT: ALL PASS (76/76 passed, 0 failures)"
}
p_app_mirror_probe() {   # 更新镜像解析:需联网(raw.githubusercontent / cloudflare trace / country.is / ipwho.is)
    build app/mirror-probe || return 1
    local f=0 one
    for one in probe/mirror_probe probe_fb/mirror_probe_fb; do
        # config.ini 写到二进制同目录(build/ 已 git-ignore);外部服务偶发超时 ⇒ 失败重试一次
        local B="$UT/app/mirror-probe/build/$one" tag="mirror-${one%%/*}"
        if ! (cd "$(dirname "$B")" && run "$tag" 90 "./$(basename "$B")" auto); then
            echo "  首次失败(外部网络),重试一次"
            (cd "$(dirname "$B")" && run "$tag" 90 "./$(basename "$B")" auto) || { f=1; continue; }
        fi
        OUT="$LOGD/$tag.out"; has "RESOLVED effective=" || f=1
    done
    return $f
}
p_app_plugin_autotest() {   # 主程序 CONFIG+=plugin_autotest:回放后给各插件面板与主窗口截图并退出
    local host; host=$(plugin_host) || { echo "  FAIL: bplc-plugin-host 构建失败"; return 1; }
    local b="$WORK/app-autotest"
    mkdir -p "$b"
    (cd "$b" && qmake "$REPO/BPLC_STA_Monitor.pro" CONFIG+=release CONFIG-=debug CONFIG+=crash_no_default CONFIG+=plugin_autotest \
        && make -j"$JOBS") > "$LOGD/app-autotest-build.log" 2>&1 || { echo "  FAIL: 主程序构建失败"; tail -40 "$LOGD/app-autotest-build.log" | sed 's/^/    | /'; return 1; }
    cp -f "$host" "$b/" || return 1
    local shots="$WORK/run/plugin-autotest-shots"; rm -rf "$shots"
    (cd "$b" && run plugin-autotest 900 ./BPLC_STA_Monitor -platform offscreen --plugins-dir "$REPO/src/plugin/examples" \
        --replay "$RT" --plugin-autotest "$shots") || return 1
    OUT="$LOGD/plugin-autotest.out"
    has "[autotest] reader finished" "[autotest] shoot start" || return 1
    local n; n=$(ls "$shots"/plugin_*.png 2>/dev/null | wc -l)
    if [ -s "$shots/main.png" ] && [ "$n" -ge 1 ]; then echo "  ok: 截图 main.png + $n 张 plugin_*.png"; ls -la "$shots" | sed 's/^/    | /'
    else echo "  FAIL: 截图缺失(main.png / plugin_*.png=$n)"; ls -la "$shots" 2>&1 | sed 's/^/    | /'; return 1; fi
}

# ======================= 主循环 =======================
[ $# -gt 0 ] || { echo "用法: QT_ROOT=... bash unit_test/ci/probe_suite.sh <探针目录>..." >&2; exit 2; }
pass=0; fail=0; failed=()
for dir in "$@"; do
    fn="p_$(echo "${dir%/}" | tr '/-' '__')"
    gh "::group::$dir"
    echo "== $dir =="
    t0=$(date +%s)
    if ! declare -F "$fn" >/dev/null; then
        echo "  FAIL: probe_suite.sh 未登记 $dir(需新增 $fn)"; rc=1
    else
        "$fn" 2>&1 | tee "$LOGD/$(echo "${dir%/}" | tr '/' '_').log"; rc=${PIPESTATUS[0]}
    fi
    gh "::endgroup::"
    if [ $rc -eq 0 ]; then pass=$((pass+1)); echo "PASS $dir ($(( $(date +%s) - t0 )) s)"
    else fail=$((fail+1)); failed+=("$dir"); echo "FAIL $dir ($(( $(date +%s) - t0 )) s)"; gh "::error::probe $dir failed(日志见上方分组 / $LOGD)"; fi
done
echo "PROBE SUITE: pass=$pass fail=$fail"
for f in "${failed[@]:-}"; do [ -n "$f" ] && echo "  FAILED: $f"; done
[ $fail -eq 0 ]
