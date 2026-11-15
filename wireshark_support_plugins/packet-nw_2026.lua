--[[
    packet-nw_2026.lua
    南网 SPLC 2026 (NW_2026, 通感一体化高速载波) 数据链路层协议 dissector
    依据: 《通感一体化低压电力线宽带载波通信(SPLC)规约 第4部分: 数据链路层通信协议(试行)》
          与《计量自动化系统...第2部分》(无线), 字段坐标对照 Qt 监控器
          src/protocol/nw_protocol/nw_2026/* (nw_2026_parser.cpp 等)。

    入口(重要): 本文件不注册 wtap_encap。packet-nw_2021.lua 的 nw.dissector 入口做版本
    分派(FCH byte12 高 nibble 标准版本号==2 即 SPLC), 整帧 Dissector.get("nw_2026"):call
    委托到本文件; 收到的 tvb 为裸 MPDU(FCH 16B 起, USER5 串口混合格式的 4B 媒介头已被
    委托方剥离), tree 为根。版本=1(BPLC)/0(保留) 帧仍由 packet-nw_2021.lua 解析, 但两类例外
    经入口分派进入本文件本地解析: ① 载波 SOF version≠2 但 PB 头聚合标志(表47 byte2 bit0)=1
    的聚合 BPLC 帧(BPLC 表20 布局 + 级联 MAC 帧拆分); ② 载波 SOF version=1 非聚合但承载
    SPLC 扩展 MMe 0x0080-0x0085 的帧(实网设备以 version=1 承载 SPLC 表77 扩展消息,
    BPLC 第2部分无定义, 预读 MSDU 帧类型/MMe 类型后分派)。

    与 BPLC(2021, packet-nw_2021.lua) 的主要差异:
      - SNID 5bit: 低4b 在 FCH(0,4,4), 高位按帧型合并(SOF/COORD 12,0,1 / 信标载波 12,1,1 /
        信标无线 12,0,1 / ACK 4,0,1)
      - 载波 SOF(表23-26): 多站点帧标识(4,0,1)/训练帧标识(4,1,1) 分派; 单站点帧
        PB个数(4,2-5)/Bitloading(6,0,1)/TMI编号(6,1-5); DL-OFDMA(表27) eFC 16B 自字节16,
        PB 基址 32; 训练帧无数据物理块
      - 无线 SOF(表131): 帧长(5,0,12)/载荷PB大小(6,4,4)/MCS(7,0,4)/重传(7,5,1), 单块
      - PB 块 = PB头(4B) + 块体(PBSize-8) + 保留(1B) + CRC24(3B) (国网为 1B 头, 不同)
      - 信标载荷固定头(表51): PLC能力指示/无线信道/通道数/网络版本号/信标机制状态/
        发现信标使能 等增量字段
      - MAC 帧头 12B 短头/32B 长头; 单跳帧版本=2(表113/114, 无线信道)
      - 管理消息 MMe 头 6B; NW MAC/MSDU/APP 字段前缀 nw_2026.*

    ★ 字节序约定: 字节内 bit0=LSB; 跨字节 bit 字段 little-endian bit 序(read_bits);
      整字节多字节字段 little-endian; CRC24/CRC32 校验"前 len-3/len-4 字节"。

    覆盖: FCH/信标(表51+管理条目)/SOF(表23-27+表131)/ACK(4种扩展)/网间协调(表41)/
          PB 块(多块重组)/MAC 帧(长短头+单跳)/MMe 全集/APP 报文/无线发现列表(表214-227)/
          IoT(0x00A0-0x00A2)/FCCS·PB CRC24·BPCS·MSDU ICV 校验。

    使用: tshark -r capture.pcap -X lua_script:packet-nw_2021.lua -X lua_script:packet-nw_2026.lua -V
          (pcap linktype: USER2=149 载波 / USER3=150 无线, 由 bin2pcap.py --nw 生成)
]]

-- Wireshark Lua 位运算: 标准版有 bit 库, 但为兼容所有环境(含定制版无 bit 库),
-- 全部用纯算术实现, 不依赖 bit/bit32/原生 & 运算符.
local function band(a, b)  -- 按位与
    local r, p = 0, 1
    while a > 0 and b > 0 do
        if a % 2 == 1 and b % 2 == 1 then r = r + p end
        a, b, p = math.floor(a / 2), math.floor(b / 2), p * 2
    end
    return r
end

-- 按位异或 (纯算术, 不依赖 bit 库)
local function bxor(a, b)
    local r, p = 0, 1
    while a > 0 or b > 0 do
        local ba, bb = a % 2, b % 2
        if ba ~= bb then r = r + p end
        a, b, p = math.floor(a / 2), math.floor(b / 2), p * 2
    end
    return r
end

-- CRC24 (poly=0xC60001, init=0, LSB-first, 校验前 len-3 字节, 结果末 3B 小端)
-- 与 Qt fieldspec.h crc24_lsb / Python MPDU_Class.cal_crc24 一致 (GW_2022/NW_2021 同算法)
local crc24_table = {}
for v = 0, 255 do
    local crc = v
    for _ = 1, 8 do
        if band(crc, 1) == 1 then
            crc = bxor(math.floor(crc / 2), 0xC60001)
        else
            crc = math.floor(crc / 2)
        end
    end
    crc24_table[v] = band(crc, 0xFFFFFF)
end

local function crc24_lsb(tvb, off, len)
    local crc = 0
    for i = 0, len - 3 - 1 do
        local idx = band(bxor(crc, tvb(off + i, 1):uint()), 0xFF)
        crc = bxor(math.floor(crc / 256), crc24_table[idx])
    end
    return band(crc, 0xFFFFFF)
end

-- CRC32 (poly=0xEDB88320, init=0xFFFFFFFF, LSB-first, 末取反, 校验前 len-4 字节)
-- 与 Qt fieldspec.h crc32_le / Python cal_crc32 一致 (MSDU ICV/信标 BPCS 同算法)
local crc32_table = {}
for v = 0, 255 do
    local crc = v
    for _ = 1, 8 do
        if band(crc, 1) == 1 then
            crc = bxor(math.floor(crc / 2), 0xEDB88320)
        else
            crc = math.floor(crc / 2)
        end
    end
    crc32_table[v] = crc
end

local function crc32_le(tvb, off, len)
    local crc = 0xFFFFFFFF
    for i = 0, len - 4 - 1 do
        local idx = band(bxor(crc, tvb(off + i, 1):uint()), 0xFF)
        crc = bxor(math.floor(crc / 256), crc32_table[idx])
    end
    return bxor(crc, 0xFFFFFFFF)  -- 末取反
end

-- 语言开关: 与 GW_2022 相同策略 (界面语言 → Wireshark 个人配置目录的 language 文件, 环境变量可覆盖)
local function system_is_chinese()
    -- 1) 区域设置环境变量 (POSIX 优先级 LC_ALL > LC_MESSAGES > LANG, 首个非空者决定; 都没设再看 GNU LANGUAGE)
    local function env(name)
        local v = os.getenv(name)
        if v and v ~= "" then return v end
        return nil
    end
    local lc = env("LC_ALL") or env("LC_MESSAGES") or env("LANG")
    if lc then
        if lc:lower():match("^zh") then return true end
    else
        local language = env("LANGUAGE")
        if language and language:lower():match("^zh") then return true end
    end
    -- 2) 仅 Windows: 注册表 LocaleName (如 zh-CN; GUI 从桌面启动时通常无 LANG)
    --    非 Windows 绝不执行: POSIX shell 会把 "2>nul" 当成重定向到当前目录下名为 nul 的文件并创建它,
    --    而且 Linux/macOS 上本就没有 reg 命令
    local sep = (type(package) == "table" and type(package.config) == "string"
                 and package.config:sub(1, 1)) or "/"
    if sep ~= "\\" or lc then return false end
    if type(io) ~= "table" or type(io.popen) ~= "function" then return false end
    local ok, h = pcall(io.popen, 'reg query "HKCU\\Control Panel\\International" /v LocaleName 2>nul')
    if ok and h then
        local out = h:read("*a") or ""
        h:close()
        if out:lower():match("zh%-") then return true end
    end
    return false
end

-- Wireshark 界面语言文件路径 (跨平台, 取不到返回 nil, 调用方回退默认语言, 绝不抛错)
--   Windows : %APPDATA%\Wireshark\language
--   其他平台: 优先 Wireshark API Dir.personal_config_path("language") (pcall 包住, 存在才用),
--             否则 $XDG_CONFIG_HOME/wireshark/language, 再否则 $HOME/.config/wireshark/language
--             (macOS 的 Wireshark 同样用 ~/.config/wireshark)
-- 旧代码 os.getenv("APPDATA") .. "\\Wireshark\\language" 在 Linux/macOS 上 getenv 返回 nil,
-- 拼接抛错导致整个插件加载失败
local function wireshark_language_file()
    local sep = (type(package) == "table" and type(package.config) == "string"
                 and package.config:sub(1, 1)) or "/"
    local function env(name)
        local v = os.getenv(name)
        if v and v ~= "" then return v end
        return nil
    end
    local function ws_api_path()
        if type(Dir) ~= "table" and type(Dir) ~= "userdata" then return nil end
        local ok_get, fn = pcall(function() return Dir.personal_config_path end)
        if not ok_get or type(fn) ~= "function" then return nil end
        local ok, p = pcall(fn, "language")
        if ok and type(p) == "string" and p ~= "" then return p end
        return nil
    end
    if sep == "\\" then
        local appdata = env("APPDATA")
        if appdata then return appdata .. "\\Wireshark\\language" end
        return ws_api_path()
    end
    local p = ws_api_path()
    if p then return p end
    local xdg = env("XDG_CONFIG_HOME")
    if xdg then return xdg .. sep .. "wireshark" .. sep .. "language" end
    local home = env("HOME")
    if home then return home .. sep .. ".config" .. sep .. "wireshark" .. sep .. "language" end
    return nil
end

local function detect_english()
    -- 1) 环境变量覆盖 (NW_2021_LANG=en/zh)
    local env = os.getenv("NW_2021_LANG")
    if env == "en" then return true end
    if env == "zh" then return false end
    -- 2) 读 Wireshark language 文件
    local lang_file = wireshark_language_file()
    local f = lang_file and io.open(lang_file, "r")
    if f then
        local content = f:read("*a")
        f:close()
        local lang = content:match("language:%s*(%S+)")
        if lang then
            if lang:lower():match("^zh") then return false end
            if lang:lower():match("^en") then return true end
            return not system_is_chinese()
        end
    end
    -- 3) 回退: 系统语言
    return not system_is_chinese()
end

local nw_english = detect_english()

-- 双语显示名: 按界面语言返回中文或英文
local function T(zh, en)
    if nw_english then return en end
    return zh
end

local nw = Proto("nw_2026", T("南网NW_2026 双模通信数据链路层协议(SPLC)", "NW_2026 Dual-Mode Data Link Layer Protocol (SPLC)"))

-- =========================================================================
-- TEI ↔ MAC 映射表 (按 SNID 分组)
-- 从历史帧学习: 关联确认/关联指示/关联汇总/发现列表/信标站点能力条目 都携带 TEI+MAC
-- 之后在 Source/Destination 列附加显示 MAC 地址
-- =========================================================================
local tei_mac_map = {}   -- tei_mac_map[snid][tei] = "xx:xx:xx:xx:xx:xx"
local cur_snid = 0       -- 当前解析帧的 SNID (主 dissector 设置)

-- 6 字节 MAC → "xx:xx:xx:xx:xx:xx"
local function mac_to_str(tvb, off)
    if off + 6 > tvb:len() then return nil end
    return string.format("%02x:%02x:%02x:%02x:%02x:%02x",
        tvb(off,1):uint(), tvb(off+1,1):uint(), tvb(off+2,1):uint(),
        tvb(off+3,1):uint(), tvb(off+4,1):uint(), tvb(off+5,1):uint())
end

-- 记录 TEI → MAC (TEI=0 未分配 / 0xFFF 广播不记录)
local function record_tei_mac(tei, mac_str)
    if not tei or tei == 0 or tei == 0xFFF or not mac_str then return end
    if not tei_mac_map[cur_snid] then tei_mac_map[cur_snid] = {} end
    tei_mac_map[cur_snid][tei] = mac_str
end

-- 查询 TEI → MAC, 无则返回 nil
local function lookup_tei_mac(snid, tei)
    local m = tei_mac_map[snid]
    if not m then return nil end
    return m[tei]
end

-- =========================================================================
-- value_string 表
-- =========================================================================
local dt_vals = {
    [0] = T("信标帧", "Beacon"), [1] = T("SOF", "SOF"),
    [2] = T("ACK 确认帧", "ACK"), [3] = T("网间协调帧", "Coordination"),
}
local ack_ext_type_vals = {
    [0] = T("常规 ACK", "Normal ACK"), [1] = T("网络搜索帧", "Network Search"),
    [2] = T("同步帧", "Sync"),
    -- 表33:3 = Bitloading 扩展帧(可变区域按 Bitloading 帧类型细分,表35-40)
    [3] = T("Bitloading 扩展帧", "Bitloading Extended Frame"),
    [10] = T("时隙预约(南网扩展)", "Slot Reservation"), [11] = T("测距响应(南网扩展)", "Ranging Response"),
    [12] = T("测距请求(南网扩展)", "Ranging Request"),
}
-- Bitloading 帧类型(表35-40):0 训练指示/1 拒绝/2 请求/3 请求拒绝/4 取消请求/5 取消确认
local bl_type_vals = {
    [0] = T("训练指示", "Training Indication"), [1] = T("训练指示拒绝", "Training Indication Reject"),
    [2] = T("训练请求", "Training Request"), [3] = T("训练请求拒绝", "Training Request Reject"),
    [4] = T("训练取消请求", "Training Cancel Request"), [5] = T("训练取消确认", "Training Cancel Confirm"),
}
local beacon_type_vals = {
    [0] = T("发现信标", "Discovery Beacon"), [1] = T("代理信标", "Proxy Beacon"), [2] = T("中央信标", "Central Beacon"),
}
-- 相线: 信标可变区域/关联请求用 (0=未知); 站点能力/CSMA时隙用 (0=全相线)
local phase_unk_vals = {
    [0] = T("未知", "Unknown"), [1] = T("A相线", "Line A"), [2] = T("B相线", "Line B"), [3] = T("C相线", "Line C"),
}
local phase_all_vals = {
    [0] = T("全相线", "All lines"), [1] = T("A相线", "Line A"), [2] = T("B相线", "Line B"), [3] = T("C相线", "Line C"),
}
local role_vals = {
    [0] = T("未知", "Unknown"), [1] = T("站点 STA", "STA"), [2] = T("代理站点 PCO", "PCO"), [4] = T("中央协调器 CCO", "CCO"),
}
local beacon_entry_type_vals = {
    [0x01] = T("站点能力条目", "STA Capability Item"), [0x02] = T("时隙分配条目", "Time Slot Allocation Item"),
    [0x06] = T("路由参数条目", "Route Parameter Item"), [0x07] = T("频段变更条目", "Band Change Item"),
    [0x0A] = T("频段探测条目", "Band Probe Item"), [0x0B] = T("万年历同步条目", "Calendar Sync Item"),
    -- 表142 分配 0x0C/0x0D/0x0E(表152/153 头列旧编号残留)/0x0F 信标机制切换(表71)/0x10 代理角色(表72)
    [0x0C] = T("无线路由参数条目", "RF Route Parameter Item"),
    [0x0D] = T("无线信道变更条目", "RF Channel Change Item"),
    [0x0E] = T("精简信标站点信息及时隙条目", "Lite Beacon STA Info & Slot Item"),
    [0x0F] = T("信标机制切换条目", "Beacon Mechanism Switch Item"),
    [0x10] = T("代理角色条目", "Proxy Role Item"),
}
-- 载波频段(表156,精简信标 0x0E 条目用)
local lite_band_vals = {
    [0] = T("1.953~11.96MHz", "1.953~11.96 MHz"), [1] = T("2.441~5.615MHz", "2.441~5.615 MHz"),
    [2] = T("0.781~2.930MHz", "0.781~2.930 MHz"),
}
-- 切换目标机制ID(表71):0 集中/1 分散/其他保留
local mech_vals = {
    [0] = T("集中信标机制", "Central beacon mechanism"), [1] = T("分散信标机制", "Distributed beacon mechanism"),
}
local ncb_type_vals = { [0] = T("发现信标", "Discovery Beacon"), [1] = T("代理信标", "Proxy Beacon") }
local msdu_type_long_vals = {
    [0x88E1] = T("管理消息报文", "Management message"), [0x0001] = T("应用层报文", "Application packet"),
}
local msdu_type_short_vals = { [0x01] = T("应用层报文", "Application packet") }
-- MAC 头枚举与 Qt 监控器字典对齐(南网第5部分 表6/表7/表8;字典外值即保留)
local mac_version_vals = {
    [0] = T("保留", "Reserved"), [1] = T("本标准协议", "This standard"),
    [2] = T("单跳帧协议", "Single-hop frame protocol"), [3] = T("保留", "Reserved"),
}
local mac_send_type_vals = {
    [0] = T("单播,需要确认回应", "Unicast, ACK required"),
    [1] = T("全网广播,不需要回应", "Network broadcast, no ACK"),
    [2] = T("本地广播,不需要回应", "Local broadcast, no ACK"),
    [3] = T("全网广播,需要确认回应", "Network broadcast, ACK required"),
    [4] = T("本地广播,需要确认回应", "Local broadcast, ACK required"),
}
local mac_bcast_dir_vals = {
    [0] = T("保留", "Reserved"), [1] = T("下行广播", "Downlink broadcast"),
    [2] = T("上行广播", "Uplink broadcast"), [3] = T("保留", "Reserved"),
}
-- MCS 释义(南网第2部分 表129, 与国网表28 逐值相同)
local mcs_vals = {
    [0] = T("分集4次 BPSK 码率1/2", "diversity 4, BPSK, code rate 1/2"),
    [1] = T("分集2次 BPSK 码率1/2", "diversity 2, BPSK, code rate 1/2"),
    [2] = T("分集2次 QPSK 码率1/2", "diversity 2, QPSK, code rate 1/2"),
    [3] = T("分集1次 QPSK 码率1/2", "diversity 1, QPSK, code rate 1/2"),
    [4] = T("分集1次 QPSK 码率4/5", "diversity 1, QPSK, code rate 4/5"),
    [5] = T("分集1次 16QAM 码率1/2", "diversity 1, 16QAM, code rate 1/2"),
    [6] = T("分集1次 16QAM 码率4/5", "diversity 1, 16QAM, code rate 4/5"),
}
local mac_head_flag_vals = { [0] = T("长帧头(32B)", "Long head (32B)"), [1] = T("短帧头(12B)", "Short head (12B)") }
local mme_type_vals = {
    [0x0030] = T("关联请求 MMeAssocReq", "MMeAssocReq"),
    [0x0031] = T("关联确认 MMeAssocCnf", "MMeAssocCnf"),
    [0x0032] = T("代理变更请求 MMeChangeProxyReq", "MMeChangeProxyReq"),
    [0x0034] = T("关联指示 MMeAssocInd", "MMeAssocInd"),
    [0x0037] = T("代理变更确认 MMeChangeProxyCnf", "MMeChangeProxyCnf"),
    [0x003A] = T("关联汇总指示 MMeAssocGatherInd", "MMeAssocGatherInd"),
    [0x003B] = T("代理变更确认位图版 MMeChangeProxyBitMapCnf", "MMeChangeProxyBitMapCnf"),
    [0x0049] = T("离线指示 MMeLeaveInd", "MMeLeaveInd"),
    [0x0051] = T("心跳检测 MMeHeartBeatCheck", "MMeHeartBeatCheck"),
    [0x0055] = T("发现列表 MMeDiscoverNodeList", "MMeDiscoverNodeList"),
    [0x005D] = T("延迟离线指示 MMeDelayLeaveInd", "MMeDelayLeaveInd"),
    [0x005E] = T("通信成功率上报 MMeSuccessRateReport", "MMeSuccessRateReport"),
    [0x005F] = T("网络冲突上报 MMeNetworkConflictReport", "MMeNetworkConflictReport"),   -- SPLC-4 表129/BPLC-2 表204
    [0x0062] = T("过零NTB采集指示 MMeZeroCrossNTBCollectInd", "MMeZeroCrossNTBCollectInd"),
    [0x0063] = T("过零NTB上报 MMeZeroCrossNTBReport", "MMeZeroCrossNTBReport"),
    [0x0064] = T("网络诊断 MMeNetDiagnose", "MMeNetDiagnose"),
    [0x0070] = T("无线信道冲突上报 MMeRFChannelConflictReport", "MMeRFChannelConflictReport"),   -- SPLC-4 表137/BPLC-2 表212
    [0x0083] = T("站点TEI列表请求 MMeStationTEIListRequest", "MMeStationTEIListRequest"),
    [0x0084] = T("站点TEI列表响应 MMeStationTEIListResponse", "MMeStationTEIListResponse"),
    [0x0080] = T("Bitloading训练结果更新请求 MMeBitLoadUpdateReq", "MMeBitLoadUpdateReq"),
    [0x0081] = T("Bitloading训练结果更新确认 MMeBitLoadUpdateCnf", "MMeBitLoadUpdateCnf"),
    [0x0082] = T("RU_SNR信息告知 MMeRUSNRInfoInd", "MMeRUSNRInfoInd"),
    [0x0085] = T("扩展网络冲突上报 MMeExtNetConflictReport", "MMeExtNetConflictReport"),
    [0x00A0] = T("物联终端接入请求 MMeIoTAssocReq", "MMeIoTAssocReq"),   -- SPLC-4 表242/BPLC-2 表38 段
    [0x00A1] = T("物联终端接入确认 MMeIoTAssocInd", "MMeIoTAssocInd"),   -- SPLC-4 表242/BPLC-2 表38 段
    [0x00A2] = T("物联终端离线指示 MMeIoTLeaveInd", "MMeIoTLeaveInd"),   -- SPLC-4 表242/BPLC-2 表38 段
}

-- MMe 短名(聚合帧子帧摘要用, 与 C++ nw_2026_msdu_parser mme_type_name 对齐:
-- 中文短名不带英文后缀, 未分配类型统一带“保留”后缀, 如 "MMe 0x%04x (保留)")
local function mme_short_name(mmtype)
    local full = mme_type_vals[mmtype]
    if not full then
        return string.format("MMe 0x%04x (%s)", mmtype, T("保留", "Reserved"))
    end
    local short = full:match("^[^%s]+")
    return short or full
end
-- 关联确认结果 (表53)
local assoc_cnf_result_vals = {
    [0x00] = T("关联请求成功", "Association succeeded"), [0x01] = T("站点不在白名单中", "STA not in whitelist"),
    [0x03] = T("加入站点个数超过上限", "STA count over limit"), [0x04] = T("没有设置白名单列表", "No whitelist configured"),
    [0x05] = T("代理站点个数超过上限", "PCO count over limit"), [0x06] = T("子站点个数超过上限", "Child STA count over limit"),
    [0x08] = T("重复的MAC地址", "Duplicate MAC address"), [0x09] = T("超过拓扑层级", "Topology level exceeded"),
    [0x0A] = T("站点再次关联请求入网成功", "STA re-association succeeded"),
    [0x0B] = T("新站点试图以自己的子站点为代理入网", "New STA uses own child as proxy"),
    [0x0C] = T("组网拓扑中存在环路", "Loop in topology"), [0x0D] = T("CCO端未知原因出错", "CCO unknown error"),
}
-- 关联指示结果 (表58, 0x07=没有回复 / 0x0A=曾经入网再次入网)
local assoc_ind_result_vals = {
    [0x00] = T("关联请求成功", "Association succeeded"), [0x01] = T("站点不在白名单中", "STA not in whitelist"),
    [0x03] = T("加入站点个数超过上限", "STA count over limit"), [0x04] = T("没有设置白名单列表", "No whitelist configured"),
    [0x05] = T("代理站点个数超过上限", "PCO count over limit"), [0x06] = T("子站点个数超过上限", "Child STA count over limit"),
    [0x07] = T("没有回复", "No reply"), [0x08] = T("重复的MAC地址", "Duplicate MAC address"),
    [0x09] = T("超过拓扑层级", "Topology level exceeded"), [0x0A] = T("曾经入网的站点再次入网", "Former STA rejoined"),
    [0x0B] = T("新站点试图以自己的子站点为代理入网", "New STA uses own child as proxy"),
    [0x0C] = T("组网拓扑中存在环路", "Loop in topology"), [0x0D] = T("CCO端未知原因出错", "CCO unknown error"),
}
local last_pkt_vals = { [0] = T("不是最后一个分包", "Not last fragment"), [1] = T("是最后一个分包", "Last fragment") }
local proxy_change_reason_vals = { [1] = T("周期代理变更", "Periodic proxy change"), [2] = T("快速代理变更", "Fast proxy change") }
local proxy_change_result_vals = { [0] = T("变更成功", "Change succeeded") }
local gather_result_vals = { [0] = T("允许加入网络", "Allow join") }
local leave_reason_vals = {
    [0] = T("站点未入网却收到其报文", "STA not joined but packet received"),
    [2] = T("拓扑层级超过上限", "Topology level exceeds limit"), [4] = T("立即离线", "Leave immediately"),
}
local delay_leave_reason_vals = { [3] = T("站点不在最新白名单中", "STA not in latest whitelist") }
local route_type_vals = {
    [0] = T("错误路由类型", "Incorrect route"), [1] = T("同级路由类型", "Same-level route"),
    [2] = T("上级路由类型", "Upper-level route"), [3] = T("代理主路径路由类型", "Proxy main path route"),
    [4] = T("上上级路由类型", "Upper-upper-level route"),
}
local rate_calc_vals = { [0] = T("未完成", "Not finished"), [1] = T("已完成", "Finished") }
local device_type_vals = {
    [1] = T("抄控器", "Reader/CCO device"), [2] = T("集中器通信模块", "Concentrator comm module"),
    [3] = T("单相电表通信模块", "Meter comm module"), [4] = T("中继器", "Repeater"),
    [5] = T("II型采集器", "Type-II collector"), [6] = T("I型采集器", "Type-I collector"),
    [7] = T("三相表通信模块", "3-phase meter comm module"),
}
local mac_addr_type_vals = {
    [0] = T("电能表地址", "Meter address"), [1] = T("模块本身MAC地址", "Module MAC address"), [2] = T("采集器地址", "Collector address"),
}
local proxy_type_vals = { [2] = T("动态代理", "Dynamic proxy") }
local band_support_vals = { [0] = T("频段0和频段1", "Band 0 & 1"), [1] = T("频段0/1/2", "Band 0/1/2") }
local boot_reason_vals = { [0] = T("正常重启", "Normal boot") }
local band_vals = {
    [0] = T("频段0 (1.953~11.96)", "Band 0 (1.953~11.96)"),
    [1] = T("频段1 (2.441~5.615)", "Band 1 (2.441~5.615)"),
    [2] = T("频段2 (0.781~2.930)", "Band 2 (0.781~2.930)"),
    [3] = T("频段3 (0.781~11.963)", "Band 3 (0.781~11.963)"),
    [4] = T("频段4 (0.781~5.615)", "Band 4 (0.781~5.615)"),
    [5] = T("保留", "Reserved"), [6] = T("保留", "Reserved"), [7] = T("保留", "Reserved"),
}
local chip_id_vals = {
    [0] = T("保留", "Reserved"), [1] = "HS", [2] = "ES", [3] = "TC", [4] = "LH",
    [5] = "HT", [6] = "RS", [7] = "SW", [8] = "SC",
}
local collect_mode_vals = { [1] = T("下降沿采集", "Falling edge"), [2] = T("上升沿采集", "Rising edge") }
local app_port_vals = { [0x11] = T("业务报文", "Service packet"), [0x13] = T("管理报文", "Management packet") }
local app_packet_id_vals = { [0x0101] = T("CCO-STA 应用层报文", "CCO-STA APP packet") }
local app_packet_type_vals = {
    [0x0] = T("确认/否认", "ACK/NACK"), [0x1] = T("数据转发帧", "Data forward"),
    [0x2] = T("命令帧", "Command"), [0x3] = T("主动上报帧", "Event report"),
    [0x4] = T("抄控器相关协议", "Reader protocol"), [0x5] = T("广播命令帧", "Broadcast command"),
    [0x6] = T("数据订阅路由帧", "Data subscription route"), [0xE] = T("厂家调试", "Vendor debug"),
    [0xF] = T("厂测帧", "Factory frame"),
}

-- 业务标识(BID)释义: 依赖帧类型域(表9), 返回 nil 表示保留/无释义
local function business_id_name(port, ptype, bid)
    if ptype == 0x0 then
        if bid == 0x00 then return T("确认", "ACK") end
        if bid == 0x01 then return T("否认", "NACK") end
    elseif ptype == 0x1 then
        if bid == 0x00 then return T("数据透传至设备", "Forward to device") end
        if bid == 0x01 then return T("数据透传至模块", "Forward to module") end
    elseif ptype == 0x2 then
        if bid == 0x00 then return T("查询终端搜索结果", "Query search result") end
        if bid == 0x01 then return T("下发搜索终端列表", "Distribute search list") end
        if bid == 0x02 then return T("文件传输", "File transfer") end
        if bid == 0x03 then return T("允许/禁止从节点事件", "Enable/disable node event") end
        if bid == 0x04 then return T("从节点重启", "Reboot node") end
        if bid == 0x05 then return T("从节点信息查询", "Query node info") end
        if bid == 0x06 then return T("下发通信地址映射表列表", "Distribute address map") end
        if bid == 0x07 then return T("查询从节点运行状态信息", "Query node running status") end
        if bid == 0x08 then return T("查询从节点信道信息", "Query node channel info") end
        if bid == 0x10 then return T("台区户变关系/相位识别", "Station/phase identification") end
        if bid == 0xF0 then return T("测试帧", "Test frame") end
    elseif ptype == 0x3 then
        if bid == 0x00 then return T("电表事件主动上报", "Meter event report") end
        if bid == 0x01 then return T("停上电事件上报", "Power on/off event report") end
        if bid == 0x02 then
            if port == 0x13 then return T("通信模块事件上报", "Comm module event report") end
            return T("设备事件主动上报", "Device event report")
        end
    elseif ptype == 0x4 then
        if bid == 0x00 then return T("抄控器-CCO协议", "Reader-CCO protocol") end
        if bid == 0x01 then return T("数据透传串口转发", "Forward via UART") end
    elseif ptype == 0x5 then
        if bid == 0x04 then return T("从节点重启", "Reboot node") end
        if bid == 0x05 then return T("从节点信息查询", "Query node info") end
        if bid == 0x07 then return T("查询从节点运行状态信息", "Query node running status") end
        if bid == 0x08 then return T("查询从节点信道信息", "Query node channel info") end
    end
    return nil
end

-- =========================================================================
-- ProtoField 定义 (第一参数 = filter abbr, 统一 nw_2026. 前缀)
-- =========================================================================
local f = {}

-- MPDU 帧控制 (16B)
f.fc_dt = ProtoField.uint8 ("nw_2026.fc.dt", T("帧类型", "Frame Type"), base.DEC, dt_vals, 0x07)
f.fc_conind = ProtoField.bool ("nw_2026.fc.conind", T("接入指示(ConInd)", "Access Indication (ConInd)"), 8, nil, 0x08)
f.fc_snid = ProtoField.uint8 ("nw_2026.fc.snid", T("短网络标识(SNID)", "Short Network ID (SNID)"), base.HEX, nil, 0xF0)
f.fc_vf = ProtoField.bytes ("nw_2026.fc.vf", T("可变区域", "Variant Field"), base.NONE)
f.fc_std_ver = ProtoField.uint8 ("nw_2026.fc.std_ver", T("标准版本号", "Standard Version"), base.DEC, nil, 0xF0)
f.fc_fccs = ProtoField.uint24 ("nw_2026.fc.fccs", T("帧控制校验序列(FCCS,CRC24)", "Frame Control Check Sequence (FCCS, CRC24)"), base.HEX)
f.fc_fccs_calc = ProtoField.uint24 ("nw_2026.fc.fccs_calc", T("FCCS 计算值", "FCCS Calculated"), base.HEX)
f.fc_fccs_ok = ProtoField.bool ("nw_2026.fc.fccs_ok", T("FCCS 校验通过", "FCCS Check Passed"), 8, nil, 0x01)

-- 信标帧可变区域 (字节1-12, 载波/无线同坐标至源TEI)
f.beacon_bts = ProtoField.uint32 ("nw_2026.beacon.bts", T("信标时间戳(BTS,原始NTB)", "Beacon Timestamp (BTS, raw NTB)"), base.DEC)
f.beacon_bts_sec = ProtoField.double ("nw_2026.beacon.bts_sec", T("信标时间戳(秒)", "Beacon Timestamp (seconds)"), base.DEC)
f.beacon_bpc = ProtoField.uint32 ("nw_2026.beacon.bpc", T("信标周期计数(BPC)", "Beacon Period Count (BPC)"), base.DEC)
f.beacon_src_tei = ProtoField.uint16 ("nw_2026.beacon.src_tei", T("源TEI", "Source TEI"), base.DEC)
f.beacon_tmi = ProtoField.uint8 ("nw_2026.beacon.tmi", T("载波映射表索引(TMI)", "Tone Map Index (TMI)"), base.DEC, nil, 0xF0)
f.beacon_symbol_cnt = ProtoField.uint16 ("nw_2026.beacon.symbol_cnt", T("符号数", "Symbol Count"), base.DEC)
f.beacon_phase = ProtoField.uint8 ("nw_2026.beacon.phase", T("信标相线", "Beacon Line"), base.DEC, phase_unk_vals, 0x0C)
f.beacon_pblen = ProtoField.uint8 ("nw_2026.beacon.pblen", T("载荷PB大小(无线)", "Payload PB Size (RF)"), base.DEC, nil, 0x0F)
f.beacon_mcs = ProtoField.uint8 ("nw_2026.beacon.mcs", T("调制编码方式(MCS,无线)", "MCS (RF)"), base.DEC, mcs_vals, 0xF0)
f.beacon_rsv1 = ProtoField.uint8 ("nw_2026.beacon.rsv1", T("保留", "Reserved"), base.HEX, nil, 0xF0)
f.beacon_rsv2 = ProtoField.uint8 ("nw_2026.beacon.rsv2", T("保留", "Reserved"), base.HEX, nil, 0x0F)
f.beacon_rsv3 = ProtoField.uint8 ("nw_2026.beacon.rsv3", T("保留", "Reserved"), base.HEX, nil, 0x02)

-- SOF 帧可变区域 (字节1-12)
f.sof_src_tei = ProtoField.uint16 ("nw_2026.sof.src_tei", T("源TEI", "Source TEI"), base.DEC)
f.sof_dst_tei = ProtoField.uint16 ("nw_2026.sof.dst_tei", T("目的TEI", "Destination TEI"), base.DEC)
f.sof_lid = ProtoField.uint8 ("nw_2026.sof.lid", T("链路标识符(LID,无线)", "Link Identifier (LID, RF)"), base.DEC)
-- SPLC 载波 SOF(表23-26): 多站点帧标识/训练帧标识/OFDMA类型 同在字节4
f.sof_multi = ProtoField.uint8 ("nw_2026.sof.multi", T("多站点帧标识", "Multi-Station Frame Flag"), base.DEC, {[0]=T("单站点帧", "Single-station"), [1]=T("多站点帧", "Multi-station")}, 0x01)
f.sof_train = ProtoField.uint8 ("nw_2026.sof.train", T("训练帧标识", "Training Frame Flag"), base.DEC, {[0]=T("数据帧", "Data frame"), [1]=T("训练帧(无数据物理块)", "Training frame (no data PB)")}, 0x02)
f.sof_ofdma_type = ProtoField.uint8 ("nw_2026.sof.ofdma_type", T("OFDMA 帧类型(表26)", "OFDMA Frame Type (Table 26)"), base.DEC, {[0]=T("DL-OFDMA", "DL-OFDMA"),     [1]=T("DL-SACK/UL-OFDMA", "DL-SACK/UL-OFDMA"), [2]=T("Trigger", "Trigger"), [3]=T("UL-SACK", "UL-SACK")}, 0x06)
f.sof_bitload = ProtoField.uint8 ("nw_2026.sof.bitloading", T("Bitloading 标识(表23)", "Bitloading Flag (Table 23)"), base.DEC, {[0]=T("普通 TMI 编号", "Normal TMI index"), [1]=T("Bitloading TMI 编号", "Bitloading TMI index")}, 0x01)
f.sof_pb_num = ProtoField.uint8 ("nw_2026.sof.pb_num", T("物理块个数(表23)", "PB Count (Table 23)"), base.DEC, nil, 0x3C)
f.sof_tmi = ProtoField.uint8 ("nw_2026.sof.tmi", T("TMI 编号(表23)", "TMI Index (Table 23)"), base.DEC, nil, 0x3E)
f.sof_frame_len = ProtoField.uint16 ("nw_2026.sof.frame_len", T("帧长", "Frame Length"), base.DEC)
f.sof_tmi_ext = ProtoField.uint8 ("nw_2026.sof.tmi_ext", T("扩展TMI(TMI_EXT)", "Extended TMI"), base.DEC, nil, 0x0F)
f.sof_pblen = ProtoField.uint8 ("nw_2026.sof.pblen", T("载荷PB大小(无线)", "Payload PB Size (RF)"), base.DEC, nil, 0xF0)
-- 无线 SOF 表45 byte12 = SNID 高位(1b) + 保留(3b);表131 byte12 低半字节保留、无 SNID 高位语义,
-- 两表均未定义高半字节(12,4,4),按保留位渲染(不参与 SNID 合并);RF byte12 不用载波 TMI_EXT 语义
f.sof_rf_snid_hi = ProtoField.uint8 ("nw_2026.sof.rf_snid_hi", T("短网络标识高位(无线,表45)", "SNID High (RF, Table 45)"), base.DEC, nil, 0x01)
f.sof_rf_rsv12 = ProtoField.uint8 ("nw_2026.sof.rf_rsv12", T("保留(无线,表45)", "Reserved (RF, Table 45)"), base.DEC, nil, 0x0E)
f.sof_rf_rsv12_hi = ProtoField.uint8 ("nw_2026.sof.rf_rsv12_hi", T("保留(无线,表45/表131未定义)", "Reserved (RF, undefined in Table 45/131)"), base.DEC, nil, 0xF0)
f.sof_mcs = ProtoField.uint8 ("nw_2026.sof.mcs", T("调制编码方式(MCS,无线)", "MCS (RF)"), base.DEC, mcs_vals, 0x0F)
f.sof_symbol_cnt = ProtoField.uint16 ("nw_2026.sof.symbol_cnt", T("符号数(载波)", "Symbol Count (PLC)"), base.DEC)
f.sof_tei_filter = ProtoField.uint8 ("nw_2026.sof.tei_filter", T("目的TEI过滤标志", "Destination TEI Filter Flag"), base.DEC)
f.sof_resend = ProtoField.uint8 ("nw_2026.sof.resend", T("重传标志", "Re-transmission Flag"), base.DEC)
-- BPLC 版载波 SOF(表20): 聚合 BPLC 帧(用户需求)由本脚本本地解析的专属字段
f.sof_bplc_lid = ProtoField.uint8 ("nw_2026.sof.bplc.lid", T("链路标识符(LID)", "Link Identifier (LID)"), base.DEC)
f.sof_bplc_snid_hi = ProtoField.uint8 ("nw_2026.sof.bplc.snid_hi", T("短网络标识高位", "SNID High"), base.DEC, nil, 0x01)
f.sof_bplc_rsv = ProtoField.bytes ("nw_2026.sof.bplc.rsv", T("保留", "Reserved"))
f.sof_bplc_pbnum = ProtoField.uint8 ("nw_2026.sof.bplc.pbnum", T("物理块个数(表20)", "PB Count (Table 20)"), base.DEC, nil, 0x0F)
f.sof_bplc_tmi = ProtoField.uint8 ("nw_2026.sof.bplc.tmi", T("TMI 编号(表20)", "TMI Index (Table 20)"), base.DEC, nil, 0xF0)
f.sof_rsv = ProtoField.uint32 ("nw_2026.sof.rsv", T("保留", "Reserved"), base.HEX)

-- DL-OFDMA 增强帧控制 eFC(表27, 16B, 自字节16): 仅解析站点0 关键字段(与 Qt 解析器一致)
f.efc = ProtoField.bytes ("nw_2026.efc", T("eFC(DL-OFDMA 增强帧控制,表27)", "eFC (DL-OFDMA Enhanced FC, Table 27)"), base.NONE)
f.efc_st0_pbn = ProtoField.uint8 ("nw_2026.efc.st0_pbn", T("站点0 物理块数字段(0→1块,1→2块)", "Station0 PB Count Field (0→1 PB, 1→2 PB)"), base.DEC, nil, 0x04)
f.efc_st0_tmi = ProtoField.uint8 ("nw_2026.efc.st0_tmi", T("站点0 TMI 编号", "Station0 TMI Index"), base.DEC)
-- eFC 站点字段(表27/28/29, 与 Qt 解析器同坐标;仅展示不重组)
f.efc_tfnum = ProtoField.uint8 ("nw_2026.efc.tfnum", T("TF 个数(字段值+1)×2", "TF Count ((v+1)*2)"), base.DEC, nil, 0x03)
f.efc_st_pbn = ProtoField.uint8 ("nw_2026.efc.st_pbn", T("站点物理块个数(字段值+1)", "Station PB Count (v+1)"), base.DEC)
f.efc_st_tei = ProtoField.uint16 ("nw_2026.efc.st_tei", T("站点 TEI", "Station TEI"), base.DEC)
f.efc_st_tmi = ProtoField.uint8 ("nw_2026.efc.st_tmi", T("站点 TMI 编号", "Station TMI"), base.DEC)
f.efc_st_ru = ProtoField.uint8 ("nw_2026.efc.st_ru", T("站点 RU", "Station RU"), base.DEC)
f.efc_st0_sackru = ProtoField.uint8 ("nw_2026.efc.st0_sackru", T("站点0 SACK RU(表27)", "Sta0 SACK RU"), base.DEC, nil, 0x07)
f.efc_st0_backoff = ProtoField.uint8 ("nw_2026.efc.st0_backoff", T("站点0 TxPowerBackoff(表28,回退 v×4dB)", "Sta0 TxPowerBackoff (v*4dB)"), base.DEC, nil, 0x07)
f.efc_st_sackru = ProtoField.uint8 ("nw_2026.efc.st_sackru", T("站点 SACK RU(表27)", "Station SACK RU"), base.DEC, nil, 0x07)
f.efc_st_backoff = ProtoField.uint8 ("nw_2026.efc.st_backoff", T("站点 TxPowerBackoff(表28,回退 v×4dB)", "Station TxPowerBackoff (v*4dB)"), base.DEC, nil, 0x07)
f.efc29_st_tei = ProtoField.uint16 ("nw_2026.efc29.st_tei", T("站点 TEI", "Station TEI"), base.DEC)
f.efc29_st_status = ProtoField.uint8 ("nw_2026.efc29.st_status", T("站点接收状态(位图 PB0-3)", "Station RxStatus (PB0-3 bitmap)"), base.DEC, nil, 0xF0)
f.efc29_st_rsv = ProtoField.uint8 ("nw_2026.efc29.st_rsv", T("保留", "Reserved"), base.HEX)
-- 级联头(表48,聚合标志=1 时 PB 体首 2B;聚合标志=表47 byte2 bit0)
f.pb_agg = ProtoField.bool ("nw_2026.pb.agg", T("聚合标志", "Aggregation Flag"), 8, nil, 0x01)
f.cas_len = ProtoField.uint16 ("nw_2026.pb.cas_len", T("级联数据块长度(12b)", "Cascade Block Length (12b)"), base.DEC)
f.cas_start = ProtoField.bool ("nw_2026.pb.cas_start", T("级联块起始标识", "Cascade Start Flag"), 8, nil, 0x10)
f.cas_end = ProtoField.bool ("nw_2026.pb.cas_end", T("级联块结束标识", "Cascade End Flag"), 8, nil, 0x20)
f.cas_rsv = ProtoField.uint8 ("nw_2026.pb.cas_rsv", T("保留", "Reserved"), base.HEX, nil, 0xC0)
-- 16B 物理块 SACK(表49/50)
f.sack16_msgid = ProtoField.uint8 ("nw_2026.sack16.msgid", T("报文ID(体首 nibble,0=DL-OFDMA SACK)", "Message ID (0=DL-OFDMA SACK)"), base.DEC, nil, 0x0F)
f.sack16_src = ProtoField.uint16 ("nw_2026.sack16.src", T("源TEI", "Source TEI"), base.DEC)
f.sack16_rx = ProtoField.uint8 ("nw_2026.sack16.rx", T("接收状态(2b)", "RxStatus (2b)"), base.DEC, nil, 0x03)
f.sack16_rsv = ProtoField.uint8 ("nw_2026.sack16.rsv", T("保留", "Reserved"), base.HEX, nil, 0xFC)
-- ACK Bitloading 扩展帧(表33/34-40)
f.ack_bl_src = ProtoField.uint16 ("nw_2026.ack.bl.src", T("源TEI(1,0,12)", "SrcTEI"), base.DEC)
f.ack_bl_dst = ProtoField.uint16 ("nw_2026.ack.bl.dst", T("目的TEI(2,4,12)", "DstTEI"), base.DEC)
f.ack_bl_snid = ProtoField.uint8 ("nw_2026.ack.bl.snid", T("短网络标识高位", "SNID High"), base.DEC, nil, 0x01)
f.ack_bl_type = ProtoField.uint8 ("nw_2026.ack.bl.type", T("Bitloading 帧类型(表35-40)", "Bitloading Frame Type"), base.DEC, bl_type_vals, 0x0E)
f.ack_bl_reason = ProtoField.uint8 ("nw_2026.ack.bl.reason", T("拒绝原因(表36/表38)", "Reject Reason"), base.DEC, nil, 0xF0)
f.ack_bl_stream = ProtoField.uint8 ("nw_2026.ack.bl.stream", T("流数(表37)", "Stream Num"), base.DEC, nil, 0x10)
f.ack_bl_group = ProtoField.uint8 ("nw_2026.ack.bl.group", T("子载波分组(表37)", "Subcarrier Group"), base.DEC, nil, 0x60)
f.ack_bl_rsv4 = ProtoField.uint8 ("nw_2026.ack.bl.rsv4", T("保留", "Reserved"), base.HEX, nil, 0xF0)
f.ack_bl_rsv56 = ProtoField.bytes ("nw_2026.ack.bl.rsv56", T("保留(5-11,56b)", "Reserved (56b)"), base.NONE)
f.ack_bl_ver = ProtoField.uint8 ("nw_2026.ack.bl.ver", T("标准版本号(12,4-7)", "Std Version"), base.DEC, nil, 0xF0)
-- ACK 表15(反馈 SNR 版)
f.ack15_pbn = ProtoField.uint8 ("nw_2026.ack15.pbn", T("接收物理块个数(表15 4,2-3)", "RxPBNum (v+1)"), base.DEC, nil, 0x0C)
f.ack15_status = ProtoField.uint8 ("nw_2026.ack15.status", T("接收状态(表15 4,4-7)", "RxStatus"), base.DEC, nil, 0xF0)
f.ack15_src = ProtoField.uint16 ("nw_2026.ack15.src", T("源TEI(5,0,12)", "SrcTEI"), base.DEC)
f.ack15_dst = ProtoField.uint16 ("nw_2026.ack15.dst", T("目的TEI(6,4,12)", "DstTEI"), base.DEC)
f.ack15_bru = ProtoField.uint8 ("nw_2026.ack15.bru", T("BRU SNR(表15 档位)", "BRU SNR (level)"), base.DEC)

-- ACK 帧可变区域 (按扩展帧类型, 字节12 低4bit)
f.ack_ext_type = ProtoField.uint8 ("nw_2026.ack.ext_type", T("扩展帧类型", "Extended Frame Type"), base.DEC, ack_ext_type_vals, 0x0F)
f.ack_rx_res = ProtoField.uint8 ("nw_2026.ack.rx_res", T("接收结果", "Receive Result"), base.DEC, nil, 0x0F)
f.ack_rx_status = ProtoField.uint8 ("nw_2026.ack.rx_status", T("接收状态", "Receive Status"), base.HEX, nil, 0xF0)
f.ack_dst_tei = ProtoField.uint16 ("nw_2026.ack.dst_tei", T("目的TEI", "Destination TEI"), base.DEC)
f.ack_rx_pb_num = ProtoField.uint8 ("nw_2026.ack.rx_pb_num", T("接收物理块个数", "Received PB Count"), base.DEC, nil, 0xF0)
f.ack_dst_mac = ProtoField.ether ("nw_2026.ack.dst_mac", T("目的地址(MAC)", "Destination Address (MAC)"))
f.ack_search_tei = ProtoField.uint16 ("nw_2026.ack.search_tei", T("网络搜索站点TEI", "Search STA TEI"), base.DEC)
f.ack_sync_ts = ProtoField.uint32 ("nw_2026.ack.sync_ts", T("同步时间戳(NTB)", "Sync Timestamp (NTB)"), base.DEC)
f.ack_sync_tei = ProtoField.uint16 ("nw_2026.ack.sync_tei", T("同步站点TEI", "Sync STA TEI"), base.DEC)
f.ack_seq = ProtoField.uint8 ("nw_2026.ack.seq", T("序号", "Sequence Number"), base.DEC)
f.ack_rsv = ProtoField.uint32 ("nw_2026.ack.rsv", T("保留", "Reserved"), base.HEX)

-- 网间协调帧可变区域 (字节1-12)
f.coord_nbr_bmp = ProtoField.uint16 ("nw_2026.coord.nbr_bmp", T("邻居网络号位图", "Neighbor Network ID Bitmap"), base.HEX)
f.coord_rf_ch = ProtoField.uint8 ("nw_2026.coord.rf_ch", T("本网络无线信道编号", "RF Channel Number"), base.DEC)
f.coord_rsv_b3 = ProtoField.uint8 ("nw_2026.coord.rsv_b3", T("保留", "Reserved"), base.HEX)
f.coord_rsv_opt = ProtoField.uint8 ("nw_2026.coord.rsv_opt", T("保留", "Reserved"), base.HEX, nil, 0x0C)
f.coord_rsv1 = ProtoField.uint16 ("nw_2026.coord.rsv1", T("保留", "Reserved"), base.HEX, nil, 0x03FF)
f.coord_duration = ProtoField.uint16 ("nw_2026.coord.duration", T("持续时间(×40ms)", "Duration (×40ms)"), base.DEC)
f.coord_rsv2 = ProtoField.uint8 ("nw_2026.coord.rsv2", T("保留", "Reserved"), base.HEX, nil, 0x01)
f.coord_band_end_flag = ProtoField.uint8 ("nw_2026.coord.band_end_flag", T("带宽截止标志", "Band End Flag"), base.DEC, {[0]=T("无截止","None"),[1]=T("有截止","Ended")}, 0x02)
f.coord_option = ProtoField.uint8 ("nw_2026.coord.option", T("option", "option"), base.DEC, nil, 0x0C)
f.coord_rsv3 = ProtoField.uint8 ("nw_2026.coord.rsv3", T("保留", "Reserved"), base.HEX, nil, 0xF0)
f.coord_band_end_offset = ProtoField.uint16 ("nw_2026.coord.band_end_offset", T("带宽截止偏移(×4ms)", "Band End Offset (×4ms)"), base.DEC)
f.coord_band_start_offset = ProtoField.uint16 ("nw_2026.coord.band_start_offset", T("带宽开始偏移(×4ms)", "Band Start Offset (×4ms)"), base.DEC)
f.coord_rsv0 = ProtoField.uint8 ("nw_2026.coord.rsv0", T("保留", "Reserved"), base.HEX, nil, 0x0F)

-- SOF 物理块 (南网: PB头4B + 块体(PBSize-8) + 保留1B + CRC24 3B)
f.pb_hdr = ProtoField.bytes ("nw_2026.pb.hdr", T("物理块头(PB头)", "PB Header"), base.NONE)
f.pb_size = ProtoField.uint16 ("nw_2026.pb.size", T("物理块大小(字节)", "PB Size (bytes)"), base.DEC)
f.pb_body = ProtoField.bytes ("nw_2026.pb.body", T("物理块体(PB Body)", "PB Body"), base.NONE)
f.pb_rsv = ProtoField.uint8 ("nw_2026.pb.rsv", T("保留", "Reserved"), base.HEX)
f.pb_pbcs = ProtoField.uint24 ("nw_2026.pb.pbcs", T("物理块检查序列(PBCS,CRC24)", "PB Check Sequence (PBCS, CRC24)"), base.HEX)
f.pb_crc_ok = ProtoField.bool ("nw_2026.pb.crc_ok", T("CRC24校验通过", "CRC24 Check Passed"), 8, nil, 0x01)
f.pb_crc_calc = ProtoField.uint24 ("nw_2026.pb.crc_calc", T("CRC24计算值", "CRC24 Calculated"), base.HEX)
f.pb_padding = ProtoField.bytes ("nw_2026.pb.padding", T("填充(Padding)", "Padding"), base.NONE)

-- 信标帧载荷固定头 (6B)
f.beacon_type = ProtoField.uint8 ("nw_2026.beacon.type", T("信标类型", "Beacon Type"), base.DEC, beacon_type_vals, 0x07)
f.beacon_net_cplt = ProtoField.bool ("nw_2026.beacon.net_cplt", T("组网标志位", "Networking Flag"), 8, nil, 0x08)
f.beacon_multi_net = ProtoField.bool ("nw_2026.beacon.multi_net", T("多网络优选功能标志", "Multi-Network Choose Flag"), 8, nil, 0x20)
f.beacon_start_assoc = ProtoField.bool ("nw_2026.beacon.start_assoc", T("开始关联标志", "Start Association Flag"), 8, nil, 0x40)
f.beacon_net_seq = ProtoField.uint8 ("nw_2026.beacon.net_seq", T("组网序列号", "Networking Sequence Number"), base.DEC)
f.beacon_snid = ProtoField.uint8 ("nw_2026.beacon.snid", T("短网络标识低位", "Short Network ID Low"), base.HEX, nil, 0x0F)
f.beacon_snid_high = ProtoField.bool ("nw_2026.beacon.snid_high", T("短网络标识高位", "Short Network ID High"), 8, nil, 0x80)
f.beacon_reduce = ProtoField.bool ("nw_2026.beacon.reduce", T("精简信标标志(表137)", "Reduce Beacon Flag (Table 137)"), 8, nil, 0x10)
-- 表51 新增: 无线 option / PLC 能力指示 / 无线信道 / 通道数 / 网络版本号 / 信标机制状态 / 发现信标使能
f.beacon_rf_opt = ProtoField.uint8 ("nw_2026.beacon.rf_opt", T("本网络无线 option", "Network RF Option"), base.DEC, nil, 0x30)
f.beacon_plc_cap = ProtoField.uint8 ("nw_2026.beacon.plc_cap", T("PLC 能力指示(表51)", "PLC Capability Indication (Table 51)"), base.DEC, {[0]=T("支持BPLC", "BPLC only"), [1]=T("支持BPLC和SPLC", "BPLC and SPLC"), [2]=T("保留", "Reserved"), [3]=T("保留", "Reserved")}, 0xC0)
f.beacon_rf_ch = ProtoField.uint8 ("nw_2026.beacon.rf_ch", T("本网络无线信道编号", "Network RF Channel"), base.DEC)
f.beacon_chnum = ProtoField.uint8 ("nw_2026.beacon.chnum", T("通道数", "Channel Count"), base.DEC, {[0]=T("单通道模块", "Single-channel"), [1]=T("多通道通信模块", "Multi-channel")}, 0x01)
f.beacon_netver = ProtoField.uint8 ("nw_2026.beacon.net_ver", T("网络版本号(表51)", "Network Version (Table 51)"), base.DEC, {[0]=T("BPLC版本", "BPLC"), [1]=T("SPLC版本", "SPLC")}, 0x0E)
f.beacon_mech = ProtoField.uint8 ("nw_2026.beacon.mech", T("信标机制状态", "Beacon Mechanism Status"), base.DEC, {[0]=T("集中信标机制", "Centralized"), [1]=T("分散信标机制", "Distributed")}, 0x10)
f.beacon_disc_en = ProtoField.uint8 ("nw_2026.beacon.disc_en", T("发现信标发送使能", "Discover Beacon Enable"), base.DEC, {[0]=T("不允许发送", "Disabled"), [1]=T("允许发送", "Enabled")}, 0x20)
f.beacon_head_rsv = ProtoField.bytes ("nw_2026.beacon.head_rsv", T("保留", "Reserved"), base.NONE)

-- 信标管理信息
f.beacon_entry_cnt = ProtoField.uint8 ("nw_2026.beacon.entry_cnt", T("信标条目数", "Beacon Item Count"), base.DEC)
f.beacon_ent_type = ProtoField.uint8 ("nw_2026.beacon.ent.type", T("信标条目头", "Beacon Item Head"), base.HEX, beacon_entry_type_vals)
f.beacon_ent_len = ProtoField.uint16 ("nw_2026.beacon.ent.len", T("信标条目长度", "Beacon Item Length"), base.DEC)
f.beacon_ent_data = ProtoField.bytes ("nw_2026.beacon.ent.data", T("信标条目内容", "Beacon Item Content"), base.NONE)
f.beacon_bpcs = ProtoField.uint32 ("nw_2026.beacon.bpcs", T("帧载荷校验序列(BPCS,CRC32)", "Beacon Payload Check Sequence (BPCS, CRC32)"), base.HEX)
f.beacon_bpcs_calc = ProtoField.uint32 ("nw_2026.beacon.bpcs_calc", T("BPCS 计算值", "BPCS Calculated"), base.HEX)
f.beacon_bpcs_ok = ProtoField.bool ("nw_2026.beacon.bpcs_ok", T("BPCS 校验通过", "BPCS Check Passed"), 8, nil, 0x01)
f.beacon_bpcs_rsv = ProtoField.uint8 ("nw_2026.beacon.bpcs_rsv", T("保留字节", "Reserved Byte"), base.HEX)

-- 站点能力条目 (0x01, 内容 20B)
f.ent_net_level = ProtoField.uint8 ("nw_2026.beacon.cap.net_level", T("层级数", "Level"), base.DEC, nil, 0x3F)
f.ent_sta_line = ProtoField.uint8 ("nw_2026.beacon.cap.sta_line", T("站点相线", "STA Line"), base.DEC, phase_all_vals, 0xC0)
f.ent_tei = ProtoField.uint16 ("nw_2026.beacon.cap.tei", T("TEI", "TEI"), base.DEC)
f.ent_role = ProtoField.uint8 ("nw_2026.beacon.cap.role", T("角色", "Role"), base.DEC, role_vals, 0xF0)
f.ent_beacon_usage = ProtoField.uint8 ("nw_2026.beacon.cap.beacon_usage", T("信标使用标志", "Beacon Usage Flag"), base.DEC, {[0]=T("不使用信标评估信道","Not used for estimation"),[1]=T("使用信标评估信道","Used for estimation")})
f.ent_sta_mac = ProtoField.ether ("nw_2026.beacon.cap.sta_mac", T("发送信标站点MAC", "Beacon TX STA MAC"), base.NONE)
f.ent_pco_tei = ProtoField.uint16 ("nw_2026.beacon.cap.pco_tei", T("代理站点TEI", "Proxy TEI"), base.DEC)
f.ent_path_rate = ProtoField.uint32 ("nw_2026.beacon.cap.path_rate", T("路径最低通信成功率(%)", "Path Min Comm Rate (%)"), base.DEC)
f.ent_cap_rsv = ProtoField.bytes ("nw_2026.beacon.cap.rsv", T("保留", "Reserved"), base.NONE)

-- 时隙分配条目 (0x02, 固定头 24B + 可变长区)
f.ent_nc_beacon_cnt = ProtoField.uint8 ("nw_2026.beacon.slot.nc_beacon_cnt", T("非中央信标时隙总数", "Non-CCO Beacon Slot Count"), base.DEC)
f.ent_c_beacon_cnt = ProtoField.uint8 ("nw_2026.beacon.slot.c_beacon_cnt", T("中央信标时隙总数", "CCO Beacon Slot Count"), base.DEC)
f.ent_csma_line_cnt = ProtoField.uint8 ("nw_2026.beacon.slot.csma_line_cnt", T("CSMA时隙相线个数", "CSMA Slot Line Count"), base.DEC)
f.ent_proxy_beacon_cnt = ProtoField.uint8 ("nw_2026.beacon.slot.proxy_beacon_cnt", T("代理信标时隙总数", "Proxy Beacon Slot Count"), base.DEC)
f.ent_beacon_slot_len = ProtoField.uint16 ("nw_2026.beacon.slot.beacon_slot_len", T("信标时隙长度(×100us)", "Beacon Slot Length (×100us)"), base.DEC)
f.ent_csma_slot_size = ProtoField.uint8 ("nw_2026.beacon.slot.csma_slot_size", T("CSMA时隙大小(×10ms)", "CSMA Slot Size (×10ms)"), base.DEC)
f.ent_bcsma_line_cnt = ProtoField.uint8 ("nw_2026.beacon.slot.bcsma_line_cnt", T("绑定CSMA相线个数", "Binding CSMA Line Count"), base.DEC)
f.ent_bcsma_lid = ProtoField.uint8 ("nw_2026.beacon.slot.bcsma_lid", T("绑定CSMA链路标识符", "Binding CSMA Link ID"), base.DEC)
f.ent_tdma_slot_len = ProtoField.uint16 ("nw_2026.beacon.slot.tdma_slot_len", T("TDMA时隙长度(×100us)", "TDMA Slot Length (×100us)"), base.DEC)
f.ent_tdma_lid = ProtoField.uint8 ("nw_2026.beacon.slot.tdma_lid", T("TDMA链路标识符", "TDMA Link ID"), base.DEC)
f.ent_bp_start_ntb = ProtoField.uint32 ("nw_2026.beacon.slot.bp_start_ntb", T("信标周期起始网络基准时", "Beacon Period Start NTB"), base.HEX)
f.ent_bp_len = ProtoField.uint32 ("nw_2026.beacon.slot.bp_len", T("信标周期长度(×100us)", "Beacon Period Length (×100us)"), base.DEC)
f.ent_slot_rsv = ProtoField.uint32 ("nw_2026.beacon.slot.rsv", T("保留", "Reserved"), base.HEX)
-- 非中央信标信息 (2B/条)
f.ent_ncb_tei = ProtoField.uint16 ("nw_2026.beacon.ncb.tei", T("TEI", "TEI"), base.DEC)
f.ent_ncb_type = ProtoField.uint8 ("nw_2026.beacon.ncb.type", T("信标类型", "Beacon Type"), base.DEC, ncb_type_vals, 0x10)
f.ent_ncb_rsv = ProtoField.uint8 ("nw_2026.beacon.ncb.rsv", T("保留", "Reserved"), base.HEX, nil, 0xE0)
-- CSMA/绑定CSMA 时隙信息 (4B/条)
f.ent_csma_len = ProtoField.uint24 ("nw_2026.beacon.csma.len", T("CSMA时隙长度(×100us)", "CSMA Slot Length (×100us)"), base.DEC)
f.ent_csma_phase = ProtoField.uint8 ("nw_2026.beacon.csma.phase", T("CSMA时隙相线", "CSMA Slot Line"), base.DEC, phase_all_vals)
f.ent_bcsma_len = ProtoField.uint24 ("nw_2026.beacon.bcsma.len", T("绑定CSMA时隙长度(×100us)", "Binding CSMA Slot Length (×100us)"), base.DEC)
f.ent_bcsma_phase = ProtoField.uint8 ("nw_2026.beacon.bcsma.phase", T("绑定CSMA时隙相线", "Binding CSMA Slot Line"), base.DEC, phase_all_vals)

-- 路由参数条目 (0x06, 内容 32B)
f.ent_route_period = ProtoField.uint16 ("nw_2026.beacon.rp.route_period", T("路由周期(秒)", "Route Period (s)"), base.DEC)
f.ent_rp_rsv0 = ProtoField.uint16 ("nw_2026.beacon.rp.rsv0", T("保留", "Reserved"), base.HEX)
f.ent_route_remain = ProtoField.uint16 ("nw_2026.beacon.rp.route_remain", T("路由评估剩余时间(秒)", "Route Estimate Remaining (s)"), base.DEC)
f.ent_rp_rsv1 = ProtoField.bytes ("nw_2026.beacon.rp.rsv1", T("保留", "Reserved"), base.NONE)
f.ent_rp_cco_mac = ProtoField.ether ("nw_2026.beacon.rp.cco_mac", T("CCO MAC地址", "CCO MAC Address"))

-- 频段变更条目 (0x07, 内容 5B)
f.ent_target_band = ProtoField.uint8 ("nw_2026.beacon.bc.target_band", T("目标频段", "Target Band"), base.DEC, band_vals)
f.ent_band_remain = ProtoField.uint32 ("nw_2026.beacon.bc.band_remain", T("频段切换剩余时间(ms)", "Band Switch Remaining (ms)"), base.DEC)

-- 万年历同步条目 (0x0B, 内容 8B)
f.ent_cal_time = ProtoField.uint32 ("nw_2026.beacon.cal.time", T("CCO万年历(秒,自2000-01-01)", "CCO Calendar (s, since 2000-01-01)"), base.DEC)
f.ent_cal_ntb = ProtoField.uint32 ("nw_2026.beacon.cal.ntb", T("CCO万年历NTB(40ns/tick)", "CCO Calendar NTB (40ns/tick)"), base.DEC)

-- 无线路由参数条目 (0x0C, 表152, 内容 2B;表152 头列 0x09 为旧编号残留)
f.ent_rfp_period = ProtoField.uint8 ("nw_2026.beacon.rfp.period", T("无线发现列表周期(秒)", "RF Discover Period (s)"), base.DEC)
f.ent_rfp_aging = ProtoField.uint8 ("nw_2026.beacon.rfp.aging", T("无线接收率老化周期个数", "RF Aging Cycles"), base.DEC)
-- 无线信道变更条目 (0x0D, 表153, 内容 6B;表153 头列 0x0A 为旧编号残留)
f.ent_rfc_channel = ProtoField.uint8 ("nw_2026.beacon.rfc.channel", T("目标信道编号", "Target Channel"), base.DEC)
f.ent_rfc_option = ProtoField.uint8 ("nw_2026.beacon.rfc.option", T("目标信道option", "Target Option"), base.DEC, nil, 0x03)
f.ent_rfc_rsv = ProtoField.uint8 ("nw_2026.beacon.rfc.rsv", T("保留", "Reserved"), base.HEX, nil, 0xFC)
f.ent_rfc_remain = ProtoField.uint32 ("nw_2026.beacon.rfc.remain", T("信道切换剩余时间(毫秒)", "Switch Remain Time (ms)"), base.DEC)
-- 精简信标站点信息及时隙条目 (0x0E, 表155, 内容 17B)
f.ent_lite_tei = ProtoField.uint16 ("nw_2026.beacon.lite.tei", T("发送信标站点TEI", "Beacon STA TEI"), base.DEC)
f.ent_lite_pcotei = ProtoField.uint16 ("nw_2026.beacon.lite.pcotei", T("代理站点TEI", "Proxy TEI"), base.DEC)
f.ent_lite_role = ProtoField.uint8 ("nw_2026.beacon.lite.role", T("角色", "Role"), base.DEC, role_vals, 0x0F)
f.ent_lite_level = ProtoField.uint8 ("nw_2026.beacon.lite.level", T("层级数", "Level"), base.DEC)
f.ent_lite_mac = ProtoField.ether ("nw_2026.beacon.lite.mac", T("发送信标站点MAC", "Beacon STA MAC"))
f.ent_lite_hop = ProtoField.uint8 ("nw_2026.beacon.lite.hop", T("链路RF跳数", "RF Link Hop"), base.DEC, nil, 0x0F)
f.ent_lite_band = ProtoField.uint8 ("nw_2026.beacon.lite.band", T("载波频段", "Carrier Band"), base.DEC, lite_band_vals, 0x30)
f.ent_lite_rsv = ProtoField.uint8 ("nw_2026.beacon.lite.rsv", T("保留", "Reserved"), base.HEX, nil, 0xC0)
f.ent_lite_slot_ntb = ProtoField.uint32 ("nw_2026.beacon.lite.slot_ntb", T("CSMA时隙开始时间(NTB)", "CSMA Slot Start (NTB)"), base.HEX)
f.ent_lite_slot_len = ProtoField.uint16 ("nw_2026.beacon.lite.slot_len", T("CSMA时隙长度(毫秒)", "CSMA Slot Length (ms)"), base.DEC)
-- 信标机制切换条目 (0x0F, 表71, 内容 5B)
f.ent_switch_mech = ProtoField.uint8 ("nw_2026.beacon.sw.mech", T("切换目标机制ID", "Target Mechanism ID"), base.DEC, mech_vals)
f.ent_switch_ntb = ProtoField.uint32 ("nw_2026.beacon.sw.ntb", T("切换NTB时刻", "Switch NTB"), base.HEX)
-- 代理角色条目 (0x10, 表72, 长度字段 2B, N×12b 代理 TEI 连续位流)
f.ent_proxy_tei = ProtoField.uint16 ("nw_2026.beacon.proxy.tei", T("代理节点TEI", "Proxy TEI"), base.DEC)
f.ent_proxy_rsv = ProtoField.uint8 ("nw_2026.beacon.proxy.rsv", T("保留(奇数个代理站点时末尾4b对齐)", "Reserved (4b tail pad)"), base.DEC)

-- MAC 帧头 (标准帧 MSDU_BASE: 32B长/12B短; 单跳帧 MSDU_BASE_S: 4B)
f.mac_version = ProtoField.uint8 ("nw_2026.mac.version", T("MAC帧版本", "MAC Frame Version"), base.DEC, mac_version_vals, 0x06)
f.mac_head_flag = ProtoField.uint8 ("nw_2026.mac.head_flag", T("MAC帧头标志", "MAC Head Flag"), base.DEC, mac_head_flag_vals, 0x01)
f.mac_msdu_len = ProtoField.uint16 ("nw_2026.mac.msdu_len", T("MSDU长度", "MSDU Length"), base.DEC)
f.mac_dst_tei = ProtoField.uint16 ("nw_2026.mac.dst_tei", T("目的TEI", "Destination TEI"), base.DEC)
f.mac_src_tei = ProtoField.uint16 ("nw_2026.mac.src_tei", T("源TEI", "Source TEI"), base.DEC)
f.mac_restart_cnt = ProtoField.uint8 ("nw_2026.mac.restart_cnt", T("重启次数", "Restart Count"), base.DEC, nil, 0xF0)
f.mac_bcast_dir = ProtoField.uint8 ("nw_2026.mac.bcast_dir", T("广播方向", "Broadcast Direction"), base.DEC, mac_bcast_dir_vals, 0xF0)
f.mac_send_type = ProtoField.uint8 ("nw_2026.mac.send_type", T("发送类型", "Send Type"), base.DEC, mac_send_type_vals, 0x07)
f.mac_msdu_seq = ProtoField.uint16 ("nw_2026.mac.msdu_seq", T("MSDU序列号", "MSDU Sequence Number"), base.DEC)
f.mac_hdr_rsv = ProtoField.bytes ("nw_2026.mac.hdr_rsv", T("保留", "Reserved"), base.NONE)
-- MSDU 帧头 (长 18B: MAC48b×2 + VLAN32b + 类型16b; 短 2B: VLAN8b + 类型8b)
f.msdu_dst_mac = ProtoField.ether ("nw_2026.msdu.dst_mac", T("原始目的MAC地址", "Original Destination MAC"))
f.msdu_src_mac = ProtoField.ether ("nw_2026.msdu.src_mac", T("原始源MAC地址", "Original Source MAC"))
f.msdu_vlan = ProtoField.uint32 ("nw_2026.msdu.vlan", T("VLAN标签(0x8100=管理消息)", "VLAN Tag (0x8100=Mgmt)"), base.HEX)
f.msdu_type = ProtoField.uint16 ("nw_2026.msdu.type", T("MSDU类型", "MSDU Type"), base.HEX, msdu_type_long_vals)
f.msdu_vlan_s = ProtoField.uint8 ("nw_2026.msdu.vlan_s", T("VLAN标签(短帧头)", "VLAN Tag (short head)"), base.HEX)
f.msdu_type_s = ProtoField.uint8 ("nw_2026.msdu.type_s", T("MSDU类型(短帧头)", "MSDU Type (short head)"), base.HEX, msdu_type_short_vals)
-- 单跳帧头 (4B)
f.sh_type = ProtoField.uint8 ("nw_2026.sh.msg_type", T("消息类型(表114)", "Message Type (Table 114)"), base.DEC, {
    [1] = T("应用层报文", "Application layer message"), [2] = T("无线发现列表消息", "RF Discovery list message"),
    [128] = T("IPv4 报文", "IPv4 packet"),
})
f.sh_htype = ProtoField.uint8 ("nw_2026.sh.hdr_type", T("帧头类型", "Header Type"), base.DEC, nil, 0x01)
f.sh_rsv0 = ProtoField.uint8 ("nw_2026.sh.rsv0", T("保留(byte0 bit3-7)", "Reserved (byte0 bit3-7)"), base.HEX, nil, 0xF8)
f.sh_len = ProtoField.uint16 ("nw_2026.sh.msdu_len", T("MSDU长度", "MSDU Length"), base.DEC)
f.sh_data = ProtoField.bytes ("nw_2026.sh.data", T("MSDU载荷", "MSDU Payload"), base.NONE)
-- MSDU 帧尾 ICV (CRC32)
f.mac_icv = ProtoField.uint32 ("nw_2026.mac.icv", T("完整性校验值(ICV,CRC32)", "Integrity Check Value (ICV, CRC32)"), base.HEX)
f.mac_icv_calc = ProtoField.uint32 ("nw_2026.mac.icv_calc", T("ICV 计算值", "ICV Calculated"), base.HEX)
f.mac_icv_ok = ProtoField.bool ("nw_2026.mac.icv_ok", T("ICV 校验通过", "ICV Check Passed"), 8, nil, 0x01)

-- MMe 管理消息头 (6B)
f.mme_version = ProtoField.uint8 ("nw_2026.mme.version", T("管理消息版本", "Management Message Version"), base.HEX)
f.mme_type = ProtoField.uint16 ("nw_2026.mme.type", T("管理消息类型(MMType)", "Management Message Type (MMType)"), base.HEX, mme_type_vals)
f.mme_rsv = ProtoField.bytes ("nw_2026.mme.rsv", T("保留", "Reserved"), base.NONE)

-- 关联请求 MMeAssocReq (0x0030)
f.ar_sta_mac = ProtoField.ether ("nw_2026.assoc_req.sta_mac", T("站点MAC地址", "STA MAC Address"))
f.ar_proxy_tei = ProtoField.uint16 ("nw_2026.assoc_req.proxy_tei", T("候选代理TEI", "Candidate Proxy TEI"), base.DEC)
f.ar_link_type = ProtoField.bool ("nw_2026.assoc_req.link_type", T("链路类型(1=无线)", "Link Type (1=RF)"), 8, nil, 0x10)
f.ar_link_rsv = ProtoField.uint8 ("nw_2026.assoc_req.link_rsv", T("保留", "Reserved"), base.HEX, nil, 0xE0)
f.ar_phase = ProtoField.uint8 ("nw_2026.assoc_req.phase", T("相线", "Line"), base.DEC, phase_unk_vals)
f.ar_dev_type = ProtoField.uint8 ("nw_2026.assoc_req.dev_type", T("设备类型", "Device Type"), base.DEC, device_type_vals)
f.ar_rsv = ProtoField.bytes ("nw_2026.assoc_req.rsv", T("保留", "Reserved"), base.NONE)
f.ar_mac_type = ProtoField.uint8 ("nw_2026.assoc_req.mac_type", T("MAC地址类型", "MAC Address Type"), base.DEC, mac_addr_type_vals)
f.ar_module = ProtoField.uint8 ("nw_2026.assoc_req.module", T("模块类型", "Module Type"), base.DEC, nil, 0x03)
f.ar_link = ProtoField.uint8 ("nw_2026.assoc_req.link", T("链路信息", "Link Info"), base.DEC, nil, 0x7C)
f.ar_assoc_rand = ProtoField.uint32 ("nw_2026.assoc_req.assoc_rand", T("站点关联随机数", "Association Random Number"), base.DEC)
f.ar_manuf_info = ProtoField.bytes ("nw_2026.assoc_req.manuf_info", T("厂家自定义信息", "Vendor Custom Info"), base.NONE)
f.ar_boot_reason = ProtoField.uint8 ("nw_2026.assoc_req.boot_reason", T("系统启动原因", "Boot Reason"), base.DEC, boot_reason_vals)
f.ar_boot_ver = ProtoField.uint8 ("nw_2026.assoc_req.boot_ver", T("BOOT版本号", "BOOT Version"), base.DEC)
f.ar_soft_ver = ProtoField.uint16 ("nw_2026.assoc_req.soft_ver", T("软件版本号", "Software Version"), base.DEC)
f.ar_ver_year = ProtoField.uint8 ("nw_2026.assoc_req.ver_year", T("版本时间-年(+2000)", "Version Year (+2000)"), base.DEC, nil, 0x7F)
f.ar_ver_month = ProtoField.uint8 ("nw_2026.assoc_req.ver_month", T("版本时间-月", "Version Month"), base.DEC, nil, 0x78)
f.ar_ver_day = ProtoField.uint8 ("nw_2026.assoc_req.ver_day", T("版本时间-日", "Version Day"), base.DEC, nil, 0xF8)
f.ar_manuf_id = ProtoField.uint16 ("nw_2026.assoc_req.manuf_id", T("厂家代码", "Manufacturer ID"), base.HEX)
f.ar_chip_code = ProtoField.uint16 ("nw_2026.assoc_req.chip_code", T("芯片代码", "Chip Code"), base.HEX)
f.ar_hard_rst = ProtoField.uint16 ("nw_2026.assoc_req.hard_rst", T("硬复位累积次数", "Hard Reset Count"), base.DEC)
f.ar_soft_rst = ProtoField.uint16 ("nw_2026.assoc_req.soft_rst", T("软复位累积次数", "Soft Reset Count"), base.DEC)
f.ar_proxy_type = ProtoField.uint8 ("nw_2026.assoc_req.proxy_type", T("代理类型", "Proxy Type"), base.DEC, proxy_type_vals)
f.ar_net_sn = ProtoField.uint8 ("nw_2026.assoc_req.net_sn", T("组网序列号", "Networking Sequence Number"), base.DEC)
f.ar_mme_ver = ProtoField.uint8 ("nw_2026.assoc_req.mme_ver", T("MMe版本号", "MMe Version"), base.DEC, nil, 0x1E)
f.ar_band_support = ProtoField.uint8 ("nw_2026.assoc_req.band_support", T("支持频段标识", "Band Support"), base.DEC, band_support_vals, 0x03)
f.ar_e2e_seq = ProtoField.uint32 ("nw_2026.assoc_req.e2e_seq", T("端到端序列号", "End-to-End Sequence Number"), base.DEC)

-- 关联确认 MMeAssocCnf (0x0031)
f.ac_sta_mac = ProtoField.ether ("nw_2026.assoc_cnf.sta_mac", T("站点MAC地址", "STA MAC Address"))
f.ac_result = ProtoField.uint8 ("nw_2026.assoc_cnf.result", T("结果", "Result"), base.HEX, assoc_cnf_result_vals)
f.ac_sta_level = ProtoField.uint8 ("nw_2026.assoc_cnf.sta_level", T("站点层级", "STA Level"), base.DEC)
f.ac_sta_tei = ProtoField.uint16 ("nw_2026.assoc_cnf.sta_tei", T("站点TEI", "STA TEI"), base.DEC)
f.ac_proxy_tei = ProtoField.uint16 ("nw_2026.assoc_cnf.proxy_tei", T("代理TEI", "Proxy TEI"), base.DEC)
f.ac_total_pkgs = ProtoField.uint8 ("nw_2026.assoc_cnf.total_pkgs", T("总分包数", "Total Packages"), base.DEC)
f.ac_pkg_idx = ProtoField.uint8 ("nw_2026.assoc_cnf.pkg_idx", T("分包序号", "Package Index"), base.DEC)
f.ac_last_pkg = ProtoField.uint8 ("nw_2026.assoc_cnf.last_pkg", T("最后一个分包标识", "Last Packet Flag"), base.DEC, last_pkt_vals)
f.ac_link_type = ProtoField.bool ("nw_2026.assoc_cnf.link_type", T("链路类型(1=无线)", "Link Type (1=RF)"), 8, nil, 0x01)
f.ac_carrier = ProtoField.uint8 ("nw_2026.assoc_cnf.carrier", T("载波频段", "Carrier Band"), base.DEC, band_vals, 0x0E)
f.ac_assoc_rand = ProtoField.uint32 ("nw_2026.assoc_cnf.assoc_rand", T("站点关联随机数", "Association Random Number"), base.DEC)
f.ac_reassoc_time = ProtoField.uint32 ("nw_2026.assoc_cnf.reassoc_time", T("重新关联时间(ms)", "Re-association Time (ms)"), base.DEC)
f.ac_e2e_seq = ProtoField.uint32 ("nw_2026.assoc_cnf.e2e_seq", T("端到端序列号", "End-to-End Sequence Number"), base.DEC)
f.ac_path_seq = ProtoField.uint32 ("nw_2026.assoc_cnf.path_seq", T("路径序号", "Path Sequence Number"), base.DEC)
f.ac_net_sn = ProtoField.uint8 ("nw_2026.assoc_cnf.net_sn", T("组网序列号", "Networking Sequence Number"), base.DEC)
f.ac_mme_ver = ProtoField.uint8 ("nw_2026.assoc_cnf.mme_ver", T("MMe版本号", "MMe Version"), base.DEC, nil, 0x0F)
f.ac_detech = ProtoField.bool ("nw_2026.assoc_cnf.detech", T("detechFlag", "detechFlag"), 8, nil, 0x10)
-- 路由信息 (关联确认/关联指示共用)
f.ri_straight_sta = ProtoField.uint16 ("nw_2026.route_info.straight_sta", T("直连站点数", "Direct STA Count"), base.DEC)
f.ri_straight_pco = ProtoField.uint16 ("nw_2026.route_info.straight_pco", T("直连代理数", "Direct PCO Count"), base.DEC)
f.ri_table_size = ProtoField.uint16 ("nw_2026.route_info.table_size", T("路由表大小", "Route Table Size"), base.DEC)
f.ri_rsv = ProtoField.uint16 ("nw_2026.route_info.rsv", T("保留", "Reserved"), base.HEX)
f.ri_sta_tei = ProtoField.uint16 ("nw_2026.route_info.sta_tei", T("直连站点TEI", "Direct STA TEI"), base.DEC)
f.ri_pco_tei = ProtoField.uint16 ("nw_2026.route_info.pco_tei", T("直连代理TEI", "Direct PCO TEI"), base.DEC)
f.ri_pco_child_cnt = ProtoField.uint16 ("nw_2026.route_info.pco_child_cnt", T("代理子站点数", "PCO Child Count"), base.DEC)
f.ri_child_tei = ProtoField.uint16 ("nw_2026.route_info.child_tei", T("子站点TEI", "Child STA TEI"), base.DEC)
f.ri_link_type = ProtoField.bool ("nw_2026.route_info.link_type", T("链路类型(1=无线)", "Link Type (1=RF)"), 8, nil, 0x10)
f.ri_link_rsv = ProtoField.uint8 ("nw_2026.route_info.link_rsv", T("保留", "Reserved"), base.HEX, nil, 0xE0)

-- 代理变更请求 MMeChangeProxyReq (0x0032)
f.cpr_sta_tei = ProtoField.uint16 ("nw_2026.cproxy_req.sta_tei", T("站点TEI", "STA TEI"), base.DEC)
f.cpr_new_proxy = ProtoField.uint16 ("nw_2026.cproxy_req.new_proxy", T("新代理TEI", "New Proxy TEI"), base.DEC)
f.cpr_link_type = ProtoField.bool ("nw_2026.cproxy_req.link_type", T("链路类型(1=无线)", "Link Type (1=RF)"), 8, nil, 0x10)
f.cpr_link_rsv = ProtoField.uint8 ("nw_2026.cproxy_req.link_rsv", T("保留", "Reserved"), base.HEX, nil, 0xE0)
f.cpr_old_proxy = ProtoField.uint16 ("nw_2026.cproxy_req.old_proxy", T("旧代理TEI", "Old Proxy TEI"), base.DEC)
f.cpr_proxy_type = ProtoField.uint8 ("nw_2026.cproxy_req.proxy_type", T("代理类型", "Proxy Type"), base.DEC, proxy_type_vals)
f.cpr_reason = ProtoField.uint8 ("nw_2026.cproxy_req.reason", T("原因", "Reason"), base.DEC, proxy_change_reason_vals)
f.cpr_phase = ProtoField.uint8 ("nw_2026.cproxy_req.phase", T("站点相线", "STA Line"), base.DEC, phase_unk_vals)
f.cpr_link = ProtoField.uint8 ("nw_2026.cproxy_req.link", T("链路信息", "Link Info"), base.DEC, nil, 0x1F)
f.cpr_e2e_seq = ProtoField.uint32 ("nw_2026.cproxy_req.e2e_seq", T("端到端序列号", "End-to-End Sequence Number"), base.DEC)
f.cpr_net_sn = ProtoField.uint8 ("nw_2026.cproxy_req.net_sn", T("组网序列号", "Networking Sequence Number"), base.DEC)
f.cpr_rsv = ProtoField.bytes ("nw_2026.cproxy_req.rsv", T("保留", "Reserved"), base.NONE)

-- 关联指示 MMeAssocInd (0x0034)
f.ai_result = ProtoField.uint8 ("nw_2026.assoc_ind.result", T("结果", "Result"), base.HEX, assoc_ind_result_vals)
f.ai_sta_level = ProtoField.uint8 ("nw_2026.assoc_ind.sta_level", T("站点层级", "STA Level"), base.DEC)
f.ai_sta_mac = ProtoField.ether ("nw_2026.assoc_ind.sta_mac", T("站点MAC地址", "STA MAC Address"))
f.ai_cco_mac = ProtoField.ether ("nw_2026.assoc_ind.cco_mac", T("CCO MAC地址", "CCO MAC Address"))
f.ai_sta_tei = ProtoField.uint16 ("nw_2026.assoc_ind.sta_tei", T("站点TEI", "STA TEI"), base.DEC)
f.ai_proxy_tei = ProtoField.uint16 ("nw_2026.assoc_ind.proxy_tei", T("代理TEI", "Proxy TEI"), base.DEC)
f.ai_link_type = ProtoField.bool ("nw_2026.assoc_ind.link_type", T("链路类型(1=无线)", "Link Type (1=RF)"), 8, nil, 0x01)
f.ai_carrier = ProtoField.uint8 ("nw_2026.assoc_ind.carrier", T("载波频段", "Carrier Band"), base.DEC, band_vals, 0x0E)
f.ai_rsv = ProtoField.bytes ("nw_2026.assoc_ind.rsv", T("保留", "Reserved"), base.NONE)
f.ai_total_pkgs = ProtoField.uint8 ("nw_2026.assoc_ind.total_pkgs", T("总分包数", "Total Packages"), base.DEC)
f.ai_pkg_idx = ProtoField.uint8 ("nw_2026.assoc_ind.pkg_idx", T("分包序号", "Package Index"), base.DEC)
f.ai_last_pkg = ProtoField.uint8 ("nw_2026.assoc_ind.last_pkg", T("最后一个分包标识", "Last Packet Flag"), base.DEC, last_pkt_vals)
f.ai_assoc_rand = ProtoField.uint32 ("nw_2026.assoc_ind.assoc_rand", T("站点关联随机数", "Association Random Number"), base.DEC)
f.ai_net_sn = ProtoField.uint8 ("nw_2026.assoc_ind.net_sn", T("组网序列号", "Networking Sequence Number"), base.DEC)
f.ai_reassoc_time = ProtoField.uint32 ("nw_2026.assoc_ind.reassoc_time", T("重新关联时间(ms)", "Re-association Time (ms)"), base.DEC)
f.ai_e2e_seq = ProtoField.uint32 ("nw_2026.assoc_ind.e2e_seq", T("端到端序列号", "End-to-End Sequence Number"), base.DEC)

-- 代理变更确认 MMeChangeProxyCnf (0x0037)
f.cpc_result = ProtoField.uint32 ("nw_2026.cproxy_cnf.result", T("结果", "Result"), base.DEC, proxy_change_result_vals)
f.cpc_total_pkgs = ProtoField.uint8 ("nw_2026.cproxy_cnf.total_pkgs", T("总分包数", "Total Packages"), base.DEC)
f.cpc_pkg_idx = ProtoField.uint8 ("nw_2026.cproxy_cnf.pkg_idx", T("分包序号", "Package Index"), base.DEC)
f.cpc_sta_tei = ProtoField.uint16 ("nw_2026.cproxy_cnf.sta_tei", T("站点TEI", "STA TEI"), base.DEC)
f.cpc_proxy_tei = ProtoField.uint16 ("nw_2026.cproxy_cnf.proxy_tei", T("代理TEI", "Proxy TEI"), base.DEC)
f.cpc_child_cnt = ProtoField.uint16 ("nw_2026.cproxy_cnf.child_cnt", T("子站点数", "Child STA Count"), base.DEC)
f.cpc_net_sn = ProtoField.uint8 ("nw_2026.cproxy_cnf.net_sn", T("组网序列号", "Networking Sequence Number"), base.DEC)
f.cpc_link_type = ProtoField.bool ("nw_2026.cproxy_cnf.link_type", T("链路类型(1=无线)", "Link Type (1=RF)"), 8, nil, 0x01)
f.cpc_rsv = ProtoField.bytes ("nw_2026.cproxy_cnf.rsv", T("保留", "Reserved"), base.NONE)
f.cpc_e2e_seq = ProtoField.uint32 ("nw_2026.cproxy_cnf.e2e_seq", T("端到端序列号", "End-to-End Sequence Number"), base.DEC)
f.cpc_path_seq = ProtoField.uint32 ("nw_2026.cproxy_cnf.path_seq", T("路径序号", "Path Sequence Number"), base.DEC)
f.cpc_child_tei = ProtoField.uint16 ("nw_2026.cproxy_cnf.child_tei", T("子站点TEI", "Child STA TEI"), base.DEC)

-- 关联汇总指示 MMeAssocGatherInd (0x003A)
f.ag_result = ProtoField.uint8 ("nw_2026.assoc_gather.result", T("结果", "Result"), base.DEC, gather_result_vals)
f.ag_sta_level = ProtoField.uint8 ("nw_2026.assoc_gather.sta_level", T("站点层级", "STA Level"), base.DEC)
f.ag_cco_mac = ProtoField.ether ("nw_2026.assoc_gather.cco_mac", T("CCO MAC地址", "CCO MAC Address"))
f.ag_proxy_tei = ProtoField.uint16 ("nw_2026.assoc_gather.proxy_tei", T("代理TEI", "Proxy TEI"), base.DEC)
f.ag_net_sn = ProtoField.uint8 ("nw_2026.assoc_gather.net_sn", T("组网序列号", "Networking Sequence Number"), base.DEC)
f.ag_gather_cnt = ProtoField.uint8 ("nw_2026.assoc_gather.gather_cnt", T("新站点数", "New STA Count"), base.DEC)
f.ag_carrier = ProtoField.uint8 ("nw_2026.assoc_gather.carrier", T("载波频段", "Carrier Band"), base.DEC, band_vals, 0x07)
f.ag_rsv = ProtoField.bytes ("nw_2026.assoc_gather.rsv", T("保留", "Reserved"), base.NONE)
f.ag_sta_mac = ProtoField.ether ("nw_2026.assoc_gather.sta_mac", T("站点MAC地址", "STA MAC Address"))
f.ag_sta_tei = ProtoField.uint16 ("nw_2026.assoc_gather.sta_tei", T("站点TEI", "STA TEI"), base.DEC)

-- 代理变更确认位图版 MMeChangeProxyBitMapCnf (0x003B)
f.cpb_result = ProtoField.uint32 ("nw_2026.cproxy_bmp.result", T("结果", "Result"), base.DEC, proxy_change_result_vals)
f.cpb_sta_tei = ProtoField.uint16 ("nw_2026.cproxy_bmp.sta_tei", T("站点TEI", "STA TEI"), base.DEC)
f.cpb_proxy_tei = ProtoField.uint16 ("nw_2026.cproxy_bmp.proxy_tei", T("代理TEI", "Proxy TEI"), base.DEC)
f.cpb_net_sn = ProtoField.uint8 ("nw_2026.cproxy_bmp.net_sn", T("组网序列号", "Networking Sequence Number"), base.DEC)
f.cpb_child_bmp = ProtoField.bytes ("nw_2026.cproxy_bmp.child_bmp", T("子站点位图(130B)", "Child STA Bitmap (130B)"), base.NONE)
f.cpb_link_type = ProtoField.bool ("nw_2026.cproxy_bmp.link_type", T("链路类型(1=无线)", "Link Type (1=RF)"), 8, nil, 0x01)
f.cpb_e2e_seq = ProtoField.uint32 ("nw_2026.cproxy_bmp.e2e_seq", T("端到端序列号", "End-to-End Sequence Number"), base.DEC)
f.cpb_path_seq = ProtoField.uint32 ("nw_2026.cproxy_bmp.path_seq", T("路径序号", "Path Sequence Number"), base.DEC)

-- 离线指示 MMeLeaveInd (0x0049)
f.li_sta_tei = ProtoField.uint16 ("nw_2026.leave.sta_tei", T("离线站点TEI", "Leave STA TEI"), base.DEC)
f.li_reason = ProtoField.uint16 ("nw_2026.leave.reason", T("原因", "Reason"), base.DEC, leave_reason_vals)
f.li_sta_mac = ProtoField.ether ("nw_2026.leave.sta_mac", T("离线站点MAC地址", "Leave STA MAC Address"))
f.li_proxy_tei = ProtoField.uint16 ("nw_2026.leave.proxy_tei", T("代理TEI", "Proxy TEI"), base.DEC)
f.li_rsv = ProtoField.bytes ("nw_2026.leave.rsv", T("保留", "Reserved"), base.NONE)

-- 心跳检测 MMeHeartBeatCheck (0x0051)
f.hb_ostei = ProtoField.uint16 ("nw_2026.hb.ostei", T("原始源TEI", "Original Source TEI"), base.DEC)
f.hb_max_disc_tei = ProtoField.uint16 ("nw_2026.hb.max_disc_tei", T("发现站点数最大的站点TEI", "Max Discovery STA TEI"), base.DEC)
f.hb_max_disc_cnt = ProtoField.uint32 ("nw_2026.hb.max_disc_cnt", T("最大的发现站点数", "Max Discovery STA Count"), base.DEC)
f.hb_disc_bmp = ProtoField.bytes ("nw_2026.hb.disc_bmp", T("可发现站点位图(130B)", "Discoverable STA Bitmap (130B)"), base.NONE)
f.hb_rsv = ProtoField.uint8 ("nw_2026.hb.rsv", T("保留", "Reserved"), base.HEX)

-- 发现列表 MMeDiscoverNodeList (0x0055)
f.dl_tei = ProtoField.uint16 ("nw_2026.dl.tei", T("TEI", "TEI"), base.DEC)
f.dl_role = ProtoField.uint8 ("nw_2026.dl.role", T("角色", "Role"), base.DEC, role_vals)
f.dl_level = ProtoField.uint8 ("nw_2026.dl.level", T("层级", "Level"), base.DEC)
f.dl_mac = ProtoField.ether ("nw_2026.dl.mac", T("MAC地址", "MAC Address"))
f.dl_proxy_tei = ProtoField.uint16 ("nw_2026.dl.proxy_tei", T("代理TEI", "Proxy TEI"), base.DEC)
f.dl_rsv = ProtoField.bytes ("nw_2026.dl.rsv", T("保留", "Reserved"), base.NONE)
f.dl_rate_finish = ProtoField.uint8 ("nw_2026.dl.rate_finish", T("通信成功率计算完成标志", "Comm Rate Calc Finish"), base.DEC, rate_calc_vals, 0x80)
f.dl_proxy_rate = ProtoField.uint32 ("nw_2026.dl.proxy_rate", T("代理站点通信成功率(%)", "Proxy Comm Rate (%)"), base.DEC)
f.dl_proxy_dl_rate = ProtoField.uint32 ("nw_2026.dl.proxy_dl_rate", T("代理站点下行通信成功率(%)", "Proxy Downlink Comm Rate (%)"), base.DEC)
f.dl_sta_cnt = ProtoField.uint16 ("nw_2026.dl.sta_cnt", T("发现站点数", "Discovered STA Count"), base.DEC)
f.dl_send_cnt = ProtoField.uint16 ("nw_2026.dl.send_cnt", T("发送发现列表报文个数", "Discovery List TX Count"), base.DEC)
f.dl_up_route_cnt = ProtoField.uint16 ("nw_2026.dl.up_route_cnt", T("上行路由条目数", "Uplink Route Entry Count"), base.DEC)
f.dl_up_route_size = ProtoField.uint8 ("nw_2026.dl.up_route_size", T("上行路由条目大小(bit)", "Uplink Route Entry Size (bit)"), base.DEC)
f.dl_route_remain = ProtoField.uint16 ("nw_2026.dl.route_remain", T("路由周期到期剩余时间(秒)", "Route Period Remaining (s)"), base.DEC)
f.dl_phase0 = ProtoField.uint8 ("nw_2026.dl.phase0", T("相线0(高可信)", "Line 0 (high confidence)"), base.DEC, phase_unk_vals, 0x30)
f.dl_phase1 = ProtoField.uint8 ("nw_2026.dl.phase1", T("相线1(中可信)", "Line 1 (medium confidence)"), base.DEC, phase_unk_vals, 0x0C)
f.dl_phase2 = ProtoField.uint8 ("nw_2026.dl.phase2", T("相线2(低可信)", "Line 2 (low confidence)"), base.DEC, phase_unk_vals, 0x03)
f.dl_min_rate = ProtoField.uint8 ("nw_2026.dl.min_rate", T("最小通信成功率(%)", "Min Comm Rate (%)"), base.DEC)
f.dl_next_hop_tei = ProtoField.uint16 ("nw_2026.dl.next_hop_tei", T("下一跳站点TEI", "Next Hop STA TEI"), base.DEC)
f.dl_route_type = ProtoField.uint8 ("nw_2026.dl.route_type", T("路由类型", "Route Type"), base.DEC, route_type_vals)
f.dl_disc_bmp = ProtoField.bytes ("nw_2026.dl.disc_bmp", T("发现站点列表位图(128B)", "Discovery STA List Bitmap (128B)"), base.NONE)
f.dl_rcv_cnt = ProtoField.uint8 ("nw_2026.dl.rcv_cnt", T("接收发现列表数", "Received Discovery List Count"), base.DEC)
f.dl_rcv_item = ProtoField.string ("nw_2026.dl.rcv_item", T("接收发现列表数(按TEI)", "Received Discovery List Count (by TEI)"))

-- 延迟离线指示 MMeDelayLeaveInd (0x005D)
f.dl2_reason = ProtoField.uint16 ("nw_2026.delay_leave.reason", T("原因", "Reason"), base.DEC, delay_leave_reason_vals)
f.dl2_sta_cnt = ProtoField.uint16 ("nw_2026.delay_leave.sta_cnt", T("站点总数", "STA Count"), base.DEC)
f.dl2_delay = ProtoField.uint16 ("nw_2026.delay_leave.delay", T("延迟时间(秒)", "Delay Time (s)"), base.DEC)
f.dl2_rsv = ProtoField.bytes ("nw_2026.delay_leave.rsv", T("保留", "Reserved"), base.NONE)
f.dl2_sta_mac = ProtoField.ether ("nw_2026.delay_leave.sta_mac", T("站点MAC地址", "STA MAC Address"))

-- 通信成功率上报 MMeSuccessRateReport (0x005E)
f.sr_proxy_tei = ProtoField.uint16 ("nw_2026.sr.proxy_tei", T("代理站点TEI", "Proxy STA TEI"), base.DEC)
f.sr_sta_cnt = ProtoField.uint16 ("nw_2026.sr.sta_cnt", T("站点总数", "STA Count"), base.DEC)
f.sr_sta_tei = ProtoField.uint16 ("nw_2026.sr.sta_tei", T("站点TEI", "STA TEI"), base.DEC)
f.sr_down_rate = ProtoField.uint8 ("nw_2026.sr.down_rate", T("下行通信成功率(%)", "Downlink Comm Rate (%)"), base.DEC)
f.sr_up_rate = ProtoField.uint8 ("nw_2026.sr.up_rate", T("上行通信成功率(%)", "Uplink Comm Rate (%)"), base.DEC)

-- 过零NTB采集指示 MMeZeroCrossNTBCollectInd (0x0062)
f.zc_quantity = ProtoField.uint8 ("nw_2026.zc.quantity", T("采集数量", "Collect Quantity"), base.DEC)
f.zc_seq = ProtoField.uint8 ("nw_2026.zc.seq", T("采集序列号", "Collect Sequence Number"), base.DEC)
f.zc_rsv = ProtoField.uint16 ("nw_2026.zc.rsv", T("保留", "Reserved"), base.HEX)

-- 过零NTB上报 MMeZeroCrossNTBReport (0x0063)
f.zr_tei = ProtoField.uint16 ("nw_2026.zr.tei", T("TEI", "TEI"), base.DEC)
f.zr_collect_mode = ProtoField.uint8 ("nw_2026.zr.collect_mode", T("相位特征采集方式", "Collect Mode"), base.DEC, collect_mode_vals, 0x30)
f.zr_seq = ProtoField.uint8 ("nw_2026.zr.seq", T("采集序列号", "Collect Sequence Number"), base.DEC)
f.zr_total_cnt = ProtoField.uint8 ("nw_2026.zr.total_cnt", T("告知总数量", "Report Total Count"), base.DEC)
f.zr_base_ntb = ProtoField.uint32 ("nw_2026.zr.base_ntb", T("基准NTB", "Base NTB"), base.DEC)
f.zr_rsv = ProtoField.uint8 ("nw_2026.zr.rsv", T("保留", "Reserved"), base.HEX)
f.zr_ph1_cnt = ProtoField.uint8 ("nw_2026.zr.ph1_cnt", T("相线1差值数量", "Line A Diff Count"), base.DEC)
f.zr_ph2_cnt = ProtoField.uint8 ("nw_2026.zr.ph2_cnt", T("相线2差值数量", "Line B Diff Count"), base.DEC)
f.zr_ph3_cnt = ProtoField.uint8 ("nw_2026.zr.ph3_cnt", T("相线3差值数量", "Line C Diff Count"), base.DEC)
f.zr_diff = ProtoField.uint16 ("nw_2026.zr.diff", T("过零NTB差值", "Zero-Cross NTB Diff"), base.DEC)

-- 网络诊断 MMeNetDiagnose (0x0064)
f.diag_chip_id = ProtoField.uint16 ("nw_2026.diag.chip_id", T("芯片厂商ID", "Chip Vendor ID"), base.DEC, chip_id_vals)
f.diag_custom = ProtoField.bytes ("nw_2026.diag.custom", T("诊断信息", "Diagnose Info"), base.NONE)



-- 应用层报文 APP_BASE (通道控制信息 4B + 业务报文头 8B)
f.app_port = ProtoField.uint8 ("nw_2026.app.port", T("报文端口号", "Port Number"), base.HEX, app_port_vals)
f.app_packet_id = ProtoField.uint16 ("nw_2026.app.packet_id", T("报文标识符", "Packet ID"), base.HEX, app_packet_id_vals)
f.app_rsv = ProtoField.uint8 ("nw_2026.app.rsv", T("保留", "Reserved"), base.HEX)
f.app_packet_type = ProtoField.uint8 ("nw_2026.app.packet_type", T("帧类型域", "Packet Type"), base.DEC, app_packet_type_vals, 0x0F)
f.app_ctrl_rsv0 = ProtoField.uint8 ("nw_2026.app.ctrl_rsv0", T("控制域保留", "Ctrl Reserved"), base.HEX, nil, 0xF0)
f.app_ctrl_rsv1 = ProtoField.uint8 ("nw_2026.app.ctrl_rsv1", T("控制域保留", "Ctrl Reserved"), base.HEX, nil, 0x0F)
f.app_ext_flag = ProtoField.bool ("nw_2026.app.ext_flag", T("业务扩展域标识位", "Extended Field Flag"), 8, nil, 0x10)
f.app_respond_flag = ProtoField.bool ("nw_2026.app.respond_flag", T("响应标识位", "Response Flag"), 8, nil, 0x20)
f.app_start_flag = ProtoField.bool ("nw_2026.app.start_flag", T("启动标志位", "Start Flag"), 8, nil, 0x40)
f.app_trans_dir = ProtoField.bool ("nw_2026.app.trans_dir", T("传输方向位", "Transmission Direction"), 8, nil, 0x80)
f.app_business_id = ProtoField.uint8 ("nw_2026.app.business_id", T("业务标识(BID)", "Business ID (BID)"), base.HEX)
f.app_bid_desc = ProtoField.string ("nw_2026.app.bid_desc", T("业务标识释义", "Business ID Description"))
f.app_version = ProtoField.uint8 ("nw_2026.app.version", T("应用版本号", "Application Version"), base.DEC)
f.app_packet_sn = ProtoField.uint16 ("nw_2026.app.packet_sn", T("帧序号", "Packet SN"), base.DEC)
f.app_packet_len = ProtoField.uint16 ("nw_2026.app.packet_len", T("帧长(字节)", "Packet Length (bytes)"), base.DEC)
f.app_payload = ProtoField.bytes ("nw_2026.app.payload", T("应用层载荷(APP Data)", "Application Payload (APP Data)"), base.NONE)


-- 媒介头 (串口混合采集 USER4/USER5 格式: [phr_mcs][option][channel][isRF], 之后纯 MPDU)
f.media_phr_mcs = ProtoField.uint8 ("nw_2026.media.phr_mcs", T("PHR MCS", "PHR MCS"), base.HEX)
f.media_option = ProtoField.uint8 ("nw_2026.media.option", T("option", "option"), base.HEX)
f.media_channel = ProtoField.uint8 ("nw_2026.media.channel", T("信道", "Channel"), base.DEC)
f.media_is_rf = ProtoField.uint8 ("nw_2026.media.is_rf", T("媒介(0=载波,非0=无线)", "Media (0=PLC, non-0=RF)"), base.DEC, {[0]=T("载波 HPLC", "PLC"), [1]=T("无线 RF", "RF")})

-- 原始目标地址列 (自定义列引用, 显示目的TEI + MAC 映射)
f.col_orig_dst = ProtoField.string ("nw_2026.col_orig_dst", "Original Destination Address")
f.col_orig_src = ProtoField.string ("nw_2026.col_orig_src", "Original Source Address")

-- 位图逐字节解析节点 (string, 承载 "值 (TEI列表)" 文本)
f.bmp_byte = ProtoField.string ("nw_2026.bmp.byte", T("位图字节", "Bitmap Byte"))


-- =========================================================================
-- 位域读取 helper (little-endian bit 序, 字节内 bit0=LSB, 跨字节连续)
-- =========================================================================
local function read_bits(tvb, start_bit, nbits)
    local val = 0
    for i = 0, nbits - 1 do
        local abs_bit = start_bit + i
        local byte_off = math.floor(abs_bit / 8)
        if byte_off < tvb:len() then
            local b = tvb(byte_off, 1):uint()
            local bit_in_byte = abs_bit % 8
            if band(b, 2 ^ bit_in_byte) ~= 0 then
                val = val + 2 ^ i
            end
        end
    end
    return val
end

-- 小端读多字节字段, 带显式值 (用于跨字节 bit 字段和 le 字段)
local function add_val(tree, field, tvb, off, len, value)
    return tree:add(field, tvb(off, len), value)
end

-- 小端读整字节字段 (逐字节累加: 兼容"块体逻辑视图", 跨块读取仍正确)
local function add_le(tree, field, tvb, off, len)
    local val = 0
    for i = 0, len - 1 do
        val = val + tvb(off + i, 1):uint() * 2 ^ (8 * i)
    end
    return tree:add(field, tvb(off, len), val)
end
-- 块体逻辑视图: 多物理块时把"重组坐标"(各块块体拼接)映射回原始帧坐标.
-- 逐字节读取(1B Range)总是字节精确; (off,len) 跨块时高亮范围顺带覆盖块间字节(值不受影响).
-- 不生成新数据源 → hex 窗口始终显示完整原始帧(PB头/块尾CRC 都在), 点击字段高亮原帧对应字节
local function make_block_view(tvb, base, pbsz, n)
    local body = pbsz - 8  -- NW_2021: PB头4B + 体 + 保留1B + CRC24 3B          -- 块体长
    local inter = pbsz - body      -- 块间字节数
    local total = n * body
    local function map(off)
        local i = math.floor(off / body)
        return base + i * pbsz + (off - i * body)
    end
    local v = setmetatable({}, {
        __call = function(_, off, len)
            off = off or 0
            len = len or (total - off)
            if off < 0 or len <= 0 or off + len > total then
                error("block view: Range is out of bounds")
            end
            local crossings = math.floor((off + len - 1) / body) - math.floor(off / body)
            return tvb(map(off), len + crossings * inter)
        end,
    })
    v.len = function() return total end
    v.body = body    -- 供 add_span 判断跨块分段
    return v
end

-- 逻辑视图的子视图 (坐标平移, 供管理消息体/APP 体; 替代 range:tvb() 子集)
local function view_slice(v, delta)
    local s = setmetatable({}, {
        __call = function(_, off, len)
            off = off or 0
            if len == nil then len = v.len() - delta - off end
            return v(off + delta, len)
        end,
    })
    s.len = function() return v.len() - delta end
    if type(v) == "table" then s.body = v.body end   -- 真实 tvb 无 body(无需分段)
    return s
end

-- 跨块字段分段高亮: 范围跨物理块时按块拆成多个树项(同一字段), 每项只高亮该块内的
-- 数据字节, 不覆盖块间 PB头/CRC; 未跨块/真实 tvb 时等价于普通 tree:add(field, v(off, len))
local function add_span(tree, field, v, off, len)
    if type(v) ~= "table" then
        -- 真实 tvb(单块): 连续, 直接加
        if len == nil then len = v:len() - off end
        return tree:add(field, v(off, len))
    end
    local body = v.body
    if len == nil then len = v.len() - off end
    if not body or math.floor((off + len - 1) / body) == math.floor(off / body) then
        return tree:add(field, v(off, len))
    end
    local last
    for i = math.floor(off / body), math.floor((off + len - 1) / body) do
        local seg_s = math.max(off, i * body)
        local seg_e = math.min(off + len, (i + 1) * body)
        last = tree:add(field, v(seg_s, seg_e - seg_s))
    end
    return last
end


-- 12bit TEI @ 字节 off 起 (bit0)
local function add_tei12(tree, field, tvb, off)
    return add_val(tree, field, tvb, off, 2, read_bits(tvb, off * 8, 12))
end

-- 12bit TEI @ 字节 off bit4 起 (右半字节起)
local function add_tei12h(tree, field, tvb, off)
    return add_val(tree, field, tvb, off, 2, read_bits(tvb, off * 8 + 4, 12))
end

-- 位图逐字节解析: bit 全局索引 = TEI (字节i的bit j → TEI = i*8+j)
-- 每字节输出 "值 (TEI列表)", 顶层节点用 bytes 字段, 逐字节子节点用 string
local function dissect_tei_bitmap(tvb, tree, off, size, field, label_zh, label_en)
    if size <= 0 or off + size > tvb:len() then return end
    local bmp_tree = add_span(tree, field, tvb, off, size)
    for i = 0, size - 1 do
        local b = tvb(off + i, 1):uint()
        local teis = {}
        for j = 0, 7 do
            if band(b, 2 ^ j) ~= 0 then
                teis[#teis + 1] = T("TEI", "TEI") .. (i * 8 + j)
            end
        end
        local txt
        if #teis > 0 then
            txt = string.format("0x%02X (%s)", b, table.concat(teis, ", "))
        else
            txt = string.format("0x%02X", b)
        end
        bmp_tree:add(f.bmp_byte, tvb(off + i, 1), string.format(T("%s[%d]: %s", "%s[%d]: %s"), T(label_zh, label_en), i, txt))
    end
end

-- =========================================================================
-- PB 块大小查表 (与 nw_2026_pb_table.h 一致, 勿与国网共享)
-- =========================================================================

-- 载波路径 TMI(载波映射表索引) → PB 块大小(字节); TMI 13-14 转查 TMI_EXT
local function plc_pb_size(tmi, tmi_ext)
    if tmi == 0 or tmi == 1 then return 520 end
    if tmi >= 2 and tmi <= 6 then return 136 end
    if tmi >= 7 and tmi <= 10 then return 520 end
    if tmi == 11 or tmi == 12 then return 264 end
    -- TMI 13-14: 转查扩展 TMI_EXT
    if tmi_ext >= 1 and tmi_ext <= 6 then return 520 end
    if tmi_ext >= 10 and tmi_ext <= 14 then return 136 end
    return -1
end

-- NW_2026 (SPLC) PB 块大小(表23/物理层表13): TMI编号 0-8→520 / 9-15→264 / 16-20→136 / 21-25→72 / 26-27→16
local function splc_pb_size(tmi_idx)
    if tmi_idx <= 8 then return 520 end
    if tmi_idx <= 15 then return 264 end
    if tmi_idx <= 20 then return 136 end
    if tmi_idx <= 25 then return 72 end
    if tmi_idx <= 27 then return 16 end
    return -1
end

-- BPLC 版载波 SOF(表20/第2部分)PB 块大小: TMI 0/1→520 / 2-6→136 / 7-10→520 /
-- 11-12→264 / 13-14 转查 TMI_EXT(1-6→520 / 10-14→136); 与 C++ nw_2026_pb_size 同表
local function bplc_pb_size(tmi, tmi_ext)
    if tmi == 0 or tmi == 1 then return 520 end
    if tmi >= 2 and tmi <= 6 then return 136 end
    if tmi >= 7 and tmi <= 10 then return 520 end
    if tmi == 11 or tmi == 12 then return 264 end
    if tmi_ext >= 1 and tmi_ext <= 6 then return 520 end
    if tmi_ext >= 10 and tmi_ext <= 14 then return 136 end
    return -1
end

-- SPLC 版 Bitloading标识=1 时 TMI编号 → 物理块大小(表23: 0→136/1→520/2→72/3→264)
local function splc_bitload_pb_size(idx)
    if idx == 0 then return 136 end
    if idx == 1 then return 520 end
    if idx == 2 then return 72 end
    if idx == 3 then return 264 end
    return -1
end

-- 无线路径「载荷 PB 大小」(表130) → PB 块大小(字节)
local function rf_pb_size(pblen)
    if pblen == 0 then return 16 end
    if pblen == 1 then return 40 end
    if pblen == 2 then return 72 end
    if pblen == 3 then return 136 end
    if pblen == 4 then return 264 end
    if pblen == 5 then return 520 end
    return -1
end

-- =========================================================================
-- FCH 可变区域解析 (字节1-12, 帧型各自坐标)
-- =========================================================================

-- 信标帧可变区域: BTS(4B) + BPC(4B) + 源TEI(12b) + [载波TMI/符号数/相线 | 无线载荷PB大小]
local function dissect_beacon_vf(tvb, tree, is_rf)
    local bts_raw = tvb(1, 4):le_uint()
    tree:add(f.beacon_bts, tvb(1, 4), bts_raw)
    -- NTB: 25MHz时钟, 40ns/tick, 换算秒 = NTB / 25e6
    tree:add(f.beacon_bts_sec, tvb(1, 4), bts_raw / 25000000.0)
    add_le(tree, f.beacon_bpc, tvb, 5, 4)
    add_tei12(tree, f.beacon_src_tei, tvb, 9)
    if is_rf then
        -- 无线信标(第2部分 表128): MCS(10,4,4) + 载荷PB大小(11,0,4) + 保留(11,4,4)/(12,0,4)
        tree:add(f.beacon_mcs, tvb(10, 1))
        tree:add(f.beacon_pblen, tvb(11, 1))
        tree:add(f.beacon_rsv1, tvb(11, 1))
        tree:add(f.beacon_rsv2, tvb(12, 1))
    else
        tree:add(f.beacon_tmi, tvb(10, 1))
        add_val(tree, f.beacon_symbol_cnt, tvb, 11, 2, read_bits(tvb, 11 * 8, 9))
        tree:add(f.beacon_rsv3, tvb(12, 1))
        tree:add(f.beacon_phase, tvb(12, 1))
    end
end

-- SOF 帧可变区域: 源TEI(12b) + 目的TEI(12b) + 分帧型可变域, 返回载荷解析参数:
--   载波 SPLC(表23-26): 多站点(4,0,1)/训练(4,1,1) 分派; 单站点 PB个数(4,2,4)/
--     Bitloading(6,0,1)/TMI编号(6,1,5)/帧长(8,0,12); DL-OFDMA(表26/27) eFC 16B 自
--     字节16 → PB 基址 32; 训练帧(表24/25)无数据物理块
--   无线(表131): LID(4,0,8)/帧长(5,0,12)/载荷PB大小(6,4,4)/MCS(7,0,4)/重传(7,5,1), 单块
local function dissect_sof_vf(tvb, tree, is_rf)
    local r = { pb_base = 16, pb_num = 0, pbsize = -1, otype1 = 0 }
    add_tei12(tree, f.sof_src_tei, tvb, 1)
    add_tei12h(tree, f.sof_dst_tei, tvb, 2)
    if is_rf then
        -- 无线 SOF(SPLC 第4部分 表45): 帧长(5,0,12) + 载荷PB大小(6,4,4) + MCS(7,0,4) +
        --   TEI过滤(7,4,1) + 重传(7,5,1) + 保留(7,6,2)/(8,0,32) + SNID高位(12,0,1)+保留(12,1,3)/
        --   保留(12,4,4;表45/表131均只定义至bit3,高半字节无定义,按保留位渲染)
        tree:add(f.sof_lid, tvb(4, 1))
        add_val(tree, f.sof_frame_len, tvb, 5, 2, read_bits(tvb, 5 * 8, 12))
        tree:add(f.sof_pblen, tvb(6, 1))
        tree:add(f.sof_mcs, tvb(7, 1))
        add_val(tree, f.sof_tei_filter, tvb, 7, 1, read_bits(tvb, 7 * 8 + 4, 1))
        add_val(tree, f.sof_resend, tvb, 7, 1, read_bits(tvb, 7 * 8 + 5, 1))
        add_val(tree, f.sof_rsv, tvb, 7, 1, read_bits(tvb, 7 * 8 + 6, 2))
        add_le(tree, f.sof_rsv, tvb, 8, 4)
        tree:add(f.sof_rf_snid_hi, tvb(12, 1))   -- SNID 高位(12,0,1,表45)
        tree:add(f.sof_rf_rsv12, tvb(12, 1))     -- 保留(12,1,3,表45)
        tree:add(f.sof_rf_rsv12_hi, tvb(12, 1))  -- 保留(12,4,4;两表均无定义,按保留位渲染)
        r.pb_num = 1                                  -- 无线信道仅 1 个物理块
        r.pbsize = rf_pb_size(read_bits(tvb, 6 * 8 + 4, 4))
    else
        local std_ver = math.floor(band(tvb(12, 1):uint(), 0xF0) / 16)
        if std_ver ~= 2 then
            -- BPLC 版载波 SOF(表20): 聚合 BPLC 帧(用户需求)由本脚本本地解析
            -- (非聚合 version=1 在 packet-nw_2021.lua 入口分派走旧布局,不经此处)——
            -- 坐标与 packet-nw_2021.lua 载波 SOF 同源: LID(4,0,8)/SNID高位(5,0,1)/
            -- PBNum(7,0-3)/TMI(7,4-7)/帧长(8,0,12)/TEI过滤(10,5)/重传(10,6)/
            -- 符号数(10,7,9)/TMI_EXT(12,0-3); PB 头循环聚合标志/级联头/级联 MAC 帧通用
            tree:add(f.sof_bplc_lid, tvb(4, 1))
            tree:add(f.sof_bplc_snid_hi, tvb(5, 1))
            tree:add(f.sof_bplc_rsv, tvb(5, 2))
            tree:add(f.sof_bplc_pbnum, tvb(7, 1))
            tree:add(f.sof_bplc_tmi, tvb(7, 1))
            add_val(tree, f.sof_frame_len, tvb, 8, 2, read_bits(tvb, 8 * 8, 12))
            add_val(tree, f.sof_tei_filter, tvb, 10, 1, read_bits(tvb, 10 * 8 + 5, 1))
            add_val(tree, f.sof_resend, tvb, 10, 1, read_bits(tvb, 10 * 8 + 6, 1))
            add_val(tree, f.sof_symbol_cnt, tvb, 10, 2, read_bits(tvb, 10 * 8 + 7, 9))
            add_val(tree, f.sof_tmi_ext, tvb, 12, 1, read_bits(tvb, 12 * 8, 4))
            r.pb_num = read_bits(tvb, 7 * 8, 4)
            r.pbsize = bplc_pb_size(read_bits(tvb, 7 * 8 + 4, 4), read_bits(tvb, 12 * 8, 4))
            return r
        end
        -- SPLC 载波 SOF(表23-26): 多站点帧标识(4,0,1)/训练帧标识(4,1,1)/OFDMA类型(4,1,2)/
        -- 帧长(8,0,12,×10µs); byte5/7 保留 (带掩码字段直接挂整字节, Wireshark 按掩码取值)
        local multi = read_bits(tvb, 4 * 8, 1)
        tree:add(f.sof_multi, tvb(4, 1))
        add_val(tree, f.sof_frame_len, tvb, 8, 2, read_bits(tvb, 8 * 8, 12))
        if multi == 1 then
            local otype = read_bits(tvb, 4 * 8 + 1, 2)
            tree:add(f.sof_ofdma_type, tvb(4, 1))
            if (otype == 0 or otype == 2) and tvb:len() >= 32 then
                -- 表27(DL-OFDMA,otype 0)/表28(trigger,otype 2):类型1 无 eFC,不进此分支;
                -- eFC 16B 自字节16, 站点循环位推进(与 Qt 解析器同坐标), 仅展示不重组;
                -- 站点数-1 取 FCH byte4 bit6-7, 尾字段每站都有: 表27=SACK RU / 表28=TxPowerBackoff
                local efc_tree = tree:add(f.efc, tvb(16, 16))
                local sn = read_bits(tvb, 4 * 8 + 6, 2)
                efc_tree:add(f.efc_tfnum, tvb(16, 1))
                local bp = 2   -- eFC 内位偏移(TF 个数 2b 之后)
                for s = 0, sn do
                    local pbn_f = read_bits(tvb, 16 * 8 + bp, 1)
                    efc_tree:add(f.efc_st_pbn, tvb(16 + math.floor(bp / 8), 1), pbn_f + 1)
                    bp = bp + 1
                    efc_tree:add(f.efc_st_tei, tvb(16 + math.floor(bp / 8), 2),
                        read_bits(tvb, 16 * 8 + bp, 12))
                    bp = bp + 12
                    efc_tree:add(f.efc_st_tmi, tvb(16 + math.floor(bp / 8), 1),
                        read_bits(tvb, 16 * 8 + bp, 5))
                    bp = bp + 5
                    efc_tree:add(f.efc_st_ru, tvb(16 + math.floor(bp / 8), 1),
                        read_bits(tvb, 16 * 8 + bp, 4))
                    bp = bp + 4
                    -- 表27 SACK RU / 表28 TxPowerBackoff(3b):每站都有,不是仅站0
                    -- (原实现仅站0推进 3b,3站以上帧的站2/站3 eFC 字段整体错位 3b;与 C++ 侧同修)
                    if otype == 2 then
                        efc_tree:add(f.efc_st_backoff, tvb(16 + math.floor(bp / 8), 1),
                            read_bits(tvb, 16 * 8 + bp, 3))
                    else
                        efc_tree:add(f.efc_st_sackru, tvb(16 + math.floor(bp / 8), 1),
                            read_bits(tvb, 16 * 8 + bp, 3))
                    end
                    bp = bp + 3
                end
                if otype == 0 then
                    -- 仅 DL-OFDMA 数据帧重组 MSDU;PB 块自字节32 起(站点0), 其余站点 PB 依序随后
                    local tmi0 = read_bits(tvb, 17 * 8 + 7, 5)
                    r.pb_base = 32
                    r.pb_num = read_bits(tvb, 16 * 8 + 2, 1) + 1  -- 表27/28: 字段 0→1 块, 1→2 块
                    r.pbsize = splc_pb_size(tmi0)
                else
                    r.pb_num = 0
                    r.pbsize = 0
                end
            elseif otype == 3 and tvb:len() >= 32 then
                -- UL-SACK(表29): 4×[TEI 12b + 接收状态 4b + 保留 8b], 每站点 3B;仅展示
                local efc_tree = tree:add(f.efc, tvb(16, 16))
                for s = 0, 3 do
                    local b = 16 + s * 3
                    efc_tree:add(f.efc29_st_tei, tvb(b, 2), read_bits(tvb, b * 8, 12))
                    efc_tree:add(f.efc29_st_status, tvb(b + 1, 1))
                    efc_tree:add(f.efc29_st_rsv, tvb(b + 2, 1))
                end
                r.pb_num = 0
                r.pbsize = 0
            else
                -- 类型未知 / 截断帧 / 类型1(无 eFC): 本站不重组 MSDU
                if otype == 0 then
                    -- DL-OFDMA 本应有 eFC(表27)+PB，长度不足说明帧被截断
                    tree:append_text(" · " .. T("DL-OFDMA 帧被截断", "DL-OFDMA Frame Truncated"))
                elseif otype == 1 then
                    -- 类型1 双义(无 eFC): DL-SACK(单16B PB) / UL-OFDMA 数据(需 trigger 上下文)
                    -- 先试 DL-SACK: 总长 32B + PB@16 CRC24 通过 + 体首 nibble MsgID==0
                    local dl_sack = false
                    if tvb:len() == 32 then
                        local calc = crc24_lsb(tvb, 16, 16)
                        local rx = tvb(16 + 13, 3):le_uint()
                        if calc == rx and band(tvb(20, 1):uint(), 0x0F) == 0 then
                            dl_sack = true
                        end
                    end
                    if dl_sack then
                        -- DL-SACK: 单16B PB @16, 体按表49/50 展示 MsgID/SrcTEI/RxStatus
                        tree:add(f.sack16_msgid, tvb(20, 1))
                        tree:add(f.sack16_src, tvb(20, 2),
                            math.floor(band(tvb(20, 1):uint(), 0xF0) / 16) + tvb(21, 1):uint() * 16)
                        tree:add(f.sack16_rx, tvb(22, 1))
                        tree:add(f.sack16_rsv, tvb(22, 1))
                        tree:append_text(" · " .. T("DL-OFDMA SACK", "DL-OFDMA SACK"))
                        r.otype1 = 1
                    else
                        -- UL-OFDMA 数据: Lua 无 trigger 上下文(跨帧状态难做), 明确标「需 trigger」
                        tree:append_text(" · " .. T("UL-OFDMA 数据帧，需 trigger 上下文",
                            "UL-OFDMA Data Frame, Requires Trigger Context"))
                        r.otype1 = 2
                    end
                end
                r.pb_num = 0
                r.pbsize = 0
            end
        else
            local train = read_bits(tvb, 4 * 8 + 1, 1)
            tree:add(f.sof_train, tvb(4, 1))
            if train == 1 then
            -- 训练帧(表24/25): 无数据物理块, 不重组 MSDU
            r.pb_num = 0
            r.pbsize = 0
            else
            -- SPLC 单站点数据帧(表23): 物理块个数(4,2-5)/Bitloading(6,0)/TMI编号(6,1-5)
            local pbn = read_bits(tvb, 4 * 8 + 2, 4)
            local bitload = read_bits(tvb, 6 * 8, 1)
            local tmi_idx = read_bits(tvb, 6 * 8 + 1, 5)
            tree:add(f.sof_pb_num, tvb(4, 1))
            tree:add(f.sof_bitload, tvb(6, 1))
            tree:add(f.sof_tmi, tvb(6, 1))
            r.pb_num = pbn
            r.pbsize = (bitload == 1) and splc_bitload_pb_size(tmi_idx) or splc_pb_size(tmi_idx)
            end
        end
    end
    return r
end

-- ACK 帧可变区域: 按字节12低4bit 扩展帧类型分流
local function dissect_ack_vf(tvb, tree)
    local ext_type = read_bits(tvb, 12 * 8, 4)
    tree:add(f.ack_ext_type, tvb(12, 1))
    if ext_type == 1 then
        -- 网络搜索帧(附录 表C-2): 目的地址(48b) + 搜索站点TEI(12b) + 保留 + 序号(字节11)
        tree:add(f.ack_dst_mac, tvb(1, 6))
        add_tei12(tree, f.ack_search_tei, tvb, 7)
        add_val(tree, f.ack_rsv, tvb, 8, 1, read_bits(tvb, 8 * 8 + 4, 4))
        add_le(tree, f.ack_rsv, tvb, 9, 2)
        tree:add(f.ack_seq, tvb(11, 1))
    elseif ext_type == 2 then
        -- 同步帧(附录 表C-3): 同步时间戳(32b) + 同步站点TEI(12b) + 保留 + 序号(字节11)
        add_le(tree, f.ack_sync_ts, tvb, 1, 4)
        add_tei12(tree, f.ack_sync_tei, tvb, 5)
        add_val(tree, f.ack_rsv, tvb, 6, 1, read_bits(tvb, 6 * 8 + 4, 4))
        add_le(tree, f.ack_rsv, tvb, 7, 4)
        tree:add(f.ack_seq, tvb(11, 1))
    elseif ext_type == 3 then
        -- Bitloading 扩展帧(表34,可变区域按 Bitloading 帧类型细分 表35-40)
        add_tei12(tree, f.ack_bl_src, tvb, 1)
        add_tei12h(tree, f.ack_bl_dst, tvb, 2)
        tree:add(f.ack_bl_snid, tvb(4, 1))
        tree:add(f.ack_bl_type, tvb(4, 1))
        local blt = read_bits(tvb, 4 * 8 + 1, 3)
        if blt == 1 then
            -- 训练指示拒绝(表36):拒绝原因 1 站点正在训练/2 训练站点已满/其他保留
            tree:add(f.ack_bl_reason, tvb(4, 1))
        elseif blt == 3 then
            -- 训练请求拒绝(表38):拒绝原因 1 训练站点已满/其他保留(0 值文案文档缺失)
            tree:add(f.ack_bl_reason, tvb(4, 1))
        elseif blt == 2 then
            -- 训练请求(表37):流数 bit4(0 单流/1 双流)/子载波分组大小 bit5-6(1/2/4/8 个一组)/保留 bit7
            tree:add(f.ack_bl_stream, tvb(4, 1))
            tree:add(f.ack_bl_group, tvb(4, 1))
            tree:add(f.ack_bl_rsv4, tvb(4, 1))
        else
            -- 类型 0/4/5(表35/39/40):byte4 bit4-7 保留
            tree:add(f.ack_bl_rsv4, tvb(4, 1))
        end
        tree:add(f.ack_bl_rsv56, tvb(5, 7))
        tree:add(f.ack_bl_ver, tvb(12, 1))
    else
        local bru_flag = band(tvb(4, 1):uint(), 0x01)
        if bru_flag == 1 then
            -- 表15(选择确认帧 反馈SNR版):RxPBNum(4,2-3)/RxStatus(4,4-7)
            --   SrcTEI(5,0,12)/DstTEI(6,4,12)/BRU0-7 SNR(8-11,8×4b)
            tree:add(f.ack15_pbn, tvb(4, 1))
            tree:add(f.ack15_status, tvb(4, 1))
            add_tei12(tree, f.ack15_src, tvb, 5)
            add_tei12h(tree, f.ack15_dst, tvb, 6)
            -- 档位:0=无效值;v≥1 → SNR∈[-10+3(v-1), -7+3(v-1)]dB(以表15 行内定义为准,
            -- 表16 档位表文档提取错位数值不自洽,不采用)
            for i = 0, 7 do
                local v = read_bits(tvb, (8 + math.floor(i / 2)) * 8 + (i % 2) * 4, 4)
                local desc
                if v == 0 then
                    desc = string.format(T("%d (无效值)", "%d (Invalid)"), v)
                else
                    desc = string.format(T("%d (SNR %d~%ddB)", "%d (SNR %d~%d dB)"),
                        v, -10 + 3 * (v - 1), -7 + 3 * (v - 1))
                end
                tree:add(f.ack15_bru, tvb(8 + math.floor(i / 2), 1), desc)
            end
        else
            -- 常规 ACK(0,表14);其余扩展类型(含原"切频")规约未定义,按选择确认帧解析(与 Qt 监控器一致)
            tree:add(f.ack_rx_res, tvb(1, 1))
            tree:add(f.ack_rx_status, tvb(1, 1))
            add_tei12(tree, f.ack_dst_tei, tvb, 2)
            tree:add(f.ack_rx_pb_num, tvb(3, 1))
        end
    end
    -- 10 时隙预约 / 11 测距响应 / 12 测距请求: 南网扩展, 暂不解析(与 Qt 监控器一致)
end

-- 网间协调帧可变区域: 邻居NID位图(16b) + 信道(8b) + 时长(14b,×40ms) +
--   带宽截止标志/option + 带宽截止/开始偏移(16b,×4ms)
local function dissect_coord_vf(tvb, tree, is_rf)
    add_le(tree, f.coord_nbr_bmp, tvb, 1, 2)
    -- 字节3 与 (7,2,2) 按介质定名(与 Qt 监控器一致): 无线=本网络无线信道编号/本网络无线option
    -- (第2部分 表127); 载波=保留(第5部分 表22)
    if is_rf then
        tree:add(f.coord_rf_ch, tvb(3, 1))
    else
        tree:add(f.coord_rsv_b3, tvb(3, 1))
    end
    add_val(tree, f.coord_rsv1, tvb, 4, 2, read_bits(tvb, 4 * 8, 10))
    add_val(tree, f.coord_duration, tvb, 5, 2, read_bits(tvb, 5 * 8 + 2, 14))
    tree:add(f.coord_rsv2, tvb(7, 1))
    tree:add(f.coord_band_end_flag, tvb(7, 1))
    if is_rf then
        tree:add(f.coord_option, tvb(7, 1))
    else
        tree:add(f.coord_rsv_opt, tvb(7, 1))
    end
    tree:add(f.coord_rsv3, tvb(7, 1))
    add_le(tree, f.coord_band_end_offset, tvb, 8, 2)
    add_le(tree, f.coord_band_start_offset, tvb, 10, 2)
    tree:add(f.coord_rsv0, tvb(12, 1))
end

-- =========================================================================
-- 信标帧载荷 (固定头 6B + 管理信息 + BPCS + 保留字节 + PB CRC24)
-- =========================================================================

-- 站点能力条目 (0x01, 内容 20B)
local function dissect_entry_sta_cap(tvb, tree, off)
    tree:add(f.ent_net_level, tvb(off, 1))
    tree:add(f.ent_sta_line, tvb(off, 1))
    local tei = read_bits(tvb, off * 8 + 8, 12)
    add_tei12(tree, f.ent_tei, tvb, off + 1)
    tree:add(f.ent_role, tvb(off + 2, 1))
    tree:add(f.ent_beacon_usage, tvb(off + 3, 1))
    tree:add(f.ent_sta_mac, tvb(off + 4, 6))
    -- 记录 TEI ↔ MAC 映射
    record_tei_mac(tei, mac_to_str(tvb, off + 4))
    add_tei12(tree, f.ent_pco_tei, tvb, off + 10)
    add_le(tree, f.ent_path_rate, tvb, off + 12, 4)
    tree:add(f.ent_cap_rsv, tvb(off + 16, 4))
end

-- 时隙分配条目 (0x02, 固定头 24B + 可变长区)
local function dissect_entry_slot_alloc(tvb, tree, off)
    local nc_beacon_cnt = tvb(off, 1):uint()
    local csma_cnt = tvb(off + 2, 1):uint()
    local bcsma_cnt = tvb(off + 7, 1):uint()
    tree:add(f.ent_nc_beacon_cnt, tvb(off, 1))
    tree:add(f.ent_c_beacon_cnt, tvb(off + 1, 1))
    tree:add(f.ent_csma_line_cnt, tvb(off + 2, 1))
    tree:add(f.ent_proxy_beacon_cnt, tvb(off + 3, 1))
    add_le(tree, f.ent_beacon_slot_len, tvb, off + 4, 2)
    tree:add(f.ent_csma_slot_size, tvb(off + 6, 1))
    tree:add(f.ent_bcsma_line_cnt, tvb(off + 7, 1))
    tree:add(f.ent_bcsma_lid, tvb(off + 8, 1))
    add_le(tree, f.ent_tdma_slot_len, tvb, off + 9, 2)
    tree:add(f.ent_tdma_lid, tvb(off + 11, 1))
    add_le(tree, f.ent_bp_start_ntb, tvb, off + 12, 4)
    add_le(tree, f.ent_bp_len, tvb, off + 16, 4)
    add_le(tree, f.ent_slot_rsv, tvb, off + 20, 4)
    -- 可变长区从固定头 24B 后开始
    local pos = off + 24
    -- 非中央信标信息 (2B/条): TEI 12b + 信标类型 1b + 保留 3b
    for i = 1, nc_beacon_cnt do
        if pos + 2 > tvb:len() then return end
        add_tei12(tree, f.ent_ncb_tei, tvb, pos)
        tree:add(f.ent_ncb_type, tvb(pos + 1, 1))
        tree:add(f.ent_ncb_rsv, tvb(pos + 1, 1))
        pos = pos + 2
    end
    -- CSMA 时隙信息 (4B/条): 时隙长度 24b + 相线 8b
    for i = 1, csma_cnt do
        if pos + 4 > tvb:len() then return end
        tree:add(f.ent_csma_len, tvb(pos, 3), tvb(pos, 3):le_uint())
        tree:add(f.ent_csma_phase, tvb(pos + 3, 1))
        pos = pos + 4
    end
    -- 绑定 CSMA 时隙信息 (4B/条)
    for i = 1, bcsma_cnt do
        if pos + 4 > tvb:len() then return end
        tree:add(f.ent_bcsma_len, tvb(pos, 3), tvb(pos, 3):le_uint())
        tree:add(f.ent_bcsma_phase, tvb(pos + 3, 1))
        pos = pos + 4
    end
end

-- 路由参数条目 (0x06, 内容 32B)
local function dissect_entry_route_param(tvb, tree, off)
    add_le(tree, f.ent_route_period, tvb, off, 2)
    add_le(tree, f.ent_rp_rsv0, tvb, off + 2, 2)
    add_le(tree, f.ent_route_remain, tvb, off + 4, 2)
    tree:add(f.ent_rp_rsv1, tvb(off + 6, 20))
    tree:add(f.ent_rp_cco_mac, tvb(off + 26, 6))
end

-- 频段变更条目 (0x07, 内容 5B)
local function dissect_entry_band_change(tvb, tree, off)
    tree:add(f.ent_target_band, tvb(off, 1))
    add_le(tree, f.ent_band_remain, tvb, off + 1, 4)
end

-- 万年历同步条目 (0x0B, 内容 8B)
local function dissect_entry_calendar(tvb, tree, off)
    add_le(tree, f.ent_cal_time, tvb, off, 4)
    add_le(tree, f.ent_cal_ntb, tvb, off + 4, 4)
end

-- 无线路由参数条目 (0x0C, 表152, 内容 2B;表152 头列 0x09 为旧编号残留)
local function dissect_entry_rf_route_param(tvb, tree, off)
    add_le(tree, f.ent_rfp_period, tvb, off, 1)
    add_le(tree, f.ent_rfp_aging, tvb, off + 1, 1)
end

-- 无线信道变更条目 (0x0D, 表153, 内容 6B;表153 头列 0x0A 为旧编号残留)
local function dissect_entry_rf_channel_change(tvb, tree, off)
    add_le(tree, f.ent_rfc_channel, tvb, off, 1)
    tree:add(f.ent_rfc_option, tvb(off + 1, 1))
    tree:add(f.ent_rfc_rsv, tvb(off + 1, 1))
    add_le(tree, f.ent_rfc_remain, tvb, off + 2, 4)
end

-- 精简信标站点信息及时隙条目 (0x0E, 表155, 内容 17B)
local function dissect_entry_lite_sta_slot(tvb, tree, off)
    -- TEI(0,0,12)/代理站点TEI(1,4,12):12b 跨 nibble,取 LE16 后移位
    tree:add(f.ent_lite_tei, tvb(off, 2), band(tvb(off, 2):le_uint(), 0x0FFF))
    tree:add(f.ent_lite_pcotei, tvb(off + 1, 2), math.floor(band(tvb(off + 1, 2):le_uint(), 0xFFF0) / 16))
    tree:add(f.ent_lite_role, tvb(off + 3, 1))
    tree:add(f.ent_lite_level, tvb(off + 3, 1))
    tree:add(f.ent_lite_mac, tvb(off + 4, 6))
    tree:add(f.ent_lite_hop, tvb(off + 8, 1))
    tree:add(f.ent_lite_band, tvb(off + 8, 1))
    tree:add(f.ent_lite_rsv, tvb(off + 8, 1))
    add_le(tree, f.ent_lite_slot_ntb, tvb, off + 9, 4)
    add_le(tree, f.ent_lite_slot_len, tvb, off + 13, 2)
end

-- 信标机制切换条目 (0x0F, 表71, 内容 5B)
local function dissect_entry_mech_switch(tvb, tree, off)
    tree:add(f.ent_switch_mech, tvb(off, 1))
    add_le(tree, f.ent_switch_ntb, tvb, off + 1, 4)
end

-- 代理角色条目 (0x10, 表72, 长度字段 2B):N×12b 代理 TEI 连续位流,
-- 代理站点个数为奇数时末尾 4b 保留对齐(与 C++ nw_2026_beacon_parser 同款推导)
local function dissect_entry_proxy_role(tvb, tree, off, item_len)
    local content_bits = item_len * 8
    local n = math.floor(content_bits / 12)
    local odd_pad = (content_bits % 12) ~= 0
    if odd_pad then n = math.floor((content_bits - 4) / 12) end
    for i = 0, n - 1 do
        -- 12b 跨 nibble:起始字节 off+i*1.5,取 LE 后按位截取
        local b = off + math.floor(i * 12 / 8)
        local bitoff = (i * 12) % 8
        local v = math.floor(band(tvb(b, 2):le_uint(), 0xFFFF) / 2 ^ bitoff) % 4096
        tree:add(f.ent_proxy_tei, tvb(b, 2), v)
    end
    if odd_pad then
        local rb = off + math.floor(n * 12 / 8)
        local rbitoff = (n * 12) % 8
        local rv = math.floor(band(tvb(rb, 1):uint(), 0xFF) / 2 ^ rbitoff) % 16
        tree:add(f.ent_proxy_rsv, tvb(rb, 1), rv)
    end
end

-- 信标管理信息 (首字节条目数, 随后 头+长度+内容), 返回下一个 offset
-- 条目长度语义(与 Qt nw_2026_beaconparser 一致):
--   长度字段值 len_raw = 头(1B) + 长度字段(1/2B) + 内容
--   内容长 = len_raw - 2 (普通) / len_raw - 3 (0x02 时隙分配, 长度字段 2B)
local function dissect_beacon_mgmt_info(tvb, tree, off, mgmt_end)
    if off >= tvb:len() then return off end
    tree:add(f.beacon_entry_cnt, tvb(off, 1))
    local cnt = tvb(off, 1):uint()
    local pos = off + 1
    for i = 1, cnt do
        if pos >= mgmt_end then break end
        local etype = tvb(pos, 1):uint()
        tree:add(f.beacon_ent_type, tvb(pos, 1))
        pos = pos + 1
        -- 长度字段: 时隙分配(0x02)/代理角色(0x10,表72)用 2B, 其余 1B (小端)
        local len_bytes = (etype == 0x02 or etype == 0x10) and 2 or 1
        if pos + len_bytes > mgmt_end then break end
        local len_raw = tvb(pos, len_bytes):le_uint()
        tree:add(f.beacon_ent_len, tvb(pos, len_bytes), len_raw)
        pos = pos + len_bytes
        -- 内容长 = len_raw - (头1B + 长度字段len_bytes)
        local item_len = len_raw - (1 + len_bytes)
        if item_len <= 0 or pos + item_len > mgmt_end then break end
        tree:add(f.beacon_ent_data, tvb(pos, item_len))
        -- 按条目类型解析内容
        if etype == 0x01 then
            dissect_entry_sta_cap(tvb, tree, pos)
        elseif etype == 0x02 then
            dissect_entry_slot_alloc(tvb, tree, pos)
        elseif etype == 0x06 then
            dissect_entry_route_param(tvb, tree, pos)
        elseif etype == 0x07 then
            dissect_entry_band_change(tvb, tree, pos)
        elseif etype == 0x0B then
            dissect_entry_calendar(tvb, tree, pos)
        elseif etype == 0x0C then
            dissect_entry_rf_route_param(tvb, tree, pos)
        elseif etype == 0x0D then
            dissect_entry_rf_channel_change(tvb, tree, pos)
        elseif etype == 0x0E then
            dissect_entry_lite_sta_slot(tvb, tree, pos)
        elseif etype == 0x0F then
            dissect_entry_mech_switch(tvb, tree, pos)
        elseif etype == 0x10 then
            dissect_entry_proxy_role(tvb, tree, pos, item_len)
        end
        -- 0x0A 频段探测 / 0x80-0xEF 厂家自定义 / 其它保留: 仅显示内容 hex
        pos = pos + item_len
    end
    return pos
end

-- 信标帧载荷 (固定头 6B 起始于 off, 整块 pbsize)
-- 结构(与 Qt nw_2026_beaconparser 一致):
--   帧载荷区 gb = [off, off+pbsize-3): 固定头(6B) + 管理区 + BPCS(CRC32,4B) + 保留字节(1B)
--   BPCS 覆盖 gb 前 gb_len-5 字节(固定头+管理区); 块尾 3B 为 PB CRC24
local function dissect_beacon_payload(tvb, tree, off, pbsize)
    local gb_end = off + pbsize - 3     -- 帧载荷区末尾(不含 PB CRC24)
    -- 固定头 (表51, 6B, 统一载波/无线): byte0 标志组 / byte1 组网序列号 /
    --   byte2 SNID低4b+无线option+PLC能力 / byte3 无线信道 /
    --   byte4 通道数+网络版本号+信标机制+发现信标使能 / byte5 保留
    tree:add(f.beacon_type, tvb(off, 1))
    tree:add(f.beacon_net_cplt, tvb(off, 1))
    tree:add(f.beacon_reduce, tvb(off, 1))
    tree:add(f.beacon_multi_net, tvb(off, 1))
    tree:add(f.beacon_start_assoc, tvb(off, 1))
    tree:add(f.beacon_snid_high, tvb(off, 1))
    tree:add(f.beacon_net_seq, tvb(off + 1, 1))
    tree:add(f.beacon_snid, tvb(off + 2, 1))
    tree:add(f.beacon_rf_opt, tvb(off + 2, 1))
    tree:add(f.beacon_plc_cap, tvb(off + 2, 1))
    tree:add(f.beacon_rf_ch, tvb(off + 3, 1))
    tree:add(f.beacon_chnum, tvb(off + 4, 1))
    tree:add(f.beacon_netver, tvb(off + 4, 1))
    tree:add(f.beacon_mech, tvb(off + 4, 1))
    tree:add(f.beacon_disc_en, tvb(off + 4, 1))
    tree:add(f.beacon_head_rsv, tvb(off + 4, 1))
    tree:add(f.beacon_head_rsv, tvb(off + 5, 1))

    -- 信标管理信息从 off+6 到 BPCS 起点(gb_end-5)
    local pos = dissect_beacon_mgmt_info(tvb, tree, off + 6, gb_end - 5)

    -- 填充区: 管理区消费终点到 BPCS 前
    if pos < gb_end - 5 then
        tree:add(f.pb_padding, tvb(pos, gb_end - 5 - pos))
    end

    -- BPCS CRC32 (帧载荷区倒数 5..2 字节): 校验 off..gb_end-5 (不含 BPCS 与保留字节)
    if gb_end - 5 >= off then
        local bpcs_rx = tvb(gb_end - 5, 4):le_uint()
        local bpcs_calc = crc32_le(tvb, off, pbsize - 4)
        tree:add(f.beacon_bpcs, tvb(gb_end - 5, 4), bpcs_rx)
        tree:add(f.beacon_bpcs_calc, tvb(gb_end - 5, 4), bpcs_calc)
        tree:add(f.beacon_bpcs_ok, tvb(gb_end - 5, 1), bpcs_calc == bpcs_rx)
    end
    -- 保留字节 (帧载荷区最后 1B)
    tree:add(f.beacon_bpcs_rsv, tvb(gb_end - 1, 1))
    -- PB CRC24 (块尾 3B): 覆盖块内前 pbsize-3 字节
    if off + pbsize <= tvb:len() then
        local crc_rx = tvb(off + pbsize - 3, 3):le_uint()
        local crc_calc = crc24_lsb(tvb, off, pbsize)
        tree:add(f.pb_pbcs, tvb(off + pbsize - 3, 3), crc_rx)
        tree:add(f.pb_crc_calc, tvb(off + pbsize - 3, 3), crc_calc)
        tree:add(f.pb_crc_ok, tvb(off + pbsize - 3, 1), crc_calc == crc_rx)
    end
end

-- =========================================================================
-- MMe 管理消息体解析 (偏移相对 MMe 起点: 0=MMVersion, 1-2=MMType, 消息体从 6 起)
-- =========================================================================

-- 关联请求 (0x0030)
local function dissect_mme_assoc_req(tvb, tree)
    tree:add(f.ar_sta_mac, tvb(6, 6))
    -- 候选代理 TEI x5, 每个 2 字节 (TEI 12b + 链路类型 1b + 保留 3b)
    for i = 0, 4 do
        local p = 12 + i * 2
        add_tei12(tree, f.ar_proxy_tei, tvb, p)
        tree:add(f.ar_link_type, tvb(p + 1, 1))
        tree:add(f.ar_link_rsv, tvb(p + 1, 1))
    end
    tree:add(f.ar_phase, tvb(22, 1))
    tree:add(f.ar_phase, tvb(23, 1))
    tree:add(f.ar_phase, tvb(24, 1))
    tree:add(f.ar_dev_type, tvb(25, 1))
    tree:add(f.ar_rsv, tvb(26, 2))
    tree:add(f.ar_mac_type, tvb(28, 1))
    tree:add(f.ar_module, tvb(29, 1))
    tree:add(f.ar_link, tvb(29, 1))
    add_le(tree, f.ar_assoc_rand, tvb, 30, 4)
    add_span(tree, f.ar_manuf_info, tvb, 34, 18)
    -- 站点版本信息 (10B @52)
    tree:add(f.ar_boot_reason, tvb(52, 1))
    tree:add(f.ar_boot_ver, tvb(53, 1))
    add_le(tree, f.ar_soft_ver, tvb, 54, 2)
    tree:add(f.ar_ver_year, tvb(56, 1))
    add_val(tree, f.ar_ver_month, tvb, 56, 2, read_bits(tvb, 56 * 8 + 7, 4))
    add_val(tree, f.ar_ver_day, tvb, 57, 1, read_bits(tvb, 57 * 8 + 3, 5))
    add_le(tree, f.ar_manuf_id, tvb, 58, 2)
    add_le(tree, f.ar_chip_code, tvb, 60, 2)
    add_le(tree, f.ar_hard_rst, tvb, 62, 2)
    add_le(tree, f.ar_soft_rst, tvb, 64, 2)
    tree:add(f.ar_proxy_type, tvb(66, 1))
    tree:add(f.ar_net_sn, tvb(67, 1))
    tree:add(f.ar_mme_ver, tvb(68, 1))
    tree:add(f.ar_band_support, tvb(69, 1))
    add_le(tree, f.ar_e2e_seq, tvb, 70, 4)
end

-- 路由信息 (关联确认/关联指示共用): 汇总头 8B + 直连站点(2B/条) + 直连代理(4B/条,含子站点)
local function dissect_route_info(tvb, tree, off)
    if off + 8 > tvb:len() then return end
    local sta_sum = read_bits(tvb, off * 8, 16)
    local pco_sum = read_bits(tvb, (off + 2) * 8, 16)
    add_le(tree, f.ri_straight_sta, tvb, off, 2)
    add_le(tree, f.ri_straight_pco, tvb, off + 2, 2)
    add_le(tree, f.ri_table_size, tvb, off + 4, 2)
    add_le(tree, f.ri_rsv, tvb, off + 6, 2)
    local pos = off + 8
    -- 直连站点条目: 每个 2 字节
    for i = 1, sta_sum do
        if pos + 2 > tvb:len() then return end
        add_tei12(tree, f.ri_sta_tei, tvb, pos)
        tree:add(f.ri_link_type, tvb(pos + 1, 1))
        tree:add(f.ri_link_rsv, tvb(pos + 1, 1))
        pos = pos + 2
    end
    -- 直连代理条目: 每个 4 字节 (PCO TEI + 链路 + 子站点数) + 子站点(2B/条)
    for i = 1, pco_sum do
        if pos + 4 > tvb:len() then return end
        add_tei12(tree, f.ri_pco_tei, tvb, pos)
        tree:add(f.ri_link_type, tvb(pos + 1, 1))
        tree:add(f.ri_link_rsv, tvb(pos + 1, 1))
        local child_sum = read_bits(tvb, (pos + 2) * 8, 16)
        add_le(tree, f.ri_pco_child_cnt, tvb, pos + 2, 2)
        pos = pos + 4
        for c = 1, child_sum do
            if pos + 2 > tvb:len() then return end
            add_tei12(tree, f.ri_child_tei, tvb, pos)
            pos = pos + 2
        end
    end
end

-- 关联确认 (0x0031)
local function dissect_mme_assoc_cnf(tvb, tree)
    tree:add(f.ac_sta_mac, tvb(6, 6))
    tree:add(f.ac_result, tvb(12, 1))
    tree:add(f.ac_sta_level, tvb(13, 1))
    local sta_tei = read_bits(tvb, 14 * 8, 12)
    add_tei12(tree, f.ac_sta_tei, tvb, 14)
    add_le(tree, f.ac_proxy_tei, tvb, 16, 2)
    tree:add(f.ac_total_pkgs, tvb(18, 1))
    tree:add(f.ac_pkg_idx, tvb(19, 1))
    tree:add(f.ac_last_pkg, tvb(20, 1))
    tree:add(f.ac_link_type, tvb(21, 1))
    tree:add(f.ac_carrier, tvb(21, 1))
    add_le(tree, f.ac_assoc_rand, tvb, 22, 4)
    add_le(tree, f.ac_reassoc_time, tvb, 26, 4)
    add_le(tree, f.ac_e2e_seq, tvb, 30, 4)
    add_le(tree, f.ac_path_seq, tvb, 34, 4)
    tree:add(f.ac_net_sn, tvb(38, 1))
    tree:add(f.ac_mme_ver, tvb(39, 1))
    tree:add(f.ac_detech, tvb(39, 1))
    -- 记录 TEI ↔ MAC 映射 (CCO 分配的站点 TEI 与站点 MAC)
    record_tei_mac(sta_tei, mac_to_str(tvb, 6))
    -- 路由信息 (@42)
    dissect_route_info(tvb, tree, 42)
end

-- 代理变更请求 (0x0032)
local function dissect_mme_cproxy_req(tvb, tree)
    add_le(tree, f.cpr_sta_tei, tvb, 6, 2)
    -- 新代理 TEI x5, 每个 2 字节
    for i = 0, 4 do
        local p = 8 + i * 2
        add_tei12(tree, f.cpr_new_proxy, tvb, p)
        tree:add(f.cpr_link_type, tvb(p + 1, 1))
        tree:add(f.cpr_link_rsv, tvb(p + 1, 1))
    end
    add_le(tree, f.cpr_old_proxy, tvb, 18, 2)
    tree:add(f.cpr_proxy_type, tvb(20, 1))
    tree:add(f.cpr_reason, tvb(21, 1))
    tree:add(f.cpr_phase, tvb(22, 1))
    tree:add(f.cpr_phase, tvb(23, 1))
    tree:add(f.cpr_phase, tvb(24, 1))
    tree:add(f.cpr_link, tvb(25, 1))
    add_le(tree, f.cpr_e2e_seq, tvb, 26, 4)
    tree:add(f.cpr_net_sn, tvb(30, 1))
    tree:add(f.cpr_rsv, tvb(31, 15))
end

-- 关联指示 (0x0034)
local function dissect_mme_assoc_ind(tvb, tree)
    tree:add(f.ai_result, tvb(6, 1))
    tree:add(f.ai_sta_level, tvb(7, 1))
    tree:add(f.ai_sta_mac, tvb(8, 6))
    tree:add(f.ai_cco_mac, tvb(14, 6))
    local sta_tei = read_bits(tvb, 20 * 8, 12)
    add_tei12(tree, f.ai_sta_tei, tvb, 20)
    add_le(tree, f.ai_proxy_tei, tvb, 22, 2)
    tree:add(f.ai_link_type, tvb(24, 1))
    tree:add(f.ai_carrier, tvb(24, 1))
    tree:add(f.ai_rsv, tvb(24, 3))
    tree:add(f.ai_total_pkgs, tvb(27, 1))
    tree:add(f.ai_pkg_idx, tvb(28, 1))
    tree:add(f.ai_last_pkg, tvb(29, 1))
    add_le(tree, f.ai_assoc_rand, tvb, 30, 4)
    tree:add(f.ai_net_sn, tvb(51, 1))
    tree:add(f.ai_rsv, tvb(52, 2))
    add_le(tree, f.ai_reassoc_time, tvb, 54, 4)
    add_le(tree, f.ai_e2e_seq, tvb, 58, 4)
    tree:add(f.ai_rsv, tvb(62, 8))
    -- 记录 TEI ↔ MAC 映射
    record_tei_mac(sta_tei, mac_to_str(tvb, 8))
    -- 路由信息 (@70)
    dissect_route_info(tvb, tree, 70)
end

-- 代理变更确认 (0x0037)
local function dissect_mme_cproxy_cnf(tvb, tree)
    add_le(tree, f.cpc_result, tvb, 6, 4)
    tree:add(f.cpc_total_pkgs, tvb(10, 1))
    tree:add(f.cpc_pkg_idx, tvb(11, 1))
    add_le(tree, f.cpc_sta_tei, tvb, 12, 2)
    add_le(tree, f.cpc_proxy_tei, tvb, 14, 2)
    local child_cnt = read_bits(tvb, 128, 16)
    add_le(tree, f.cpc_child_cnt, tvb, 16, 2)
    tree:add(f.cpc_rsv, tvb(18, 1))
    tree:add(f.cpc_net_sn, tvb(19, 1))
    tree:add(f.cpc_link_type, tvb(20, 1))
    tree:add(f.cpc_rsv, tvb(21, 1))
    add_le(tree, f.cpc_e2e_seq, tvb, 22, 4)
    add_le(tree, f.cpc_path_seq, tvb, 26, 4)
    tree:add(f.cpc_rsv, tvb(30, 8))
    -- 子站点条目 (@38): 每个 2 字节 (TEI 12b + 链路类型 + 保留)
    for i = 0, child_cnt - 1 do
        local p = 38 + i * 2
        if p + 2 > tvb:len() then break end
        add_tei12(tree, f.cpc_child_tei, tvb, p)
        tree:add(f.ri_link_type, tvb(p + 1, 1))
        tree:add(f.ri_link_rsv, tvb(p + 1, 1))
    end
end

-- 关联汇总指示 (0x003A)
local function dissect_mme_assoc_gather(tvb, tree)
    tree:add(f.ag_result, tvb(6, 1))
    tree:add(f.ag_sta_level, tvb(7, 1))
    tree:add(f.ag_cco_mac, tvb(8, 6))
    add_tei12(tree, f.ag_proxy_tei, tvb, 14)
    tree:add(f.ag_net_sn, tvb(16, 1))
    local cnt = tvb(17, 1):uint()
    tree:add(f.ag_gather_cnt, tvb(17, 1))
    tree:add(f.ag_carrier, tvb(18, 1))
    tree:add(f.ag_rsv, tvb(19, 15))
    -- 新站点信息 (@34): 每条 8 字节 (MAC 6B + TEI 12b + 保留 4b)
    for i = 0, cnt - 1 do
        local p = 34 + i * 8
        if p + 8 > tvb:len() then break end
        tree:add(f.ag_sta_mac, tvb(p, 6))
        local sta_tei = read_bits(tvb, (p + 6) * 8, 12)
        add_tei12(tree, f.ag_sta_tei, tvb, p + 6)
        -- 记录 TEI ↔ MAC 映射
        record_tei_mac(sta_tei, mac_to_str(tvb, p))
    end
end

-- 代理变更确认位图版 (0x003B)
local function dissect_mme_cproxy_bmp(tvb, tree)
    add_le(tree, f.cpb_result, tvb, 6, 4)
    add_le(tree, f.cpb_sta_tei, tvb, 10, 2)
    add_le(tree, f.cpb_proxy_tei, tvb, 12, 2)
    tree:add(f.cpb_net_sn, tvb(14, 1))
    -- 子站点位图 (@15, 130B)
    dissect_tei_bitmap(tvb, tree, 15, 130, f.cpb_child_bmp, T("子站点位图", "Child STA Bitmap"), "Child STA Bitmap")
    tree:add(f.cpb_link_type, tvb(145, 1))
    add_le(tree, f.cpb_e2e_seq, tvb, 146, 4)
    add_le(tree, f.cpb_path_seq, tvb, 150, 4)
end

-- 离线指示 (0x0049)
local function dissect_mme_leave(tvb, tree)
    add_le(tree, f.li_sta_tei, tvb, 6, 2)
    add_le(tree, f.li_reason, tvb, 8, 2)
    tree:add(f.li_sta_mac, tvb(10, 6))
    add_le(tree, f.li_proxy_tei, tvb, 16, 2)
    tree:add(f.li_rsv, tvb(18, 8))
end

-- 心跳检测 (0x0051)
local function dissect_mme_heartbeat(tvb, tree)
    add_le(tree, f.hb_ostei, tvb, 6, 2)
    add_le(tree, f.hb_max_disc_tei, tvb, 8, 2)
    add_le(tree, f.hb_max_disc_cnt, tvb, 10, 4)
    -- 可发现站点位图 (@14, 130B) + 保留 (@144)
    -- 依规约表196: 原始源TEI 0-1 / 发现站点数最大TEI 2-3 / 最大发现数 4-7 /
    --              可发现站点TEI位图 8-137 / 保留 138; body 起点 tvb 6 → 位图 @14
    dissect_tei_bitmap(tvb, tree, 14, 130, f.hb_disc_bmp, T("可发现站点位图", "Discoverable STA Bitmap"), "Discoverable STA Bitmap")
    tree:add(f.hb_rsv, tvb(144, 1))
end

-- 发现列表 (0x0055)
local function dissect_mme_disc_list(tvb, tree)
    local tei = read_bits(tvb, 6 * 8, 16)
    add_le(tree, f.dl_tei, tvb, 6, 2)
    tree:add(f.dl_role, tvb(8, 1))
    tree:add(f.dl_level, tvb(9, 1))
    tree:add(f.dl_mac, tvb(10, 6))
    add_le(tree, f.dl_proxy_tei, tvb, 16, 2)
    tree:add(f.dl_rsv, tvb(18, 3))
    tree:add(f.dl_rate_finish, tvb(21, 1))
    add_le(tree, f.dl_proxy_rate, tvb, 22, 4)
    add_le(tree, f.dl_proxy_dl_rate, tvb, 26, 4)
    local node_num = read_bits(tvb, 240, 16)
    add_le(tree, f.dl_sta_cnt, tvb, 30, 2)
    add_le(tree, f.dl_send_cnt, tvb, 32, 2)
    local up_route_cnt = read_bits(tvb, 272, 16)
    add_le(tree, f.dl_up_route_cnt, tvb, 34, 2)
    tree:add(f.dl_up_route_size, tvb(36, 1))
    tree:add(f.dl_rsv, tvb(37, 2))
    add_le(tree, f.dl_route_remain, tvb, 39, 2)
    tree:add(f.dl_phase0, tvb(41, 1))
    tree:add(f.dl_phase1, tvb(41, 1))
    tree:add(f.dl_phase2, tvb(41, 1))
    tree:add(f.dl_min_rate, tvb(42, 1))
    tree:add(f.dl_rsv, tvb(43, 5))
    -- 记录 TEI ↔ MAC 映射 (发送发现列表报文的站点)
    record_tei_mac(read_bits(tvb, 6 * 8, 16), mac_to_str(tvb, 10))
    -- 上行路由条目 (@48): 每条 3 字节 (下一跳TEI 12b + 保留4b + 路由类型 8b)
    local pos = 48
    for i = 0, up_route_cnt - 1 do
        if pos + 3 > tvb:len() then break end
        add_tei12(tree, f.dl_next_hop_tei, tvb, pos)
        tree:add(f.ri_link_rsv, tvb(pos + 1, 1))
        tree:add(f.dl_route_type, tvb(pos + 2, 1))
        pos = pos + 3
    end
    -- 发现站点列表位图 (128B, bit 位置 = TEI)
    dissect_tei_bitmap(tvb, tree, pos, 128, f.dl_disc_bmp, T("发现站点列表位图", "Discovery STA List Bitmap"), "Discovery STA List Bitmap")
    -- 收到发现列表信息: 条目数 = 位图中置位 bit 总数, 每个 1 字节, 依次对应置位 TEI
    local rcv_pos = pos + 128
    if rcv_pos <= tvb:len() then
        local order = 0
        for bi = 0, 127 do
            local b = tvb(pos + bi, 1):uint()
            for j = 0, 7 do
                if band(b, 2 ^ j) ~= 0 then
                    local tei2 = bi * 8 + j
                    if rcv_pos + order < tvb:len() then
                        local v = tvb(rcv_pos + order, 1):uint()
                        tree:add(f.dl_rcv_cnt, tvb(rcv_pos + order, 1), v)
                        tree:add(f.dl_rcv_item, tvb(rcv_pos + order, 1),
                            string.format(T("接收发现列表数[%d] (TEI %d): %d", "Rcv Discovery List Count[%d] (TEI %d): %d"), order, tei2, v))
                    end
                    order = order + 1
                end
            end
        end
    end
end

-- 延迟离线指示 (0x005D)
local function dissect_mme_delay_leave(tvb, tree)
    add_le(tree, f.dl2_reason, tvb, 6, 2)
    local sta_cnt = read_bits(tvb, 64, 16)
    add_le(tree, f.dl2_sta_cnt, tvb, 8, 2)
    add_le(tree, f.dl2_delay, tvb, 10, 2)
    tree:add(f.dl2_rsv, tvb(12, 10))
    -- 离线站点 MAC (@22): 每条 6 字节
    for i = 0, sta_cnt - 1 do
        local p = 22 + i * 6
        if p + 6 > tvb:len() then break end
        tree:add(f.dl2_sta_mac, tvb(p, 6))
    end
end

-- 通信成功率上报 (0x005E)
local function dissect_mme_succ_rate(tvb, tree)
    add_le(tree, f.sr_proxy_tei, tvb, 6, 2)
    local cnt = read_bits(tvb, 64, 16)
    add_le(tree, f.sr_sta_cnt, tvb, 8, 2)
    -- 站点成功率条目 (@10): 每条 4 字节 (TEI 16b + 下行 8b + 上行 8b)
    for i = 0, cnt - 1 do
        local p = 10 + i * 4
        if p + 4 > tvb:len() then break end
        add_le(tree, f.sr_sta_tei, tvb, p, 2)
        tree:add(f.sr_down_rate, tvb(p + 2, 1))
        tree:add(f.sr_up_rate, tvb(p + 3, 1))
    end
end

-- 过零NTB采集指示 (0x0062)
local function dissect_mme_zc_collect(tvb, tree)
    tree:add(f.zc_quantity, tvb(6, 1))
    tree:add(f.zc_seq, tvb(7, 1))
    add_le(tree, f.zc_rsv, tvb, 8, 2)
end

-- 过零NTB上报 (0x0063): 相线1/2/3差值列表 (每差值 2B 16bit, 按相线顺序)
local function dissect_mme_zc_report(tvb, tree)
    add_tei12(tree, f.zr_tei, tvb, 6)
    tree:add(f.zr_collect_mode, tvb(7, 1))
    tree:add(f.zr_seq, tvb(8, 1))
    tree:add(f.zr_total_cnt, tvb(9, 1))
    add_le(tree, f.zr_base_ntb, tvb, 10, 4)
    tree:add(f.zr_rsv, tvb(14, 1))
    local n1 = tvb(15, 1):uint()
    local n2 = tvb(16, 1):uint()
    local n3 = tvb(17, 1):uint()
    tree:add(f.zr_ph1_cnt, tvb(15, 1))
    tree:add(f.zr_ph2_cnt, tvb(16, 1))
    tree:add(f.zr_ph3_cnt, tvb(17, 1))
    local pos = 18
    local function add_diffs(cnt)
        for i = 1, cnt do
            if pos + 2 > tvb:len() then return end
            add_le(tree, f.zr_diff, tvb, pos, 2)
            pos = pos + 2
        end
    end
    add_diffs(n1)
    add_diffs(n2)
    add_diffs(n3)
end

-- 网络诊断 (0x0064)
local function dissect_mme_diag(tvb, tree)
    add_le(tree, f.diag_chip_id, tvb, 6, 2)
    if tvb:len() > 8 then
        add_span(tree, f.diag_custom, tvb, 8, nil)
    end
end

-- MMe 消息体分发
-- NW_2026 (SPLC) 新增 MMe 报文体(表153-164/243-247)
local function dissect_mme_bitload_req(tvb, tree)
    -- 表153(PDF 第62页原文): 偏移含 6B MMe 头(与 C++ add_fields(mme,6,...) 同基)——
    -- 源TEI 12b(mme6)/目的TEI 12b(mme7.5,跨字节)/流数(mme9)/截止载波 9b(mme9.1)/
    -- 保留(mme10-11)/比特加载表长度 16b(mme12-13)/可变表自 mme14
    add_val(tree, f.mme_bl_src, tvb, 6, 2, read_bits(tvb, 48, 12))
    add_val(tree, f.mme_bl_dst, tvb, 7, 2, read_bits(tvb, 60, 12))
    tree:add(f.mme_bl_stream, tvb(9, 1))
    add_val(tree, f.mme_bl_cut, tvb, 9, 2, read_bits(tvb, 73, 9))
    add_val(tree, f.mme_bl_rsv0, tvb, 10, 1, read_bits(tvb, 82, 6))
    tree:add(f.mme_bl_rsv1, tvb(11, 1))
    add_val(tree, f.mme_bl_tablen, tvb, 12, 2, tvb(12, 2):le_uint())
    if tvb:len() > 14 then local t = tree:add(f.pb_tbl, tvb(14)); t:append_text(": " .. T("可变比特加载表", "Variable Bit Load Table")) end
end
local function dissect_mme_bitload_cnf(tvb, tree)
    -- 表157(PDF 第63页原文,与 C++ kMMeBitLoadUpdateCnfSpec 同表): 4B
    -- 源TEI 12b(0,0) + 目的TEI 12b(1,4,跨字节) + 更新结果 1b(3,0) + 保留 7b(3,1-7)
    -- 偏移含 6B MMe 头(同上):源TEI(mme6)/目的TEI(mme7.5)/更新结果 1b(mme9.0)/保留 7b
    add_val(tree, f.mme_bl_src, tvb, 6, 2, read_bits(tvb, 48, 12))
    add_val(tree, f.mme_bl_dst, tvb, 7, 2, read_bits(tvb, 60, 12))
    add_val(tree, f.mme_bl_result, tvb, 9, 1, read_bits(tvb, 72, 1))
end
local function dissect_mme_ru_snr(tvb, tree)
    -- 表158:固定头 8B 自 MMe 头 6B 之后(mme[6..13],与 C++ add_fields(mme,6,...) 同基);
    -- 邻居站点位图 + 邻居 RU_SNR(表159,每邻居 4B: RU0-RU5 各 5bit SNR + 保留 2bit)
    add_val(tree, f.mme_bl_src, tvb, 6, 2, read_bits(tvb, 48, 12))
    add_val(tree, f.mme_ru_start, tvb, 7, 2, read_bits(tvb, 60, 12))
    tree:add(f.mme_ru_gid, tvb(9, 1))
    tree:add(f.mme_ru_num, tvb(10, 2), tvb(10, 2):le_uint())
    tree:add(f.mme_ru_bmlen, tvb(12, 2), tvb(12, 2):le_uint())
    if tvb:len() <= 14 then return end
    local bm_len = tvb(12, 2):le_uint()
    local nb_num = tvb(10, 2):le_uint()
    local gid = tvb(9, 1):uint()
    local nb_start_tei = read_bits(tvb, 60, 12)
    -- 表159 各 RU 5bit SNR 的载波范围(仅 RU分组 ID0 有定义)
    local ru_carrier = {{32,101},{109,178},{186,255},{263,332},{340,409},{417,490}}
    if bm_len > 0 and 14 + bm_len <= tvb:len() then
        local bmn = tree:add(f.pb_tbl, tvb(14, bm_len))
        bmn:append_text(": " .. T("邻居站点位图", "Neighbor Bitmap"))
        -- 位图逐位展开(位序与表226 一致:byte k/8 的 bit k%8,LSB 在前):
        -- bit=1 的邻居 TEI = NeighborStartTEI + k(表158 语义),值标注该 bit
        -- 所在的字节号(k>>3);bit=0 的位不列
        for k = 0, bm_len * 8 - 1 do
            local byte_i = math.floor(k / 8)
            local byte_val = tvb(14 + byte_i, 1):uint()
            if math.floor(byte_val / 2 ^ (k % 8)) % 2 == 1 then
                bmn:add(nw, tvb(14 + byte_i, 1),
                    string.format(T("Neighbor[%d] TEI=%d", "Neighbor[%d] TEI=%d"),
                                  k, nb_start_tei + k)
                        .. string.format(T("在位图(第%d字节)", "in bitmap (byte %d)"),
                                         byte_i))
            end
        end
    end
    local nb_start = 14 + bm_len
    for i = 0, nb_num - 1 do
        if gid ~= 0 or nb_start + (i + 1) * 4 > tvb:len() then break end
        local b = nb_start + i * 4
        local g = tree:add(nw, tvb(b, 4),
            string.format(T("邻居 RU_SNR[%d]", "Neighbor RU_SNR [%d]"), i))
        for k = 0, 5 do
            local v = read_bits(tvb, b * 8 + k * 5, 5)
            local it = g:add(f.mme_ru_snr, tvb(b + math.floor((k * 5) / 8), 2), v)
            it:append_text(string.format(T(" (RU%d_SNR)", " (RU%d_SNR)"), k)
                .. string.format(T(" (载波 %d-%d)", " (carrier %d-%d)"),
                    ru_carrier[k + 1][1], ru_carrier[k + 1][2]))
        end
    end
end
local function dissect_mme_tei_list(tvb, tree, is_cnf)
    -- 表160/161:固定头 8B 自 MMe 头 6B 之后(mme[6..13]),列表自 mme[14]
    tree:add(f.mme_tei_seq, tvb(6, 1))
    tree:add(f.mme_tei_mac, tvb(7, 6))
    local n = tvb(13, 1):uint()
    tree:add(f.mme_tei_num, tvb(13, 1), n)
    local p = 14
    for i = 0, n - 1 do
        if is_cnf then
            if p + 8 > tvb:len() then break end
            tree:add(f.mme_tei_stmac, tvb(p, 6))
            add_val(tree, f.mme_tei_tei, tvb, p+6, 2, read_bits(tvb, p*8+6*8, 12))
            p = p + 8
        else
            if p + 6 > tvb:len() then break end
            tree:add(f.mme_tei_stmac, tvb(p, 6))
            p = p + 6
        end
    end
end
local function dissect_mme_ext_net_conflict(tvb, tree)
    -- 表163/164:固定头 7B 自 MMe 头 6B 之后(mme[6..12]),条目自 mme[13](SNID 5b+保留 3b)
    tree:add(f.mme_xnc_mac, tvb(6, 6))
    local n = tvb(12, 1):uint()
    tree:add(f.mme_xnc_num, tvb(12, 1), n)
    for i = 0, n - 1 do
        if 13 + i >= tvb:len() then break end
        add_val(tree, f.mme_xnc_snid, tvb, 13 + i, 1, read_bits(tvb, (13 + i) * 8, 5))
    end
end
local function dissect_mme_iot_assoc_req(tvb, tree)
    -- 表243:固定体 10B 自 MMe 头 6B 之后(mme[6..15])
    tree:add(f.mme_iot_mac, tvb(6, 6))
    add_val(tree, f.mme_iot_gw, tvb, 12, 2, read_bits(tvb, 96, 12))
    tree:add(f.mme_iot_rsv, tvb(13, 1))
    tree:add(f.mme_iot_dev, tvb(14, 1))
    tree:add(f.mme_iot_pwr, tvb(15, 1))
    tree:add(f.mme_iot_rsv2, tvb(15, 1))   -- 表243 byte9 高4b 保留(与功耗类型同字节)
end
local function dissect_mme_iot_assoc_ind(tvb, tree)
    -- 表244:固定体 7B 自 MMe 头 6B 之后
    tree:add(f.mme_iot_mac, tvb(6, 6))
    tree:add(f.mme_iot_result, tvb(12, 1))
end
local function dissect_mme_iot_leave_ind(tvb, tree)
    -- 表246:固定体 7B 自 MMe 头 6B 之后
    tree:add(f.mme_iot_mac, tvb(6, 6))
    tree:add(f.mme_iot_reason, tvb(12, 1))
end

local function dissect_mme_body(tvb, tree, mmtype)
    if mmtype == 0x0030 then dissect_mme_assoc_req(tvb, tree)
    elseif mmtype == 0x0031 then dissect_mme_assoc_cnf(tvb, tree)
    elseif mmtype == 0x0032 then dissect_mme_cproxy_req(tvb, tree)
    elseif mmtype == 0x0034 then dissect_mme_assoc_ind(tvb, tree)
    elseif mmtype == 0x0037 then dissect_mme_cproxy_cnf(tvb, tree)
    elseif mmtype == 0x003A then dissect_mme_assoc_gather(tvb, tree)
    elseif mmtype == 0x003B then dissect_mme_cproxy_bmp(tvb, tree)
    elseif mmtype == 0x0049 then dissect_mme_leave(tvb, tree)
    elseif mmtype == 0x0051 then dissect_mme_heartbeat(tvb, tree)
    elseif mmtype == 0x0055 then dissect_mme_disc_list(tvb, tree)
    elseif mmtype == 0x005D then dissect_mme_delay_leave(tvb, tree)
    elseif mmtype == 0x005E then dissect_mme_succ_rate(tvb, tree)
    elseif mmtype == 0x0062 then dissect_mme_zc_collect(tvb, tree)
    elseif mmtype == 0x0063 then dissect_mme_zc_report(tvb, tree)
    elseif mmtype == 0x0064 then dissect_mme_diag(tvb, tree)
    elseif mmtype == 0x0080 then dissect_mme_bitload_req(tvb, tree)
    elseif mmtype == 0x0081 then dissect_mme_bitload_cnf(tvb, tree)
    elseif mmtype == 0x0082 then dissect_mme_ru_snr(tvb, tree)
    elseif mmtype == 0x0083 then dissect_mme_tei_list(tvb, tree, false)
    elseif mmtype == 0x0084 then dissect_mme_tei_list(tvb, tree, true)
    elseif mmtype == 0x0085 then dissect_mme_ext_net_conflict(tvb, tree)
    elseif mmtype == 0x00A0 then dissect_mme_iot_assoc_req(tvb, tree)
    elseif mmtype == 0x00A1 then dissect_mme_iot_assoc_ind(tvb, tree)
    elseif mmtype == 0x00A2 then dissect_mme_iot_leave_ind(tvb, tree)
    end
end

-- 管理消息体里「单一 MMe 主体」的 STA MAC 字符串 + TEI(代理转发判定 + STA-N 显示);
-- 无单一主体(批量/网关/无主体)返回 nil,nil。偏移与各 dissect_mme_* 字段一致。
local function mme_body_sta_mac_tei(mmtype, tvb)
    if mmtype == 0x0030 then return mac_to_str(tvb, 6), 0                          -- 关联请求 STAMACAddr@6(无 TEI)
    elseif mmtype == 0x0031 then return mac_to_str(tvb, 6), read_bits(tvb, 14 * 8, 12)   -- 关联确认 STAMACAddr@6,STATEI@14
    elseif mmtype == 0x0034 then return mac_to_str(tvb, 8), read_bits(tvb, 20 * 8, 12)   -- 关联指示 STAMACAddr@8,STATEI@20
    elseif mmtype == 0x0049 then return mac_to_str(tvb, 10), read_bits(tvb, 6 * 8, 16)   -- 离网指示 MAC@10,TEI@6
    elseif mmtype == 0x0055 then return mac_to_str(tvb, 10), read_bits(tvb, 6 * 8, 16)   -- 发现列表 MACAddr@10,STATEI@6
    end
    return nil, nil
end

-- =========================================================================
-- APP 应用层报文 (通道控制信息 4B + 业务报文头 8B + APP Data)
-- =========================================================================
local function dissect_app(tvb, tree, pinfo, no_info)
    if tvb:len() < 12 then return nil end
    -- 通道控制信息 (4B)
    tree:add(f.app_port, tvb(0, 1))
    tree:add(f.app_packet_id, tvb(1, 2), read_bits(tvb, 8, 16))
    tree:add(f.app_rsv, tvb(3, 1))
    -- 业务报文头 (8B)
    local packet_type = band(tvb(4, 1):uint(), 0x0F)
    local bid = tvb(6, 1):uint()
    tree:add(f.app_packet_type, tvb(4, 1))
    tree:add(f.app_ctrl_rsv0, tvb(4, 1))
    tree:add(f.app_ctrl_rsv1, tvb(5, 1))
    tree:add(f.app_ext_flag, tvb(5, 1))
    tree:add(f.app_respond_flag, tvb(5, 1))
    tree:add(f.app_start_flag, tvb(5, 1))
    tree:add(f.app_trans_dir, tvb(5, 1))
    tree:add(f.app_business_id, tvb(6, 1))
    -- 业务标识释义 (依赖帧类型域, 表9)
    local port = tvb(0, 1):uint()
    local bid_name = business_id_name(port, packet_type, bid)
    if bid_name then
        tree:add(f.app_bid_desc, tvb(6, 1), bid_name)
    end
    tree:add(f.app_version, tvb(7, 1))
    add_le(tree, f.app_packet_sn, tvb, 8, 2)
    add_le(tree, f.app_packet_len, tvb, 10, 2)
    -- 应用层载荷 (业务报文头之后, 含业务扩展域)
    if tvb:len() > 12 then
        add_span(tree, f.app_payload, tvb, 12, nil)
    end
    -- 子帧摘要(C++ cm.summary 格式: 应用报文 类型 (BID=0xXX 释义)), 供聚合帧收集
    local pt_name = app_packet_type_vals[packet_type] or string.format("0x%X", packet_type)
    local summary = string.format(
        T("应用报文 %s (BID=0x%02X%s)", "APP %s (BID=0x%02X%s)"),
        pt_name, bid, (bid_name and (" " .. bid_name) or ""))
    -- info 列追加帧类型 + BID 释义 (非聚合帧)
    if not no_info then
        local cur_info = tostring(pinfo.cols.info)
        if bid_name then
            pinfo.cols.info = cur_info .. string.format(" APP[%s BID=0x%02X %s]", pt_name, bid, bid_name)
        else
            pinfo.cols.info = cur_info .. string.format(" APP[%s BID=0x%02X]", pt_name, bid)
        end
    end
    return summary
end

-- =========================================================================
-- MAC 帧解析 (输入为 SOF 各物理块块体重组出的 MAC 帧 tvb)
-- =========================================================================
-- =========================================================================
-- NW_2026 (SPLC) 新增: 单跳帧链(表113/114/214/215/217/218/219-220/226-227) 字段
-- =========================================================================
f.rf_mac = ProtoField.ether ("nw_2026.rf.mac", T("站点 MAC 地址", "Station MAC Address"))
f.rf_seq = ProtoField.uint8 ("nw_2026.rf.seq", T("统计序号", "Statistics Sequence Number"), base.DEC)
local rf_ie_type_vals = {
    [0] = T("站点属性信息", "STA attribute info"), [1] = T("站点路由信息", "STA route info"),
    [2] = T("邻居节点信道信息(非位图版)", "Neighbor channel info (non-bitmap)"),
    [3] = T("邻居节点信道信息(位图版)", "Neighbor channel info (bitmap)"),
}
f.rf_ie_type = ProtoField.uint8 ("nw_2026.rf.ie.type", T("信息单元类型", "Information Element Type"), base.DEC, rf_ie_type_vals, 0x7F)
f.rf_ie_ltype = ProtoField.uint8 ("nw_2026.rf.ie.ltype", T("长度类型", "Length Type"), base.DEC, {
    [0] = T("1字节长度", "1-byte length"), [1] = T("2字节长度", "2-byte length"),
}, 0x80)
f.rf_ie_len = ProtoField.uint16 ("nw_2026.rf.ie.len", T("信息单元长度", "Information Element Length"), base.DEC)
f.rf_attr_cco = ProtoField.ether ("nw_2026.rf.attr.cco", T("CCO MAC 地址", "CCO MAC Address"))
f.rf_attr_proxy = ProtoField.uint16 ("nw_2026.rf.attr.proxy", T("代理 TEI", "Proxy TEI"), base.DEC)
f.rf_attr_role = ProtoField.uint8 ("nw_2026.rf.attr.role", T("角色", "Role"), base.DEC, role_vals, 0xF0)
f.rf_attr_level = ProtoField.uint8 ("nw_2026.rf.attr.level", T("层级", "Level"), base.DEC, nil, 0x0F)
f.rf_attr_hop = ProtoField.uint8 ("nw_2026.rf.attr.hop", T("链路 RF 跳数", "RF Link Hop"), base.DEC, nil, 0xF0)
f.rf_attr_up = ProtoField.uint8 ("nw_2026.rf.attr.up", T("代理上行接收率(%)", "Proxy Up Rate (%)"), base.DEC)
f.rf_attr_down = ProtoField.uint8 ("nw_2026.rf.attr.down", T("代理下行接收率(%)", "Proxy Down Rate (%)"), base.DEC)
f.rf_attr_min = ProtoField.uint8 ("nw_2026.rf.attr.min", T("链路最小接收率(%)", "Min Link Rate (%)"), base.DEC)
f.rf_attr_period = ProtoField.uint8 ("nw_2026.rf.attr.period", T("无线发现列表周期(s)", "RF Discover Period (s)"), base.DEC)
f.rf_attr_aging = ProtoField.uint8 ("nw_2026.rf.attr.aging", T("接收率老化周期个数", "Rate Aging Cycles"), base.DEC)
f.rf_route_tei = ProtoField.uint16 ("nw_2026.rf.route.tei", T("下一跳站点 TEI", "Next-hop TEI"), base.DEC)
f.rf_route_type = ProtoField.uint8 ("nw_2026.rf.route.type", T("路由类型", "Route Type"), base.DEC, {
    [0] = T("错误的路由类型", "Invalid route type"), [1] = T("同级备份路由类型", "Same-level backup route"),
    [2] = T("上级备份路由类型", "Upper-level backup route"), [3] = T("代理主路径路由类型", "Proxy main path route"),
    [4] = T("上上级路由类型", "Upper-upper-level route"),
}, 0xF0)
f.rf_combo = ProtoField.uint8 ("nw_2026.rf.combo", T("信道信息组合类型", "Channel Info Combo Type"), base.DEC, nil, 0x0F)
f.rf_nbr_tei = ProtoField.uint16 ("nw_2026.rf.nbr.tei", T("邻居 TEI", "Neighbor TEI"), base.DEC)
f.rf_nbr_rate = ProtoField.uint16 ("nw_2026.rf.nbr.rate", T("接收率", "Receive Rate"), base.DEC)
f.rf_nbr_snr = ProtoField.uint16 ("nw_2026.rf.nbr.snr", T("平均信噪比", "Average SNR"), base.DEC)
f.rf_nbr_rssi = ProtoField.uint16 ("nw_2026.rf.nbr.rssi", T("信号强度", "Signal Strength"), base.DEC)
f.rf_grp_tei = ProtoField.uint16 ("nw_2026.rf.grp.tei", T("位图起始 TEI", "Bitmap Start TEI"), base.DEC)
f.rf_grp_size = ProtoField.uint8 ("nw_2026.rf.grp.size", T("位图大小(B)", "Bitmap Size (bytes)"), base.DEC)
f.rf_grp_bitmap = ProtoField.bytes ("nw_2026.rf.grp.bitmap", T("位图", "Bitmap"), base.NONE)
-- SPLC 新增 MMe(表153-164/243-247)
f.mme_bl_src = ProtoField.uint16 ("nw_2026.mme.bl.src", T("源 TEI", "Source TEI"), base.DEC)
f.mme_bl_dst = ProtoField.uint16 ("nw_2026.mme.bl.dst", T("目的 TEI", "Destination TEI"), base.DEC)
f.mme_bl_stream = ProtoField.uint8 ("nw_2026.mme.bl.stream", T("流数", "Stream Number"), base.DEC, {
    [0] = T("单流", "Single stream"), [1] = T("双流", "Dual stream"),
}, 0x01)
f.mme_bl_cut = ProtoField.uint16 ("nw_2026.mme.bl.cut", T("截止载波", "Cut-off Carrier"), base.DEC)
f.mme_bl_tablen = ProtoField.uint16 ("nw_2026.mme.bl.tablen", T("比特加载表长度(B)", "Bit Load Table Length (bytes)"), base.DEC)
f.mme_bl_rsv0 = ProtoField.uint8 ("nw_2026.mme.bl.rsv0", T("保留(表153 byte4)", "Reserved (Table 153 byte4)"), base.HEX, nil, 0xFC)
f.mme_bl_rsv1 = ProtoField.uint8 ("nw_2026.mme.bl.rsv1", T("保留(表153 byte5)", "Reserved (Table 153 byte5)"), base.HEX)
f.mme_iot_rsv = ProtoField.uint8 ("nw_2026.mme.iot.rsv", T("保留(表243 byte7 高4b)", "Reserved (Table 243 byte7 high)"), base.HEX, nil, 0xF0)
f.mme_iot_rsv2 = ProtoField.uint8 ("nw_2026.mme.iot.rsv2", T("保留(表243 byte9 高4b)", "Reserved (Table 243 byte9 high)"), base.HEX, nil, 0xF0)
f.mme_bl_result = ProtoField.uint8 ("nw_2026.mme.bl.result", T("更新结果", "Update Result"), base.DEC, {
    [0] = T("更新成功", "Update OK"), [1] = T("更新失败", "Update failed"),
}, 0x01)
f.mme_ru_start = ProtoField.uint16 ("nw_2026.mme.ru.start", T("邻居起始 TEI", "Neighbor Start TEI"), base.DEC)
f.mme_ru_gid = ProtoField.uint8 ("nw_2026.mme.ru.gid", T("RU 分组 ID", "RU Group ID"), base.DEC)
f.mme_ru_num = ProtoField.uint16 ("nw_2026.mme.ru.num", T("告知的邻居站点总数", "Neighbor STA Count"), base.DEC)
f.mme_ru_bmlen = ProtoField.uint16 ("nw_2026.mme.ru.bmlen", T("邻居站点位图长度(B)", "Neighbor Bitmap Length (bytes)"), base.DEC)
f.mme_ru_snr = ProtoField.uint16 ("nw_2026.mme.ru.snr", T("RU SNR", "RU SNR"), base.DEC)
f.mme_tei_seq = ProtoField.uint8 ("nw_2026.mme.tei.seq", T("请求序列号", "Request Sequence"), base.DEC)
f.mme_tei_mac = ProtoField.ether ("nw_2026.mme.tei.mac", T("源 MAC", "Source MAC"))
f.mme_tei_num = ProtoField.uint8 ("nw_2026.mme.tei.num", T("站点数", "Station Count"), base.DEC)
f.mme_tei_stmac = ProtoField.ether ("nw_2026.mme.tei.stmac", T("站点 MAC", "Station MAC"))
f.mme_tei_tei = ProtoField.uint16 ("nw_2026.mme.tei.tei", T("站点 TEI", "Station TEI"), base.DEC)
f.mme_xnc_mac = ProtoField.ether ("nw_2026.mme.xnc.mac", T("冲突 CCO MAC", "Conflict CCO MAC"))
f.mme_xnc_num = ProtoField.uint8 ("nw_2026.mme.xnc.num", T("邻居网络个数", "Neighbor Network Count"), base.DEC)
f.mme_xnc_snid = ProtoField.uint8 ("nw_2026.mme.xnc.snid", T("邻居 SNID", "Neighbor SNID"), base.DEC, nil, 0x1F)
f.mme_iot_mac = ProtoField.ether ("nw_2026.mme.iot.mac", T("物联终端设备地址", "IoT Device Address"))
f.mme_iot_gw = ProtoField.uint16 ("nw_2026.mme.iot.gw", T("物联网关设备地址(TEI)", "IoT Gateway TEI"), base.DEC)
f.mme_iot_dev = ProtoField.uint8 ("nw_2026.mme.iot.dev", T("设备类型", "Device Type"), base.DEC)
f.mme_iot_pwr = ProtoField.uint8 ("nw_2026.mme.iot.pwr", T("功耗类型", "Power Type"), base.DEC, nil, 0x0F)
f.mme_iot_result = ProtoField.uint8 ("nw_2026.mme.iot.result", T("接入结果", "Access Result"), base.DEC, {
    [0] = T("允许接入网络", "Allow network access"), [1] = T("认证失败", "Authentication failed"),
})
f.mme_iot_reason = ProtoField.uint8 ("nw_2026.mme.iot.reason", T("离线原因", "Leave Reason"), base.DEC, {
    [0] = T("未接入网络,需要重新接入网络", "Not joined, rejoin required"),
    [1] = T("不在认证名单中", "Not in authentication list"),
})
f.pb_tbl = ProtoField.bytes ("nw_2026.pb.tbl", T("可变表", "Variable Table"), base.NONE)

local function dissect_mac_frame(tvb, tree, pinfo, snid, sof_src_tei, no_info)
    local version = read_bits(tvb, 1, 2)   -- byte0 bits1-2: 1=标准帧, 2=单跳帧

    -- 单跳帧 (MSDU_BASE_S, 4B)
    if version == 2 then
        -- 单跳帧协议(第2部分 §8.1.2.4 表113,4B 头;MSDU 类型分派 表114)
        local mac_tree = tree:add(nw, tvb(), T("MAC 帧(单跳)", "MAC Frame (Single-hop)"))
        mac_tree:add(f.sh_htype, tvb(0, 1))
        mac_tree:add(f.mac_version, tvb(0, 1))
        mac_tree:add(f.sh_rsv0, tvb(0, 1))
        mac_tree:add(f.sh_type, tvb(1, 1))
        local msdu_len = read_bits(tvb, 16, 16)
        mac_tree:add(f.sh_len, tvb(2, 2), msdu_len)
        local msg_type = tvb(1, 1):uint()
        if msg_type == 2 and 4 + msdu_len <= tvb:len() then
            -- 无线发现列表(表214): 站点MAC 6B + 统计序号 1B + IE TLV
            -- (7b类型 + 1b长度类型 + 1/2B长度 + 内容; 内容逐字段 表215/217/218/219-220/226-227)
            local rtree = mac_tree:add(nw, tvb(4, msdu_len), T("无线发现列表", "RF DiscoverNodeList"))
            rtree:add(f.rf_mac, tvb(4, 6))
            rtree:add(f.rf_seq, tvb(10, 1))
            local pos = 11
            local rfdl_end = 4 + msdu_len
            local idx = 0
            while pos + 1 < rfdl_end do
                local ie_type = band(tvb(pos, 1):uint(), 0x7F)
                local ltype = band(tvb(pos, 1):uint(), 0x80)
                rtree:add(f.rf_ie_type, tvb(pos, 1))
                rtree:add(f.rf_ie_ltype, tvb(pos, 1))
                pos = pos + 1
                local len_bytes = (ltype ~= 0) and 2 or 1
                if pos + len_bytes > rfdl_end then break end
                local elen = tvb(pos, 1):uint()
                if len_bytes == 2 then elen = elen + tvb(pos + 1, 1):uint() * 256 end
                rtree:add(f.rf_ie_len, tvb(pos, len_bytes), elen)
                pos = pos + len_bytes
                if pos + elen > rfdl_end then
                    rtree:add_expert_info(PI_MALFORMED, PI_WARN,
                        T("信息单元长度越界(截断)", "IE length out of range (truncated)"))
                    break
                end
                if elen > 0 then
                    local itree = rtree:add(nw, tvb(pos, elen)):
                        append_text(string.format(" [%s]", tostring(rf_ie_type_vals[ie_type] or ie_type)))
                    local c0, nb = pos, elen * 8
                    if ie_type == 0 and elen >= 14 then
                        -- 站点属性信息(表217, 14B)
                        itree:add(f.rf_attr_cco, tvb(c0, 6))
                        add_val(itree, f.rf_attr_proxy, tvb, c0+6, 2, read_bits(tvb, c0*8+6*8, 12))
                        itree:add(f.rf_attr_role, tvb(c0+7, 1))
                        itree:add(f.rf_attr_level, tvb(c0+8, 1))
                        itree:add(f.rf_attr_hop, tvb(c0+8, 1))
                        itree:add(f.rf_attr_up, tvb(c0+9, 1))
                        itree:add(f.rf_attr_down, tvb(c0+10, 1))
                        itree:add(f.rf_attr_min, tvb(c0+11, 1))
                        itree:add(f.rf_attr_period, tvb(c0+12, 1))
                        itree:add(f.rf_attr_aging, tvb(c0+13, 1))
                    elseif ie_type == 1 then
                        -- 站点路由信息(表218): 每条 2B = 下一跳 TEI 12b + 路由类型 4b(bit4-7)
                        for i = 0, math.floor(elen / 2) - 1 do
                            local p = c0 + i * 2
                            local it = itree:add(nw, string.format(T("NextHop[%d]", "NextHop[%d]"), i))
                            add_val(it, f.rf_route_tei, tvb, p, 2, read_bits(tvb, p*8, 12))
                            it:add(f.rf_route_type, tvb(p+1, 1))
                        end
                    elseif ie_type == 2 then
                        -- 邻居信道信息非位图版(表219/220): 组合类型 0-3
                        local combo = band(tvb(c0, 1):uint(), 0x0F)
                        local snr_b = ({0,4,6,0})[combo+1] or 0
                        local rssi_b = ({0,0,6,4})[combo+1] or 0
                        itree:add(f.rf_combo, tvb(c0, 1)):append_text(
                            (combo <= 3) and string.format(T(" (%db/邻居)", " (%db/neighbor)"), 12+8+snr_b+rssi_b)
                            or T(" (保留)", " (Reserved)"))
                        if combo <= 3 then
                            local entry_bits = 12 + 8 + snr_b + rssi_b
                            local bp, i = 8, 0
                            while bp + entry_bits <= nb do
                                local tei = read_bits(tvb, c0*8+bp, 12)
                                local nt = itree:add(nw, string.format(T("Neighbor[%d] TEI=%d", "Neighbor[%d] TEI=%d"), i, tei))
                                add_val(nt, f.rf_nbr_tei, tvb, (c0*8+bp)/8, 2, tei)
                                add_val(nt, f.rf_nbr_rate, tvb, (c0*8+bp+12)/8, 2, read_bits(tvb, c0*8+bp+12, 8))
                                if snr_b > 0 then
                                    add_val(nt, f.rf_nbr_snr, tvb, (c0*8+bp+20)/8, 2, read_bits(tvb, c0*8+bp+20, snr_b))
                                end
                                if rssi_b > 0 then
                                    add_val(nt, f.rf_nbr_rssi, tvb, (c0*8+bp+20+snr_b)/8, 2, read_bits(tvb, c0*8+bp+20+snr_b, rssi_b))
                                end
                                bp = bp + entry_bits
                                i = i + 1
                            end
                        end
                    elseif ie_type == 3 then
                        -- 邻居信道信息位图版(表226/227): 组合类型 0-5 + 多组[起始TEI+保留+位图大小+位图+条目]
                        local combo = band(tvb(c0, 1):uint(), 0x0F)
                        local snr_b = ({0,4,0,6,4,0})[combo+1] or 0
                        local rssi_b = ({0,0,8,6,4,4})[combo+1] or 0
                        itree:add(f.rf_combo, tvb(c0, 1)):append_text(
                            (combo <= 5) and string.format(T(" (%db/邻居)", " (%db/neighbor)"), 8+snr_b+rssi_b)
                            or T(" (保留)", " (Reserved)"))
                        if combo <= 5 then
                            local entry_bits = 8 + snr_b + rssi_b
                            local off, k = 1, 0
                            while off + 3 < elen do
                                local start_tei = read_bits(tvb, (c0+off)*8, 12)
                                local bm_len = tvb(c0+off+2, 1):uint()
                                if off + 3 + bm_len > elen then break end
                                local g = itree:add(nw, string.format(T("BitmapSet[%d] StartTEI=%d", "BitmapSet[%d] StartTEI=%d"), k, start_tei))
                                add_val(g, f.rf_grp_tei, tvb, c0+off, 2, start_tei)
                                g:add(f.rf_grp_size, tvb(c0+off+2, 1), bm_len)
                                local bmp = tvb(c0+off+3, bm_len)
                                local teis, nk = {}, 0
                                for bi = 0, bm_len - 1 do
                                    local b = tvb(c0+off+3+bi, 1):uint()
                                    for j = 0, 7 do
                                        if band(b, 2 ^ j) ~= 0 then
                                            nk = nk + 1
                                            teis[#teis + 1] = tostring(math.floor(start_tei + bi * 8 + j))
                                        end
                                    end
                                end
                                local bmp_item = g:add(f.rf_grp_bitmap, bmp)
                                bmp_item:append_text(string.format(" (TEI: %s)",
                                    #teis > 0 and table.concat(teis, ",") or "-"))
                                -- 位图逐位(仅 bit=1):值标注该 bit 所在的字节号(位图内第 bi 字节)
                                for bi2 = 0, bm_len - 1 do
                                    local b2 = tvb(c0+off+3+bi2, 1):uint()
                                    for j2 = 0, 7 do
                                        if band(b2, 2 ^ j2) ~= 0 then
                                            bmp_item:add(nw, tvb(c0+off+3+bi2, 1),
                                                string.format(T("Neighbor[%d] TEI=%d = 在位图(第%d字节)",
                                                                "Neighbor[%d] TEI=%d = in bitmap (byte %d)"),
                                                              bi2*8+j2, start_tei + bi2*8+j2, bi2))
                                        end
                                    end
                                end
                                -- 逐置位邻居条目(位预算守卫, 防发端声明虚大)
                                local bp = (off + 3 + bm_len) * 8
                                local i = 0
                                for bi = 0, bm_len - 1 do
                                    local b = tvb(c0+off+3+bi, 1):uint()
                                    for j = 0, 7 do
                                        if band(b, 2 ^ j) ~= 0 then
                                            if bp + entry_bits > nb then break end
                                            local nt = g:add(nw, string.format(T("Neighbor[%d] TEI=%d", "Neighbor[%d] TEI=%d"), i, start_tei + bi*8 + j)
                                                .. string.format(T(" (位图 byte %d bit %d)", " (bitmap byte %d bit %d)"), bi, j))
                                            add_val(nt, f.rf_nbr_rate, tvb, (c0*8+bp)/8, 2, read_bits(tvb, c0*8+bp, 8))
                                            if snr_b > 0 then
                                                add_val(nt, f.rf_nbr_snr, tvb, (c0*8+bp+8)/8, 2, read_bits(tvb, c0*8+bp+8, snr_b))
                                            end
                                            if rssi_b > 0 then
                                                add_val(nt, f.rf_nbr_rssi, tvb, (c0*8+bp+8+snr_b)/8, 2, read_bits(tvb, c0*8+bp+8+snr_b, rssi_b))
                                            end
                                            bp = bp + entry_bits
                                            i = i + 1
                                        end
                                    end
                                end
                                off = math.floor(bp / 8) + (bp % 8 ~= 0 and 1 or 0)
                                k = k + 1
                            end
                        end
                    end
                end
                pos = pos + elen
                idx = idx + 1
            end
        elseif msg_type == 128 and 4 + msdu_len <= tvb:len() then
            mac_tree:add(nw, tvb(4, msdu_len), T("IPv4 报文", "IPv4 Packet"))
        elseif msg_type ~= 1 and msg_type ~= 128 then
            if 4 + msdu_len <= tvb:len() then
                mac_tree:add(f.pb_tbl, tvb(4, msdu_len),
                    string.format(T("保留类型 %d 载荷", "Reserved type %d payload"), msg_type))
            end
        end
        -- MSDU 载荷 + 帧尾 CRC32 (校验载荷, 不含单跳头)
        if msdu_len > 0 and 4 + msdu_len <= tvb:len() then
            if msg_type == 1 or msg_type == 2 or msg_type == 128 or msg_type > 128 then
                add_span(mac_tree, f.sh_data, tvb, 4, msdu_len)
            end
            local icv_off = 4 + msdu_len
            if icv_off + 4 <= tvb:len() then
                local icv_rx = read_bits(tvb, icv_off * 8, 32)
                local icv_calc = crc32_le(tvb, 4, msdu_len + 4)
                tree:add(f.mac_icv, tvb(icv_off, 4), icv_rx)
                tree:add(f.mac_icv_calc, tvb(icv_off, 4), icv_calc)
                tree:add(f.mac_icv_ok, tvb(icv_off, 1), icv_calc == icv_rx)
            end
        end
        return
    end

    if version ~= 1 then
        tree:add_expert_info(PI_MALFORMED, PI_WARN, T("未知 MAC 帧版本", "Unknown MAC frame version"))
        return
    end

    -- 标准帧 (MSDU_BASE): MACHeadFlag 决定长(32B)/短(12B)帧头
    local mac_tree = tree:add(nw, tvb(), T("MAC 帧", "MAC Frame"))
    local head_flag = read_bits(tvb, 0, 1)
    local msdu_len = read_bits(tvb, 16, 16)
    mac_tree:add(f.mac_version, tvb(0, 1))
    mac_tree:add(f.mac_head_flag, tvb(0, 1))
    add_val(mac_tree, f.mac_msdu_len, tvb, 2, 2, msdu_len)
    add_tei12(mac_tree, f.mac_dst_tei, tvb, 4)
    add_tei12h(mac_tree, f.mac_src_tei, tvb, 5)
    mac_tree:add(f.mac_restart_cnt, tvb(7, 1))
    mac_tree:add(f.mac_bcast_dir, tvb(8, 1))
    mac_tree:add(f.mac_send_type, tvb(9, 1))
    add_le(mac_tree, f.mac_msdu_seq, tvb, 10, 2)
    local hdr_len = 12
    if head_flag == 0 then
        mac_tree:add(f.mac_hdr_rsv, tvb(12, 20))
        hdr_len = 32
    end

    -- 方向判断 + 原始目标地址列: 源TEI=1(CCO) 且 目的TEI!=0xFFF → 下行; 否则上行
    -- 当前发出者 sof_src_tei != 源TEI → 中继 Relay
    local src_tei = read_bits(tvb, 5 * 8 + 4, 12)
    local dst_tei = read_bits(tvb, 4 * 8, 12)
    local ods
    if dst_tei == 0xFFF then
        ods = T("广播 (TEI 4095)", "Broadcast (TEI 4095)")
    elseif dst_tei == 1 then
        ods = T("CCO (TEI 1)", "CCO (TEI 1)")
    else
        ods = string.format(T("STA (TEI %d)", "STA (TEI %d)"), dst_tei)
    end
    local odmac = lookup_tei_mac(snid, dst_tei)
    if odmac then ods = ods .. " [" .. odmac .. "]" end
    tree:add(f.col_orig_dst, tvb(4, 2), ods)
    local oss
    if src_tei == 0xFFF then
        oss = T("广播 (TEI 4095)", "Broadcast (TEI 4095)")
    elseif src_tei == 1 then
        oss = T("CCO (TEI 1)", "CCO (TEI 1)")
    else
        oss = string.format(T("STA (TEI %d)", "STA (TEI %d)"), src_tei)
    end
    local osmac = lookup_tei_mac(snid, src_tei)
    if osmac then oss = oss .. " [" .. osmac .. "]" end
    tree:add(f.col_orig_src, tvb(5, 2), oss)
    local dir_mark = ""
    if dst_tei == 1 then
        dir_mark = T(" ↑上行", " ↑Uplink")            -- 发给 CCO → 上行(优先)
    elseif src_tei == 1 and dst_tei ~= 0xFFF then
        dir_mark = T(" ↓下行", " ↓Downlink")          -- CCO 发出(非广播) → 下行
    elseif src_tei ~= 1 and dst_tei ~= 0xFFF then
        -- P2P(非 CCO,非广播): APP 报文用 TransDirectionFlag(表8 0=下行 1=上行);
        -- 业务报文头 byte1 bit7 = MSDU 载荷起点 + 通道控制信息(4B) + 1;MMe/无 flag → 方向未知 *(与主界面 dir_display 对齐)
        local msdu_hdr = (head_flag == 0) and 18 or 2
        local is_app = (head_flag == 1)   -- 短帧头只携带应用层报文
        if head_flag == 0 then
            is_app = (read_bits(tvb, (hdr_len + 12) * 8, 32) ~= 0x8100)  -- 长帧头 VLAN≠0x8100 → APP
        end
        local tdf = nil
        if is_app then
            local tdf_off = hdr_len + msdu_hdr + 5
            if tdf_off + 1 <= tvb:len() then
                tdf = band(tvb(tdf_off, 1):uint(), 0x80)
            end
        end
        if tdf == 0x00 then
            dir_mark = T(" ↓下行", " ↓Downlink")
        elseif tdf == 0x80 then
            dir_mark = T(" ↑上行", " ↑Uplink")        -- flag=1 → 上行
        else
            dir_mark = T(" *", " *")                  -- 无 flag(MMe/截断) → 方向未知,与主界面 dir_display 的 * 对齐
        end
    elseif src_tei ~= 1 then
        dir_mark = T(" ↑上行", " ↑Uplink")            -- 广播(dst==0xFFF) src!=1 → 保持现有 ↑
    end
    if sof_src_tei and src_tei and sof_src_tei ~= src_tei then
        dir_mark = dir_mark .. " Relay"
    end
    if dir_mark ~= "" and not no_info then
        pinfo.cols.info = tostring(pinfo.cols.info) .. dir_mark
    end

    -- MSDU 帧头
    local msdu_off = hdr_len
    local vlan, msdu_type
    local src_mac_str = nil   -- 本跳发送方 MAC(长帧头;代理转发判定用)
    if head_flag == 0 then
        -- 长帧头 MSDU_LONGHEAD (18B): 目的/源 MAC + VLAN(32b) + MSDU 类型(16b)
        if msdu_off + 18 > tvb:len() then return end
        mac_tree:add(f.msdu_dst_mac, tvb(msdu_off, 6))
        mac_tree:add(f.msdu_src_mac, tvb(msdu_off + 6, 6))
        src_mac_str = mac_to_str(tvb, msdu_off + 6)
        vlan = read_bits(tvb, (msdu_off + 12) * 8, 32)
        add_val(mac_tree, f.msdu_vlan, tvb, msdu_off + 12, 4, vlan)
        msdu_type = read_bits(tvb, (msdu_off + 16) * 8, 16)
        add_val(mac_tree, f.msdu_type, tvb, msdu_off + 16, 2, msdu_type)
        msdu_off = msdu_off + 18
    else
        -- 短帧头 MSDU_SHORTHEAD (2B): VLAN(8b) + MSDU 类型(8b), 只携带应用层报文
        if msdu_off + 2 > tvb:len() then return end
        vlan = tvb(msdu_off, 1):uint()
        mac_tree:add(f.msdu_vlan_s, tvb(msdu_off, 1))
        msdu_type = tvb(msdu_off + 1, 1):uint()
        mac_tree:add(f.msdu_type_s, tvb(msdu_off + 1, 1))
        msdu_off = msdu_off + 2
    end

    -- MSDU 载荷: VLAN=0x8100 → MMe 管理消息; 否则 APP 应用层报文
    local payload_len = msdu_len - (msdu_off - hdr_len)
    local mac_summary = nil
    if payload_len > 0 and msdu_off + payload_len <= tvb:len() then
        local body_tvb = view_slice(tvb, msdu_off)
        if vlan == 0x8100 then
            -- MMe: 头 6B (MMVersion + MMType 16b + RSV 24b)
            local mmt = mac_tree:add(nw, tvb(msdu_off, payload_len), T("管理消息(MMe)", "Management Message (MMe)"))
            local mme_summary = nil
            if payload_len >= 6 then
                local mmtype = read_bits(body_tvb, 8, 16)
                mmt:add(f.mme_version, body_tvb(0, 1))
                mmt:add(f.mme_type, body_tvb(1, 2), mmtype)
                mmt:add(f.mme_rsv, body_tvb(3, 3))
                mme_summary = mme_short_name(mmtype)
                -- info 列追加管理消息类型 (非聚合帧)
                if not no_info then
                    local mt_name = mme_type_vals[mmtype] or ""
                    local cur_info = tostring(pinfo.cols.info)
                    if mt_name ~= "" then
                        -- info 列拼接:cur_info 为空时不加前导空格(保持左对齐)
                        pinfo.cols.info = (cur_info == "" or cur_info == "NW-HPLC" or cur_info == "NW-RF")
                            and mt_name or (cur_info .. string.format(" %s", mt_name))
                    else
                        -- 未分配类型统一带“保留”后缀(与 C++ mme_type_name 回落口径一致)
                        pinfo.cols.info = cur_info .. string.format(" MMType=0x%04x (%s)", mmtype, T("保留", "Reserved"))
                    end
                end
                -- 消息体 (MMe 头 6B 之后)
                if payload_len > 6 then
                    local ok, err = pcall(dissect_mme_body, body_tvb, mmt, mmtype)
                    if not ok then
                        mmt:add_expert_info(PI_MALFORMED, PI_WARN,
                            T("管理消息体解析失败(可能截断): ", "MMe body parse failed (possibly truncated): ") .. tostring(err))
                    end
                end
                -- 代理转发主体标记(与 C++ packetlistmodel COL_MSDU_TYPE 同口径):
                -- 单一 MMe 主体 MAC ≠ 本跳发送方 MAC → Info 追加 " STA-N [MAC:...]"
                -- ⚠️ 本调用在 dissect_mme_body 的 pcall 之外:按 mmtype 最小长度守卫
                -- (BPLC-2/SPLC-4 同构),防未来 helper 演化引入裸 tvb() 访问时整个 dissector 报错
                local BODY_MIN_LEN = { [0x0030]=12, [0x0031]=16, [0x0034]=22, [0x0049]=16, [0x0055]=16 }
                local body_mac_str, body_tei
                if body_tvb:len() >= (BODY_MIN_LEN[mmtype] or 0) then
                    body_mac_str, body_tei = mme_body_sta_mac_tei(mmtype, body_tvb)
                end
                if body_mac_str and src_mac_str and body_mac_str ~= src_mac_str and not no_info then
                    local body = (body_tei and body_tei ~= 0)
                        and string.format("STA-%d", body_tei) or "STA-X"
                    pinfo.cols.info = tostring(pinfo.cols.info)
                        .. string.format(" %s [MAC:%s]", body, body_mac_str)
                end
            else
                mme_summary = T("未识别", "unrecognized")
            end
            mac_summary = mme_summary
        else
            local app_tree = mac_tree:add(nw, tvb(msdu_off, payload_len), T("应用层报文", "Application Layer Packet"))
            local ok, app_summary = pcall(dissect_app, body_tvb, app_tree, pinfo, no_info)
            if not ok then
                app_tree:add_expert_info(PI_MALFORMED, PI_WARN,
                    T("应用层报文解析失败(可能截断): ", "APP parse failed (possibly truncated): ") .. tostring(app_summary))
                mac_summary = T("未识别", "unrecognized")
            else
                mac_summary = app_summary
            end
        end
    end

    -- MSDU 帧尾 4B CRC32: 校验 MSDU 载荷(MAC 帧头之后, 不含帧头)
    local icv_off = hdr_len + msdu_len
    if msdu_len > 0 and icv_off + 4 <= tvb:len() then
        local icv_rx = read_bits(tvb, icv_off * 8, 32)
        local icv_calc = crc32_le(tvb, hdr_len, msdu_len + 4)
        tree:add(f.mac_icv, tvb(icv_off, 4), icv_rx)
        tree:add(f.mac_icv_calc, tvb(icv_off, 4), icv_calc)
        tree:add(f.mac_icv_ok, tvb(icv_off, 1), icv_calc == icv_rx)
    end
    return mac_summary, dir_mark
end

-- =========================================================================
-- 媒介类型 field extractor (必须在 dissector 注册前定义)
-- =========================================================================

nw.fields = {
    f.fc_dt, f.fc_conind, f.fc_snid, f.fc_vf, f.fc_std_ver, f.fc_fccs,
    f.fc_fccs_calc, f.fc_fccs_ok,
    f.beacon_bts, f.beacon_bts_sec, f.beacon_bpc, f.beacon_src_tei,
    f.beacon_tmi, f.beacon_symbol_cnt, f.beacon_phase, f.beacon_pblen,
    f.beacon_mcs, f.beacon_rsv1, f.beacon_rsv2, f.beacon_rsv3,
    f.sof_src_tei, f.sof_dst_tei, f.sof_lid, f.sof_pb_num, f.sof_tmi,
    f.sof_frame_len, f.sof_tmi_ext, f.sof_pblen,
    f.sof_rf_snid_hi, f.sof_rf_rsv12, f.sof_rf_rsv12_hi,
    f.mme_bl_rsv0, f.mme_bl_rsv1, f.mme_iot_rsv, f.mme_iot_rsv2,
    f.sof_mcs, f.sof_symbol_cnt, f.sof_tei_filter, f.sof_resend, f.sof_rsv,
    f.sof_bplc_lid, f.sof_bplc_snid_hi, f.sof_bplc_rsv, f.sof_bplc_pbnum, f.sof_bplc_tmi,
    f.ack_ext_type, f.ack_rx_res, f.ack_rx_status, f.ack_dst_tei, f.ack_rx_pb_num,
    f.ack_dst_mac, f.ack_search_tei, f.ack_sync_ts, f.ack_sync_tei,
    f.ack_seq, f.ack_rsv,
    f.coord_nbr_bmp, f.coord_rf_ch, f.coord_rsv_b3, f.coord_rsv_opt, f.coord_rsv1, f.coord_duration,
    f.coord_rsv2, f.coord_band_end_flag, f.coord_option, f.coord_rsv3,
    f.coord_band_end_offset, f.coord_band_start_offset, f.coord_rsv0,
    f.pb_hdr, f.pb_size, f.pb_body, f.pb_rsv, f.pb_pbcs, f.pb_crc_ok, f.pb_crc_calc, f.pb_padding,
    f.beacon_type, f.beacon_net_cplt, f.beacon_multi_net, f.beacon_start_assoc,
    f.beacon_reduce, f.beacon_snid_high, f.beacon_rf_opt, f.beacon_plc_cap,
    f.beacon_rf_ch, f.beacon_chnum, f.beacon_netver, f.beacon_mech, f.beacon_disc_en,
    f.beacon_net_seq, f.beacon_snid, f.beacon_head_rsv,
    f.sof_multi, f.sof_train, f.sof_ofdma_type, f.sof_bitload,
    f.efc, f.efc_st0_pbn, f.efc_st0_tmi,
    f.beacon_entry_cnt, f.beacon_ent_type, f.beacon_ent_len, f.beacon_ent_data,
    f.beacon_bpcs, f.beacon_bpcs_calc, f.beacon_bpcs_ok, f.beacon_bpcs_rsv,
    f.ent_net_level, f.ent_sta_line, f.ent_tei, f.ent_role, f.ent_beacon_usage,
    f.ent_sta_mac, f.ent_pco_tei, f.ent_path_rate, f.ent_cap_rsv,
    f.ent_nc_beacon_cnt, f.ent_c_beacon_cnt, f.ent_csma_line_cnt,
    f.ent_proxy_beacon_cnt, f.ent_beacon_slot_len, f.ent_csma_slot_size,
    f.ent_bcsma_line_cnt, f.ent_bcsma_lid, f.ent_tdma_slot_len, f.ent_tdma_lid,
    f.ent_bp_start_ntb, f.ent_bp_len, f.ent_slot_rsv,
    f.ent_ncb_tei, f.ent_ncb_type, f.ent_ncb_rsv,
    f.ent_csma_len, f.ent_csma_phase, f.ent_bcsma_len, f.ent_bcsma_phase,
    f.ent_route_period, f.ent_rp_rsv0, f.ent_route_remain, f.ent_rp_rsv1, f.ent_rp_cco_mac,
    f.ent_target_band, f.ent_band_remain,
    f.ent_cal_time, f.ent_cal_ntb,
    f.ent_rfp_period, f.ent_rfp_aging,
    f.ent_rfc_channel, f.ent_rfc_option, f.ent_rfc_rsv, f.ent_rfc_remain,
    f.ent_lite_tei, f.ent_lite_pcotei, f.ent_lite_role, f.ent_lite_level,
    f.ent_lite_mac, f.ent_lite_hop, f.ent_lite_band, f.ent_lite_rsv,
    f.ent_lite_slot_ntb, f.ent_lite_slot_len,
    f.ent_switch_mech, f.ent_switch_ntb, f.ent_proxy_tei, f.ent_proxy_rsv,
    f.efc_tfnum, f.efc_st_pbn, f.efc_st_tei, f.efc_st_tmi, f.efc_st_ru,
    f.efc_st0_sackru, f.efc_st0_backoff,
    f.efc29_st_tei, f.efc29_st_status, f.efc29_st_rsv,
    f.pb_agg, f.cas_len, f.cas_start, f.cas_end, f.cas_rsv,
    f.sack16_msgid, f.sack16_src, f.sack16_rx, f.sack16_rsv,
    f.ack_bl_src, f.ack_bl_dst, f.ack_bl_snid, f.ack_bl_type, f.ack_bl_reason,
    f.ack_bl_stream, f.ack_bl_group, f.ack_bl_rsv4, f.ack_bl_rsv56, f.ack_bl_ver,
    f.ack15_pbn, f.ack15_status, f.ack15_src, f.ack15_dst, f.ack15_bru,
    f.mac_version, f.mac_head_flag, f.mac_msdu_len, f.mac_dst_tei, f.mac_src_tei,
    f.mac_restart_cnt, f.mac_bcast_dir, f.mac_send_type, f.mac_msdu_seq, f.mac_hdr_rsv,
    f.msdu_dst_mac, f.msdu_src_mac, f.msdu_vlan, f.msdu_type, f.msdu_vlan_s, f.msdu_type_s,
    f.sh_type, f.sh_len, f.sh_data,
    f.sh_htype, f.sh_rsv0,
    f.mac_icv, f.mac_icv_calc, f.mac_icv_ok,
    f.mme_version, f.mme_type, f.mme_rsv,
    f.ar_sta_mac, f.ar_proxy_tei, f.ar_link_type, f.ar_link_rsv, f.ar_phase,
    f.ar_dev_type, f.ar_rsv, f.ar_mac_type, f.ar_module, f.ar_link,
    f.ar_assoc_rand, f.ar_manuf_info, f.ar_boot_reason, f.ar_boot_ver,
    f.ar_soft_ver, f.ar_ver_year, f.ar_ver_month, f.ar_ver_day,
    f.ar_manuf_id, f.ar_chip_code, f.ar_hard_rst, f.ar_soft_rst,
    f.ar_proxy_type, f.ar_net_sn, f.ar_mme_ver, f.ar_band_support, f.ar_e2e_seq,
    f.ac_sta_mac, f.ac_result, f.ac_sta_level, f.ac_sta_tei, f.ac_proxy_tei,
    f.ac_total_pkgs, f.ac_pkg_idx, f.ac_last_pkg, f.ac_link_type, f.ac_carrier,
    f.ac_assoc_rand, f.ac_reassoc_time, f.ac_e2e_seq, f.ac_path_seq,
    f.ac_net_sn, f.ac_mme_ver, f.ac_detech,
    f.ri_straight_sta, f.ri_straight_pco, f.ri_table_size, f.ri_rsv,
    f.ri_sta_tei, f.ri_pco_tei, f.ri_pco_child_cnt, f.ri_child_tei,
    f.ri_link_type, f.ri_link_rsv,
    f.cpr_sta_tei, f.cpr_new_proxy, f.cpr_link_type, f.cpr_link_rsv,
    f.cpr_old_proxy, f.cpr_proxy_type, f.cpr_reason, f.cpr_phase, f.cpr_link,
    f.cpr_e2e_seq, f.cpr_net_sn, f.cpr_rsv,
    f.ai_result, f.ai_sta_level, f.ai_sta_mac, f.ai_cco_mac, f.ai_sta_tei,
    f.ai_proxy_tei, f.ai_link_type, f.ai_carrier, f.ai_rsv,
    f.ai_total_pkgs, f.ai_pkg_idx, f.ai_last_pkg, f.ai_assoc_rand,
    f.ai_net_sn, f.ai_reassoc_time, f.ai_e2e_seq,
    f.cpc_result, f.cpc_total_pkgs, f.cpc_pkg_idx, f.cpc_sta_tei, f.cpc_proxy_tei,
    f.cpc_child_cnt, f.cpc_net_sn, f.cpc_link_type, f.cpc_rsv,
    f.cpc_e2e_seq, f.cpc_path_seq, f.cpc_child_tei,
    f.ag_result, f.ag_sta_level, f.ag_cco_mac, f.ag_proxy_tei, f.ag_net_sn,
    f.ag_gather_cnt, f.ag_carrier, f.ag_rsv, f.ag_sta_mac, f.ag_sta_tei,
    f.cpb_result, f.cpb_sta_tei, f.cpb_proxy_tei, f.cpb_net_sn, f.cpb_child_bmp,
    f.cpb_link_type, f.cpb_e2e_seq, f.cpb_path_seq,
    f.li_sta_tei, f.li_reason, f.li_sta_mac, f.li_proxy_tei, f.li_rsv,
    f.hb_ostei, f.hb_max_disc_tei, f.hb_max_disc_cnt, f.hb_disc_bmp, f.hb_rsv,
    f.dl_tei, f.dl_role, f.dl_level, f.dl_mac, f.dl_proxy_tei, f.dl_rsv,
    f.dl_rate_finish, f.dl_proxy_rate, f.dl_proxy_dl_rate,
    f.dl_sta_cnt, f.dl_send_cnt, f.dl_up_route_cnt, f.dl_up_route_size,
    f.dl_route_remain, f.dl_phase0, f.dl_phase1, f.dl_phase2, f.dl_min_rate,
    f.dl_next_hop_tei, f.dl_route_type, f.dl_disc_bmp, f.dl_rcv_cnt, f.dl_rcv_item,
    f.dl2_reason, f.dl2_sta_cnt, f.dl2_delay, f.dl2_rsv, f.dl2_sta_mac,
    f.sr_proxy_tei, f.sr_sta_cnt, f.sr_sta_tei, f.sr_down_rate, f.sr_up_rate,
    f.zc_quantity, f.zc_seq, f.zc_rsv,
    f.zr_tei, f.zr_collect_mode, f.zr_seq, f.zr_total_cnt, f.zr_base_ntb,
    f.zr_rsv, f.zr_ph1_cnt, f.zr_ph2_cnt, f.zr_ph3_cnt, f.zr_diff,
    f.diag_chip_id, f.diag_custom,
    -- NW_2026 (SPLC) 新增 MMe 报文体字段(表153-164/243-247) + 无线发现列表(表214-227)
    f.mme_bl_src, f.mme_bl_dst, f.mme_bl_stream, f.mme_bl_cut, f.mme_bl_tablen,
    f.mme_bl_result, f.mme_ru_start, f.mme_ru_gid, f.mme_ru_num, f.mme_ru_bmlen,
    f.mme_ru_snr, f.mme_tei_seq, f.mme_tei_mac, f.mme_tei_num, f.mme_tei_stmac,
    f.mme_tei_tei, f.mme_xnc_mac, f.mme_xnc_num, f.mme_xnc_snid,
    f.mme_iot_mac, f.mme_iot_gw, f.mme_iot_dev, f.mme_iot_pwr,
    f.mme_iot_result, f.mme_iot_reason, f.pb_tbl,
    f.rf_mac, f.rf_seq, f.rf_ie_type, f.rf_ie_ltype, f.rf_ie_len,
    f.rf_attr_cco, f.rf_attr_proxy, f.rf_attr_role, f.rf_attr_level, f.rf_attr_hop,
    f.rf_attr_up, f.rf_attr_down, f.rf_attr_min, f.rf_attr_period, f.rf_attr_aging,
    f.rf_route_tei, f.rf_route_type, f.rf_combo, f.rf_nbr_tei, f.rf_nbr_rate,
    f.rf_nbr_snr, f.rf_nbr_rssi, f.rf_grp_tei, f.rf_grp_size, f.rf_grp_bitmap,
    f.app_port, f.app_packet_id, f.app_rsv, f.app_packet_type,
    f.app_ctrl_rsv0, f.app_ctrl_rsv1, f.app_ext_flag, f.app_respond_flag,
    f.app_start_flag, f.app_trans_dir, f.app_business_id, f.app_bid_desc,
    f.app_version, f.app_packet_sn, f.app_packet_len, f.app_payload,
    f.media_phr_mcs, f.media_option, f.media_channel, f.media_is_rf,
    f.col_orig_dst, f.col_orig_src,
    f.bmp_byte,
}

local encap_type_f = Field.new("frame.encap_type")

function nw.dissector(tvb, pinfo, tree)
    -- 入口在媒介剥离前分派(与 GW 侧同构): USER2(47)=载波 / USER3(48)=无线 按 encap
    -- 判定; USER5(50) 混合格式的 4B 媒介头由本文件自行剥离并读取媒介类型。
    local ev = encap_type_f()
    local evs = ev and tostring(ev) or ""
    local is_rf = (evs == "48")
    if evs == "50" then
        -- USER5 混合格式: [phr_mcs][option][channel][isRF] + MPDU (与 GW 侧同构:
        -- 委托方在媒介剥离前分派, 本文件自行剥离并读取媒介类型, 不再猜媒介)
        local mtree = tree:add(nw, tvb(0, 4), T("媒介头(串口采集)", "Media Header (serial capture)"))
        mtree:add(f.media_phr_mcs, tvb(0, 1))
        mtree:add(f.media_option, tvb(1, 1))
        mtree:add(f.media_channel, tvb(2, 1))
        mtree:add(f.media_is_rf, tvb(3, 1))
        is_rf = tvb(3, 1):uint() ~= 0
        tvb = tvb(4):tvb()
    end
    if is_rf then
        pinfo.cols.protocol = "NW-RF"
    else
        pinfo.cols.protocol = "NW-HPLC"
    end

    if tvb:len() < 16 then
        tree:add_expert_info(PI_MALFORMED, PI_WARN, T("帧长不足 16 字节(最小 MPDU 帧控制)", "Frame < 16 bytes (min FCH)"))
        return 0
    end

    local dt = band(tvb(0, 1):uint(), 0x07)
    -- SNID 5bit(表16): 低 4b 在 FCH(0,4,4), 高位按帧型坐标合并(试行规约 §5.1.2.2.1):
    --   信标 载波(12,1,1)/无线(12,0,1) / SOF 载波(12,0,1), 无线无高位 /
    --   ACK(4,0,1) / COORD(12,0,1)
    local snid = read_bits(tvb, 4, 4)
    do
        local snid_high = 0
        if dt == 0 then
            snid_high = read_bits(tvb, is_rf and 12 * 8 or 12 * 8 + 1, 1)
        elseif dt == 1 then
            if not is_rf then snid_high = read_bits(tvb, 12 * 8, 1) end
        elseif dt == 2 then
            snid_high = read_bits(tvb, 4 * 8, 1)
        elseif dt == 3 then
            snid_high = read_bits(tvb, 12 * 8, 1)
        end
        snid = snid + snid_high * 16
    end
    cur_snid = snid  -- 供 record_tei_mac 记录映射

    -- 源/目的地址列 (Source/Destination 列): 按帧类型提取 TEI
    local src_tei, dst_tei
    local dst_is_mac = false
    if dt == 0 then
        src_tei = read_bits(tvb, 9 * 8, 12)          -- 信标源TEI (FCH 字节9)
    elseif dt == 1 then
        src_tei = read_bits(tvb, 1 * 8, 12)          -- SOF 源TEI
        dst_tei = read_bits(tvb, 2 * 8 + 4, 12)      -- SOF 目的TEI
    elseif dt == 2 then
        local ext_type = read_bits(tvb, 12 * 8, 4)
        if ext_type == 0 then
            dst_tei = read_bits(tvb, 2 * 8, 12)      -- 常规 ACK 目的TEI
        elseif ext_type == 1 or ext_type == 3 then
            -- 搜索/切频帧: 目的为 48b MAC 地址, 直接显示
            dst_is_mac = true
            local mac = mac_to_str(tvb, 1)
            if mac then pinfo.cols.dst = mac end
        end
    elseif dt == 3 then
        src_tei = 1                                   -- 网间协调帧必然由 CCO 发出 (TEI 1)
    end
    -- 附加 MAC 地址 (历史帧已学到的 TEI↔MAC 映射)
    if src_tei then
        local base
        if src_tei == 1 then
            base = T("CCO (TEI 1)", "CCO (TEI 1)")
        else
            base = string.format(T("STA (TEI %d)", "STA (TEI %d)"), src_tei)
        end
        local mac = lookup_tei_mac(snid, src_tei)
        if mac then base = base .. " [" .. mac .. "]" end
        pinfo.cols.src = base
    else
        pinfo.cols.src = ""
    end
    if dst_tei then
        local base
        if dst_tei == 0xFFF then
            base = T("广播 (TEI 4095)", "Broadcast (TEI 4095)")
        else
            base = string.format("TEI %d", dst_tei)
        end
        local mac = lookup_tei_mac(snid, dst_tei)
        if mac then base = base .. " [" .. mac .. "]" end
        pinfo.cols.dst = base
    elseif not dst_is_mac then
        pinfo.cols.dst = ""
    end

    local dt_txt = dt_vals[dt] or T("保留", "Reserved").."("..dt..")"
    if dt == 1 and not is_rf then
        local is_multi = band(tvb(4, 1):uint(), 0x01) ~= 0
        if is_multi then
            -- 多站点帧(表26): byte4 bit1-2 = OFDMA 帧类型(同一位,多站点不能判训练帧!)
            local oft = math.floor(band(tvb(4, 1):uint(), 0x06) / 2)
            if oft == 0 then
                dt_txt = T("SOF", "SOF") .. " " .. T("DL-OFDMA", "DL-OFDMA")
            elseif oft == 1 then
                dt_txt = T("SOF", "SOF") .. " " .. T("DL-OFDMA SACK/UL-OFDMA", "DL-OFDMA SACK / UL-OFDMA")
            elseif oft == 2 then
                dt_txt = T("SOF", "SOF") .. " " .. T("UL-OFDMA trigger", "UL-OFDMA trigger")
            else
                dt_txt = T("SOF", "SOF") .. " " .. T("UL-OFDMA SACK", "UL-OFDMA SACK")
            end
        else
            -- 单站点帧(表23): byte4 bit1 = 训练帧标识(仅 SPLC 载波 SOF 定义)
            local std_ver = math.floor(band(tvb(12, 1):uint(), 0xF0) / 16)
            if std_ver == 2 and band(tvb(4, 1):uint(), 0x02) ~= 0 then
                local tt = band(tvb(5, 1):uint(), 0x01)
                dt_txt = T("SOF", "SOF") .. " " .. (tt == 1
                    and T("训练帧(Bitloading)", "Training Frame (Bitloading)")
                    or T("训练帧(MIMO)", "Training Frame (MIMO)"))
            end
        end
    end
    pinfo.cols.info = string.format("DT=%s SNID=0x%x", dt_txt, snid)

    local root = tree:add(nw, tvb())

    -- MPDU 帧控制 16B
    local fc_tree = root:add(nw, tvb(0, 16), T("MPDU 帧控制 (FCH)", "MPDU Frame Control (FCH)"))
    fc_tree:add(f.fc_dt, tvb(0, 1))
    fc_tree:add(f.fc_conind, tvb(0, 1))
    fc_tree:add(f.fc_snid, tvb(0, 1))

    local vf_tree = fc_tree:add(f.fc_vf, tvb(1, 12))
    local sof_res = nil
    if dt == 0 then
        dissect_beacon_vf(tvb, vf_tree, is_rf)
    elseif dt == 1 then
        sof_res = dissect_sof_vf(tvb, vf_tree, is_rf)
        if sof_res and sof_res.otype1 == 1 then
            pinfo.cols.info = string.format("DT=%s SNID=0x%x",
                T("SOF", "SOF") .. " " .. T("DL-OFDMA SACK", "DL-OFDMA SACK"), snid)
        elseif sof_res and sof_res.otype1 == 2 then
            pinfo.cols.info = string.format("DT=%s SNID=0x%x",
                T("SOF", "SOF") .. " " .. T("UL-OFDMA 数据帧，需 trigger 上下文",
                    "UL-OFDMA Data Frame, Requires Trigger Context"), snid)
        end
    elseif dt == 2 then
        dissect_ack_vf(tvb, vf_tree)
    elseif dt == 3 then
        dissect_coord_vf(tvb, vf_tree, is_rf)
    end

    fc_tree:add(f.fc_std_ver, tvb(12, 1))
    -- FCCS CRC24: 校验 FCH 前 13 字节(0-12), 存储值字节 13-15
    local fccs_rx = tvb(13, 3):le_uint()
    local fccs_calc = crc24_lsb(tvb, 0, 16)
    fc_tree:add(f.fc_fccs, tvb(13, 3), fccs_rx)
    fc_tree:add(f.fc_fccs_calc, tvb(13, 3), fccs_calc)
    fc_tree:add(f.fc_fccs_ok, tvb(13, 1), fccs_calc == fccs_rx)

    -- 信标帧载荷 (dt=0): 物理块紧跟 FCH
    if dt == 0 and tvb:len() > 16 then
        local pbsize
        if is_rf then
            pbsize = rf_pb_size(read_bits(tvb, 11 * 8, 4))
        else
            pbsize = plc_pb_size(read_bits(tvb, 10 * 8 + 4, 4), 0)
        end
        if pbsize > 0 and 16 + pbsize <= tvb:len() then
            dissect_beacon_payload(tvb, root:add(nw, tvb(16, pbsize), T("信标帧载荷", "Beacon Payload")), 16, pbsize)
        else
            root:add_expert_info(PI_MALFORMED, PI_WARN, T("TMI/载荷PB大小 无效或帧长不足", "Invalid TMI/PBLen or frame too short"))
        end
    end

    -- SOF 帧载荷 (dt=1): 物理块 → 块体重组出 MAC 帧
    -- 块基址: 普通帧 16(FCH 后) / DL-OFDMA 帧 32(FCH 16 + eFC 16B, 表27)
    if dt == 1 and tvb:len() > 16 and sof_res then
        local pb_base = sof_res.pb_base
        local pb_num = sof_res.pb_num
        local pbsize = sof_res.pbsize
        if pb_num == 0 then
            local note
            if sof_res.otype1 == 2 then
                -- UL-OFDMA 数据帧：帧本身有数据，缺 trigger 上下文
                note = T(" (UL-OFDMA 数据帧: 需 trigger 上下文才能定位 PB)",
                         " (UL-OFDMA Data Frame: Requires Trigger Context to Locate PBs)")
            elseif sof_res.otype1 == 1 then
                -- DL-SACK：单 16B PB，已在上面渲染
                note = T(" (DL-OFDMA SACK: 单 16B 物理块)",
                         " (DL-OFDMA SACK: Single 16 B PB)")
            else
                -- 训练帧 / trigger / UL-SACK：真的没有数据 PB
                note = T(" (训练帧/Trigger/UL-SACK: 无数据物理块, 不重组 MSDU)",
                         " (Training/Trigger/UL-SACK: No Data PB, No MSDU Reassembly)")
            end
            root:add(nw, tvb(16, math.min(16, tvb:len() - 16))):append_text(note)
        elseif pbsize > 8 and pb_num >= 1 and pb_num <= 16 then
            -- 逐 PB 块解析: 南网块 = PB头(4B) + 块体(pbsize-8) + 保留(1B) + CRC24(3B)
            -- MAC 帧统一用"块体逻辑视图"(单块/多块): 不生成新数据源, hex 始终完整显示原始帧
            local blocks_done = 0
            -- 级联记录边界预走(与后级联拆分循环同条件、同断开):沿拼接体流按
            -- [2B 级联头 + clen] 步进,收真记录头体流偏移集合;PB 循环里 cas 字段
            -- 只贴在真记录头上,体首为记录中段的 PB 不贴(记录可跨 PB 体边界)。
            -- 仅块齐全时预走(与拆分循环 blocks_done==pb_num 同义);截断帧边界集为空,
            -- cas 字段全不贴(与拆分循环不渲染一致),PB 级字段不受影响。
            local cas_bounds = {}
            if pbsize > 16 and pb_base + pb_num * pbsize <= tvb:len() then
                local pre_body = make_block_view(tvb, pb_base + 4, pbsize, pb_num)
                local o = 0
                while o + 2 <= pre_body:len() do
                    local clen = pre_body(o, 1):uint()
                               + band(pre_body(o + 1, 1):uint(), 0x0F) * 256
                    if clen <= 0 or o + 2 + clen > pre_body:len() then break end
                    cas_bounds[o] = true
                    o = o + 2 + clen
                end
            end
            for i = 0, pb_num - 1 do
                local bstart = pb_base + i * pbsize
                if bstart + pbsize > tvb:len() then break end
                local blk_tree = root:add(nw, tvb(bstart, pbsize),
                    string.format(T("物理块 %d", "PB %d"), i))
                blk_tree:add(f.pb_size, tvb(bstart, pbsize), pbsize)
                blk_tree:add(f.pb_hdr, tvb(bstart, 4))
                -- 聚合标志(表47 PB头 byte2 bit0)=1 时 PB 体含级联记录流;
                -- 级联头只在真记录头处(见 cas_bounds 预走),体首未必是记录头
                local agg = band(tvb(bstart + 2, 1):uint(), 0x01)
                blk_tree:add(f.pb_agg, tvb(bstart + 2, 1))
                blk_tree:add(f.pb_body, tvb(bstart + 4, pbsize - 8))
                if agg == 1 and pbsize > 16 and cas_bounds[i * (pbsize - 8)] then
                    -- 级联头(表48):级联数据块长度 12b(体0 全+体1 低 nib,LSB 在前)
                    -- +起始/结束标识+保留(体1 bit4/5/6-7), 其后为级联的 MAC 帧;
                    -- 16B PB 为 SACK 载体(表49/50),体首不是级联头,不贴
                    blk_tree:add(f.cas_len, tvb(bstart + 4, 2),
                        tvb(bstart + 4, 1):uint() + band(tvb(bstart + 5, 1):uint(), 0x0F) * 256)
                    blk_tree:add(f.cas_start, tvb(bstart + 5, 1))
                    blk_tree:add(f.cas_end, tvb(bstart + 5, 1))
                    blk_tree:add(f.cas_rsv, tvb(bstart + 5, 1))
                end
                if pbsize == 16 then
                    -- 16B 物理块(表49):体首 nibble=报文ID(0=DL-OFDMA SACK),报文内容(表50):
                    -- 源TEI 12b + 接收状态 2b + 保留(不重组 MSDU,仅展示)
                    local b0 = bstart + 4
                    blk_tree:add(f.sack16_msgid, tvb(b0, 1))
                    if band(tvb(b0, 1):uint(), 0x0F) == 0 then
                        blk_tree:add(f.sack16_src, tvb(b0, 2),
                            math.floor(band(tvb(b0, 1):uint(), 0xF0) / 16) + tvb(b0 + 1, 1):uint() * 16)
                        blk_tree:add(f.sack16_rx, tvb(b0 + 2, 1))
                        blk_tree:add(f.sack16_rsv, tvb(b0 + 2, 1))
                    end
                end
                blk_tree:add(f.pb_rsv, tvb(bstart + pbsize - 4, 1))
                -- CRC24: 块尾 3 字节 (小端), 校验前 pbsize-3 字节 (PB头+块体+保留)
                local crc_rx = tvb(bstart + pbsize - 3, 3):le_uint()
                local crc_calc = crc24_lsb(tvb, bstart, pbsize)
                blk_tree:add(f.pb_pbcs, tvb(bstart + pbsize - 3, 3), crc_rx)
                blk_tree:add(f.pb_crc_calc, tvb(bstart + pbsize - 3, 3), crc_calc)
                blk_tree:add(f.pb_crc_ok, tvb(bstart + pbsize - 3, 1), crc_calc == crc_rx)
                blocks_done = blocks_done + 1
            end
            if blocks_done == pb_num and pbsize > 16 then
                -- 16B PB 为 SACK 载体(表49/50,已按字段展示),不做 MAC 帧重组
                -- 聚合帧(用户需求,与 C++ pb_assembler 同构):任一 PB 聚合标志=1 →
                -- 各 PB 体依序拼接为连续级联记录流(记录可跨 PB 体边界),逐条
                -- [级联头 2B(表48) + 级联长度的独立 MAC 帧] 解析展示;非聚合保持
                -- 整流重组单 MSDU(原行为)
                local any_agg = false
                for i = 0, pb_num - 1 do
                    local bs = pb_base + i * pbsize
                    if band(tvb(bs + 2, 1):uint(), 0x01) == 1 then any_agg = true end
                end
                if any_agg then
                    local body = make_block_view(tvb, pb_base + 4, pbsize, pb_num)
                    local o = 0
                    local idx = 0
                    local cas_sums = {}
                    local cas_dir = nil
                    local end_idx = nil  -- 带 End 标识的记录序号(用于事后校验末条)
                    while o + 2 <= body:len() do
                        local clen = body(o, 1):uint()
                                   + band(body(o + 1, 1):uint(), 0x0F) * 256
                        if clen <= 0 or o + 2 + clen > body:len() then
                            root:add_expert_info(PI_MALFORMED, PI_WARN,
                                T(string.format("级联记录长度非法(clen=%d,偏移 %d),停止拆分", clen, o),
                                  string.format("Illegal cascade record length (clen=%d, offset %d); splitting stopped", clen, o)))
                            break
                        end
                        -- 表48 级联头字节1:bit4=Start/bit5=End;首条须 Start、中间条须无 Start
                        local cas_flags = band(body(o + 1, 1):uint(), 0x30)
                        if idx == 0 and band(cas_flags, 0x10) == 0 then
                            root:add_expert_info(PI_MALFORMED, PI_WARN,
                                T("级联首条缺 Start 标识", "First cascade record missing Start flag"))
                        elseif idx > 0 and band(cas_flags, 0x10) ~= 0 then
                            root:add_expert_info(PI_MALFORMED, PI_WARN,
                                T(string.format("级联中间条带 Start 标识(第 %d 条)", idx),
                                  string.format("Middle cascade record carries Start flag (record %d)", idx)))
                        end
                        if band(cas_flags, 0x20) ~= 0 then end_idx = idx end
                        local ct = root:add(nw, body(o + 2, clen),
                            string.format(T("级联 MAC 帧[%d]", "Cascade MAC Frame [%d]"), idx))
                        -- 有界子视图(坐标平移 + 长度截到 clen),MAC 帧内相对坐标映射回原始 tvb
                        local base = o + 2
                        local sv = setmetatable({}, { __call = function(_, off, ln)
                            off = off or 0
                            ln = ln or (clen - off)
                            return body(base + off, math.min(ln, clen - off))
                        end })
                        sv.len = function() return clen end
                        local sum, dmark = dissect_mac_frame(sv, ct, pinfo, snid, src_tei, true)
                        if not cas_dir and dmark and dmark ~= "" then cas_dir = dmark end
                        cas_sums[#cas_sums + 1] = (sum and sum ~= "") and sum or T("未识别", "unrecognized")
                        o = base + clen
                        idx = idx + 1
                    end
                    -- 事后 End 校验:无 End→末条缺 End;End 不在末条→提前结束
                    if idx > 0 then
                        if end_idx == nil then
                            root:add_expert_info(PI_MALFORMED, PI_WARN,
                                T("级联末条缺 End 标识", "Last cascade record missing End flag"))
                        elseif end_idx ~= idx - 1 then
                            root:add_expert_info(PI_MALFORMED, PI_WARN,
                                T(string.format("级联第 %d 条带 End 标识但后仍有记录", end_idx),
                                  string.format("Cascade record %d carries End flag but more records follow", end_idx)))
                        end
                    end
                    -- 聚合帧摘要(与 C++ nw_2026_parser.cpp r.msdu.summary 对齐):
                    -- 全同型压缩 "类型 ×N";混合型列前4项(>4 加" 等");空流计数式
                    local cas_cnt = idx
                    local agg_summary
                    if #cas_sums == 0 then
                        agg_summary = string.format(T("聚合帧(%d 个级联 MAC 帧)", "Aggregated Frame (%d cascade MAC frames)"), cas_cnt)
                    else
                        local all_same = true
                        for i = 2, #cas_sums do
                            if cas_sums[i] ~= cas_sums[1] then
                                all_same = false
                                break
                            end
                        end
                        if all_same then
                            agg_summary = string.format(T("聚合帧(%d 帧: %s ×%d)", "Aggregated Frame (%d frames: %s x%d)"), cas_cnt, cas_sums[1], cas_cnt)
                        else
                            local head = {}
                            for i = 1, math.min(#cas_sums, 4) do head[#head + 1] = cas_sums[i] end
                            local list = table.concat(head, T(", ", ", "))
                            if #cas_sums > 4 then list = list .. T(" 等", " etc.") end
                            agg_summary = string.format(T("聚合帧(%d 帧: %s)", "Aggregated Frame (%d frames: %s)"), cas_cnt, list)
                        end
                    end
                    -- 方向标记(取首个级联子帧) + 聚合摘要一次性写入, 不再逐子帧重复
                    local base_info = tostring(pinfo.cols.info)
                    if cas_dir then base_info = base_info .. cas_dir end
                    pinfo.cols.info = base_info .. " " .. agg_summary
                else
                    dissect_mac_frame(make_block_view(tvb, pb_base + 4, pbsize, pb_num), root, pinfo, snid, src_tei)
                end
            end
        else
            root:add_expert_info(PI_MALFORMED, PI_WARN, T("TMI 编号无效或 PB 个数越界", "Invalid TMI index or PB count out of range"))
        end
    end

    return tvb:len()
end

-- =========================================================================
-- 注册: 本协议不注册 wtap_encap —— 入口为 packet-nw_2021.lua 的版本分派委托
-- (FCH byte12 高 nibble==2 即 SPLC/NW_2026 时整帧 Dissector.get("nw_2026"):call),
-- 收到的 tvb 为裸 MPDU(FCH 16B 起, USER5 的 4B 媒介头已剥离), tree 为根。
-- 版本=1(BPLC)/0(保留) 帧仍由 nw_2021 自行解析, 但两类例外经入口分派进入本文件本地解析:
-- ① 载波 SOF version≠2 但 PB 头聚合标志(表47 byte2 bit0)=1 的聚合 BPLC 帧(BPLC 表20 布局);
-- ② 载波 SOF version=1 非聚合但承载 SPLC 扩展 MMe 0x0080-0x0085 的帧(表77 预读分派)。
-- =========================================================================
