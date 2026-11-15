--[[
    packet-gw_2026.lua
    国网 GW_2026 双模通信(高速载波+无线) 数据链路层协议 dissector (HDC 2.0)
    依据: 《双模通信互联互通技术规范 第4-2部分：数据链路层通信协议》HDC 2.0 版
          (FCH 表4 / SOF 表7-13 / SACK 表14 / MAC 表2-3 / MMe 表43+ / 信标 表38+ /
           单跳无线发现列表 表91-103 / 载波发现列表 表62-77 / 信道评估 表106-108)

    ★ 与 GW_2022(HDC 1.0) 的关系: 版本自适应委托 —— 本文件不注册 wtap_encap,
      由 packet-gw_2022.lua 入口读 FCH 标准版本号(byte12 bit4-7):
      版本=0(HDC 1.0) → 旧布局就地解析; 版本=1(HDC 2.0) → 本文件解析。
      (与上位机 GW_2026_Parser 委托 GW_2022_Parser 的架构互为镜像)

    ★ 字节序约定 (关键):
      - 字节内 bit0 = LSB
      - 跨字节 bit 字段(12bit TEI 等): little-endian bit 序, 用 read_bits()
      - 整字节多字节字段(16/24/32bit): little-endian, 用 le_uint()/le_uint24()
      - 时间戳(BTS/基准NTB)=NTB值, 25MHz时钟, 40ns/tick, 约171.8s回绕

    HDC 2.0 相对 1.0 的差异(本文件已体现):
      - FCH 表4: NID 24→16bit(byte1-2), byte3 保留
      - SOF 可变区域 表7: byte7 帧类型3b/TF符号位置2b/TF符号数3b, 帧长FL 12b,
        FCH符号数(9,7)+(10,0), 调制方式(10,1)+参数(10,2-5), PB个数 2b 编码
        (10,7)+(11,0), 广播/加密/重传(11,1-3), 频段(11,4-6), 增益(11,7)+(12,0-2),
        动态加载表ID(12,3); 链路标识符移至 MAC 头 byte15
      - SACK 可变区域 表14: 68bit 连续位流(RxStatus 跨字节等)
      - MAC 头 表2: 新增 聚合MAC帧标识(4,5) / 发送帧序号(11,4,12) / 链路标识符(byte15)
      - 单跳头 表3: 新增 聚合MAC帧标识(3,7); 消息类型 1=信道评估参数更新(表106-108)
        / 2=载波发现列表(表62,组合表 表68/77 含 BRU 变体)
      - 无线发现列表 表91-103: IE 内容逐字段(站点属性/路由/邻居信道非位图/位图版)
      - MMe 表43: 0x0008 发现列表改保留(改经单跳帧承载), 新增 0x0011-0x0014
        Bitloading训练请求/拒绝(表104/105)与分组请求/确认(表109-112),
        0x0050-0x0055 旧路由族废弃; 关联确认/汇总指示 载波频段 2→3bit(表47/52)
      - 信标 表38: 固定头 byte13 新增 信标机制状态(bit2)/发现信标使能(bit3);
        条目新增 0x06 万年历/0x07 信道评估参数/0x08 信标机制切换/0xC1 代理角色

    使用:
      tshark -r capture.pcap -X lua_script:packet-gw_2022.lua -X lua_script:packet-gw_2026.lua -V
      (委托入口在 packet-gw_2022.lua, 两文件须同时加载)
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
-- 与 Qt fieldspec.h crc24_lsb / Python MPDU_Class.cal_crc24 一致
-- 查找表法: 预计算 256 项, 每字节 O(1)
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
-- 与 Qt fieldspec.h crc32_le / Python cal_crc32 一致 (MSDU/信标载荷 ICV/BPCS 同算法)
-- 查找表法: 预计算 256 项, 每字节 O(1)
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

-- 语言开关: 读取 Wireshark 界面语言 (Edit→Preferences→Appearance→Language)
-- Wireshark 4.x 把界面语言存于个人配置目录的 language 文件 (Windows: %APPDATA%\Wireshark\language,
-- Linux/macOS: ~/.config/wireshark/language; 内容如 "language: en")
-- Lua pref 在脚本加载阶段恒为默认值, 无法用于决定字段名; 直接读该文件最可靠

-- 判断系统语言是否为中文: 优先 LC_ALL/LC_MESSAGES/LANG 环境变量, 其次仅在 Windows 查注册表 (GUI 从桌面启动时无 LANG)
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
    -- 1) 环境变量覆盖 (HPLC_RF_LANG=en/zh)
    local env = os.getenv("HPLC_RF_LANG")
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
            -- en / en_US 等 → 英文; zh / zh_CN 等 → 中文; system/auto 跟随系统
            if lang:lower():match("^zh") then return false end
            if lang:lower():match("^en") then return true end
            -- system/auto: 回退到系统语言
            return not system_is_chinese()
        end
    end
    -- 3) 回退: 系统语言
    return not system_is_chinese()
end

local hplc_english = detect_english()

-- 双语显示名: 按界面语言返回中文或英文
local function T(zh, en)
    if hplc_english then return en end
    return zh
end

local gw = Proto("gw_2026", T("国网GW_2026 双模通信数据链路层协议(HDC 2.0)", "GW_2026 Dual-Mode Data Link Layer Protocol (HDC 2.0)"))

-- =========================================================================
-- TEI ↔ MAC 映射表 (按 NID 分组)
-- 从历史帧学习: 关联确认/关联汇总/站点能力条目/发现列表 都携带 TEI+MAC
-- 之后在 Source/Destination 列附加显示 MAC 地址
-- =========================================================================
local tei_mac_map = {}   -- tei_mac_map[nid][tei] = "xx:xx:xx:xx:xx:xx"
local cur_nid = 0        -- 当前解析帧的 NID (主 dissector 设置)

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
    if not tei_mac_map[cur_nid] then tei_mac_map[cur_nid] = {} end
    tei_mac_map[cur_nid][tei] = mac_str
end

-- 查询 TEI → MAC, 无则返回 nil
local function lookup_tei_mac(nid, tei)
    local m = tei_mac_map[nid]
    if not m then return nil end
    return m[tei]
end

-- =========================================================================
-- value_string 表
-- =========================================================================
local dt_vals = {
    [0] = T("Beacon 信标帧", "Beacon"), [1] = T("SOF 数据帧", "SOF"),
    [2] = T("SACK 选择确认帧", "SACK"), [3] = T("网间协调帧", "Coordination"),
}
local network_type_vals = { [0] = T("用电信息采集系统", "Electricity usage information collection system") }
local std_ver_vals = { [0] = T("HDC 1.0(Q/GDW 12087.42)", "HDC 1.0 (Q/GDW 12087.42)"),
                       [1] = T("HDC 2.0(本标准)", "HDC 2.0 (this standard)") }
local send_type_vals = {
    [0] = T("单播", "Unicast"), [1] = T("全网广播", "Full-network broadcast"), [2] = T("本地广播", "Local broadcast"), [3] = T("代理广播", "Proxy broadcast"),
}
-- MCS 释义(表28; 与南网第2部分表129 逐值相同)
local mcs_vals = {
    [0] = T("分集4次 BPSK 码率1/2", "diversity 4, BPSK, code rate 1/2"),
    [1] = T("分集2次 BPSK 码率1/2", "diversity 2, BPSK, code rate 1/2"),
    [2] = T("分集2次 QPSK 码率1/2", "diversity 2, QPSK, code rate 1/2"),
    [3] = T("分集1次 QPSK 码率1/2", "diversity 1, QPSK, code rate 1/2"),
    [4] = T("分集1次 QPSK 码率4/5", "diversity 1, QPSK, code rate 4/5"),
    [5] = T("分集1次 16QAM 码率1/2", "diversity 1, 16QAM, code rate 1/2"),
    [6] = T("分集1次 16QAM 码率4/5", "diversity 1, 16QAM, code rate 4/5"),
}
-- 无线载荷 PB 大小(表29): 大小码 -> 字节数; >5 为保留值返回 -1
local rf_pb_sizes = { [0] = 16, [1] = 40, [2] = 72, [3] = 136, [4] = 264, [5] = 520 }
local function rf_pb_size(code)
    return rf_pb_sizes[code] or -1
end
local broadcast_dir_vals = {
    [0] = T("双向广播", "Bidirectional broadcast"), [1] = T("下行广播(CCO->STA)", "Downlink broadcast (CCO->STA)"), [2] = T("上行广播(STA->CCO)", "Uplink broadcast (STA->CCO)"),
}
local msdu_type_vals = {
    [0] = T("网络管理消息", "Network management message"), [48] = T("应用层报文", "Application layer packet"), [49] = T("IP 报文", "IP packet"),
}
local msg_type_vals = {
    [0] = T("无线发现列表消息", "RF Discovery list message"), [1] = T("信道评估参数更新报文", "Channel Evaluation Param Update"),
    [2] = T("载波发现列表消息", "Carrier Discovery list message"),
    [128] = T("应用层报文", "Application layer packet"), [129] = T("IPv4 报文", "IPv4 packet"),
}
-- 应用层报文 APP_BASE: 端口号 / 报文ID (依据 Qt 监控器 msduparser.cpp)
local app_port_vals = {
    [0x11] = T("管理/抄表端口", "Management/Meter-reading port"),
    [0x12] = T("升级端口", "Upgrade port"),
    [0x1A] = T("安全端口", "Security port"),
}
local app_packet_id_vals = {
    [0x0001] = T("终端主动抄表", "Terminal active meter-reading"),
    [0x0002] = T("路由主动抄表", "Routing active meter-reading"),
    [0x0003] = T("终端主动并发抄表", "Terminal active concurrent meter-reading"),
    [0x00B3] = T("终端主动并发抄表", "Terminal active concurrent meter-reading"),
    [0x0004] = T("校时", "Clock calibration"),
    [0x0006] = T("通信测试", "Communication test"),
    [0x0008] = T("事件上报", "Event report"),
    [0x0011] = T("查询从节点主动注册", "Query slave active registration"),
    [0x0012] = T("启动从节点主动注册", "Start slave active registration"),
    [0x0013] = T("停止从节点主动注册", "Stop slave active registration"),
    [0x0020] = T("确认/否认", "Ack/Nak"),
}
local beacon_type_vals = {
    [0] = T("发现信标", "Discovery Beacon"), [1] = T("代理信标", "Proxy Beacon"), [2] = T("中央信标", "Central Beacon"),
}
local link_type_vals = { [0] = T("高速载波链路", "PLC carrier link"), [1] = T("无线链路", "RF link") }
local phase_vals = { [0] = T("未知", "Unknown"), [1] = T("A相线", "Line A"), [2] = T("B相线", "Line B"), [3] = T("C相线", "Line C") }
local device_type_vals = {
    [1] = T("抄控器", "CCO device"), [2] = T("集中器本地通信单元", "Concentrator local comm unit"), [3] = T("电表通信单元", "Meter comm unit"),
    [4] = T("中继器", "Repeater"), [5] = T("II型采集器", "Type-II collector"), [6] = T("I型采集器单元", "Type-I collector unit"),
    [7] = T("三相电表通信单元", "Three-phase meter comm unit"),
}
local mac_addr_type_vals = {
    [0] = T("电能表地址作为入网MAC", "Meter address as MAC"), [1] = T("通信模块本身MAC作为入网MAC", "Module MAC as MAC"),
}
local module_type_vals = {
    [0] = T("高速载波单模", "PLC single-mode"), [1] = T("双模(载波+无线)", "Dual-mode (PLC+RF)"), [2] = T("无线单模", "RF single-mode"),
}
local assoc_result_vals = {
    [0x00] = T("关联请求成功", "Association succeeded"), [0x01] = T("站点不在白名单中", "STA not in whitelist"),
    [0x02] = T("站点在黑名单中", "STA in blacklist"), [0x03] = T("站点个数超过上限", "STA count over limit"),
    [0x04] = T("没有设置白名单列表", "No whitelist configured"), [0x05] = T("代理站点个数超过上限", "Proxy count over limit"),
    [0x06] = T("子站点个数超过上限", "Child STA count over limit"), [0x08] = T("重复的MAC地址", "Duplicate MAC address"),
    [0x09] = T("超过拓扑层级", "Exceeds topology level"), [0x0A] = T("站点再次关联请求入网成功", "STA re-association succeeded"),
    [0x0B] = T("新站点试图以自己子站点为代理入网", "New STA uses own child as proxy"), [0x0C] = T("组网拓扑中存在环路", "Loop in topology"),
    [0x0D] = T("CCO端未知原因出错", "CCO unknown error"), [0x0E] = T("无线代理达到上限", "RF proxy over limit"),
}
-- HDC 2.0 频段标识(表49/表7): 0-6 有效,值3 保留(HDC 2.0 新增 4/5/6)
local carrier_band_vals = {
    [0] = T("1.953~11.96MHz", "1.953~11.96 MHz"), [1] = T("2.441~5.615MHz", "2.441~5.615 MHz"),
    [2] = T("0.781~2.930MHz", "0.781~2.930 MHz"), [3] = T("保留", "Reserved"),
    [4] = T("0.781~5.615MHz", "0.781~5.615 MHz"), [5] = T("0.781~11.96MHz", "0.781~11.96 MHz"),
    [6] = T("6.08~11.96MHz", "6.08~11.962 MHz"),  [7] = T("保留", "Reserved"),
}
local route_type_vals = {
    [0] = T("错误", "Error"), [1] = T("同级路由", "Same-level route"), [2] = T("上级路由", "Upper-level route"),
    [3] = T("代理主路径路由", "Proxy main path route"), [4] = T("上上级路由", "Upper-upper-level route"),
}
local mgmt_type_vals = {
    [0x0000] = T("关联请求 AssocReq", "AssocReq"),
    [0x0001] = T("关联确认 AssocCnf", "AssocCnf"),
    [0x0002] = T("关联汇总指示 AssocGatherInd", "AssocGatherInd"),
    [0x0003] = T("代理变更请求 ChangeProxyReq", "ChangeProxyReq"),
    [0x0004] = T("代理变更确认 ChangeProxyCnf", "ChangeProxyCnf"),
    [0x0005] = T("代理变更确认(位图版) ChangeProxyBitMapCnf", "ChangeProxyBitMapCnf"),
    [0x0006] = T("离线指示 LeaveInd", "LeaveInd"),
    [0x0007] = T("心跳检测 HeartBeatCheck", "HeartBeatCheck"),
    [0x0008] = T("保留(1.0 发现列表,2.0 改经单跳帧/信标承载)", "Reserved (was DiscoverNodeList in 1.0)"),
    [0x0009] = T("通信成功率上报 SuccessRateReport", "SuccessRateReport"),
    [0x000A] = T("网络冲突上报 NetworkConflictReport", "NetworkConflictReport"),
    [0x000B] = T("过零NTB采集指示 ZeroCrossNTBCollectInd", "ZeroCrossNTBCollectInd"),
    [0x000C] = T("过零NTB上报 ZeroCrossNTBReport", "ZeroCrossNTBReport"),
    [0x0011] = T("Bitloading训练请求 BitloadingTrainReq", "BitloadingTrainReq"),
    [0x0012] = T("Bitloading训练请求拒绝 BitloadingTrainReqReject", "BitloadingTrainReqReject"),
    [0x0013] = T("分组请求 GroupReq", "GroupReq"),
    [0x0014] = T("分组确认 GroupCnf", "GroupCnf"),
    [0x004F] = T("网络诊断报文 Diagnose", "Diagnose"),
    [0x0050] = T("保留(1.0 路由请求)", "Reserved (was RouteRequest in 1.0)"),
    [0x0051] = T("保留(1.0 路由回复)", "Reserved (was RouteReply in 1.0)"),
    [0x0052] = T("保留(1.0 路由错误)", "Reserved (was RouteError in 1.0)"),
    [0x0053] = T("保留(1.0 路由应答)", "Reserved (was RouteAck in 1.0)"),
    [0x0054] = T("保留(1.0 链路确认请求)", "Reserved (was LinkConfirmRequest in 1.0)"),
    [0x0055] = T("保留(1.0 链路确认回应)", "Reserved (was LinkConfirmResponse in 1.0)"),
    [0x0080] = T("无线信道冲突上报 RFChannelConflictReport", "RFChannelConflictReport"),
}
local beacon_entry_type_vals = {
    [0x00] = T("站点能力条目", "STA Capability Item"), [0x01] = T("路由参数条目", "Route Parameter Item"),
    [0x02] = T("频段变更条目", "Band Change Item"), [0x03] = T("无线路由参数条目", "RF Route Parameter Item"),
    [0x04] = T("无线信道变更条目", "RF Channel Change Item"), [0x05] = T("精简信标站点信息及时隙条目", "Lite STA Info & Slot Item"),
    [0x06] = T("万年历条目", "Perpetual Calendar Item"), [0x07] = T("信道评估参数条目", "Channel Assess Param Item"),
    [0x08] = T("信标机制切换条目", "Beacon Mechanism Switch Item"),
    [0xC0] = T("时隙分配条目", "Time Slot Allocation Item"), [0xC1] = T("代理角色条目", "Proxy Role Item"),
    [0xC2] = T("发现列表条目(载荷在 PB Padding 区)", "Discover List Item (payload in PB padding)"),
}
local role_vals = {
    [0x0] = T("未知", "Unknown"), [0x1] = "STA", [0x2] = "PCO", [0x4] = "CCO",
}
local boot_reason_vals = {
    [0x0] = T("正常启动", "Normal boot"), [0x1] = T("断电重启", "Power-cycle reboot"), [0x2] = T("看门狗复位", "Watchdog reset"), [0x3] = T("程序指针异常", "Program counter fault"),
}
local chip_vendor_vals = {
    [0x0001] = "HS", [0x0002] = "ES", [0x0003] = "TC", [0x0004] = "LH",
    [0x0005] = "HT", [0x0006] = "RS", [0x0007] = "SW", [0x0008] = "SC",
    [0x0009] = "YM", [0x000A] = "QJ", [0x000B] = "HZ", [0x000C] = "ZC",
    [0x000D] = "SP", [0x000E] = "PE", [0x000F] = "NR", [0x0010] = "SL",
    [0x0011] = "MT", [0x0012] = "SI", [0x0013] = "RS", [0x0014] = "XY",
}
local ie_type_vals = {
    [0] = T("站点属性信息", "STA attribute info"), [1] = T("站点路由信息", "STA route info"),
    [2] = T("邻居节点信道信息(非位图版)", "Neighbor channel info (non-bitmap)"), [3] = T("邻居节点信道信息(位图版)", "Neighbor channel info (bitmap)"),
}
local len_type_vals = { [0] = T("1字节", "1 byte"), [1] = T("2字节", "2 bytes") }
local collect_site_vals = { [0] = T("指定单站点采集", "Single STA collect"), [1] = T("指定全网站点采集", "All STA collect") }
local collect_period_vals = { [0] = T("二分之一电力线周期", "Half power-line cycle"), [1] = T("一个电力线周期", "One power-line cycle") }
local payload_type_vals = { [0] = T("未携带负载数据", "No payload data"), [1] = T("传播路径列表", "Propagation path list") }
local leave_reason_vals = {
    [0] = T("CCO通知站点立即离线", "CCO orders immediate leave"), [1] = T("网络拓扑层级超过上限", "Topology level exceeds limit"),
    [2] = T("站点不在最新白名单中", "STA not in latest whitelist"),
}

-- =========================================================================
-- ProtoField 定义 (第一参数 = filter abbr)
-- =========================================================================
local f = {}

-- MPDU 帧控制 (表13)
f.fc_dt = ProtoField.uint8 ("gw_2026.fc.dt", T("定界符类型", "Delimiter Type"), base.DEC, dt_vals, 0x07)
f.fc_net_type = ProtoField.uint8 ("gw_2026.fc.net_type", T("网络类型", "Network Type"),   base.DEC, network_type_vals, 0xF8)
f.fc_nid = ProtoField.uint16 ("gw_2026.fc.nid", T("网络标识(NID,16bit)", "Network ID (NID, 16bit)"), base.HEX)
f.fc_nid_rsv = ProtoField.uint8 ("gw_2026.fc.nid_rsv", T("保留(byte3)", "Reserved (byte3)"), base.HEX)
f.fc_vf = ProtoField.bytes ("gw_2026.fc.vf", T("可变区域", "Variant Field"), base.NONE)
f.fc_std_ver = ProtoField.uint8 ("gw_2026.fc.std_ver", T("标准版本号", "Standard Version"), base.DEC, std_ver_vals, 0xF0)
f.fc_fccs = ProtoField.uint24 ("gw_2026.fc.fccs", T("帧控制校验序列(FCCS,CRC24)", "Frame Control Check Sequence (FCCS, CRC24)"), base.HEX)
f.fc_fccs_calc = ProtoField.uint24 ("gw_2026.fc.fccs_calc", T("FCCS 计算值", "FCCS Calculated"), base.HEX)
f.fc_fccs_ok = ProtoField.bool ("gw_2026.fc.fccs_ok", T("FCCS 校验通过", "FCCS Check Passed"), 8, nil, 0x01)

-- 物理块头 (表37)
f.pb_seq = ProtoField.uint8 ("gw_2026.pb.seq", T("序列号", "Sequence Number"), base.DEC, nil, 0x3F)
f.pb_sof = ProtoField.bool ("gw_2026.pb.sof", T("帧起始标志", "Start of Frame Flag"), 8, nil, 0x40)
f.pb_eof = ProtoField.bool ("gw_2026.pb.eof", T("帧结束标志", "End of Frame Flag"), 8, nil, 0x80)
f.pb_pbcs = ProtoField.uint24 ("gw_2026.pb.pbcs", T("物理块检查序列(PBCS,CRC24)", "PB Check Sequence (PBCS, CRC24)"), base.HEX)
f.pb_size = ProtoField.uint16 ("gw_2026.pb.size", T("物理块大小(字节)", "PB Size (bytes)"), base.DEC)
f.pb_crc_ok = ProtoField.bool ("gw_2026.pb.crc_ok", T("CRC24校验通过", "CRC24 Check Passed"), 8, nil, 0x01)
f.pb_crc_calc = ProtoField.uint24 ("gw_2026.pb.crc_calc", T("CRC24计算值", "CRC24 Calculated"), base.HEX)
f.pb_body = ProtoField.bytes ("gw_2026.pb.body", T("物理块体(PB Body)", "PB Body"), base.NONE)
f.pb_padding = ProtoField.bytes ("gw_2026.pb.padding", T("填充(Padding)", "Padding"), base.NONE)

-- 信标帧可变区域 (表17 载波)
f.beacon_bts = ProtoField.uint32 ("gw_2026.beacon.bts", T("信标时间戳(BTS,原始NTB)", "Beacon Timestamp (BTS, raw NTB)"), base.DEC)
f.beacon_bts_sec = ProtoField.double ("gw_2026.beacon.bts_sec", T("信标时间戳(秒)", "Beacon Timestamp (seconds)"), base.DEC)
f.beacon_src_tei = ProtoField.uint16 ("gw_2026.beacon.src_tei", T("源TEI", "Source TEI"), base.DEC)
f.beacon_div_mode = ProtoField.uint8 ("gw_2026.beacon.div_mode", T("分集拷贝基本模式", "Diversity Copy Basic Mode"), base.DEC, nil, 0xF0)
f.beacon_symbol_cnt = ProtoField.uint16 ("gw_2026.beacon.symbol_cnt", T("符号数", "Symbol Count"), base.DEC)
f.beacon_phase = ProtoField.uint8 ("gw_2026.beacon.phase", T("相线", "Line"), base.DEC, phase_vals, 0x06)

-- 信标帧载荷 (表38/56)
f.beacon_type = ProtoField.uint8 ("gw_2026.beacon.type", T("信标类型", "Beacon Type"), base.DEC, beacon_type_vals, 0x07)
f.beacon_net_cplt = ProtoField.bool ("gw_2026.beacon.net_cplt", T("组网标志位", "Networking Flag"), 8, nil, 0x08)
f.beacon_simple = ProtoField.bool ("gw_2026.beacon.simple", T("精简信标标志", "Lite Beacon Flag"), 8, nil, 0x10)
f.beacon_start_assoc = ProtoField.bool ("gw_2026.beacon.start_assoc", T("开始关联标志", "Start Association Flag"), 8, nil, 0x40)
f.beacon_use_flag = ProtoField.bool ("gw_2026.beacon.use_flag", T("信标使用标志", "Beacon Use Flag"), 8, nil, 0x80)
f.beacon_net_seq = ProtoField.uint8 ("gw_2026.beacon.net_seq", T("组网序列号", "Networking Sequence Number"), base.DEC)
f.beacon_cco_mac = ProtoField.ether ("gw_2026.beacon.cco_mac", T("CCO MAC地址", "CCO MAC Address"))
f.beacon_bpc = ProtoField.uint32 ("gw_2026.beacon.bpc", T("信标周期计数(BPC)", "Beacon Period Count (BPC)"), base.DEC)
f.beacon_rf_ch = ProtoField.uint8 ("gw_2026.beacon.rf_ch", T("本网络无线信道编号", "RF Channel Number"), base.DEC)
-- HDC 2.0 表38 byte13 新增
f.beacon_rf_option = ProtoField.uint8 ("gw_2026.beacon.rf_option", T("option", "Option"), base.DEC, nil, 0x03)
f.beacon_mech_state = ProtoField.uint8 ("gw_2026.beacon.mech_state", T("信标机制状态", "Beacon Mechanism State"), base.DEC, {
    [0] = T("固定信标", "Fixed beacon"), [1] = T("竞争信标", "Contention beacon"),
}, 0x04)
f.beacon_disc_en = ProtoField.uint8 ("gw_2026.beacon.disc_en", T("发现信标发送使能", "Discover Beacon Enable"), base.DEC, {
    [0] = T("未使能", "Disabled"), [1] = T("使能", "Enabled"),
}, 0x08)
f.beacon_rsv13 = ProtoField.uint8 ("gw_2026.beacon.rsv13", T("保留(byte13 bit4-7)", "Reserved (byte13 bit4-7)"), base.HEX, nil, 0xF0)
-- HDC 2.0 信标新条目(表34/35/36/37)
f.beacon_cal_sec = ProtoField.uint32 ("gw_2026.beacon.cal_sec", T("万年历时钟(自 2000-01-01 秒数)", "Calendar Seconds (since 2000-01-01)"), base.DEC)
f.beacon_cal_ntb = ProtoField.uint32 ("gw_2026.beacon.cal_ntb", T("对应 NTB", "Corresponding NTB"), base.DEC)
f.beacon_ca_active = ProtoField.uint8 ("gw_2026.beacon.ca_active", T("主动评估使能", "Active Assess Enable"), base.DEC, nil, 0x01)
f.beacon_ca_passive = ProtoField.uint8 ("gw_2026.beacon.ca_passive", T("被动评估使能", "Passive Assess Enable"), base.DEC, nil, 0x02)
f.beacon_ca_period = ProtoField.uint8 ("gw_2026.beacon.ca_period", T("被动评估周期(10s)", "Passive Assess Period (10s)"), base.DEC)
f.beacon_sw_target = ProtoField.uint8 ("gw_2026.beacon.sw_target", T("切换目标机制 ID", "Target Mechanism ID"), base.DEC)
f.beacon_sw_ntb = ProtoField.uint32 ("gw_2026.beacon.sw_ntb", T("切换 NTB 时刻", "Switch NTB"), base.DEC)
f.beacon_proxy_cnt = ProtoField.uint8 ("gw_2026.beacon.proxy_cnt", T("网络内代理站点总数", "Proxy STA Count"), base.DEC)
f.beacon_proxy_tei = ProtoField.uint16 ("gw_2026.beacon.proxy_tei", T("代理节点 TEI", "Proxy Node TEI"), base.DEC)
f.beacon_entry_cnt = ProtoField.uint8 ("gw_2026.beacon.entry_cnt", T("信标条目数", "Beacon Item Count"), base.DEC)
f.beacon_bpcs = ProtoField.uint32 ("gw_2026.beacon.bpcs", T("帧载荷校验序列(BPCS,CRC32)", "Beacon Payload Check Sequence (BPCS, CRC32)"), base.HEX)
f.beacon_bpcs_calc = ProtoField.uint32 ("gw_2026.beacon.bpcs_calc", T("BPCS 计算值", "BPCS Calculated"), base.HEX)
f.beacon_bpcs_ok = ProtoField.bool ("gw_2026.beacon.bpcs_ok", T("BPCS 校验通过", "BPCS Check Passed"), 8, nil, 0x01)

-- 信标管理信息条目 (表46-57)
f.beacon_ent_type = ProtoField.uint8 ("gw_2026.beacon.ent.type", T("信标条目头", "Beacon Item Head"), base.HEX, beacon_entry_type_vals)
f.beacon_ent_len = ProtoField.uint16 ("gw_2026.beacon.ent.len", T("信标条目长度", "Beacon Item Length"), base.DEC)
f.beacon_ent_data = ProtoField.bytes ("gw_2026.beacon.ent.data", T("信标条目内容", "Beacon Item Content"), base.NONE)

-- 站点能力条目 (表47)
f.ent_tei = ProtoField.uint16 ("gw_2026.beacon.cap.tei", T("TEI", "TEI"), base.DEC)
f.ent_proxy_tei = ProtoField.uint16 ("gw_2026.beacon.cap.proxy_tei", T("代理站点TEI", "Proxy TEI"), base.DEC)
f.ent_path_rate = ProtoField.uint8 ("gw_2026.beacon.cap.path_rate", T("路径最低通信成功率(%)", "Path Min Comm Rate (%)"), base.DEC)
f.ent_sta_mac = ProtoField.ether ("gw_2026.beacon.cap.sta_mac", T("发送信标站点MAC", "Beacon TX STA MAC"), base.NONE)
f.ent_role = ProtoField.uint8 ("gw_2026.beacon.cap.role", T("角色", "Role"), base.DEC, role_vals, 0x0F)
f.ent_level = ProtoField.uint8 ("gw_2026.beacon.cap.level", T("层级数", "Level"), base.DEC, nil, 0xF0)
f.ent_proxy_qual = ProtoField.uint8 ("gw_2026.beacon.cap.proxy_qual", T("代理站点信道质量(dB)", "Proxy Channel Quality (dB)"), base.DEC)
f.ent_phase = ProtoField.uint8 ("gw_2026.beacon.cap.phase", T("相线", "Line"), base.DEC, phase_vals, 0x03)
f.ent_rf_hop = ProtoField.uint8 ("gw_2026.beacon.cap.rf_hop", T("链路上RF跳数", "RF Hops on Path"), base.DEC, nil, 0x3C)

-- 路由参数条目 (表48)
f.ent_route_period = ProtoField.uint16 ("gw_2026.beacon.rp.route_period", T("路由周期(秒)", "Route Period (s)"), base.DEC)
f.ent_route_remain = ProtoField.uint16 ("gw_2026.beacon.rp.route_remain", T("路由评估剩余时间(秒)", "Route Estimate Remaining (s)"), base.DEC)
f.ent_proxy_dl_period = ProtoField.uint16 ("gw_2026.beacon.rp.proxy_dl_period", T("代理站点发现列表周期(秒)", "Proxy Discovery List Period (s)"), base.DEC)
f.ent_disc_dl_period = ProtoField.uint16 ("gw_2026.beacon.rp.disc_dl_period", T("发现站点发现列表周期(秒)", "STA Discovery List Period (s)"), base.DEC)

-- 频段变更条目 (表49)
f.ent_target_band = ProtoField.uint8 ("gw_2026.beacon.bc.target_band", T("目标频段", "Target Band"), base.HEX)
f.ent_band_remain = ProtoField.uint32 ("gw_2026.beacon.bc.band_remain", T("频段切换剩余时间(ms)", "Band Switch Remaining (ms)"), base.DEC)

-- 时隙分配条目 (表50)
f.ent_nc_beacon_cnt = ProtoField.uint8 ("gw_2026.beacon.slot.nc_beacon_cnt", T("非中央信标时隙总数", "Non-CCO Beacon Slot Count"), base.DEC)
f.ent_c_beacon_cnt = ProtoField.uint8 ("gw_2026.beacon.slot.c_beacon_cnt", T("中央信标时隙总数", "CCO Beacon Slot Count"), base.DEC, nil, 0x0F)
f.ent_csma_phase_cnt = ProtoField.uint8 ("gw_2026.beacon.slot.csma_phase_cnt", T("CSMA时隙支持相线个数", "CSMA Slot Line Count"), base.DEC, nil, 0x30)
f.ent_proxy_beacon_cnt = ProtoField.uint8 ("gw_2026.beacon.slot.proxy_beacon_cnt", T("代理信标时隙总数", "Proxy Beacon Slot Count"), base.DEC)
f.ent_beacon_slot_len = ProtoField.uint8 ("gw_2026.beacon.slot.beacon_slot_len", T("信标时隙长度(ms)", "Beacon Slot Length (ms)"), base.DEC)
f.ent_csma_slice_len = ProtoField.uint8 ("gw_2026.beacon.slot.csma_slice_len", T("CSMA时隙分片长度(10ms)", "CSMA Slot Slice Length (10ms)"), base.DEC)
f.ent_bcsma_phase_cnt = ProtoField.uint8 ("gw_2026.beacon.slot.bcsma_phase_cnt", T("绑定CSMA时隙相线个数", "Binding CSMA Slot Line Count"), base.DEC)
f.ent_bcsma_lid = ProtoField.uint8 ("gw_2026.beacon.slot.bcsma_lid", T("绑定CSMA时隙链路标识符", "Binding CSMA Slot LID"), base.DEC)
f.ent_tdma_slot_len = ProtoField.uint8 ("gw_2026.beacon.slot.tdma_slot_len", T("TDMA时隙长度(ms)", "TDMA Slot Length (ms)"), base.DEC)
f.ent_tdma_lid = ProtoField.uint8 ("gw_2026.beacon.slot.tdma_lid", T("TDMA时隙链路标识符", "TDMA Slot LID"), base.DEC)
f.ent_bp_start_ntb = ProtoField.uint32 ("gw_2026.beacon.slot.bp_start_ntb", T("信标周期起始网络基准时", "Beacon Period Start NTB"), base.DEC)
f.ent_bp_len = ProtoField.uint32 ("gw_2026.beacon.slot.bp_len", T("信标周期长度(ms)", "Beacon Period Length (ms)"), base.DEC)
f.ent_rf_beacon_len = ProtoField.uint16 ("gw_2026.beacon.slot.rf_beacon_len", T("RF信标时隙长度(ms)", "RF Beacon Slot Length (ms)"), base.DEC)

-- 非中央信标信息 (表51)
f.ent_ncb_tei = ProtoField.uint16 ("gw_2026.beacon.ncb.tei", T("TEI", "TEI"), base.DEC)
f.ent_ncb_type = ProtoField.uint8 ("gw_2026.beacon.ncb.type", T("信标类型", "Beacon Type"), base.DEC, {[0]=T("发现信标", "Discovery Beacon"),[1]=T("代理信标", "Proxy Beacon")}, 0x10)
f.ent_ncb_rf_flag = ProtoField.uint8 ("gw_2026.beacon.ncb.rf_flag", T("无线信标标志", "RF Beacon Flag"), base.DEC, nil, 0xE0)

-- CSMA时隙信息 (表52)
f.ent_csma_len = ProtoField.uint24 ("gw_2026.beacon.csma.len", T("CSMA时隙长度(ms)", "CSMA Slot Length (ms)"), base.DEC)
f.ent_csma_phase = ProtoField.uint8 ("gw_2026.beacon.csma.phase", T("CSMA时隙相线", "CSMA Slot Line"), base.DEC, phase_vals, 0x03)

-- 绑定CSMA时隙信息 (表53)
f.ent_bcsma_len = ProtoField.uint24 ("gw_2026.beacon.bcsma.len", T("绑定CSMA时隙长度(ms)", "Binding CSMA Slot Length (ms)"), base.DEC)
f.ent_bcsma_phase = ProtoField.uint8 ("gw_2026.beacon.bcsma.phase", T("绑定CSMA时隙相线", "Binding CSMA Slot Line"), base.DEC, phase_vals, 0x03)

-- 无线路由参数条目 (表54)
f.ent_rf_dl_period = ProtoField.uint8 ("gw_2026.beacon.rfp.dl_period", T("无线发现列表周期(秒)", "RF Discovery List Period (s)"), base.DEC)
f.ent_rf_age_cnt = ProtoField.uint8 ("gw_2026.beacon.rfp.age_cnt", T("无线接收率老化周期个数", "RF Rate Age Period Count"), base.DEC)

-- 无线信道变更条目 (表55)
f.ent_target_ch = ProtoField.uint8 ("gw_2026.beacon.rcc.target_ch", T("目标信道", "Target Channel"), base.DEC)
f.ent_ch_remain = ProtoField.uint32 ("gw_2026.beacon.rcc.ch_remain", T("信道切换剩余时间(ms)", "Channel Switch Remaining (ms)"), base.DEC)

-- 精简信标站点信息及时隙条目 (表57)
f.ent_sb_csma_start = ProtoField.uint32 ("gw_2026.beacon.sb.csma_start", T("CSMA时隙开始时间(NTB)", "CSMA Slot Start Time (NTB)"), base.DEC)
f.ent_sb_csma_len = ProtoField.uint16 ("gw_2026.beacon.sb.csma_len", T("CSMA时隙长度(ms)", "CSMA Slot Length (ms)"), base.DEC)

-- SOF 帧可变区域 (表19 载波 / 表30 无线)
f.sof_src_tei = ProtoField.uint16 ("gw_2026.sof.src_tei", T("源TEI", "Source TEI"), base.DEC)
f.sof_dst_tei = ProtoField.uint16 ("gw_2026.sof.dst_tei", T("目的TEI", "Destination TEI"), base.DEC)
f.sof_lid = ProtoField.uint8 ("gw_2026.sof.lid", T("链路标识符(LID)", "Link Identifier (LID)"), base.DEC)
f.sof_frame_len = ProtoField.uint16 ("gw_2026.sof.frame_len", T("帧长", "Frame Length"), base.DEC)
f.sof_pb_count = ProtoField.uint8 ("gw_2026.sof.pb_count", T("物理块个数", "PB Count"), base.DEC, nil, 0xF0)
f.sof_symbol_cnt = ProtoField.uint16 ("gw_2026.sof.symbol_cnt", T("符号数", "Symbol Count"), base.DEC)
f.sof_bcast = ProtoField.bool ("gw_2026.sof.bcast", T("广播标志", "Broadcast Flag"), 8, nil, 0x02)
f.sof_retrans = ProtoField.bool ("gw_2026.sof.retrans", T("重传标志", "Retransmit Flag"), 8, nil, 0x04)
f.sof_encrypt = ProtoField.bool ("gw_2026.sof.encrypt", T("加密标志(预留)", "Encryption Flag (reserved)"), 8, nil, 0x08)
f.sof_div_mode = ProtoField.uint8 ("gw_2026.sof.div_mode", T("分集拷贝基本模式", "Diversity Copy Basic Mode"), base.DEC, nil, 0xF0)
f.sof_div_ext = ProtoField.uint8 ("gw_2026.sof.div_ext", T("分集拷贝扩展模式", "Diversity Copy Extended Mode"), base.DEC, nil, 0x0F)
f.sof_pb_size = ProtoField.uint8 ("gw_2026.sof.pb_size", T("载荷PB块大小(无线)", "Payload PB Size (RF)"), base.DEC, nil, 0xF0)
f.sof_mcs = ProtoField.uint8 ("gw_2026.sof.mcs", T("MCS(无线)", "MCS (RF)"), base.DEC, mcs_vals, 0xF0)
f.sof_rsv = ProtoField.uint16 ("gw_2026.sof.rsv", T("保留", "Reserved"), base.HEX)
f.sof_rsv4 = ProtoField.uint8 ("gw_2026.sof.rsv4", T("保留", "Reserved"), base.HEX, nil, 0x0F)
-- HDC 2.0 SOF 可变区域(表7 数据帧)
f.sof_frame_type = ProtoField.uint8 ("gw_2026.sof.frame_type", T("帧类型", "Frame Type"), base.DEC, {
    [0] = T("数据帧", "Data"), [1] = T("信道探测帧", "Channel Probe"),
    [2] = T("OFDMA下行帧", "OFDMA Downlink"), [3] = T("TDA下行帧", "TDA Downlink"),
}, 0x07)
f.sof_tf_sym_pos = ProtoField.uint8 ("gw_2026.sof.tf_sym_pos", T("TF符号位置", "TF Symbol Position"), base.DEC, {
    [0] = T("不携带TF", "No TF"), [1] = T("数据载荷之前", "Before payload"), [2] = T("数据载荷之后", "After payload"),
}, 0x18)
f.sof_tf_sym_num = ProtoField.uint8 ("gw_2026.sof.tf_sym_num", T("TF符号数", "TF Symbol Count"), base.DEC, nil, 0xE0)
-- SOF 子类型专属字段(表9/10/12, 与 Qt 解析器同坐标;仅展示)
f.sof_subc_group = ProtoField.uint8 ("gw_2026.sof.subc_group", T("子载波分组(表9:0=4个/1=6个一组)", "Subcarrier Group (4/6 per group)"), base.DEC, nil, 0x18)
f.sof_train_band = ProtoField.uint8 ("gw_2026.sof.train_band", T("训练序列频段标识(表9)", "Training Seq Band"), base.DEC, nil, 0x70)
f.sof_train_sym = ProtoField.uint8 ("gw_2026.sof.train_sym", T("信道探测训练序列符号数(表9,(v+1)*2)", "Training Seq Symbols"), base.DEC, nil, 0xFE)
f.sof_ext_dst = ProtoField.uint16 ("gw_2026.sof.ext_dst", T("扩展目的TEI(表9)", "Extended Dst TEI"), base.DEC)
f.sof_sta_num = ProtoField.uint8 ("gw_2026.sof.sta_num", T("站点数(表10/12:1=2站/2=3站/3=4站)", "Station Count"), base.DEC, nil, 0x18)
f.sof_pay_sym = ProtoField.uint16 ("gw_2026.sof.pay_sym", T("数据载荷符号数(表10/12)", "Payload Symbol Count"), base.DEC)
f.sof_efc_sym = ProtoField.uint8 ("gw_2026.sof.efc_sym", T("扩展帧控制符号数(表10/12:0:2/1:4/2:8/3:12/4:16)", "eFC Symbol Count"), base.DEC, nil, 0x80)
f.sof_st0_pbn = ProtoField.uint8 ("gw_2026.sof.st0_pbn", T("站点0物理块个数(表10,0/1→1/2块)", "Sta0 PB Count"), base.DEC, nil, 0x04)
f.sof_st0_div = ProtoField.uint8 ("gw_2026.sof.st0_div", T("站点0分集拷贝模式", "Sta0 DivCopy Mode"), base.DEC, nil, 0xF8)
f.sof_st0_ru = ProtoField.uint8 ("gw_2026.sof.st0_ru", T("站点0RU(表10)", "Sta0 RU"), base.DEC, nil, 0x0F)
f.sof_enc_tda = ProtoField.uint8 ("gw_2026.sof.enc_tda", T("加密标志位(表12,预留)", "Encrypted (reserved)"), base.DEC, nil, 0x04)
f.sof_st0_band = ProtoField.uint8 ("gw_2026.sof.st0_band", T("站点0TF和数据载荷频段标识(表12)", "Sta0 TF&Payload Band"), base.DEC, nil, 0x07)
f.sof_st0_tf = ProtoField.uint8 ("gw_2026.sof.st0_tf", T("站点0TF标识(表12:0=携带)", "Sta0 TF Flag"), base.DEC, nil, 0x08)
f.sof_rsv_b12 = ProtoField.uint8 ("gw_2026.sof.rsv_b12", T("保留(表10/12 byte12 bit4-7)", "Reserved"), base.HEX, nil, 0xF0)
-- eFC 站点字段(表11 OFDMA 每站 3B / 表13 TDA 每站 4B;与 Qt 解析器同坐标)
f.efc1_st_tei = ProtoField.uint16 ("gw_2026.efc1.st_tei", T("站点目的TEI(表11)", "Station DstTEI"), base.DEC)
f.efc1_st_ru = ProtoField.uint8 ("gw_2026.efc1.st_ru", T("站点RU(表11)", "Station RU"), base.DEC, nil, 0xF0)
f.efc1_st_div = ProtoField.uint8 ("gw_2026.efc1.st_div", T("站点分集拷贝模式(表11)", "Station DivCopy"), base.DEC)
f.efc1_st_pbn = ProtoField.uint8 ("gw_2026.efc1.st_pbn", T("站点物理块个数(表11,0/1→1/2块)", "Station PB Count"), base.DEC)
f.efc1_st_rsv = ProtoField.uint8 ("gw_2026.efc1.st_rsv", T("保留(表11)", "Reserved"), base.HEX)
f.efd_st_tei = ProtoField.uint16 ("gw_2026.efd.st_tei", T("站点目的TEI(表13)", "Station DstTEI"), base.DEC)
f.efd_st_sym = ProtoField.uint16 ("gw_2026.efd.st_sym", T("站点数据载荷符号数(表13)", "Station Payload Symbols"), base.DEC)
f.efd_st_band = ProtoField.uint8 ("gw_2026.efd.st_band", T("站点TF与数据载荷频段(表13)", "Station Band"), base.DEC)
f.efd_st_div = ProtoField.uint8 ("gw_2026.efd.st_div", T("站点分集拷贝模式(表13)", "Station DivCopy"), base.DEC)
f.efd_st_rsv = ProtoField.uint8 ("gw_2026.efd.st_rsv", T("保留(表13)", "Reserved"), base.HEX)
-- 选择确认 表15(反馈 SNR 版)
f.sack15_pbn = ProtoField.uint8 ("gw_2026.sack15.pbn", T("接收物理块个数(表15 4,2-3)", "RxPBNum (v+1)"), base.DEC, nil, 0x0C)
f.sack15_status = ProtoField.uint8 ("gw_2026.sack15.status", T("接收状态(表15 4,4-7)", "RxStatus"), base.DEC, nil, 0xF0)
f.sack15_src = ProtoField.uint16 ("gw_2026.sack15.src", T("源TEI(表15 5,0,12)", "SrcTEI"), base.DEC)
f.sack15_dst = ProtoField.uint16 ("gw_2026.sack15.dst", T("目的TEI(表15 6,4,12)", "DstTEI"), base.DEC)
f.sack15_bru = ProtoField.uint8 ("gw_2026.sack15.bru", T("BRU SNR(表15 档位)", "BRU SNR (level)"), base.DEC)
f.sof_fl = ProtoField.uint16 ("gw_2026.sof.fl", T("帧长(FL,×10µs)", "Frame Length (FL, ×10µs)"), base.DEC)
f.sof_fl_rsv = ProtoField.uint8 ("gw_2026.sof.fl_rsv", T("保留(byte9 bit4-6)", "Reserved (byte9 bit4-6)"), base.HEX, nil, 0x70)
f.sof_fch_sym_num = ProtoField.uint8 ("gw_2026.sof.fch_sym_num", T("FCH符号数", "FCH Symbol Count"), base.DEC, {
    [0] = T("短FCH", "Short FCH"), [1] = T("标准FCH", "Standard FCH"), [2] = T("长FCH", "Long FCH"),
}, nil)
f.sof_mod_mode = ProtoField.uint8 ("gw_2026.sof.mod_mode", T("数据载荷调制方式", "Payload Modulation Mode"), base.DEC, {
    [0] = T("分集拷贝模式", "Diversity copy"), [1] = T("动态加载模式", "Dynamic loading"),
}, 0x02)
f.sof_mod_param = ProtoField.uint8 ("gw_2026.sof.mod_param", T("数据载荷调制参数", "Payload Modulation Parameter"), base.DEC, nil, 0x7C)
f.sof_pb_code = ProtoField.uint8 ("gw_2026.sof.pb_code", T("PB物理块个数(2b编码)", "PB Count (2bit code)"), base.DEC, nil, nil)
f.sof_band = ProtoField.uint8 ("gw_2026.sof.band", T("TF与数据载荷频段标识", "TF & Payload Band"), base.DEC, carrier_band_vals, 0x70)
f.sof_gain = ProtoField.uint8 ("gw_2026.sof.gain", T("数据载荷增益", "Payload Gain"), base.DEC, nil, nil)
f.sof_load_table_id = ProtoField.uint8 ("gw_2026.sof.load_table_id", T("动态加载表ID标识", "Dynamic Load Table ID"), base.DEC, nil, 0x08)
f.beacon_mcs = ProtoField.uint8 ("gw_2026.beacon.mcs", T("MCS(无线)", "MCS (RF)"), base.DEC, mcs_vals, 0xF0)
f.beacon_pbcode = ProtoField.uint8 ("gw_2026.beacon.pbcode", T("载荷PB大小(无线)", "Payload PB Size (RF)"), base.DEC, nil, 0x0F)
f.beacon_rsv1 = ProtoField.uint8 ("gw_2026.beacon.rsv1", T("保留", "Reserved"), base.HEX, nil, 0xF0)
f.beacon_rsv_b11 = ProtoField.uint8 ("gw_2026.beacon.rsv_b11", T("保留", "Reserved"), base.HEX)
f.beacon_vf_rsv2 = ProtoField.uint8 ("gw_2026.beacon.vf.rsv2", T("保留", "Reserved"), base.HEX, nil, 0x0F)

-- SACK 帧可变区域 (表23/34)
f.sack_recv_result = ProtoField.uint8 ("gw_2026.sack.recv_result", T("接收结果", "Receive Result"), base.DEC, nil, 0x0F)
f.sack_recv_status = ProtoField.uint8 ("gw_2026.sack.recv_status", T("接收状态", "Receive Status"), base.HEX, nil, 0xF0)
f.sack_src_tei = ProtoField.uint16 ("gw_2026.sack.src_tei", T("源TEI", "Source TEI"), base.DEC)
f.sack_dst_tei = ProtoField.uint16 ("gw_2026.sack.dst_tei", T("目的TEI", "Destination TEI"), base.DEC)
f.sack_pb_count = ProtoField.uint8 ("gw_2026.sack.pb_count", T("接收物理块个数", "Received PB Count"), base.DEC, nil, 0x07)
f.sack_chan_qual = ProtoField.uint8 ("gw_2026.sack.chan_qual", T("信道质量(SNR,dB)", "Channel Quality (SNR, dB)"), base.DEC)
f.sack_site_load = ProtoField.uint8 ("gw_2026.sack.site_load", T("站点负载(缓存报文数)", "STA Load (buffered packets)"), base.DEC)
f.sack_ext_type = ProtoField.uint8 ("gw_2026.sack.ext_type", T("扩展帧类型", "Extended Frame Type"), base.DEC, nil, 0x1E)
-- HDC 2.0 SACK 可变区域(表14):68bit 连续位流
f.sack_bru = ProtoField.uint8 ("gw_2026.sack.bru", T("BRU SNR 反馈标志", "BRU SNR Feedback Flag"), base.DEC, nil, nil)
f.sack_satid = ProtoField.uint8 ("gw_2026.sack.satid", T("SAT ID 反馈标志", "SAT ID Feedback Flag"), base.DEC, nil, nil)
f.sack_rx_res = ProtoField.uint8 ("gw_2026.sack.rx_res", T("接收结果", "Receive Result"), base.DEC, nil, nil)
f.sack_rx_pb_num = ProtoField.uint8 ("gw_2026.sack.rx_pb_num", T("已接收物理块个数", "Received PB Count"), base.DEC, nil, nil)
f.sack_rx_status = ProtoField.uint8 ("gw_2026.sack.rx_status", T("接收状态位图", "Receive Status Bitmap"), base.HEX, nil, nil)
f.sack_remain_sta = ProtoField.uint8 ("gw_2026.sack.remain_sta", T("剩余等待站点个数", "Remaining Waiting STA Count"), base.DEC, nil, nil)
f.sack_rsv0 = ProtoField.uint8 ("gw_2026.sack.rsv0", T("保留0(byte8 bit3-7)", "Reserved0 (byte8 bit3-7)"), base.HEX, nil, nil)
f.sack_rsv1 = ProtoField.uint8 ("gw_2026.sack.rsv1", T("保留1(byte11)", "Reserved1 (byte11)"), base.HEX, nil, nil)

-- 网间协调帧可变区域 (表26)
f.coord_duration = ProtoField.uint16 ("gw_2026.coord.duration", T("持续时间(1ms)", "Duration (1ms)"), base.DEC)
f.coord_bw_offset = ProtoField.uint16 ("gw_2026.coord.bw_offset", T("带宽开始偏移(1ms)", "Bandwidth Start Offset (1ms)"), base.DEC)
f.coord_nbr_nid = ProtoField.uint24 ("gw_2026.coord.nbr_nid", T("接收到的邻居网络号", "Received Neighbor Network ID"), base.HEX)
f.coord_rf_ch = ProtoField.uint8 ("gw_2026.coord.rf_ch", T("本网络无线信道编号", "RF Channel Number"), base.DEC)

-- 标准 MAC 帧头 (表4)
f.mac_version = ProtoField.uint8 ("gw_2026.mac.version", T("版本", "Version"), base.DEC, nil, 0x0F)
f.mac_ostei = ProtoField.uint16 ("gw_2026.mac.ostei", T("原始源TEI", "Original Source TEI"), base.DEC)
f.mac_odtei = ProtoField.uint16 ("gw_2026.mac.odtei", T("原始目的TEI", "Original Destination TEI"), base.DEC)
f.mac_send_type = ProtoField.uint8 ("gw_2026.mac.send_type", T("发送类型", "Send Type"), base.DEC, send_type_vals, 0xF0)
f.mac_retry_limit = ProtoField.uint8 ("gw_2026.mac.retry_limit", T("发送次数限值", "Retry Limit"), base.DEC, nil, 0x1F)
f.mac_rsv0 = ProtoField.uint8 ("gw_2026.mac.rsv0", T("保留", "Reserved"), base.HEX, nil, 0xE0)
f.mac_msdu_seq = ProtoField.uint16 ("gw_2026.mac.msdu_seq", T("MSDU序列号", "MSDU Sequence Number"), base.DEC)
f.mac_msdu_type = ProtoField.uint8 ("gw_2026.mac.msdu_type", T("MSDU类型", "MSDU Type"), base.DEC, msdu_type_vals)
f.mac_msdu_len = ProtoField.uint16 ("gw_2026.mac.msdu_len", T("MSDU长度", "MSDU Length"), base.DEC)
f.mac_restart_cnt = ProtoField.uint8 ("gw_2026.mac.restart_cnt", T("重启次数", "Restart Count"), base.DEC, nil, 0x78)
f.mac_proxy_main = ProtoField.bool ("gw_2026.mac.proxy_main", T("代理主路径标识", "Proxy Main Path Flag"), 8, nil, 0x80)
f.mac_route_total = ProtoField.uint8 ("gw_2026.mac.route_total", T("路由总跳数", "Total Hops"), base.DEC, nil, 0x0F)
f.mac_route_left = ProtoField.uint8 ("gw_2026.mac.route_left", T("路由剩余跳数", "Remaining Hops"), base.DEC, nil, 0xF0)
f.mac_bcast_dir = ProtoField.uint8 ("gw_2026.mac.bcast_dir", T("广播方向", "Broadcast Direction"), base.DEC, broadcast_dir_vals, 0x03)
f.mac_path_repair = ProtoField.bool ("gw_2026.mac.path_repair", T("路径修复标志", "Path Repair Flag"), 8, nil, 0x04)
f.mac_addr_flag = ProtoField.bool ("gw_2026.mac.addr_flag", T("MAC地址标志", "MAC Address Flag"), 8, nil, 0x08)
f.mac_rsv1 = ProtoField.uint8 ("gw_2026.mac.rsv1", T("保留", "Reserved"), base.HEX, nil, 0xF0)
f.mac_rsv2 = ProtoField.uint8 ("gw_2026.mac.rsv2", T("保留", "Reserved"), base.HEX)
f.mac_net_seq = ProtoField.uint8 ("gw_2026.mac.net_seq", T("组网序列号", "Networking Sequence Number"), base.DEC)
f.mac_rsv3 = ProtoField.uint8 ("gw_2026.mac.rsv3", T("保留", "Reserved"), base.HEX)
f.mac_rsv4 = ProtoField.uint8 ("gw_2026.mac.rsv4", T("保留", "Reserved"), base.HEX)
-- HDC 2.0 MAC 帧头新增(表2)
f.mac_aggregate = ProtoField.bool ("gw_2026.mac.aggregate", T("聚合MAC帧标识", "Aggregate MAC Frame Flag"), 8, nil, 0x20)
f.mac_send_seq = ProtoField.uint16 ("gw_2026.mac.send_seq", T("发送帧序号", "Send Frame Sequence"), base.DEC)
f.mac_link_id = ProtoField.uint8 ("gw_2026.mac.link_id", T("链路标识符", "Link Identifier"), base.DEC)
f.mac_osmac = ProtoField.ether ("gw_2026.mac.osmac", T("原始源MAC地址", "Original Source MAC"))
f.mac_odmac = ProtoField.ether ("gw_2026.mac.odmac", T("原始目的MAC地址", "Original Destination MAC"))
f.mac_icv = ProtoField.uint32 ("gw_2026.mac.icv", T("完整性校验值(ICV,CRC32)", "Integrity Check Value (ICV, CRC32)"), base.HEX)
f.mac_icv_calc = ProtoField.uint32 ("gw_2026.mac.icv_calc", T("ICV 计算值", "ICV Calculated"), base.HEX)
f.mac_icv_ok = ProtoField.bool ("gw_2026.mac.icv_ok", T("ICV 校验通过", "ICV Check Passed"), 8, nil, 0x01)


-- 媒介头 (串口混合采集 USER4/USER5 格式: [phr_mcs][option][channel][isRF], 之后纯 MPDU)
f.media_phr_mcs = ProtoField.uint8 ("gw_2026.media.phr_mcs", T("PHR MCS", "PHR MCS"), base.HEX)
f.media_option = ProtoField.uint8 ("gw_2026.media.option", T("option", "option"), base.HEX)
f.media_channel = ProtoField.uint8 ("gw_2026.media.channel", T("信道", "Channel"), base.DEC)
f.media_is_rf = ProtoField.uint8 ("gw_2026.media.is_rf", T("媒介(0=载波,非0=无线)", "Media (0=PLC, non-0=RF)"), base.DEC, {[0]=T("载波 HPLC", "PLC"), [1]=T("无线 RF", "RF")})

-- 原始目标地址列 (自定义列引用, 显示 ODTEI + MAC 映射)
f.col_orig_dst = ProtoField.string ("gw_2026.col_orig_dst", "Original Destination Address")
f.col_orig_src = ProtoField.string ("gw_2026.col_orig_src", "Original Source Address")

-- 通用保留字段 (各帧共用)
f.rsvd = ProtoField.uint8 ("gw_2026.rsvd", T("保留", "Reserved"), base.HEX)
-- 信标帧可变区域保留位 (字节11 bit3-7)
f.beacon_vf_rsv = ProtoField.uint8 ("gw_2026.beacon.vf.rsv", T("保留", "Reserved"), base.HEX, nil, 0xF8)
-- SACK 帧保留 (字节8 bit3-7 和 字节11)
f.sack_rsv = ProtoField.uint8 ("gw_2026.sack.rsv", T("保留", "Reserved"), base.HEX)
-- 协调帧保留 (字节12 bit0-3)
f.coord_rsv = ProtoField.uint8 ("gw_2026.coord.rsv", T("保留", "Reserved"), base.HEX, nil, 0x0F)

-- 单跳 MAC 帧头 (表11)
f.sh_version = ProtoField.uint8 ("gw_2026.sh.version", T("版本", "Version"), base.DEC, nil, 0x0F)
f.sh_msgtype = ProtoField.uint8 ("gw_2026.sh.msg_type", T("消息类型", "Message Type"), base.DEC, msg_type_vals)
f.sh_msdulen = ProtoField.uint16 ("gw_2026.sh.msdu_len", T("MSDU长度", "MSDU Length"), base.DEC)
f.sh_aggregate = ProtoField.bool ("gw_2026.sh.aggregate", T("聚合MAC帧标识", "Aggregate MAC Frame Flag"), 8, nil, 0x80)
f.sh_msdu_crc = ProtoField.uint32 ("gw_2026.sh.msdu_crc", T("MSDU校验(CRC32)", "MSDU CRC32"), base.HEX)
f.sh_msdu_crc_ok = ProtoField.bool ("gw_2026.sh.msdu_crc_ok", T("MSDU CRC32 校验通过", "MSDU CRC32 OK"), 8, nil, 0xFF)
f.sh_rsv1 = ProtoField.uint8 ("gw_2026.sh.rsv1", T("保留(byte3 bit3-6)", "Reserved (byte3 bit3-6)"), base.HEX, nil, 0x78)

-- 管理消息头 (表58)
f.mgmt_mmtype = ProtoField.uint16 ("gw_2026.mgmt.mmtype", T("管理消息类型(MMTYPE)", "Management Message Type (MMTYPE)"), base.HEX, mgmt_type_vals)
f.mgmt_resv = ProtoField.uint16 ("gw_2026.mgmt.reserved", T("保留", "Reserved"), base.HEX)

-- 关联请求 (表60-68)
f.ar_sta_mac = ProtoField.ether ("gw_2026.assoc_req.sta_mac", T("站点MAC地址", "STA MAC Address"))
f.ar_proxy_tei = ProtoField.uint16 ("gw_2026.assoc_req.proxy_tei", T("候选代理TEI", "Candidate Proxy TEI"), base.DEC)
f.ar_link_type = ProtoField.uint8 ("gw_2026.assoc_req.link_type", T("链路类型", "Link Type"), base.DEC, link_type_vals, 0x10)
f.ar_phase = ProtoField.uint8 ("gw_2026.assoc_req.phase", T("相线", "Line"), base.DEC, phase_vals, 0x03)
f.ar_dev_type = ProtoField.uint8 ("gw_2026.assoc_req.dev_type", T("设备类型", "Device Type"), base.DEC, device_type_vals)
f.ar_mac_type = ProtoField.uint8 ("gw_2026.assoc_req.mac_type", T("MAC地址类型", "MAC Address Type"), base.DEC, mac_addr_type_vals)
f.ar_module = ProtoField.uint8 ("gw_2026.assoc_req.module", T("模块类型", "Module Type"), base.DEC, module_type_vals, 0x03)
f.ar_assoc_rand = ProtoField.uint32 ("gw_2026.assoc_req.assoc_rand", T("站点关联随机数", "Association Random Number"), base.HEX)
f.ar_vendor = ProtoField.bytes ("gw_2026.assoc_req.vendor", T("厂家自定义信息", "Vendor Custom Info"), base.NONE)
f.ar_boot_reason = ProtoField.uint8 ("gw_2026.assoc_req.boot_reason", T("系统启动原因", "Boot Reason"), base.DEC, boot_reason_vals)
f.ar_boot_ver = ProtoField.uint8 ("gw_2026.assoc_req.boot_ver", T("BOOT版本号", "BOOT Version"), base.DEC)
f.ar_soft_ver = ProtoField.uint16 ("gw_2026.assoc_req.soft_ver", T("软件版本号(BCD)", "Software Version (BCD)"), base.HEX)
f.ar_ver_time = ProtoField.uint16 ("gw_2026.assoc_req.ver_time", T("版本时间(BIN)", "Version Time (BIN)"), base.HEX)
f.ar_vendor_code = ProtoField.uint16 ("gw_2026.assoc_req.vendor_code", T("厂商代码(ASCII)", "Vendor Code (ASCII)"), base.DEC)
f.ar_chip_code = ProtoField.uint16 ("gw_2026.assoc_req.chip_code", T("芯片代码(ASCII)", "Chip Code (ASCII)"), base.DEC)
f.ar_hard_rst = ProtoField.uint16 ("gw_2026.assoc_req.hard_rst", T("硬复位累积次数", "Hard Reset Count"), base.DEC)
f.ar_soft_rst = ProtoField.uint16 ("gw_2026.assoc_req.soft_rst", T("软复位累积次数", "Soft Reset Count"), base.DEC)
f.ar_proxy_type = ProtoField.uint8 ("gw_2026.assoc_req.proxy_type", T("代理类型", "Proxy Type"), base.DEC, proxy_type_vals)
f.ar_e2e_seq = ProtoField.uint32 ("gw_2026.assoc_req.e2e_seq", T("端到端序列号", "End-to-End Sequence Number"), base.DEC)
f.ar_mgmt_id = ProtoField.bytes ("gw_2026.assoc_req.mgmt_id", T("管理ID信息(24B)", "Management ID Info (24B)"), base.NONE)

-- 关联确认 (表70-75)
f.ac_sta_mac = ProtoField.ether ("gw_2026.assoc_cnf.sta_mac", T("站点MAC地址", "STA MAC Address"))
f.ac_cco_mac = ProtoField.ether ("gw_2026.assoc_cnf.cco_mac", T("CCO MAC地址", "CCO MAC Address"))
f.ac_result = ProtoField.uint8 ("gw_2026.assoc_cnf.result", T("结果", "Result"), base.HEX, assoc_result_vals)
f.ac_sta_level = ProtoField.uint8 ("gw_2026.assoc_cnf.sta_level", T("站点层级", "STA Level"), base.DEC)
f.ac_sta_tei = ProtoField.uint16 ("gw_2026.assoc_cnf.sta_tei", T("站点TEI", "STA TEI"), base.DEC)
f.ac_link_type = ProtoField.uint8 ("gw_2026.assoc_cnf.link_type", T("链路类型", "Link Type"), base.DEC, link_type_vals, 0x10)
f.ac_carrier_band = ProtoField.uint8 ("gw_2026.assoc_cnf.carrier_band", T("载波频段(3bit,表47)", "Carrier Band (3bit, Table 47)"), base.DEC, carrier_band_vals, 0xE0)
f.ac_proxy_tei = ProtoField.uint16 ("gw_2026.assoc_cnf.proxy_tei", T("代理TEI", "Proxy TEI"), base.DEC)
f.ac_total_pkgs = ProtoField.uint8 ("gw_2026.assoc_cnf.total_pkgs", T("总分包数", "Total Packages"), base.DEC)
f.ac_pkg_idx = ProtoField.uint8 ("gw_2026.assoc_cnf.pkg_idx", T("分包序号", "Package Index"), base.DEC)
f.ac_assoc_rand = ProtoField.uint32 ("gw_2026.assoc_cnf.assoc_rand", T("站点关联随机数", "Association Random Number"), base.HEX)
f.ac_reassoc_time = ProtoField.uint32 ("gw_2026.assoc_cnf.reassoc_time", T("重新关联时间(ms)", "Re-association Time (ms)"), base.DEC)
f.ac_e2e_seq = ProtoField.uint32 ("gw_2026.assoc_cnf.e2e_seq", T("端到端序列号", "End-to-End Sequence Number"), base.DEC)
f.ac_path_seq = ProtoField.uint32 ("gw_2026.assoc_cnf.path_seq", T("路径序号", "Path Sequence Number"), base.DEC)
f.ac_direct_sta = ProtoField.uint16 ("gw_2026.assoc_cnf.direct_sta", T("直连站点数", "Direct STA Count"), base.DEC)
f.ac_direct_proxy = ProtoField.uint16 ("gw_2026.assoc_cnf.direct_proxy", T("直连代理数", "Direct Proxy Count"), base.DEC)
f.ac_route_size = ProtoField.uint16 ("gw_2026.assoc_cnf.route_size", T("路由表大小", "Route Table Size"), base.DEC)

-- 关联汇总指示 (表76-78)
f.ag_result = ProtoField.uint8 ("gw_2026.assoc_gather.result", T("结果", "Result"), base.DEC)
f.ag_sta_level = ProtoField.uint8 ("gw_2026.assoc_gather.sta_level", T("站点层级", "STA Level"), base.DEC)
f.ag_cco_mac = ProtoField.ether ("gw_2026.assoc_gather.cco_mac", T("CCO MAC地址", "CCO MAC Address"))
f.ag_proxy_tei = ProtoField.uint16 ("gw_2026.assoc_gather.proxy_tei", T("代理TEI", "Proxy TEI"), base.DEC)
f.ag_carrier_band = ProtoField.uint8 ("gw_2026.assoc_gather.carrier_band", T("载波频段(3bit,表52)", "Carrier Band (3bit, Table 52)"), base.DEC, carrier_band_vals, 0x70)
f.ag_gather_cnt = ProtoField.uint8 ("gw_2026.assoc_gather.gather_cnt", T("汇总站点数", "Gathered STA Count"), base.DEC)
f.ag_sta_mac = ProtoField.ether ("gw_2026.assoc_gather.sta_mac", T("站点MAC地址", "STA MAC Address"))
f.ag_sta_tei = ProtoField.uint16 ("gw_2026.assoc_gather.sta_tei", T("站点TEI", "STA TEI"), base.DEC)

-- 代理变更请求 (表79-83)
f.cpr_sta_tei = ProtoField.uint16 ("gw_2026.cproxy_req.sta_tei", T("站点TEI", "STA TEI"), base.DEC)
f.cpr_new_proxy = ProtoField.uint16 ("gw_2026.cproxy_req.new_proxy", T("新代理TEI", "New Proxy TEI"), base.DEC)
f.cpr_link_type = ProtoField.uint8 ("gw_2026.cproxy_req.link_type", T("链路类型", "Link Type"), base.DEC, link_type_vals, 0x10)
f.cpr_old_proxy = ProtoField.uint16 ("gw_2026.cproxy_req.old_proxy", T("旧代理TEI", "Old Proxy TEI"), base.DEC)
f.cpr_proxy_type = ProtoField.uint8 ("gw_2026.cproxy_req.proxy_type", T("代理类型", "Proxy Type"), base.DEC)
f.cpr_reason = ProtoField.uint8 ("gw_2026.cproxy_req.reason", T("原因", "Reason"), base.DEC)
f.cpr_e2e_seq = ProtoField.uint32 ("gw_2026.cproxy_req.e2e_seq", T("端到端序列号", "End-to-End Sequence Number"), base.DEC)
f.cpr_phase = ProtoField.uint8 ("gw_2026.cproxy_req.phase", T("站点相线", "STA Line"), base.DEC, phase_vals, 0x03)

-- 代理变更确认 (表84-87)
f.cpc_result = ProtoField.uint8 ("gw_2026.cproxy_cnf.result", T("结果", "Result"), base.DEC)
f.cpc_total_pkgs = ProtoField.uint8 ("gw_2026.cproxy_cnf.total_pkgs", T("总分包数", "Total Packages"), base.DEC)
f.cpc_pkg_idx = ProtoField.uint8 ("gw_2026.cproxy_cnf.pkg_idx", T("分包序号", "Package Index"), base.DEC)
f.cpc_sta_tei = ProtoField.uint16 ("gw_2026.cproxy_cnf.sta_tei", T("站点TEI", "STA TEI"), base.DEC)
f.cpc_link_type = ProtoField.uint8 ("gw_2026.cproxy_cnf.link_type", T("链路类型", "Link Type"), base.DEC, link_type_vals, 0x10)
f.cpc_proxy_tei = ProtoField.uint16 ("gw_2026.cproxy_cnf.proxy_tei", T("代理TEI", "Proxy TEI"), base.DEC)
f.cpc_e2e_seq = ProtoField.uint32 ("gw_2026.cproxy_cnf.e2e_seq", T("端到端序列号", "End-to-End Sequence Number"), base.DEC)
f.cpc_path_seq = ProtoField.uint32 ("gw_2026.cproxy_cnf.path_seq", T("路径序号", "Path Sequence Number"), base.DEC)
f.cpc_child_cnt = ProtoField.uint16 ("gw_2026.cproxy_cnf.child_cnt", T("子站点数", "Child STA Count"), base.DEC)
f.cpc_child_tei = ProtoField.uint16 ("gw_2026.cproxy_cnf.child_tei", T("子站点TEI", "Child STA TEI"), base.DEC)

-- 代理变更确认位图版 (表88-90)
f.cpb_result = ProtoField.uint8 ("gw_2026.cproxy_bmp.result", T("结果", "Result"), base.DEC)
f.cpb_bitmap_size = ProtoField.uint16 ("gw_2026.cproxy_bmp.bitmap_size", T("位图大小(字节)", "Bitmap Size (bytes)"), base.DEC)
f.cpb_sta_tei = ProtoField.uint16 ("gw_2026.cproxy_bmp.sta_tei", T("站点TEI", "STA TEI"), base.DEC)
f.cpb_link_type = ProtoField.uint8 ("gw_2026.cproxy_bmp.link_type", T("链路类型", "Link Type"), base.DEC, link_type_vals, 0x10)
f.cpb_proxy_tei = ProtoField.uint16 ("gw_2026.cproxy_bmp.proxy_tei", T("代理TEI", "Proxy TEI"), base.DEC)
f.cpb_e2e_seq = ProtoField.uint32 ("gw_2026.cproxy_bmp.e2e_seq", T("端到端序列号", "End-to-End Sequence Number"), base.DEC)
f.cpb_path_seq = ProtoField.uint32 ("gw_2026.cproxy_bmp.path_seq", T("路径序号", "Path Sequence Number"), base.DEC)
f.cpb_child_bmp = ProtoField.bytes ("gw_2026.cproxy_bmp.child_bmp", T("子站点位图", "Child STA Bitmap"), base.NONE)

-- 离线指示 (表91-93)
f.li_reason = ProtoField.uint16 ("gw_2026.leave.reason", T("原因", "Reason"), base.DEC, leave_reason_vals)
f.li_sta_cnt = ProtoField.uint16 ("gw_2026.leave.sta_cnt", T("站点总数", "STA Count"), base.DEC)
f.li_delay = ProtoField.uint16 ("gw_2026.leave.delay", T("延迟时间(秒)", "Delay Time (s)"), base.DEC)
f.li_sta_mac = ProtoField.ether ("gw_2026.leave.sta_mac", T("站点MAC地址", "STA MAC Address"))

-- 心跳检测 (表94)
f.hb_ostei = ProtoField.uint16 ("gw_2026.hb.ostei", T("原始源TEI", "Original Source TEI"), base.DEC)
f.hb_max_disc_tei = ProtoField.uint16 ("gw_2026.hb.max_disc_tei", T("发现站点数最大的站点TEI", "Max Discovery STA TEI"), base.DEC)
f.hb_max_disc_cnt = ProtoField.uint16 ("gw_2026.hb.max_disc_cnt", T("最大的发现站点数", "Max Discovery STA Count"), base.DEC)
f.hb_bitmap_size = ProtoField.uint16 ("gw_2026.hb.bitmap_size", T("位图大小(字节)", "Bitmap Size (bytes)"), base.DEC)
f.hb_disc_bmp = ProtoField.bytes ("gw_2026.hb.disc_bmp", T("发现站点位图", "Discovery STA Bitmap"), base.NONE)

-- 发现列表 (表95-99)
f.dl_tei = ProtoField.uint16 ("gw_2026.dl.tei", T("TEI", "TEI"), base.DEC)
f.dl_proxy_tei = ProtoField.uint16 ("gw_2026.dl.proxy_tei", T("代理TEI", "Proxy TEI"), base.DEC)
f.dl_role = ProtoField.uint8 ("gw_2026.dl.role", T("角色", "Role"), base.DEC, role_vals, 0x0F)
f.dl_level = ProtoField.uint8 ("gw_2026.dl.level", T("层级", "Level"), base.DEC, nil, 0xF0)
f.dl_mac = ProtoField.ether ("gw_2026.dl.mac", T("MAC地址", "MAC Address"))
f.dl_cco_mac = ProtoField.ether ("gw_2026.dl.cco_mac", T("CCO MAC地址", "CCO MAC Address"))
f.dl_phase = ProtoField.uint8 ("gw_2026.dl.phase", T("相线", "Line"), base.DEC, nil, 0x3F)
f.dl_proxy_qual = ProtoField.uint8 ("gw_2026.dl.proxy_qual", T("代理站点信道质量(dB)", "Proxy Channel Quality (dB)"), base.DEC)
f.dl_proxy_rate = ProtoField.uint8 ("gw_2026.dl.proxy_rate", T("代理站点通信成功率(%)", "Proxy Comm Rate (%)"), base.DEC)
f.dl_proxy_dl_rate = ProtoField.uint8 ("gw_2026.dl.proxy_dl_rate", T("代理站点下行通信成功率(%)", "Proxy Downlink Comm Rate (%)"), base.DEC)
f.dl_sta_cnt = ProtoField.uint16 ("gw_2026.dl.sta_cnt", T("站点总数", "STA Count"), base.DEC)
f.dl_send_cnt = ProtoField.uint8 ("gw_2026.dl.send_cnt", T("发送发现列表报文个数", "Discovery List TX Count"), base.DEC)
f.dl_up_route_cnt = ProtoField.uint8 ("gw_2026.dl.up_route_cnt", T("上行路由条目总数", "Uplink Route Entry Count"), base.DEC)
f.dl_route_remain = ProtoField.uint16 ("gw_2026.dl.route_remain", T("路由周期到期剩余时间(秒)", "Route Period Remaining (s)"), base.DEC)
f.dl_bitmap_size = ProtoField.uint16 ("gw_2026.dl.bitmap_size", T("位图大小(字节)", "Bitmap Size (bytes)"), base.DEC)
f.dl_min_rate = ProtoField.uint8 ("gw_2026.dl.min_rate", T("最小通信成功率(%)", "Min Comm Rate (%)"), base.DEC)
f.dl_next_hop_tei = ProtoField.uint16 ("gw_2026.dl.next_hop_tei", T("下一跳站点TEI", "Next Hop STA TEI"), base.DEC)
f.dl_route_type = ProtoField.uint8 ("gw_2026.dl.route_type", T("路由类型", "Route Type"), base.DEC, route_type_vals, 0xF0)
f.dl_disc_bmp = ProtoField.bytes ("gw_2026.dl.disc_bmp", T("发现站点列表位图", "Discovery STA List Bitmap"), base.NONE)
f.dl_rcv_cnt = ProtoField.uint8 ("gw_2026.dl.rcv_cnt", T("接收发现列表数", "Received Discovery List Count"), base.DEC)
f.dl_rcv_item = ProtoField.string ("gw_2026.dl.rcv_item", T("接收发现列表数(按TEI)", "Received Discovery List Count (by TEI)"))

-- 通信成功率上报 (表100-101)
f.sr_tei = ProtoField.uint16 ("gw_2026.sr.tei", T("TEI", "TEI"), base.DEC)
f.sr_sta_cnt = ProtoField.uint16 ("gw_2026.sr.sta_cnt", T("站点总数", "STA Count"), base.DEC)
f.sr_sta_tei = ProtoField.uint16 ("gw_2026.sr.sta_tei", T("站点TEI", "STA TEI"), base.DEC)
f.sr_down_rate = ProtoField.uint8 ("gw_2026.sr.down_rate", T("下行通信成功率(%)", "Downlink Comm Rate (%)"), base.DEC)
f.sr_up_rate = ProtoField.uint8 ("gw_2026.sr.up_rate", T("上行通信成功率(%)", "Uplink Comm Rate (%)"), base.DEC)

-- 网络冲突上报 (表102-103)
f.ncr_cco_mac = ProtoField.ether ("gw_2026.ncr.cco_mac", T("CCO MAC地址", "CCO MAC Address"))
f.ncr_nbr_cnt = ProtoField.uint8 ("gw_2026.ncr.nbr_cnt", T("邻居网络个数", "Neighbor Network Count"), base.DEC)
f.ncr_nid_width = ProtoField.uint8 ("gw_2026.ncr.nid_width", T("网络号字节宽度", "Network ID Byte Width"), base.DEC)
f.ncr_nbr_nid = ProtoField.uint24 ("gw_2026.ncr.nbr_nid", T("邻居网络号", "Neighbor Network ID"), base.HEX)

-- 过零NTB采集指示 (表104-106)
f.zc_tei = ProtoField.uint16 ("gw_2026.zc.tei", T("TEI", "TEI"), base.DEC)
f.zc_tei_rsv = ProtoField.uint8 ("gw_2026.zc.tei_rsv", T("保留(4bit)", "Reserved (4bit)"), base.HEX)
f.zc_collect_site = ProtoField.uint8 ("gw_2026.zc.collect_site", T("采集站点", "Collect Site"), base.DEC, collect_site_vals)
f.zc_collect_period = ProtoField.uint8 ("gw_2026.zc.collect_period", T("采集周期", "Collect Period"), base.DEC, collect_period_vals)
f.zc_collect_cnt = ProtoField.uint8 ("gw_2026.zc.collect_cnt", T("采集数量", "Collect Count"), base.DEC)

-- 过零NTB上报 (表107-108)
f.zr_tei = ProtoField.uint16 ("gw_2026.zr.tei", T("TEI", "TEI"), base.DEC)
f.zr_tei_rsv = ProtoField.uint8 ("gw_2026.zr.tei_rsv", T("保留(4bit)", "Reserved (4bit)"), base.HEX)
f.zr_total_cnt = ProtoField.uint8 ("gw_2026.zr.total_cnt", T("告知总数量", "Report Total Count"), base.DEC)
f.zr_ph1_cnt = ProtoField.uint8 ("gw_2026.zr.ph1_cnt", T("相线1差值告知数量", "Line 1 Diff Report Count"), base.DEC)
f.zr_ph2_cnt = ProtoField.uint8 ("gw_2026.zr.ph2_cnt", T("相线2差值告知数量", "Line 2 Diff Report Count"), base.DEC)
f.zr_ph3_cnt = ProtoField.uint8 ("gw_2026.zr.ph3_cnt", T("相线3差值告知数量", "Line 3 Diff Report Count"), base.DEC)
f.zr_base_ntb = ProtoField.uint32 ("gw_2026.zr.base_ntb", T("基准NTB", "Base NTB"), base.DEC)
f.zr_ph1_diff = ProtoField.uint16 ("gw_2026.zr.ph1_diff", T("相线1过零NTB差值", "Line 1 Zero-Cross NTB Diff"), base.DEC)
f.zr_ph2_diff = ProtoField.uint16 ("gw_2026.zr.ph2_diff", T("相线2过零NTB差值", "Line 2 Zero-Cross NTB Diff"), base.DEC)
f.zr_ph3_diff = ProtoField.uint16 ("gw_2026.zr.ph3_diff", T("相线3过零NTB差值", "Line 3 Zero-Cross NTB Diff"), base.DEC)

-- 网络诊断 (表109-110)
f.diag_vendor_id = ProtoField.uint16 ("gw_2026.diag.vendor_id", T("芯片厂商ID", "Chip Vendor ID"), base.HEX, chip_vendor_vals)
f.diag_custom = ProtoField.bytes ("gw_2026.diag.custom", T("厂家自定义", "Vendor Custom"), base.NONE)

-- 路由请求 (表111-113)
f.rreq_version = ProtoField.uint8 ("gw_2026.rreq.version", T("版本", "Version"), base.DEC)
f.rreq_seq = ProtoField.uint32 ("gw_2026.rreq.seq", T("路由请求序列号", "Route Request Sequence Number"), base.HEX)
f.rreq_path_pref = ProtoField.bool ("gw_2026.rreq.path_pref", T("路径优选标志", "Path Preference Flag"), 8, nil, 0x10)
f.rreq_payload_type = ProtoField.uint8 ("gw_2026.rreq.payload_type", T("负载数据类型", "Payload Data Type"), base.DEC, payload_type_vals, 0x0F)
f.rreq_payload_len = ProtoField.uint8 ("gw_2026.rreq.payload_len", T("负载数据长度", "Payload Data Length"), base.DEC)

-- 路由回复 (表114-116)
f.rrep_version = ProtoField.uint8 ("gw_2026.rrep.version", T("版本", "Version"), base.DEC)
f.rrep_seq = ProtoField.uint32 ("gw_2026.rrep.seq", T("路由请求序列号", "Route Request Sequence Number"), base.HEX)
f.rrep_payload_type = ProtoField.uint8 ("gw_2026.rrep.payload_type", T("负载数据类型", "Payload Data Type"), base.DEC, payload_type_vals, 0x0F)
f.rrep_payload_len = ProtoField.uint8 ("gw_2026.rrep.payload_len", T("负载数据长度", "Payload Data Length"), base.DEC)

-- 路由错误 (表117)
f.rerr_version = ProtoField.uint8 ("gw_2026.rerr.version", T("版本", "Version"), base.DEC)
f.rerr_seq = ProtoField.uint32 ("gw_2026.rerr.seq", T("路由请求序列号", "Route Request Sequence Number"), base.HEX)
f.rerr_unreach_cnt = ProtoField.uint8 ("gw_2026.rerr.unreach_cnt", T("不可达站点数量", "Unreachable STA Count"), base.DEC)
f.rerr_unreach_tei = ProtoField.uint16 ("gw_2026.rerr.unreach_tei", T("不可达站点TEI", "Unreachable STA TEI"), base.DEC)

-- 路由应答 (表118)
f.rack_version = ProtoField.uint8 ("gw_2026.rack.version", T("版本", "Version"), base.DEC)
f.rack_seq = ProtoField.uint32 ("gw_2026.rack.seq", T("路由请求序列号", "Route Request Sequence Number"), base.HEX)

-- 链路确认请求 (表119)
f.lcreq_version = ProtoField.uint8 ("gw_2026.lcreq.version", T("版本", "Version"), base.DEC)
f.lcreq_seq = ProtoField.uint32 ("gw_2026.lcreq.seq", T("路由请求序列号", "Route Request Sequence Number"), base.HEX)
f.lcreq_sta_cnt = ProtoField.uint8 ("gw_2026.lcreq.sta_cnt", T("确认站点数量", "Confirm STA Count"), base.DEC)
f.lcreq_sta_tei = ProtoField.uint16 ("gw_2026.lcreq.sta_tei", T("确认站点TEI", "Confirm STA TEI"), base.DEC)

-- 链路确认回应 (表120)
f.lcrsp_version = ProtoField.uint8 ("gw_2026.lcrsp.version", T("版本", "Version"), base.DEC)
f.lcrsp_level = ProtoField.uint8 ("gw_2026.lcrsp.level", T("层级", "Level"), base.DEC)
f.lcrsp_chan_qual = ProtoField.uint8 ("gw_2026.lcrsp.chan_qual", T("信道质量", "Channel Quality"), base.DEC)
f.lcrsp_path_pref = ProtoField.bool ("gw_2026.lcrsp.path_pref", T("路径优选标志", "Path Preference Flag"), 8, nil, 0x01)
f.lcrsp_seq = ProtoField.uint32 ("gw_2026.lcrsp.seq", T("路由请求序列号", "Route Request Sequence Number"), base.HEX)

-- 无线信道冲突上报 (表121-122)
f.rfccr_cco_mac = ProtoField.ether ("gw_2026.rfccr.cco_mac", T("CCO MAC地址", "CCO MAC Address"))
-- HDC 2.0 新增 MMe 报文体字段(表104-112)
f.mme_bl_src_tei = ProtoField.uint16 ("gw_2026.mme.bl.src_tei", T("源 TEI", "Source TEI"), base.DEC)
f.mme_bl_dst_tei = ProtoField.uint16 ("gw_2026.mme.bl.dst_tei", T("目的 TEI", "Destination TEI"), base.DEC)
f.mme_bl_param = ProtoField.uint8 ("gw_2026.mme.bl.param", T("子载波分组大小/拒绝原因", "Subcarrier Group Size / Reject Reason"), base.DEC)
f.mme_grp_rsv = ProtoField.bytes ("gw_2026.mme.grp.rsv", T("保留(64bit)", "Reserved (64bit)"), base.NONE)
f.mme_grp_num = ProtoField.uint8 ("gw_2026.mme.grp.num", T("邻居个数(含本站)", "Neighbour Count (incl. self)"), base.DEC)
f.mme_grp_tei = ProtoField.uint16 ("gw_2026.mme.grp.tei", T("邻居 TEI", "Neighbour TEI"), base.DEC)
f.mme_grp_type = ProtoField.uint8 ("gw_2026.mme.grp.type", T("类型", "Type"), base.DEC, {
    [0] = T("组成员", "Group member"), [1] = T("候选组代理", "Candidate group proxy"),
}, nil)
f.mme_grp_qplc = ProtoField.uint8 ("gw_2026.mme.grp.qplc", T("载波信道质量", "PLC Channel Quality"), base.DEC)
f.mme_grp_qrf = ProtoField.uint8 ("gw_2026.mme.grp.qrf", T("无线信道质量", "RF Channel Quality"), base.DEC)
f.mme_gc_proxy_tei = ProtoField.uint32 ("gw_2026.mme.gc.proxy_tei", T("组代理 TEI(24bit)", "Group Proxy TEI (24bit)"), base.DEC)
f.mme_gc_rsv = ProtoField.bytes ("gw_2026.mme.gc.rsv", T("保留(40bit)", "Reserved (40bit)"), base.NONE)
f.mme_gc_num = ProtoField.uint8 ("gw_2026.mme.gc.num", T("组员个数", "Member Count"), base.DEC)
f.mme_gc_tei = ProtoField.uint16 ("gw_2026.mme.gc.tei", T("组员 TEI", "Member TEI"), base.DEC)
f.rfccr_nbr_cnt = ProtoField.uint8 ("gw_2026.rfccr.nbr_cnt", T("邻居网络个数", "Neighbor Network Count"), base.DEC)
f.rfccr_nbr_ch = ProtoField.uint8 ("gw_2026.rfccr.nbr_ch", T("冲突信道号", "Conflict Channel Number"), base.DEC)

-- 无线发现列表 (表123-137)
f.rfdl_sta_mac = ProtoField.ether ("gw_2026.rfdl.sta_mac", T("站点MAC地址", "STA MAC Address"))
f.rfdl_seq = ProtoField.uint8 ("gw_2026.rfdl.seq", T("统计序号", "Statistics Sequence Number"), base.DEC)
f.rfdl_ie_type = ProtoField.uint8 ("gw_2026.rfdl.ie.type", T("信息单元类型", "Information Element Type"), base.DEC, ie_type_vals, 0x7F)
f.rfdl_ie_ltype = ProtoField.uint8 ("gw_2026.rfdl.ie.ltype", T("长度类型", "Length Type"), base.DEC, len_type_vals, 0x80)
f.rfdl_ie_len = ProtoField.uint16 ("gw_2026.rfdl.ie.len", T("信息单元长度", "Information Element Length"), base.DEC)
f.rfdl_ie_data = ProtoField.bytes ("gw_2026.rfdl.ie.data", T("信息单元内容", "Information Element Content"), base.NONE)
-- HDC 2.0 RFDL IE 内容逐字段(表92 站点属性 / 表93 站点路由 / 表94-95 非位图 / 表102-103 位图)
f.rfdl_attr_cco_mac = ProtoField.ether ("gw_2026.rfdl.attr.cco_mac", T("CCO MAC 地址", "CCO MAC Address"))
f.rfdl_attr_proxy_tei = ProtoField.uint16 ("gw_2026.rfdl.attr.proxy_tei", T("代理 TEI", "Proxy TEI"), base.DEC)
f.rfdl_attr_role = ProtoField.uint8 ("gw_2026.rfdl.attr.role", T("角色", "Role"), base.DEC, role_vals, 0xF0)
f.rfdl_attr_level = ProtoField.uint8 ("gw_2026.rfdl.attr.level", T("层级", "Level"), base.DEC, nil, 0x0F)
f.rfdl_attr_rfhop = ProtoField.uint8 ("gw_2026.rfdl.attr.rf_hop", T("链路 RF 跳数", "RF Hop Count"), base.DEC, nil, 0xF0)
f.rfdl_attr_up_rate = ProtoField.uint8 ("gw_2026.rfdl.attr.up_rate", T("代理上行接收率(%)", "Proxy Up Rate (%)"), base.DEC)
f.rfdl_attr_down_rate = ProtoField.uint8 ("gw_2026.rfdl.attr.down_rate", T("代理下行接收率(%)", "Proxy Down Rate (%)"), base.DEC)
f.rfdl_attr_min_rate = ProtoField.uint8 ("gw_2026.rfdl.attr.min_rate", T("链路最小接收率(%)", "Min Link Rate (%)"), base.DEC)
f.rfdl_attr_period = ProtoField.uint8 ("gw_2026.rfdl.attr.period", T("无线发现列表周期(s)", "RFDL Period (s)"), base.DEC)
f.rfdl_attr_aging = ProtoField.uint8 ("gw_2026.rfdl.attr.aging", T("接收率老化周期个数", "Rate Aging Cycles"), base.DEC)
-- 表63 载波发现列表站点属性(23B)
f.rfdl_attr_tei = ProtoField.uint16 ("gw_2026.rfdl.attr.tei", T("发送站点 TEI", "STA TEI"), base.DEC)
f.rfdl_attr_carrier_role = ProtoField.uint8 ("gw_2026.rfdl.attr.carrier_role", T("角色", "Role"), base.DEC, role_vals, 0x0F)
f.rfdl_attr_carrier_level = ProtoField.uint8 ("gw_2026.rfdl.attr.carrier_level", T("层级", "Level"), base.DEC, nil, 0xF0)
f.rfdl_attr_phase = ProtoField.uint8 ("gw_2026.rfdl.attr.phase", T("相线", "Phase"), base.DEC, nil, 0x3F)
f.rfdl_attr_ch_quality = ProtoField.uint8 ("gw_2026.rfdl.attr.ch_quality", T("代理站点信道质量(dB)", "Proxy Channel Quality (dB)"), base.DEC)
f.rfdl_attr_comm_rate = ProtoField.uint8 ("gw_2026.rfdl.attr.comm_rate", T("代理站点通信成功率(%)", "Proxy Comm Rate (%)"), base.DEC)
f.rfdl_attr_down_comm_rate = ProtoField.uint8 ("gw_2026.rfdl.attr.down_comm_rate", T("代理站点下行通信成功率(%)", "Proxy Down Comm Rate (%)"), base.DEC)
f.rfdl_attr_remain_time = ProtoField.uint16 ("gw_2026.rfdl.attr.remain_time", T("路由周期到期剩余时间(s)", "Route Remain Time (s)"), base.DEC)
f.rfdl_attr_min_comm_rate = ProtoField.uint8 ("gw_2026.rfdl.attr.min_comm_rate", T("最小通信成功率(%)", "Min Comm Rate (%)"), base.DEC)
f.rfdl_attr_discover_period = ProtoField.uint8 ("gw_2026.rfdl.attr.discover_period", T("发现列表周期(s)", "Discover Period (s)"), base.DEC)
f.rfdl_attr_brusnr = ProtoField.uint32 ("gw_2026.rfdl.attr.brusnr", T("代理BRUSNR信息", "Proxy BRU SNR"), base.DEC)
f.rfdl_route_tei = ProtoField.uint16 ("gw_2026.rfdl.route.tei", T("下一跳 TEI", "Next-hop TEI"), base.DEC)
f.rfdl_route_type = ProtoField.uint8 ("gw_2026.rfdl.route.type", T("路由类型", "Route Type"), base.DEC, route_type_vals, 0xF0)
f.rfdl_combo = ProtoField.uint8 ("gw_2026.rfdl.combo", T("信道信息组合类型", "Channel Info Combo Type"), base.DEC, nil, 0x0F)
f.rfdl_nbr_tei = ProtoField.uint16 ("gw_2026.rfdl.nbr.tei", T("邻居 TEI", "Neighbor TEI"), base.DEC)
f.rfdl_nbr_rate = ProtoField.uint16 ("gw_2026.rfdl.nbr.rate", T("接收率", "Receive Rate"), base.DEC)
f.rfdl_nbr_snr = ProtoField.uint16 ("gw_2026.rfdl.nbr.snr", T("平均信噪比", "Average SNR"), base.DEC)
f.rfdl_nbr_rssi = ProtoField.uint16 ("gw_2026.rfdl.nbr.rssi", T("信号强度", "Signal Strength"), base.DEC)
f.rfdl_nbr_brusnr = ProtoField.uint32 ("gw_2026.rfdl.nbr.brusnr", T("BRU SNR(32bit,8×4bit)", "BRU SNR (32bit, 8×4bit)"), base.HEX)
f.rfdl_grp_tei = ProtoField.uint16 ("gw_2026.rfdl.grp.tei", T("位图起始 TEI", "Bitmap Start TEI"), base.DEC)
f.rfdl_grp_size = ProtoField.uint8 ("gw_2026.rfdl.grp.size", T("位图大小(B)", "Bitmap Size (bytes)"), base.DEC)
f.rfdl_grp_bitmap = ProtoField.bytes ("gw_2026.rfdl.grp.bitmap", T("位图", "Bitmap"), base.NONE)
-- HDC 2.0 信道评估参数更新报文(表106-108, 单跳帧消息类型1)
f.ce_bru_valid = ProtoField.uint8 ("gw_2026.ce.bru_valid", T("BRUSNR 有效标志", "BRUSNR Valid Flag"), base.DEC, nil, 0x01)
f.ce_sat_len = ProtoField.uint8 ("gw_2026.ce.sat_len", T("SAT 配置长度", "SAT Config Length"), base.DEC, nil, 0xFE)
f.ce_bru_snr = ProtoField.uint32 ("gw_2026.ce.bru_snr", T("BRU SNR 信息表(32bit)", "BRU SNR Table (32bit)"), base.HEX)
f.ce_sat_id = ProtoField.uint8 ("gw_2026.ce.sat_id", T("SAT ID", "SAT ID"), base.DEC, nil, 0x01)
f.ce_sat_mode = ProtoField.uint8 ("gw_2026.ce.sat_mode", T("SAT 模式", "SAT Mode"), base.DEC, {
    [0] = T("子载波选择表", "Subcarrier Select Table"), [1] = T("比特加载表", "Bit Loading Table"),
}, 0x02)
f.ce_grp_size = ProtoField.uint8 ("gw_2026.ce.grp_size", T("单子载波组大小", "Subcarrier Group Size"), base.DEC, nil, 0x0C)
f.ce_tmi = ProtoField.uint8 ("gw_2026.ce.tmi", T("TMI", "TMI"), base.DEC, nil, 0x0F)
f.ce_gain = ProtoField.uint8 ("gw_2026.ce.gain", T("数据载荷增益", "Data Payload Gain"), base.DEC, nil, 0xF0)
f.ce_table = ProtoField.bytes ("gw_2026.ce.table", T("SAT 表", "SAT Table"), base.NONE)

-- 应用层报文 APP_BASE (msdu_type=48, 表 报文ID)
f.app_port = ProtoField.uint8 ("gw_2026.app.port", T("端口号", "Port Number"), base.HEX, app_port_vals)
f.app_packet_id = ProtoField.uint16 ("gw_2026.app.packet_id", T("报文ID", "Packet ID"), base.HEX, app_packet_id_vals)
f.app_ctrl_word = ProtoField.uint8 ("gw_2026.app.ctrl_word", T("报文控制字", "Packet Control Word"), base.HEX)
f.app_payload = ProtoField.bytes ("gw_2026.app.payload", T("应用层载荷(Payload)", "Application Payload"), base.NONE)

-- 位图逐字节解析节点 (string, 承载 "值 (TEI列表)" 文本)
f.bmp_byte = ProtoField.string ("gw_2026.bmp.byte", T("位图字节", "Bitmap Byte"))

gw.fields = {
    f.fc_dt, f.fc_net_type, f.fc_nid, f.fc_nid_rsv, f.fc_vf, f.fc_std_ver, f.fc_fccs,
    f.fc_fccs_calc, f.fc_fccs_ok,
    f.pb_seq, f.pb_sof, f.pb_eof, f.pb_pbcs, f.pb_size, f.pb_crc_ok, f.pb_crc_calc,
    f.pb_body, f.pb_padding,
    f.beacon_bts, f.beacon_bts_sec, f.beacon_src_tei, f.beacon_div_mode,
    f.beacon_symbol_cnt, f.beacon_phase, f.beacon_type, f.beacon_net_cplt,
    f.beacon_rf_option, f.beacon_mech_state, f.beacon_disc_en, f.beacon_rsv13,
    f.beacon_cal_sec, f.beacon_cal_ntb, f.beacon_ca_active, f.beacon_ca_passive,
    f.beacon_ca_period, f.beacon_sw_target, f.beacon_sw_ntb, f.beacon_proxy_cnt, f.beacon_proxy_tei,
    f.beacon_simple, f.beacon_start_assoc, f.beacon_use_flag, f.beacon_net_seq,
    f.beacon_cco_mac, f.beacon_bpc, f.beacon_rf_ch, f.beacon_entry_cnt, f.beacon_bpcs,
    f.beacon_bpcs_calc, f.beacon_bpcs_ok,
    f.beacon_ent_type, f.beacon_ent_len, f.beacon_ent_data,
    f.ent_tei, f.ent_proxy_tei, f.ent_path_rate, f.ent_sta_mac, f.ent_role,
    f.ent_level, f.ent_proxy_qual, f.ent_phase, f.ent_rf_hop,
    f.ent_route_period, f.ent_route_remain, f.ent_proxy_dl_period, f.ent_disc_dl_period,
    f.ent_target_band, f.ent_band_remain,
    f.ent_nc_beacon_cnt, f.ent_c_beacon_cnt, f.ent_csma_phase_cnt,
    f.ent_proxy_beacon_cnt, f.ent_beacon_slot_len, f.ent_csma_slice_len,
    f.ent_bcsma_phase_cnt, f.ent_bcsma_lid, f.ent_tdma_slot_len, f.ent_tdma_lid,
    f.ent_bp_start_ntb, f.ent_bp_len, f.ent_rf_beacon_len,
    f.ent_ncb_tei, f.ent_ncb_type, f.ent_ncb_rf_flag,
    f.ent_csma_len, f.ent_csma_phase, f.ent_bcsma_len, f.ent_bcsma_phase,
    f.ent_rf_dl_period, f.ent_rf_age_cnt, f.ent_target_ch, f.ent_ch_remain,
    f.ent_sb_csma_start, f.ent_sb_csma_len,
    f.sof_src_tei, f.sof_dst_tei, f.sof_lid, f.sof_frame_len, f.sof_pb_count,
    f.sof_symbol_cnt, f.sof_bcast, f.sof_retrans, f.sof_encrypt,
    f.sof_div_mode, f.sof_div_ext, f.sof_pb_size, f.sof_mcs, f.sof_rsv, f.sof_rsv4,
    f.sof_frame_type, f.sof_tf_sym_pos, f.sof_tf_sym_num, f.sof_fl, f.sof_fl_rsv,
    f.sof_fch_sym_num, f.sof_mod_mode, f.sof_mod_param, f.sof_pb_code,
    f.sof_band, f.sof_gain, f.sof_load_table_id,
    f.sack_bru, f.sack_satid, f.sack_rx_res, f.sack_rx_pb_num, f.sack_rx_status,
    f.sof_subc_group, f.sof_train_band, f.sof_train_sym, f.sof_ext_dst,
    f.sof_sta_num, f.sof_pay_sym, f.sof_efc_sym, f.sof_st0_pbn, f.sof_st0_div,
    f.sof_st0_ru, f.sof_enc_tda, f.sof_st0_band, f.sof_st0_tf, f.sof_rsv_b12,
    f.efc1_st_tei, f.efc1_st_ru, f.efc1_st_div, f.efc1_st_pbn, f.efc1_st_rsv,
    f.efd_st_tei, f.efd_st_sym, f.efd_st_band, f.efd_st_div, f.efd_st_rsv,
    f.sack15_pbn, f.sack15_status, f.sack15_src, f.sack15_dst, f.sack15_bru,
    f.sack_remain_sta, f.sack_rsv0, f.sack_rsv1,
    f.mac_aggregate, f.mac_send_seq, f.mac_link_id,
    f.beacon_mcs, f.beacon_pbcode, f.beacon_rsv1, f.beacon_rsv_b11, f.beacon_vf_rsv2,
    f.sack_recv_result, f.sack_recv_status, f.sack_src_tei, f.sack_dst_tei,
    f.sack_pb_count, f.sack_chan_qual, f.sack_site_load, f.sack_ext_type,
    f.coord_duration, f.coord_bw_offset, f.coord_nbr_nid, f.coord_rf_ch,
    f.mac_version, f.mac_ostei, f.mac_odtei, f.mac_send_type,
    f.mac_retry_limit, f.mac_rsv0, f.mac_msdu_seq, f.mac_msdu_type, f.mac_msdu_len,
    f.mac_restart_cnt, f.mac_proxy_main, f.mac_route_total, f.mac_route_left,
    f.mac_bcast_dir, f.mac_path_repair, f.mac_addr_flag, f.mac_rsv1, f.mac_rsv2, f.mac_net_seq,
    f.mac_rsv3, f.mac_rsv4, f.mac_osmac, f.mac_odmac, f.mac_icv,
    f.mac_icv_calc, f.mac_icv_ok,
    f.media_phr_mcs, f.media_option, f.media_channel, f.media_is_rf,
    f.col_orig_dst, f.col_orig_src,
    f.rsvd, f.beacon_vf_rsv, f.sack_rsv, f.coord_rsv,
    f.sh_version, f.sh_msgtype, f.sh_msdulen,
    f.sh_aggregate, f.sh_rsv1, f.sh_msdu_crc, f.sh_msdu_crc_ok,
    f.mgmt_mmtype, f.mgmt_resv,
    f.mme_bl_src_tei, f.mme_bl_dst_tei, f.mme_bl_param,
    f.mme_grp_rsv, f.mme_grp_num, f.mme_grp_tei, f.mme_grp_type, f.mme_grp_qplc, f.mme_grp_qrf,
    f.mme_gc_proxy_tei, f.mme_gc_rsv, f.mme_gc_num, f.mme_gc_tei,
    f.ar_sta_mac, f.ar_proxy_tei, f.ar_link_type, f.ar_phase, f.ar_dev_type,
    f.ar_mac_type, f.ar_module, f.ar_assoc_rand, f.ar_vendor,
    f.ar_boot_reason, f.ar_boot_ver, f.ar_soft_ver, f.ar_ver_time,
    f.ar_vendor_code, f.ar_chip_code, f.ar_hard_rst, f.ar_soft_rst,
    f.ar_proxy_type, f.ar_e2e_seq, f.ar_mgmt_id,
    f.ac_sta_mac, f.ac_cco_mac, f.ac_result, f.ac_sta_level, f.ac_sta_tei,
    f.ac_link_type, f.ac_carrier_band, f.ac_proxy_tei, f.ac_total_pkgs,
    f.ac_pkg_idx, f.ac_assoc_rand, f.ac_reassoc_time, f.ac_e2e_seq,
    f.ac_path_seq, f.ac_direct_sta, f.ac_direct_proxy, f.ac_route_size,
    f.ag_result, f.ag_sta_level, f.ag_cco_mac, f.ag_proxy_tei,
    f.ag_carrier_band, f.ag_gather_cnt, f.ag_sta_mac, f.ag_sta_tei,
    f.cpr_sta_tei, f.cpr_new_proxy, f.cpr_link_type, f.cpr_old_proxy,
    f.cpr_proxy_type, f.cpr_reason, f.cpr_e2e_seq, f.cpr_phase,
    f.cpc_result, f.cpc_total_pkgs, f.cpc_pkg_idx, f.cpc_sta_tei,
    f.cpc_link_type, f.cpc_proxy_tei, f.cpc_e2e_seq, f.cpc_path_seq,
    f.cpc_child_cnt, f.cpc_child_tei,
    f.cpb_result, f.cpb_bitmap_size, f.cpb_sta_tei, f.cpb_link_type,
    f.cpb_proxy_tei, f.cpb_e2e_seq, f.cpb_path_seq, f.cpb_child_bmp,
    f.li_reason, f.li_sta_cnt, f.li_delay, f.li_sta_mac,
    f.hb_ostei, f.hb_max_disc_tei, f.hb_max_disc_cnt, f.hb_bitmap_size, f.hb_disc_bmp,
    f.dl_tei, f.dl_proxy_tei, f.dl_role, f.dl_level, f.dl_mac, f.dl_cco_mac,
    f.dl_phase, f.dl_proxy_qual, f.dl_proxy_rate, f.dl_proxy_dl_rate,
    f.dl_sta_cnt, f.dl_send_cnt, f.dl_up_route_cnt, f.dl_route_remain,
    f.dl_bitmap_size, f.dl_min_rate, f.dl_next_hop_tei, f.dl_route_type, f.dl_disc_bmp,
    f.dl_rcv_cnt, f.dl_rcv_item,
    f.sr_tei, f.sr_sta_cnt, f.sr_sta_tei, f.sr_down_rate, f.sr_up_rate,
    f.ncr_cco_mac, f.ncr_nbr_cnt, f.ncr_nid_width, f.ncr_nbr_nid,
    f.zc_tei, f.zc_tei_rsv, f.zc_collect_site, f.zc_collect_period, f.zc_collect_cnt,
    f.zr_tei, f.zr_tei_rsv, f.zr_total_cnt, f.zr_ph1_cnt, f.zr_ph2_cnt, f.zr_ph3_cnt,
    f.zr_base_ntb, f.zr_ph1_diff, f.zr_ph2_diff, f.zr_ph3_diff,
    f.diag_vendor_id, f.diag_custom,
    f.rreq_version, f.rreq_seq, f.rreq_path_pref, f.rreq_payload_type, f.rreq_payload_len,
    f.rrep_version, f.rrep_seq, f.rrep_payload_type, f.rrep_payload_len,
    f.rerr_version, f.rerr_seq, f.rerr_unreach_cnt, f.rerr_unreach_tei,
    f.rack_version, f.rack_seq,
    f.lcreq_version, f.lcreq_seq, f.lcreq_sta_cnt, f.lcreq_sta_tei,
    f.lcrsp_version, f.lcrsp_level, f.lcrsp_chan_qual, f.lcrsp_path_pref, f.lcrsp_seq,
    f.rfccr_cco_mac, f.rfccr_nbr_cnt, f.rfccr_nbr_ch,
    f.rfdl_sta_mac, f.rfdl_seq, f.rfdl_ie_type, f.rfdl_ie_ltype,
    f.rfdl_ie_len, f.rfdl_ie_data,
    f.rfdl_attr_cco_mac, f.rfdl_attr_proxy_tei, f.rfdl_attr_role, f.rfdl_attr_level,
    f.rfdl_attr_rfhop, f.rfdl_attr_up_rate, f.rfdl_attr_down_rate, f.rfdl_attr_min_rate,
    f.rfdl_attr_period, f.rfdl_attr_aging, f.rfdl_route_tei, f.rfdl_route_type,
    f.rfdl_attr_tei, f.rfdl_attr_carrier_role, f.rfdl_attr_carrier_level, f.rfdl_attr_phase,
    f.rfdl_attr_ch_quality, f.rfdl_attr_comm_rate, f.rfdl_attr_down_comm_rate,
    f.rfdl_attr_remain_time, f.rfdl_attr_min_comm_rate, f.rfdl_attr_discover_period,
    f.rfdl_attr_brusnr,
    f.rfdl_combo, f.rfdl_nbr_tei, f.rfdl_nbr_rate, f.rfdl_nbr_snr, f.rfdl_nbr_rssi,
    f.rfdl_nbr_brusnr, f.rfdl_grp_tei, f.rfdl_grp_size, f.rfdl_grp_bitmap,
    f.ce_bru_valid, f.ce_sat_len, f.ce_bru_snr, f.ce_sat_id, f.ce_sat_mode,
    f.ce_grp_size, f.ce_tmi, f.ce_gain, f.ce_table,
    f.app_port, f.app_packet_id, f.app_ctrl_word, f.app_payload,
    f.bmp_byte,
}

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
    local body = pbsz - 4  -- GW_2022: PB头1B + 体 + CRC24 3B          -- 块体长
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
    s.len = function() return v:len() - delta end
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


-- 位图逐字节解析: bit 全局索引 = TEI (字节i的bit j → TEI = i*8+j)
-- 每字节输出 "值 (TEI列表)", 如 "2 (TEI1)" / "0x83 (TEI0,TEI1,TEI7)"
-- 顶层节点用 bytes 字段 field (显示原始 hex), 逐字节子节点用 string
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
-- 段解析函数
-- =========================================================================

-- TMI → PB 块大小 (字节)。与 Qt beacon_pb_size 一致 (51242 物理块大小表)
-- TMI 即 FCH 字节9 高4bit 的"分集拷贝基本模式"
local function beacon_pb_size(tmi)
    if tmi == 0 or tmi == 1 then return 520 end
    if tmi >= 2 and tmi <= 6 then return 136 end
    if tmi >= 7 and tmi <= 10 then return 520 end
    if tmi == 11 or tmi == 12 then return 264 end
    if tmi == 13 or tmi == 14 then return 72 end
    return -1
end

-- SOF PB 块大小: TMI 主表 + TMI_EXT 扩展 (HDC 2.0 分集拷贝模式;与 sofparser 一致)
local function sof_pb_size(tmi, tmi_ext)
    local s = beacon_pb_size(tmi)
    if s > 0 then return s end
    if tmi_ext >= 1 and tmi_ext <= 6 then return 520 end
    if tmi_ext >= 10 and tmi_ext <= 14 then return 136 end
    return -1
end

-- 动态加载模式: 调制参数 = 物理块类型编号(表8: 0-3 = 72/136/264/520 B)
local function sof_dynamic_pb_size(ptype)
    local t = { [0]=72, [1]=136, [2]=264, [3]=520 }
    return t[ptype] or -1
end

-- PB 个数 2b 编码 → 块数 (表7: 0-3 = 1-4 块)
local function sof_pb_num_decode(code)
    return code + 1
end

-- 信标帧可变区域 (表17 载波, 起始于 FCH 字节4)
local function dissect_beacon_vf(tvb, tree, is_rf)
    local bts_raw = tvb(4, 4):le_uint()
    tree:add(f.beacon_bts, tvb(4, 4), bts_raw)
    -- NTB: 25MHz时钟, 40ns/tick, 换算秒 = NTB / 25e6
    tree:add(f.beacon_bts_sec, tvb(4, 4), bts_raw / 25000000.0)
    add_val(tree, f.beacon_src_tei, tvb, 8, 2, read_bits(tvb, 8*8, 12))
    if is_rf then
        -- 无线信标(表27): MCS(9,4,4) + 载荷PB大小(10,0,4) + 保留(10,4,4)/(11,0,8)/(12,0,4)
        tree:add(f.beacon_mcs, tvb(9, 1))
        tree:add(f.beacon_pbcode, tvb(10, 1))
        tree:add(f.beacon_rsv1, tvb(10, 1))
        tree:add(f.beacon_rsv_b11, tvb(11, 1))
        tree:add(f.beacon_vf_rsv2, tvb(12, 1))
    else
        -- 载波信标(表17): 分集拷贝基本模式(9,4,4) + 符号数(10,0,9) + 相线(11,1,2) + 保留(11,3,9)
        tree:add(f.beacon_div_mode, tvb(9, 1))
        add_val(tree, f.beacon_symbol_cnt, tvb, 10, 2, read_bits(tvb, 10*8, 9))
        tree:add(f.beacon_phase, tvb(11, 1))
        tree:add(f.beacon_vf_rsv, tvb(11, 1))       -- 字节11 bit3-7 保留
        tree:add(f.beacon_vf_rsv2, tvb(12, 1))      -- 字节12 bit0-3 保留
    end
end

-- SOF 帧可变区域 (起始于 FCH 字节4; HDC 2.0 载波 表7(数据帧,帧子类型 分派 表9-13) / 无线 表21)
local sof_frame_type_vals = { [0]="Data", [1]="ChannelProbe", [2]="OFDMA-DL", [3]="TDA-DL" }
local function dissect_sof_vf(tvb, tree, is_rf)
    add_val(tree, f.sof_src_tei, tvb, 4, 2, read_bits(tvb, 4*8, 12))
    add_val(tree, f.sof_dst_tei, tvb, 5, 2, read_bits(tvb, 5*8+4, 12))
    if is_rf then
        -- 无线 SOF(表21,布局同 1.0 表30): 载荷PB大小(9,4,4) + 保留(10,0,9) + 标志(11 低4b) + MCS(11,4,4)
        tree:add(f.sof_pb_size, tvb(9, 1))
        add_val(tree, f.sof_rsv, tvb, 10, 2, read_bits(tvb, 10*8, 9))
        tree:add(f.sof_bcast, tvb(11, 1))
        tree:add(f.sof_retrans, tvb(11, 1))
        tree:add(f.sof_encrypt, tvb(11, 1))
        tree:add(f.sof_mcs, tvb(11, 1))
        tree:add(f.sof_rsv4, tvb(12, 1))
    else
        -- 载波: 帧子类型专属布局(表7 数据帧 / 表9 信道探测 / 表10-11 OFDMA / 表12-13 TDA)
        local ftype = read_bits(tvb, 7*8, 3)
        tree:add(f.sof_frame_type, tvb(7, 1))
        add_val(tree, f.sof_fl, tvb, 8, 2, read_bits(tvb, 8*8, 12))
        if ftype == 1 then
            -- 信道探测帧(表9): 子载波分组(7,3-4,0=4个/1=6个一组)/TF符号数(7,5-7)/
            -- FCH符号数(9,4-5)——注意与表7 (9,7)+(10,0) 位置不同/训练序列频段标识(9,6-7+10,0)/
            -- 训练序列符号数(10,1-7,(v+1)*2)/扩展目的TEI(11,0,12)
            tree:add(f.sof_subc_group, tvb(7, 1))
            tree:add(f.sof_tf_sym_num, tvb(7, 1))
            add_val(tree, f.sof_fch_sym_num, tvb, 9, 1, read_bits(tvb, 9*8+4, 2))
            add_val(tree, f.sof_train_band, tvb, 9, 1, read_bits(tvb, 9*8+6, 3))
            add_val(tree, f.sof_train_sym, tvb, 10, 1, read_bits(tvb, 10*8+1, 7))
            add_val(tree, f.sof_ext_dst, tvb, 11, 2, read_bits(tvb, 11*8, 12))
        elseif ftype == 2 or ftype == 3 then
            -- OFDMA 下行(表10-11)/TDA 下行(表12-13)
            tree:add(f.sof_sta_num, tvb(7, 1))
            tree:add(f.sof_tf_sym_num, tvb(7, 1))
            add_val(tree, f.sof_fch_sym_num, tvb, 9, 1, read_bits(tvb, 9*8+4, 2))
            add_val(tree, f.sof_pay_sym, tvb, 9, 2, read_bits(tvb, 9*8+6, 9))
            tree:add(f.sof_efc_sym, tvb(10, 1))
            if ftype == 3 then
                tree:add(f.sof_enc_tda, tvb(11, 1))    -- 加密标志位(11,2,预留)
            else
                add_val(tree, f.sof_st0_pbn, tvb, 11, 1, read_bits(tvb, 11*8+2, 1))
            end
            add_val(tree, f.sof_st0_div, tvb, 11, 1, read_bits(tvb, 11*8+3, 5))
            if ftype == 3 then
                add_val(tree, f.sof_st0_band, tvb, 12, 1, read_bits(tvb, 12*8, 3))
                tree:add(f.sof_st0_tf, tvb(12, 1))
            else
                add_val(tree, f.sof_st0_ru, tvb, 12, 1, read_bits(tvb, 12*8, 4))
            end
            tree:add(f.sof_rsv_b12, tvb(12, 1))
            -- eFC(自 byte16): 表11 OFDMA 每站 3B×[TEI/RU/分集/PB个数/RSV] /
            -- 表13 TDA 每站 4B×[TEI/符号数9b/频段/分集/RSV], 站点数决定条数
            -- eFC 固定 16 字节(表11/13 内部字节号 0-15) ⇒ PB 自 byte32 起
            local sn = read_bits(tvb, 7*8+3, 2)
            if tvb:len() < 32 then
                -- eFC 截断(帧长 < 32B): 不读 byte16 之后的站点字段(与 Qt 解析器同口径)
                if sn >= 1 then
                    tree:add_expert_info(PI_MALFORMED, PI_WARN,
                        T("OFDMA/TDA eFC 截断(帧长 < 32B)", "OFDMA/TDA eFC Truncated (Frame Length < 32B)"))
                end
            elseif ftype == 2 then
                for s = 1, sn do
                    local b = 16 + (s - 1) * 3
                    add_val(tree, f.efc1_st_tei, tvb, b, 2, read_bits(tvb, b*8, 12))
                    add_val(tree, f.efc1_st_ru, tvb, b + 1, 1, read_bits(tvb, b*8+12, 4))
                    add_val(tree, f.efc1_st_div, tvb, b + 2, 1, read_bits(tvb, b*8+16, 5))
                    add_val(tree, f.efc1_st_pbn, tvb, b + 2, 1, read_bits(tvb, b*8+21, 1))
                    add_val(tree, f.efc1_st_rsv, tvb, b + 2, 1, read_bits(tvb, b*8+22, 2))
                end
            else
                for s = 1, sn do
                    local b = 16 + (s - 1) * 4
                    add_val(tree, f.efd_st_tei, tvb, b, 2, read_bits(tvb, b*8, 12))
                    add_val(tree, f.efd_st_sym, tvb, b + 1, 2, read_bits(tvb, b*8+12, 9))
                    add_val(tree, f.efd_st_band, tvb, b + 2, 1, read_bits(tvb, b*8+21, 3))
                    add_val(tree, f.efd_st_div, tvb, b + 3, 1, read_bits(tvb, b*8+24, 5))
                    add_val(tree, f.efd_st_rsv, tvb, b + 3, 1, read_bits(tvb, b*8+29, 3))
                end
            end
        else
            -- 数据帧(表7)/保留: 帧子类型 bit 沿用表7 布局
            tree:add(f.sof_tf_sym_pos, tvb(7, 1))
            tree:add(f.sof_tf_sym_num, tvb(7, 1))
            tree:add(f.sof_fl_rsv, tvb(9, 1))
            local fch_sym = band(read_bits(tvb, 9*8+7, 1), 0x01)
            fch_sym = fch_sym + band(read_bits(tvb, 10*8, 1), 0x01) * 2
            add_val(tree, f.sof_fch_sym_num, tvb, 10, 1, fch_sym)
            tree:add(f.sof_mod_mode, tvb(10, 1))
            tree:add(f.sof_mod_param, tvb(10, 1))
            local pb_code = band(read_bits(tvb, 10*8+7, 1), 0x01)
            pb_code = pb_code + band(read_bits(tvb, 11*8, 1), 0x01) * 2
            add_val(tree, f.sof_pb_code, tvb, 11, 1, pb_code)
            tree:add(f.sof_bcast, tvb(11, 1))      -- byte11 bit1
            tree:add(f.sof_encrypt, tvb(11, 1))    -- byte11 bit2
            tree:add(f.sof_retrans, tvb(11, 1))    -- byte11 bit3
            tree:add(f.sof_band, tvb(11, 1))
            local gain = band(read_bits(tvb, 11*8+7, 1), 0x01)
            gain = gain + band(read_bits(tvb, 12*8, 3), 0x07) * 2
            add_val(tree, f.sof_gain, tvb, 12, 1, gain)
            tree:add(f.sof_load_table_id, tvb(12, 1))
        end
    end
end

-- SACK 帧可变区域 (HDC 2.0: BRU SNR 反馈标志=1 → 表15 反馈SNR版; =0 → 表14 不反馈版)
local function dissect_sack_vf(tvb, tree)
    tree:add(f.sack_bru, tvb(4, 1))              -- (4,0,1)
    tree:add(f.sack_satid, tvb(4, 1))            -- (4,1,1)
    local bru_flag = read_bits(tvb, 4*8, 1)
    if bru_flag == 1 then
        -- 表15(反馈SNR版): 接收物理块个数(4,2-3)/接收状态(4,4-7)/
        --   源TEI(5,0,12)/目的TEI(6,4,12)/BRU0-7 SNR(8-11,8×4b)
        add_val(tree, f.sack15_pbn, tvb, 4, 1, read_bits(tvb, 4*8+2, 2))
        add_val(tree, f.sack15_status, tvb, 4, 1, read_bits(tvb, 4*8+4, 4))
        add_val(tree, f.sack15_src, tvb, 5, 2, read_bits(tvb, 5*8, 12))
        add_val(tree, f.sack15_dst, tvb, 6, 2, read_bits(tvb, 6*8+4, 12))
        -- 档位: 0=无效值; v≥1 → SNR∈[-10+3(v-1), -7+3(v-1)]dB(以表15 行内定义为准,
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
            tree:add(f.sack15_bru, tvb(8 + math.floor(i / 2), 1), desc)
        end
        return
    end
    tree:add(f.sack_rx_res, tvb(4, 1))           -- (4,2,1)
    tree:add(f.sack_rx_pb_num, tvb(4, 1))        -- (4,3,2)
    -- RxStatus 4bit 跨字节: (4,5,3)|(5,0,1)<<3
    local rx_status = band(read_bits(tvb, 4*8+5, 3), 0x07)
    rx_status = rx_status + band(read_bits(tvb, 5*8, 1), 0x01) * 8
    add_val(tree, f.sack_rx_status, tvb, 5, 1, rx_status)
    add_val(tree, f.sack_src_tei, tvb, 5, 2, read_bits(tvb, 5*8+1, 12))   -- (5,1,12)
    add_val(tree, f.sack_dst_tei, tvb, 6, 2, read_bits(tvb, 6*8+5, 12))   -- (6,5,12)
    add_val(tree, f.sack_remain_sta, tvb, 8, 1, read_bits(tvb, 8*8+1, 2)) -- (8,1,2)
    tree:add(f.sack_rsv0, tvb(8, 1))             -- (8,3,5)
    add_val(tree, f.sack_chan_qual, tvb, 9, 1, read_bits(tvb, 9*8+1, 8))  -- (9,1,8)
    add_val(tree, f.sack_site_load, tvb, 10, 1, read_bits(tvb, 10*8+1, 8)) -- (10,1,8)
    tree:add(f.sack_rsv1, tvb(11, 1))            -- (11,1,8)
    tree:add(f.sack_ext_type, tvb(12, 1))        -- (12,1,4)
end

-- 网间协调帧可变区域 (表26, 起始于 FCH 字节4)
local function dissect_coord_vf(tvb, tree)
    add_le(tree, f.coord_duration, tvb, 4, 2)
    add_le(tree, f.coord_bw_offset, tvb, 6, 2)
    tree:add(f.coord_nbr_nid, tvb(8, 3), tvb(8, 3):le_uint())
    tree:add(f.coord_rf_ch, tvb(11, 1))
    tree:add(f.coord_rsv, tvb(12, 1))     -- 字节12 bit0-3 保留
end

-- 站点能力条目 (表47)
local function dissect_entry_sta_cap(tvb, tree, off)
    local tei = read_bits(tvb, off*8, 12)
    add_val(tree, f.ent_tei, tvb, off, 2, tei)
    add_val(tree, f.ent_proxy_tei, tvb, off+1, 2, read_bits(tvb, off*8+12, 12))
    tree:add(f.ent_path_rate, tvb(off+3, 1))
    tree:add(f.ent_sta_mac, tvb(off+4, 6))
    -- 记录 TEI ↔ MAC 映射
    record_tei_mac(tei, mac_to_str(tvb, off+4))
    tree:add(f.ent_role, tvb(off+10, 1))
    tree:add(f.ent_level, tvb(off+10, 1))
    tree:add(f.ent_proxy_qual, tvb(off+11, 1))
    tree:add(f.ent_phase, tvb(off+12, 1))
    tree:add(f.ent_rf_hop, tvb(off+12, 1))
end

-- 路由参数条目 (表48)
local function dissect_entry_route_param(tvb, tree, off)
    add_le(tree, f.ent_route_period, tvb, off, 2)
    add_le(tree, f.ent_route_remain, tvb, off+2, 2)
    add_le(tree, f.ent_proxy_dl_period, tvb, off+4, 2)
    add_le(tree, f.ent_disc_dl_period, tvb, off+6, 2)
end

-- 频段变更条目 (表49)
local function dissect_entry_band_change(tvb, tree, off)
    tree:add(f.ent_target_band, tvb(off, 1))
    add_le(tree, f.ent_band_remain, tvb, off+1, 4)
end

-- 时隙分配条目 (表50)
local function dissect_entry_slot_alloc(tvb, tree, off)
    local nc_beacon_cnt = tvb(off, 1):uint()
    local csma_phase_cnt = band(tvb(off+1, 1):uint(), 0x30) / 16  -- bit4-5 → 1-3
    local bcsma_phase_cnt = tvb(off+6, 1):uint()
    tree:add(f.ent_nc_beacon_cnt, tvb(off, 1))
    tree:add(f.ent_c_beacon_cnt, tvb(off+1, 1))
    tree:add(f.ent_csma_phase_cnt, tvb(off+1, 1))
    tree:add(f.ent_proxy_beacon_cnt, tvb(off+3, 1))
    tree:add(f.ent_beacon_slot_len, tvb(off+4, 1))
    tree:add(f.ent_csma_slice_len, tvb(off+5, 1))
    tree:add(f.ent_bcsma_phase_cnt, tvb(off+6, 1))
    tree:add(f.ent_bcsma_lid, tvb(off+7, 1))
    tree:add(f.ent_tdma_slot_len, tvb(off+8, 1))
    tree:add(f.ent_tdma_lid, tvb(off+9, 1))
    add_le(tree, f.ent_bp_start_ntb, tvb, off+10, 4)
    add_le(tree, f.ent_bp_len, tvb, off+14, 4)
    add_val(tree, f.ent_rf_beacon_len, tvb, off+18, 2, read_bits(tvb, (off+18)*8, 10))
    -- 非中央信标信息: 每条 2 字节 (表51: TEI 12b + 信标类型1b + RF标志3b)
    local pos = off + 20
    for i = 1, nc_beacon_cnt do
        add_val(tree, f.ent_ncb_tei, tvb, pos, 2, read_bits(tvb, pos*8, 12))
        tree:add(f.ent_ncb_type, tvb(pos+1, 1))
        tree:add(f.ent_ncb_rf_flag, tvb(pos+1, 1))
        pos = pos + 2
    end
    -- CSMA时隙信息: 每条 4 字节
    for i = 1, csma_phase_cnt do
        tree:add(f.ent_csma_len, tvb(pos, 3), tvb(pos, 3):le_uint())
        tree:add(f.ent_csma_phase, tvb(pos+3, 1))
        pos = pos + 4
    end
    -- 绑定CSMA时隙信息: 每条 4 字节
    for i = 1, bcsma_phase_cnt do
        tree:add(f.ent_bcsma_len, tvb(pos, 3), tvb(pos, 3):le_uint())
        tree:add(f.ent_bcsma_phase, tvb(pos+3, 1))
        pos = pos + 4
    end
end

-- 无线路由参数条目 (表54)
local function dissect_entry_rf_route(tvb, tree, off)
    tree:add(f.ent_rf_dl_period, tvb(off, 1))
    tree:add(f.ent_rf_age_cnt, tvb(off+1, 1))
end

-- 无线信道变更条目 (表55)
local function dissect_entry_rf_ch(tvb, tree, off)
    tree:add(f.ent_target_ch, tvb(off, 1))
    add_le(tree, f.ent_ch_remain, tvb, off+1, 4)
end

-- 精简信标站点信息及时隙条目 (表57)
local function dissect_entry_simple_beacon(tvb, tree, off)
    add_val(tree, f.ent_tei, tvb, off, 2, read_bits(tvb, off*8, 12))
    add_val(tree, f.ent_proxy_tei, tvb, off+1, 2, read_bits(tvb, off*8+12, 12))
    tree:add(f.ent_role, tvb(off+3, 1))
    tree:add(f.ent_level, tvb(off+3, 1))
    tree:add(f.ent_sta_mac, tvb(off+4, 6))
    tree:add(f.ent_rf_hop, tvb(off+10, 1))
    add_le(tree, f.ent_sb_csma_start, tvb, off+11, 4)
    add_le(tree, f.ent_sb_csma_len, tvb, off+15, 2)
end

-- 信标管理信息 (表44), 返回下一个 offset (填充区前位置)
-- 条目长度语义(与 Qt beaconparser 一致):
--   长度字段值 len_raw = 头(1B) + 长度字段(1B/2B) + 内容
--   长度字段位宽: etype 0x00-0xBF 为 1B, 0xC0-0xFF 为 2B (表46)
--   内容长 = len_raw - (1 + len_bytes)
local function dissect_beacon_mgmt_info(tvb, tree, off)
    if off >= tvb:len() then return off end
    tree:add(f.beacon_entry_cnt, tvb(off, 1))
    local pos = off + 1
    local cnt = tvb(off, 1):uint()
    for i = 1, cnt do
        if pos >= tvb:len() then break end
        local etype = tvb(pos, 1):uint()
        tree:add(f.beacon_ent_type, tvb(pos, 1))
        pos = pos + 1
        -- 长度字段位宽: 0x00-0xBF 为 1B, 0xC0-0xFF 为 2B (表46)
        local len_bytes = (etype >= 0xC0) and 2 or 1
        if pos + len_bytes > tvb:len() then break end
        local len_raw = tvb(pos, len_bytes):le_uint()
        tree:add(f.beacon_ent_len, tvb(pos, len_bytes), len_raw)
        pos = pos + len_bytes
        -- 内容长 = len_raw - (头1B + 长度字段len_bytes)
        local item_len = len_raw - (1 + len_bytes)
        if item_len <= 0 then break end
        tree:add(f.beacon_ent_data, tvb(pos, item_len))
        -- 按条目类型解析内容
        if etype == 0x00 then
            dissect_entry_sta_cap(tvb, tree, pos)
        elseif etype == 0x01 then
            dissect_entry_route_param(tvb, tree, pos)
        elseif etype == 0x02 then
            dissect_entry_band_change(tvb, tree, pos)
        elseif etype == 0x03 then
            dissect_entry_rf_route(tvb, tree, pos)
        elseif etype == 0x04 then
            dissect_entry_rf_ch(tvb, tree, pos)
        elseif etype == 0x05 then
            dissect_entry_simple_beacon(tvb, tree, pos)
        elseif etype == 0x06 and item_len >= 8 then
            -- 万年历条目(表34): 万历时钟(0,32,自 2000-01-01 秒数) + 对应 NTB(4,32)
            add_le(tree, f.beacon_cal_sec, tvb, pos, 4)
            add_le(tree, f.beacon_cal_ntb, tvb, pos+4, 4)
        elseif etype == 0x07 and item_len >= 3 then
            -- 信道评估参数条目(表35): 主动/被动评估使能(0,0/1) + 保留 + 被动评估周期(2,8,10s)
            tree:add(f.beacon_ca_active, tvb(pos, 1))
            tree:add(f.beacon_ca_passive, tvb(pos, 1))
            tree:add(f.beacon_ca_period, tvb(pos+2, 1))
        elseif etype == 0x08 and item_len >= 5 then
            -- 信标机制切换条目(表36): 目标机制 ID(0,8) + 切换 NTB(1,32)
            tree:add(f.beacon_sw_target, tvb(pos, 1))
            add_le(tree, f.beacon_sw_ntb, tvb, pos+1, 4)
        elseif etype == 0xC0 then
            dissect_entry_slot_alloc(tvb, tree, pos)
        elseif etype == 0xC1 and item_len >= 1 then
            -- 代理角色条目(表37): 代理站点总数(0,8) + 代理 TEI 12b 连续打包序列
            -- (TEI i 位于位偏移 (pos+1)*8 + 12*i;N 为奇数时末条目高 4bit 保留)
            tree:add(f.beacon_proxy_cnt, tvb(pos, 1))
            local cnt = tvb(pos, 1):uint()
            for i = 0, cnt - 1 do
                local bp = (pos + 1) * 8 + 12 * i
                if math.floor(bp / 8) + 2 > tvb:len() then break end
                add_val(tree, f.beacon_proxy_tei, tvb, math.floor(bp / 8), 2, read_bits(tvb, bp, 12))
            end
        end
        pos = pos + item_len
    end
    return pos
end

-- 标准信标帧载荷 (表38)。off = 载荷起始(16, FCH 之后)
-- 结构(与 Qt beaconparser 一致):
--   整帧 MPDU = FCH(16B) + PB块(PBSize, 由 FCH 字节9 高4bit TMI 查表)
--   PB块 = 帧载荷(pbsize-3) + PB CRC24(3B)
--   帧载荷 = 固定头(标准20B) + 管理区 + PB Padding + CRC32(尾4B)
local function dissect_beacon_payload(tvb, tree, off)
    local tmi = read_bits(tvb, 9*8+4, 4)   -- FCH 字节9 高4bit
    local pbsize = beacon_pb_size(tmi)
    if pbsize <= 0 then
        tree:add_expert_info(PI_MALFORMED, PI_WARN, T("TMI 无效", "Invalid TMI"))
        return off
    end
    local gb_end = off + pbsize - 3   -- 帧载荷区末尾(不含 PB CRC24)

    -- 固定头 (标准: 0..19)
    tree:add(f.beacon_type, tvb(off, 1))
    tree:add(f.beacon_net_cplt, tvb(off, 1))
    tree:add(f.beacon_simple, tvb(off, 1))
    tree:add(f.beacon_start_assoc, tvb(off, 1))
    tree:add(f.beacon_use_flag, tvb(off, 1))
    tree:add(f.beacon_net_seq, tvb(off+1, 1))
    tree:add(f.beacon_cco_mac, tvb(off+2, 6))
    add_le(tree, f.beacon_bpc, tvb, off+8, 4)
    tree:add(f.beacon_rf_ch, tvb(off+12, 1))
    -- HDC 2.0 表38: byte13 = option(0,2b)+信标机制状态(2,1b)+发现信标使能(3,1b)+保留(4-7)
    tree:add(f.beacon_rf_option, tvb(off+13, 1))
    tree:add(f.beacon_mech_state, tvb(off+13, 1))
    tree:add(f.beacon_disc_en, tvb(off+13, 1))
    tree:add(f.beacon_rsv13, tvb(off+13, 1))

    -- 信标管理信息从 off+20 开始, 消费到 padding 起点
    local pos = dissect_beacon_mgmt_info(tvb, tree, off + 20)

    -- PB Padding: 管理区消费终点到 CRC32 前
    if pos < gb_end - 4 then
        tree:add(f.beacon_ent_data, tvb(pos, gb_end - 4 - pos))
    end

    -- BPCS CRC32 (帧载荷尾 4B): 校验帧载荷 off..gb_end-4 (不含 CRC32 本身)
    if gb_end - 4 >= off then
        local bpcs_rx = tvb(gb_end - 4, 4):le_uint()
        local bpcs_calc = crc32_le(tvb, off, gb_end - off)
        tree:add(f.beacon_bpcs, tvb(gb_end - 4, 4), bpcs_rx)
        tree:add(f.beacon_bpcs_calc, tvb(gb_end - 4, 4), bpcs_calc)
        tree:add(f.beacon_bpcs_ok, tvb(gb_end - 4, 1), bpcs_calc == bpcs_rx)
    end
    -- PB CRC24 (块尾 3B)
    if off + pbsize <= tvb:len() then
        tree:add(f.pb_pbcs, tvb(off + pbsize - 3, 3), tvb(off + pbsize - 3, 3):le_uint())
    end
    return off + pbsize
end

-- 精简信标帧载荷 (表56)。固定头仅 12B, 管理区从 off+12 起, 无信道编号/保留段
local function dissect_simple_beacon_payload(tvb, tree, off)
    local tmi = read_bits(tvb, 9*8+4, 4)
    local pbsize = beacon_pb_size(tmi)
    if pbsize <= 0 then
        tree:add_expert_info(PI_MALFORMED, PI_WARN, T("TMI 无效", "Invalid TMI"))
        return off
    end
    local gb_end = off + pbsize - 3

    tree:add(f.beacon_type, tvb(off, 1))
    tree:add(f.beacon_net_cplt, tvb(off, 1))
    tree:add(f.beacon_simple, tvb(off, 1))
    tree:add(f.beacon_start_assoc, tvb(off, 1))
    tree:add(f.beacon_use_flag, tvb(off, 1))
    tree:add(f.beacon_net_seq, tvb(off+1, 1))
    tree:add(f.beacon_cco_mac, tvb(off+2, 6))
    add_le(tree, f.beacon_bpc, tvb, off+8, 4)

    local pos = dissect_beacon_mgmt_info(tvb, tree, off + 12)
    if pos < gb_end - 4 then
        tree:add(f.beacon_ent_data, tvb(pos, gb_end - 4 - pos))
    end
    if gb_end - 4 >= off then
        local bpcs_rx = tvb(gb_end - 4, 4):le_uint()
        local bpcs_calc = crc32_le(tvb, off, gb_end - off)
        tree:add(f.beacon_bpcs, tvb(gb_end - 4, 4), bpcs_rx)
        tree:add(f.beacon_bpcs_calc, tvb(gb_end - 4, 4), bpcs_calc)
        tree:add(f.beacon_bpcs_ok, tvb(gb_end - 4, 1), bpcs_calc == bpcs_rx)
    end
    if off + pbsize <= tvb:len() then
        tree:add(f.pb_pbcs, tvb(off + pbsize - 3, 3), tvb(off + pbsize - 3, 3):le_uint())
    end
    return off + pbsize
end

local function dissect_std_mac_hdr(tvb, tree, off)
    local addr_flag = read_bits(tvb, off*8 + 11*8 + 3, 1)
    tree:add(f.mac_version, tvb(off, 1))
    add_val(tree, f.mac_ostei, tvb, off, 2, read_bits(tvb, off*8+4, 12))
    add_val(tree, f.mac_odtei, tvb, off+2, 2, read_bits(tvb, off*8+2*8, 12))
    tree:add(f.mac_send_type, tvb(off+3, 1))
    tree:add(f.mac_retry_limit, tvb(off+4, 1))
    tree:add(f.mac_aggregate, tvb(off+4, 1))     -- (4,5,1) HDC 2.0 新增
    tree:add(f.mac_rsv0, tvb(off+4, 1))          -- 字节4 bit6-7 保留
    add_le(tree, f.mac_msdu_seq, tvb, off+5, 2)
    tree:add(f.mac_msdu_type, tvb(off+7, 1))
    add_val(tree, f.mac_msdu_len, tvb, off+8, 2, read_bits(tvb, off*8+8*8, 11))
    tree:add(f.mac_restart_cnt, tvb(off+9, 1))
    tree:add(f.mac_proxy_main, tvb(off+9, 1))
    tree:add(f.mac_route_total, tvb(off+10, 1))
    tree:add(f.mac_route_left, tvb(off+10, 1))
    tree:add(f.mac_bcast_dir, tvb(off+11, 1))
    tree:add(f.mac_path_repair, tvb(off+11, 1))
    tree:add(f.mac_addr_flag, tvb(off+11, 1))
    -- 发送帧序号(11,4,12) 跨字节: byte11 bit4-7 + byte12 (HDC 2.0 新增)
    local send_seq = read_bits(tvb, (off+11)*8+4, 12)
    add_val(tree, f.mac_send_seq, tvb, off+11, 2, send_seq)
    tree:add(f.mac_net_seq, tvb(off+13, 1))
    tree:add(f.mac_rsv3, tvb(off+14, 1))         -- 字节14 保留
    tree:add(f.mac_link_id, tvb(off+15, 1))      -- 链路标识符(表2;载波SOF的LID已移至此处)
    local hdr_len = 16
    if addr_flag == 1 then
        tree:add(f.mac_osmac, tvb(off+16, 6))
        tree:add(f.mac_odmac, tvb(off+22, 6))
        hdr_len = 28
    end
    return hdr_len
end

-- 单跳 MAC 帧头 (HDC 2.0 表3: 新增 聚合MAC帧标识(3,7))
local function dissect_sh_mac_hdr(tvb, tree, off)
    tree:add(f.sh_version, tvb(off, 1))
    tree:add(f.sh_msgtype, tvb(off+1, 1))
    add_val(tree, f.sh_msdulen, tvb, off+2, 2, read_bits(tvb, off*8+2*8, 11))
    tree:add(f.sh_rsv1, tvb(off+3, 1))
    tree:add(f.sh_aggregate, tvb(off+3, 1))
    return 4
end

-- =========================================================================
-- 管理消息体解析
-- =========================================================================

-- 关联请求 (表60)
local function dissect_assoc_req(tvb, tree, off)
    tree:add(f.ar_sta_mac, tvb(off, 6))
    -- 候选代理 TEI x5, 每个 2 字节
    for i = 0, 4 do
        local p = off + 6 + i * 2
        add_val(tree, f.ar_proxy_tei, tvb, p, 2, read_bits(tvb, p*8, 12))
        tree:add(f.ar_link_type, tvb(p+1, 1))
    end
    tree:add(f.ar_phase, tvb(off+16, 1))
    tree:add(f.ar_dev_type, tvb(off+17, 1))
    tree:add(f.ar_mac_type, tvb(off+18, 1))
    tree:add(f.ar_module, tvb(off+19, 1))
    add_le(tree, f.ar_assoc_rand, tvb, off+20, 4)
    add_span(tree, f.ar_vendor, tvb, off+24, 18)
    -- 站点版本信息 (表66)
    local vp = off + 42
    tree:add(f.ar_boot_reason, tvb(vp, 1))
    tree:add(f.ar_boot_ver, tvb(vp+1, 1))
    add_le(tree, f.ar_soft_ver, tvb, vp+2, 2)
    add_le(tree, f.ar_ver_time, tvb, vp+4, 2)
    add_le(tree, f.ar_vendor_code, tvb, vp+6, 2)
    add_le(tree, f.ar_chip_code, tvb, vp+8, 2)
    add_le(tree, f.ar_hard_rst, tvb, off+52, 2)
    add_le(tree, f.ar_soft_rst, tvb, off+54, 2)
    tree:add(f.ar_proxy_type, tvb(off+56, 1))
    add_le(tree, f.ar_e2e_seq, tvb, off+60, 4)
    add_span(tree, f.ar_mgmt_id, tvb, off+64, 24)
end

-- 关联确认 (表70)
local function dissect_assoc_cnf(tvb, tree, off)
    tree:add(f.ac_sta_mac, tvb(off, 6))
    tree:add(f.ac_cco_mac, tvb(off+6, 6))
    tree:add(f.ac_result, tvb(off+12, 1))
    tree:add(f.ac_sta_level, tvb(off+13, 1))
    local sta_tei = read_bits(tvb, (off+14)*8, 12)
    add_val(tree, f.ac_sta_tei, tvb, off+14, 2, sta_tei)
    tree:add(f.ac_link_type, tvb(off+15, 1))
    tree:add(f.ac_carrier_band, tvb(off+15, 1))
    add_val(tree, f.ac_proxy_tei, tvb, off+16, 2, read_bits(tvb, (off+16)*8, 12))
    tree:add(f.ac_total_pkgs, tvb(off+18, 1))
    tree:add(f.ac_pkg_idx, tvb(off+19, 1))
    add_le(tree, f.ac_assoc_rand, tvb, off+20, 4)
    add_le(tree, f.ac_reassoc_time, tvb, off+24, 4)
    add_le(tree, f.ac_e2e_seq, tvb, off+28, 4)
    add_le(tree, f.ac_path_seq, tvb, off+32, 4)
    -- 记录 TEI ↔ MAC 映射 (CCO 分配的站点 TEI 与站点 MAC)
    record_tei_mac(sta_tei, mac_to_str(tvb, off))
    -- 路由表信息 (表74)
    if off + 40 + 8 <= tvb:len() then
        add_le(tree, f.ac_direct_sta, tvb, off+40, 2)
        add_le(tree, f.ac_direct_proxy, tvb, off+42, 2)
        add_le(tree, f.ac_route_size, tvb, off+44, 2)
    end
end

-- 关联汇总指示 (表76)
local function dissect_assoc_gather(tvb, tree, off)
    tree:add(f.ag_result, tvb(off, 1))
    tree:add(f.ag_sta_level, tvb(off+1, 1))
    tree:add(f.ag_cco_mac, tvb(off+2, 6))
    add_val(tree, f.ag_proxy_tei, tvb, off+8, 2, read_bits(tvb, (off+8)*8, 12))
    tree:add(f.ag_carrier_band, tvb(off+9, 1))
    local cnt = tvb(off+11, 1):uint()
    tree:add(f.ag_gather_cnt, tvb(off+11, 1))
    -- 站点信息: 每条 8 字节 (MAC 6B + TEI 12bit + 保留4bit)
    for i = 0, cnt - 1 do
        local p = off + 16 + i * 8
        tree:add(f.ag_sta_mac, tvb(p, 6))
        local sta_tei = read_bits(tvb, (p+6)*8, 12)
        add_val(tree, f.ag_sta_tei, tvb, p+6, 2, sta_tei)
        -- 记录 TEI ↔ MAC 映射
        record_tei_mac(sta_tei, mac_to_str(tvb, p))
    end
end

-- 代理变更请求 (表79)
local function dissect_cproxy_req(tvb, tree, off)
    add_val(tree, f.cpr_sta_tei, tvb, off, 2, read_bits(tvb, off*8, 12))
    for i = 0, 4 do
        local p = off + 2 + i * 2
        add_val(tree, f.cpr_new_proxy, tvb, p, 2, read_bits(tvb, p*8, 12))
        tree:add(f.cpr_link_type, tvb(p+1, 1))
    end
    add_val(tree, f.cpr_old_proxy, tvb, off+12, 2, read_bits(tvb, (off+12)*8, 12))
    tree:add(f.cpr_proxy_type, tvb(off+14, 1))
    tree:add(f.cpr_reason, tvb(off+15, 1))
    add_le(tree, f.cpr_e2e_seq, tvb, off+16, 4)
    tree:add(f.cpr_phase, tvb(off+20, 1))
end

-- 代理变更确认 (表84)
local function dissect_cproxy_cnf(tvb, tree, off)
    tree:add(f.cpc_result, tvb(off, 1))
    tree:add(f.cpc_total_pkgs, tvb(off+1, 1))
    tree:add(f.cpc_pkg_idx, tvb(off+2, 1))
    add_val(tree, f.cpc_sta_tei, tvb, off+4, 2, read_bits(tvb, (off+4)*8, 12))
    tree:add(f.cpc_link_type, tvb(off+5, 1))
    add_val(tree, f.cpc_proxy_tei, tvb, off+6, 2, read_bits(tvb, (off+6)*8, 12))
    add_le(tree, f.cpc_e2e_seq, tvb, off+8, 4)
    add_le(tree, f.cpc_path_seq, tvb, off+12, 4)
    local child_cnt = read_bits(tvb, (off+16) * 8, 16)
    tree:add(f.cpc_child_cnt, tvb(off+16, 2), child_cnt)
    -- 子站点条目: 每个 2 字节
    for i = 0, child_cnt - 1 do
        local p = off + 20 + i * 2
        add_val(tree, f.cpc_child_tei, tvb, p, 2, read_bits(tvb, p*8, 12))
    end
end

-- 代理变更确认位图版 (表88)
local function dissect_cproxy_bmp(tvb, tree, off)
    tree:add(f.cpb_result, tvb(off, 1))
    local bmp_size = read_bits(tvb, (off+2) * 8, 16)
    tree:add(f.cpb_bitmap_size, tvb(off+2, 2), bmp_size)
    add_val(tree, f.cpb_sta_tei, tvb, off+4, 2, read_bits(tvb, (off+4)*8, 12))
    tree:add(f.cpb_link_type, tvb(off+5, 1))
    add_val(tree, f.cpb_proxy_tei, tvb, off+6, 2, read_bits(tvb, (off+6)*8, 12))
    add_le(tree, f.cpb_e2e_seq, tvb, off+8, 4)
    add_le(tree, f.cpb_path_seq, tvb, off+12, 4)
    dissect_tei_bitmap(tvb, tree, off+20, bmp_size, f.cpb_child_bmp, T("子站点位图", "Child STA Bitmap"), "Child STA Bitmap")
end

-- 离线指示 (表91)
local function dissect_leave(tvb, tree, off)
    add_le(tree, f.li_reason, tvb, off, 2)
    local sta_cnt = read_bits(tvb, (off+2) * 8, 16)
    tree:add(f.li_sta_cnt, tvb(off+2, 2), sta_cnt)
    add_le(tree, f.li_delay, tvb, off+4, 2)
    for i = 0, sta_cnt - 1 do
        tree:add(f.li_sta_mac, tvb(off+16+i*6, 6))
    end
end

-- 心跳检测 (表94)
local function dissect_heartbeat(tvb, tree, off)
    add_val(tree, f.hb_ostei, tvb, off, 2, read_bits(tvb, off*8, 12))
    add_val(tree, f.hb_max_disc_tei, tvb, off+2, 2, read_bits(tvb, (off+2)*8, 12))
    add_le(tree, f.hb_max_disc_cnt, tvb, off+4, 2)
    local bmp_size = read_bits(tvb, (off+6) * 8, 16)
    tree:add(f.hb_bitmap_size, tvb(off+6, 2), bmp_size)
    dissect_tei_bitmap(tvb, tree, off+8, bmp_size, f.hb_disc_bmp, T("发现站点位图", "Discovery STA Bitmap"), "Discovery STA Bitmap")
end

-- 发现列表 (表95)
local function dissect_disc_list(tvb, tree, off)
    local tei = read_bits(tvb, off*8, 12)
    add_val(tree, f.dl_tei, tvb, off, 2, tei)
    add_val(tree, f.dl_proxy_tei, tvb, off+1, 2, read_bits(tvb, (off+1)*8+4, 12))
    tree:add(f.dl_role, tvb(off+3, 1))
    tree:add(f.dl_level, tvb(off+3, 1))
    tree:add(f.dl_mac, tvb(off+4, 6))
    tree:add(f.dl_cco_mac, tvb(off+10, 6))
    -- 记录 TEI ↔ MAC 映射 (发送发现列表报文的站点)
    record_tei_mac(tei, mac_to_str(tvb, off+4))
    tree:add(f.dl_phase, tvb(off+16, 1))
    tree:add(f.dl_proxy_qual, tvb(off+17, 1))
    tree:add(f.dl_proxy_rate, tvb(off+18, 1))
    tree:add(f.dl_proxy_dl_rate, tvb(off+19, 1))
    add_le(tree, f.dl_sta_cnt, tvb, off+20, 2)
    tree:add(f.dl_send_cnt, tvb(off+22, 1))
    local up_route_cnt = tvb(off+23, 1):uint()
    tree:add(f.dl_up_route_cnt, tvb(off+23, 1))
    add_le(tree, f.dl_route_remain, tvb, off+24, 2)
    local bmp_size = read_bits(tvb, (off+26) * 8, 16)
    tree:add(f.dl_bitmap_size, tvb(off+26, 2), bmp_size)
    tree:add(f.dl_min_rate, tvb(off+28, 1))
    -- 上行路由条目信息: 每条 2 字节
    local pos = off + 32
    for i = 0, up_route_cnt - 1 do
        add_val(tree, f.dl_next_hop_tei, tvb, pos, 2, read_bits(tvb, pos*8, 12))
        tree:add(f.dl_route_type, tvb(pos+1, 1))
        pos = pos + 2
    end
    dissect_tei_bitmap(tvb, tree, pos, bmp_size, f.dl_disc_bmp, T("发现站点列表位图", "Discovery STA List Bitmap"), "Discovery STA List Bitmap")

    -- 接收发现列表信息 (表99): 条目数 = 位图中置位 bit 总数, 每个 1 字节
    -- 依次对应位图从 0 字节起第 1/2/.../N 个有效 TEI 站点的接收报文数
    local rcv_pos = pos + bmp_size
    if rcv_pos <= tvb:len() then
        -- 收集位图中置位 bit 对应的 TEI (bit 全局索引 = TEI: 字节i的bit j → TEI=i*8+j)
        local set_teis = {}
        for bi = 0, bmp_size - 1 do
            local b = tvb(pos + bi, 1):uint()
            for j = 0, 7 do
                if band(b, 2 ^ j) ~= 0 then
                    set_teis[#set_teis + 1] = bi * 8 + j
                end
            end
        end
        for k = 1, #set_teis do
            local tei = set_teis[k]
            local v = tvb(rcv_pos + k - 1, 1):uint()
            tree:add(f.dl_rcv_cnt, tvb(rcv_pos + k - 1, 1), v)
            tree:add(f.dl_rcv_item, tvb(rcv_pos + k - 1, 1),
                string.format(T("接收发现列表数[%d] (TEI %d): %d", "Rcv Discovery List Count[%d] (TEI %d): %d"), k - 1, tei, v))
        end
    end
end

-- 通信成功率上报 (表100)
local function dissect_succ_rate(tvb, tree, off)
    add_val(tree, f.sr_tei, tvb, off, 2, read_bits(tvb, off*8, 12))
    local cnt = read_bits(tvb, (off+2) * 8, 16)
    tree:add(f.sr_sta_cnt, tvb(off+2, 2), cnt)
    for i = 0, cnt - 1 do
        local p = off + 4 + i * 4
        add_val(tree, f.sr_sta_tei, tvb, p, 2, read_bits(tvb, p*8, 12))
        tree:add(f.sr_down_rate, tvb(p+2, 1))
        tree:add(f.sr_up_rate, tvb(p+3, 1))
    end
end

-- 网络冲突上报 (表102)
local function dissect_net_conflict(tvb, tree, off)
    tree:add(f.ncr_cco_mac, tvb(off, 6))
    local cnt = tvb(off+6, 1):uint()
    tree:add(f.ncr_nbr_cnt, tvb(off+6, 1))
    tree:add(f.ncr_nid_width, tvb(off+7, 1))
    for i = 0, cnt - 1 do
        tree:add(f.ncr_nbr_nid, tvb(off+8+i*3, 3), tvb(off+8+i*3, 3):le_uint())
    end
end

-- 过零NTB采集指示 (表104)
local function dissect_zc_collect(tvb, tree, off)
    local raw16 = tvb(off, 2):le_uint()
    local tei = band(raw16, 0x0FFF)
    local rsv4 = band(bit.rshift(raw16, 12), 0x0F)
    add_val(tree, f.zc_tei, tvb, off, 2, tei)
    local rsv_item = tree:add(f.zc_tei_rsv, tvb(off, 2), rsv4)
    if rsv4 ~= 0 then
        rsv_item:add_expert_info(PI_PROTOCOL, PI_WARN, T("[非零保留位]", "[Non-zero reserved bits]"))
    end
    tree:add(f.zc_collect_site, tvb(off+2, 1))
    tree:add(f.zc_collect_period, tvb(off+3, 1))
    tree:add(f.zc_collect_cnt, tvb(off+4, 1))
end

-- 过零NTB上报 (表107)
local function dissect_zc_report(tvb, tree, off)
    local raw16 = tvb(off, 2):le_uint()
    local tei = band(raw16, 0x0FFF)
    local rsv4 = band(bit.rshift(raw16, 12), 0x0F)
    add_val(tree, f.zr_tei, tvb, off, 2, tei)
    local rsv_item = tree:add(f.zr_tei_rsv, tvb(off, 2), rsv4)
    if rsv4 ~= 0 then
        rsv_item:add_expert_info(PI_PROTOCOL, PI_WARN, T("[非零保留位]", "[Non-zero reserved bits]"))
    end
    tree:add(f.zr_total_cnt, tvb(off+2, 1))
    local ph1 = tvb(off+3, 1):uint()
    local ph2 = tvb(off+4, 1):uint()
    local ph3 = tvb(off+5, 1):uint()
    tree:add(f.zr_ph1_cnt, tvb(off+3, 1))
    tree:add(f.zr_ph2_cnt, tvb(off+4, 1))
    tree:add(f.zr_ph3_cnt, tvb(off+5, 1))
    add_le(tree, f.zr_base_ntb, tvb, off+6, 4)
    -- 过零NTB差值: 12bit 字段, 每 1.5 字节
    local pos = off + 10
    local function add_diffs(field, cnt)
        for i = 0, cnt - 1 do
            add_val(tree, field, tvb, pos, 2, read_bits(tvb, pos*8 + (i % 2) * 4, 12))
            -- 每两个 12bit 占 3 字节
            if i % 2 == 1 then pos = pos + 3 end
        end
    end
    add_diffs(f.zr_ph1_diff, ph1)
    add_diffs(f.zr_ph2_diff, ph2)
    add_diffs(f.zr_ph3_diff, ph3)
end

-- 网络诊断 (表109)
local function dissect_diag(tvb, tree, off)
    add_le(tree, f.diag_vendor_id, tvb, off, 2)
    add_span(tree, f.diag_custom, tvb, off+2, nil)
end

-- 路由请求 (表111)
local function dissect_rreq(tvb, tree, off)
    tree:add(f.rreq_version, tvb(off, 1))
    add_le(tree, f.rreq_seq, tvb, off+1, 4)
    tree:add(f.rreq_path_pref, tvb(off+5, 1))
    tree:add(f.rreq_payload_type, tvb(off+5, 1))
    tree:add(f.rreq_payload_len, tvb(off+6, 1))
end

-- 路由回复 (表114)
local function dissect_rrep(tvb, tree, off)
    tree:add(f.rrep_version, tvb(off, 1))
    add_le(tree, f.rrep_seq, tvb, off+1, 4)
    tree:add(f.rrep_payload_type, tvb(off+5, 1))
    tree:add(f.rrep_payload_len, tvb(off+6, 1))
end

-- 路由错误 (表117)
local function dissect_rerr(tvb, tree, off)
    tree:add(f.rerr_version, tvb(off, 1))
    add_le(tree, f.rerr_seq, tvb, off+1, 4)
    local cnt = tvb(off+6, 1):uint()
    tree:add(f.rerr_unreach_cnt, tvb(off+6, 1))
    for i = 0, cnt - 1 do
        add_le(tree, f.rerr_unreach_tei, tvb, off+7+i*2, 2)
    end
end

-- 路由应答 (表118)
local function dissect_rack(tvb, tree, off)
    tree:add(f.rack_version, tvb(off, 1))
    add_le(tree, f.rack_seq, tvb, off+4, 4)
end

-- 链路确认请求 (表119)
local function dissect_lcreq(tvb, tree, off)
    tree:add(f.lcreq_version, tvb(off, 1))
    add_le(tree, f.lcreq_seq, tvb, off+1, 4)
    local cnt = tvb(off+6, 1):uint()
    tree:add(f.lcreq_sta_cnt, tvb(off+6, 1))
    for i = 0, cnt - 1 do
        add_le(tree, f.lcreq_sta_tei, tvb, off+7+i*2, 2)
    end
end

-- 链路确认回应 (表120)
local function dissect_lcrsp(tvb, tree, off)
    tree:add(f.lcrsp_version, tvb(off, 1))
    tree:add(f.lcrsp_level, tvb(off+1, 1))
    tree:add(f.lcrsp_chan_qual, tvb(off+2, 1))
    tree:add(f.lcrsp_path_pref, tvb(off+3, 1))
    add_le(tree, f.lcrsp_seq, tvb, off+4, 4)
end

-- 无线信道冲突上报 (表121/122)
local function dissect_rfccr(tvb, tree, off)
    tree:add(f.rfccr_cco_mac, tvb(off, 6))
    local cnt = tvb(off+6, 1):uint()
    tree:add(f.rfccr_nbr_cnt, tvb(off+6, 1))
    -- 表122:邻居网络条目 = 每邻居 1 字节(该邻居无线信道号), 无 TEI/option
    for i = 0, cnt - 1 do
        local entry_off = off + 7 + i
        if entry_off + 1 > tvb:len() then break end
        tree:add(f.rfccr_nbr_ch, tvb(entry_off, 1))
    end
end

-- 无线/载波发现列表 (表91/表62, 单跳帧消息类型0/2)
-- carrier=false: 无线版,组合表 表95(非位图 0-9)/表103(位图 0-10),无 BRU 变体
-- carrier=true : 载波版,组合表 表68(0-10)/表77(0-11),combo10/11 含 BRUSNR32(表64)
local rfdl_combo_nonbitmap = {  -- {rcv,snr,rssi,bru} 位宽(表95/表68)
    {8,0,0,0},{0,4,0,0},{0,0,8,0},{0,0,4,0},{8,4,0,0},
    {6,0,6,0},{0,6,6,0},{8,6,6,0},{0,4,4,0},{8,0,4,0},{0,0,0,32},
}
local rfdl_combo_bitmap = {     -- (表103/表77)
    {8,0,0,0},{0,4,0,0},{0,0,8,0},{0,0,4,0},{8,4,0,0},
    {8,0,8,0},{0,6,6,0},{8,6,6,0},{8,4,4,0},{0,4,4,0},{8,0,4,0},{0,0,0,32},
}
local function rfdl_db_str(v32)
    -- 表64: 32bit = 8×4bit BRU SNR, -10~35dB 3dB 步进(0 → -10dB)
    local parts = {}
    for b = 0, 7 do
        local v = math.floor(v32 / 2 ^ (4 * b)) % 0x10
        parts[#parts + 1] = tostring(-10 + 3 * v)
    end
    return table.concat(parts, ",")
end
-- 渲染一条邻居信道信息(位流), 返回下一条起始位; 调用方保证不越界
-- (树节点字节范围按 bitpos 取整: rel_start=floor(bp/8), rel_len=ceil((bp%8+bits)/8))
local function rfdl_neighbour(tree, tvb, bitpos, cb, has_tei, tei, idx, carrier, loc_sfx)
    local ntree = tree:add(gw, string.format(T("Neighbor[%d]", "Neighbor[%d]"), idx)
        .. (loc_sfx or ""))
    local bp = bitpos
    if has_tei then
        add_val(ntree, f.rfdl_nbr_tei, tvb, math.floor(bp / 8), 2, tei)
        bp = bp + 12
    end
    if cb[1] > 0 then
        local v = read_bits(tvb, bp, cb[1])
        local pct = (cb[1] == 6) and v * 2 or v
        local it = add_val(ntree, f.rfdl_nbr_rate, tvb, math.floor(bp / 8), 2, v)
        it:append_text(string.format(" (%d%%)", pct))
        bp = bp + cb[1]
    end
    if cb[2] > 0 then
        local v = read_bits(tvb, bp, cb[2])
        -- SNR 映射两簇不同(勿混): 无线=表97(6bit 连续,量化值=SNR+6)/表98(4bit 非均匀,-6 起至 >25);
        -- 载波=表70(6bit 连续,量化值=SNR+10)/表71(4bit 3dB 步进,-10 起,15 档 >35)
        local it = add_val(ntree, f.rfdl_nbr_snr, tvb, math.floor(bp / 8), 2, v)
        local note
        if v == 0 then
            note = carrier and T("(SNR≤-10dB)", "(SNR≤-10dB)") or T("(SNR≤-6dB)", "(SNR≤-6dB)")
        elseif carrier then
            note = (cb[2] == 6) and string.format(T("(SNR=%ddB)", "(SNR=%ddB)"), v - 10)
                   or ((v == 15) and T("(SNR>35dB)", "(SNR>35dB)")
                       or string.format(T("(SNR %d~%ddB)", "(SNR %d~%ddB)"), v * 3 - 13, v * 3 - 10))
        elseif cb[2] == 6 then
            note = string.format(T("(SNR=%ddB)", "(SNR=%ddB)"), v - 6)
        else
            -- 表98 非均匀: 1-11 档 2dB 步进,12-14 档 3dB 步进(上界 -4,-2,0,2,4,6,8,10,12,14,16,19,22,25)
            local hi = { -4, -2, 0, 2, 4, 6, 8, 10, 12, 14, 16, 19, 22, 25 }
            local lo = (v == 1) and -6 or hi[v - 2]
            note = (v == 15) and T("(SNR>25dB)", "(SNR>25dB)")
                   or string.format(T("(SNR %d~%ddB)", "(SNR %d~%ddB)"), lo, hi[v - 1])
        end
        it:append_text(" " .. note)
        bp = bp + cb[2]
    end
    if cb[3] > 0 then
        local v = read_bits(tvb, bp, cb[3])
        -- RSSI 映射两簇不同(勿混): 无线=表99(8bit v=RSSI+110)/表100(4bit 非均匀,-105 起)/表101(6bit 2dB 步进,-110 起);
        -- 载波=表72(8bit v=RSSI+100,-100 起)/表73(4bit 非均匀,-95 起)/表74(6bit 2dB 步进,-100 起)
        local it = add_val(ntree, f.rfdl_nbr_rssi, tvb, math.floor(bp / 8), 2, v)
        local note
        if cb[3] == 8 then
            note = string.format(T("(RSSI=%ddBm)", "(RSSI=%ddBm)"), v - (carrier and 100 or 110))
        elseif cb[3] == 6 then
            local base = carrier and 100 or 110
            note = (v == 0) and string.format(T("(RSSI≤-%ddBm)", "(RSSI≤-%ddBm)"), base)
                   or string.format(T("(RSSI %d~%ddBm)", "(RSSI %d~%ddBm)"), v * 2 - base, v * 2 - base + 2)
        else
            -- 4bit 区间硬编码(表73 载波/-95 起至 >10 / 表100 无线/-105 起至 >0, 勿混)
            local lo_hi
            if carrier then
                lo_hi = { {-95,-86},{-86,-80},{-80,-74},{-74,-68},{-68,-62},{-62,-56},
                          {-56,-48},{-48,-42},{-42,-36},{-36,-30},{-30,-20},{-20,-10},{-10,0},{0,10} }
            else
                lo_hi = { {-105,-95},{-95,-86},{-86,-80},{-80,-74},{-74,-68},{-68,-62},
                          {-62,-56},{-56,-48},{-48,-42},{-42,-36},{-36,-30},{-30,-20},{-20,-10},{-10,0} }
            end
            if v == 0 then
                note = carrier and T("(RSSI≤-95dBm)", "(RSSI≤-95dBm)") or T("(RSSI≤-105dBm)", "(RSSI≤-105dBm)")
            elseif v == 15 then
                note = carrier and T("(RSSI>10dBm)", "(RSSI>10dBm)") or T("(RSSI>0dBm)", "(RSSI>0dBm)")
            else
                note = string.format(T("(RSSI %d~%ddBm)", "(RSSI %d~%d dBm)"), lo_hi[v][1], lo_hi[v][2])
            end
        end
        it:append_text(" " .. note)
        bp = bp + cb[3]
    end
    if cb[4] > 0 then
        local v = read_bits(tvb, bp, 32)
        ntree:add(f.rfdl_nbr_brusnr, tvb(math.floor(bp / 8), 4), v):
            append_text(string.format(T(" (dB: %s)", " (dB: %s)"), rfdl_db_str(v)))
        bp = bp + 32
    end
    return bp
end
local function dissect_rfdl_ie_content(tree, tvb, pos, elen, ie_type, carrier)
    if elen <= 0 then return end
    local ok, err = pcall(function()
        if ie_type == 0 and ((not carrier and elen >= 14) or (carrier and elen >= 23)) then
            if carrier then
                -- 站点属性信息(表63, 23B 定长, 载波发现列表)
                add_val(tree, f.rfdl_attr_tei, tvb, pos, 2, read_bits(tvb, pos*8, 12))
                add_val(tree, f.rfdl_attr_proxy_tei, tvb, pos+1, 2, read_bits(tvb, pos*8+12, 12))
                tree:add(f.rfdl_attr_carrier_role, tvb(pos+3, 1))
                tree:add(f.rfdl_attr_carrier_level, tvb(pos+3, 1))
                tree:add(f.rfdl_attr_cco_mac, tvb(pos+4, 6))
                tree:add(f.rfdl_attr_phase, tvb(pos+10, 1))
                tree:add(f.rfdl_attr_ch_quality, tvb(pos+11, 1))
                tree:add(f.rfdl_attr_comm_rate, tvb(pos+12, 1))
                tree:add(f.rfdl_attr_down_comm_rate, tvb(pos+13, 1))
                add_le(tree, f.rfdl_attr_remain_time, tvb, pos+14, 2)
                tree:add(f.rfdl_attr_min_comm_rate, tvb(pos+16, 1))
                tree:add(f.rfdl_attr_discover_period, tvb(pos+17, 1))
                tree:add(f.rfdl_attr_aging, tvb(pos+18, 1))
                add_le(tree, f.rfdl_attr_brusnr, tvb, pos+19, 4)
            else
                -- 站点属性信息(表92, 14B 定长, 无线发现列表)
                tree:add(f.rfdl_attr_cco_mac, tvb(pos, 6))
                add_val(tree, f.rfdl_attr_proxy_tei, tvb, pos+6, 2, read_bits(tvb, pos*8+6*8, 12))
                tree:add(f.rfdl_attr_role, tvb(pos+7, 1))
                tree:add(f.rfdl_attr_level, tvb(pos+8, 1))
                tree:add(f.rfdl_attr_rfhop, tvb(pos+8, 1))
                tree:add(f.rfdl_attr_up_rate, tvb(pos+9, 1))
                tree:add(f.rfdl_attr_down_rate, tvb(pos+10, 1))
                tree:add(f.rfdl_attr_min_rate, tvb(pos+11, 1))
                tree:add(f.rfdl_attr_period, tvb(pos+12, 1))
                tree:add(f.rfdl_attr_aging, tvb(pos+13, 1))
            end
        elseif ie_type == 1 then
            -- 站点路由信息(表93): 每条 2B = 下一跳 TEI 12b + 路由类型 4b(bit4-7)
            local n = math.floor(elen / 2)
            for i = 0, n - 1 do
                local p = pos + i * 2
                local it = tree:add(gw, string.format(T("Route[%d]", "Route[%d]"), i))
                add_val(it, f.rfdl_route_tei, tvb, p, 2, read_bits(tvb, p*8, 12))
                it:add(f.rfdl_route_type, tvb(p+1, 1))
            end
        elseif ie_type == 2 then
            -- 邻居信道信息非位图版(表94/67 + 组合表 表95/表68)
            local combo = band(tvb(pos, 1):uint(), 0x0F)
            local tbl = carrier and rfdl_combo_nonbitmap or rfdl_combo_nonbitmap
            local max_combo = carrier and 10 or 9
            local ct = tree:add(f.rfdl_combo, tvb(pos, 1))
            if combo <= max_combo then
                -- 表94/67 头语义:TEI 12b + Rcv/SNR/RSSI/BRUSNR 按组合类型附加
                local cb0 = tbl[combo+1]
                local entry = 12 + cb0[1] + cb0[2] + cb0[3] + cb0[4]
                local sem = "TEI"
                if cb0[1] > 0 then sem = sem .. string.format("+Rcv%db", cb0[1]) end
                if cb0[2] > 0 then sem = sem .. string.format("+SNR%db", cb0[2]) end
                if cb0[3] > 0 then sem = sem .. string.format("+RSSI%db", cb0[3]) end
                if cb0[4] > 0 then sem = sem .. string.format("+BRUSNR%db", cb0[4]) end
                ct:append_text(string.format(T(" - %s (%db/邻居)", " - %s (%db/neighbor)"), sem, entry))
            else
                ct:append_text(T(" (保留)", " (Reserved)"))
            end
            if combo > max_combo then return end
            -- 表94/67 头:保留(0,4-7,4b)
            tree:add(gw, tvb(pos, 1), T("RSV [4b]", "RSV [4b]"))
            local cb = tbl[combo+1]
            local entry_bits = 12 + cb[1] + cb[2] + cb[3] + cb[4]
            local bitpos = 8
            local i = 0
            while bitpos + entry_bits <= elen * 8 do
                local tei = read_bits(tvb, bitpos, 12)
                bitpos = rfdl_neighbour(tree, tvb, bitpos, cb, true, tei, i, carrier)
                i = i + 1
            end
        elseif ie_type == 3 then
            -- 邻居信道信息位图版(表102/76 + 组合表 表103/表77)
            -- 组: 起始TEI 12b + 保留4b + 位图大小1B + 位图L B + 逐置位邻居条目
            local combo = band(tvb(pos, 1):uint(), 0x0F)
            local tbl = carrier and rfdl_combo_bitmap or rfdl_combo_bitmap
            local max_combo = carrier and 11 or 10
            local ct = tree:add(f.rfdl_combo, tvb(pos, 1))
            if combo <= max_combo then
                -- 表102/76 头语义:Rcv/SNR/RSSI/BRUSNR 按组合类型附加(无 TEI,位图定位)
                local cb0 = tbl[combo+1]
                local entry = cb0[1] + cb0[2] + cb0[3] + cb0[4]
                local sem = ""
                if cb0[1] > 0 then sem = sem .. string.format("Rcv%db", cb0[1]) end
                if cb0[2] > 0 then sem = sem .. string.format("%sSNR%db", sem ~= "" and "+" or "", cb0[2]) end
                if cb0[3] > 0 then sem = sem .. string.format("%sRSSI%db", sem ~= "" and "+" or "", cb0[3]) end
                if cb0[4] > 0 then sem = sem .. string.format("%sBRUSNR%db", sem ~= "" and "+" or "", cb0[4]) end
                if sem == "" then sem = T("无附加字段", "no extra fields") end
                ct:append_text(string.format(T(" - %s (%db/邻居)", " - %s (%db/neighbor)"), sem, entry))
            else
                ct:append_text(T(" (保留)", " (Reserved)"))
            end
            if combo > max_combo then return end
            -- 表102/76 头:保留(0,4-7,4b)
            tree:add(gw, tvb(pos, 1), T("RSV [4b]", "RSV [4b]"))
            local cb = tbl[combo+1]
            local entry_bits = cb[1] + cb[2] + cb[3] + cb[4]
            local off = 1
            local k = 0
            while off + 3 < elen do
                local start_tei = read_bits(tvb, (pos+off)*8, 12)
                local bm_len = tvb(pos+off+2, 1):uint()
                if off + 3 + bm_len > elen then break end
                local bmp = tvb(pos+off+3, bm_len)
                local g = tree:add(gw, string.format(T("Group[%d] StartTEI=%d", "Group[%d] StartTEI=%d"), k, start_tei))
                add_val(g, f.rfdl_grp_tei, tvb, pos+off, 2, start_tei)
                -- 表102/76:组保留(起始TEI 高 4bit, off+1 bit4-7)
                g:add(gw, tvb(pos+off+1, 1), T("RSV [4b]", "RSV [4b]"))
                g:add(f.rfdl_grp_size, tvb(pos+off+2, 1), bm_len)
                local teis = {}
                local nk = 0
                for bi = 0, bm_len - 1 do
                    local b = tvb(pos+off+3+bi, 1):uint()
                    for j = 0, 7 do
                        if band(b, 2 ^ j) ~= 0 then
                            nk = nk + 1
                            teis[#teis + 1] = tostring(math.floor(start_tei + bi * 8 + j))
                        end
                    end
                end
                local bmp_item = g:add(f.rfdl_grp_bitmap, bmp)
                bmp_item:append_text(string.format(" (TEI: %s)", #teis > 0 and table.concat(teis, ",") or "-"))
                -- 位图逐位(仅 bit=1):值标注该 bit 所在的字节号(位图内第 bi 字节),与 C++ 表103 一致
                for bi2 = 0, bm_len - 1 do
                    local b2 = tvb(pos+off+3+bi2, 1):uint()
                    for j2 = 0, 7 do
                        if band(b2, 2 ^ j2) ~= 0 then
                            bmp_item:add(gw, tvb(pos+off+3+bi2, 1),
                                string.format(T("Neighbor[%d] TEI=%d = 在位图(第%d字节)",
                                                "Neighbor[%d] TEI=%d = in bitmap (byte %d)"),
                                              bi2*8+j2, start_tei + bi2*8+j2, bi2))
                        end
                    end
                end
                local bitpos = (off + 3 + bm_len) * 8
                local i = 0
                for bi = 0, bm_len - 1 do
                    local b = tvb(pos+off+3+bi, 1):uint()
                    for j = 0, 7 do
                        if band(b, 2 ^ j) ~= 0 then
                            if bitpos + entry_bits > elen * 8 then break end
                            -- rfdl_neighbour 返回绝对 bit 位, 换算回相对 pos 的位偏移
                            local absp = rfdl_neighbour(g, tvb, (pos*8) + bitpos, cb, false,
                                start_tei + bi*8 + j, i, carrier,
                                string.format(T(" (位图 byte %d bit %d)", " (bitmap byte %d bit %d)"), bi, j))
                            bitpos = absp - pos*8
                            i = i + 1
                        end
                    end
                end
                off = math.floor(bitpos / 8) + (bitpos % 8 ~= 0 and 1 or 0)
                k = k + 1
            end
        end
    end)
    if not ok then
        tree:add_expert_info(PI_MALFORMED, PI_WARN,
            T("IE 内容解析失败(可能截断): ", "IE content parse failed (truncated?): ") .. tostring(err))
    end
end
local pfx_route, pfx_nbr, pfx_grp  -- (已改用 gw proto 子树,保留占位避免外部引用)

-- 无线/载波发现列表 (表91/表62)
local function dissect_rfdl(tvb, tree, off, carrier, limit)
    -- limit: 单跳 MSDU 结束(不含 MSDU CRC32), 防止把尾部 CRC32 误解析为 IE
    limit = limit or tvb:len()
    tree:add(f.rfdl_sta_mac, tvb(off, 6))
    tree:add(f.rfdl_seq, tvb(off+6, 1))
    local pos = off + 7
    while pos + 1 < limit do
        local ie_type = band(tvb(pos, 1):uint(), 0x7F)
        local ltype = band(tvb(pos, 1):uint(), 0x80)
        tree:add(f.rfdl_ie_type, tvb(pos, 1))
        tree:add(f.rfdl_ie_ltype, tvb(pos, 1))
        pos = pos + 1
        local len_bytes = (ltype ~= 0) and 2 or 1
        local elen = tvb(pos, 1):uint()
        if len_bytes == 2 then elen = elen * 256 + tvb(pos + 1, 1):uint() end
        tree:add(f.rfdl_ie_len, tvb(pos, len_bytes))
        pos = pos + len_bytes
        if pos + elen > limit then
            tree:add_expert_info(PI_MALFORMED, PI_WARN,
                T("信息单元长度越界(截断)", "IE length out of range (truncated)"))
            break
        end
        if elen > 0 then
            local itree = tree:add(f.rfdl_ie_data, tvb(pos, elen))
            dissect_rfdl_ie_content(itree, tvb, pos, elen, ie_type, carrier)
        end
        pos = pos + elen
    end
end

-- 信道评估参数更新报文 (表106-108, 单跳帧消息类型1)
-- byte0: BRUSNR有效标志(0,0,1)+SAT配置长度(0,1-7); 标志=1 后随 4B BRU SNR(表64);
-- SAT 配置固定头 2B: byte0 ID(1b)+模式(1b)+组大小(2b)+保留, byte1 TMI(4b)+增益(4b);
-- 段数自 byte2(4b/5b 按 表107/108), 后随 N+1 段位图
local function dissect_ch_eval(tvb, tree, off)
    local bru_valid = band(tvb(off, 1):uint(), 0x01)
    local sat_len = math.floor(band(tvb(off, 1):uint(), 0xFE) / 2)
    tree:add(f.ce_bru_valid, tvb(off, 1))
    tree:add(f.ce_sat_len, tvb(off, 1))
    local pos = off + 1
    if bru_valid == 1 then
        if pos + 4 > tvb:len() then return end
        local v = tvb(pos, 4):le_uint()
        tree:add(f.ce_bru_snr, tvb(pos, 4), v):
            append_text(string.format(T(" (dB: %s)", " (dB: %s)"), rfdl_db_str(v)))
        pos = pos + 4
    end
    if sat_len <= 0 or pos + sat_len > tvb:len() then return end
    local sat = tvb(pos, sat_len)
    local stree = tree:add(f.ce_table, sat)
    stree:append_text(": " .. T("SAT 配置", "SAT Config"))
    if sat_len < 2 then return end
    stree:add(f.ce_sat_id, sat(0, 1))
    stree:add(f.ce_sat_mode, sat(0, 1))
    local grp = math.floor(band(sat(0, 1):uint(), 0x0C) / 4)
    stree:add(f.ce_grp_size, sat(0, 1)):append_text(
        string.format(T(" (%d 个/组)", " (%d/group)"), (grp <= 3) and (grp + 1) * 4 or 0))
    stree:add(f.ce_tmi, sat(1, 1))
    stree:add(f.ce_gain, sat(1, 1))
    if sat_len >= 3 then
        local mode = band(sat(0, 1):uint(), 0x02) / 2
        local seg_bits = (mode == 0) and 4 or 5
        local seg_cnt = read_bits(sat, 2*8, seg_bits) + 1
        local tbl_bytes = math.min(1 + seg_cnt, sat_len - 2)
        local tbl_item = stree:add(f.ce_table, sat(2, tbl_bytes)):
            append_text(string.format(T(" [%d 段]", " [%d segments]"), seg_cnt))
        -- 表107(位图,1bit/组)/表108(阶数,2bit/组)逐位/逐组(与 C++ parse_channel_eval 对齐)
        local meaning = { T("不使用", "unused"), T("BPSK", "BPSK"), T("QPSK", "QPSK"), T("16QAM", "16QAM") }
        for k = 0, tbl_bytes - 2 do
            local b = sat(3 + k, 1):uint()
            if mode == 0 then
                for j = 0, 7 do
                    if band(b, 2 ^ j) ~= 0 then
                        tbl_item:add(gw, sat(3 + k, 1),
                            string.format(T("Segment[%d] = 在位图(第%d字节)",
                                            "Segment[%d] = in bitmap (byte %d)"), k * 8 + j, k))
                    end
                end
            else
                for j = 0, 3 do
                    local v = band(math.floor(b / 2 ^ j), 0x03)
                    tbl_item:add(gw, sat(3 + k, 1),
                        string.format(T("Group[%d] = %d - %s", "Group[%d] = %d - %s"),
                                      k * 4 + j, v, meaning[v + 1]))
                end
            end
        end
    end
end

-- Bitloading 训练请求(表104)/拒绝(表105): 4B = 源TEI(0,12) + 目的TEI(2,12) + byte3
-- (请求: 子载波分组大小 0-3=4/8/12/16 个一组; 拒绝: 0x0 未定义/0x1 节点正在训练/0x2 训练节点已满)
local function dissect_bitloading_train(tvb, tree, off, is_reject)
    add_val(tree, f.mme_bl_src_tei, tvb, off, 2, read_bits(tvb, off*8, 12))
    add_val(tree, f.mme_bl_dst_tei, tvb, off+1, 2, read_bits(tvb, (off+1)*8+4, 12))
    local v = tvb(off+3, 1):uint()
    local it = tree:add(f.mme_bl_param, tvb(off+3, 1), v)
    if not is_reject then
        it:append_text((v <= 3) and
            string.format(T(" (%d 个子载波一组)", " (%d subcarriers/group)"), (v+1)*4)
            or T(" (保留)", " (Reserved)"))
    else
        local rs = { T("未定义", "Undefined"), T("节点正在训练", "Node training in progress"), T("训练节点已满", "Training node full") }
        it:append_text((v <= 2) and string.format(" (%s)", tostring(rs[v+1])) or T(" (保留)", " (Reserved)"))
    end
end

-- 分组请求(表109/110): 保留 8B + 邻居个数(8,8) + 邻居列表 每条 3B
-- (TEI 12b + 类型 1b + 保留 3b + 载波信道质量 4b + 无线信道质量 4b)
local function dissect_group_req(tvb, tree, off)
    if off + 9 > tvb:len() then return end
    tree:add(f.mme_grp_rsv, tvb(off, 8))
    local n = tvb(off+8, 1):uint()
    tree:add(f.mme_grp_num, tvb(off+8, 1), n)
    local p = off + 9
    for i = 0, n - 1 do
        if p + 3 > tvb:len() then break end
        local it = tree:add(gw, string.format(T("Neighbour[%d] (3B)", "Neighbour[%d] (3B)"), i))
        add_val(it, f.mme_grp_tei, tvb, p, 2, read_bits(tvb, p*8, 12))
        -- 类型 1b (byte+1 bit4, 表110: 0=组成员/1=候选组代理), 与 C++ get_bits(b,off+1,4,1) 一致
        add_val(it, f.mme_grp_type, tvb, p+1, 1, read_bits(tvb, (p+1)*8+4, 1))
        add_val(it, f.mme_grp_qplc, tvb, p+2, 1, band(tvb(p+2,1):uint(), 0x0F))
        add_val(it, f.mme_grp_qrf, tvb, p+2, 1, math.floor(band(tvb(p+2,1):uint(), 0xF0) / 16))
        p = p + 3
    end
end

-- 分组确认(表111/112): 组代理TEI(0,24) + 保留(3,40) + 组员个数(8,8) + 组员 每条 2B(TEI 12b+保留4b)
local function dissect_group_cnf(tvb, tree, off)
    if off + 9 > tvb:len() then return end
    tree:add(f.mme_gc_proxy_tei, tvb(off, 3), tvb(off, 3):le_uint())
    tree:add(f.mme_gc_rsv, tvb(off+3, 5))
    local n = tvb(off+8, 1):uint()
    tree:add(f.mme_gc_num, tvb(off+8, 1), n)
    local p = off + 9
    for i = 0, n - 1 do
        if p + 2 > tvb:len() then break end
        add_val(tree, f.mme_gc_tei, tvb, p, 2, read_bits(tvb, p*8, 12))
        p = p + 2
    end
end

-- 管理消息体分发 (HDC 2.0 表43: 0x0008 改保留; 0x0050-0x0055 废弃; 新增 0x0011-0x0014)
local function dissect_mgmt_body(tvb, tree, off, mmtype)
    if mmtype == 0x0000 then dissect_assoc_req(tvb, tree, off)
    elseif mmtype == 0x0001 then dissect_assoc_cnf(tvb, tree, off)
    elseif mmtype == 0x0002 then dissect_assoc_gather(tvb, tree, off)
    elseif mmtype == 0x0003 then dissect_cproxy_req(tvb, tree, off)
    elseif mmtype == 0x0004 then dissect_cproxy_cnf(tvb, tree, off)
    elseif mmtype == 0x0005 then dissect_cproxy_bmp(tvb, tree, off)
    elseif mmtype == 0x0006 then dissect_leave(tvb, tree, off)
    elseif mmtype == 0x0007 then dissect_heartbeat(tvb, tree, off)
    elseif mmtype == 0x0008 then
        -- HDC 2.0 表43: 0x0008 发现列表改保留(改经单跳帧/信标 0xC2 承载), 保留 hex
        local t = tree:add(f.rfdl_ie_data, tvb(off))
        t:append_text(": " .. T("保留(1.0 发现列表,2.0 不再使用)", "Reserved (1.0 DiscoverNodeList, unused in 2.0)"))
    elseif mmtype == 0x0009 then dissect_succ_rate(tvb, tree, off)
    elseif mmtype == 0x000A then dissect_net_conflict(tvb, tree, off)
    elseif mmtype == 0x000B then dissect_zc_collect(tvb, tree, off)
    elseif mmtype == 0x000C then dissect_zc_report(tvb, tree, off)
    elseif mmtype == 0x0011 then dissect_bitloading_train(tvb, tree, off, false)
    elseif mmtype == 0x0012 then dissect_bitloading_train(tvb, tree, off, true)
    elseif mmtype == 0x0013 then dissect_group_req(tvb, tree, off)
    elseif mmtype == 0x0014 then dissect_group_cnf(tvb, tree, off)
    elseif mmtype == 0x004F then dissect_diag(tvb, tree, off)
    elseif mmtype == 0x0080 then dissect_rfccr(tvb, tree, off)
    end
end

-- 管理消息头 (表58), 返回 mmtype
local function dissect_mgmt_hdr(tvb, tree, off)
    add_le(tree, f.mgmt_mmtype, tvb, off, 2)
    add_le(tree, f.mgmt_resv, tvb, off+2, 2)
    return read_bits(tvb, off * 8, 16)
end

-- =========================================================================
-- 媒介类型 field extractor (必须在 dissector 注册前定义)
-- =========================================================================
local encap_type_f = Field.new("frame.encap_type")

function gw.dissector(tvb, pinfo, tree)
    -- 媒介判别: USER0(45)=载波 / USER1(46)=无线 / USER4(49)=串口混合采集(帧内媒介头)。
    -- 本文件仅经 packet-gw_2022.lua 委托进入(不注册 wtap_encap), 媒介头剥离由本文件负责。
    local ev = encap_type_f()
    local evs = ev and tostring(ev) or ""
    local is_rf = (evs == "46")
    if evs == "49" then
        -- USER4 混合格式: [phr_mcs][option][channel][isRF] + MPDU
        local mtree = tree:add(gw, tvb(0, 4), T("媒介头(串口采集)", "Media Header (serial capture)"))
        mtree:add(f.media_phr_mcs, tvb(0, 1))
        mtree:add(f.media_option, tvb(1, 1))
        mtree:add(f.media_channel, tvb(2, 1))
        mtree:add(f.media_is_rf, tvb(3, 1))
        is_rf = tvb(3, 1):uint() ~= 0
        tvb = tvb(4):tvb()
    end
    if is_rf then
        pinfo.cols.protocol = "RF"
    else
        pinfo.cols.protocol = "HPLC"
    end

    if tvb:len() < 16 then
        tree:add_expert_info(PI_MALFORMED, PI_WARN, T("帧长不足 16 字节(最小 MPDU 帧控制)", "Frame shorter than 16 bytes (minimum MPDU frame control)"))
        return 0
    end

    local dt = band(tvb(0, 1):uint(), 0x07)
    local nid = tvb(1, 2):le_uint()   -- HDC 2.0 表4: NID 16bit(byte1-2),byte3 保留
    cur_nid = nid  -- 供 record_tei_mac 记录映射

    -- 源/目的地址列 (Source/Destination 列): 按帧类型提取 TEI
    local src_tei, dst_tei
    if dt == 0 then
        src_tei = read_bits(tvb, 8*8, 12)      -- 信标源TEI (FCH 字节8)
    elseif dt == 1 then
        src_tei = read_bits(tvb, 4*8, 12)      -- SOF 源TEI
        dst_tei = read_bits(tvb, 5*8+4, 12)    -- SOF 目的TEI
    elseif dt == 2 then
        src_tei = read_bits(tvb, 5*8, 12)      -- SACK 源TEI
        dst_tei = read_bits(tvb, 6*8+4, 12)    -- SACK 目的TEI
    elseif dt == 3 then
        src_tei = 1                            -- 网间协调帧必然由 CCO 发出 (TEI 1)
    end
    -- 附加 MAC 地址 (历史帧已学到的 TEI↔MAC 映射)
    if src_tei then
        local base
        if src_tei == 1 then
            base = T("CCO (TEI 1)", "CCO (TEI 1)")
        else
            base = string.format(T("STA (TEI %d)", "STA (TEI %d)"), src_tei)
        end
        local mac = lookup_tei_mac(nid, src_tei)
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
        local mac = lookup_tei_mac(nid, dst_tei)
        if mac then base = base .. " [" .. mac .. "]" end
        pinfo.cols.dst = base
    else
        pinfo.cols.dst = ""
    end

    pinfo.cols.info = string.format("DT=%s NID=0x%04x", dt_vals[dt] or T("Reserved", "Reserved").."("..dt..")", nid)

    local root = tree:add(gw, tvb())

    -- MPDU 帧控制 16B (表4)
    local fc_tree = root:add(gw, tvb(0, 16), T("MPDU 帧控制 (FCH)", "MPDU Frame Control (FCH)"))
    fc_tree:add(f.fc_dt, tvb(0, 1))
    fc_tree:add(f.fc_net_type, tvb(0, 1))
    fc_tree:add(f.fc_nid, tvb(1, 2), nid)
    fc_tree:add(f.fc_nid_rsv, tvb(3, 1))

    local vf_tree = fc_tree:add(f.fc_vf, tvb(4, 9))
    if dt == 0 then
        dissect_beacon_vf(tvb, vf_tree, is_rf)
    elseif dt == 1 then
        dissect_sof_vf(tvb, vf_tree, is_rf)
    elseif dt == 2 then
        dissect_sack_vf(tvb, vf_tree)
    elseif dt == 3 then
        dissect_coord_vf(tvb, vf_tree)
    end

    fc_tree:add(f.fc_std_ver, tvb(12, 1))
    -- FCCS CRC24: 校验 FCH 前 13 字节(0-12), 存储值字节 13-15
    local fccs_rx = tvb(13, 3):le_uint()
    local fccs_calc = crc24_lsb(tvb, 0, 16)
    fc_tree:add(f.fc_fccs, tvb(13, 3), fccs_rx)
    fc_tree:add(f.fc_fccs_calc, tvb(13, 3), fccs_calc)
    fc_tree:add(f.fc_fccs_ok, tvb(13, 1), fccs_calc == fccs_rx)

    -- 信标帧载荷 (dt=0)
    if dt == 0 and tvb:len() > 16 then
        -- 信标物理块无物理块头, 载荷直接跟在 FCH 后
        -- 块大小: 载波由 TMI 定(表17); 无线由载荷PB大小码(10,0,4)查表29
        local bpbsize
        if is_rf then
            bpbsize = rf_pb_size(read_bits(tvb, 10*8, 4))
        else
            bpbsize = beacon_pb_size(read_bits(tvb, 9*8+4, 4))
        end
        if bpbsize > 0 and 16 + bpbsize > tvb:len() then
            -- 捕获截断: 帧长低于对应信标物理块, 仅提示不展开(避免逐字段越界)
            root:add_expert_info(PI_MALFORMED, PI_WARN,
                string.format(T("帧长 %d B 低于信标物理块 %d B(可能截断)",
                                "Frame %d B shorter than beacon PB %d B (truncated?)"),
                              tvb:len(), bpbsize))
        else
            -- 精简信标标志在载荷首字节 bit4
            local simple = band(tvb(16, 1):uint(), 0x10) ~= 0
            if simple then
                dissect_simple_beacon_payload(tvb, root:add(gw, tvb(16), T("精简信标帧载荷", "Lite Beacon Payload")), 16)
            else
                dissect_beacon_payload(tvb, root:add(gw, tvb(16), T("信标帧载荷", "Beacon Payload")), 16)
            end
        end
    end

    -- SOF 帧载荷: 物理块 -> MAC 帧 (dt=1)
    if dt == 1 and tvb:len() > 16 then
        -- PB 块大小: 载波由分集拷贝模式(TMI/TMI_EXT)定; 无线固定 1 块,
        --   块大小由载荷PB大小码(9,4,4)查表29, 码>5 为保留值(pbsz=-1, 不分段)
        local pb_count, pbsz
        if is_rf then
            pb_count = 1
            pbsz = rf_pb_size(read_bits(tvb, 9*8+4, 4))
        else
            -- 载波 SOF 按帧子类型分派(表7 (7,0,3)):
            --   0=数据帧(表7) 1=信道探测帧(表9) 2=OFDMA下行(表10/11) 3=TDA下行(表12/13)
            local sof_dt = read_bits(tvb, 7*8, 3)
            if sof_dt == 1 then
                -- 表9(信道探测帧)无 PB/调制/PB个数字段: 载荷为训练序列, 不带数据物理块
                root:add(gw, tvb(16), T("信道探测帧无数据物理块(表9 无 PB 字段)",
                                        "No Data PB in Channel Sounding Frame (Table 9 Has No PB Field)"))
                return tvb:len()
            elseif sof_dt == 2 or sof_dt == 3 then
                -- 多站点(OFDMA 表10/11, TDA 表12/13): 逐站点 PB 分组
                -- eFC 固定 16 字节(表11/13 内部字节号 0-15) ⇒ PB 起点 = 16+16 = 32
                local is_ofdma = (sof_dt == 2)
                local sn = read_bits(tvb, 7*8+3, 2)   -- 站点数(7,3,2): 0保留 1:2站 2:3站 3:4站
                local n_sites = (sn >= 1 and sn <= 3) and (sn + 1) or 0
                if n_sites == 0 then
                    root:add_expert_info(PI_MALFORMED, PI_WARN,
                        T("OFDMA/TDA 站点数为保留值 0(表10/表12 仅定义 1-3)",
                          "OFDMA/TDA Station Count Is Reserved Value 0 (Tables 10/12 Define 1-3 Only)"))
                elseif tvb:len() < 32 then
                    -- eFC(byte16-31)截断: 拒绝逐站 PB 分组, 避免越界取 tvb(与 Qt 解析器同口径)
                    root:add_expert_info(PI_MALFORMED, PI_WARN,
                        T("OFDMA/TDA eFC 截断(帧长 < 32B)", "OFDMA/TDA eFC Truncated (Frame Length < 32B)"))
                    return tvb:len()
                else
                    local blk = 32
                    for s = 0, n_sites - 1 do
                        local tei, cmode, spin
                        if s == 0 then
                            tei = read_bits(tvb, 5*8+4, 12)                -- 表10 (5,4,12) 站点0 TEI
                            cmode = read_bits(tvb, 11*8+3, 5)              -- 表10 (11,3,5)
                            spin = is_ofdma and (read_bits(tvb, 11*8+2, 1) + 1) or 1
                        else
                            local b = 16 + (s - 1) * (is_ofdma and 3 or 4)
                            tei = read_bits(tvb, b*8, 12)                  -- 表11/13 (b,0,12)
                            cmode = is_ofdma and read_bits(tvb, (b+2)*8, 5)  -- 表11 (b+2,0,5)
                                              or  read_bits(tvb, (b+3)*8, 5)  -- 表13 (b+3,0,5)
                            spin = is_ofdma and (read_bits(tvb, (b+2)*8+5, 1) + 1) or 1
                        end
                        local ssz = sof_pb_size(cmode, 0)
                        if ssz <= 0 then
                            root:add_expert_info(PI_MALFORMED, PI_WARN,
                                string.format(T("PB 大小非法(分集拷贝=%1)", "Invalid PB Size (DivCopy=%1)"), cmode))
                            return tvb:len()
                        end
                        if is_ofdma and ssz ~= 72 and ssz ~= 136 then
                            root:add_expert_info(PI_MALFORMED, PI_WARN,
                                string.format(T("OFDMA PB 大小越界(分集拷贝=%1 → %2B，协议限 72/136)",
                                    "OFDMA PB Size Out of Range (DivCopy=%1 -> %2B, Protocol Allows 72/136 Only)"), cmode, ssz))
                            return tvb:len()
                        end
                        local st_tree = root:add(gw, tvb(blk, 1),
                            string.format(T("站点 %d PB 分组 (TEI=%d, 分集拷贝=%d, %d 块 × %d B)",
                                            "Station %d PB Group (TEI=%d, DivCopy=%d, %d Block(s) x %d B)"),
                                          s, tei, cmode, spin, ssz))
                        for j = 0, spin - 1 do
                            local bstart = blk + j * ssz
                            if bstart + ssz > tvb:len() then
                                st_tree:add_expert_info(PI_MALFORMED, PI_WARN,
                                    T("PB 块超出帧长", "PB Block Exceeds Frame Length"))
                                break
                            end
                            local bt = st_tree:add(gw, tvb(bstart, ssz), string.format(T("物理块 %d", "PB %d"), j))
                            bt:add(f.pb_size, tvb(bstart, ssz), ssz)
                            bt:add(f.pb_seq, tvb(bstart, 1))
                            bt:add(f.pb_sof, tvb(bstart, 1))
                            bt:add(f.pb_eof, tvb(bstart, 1))
                            bt:add(f.pb_body, tvb(bstart + 1, ssz - 4))
                            local crc_rx = tvb(bstart + ssz - 3, 3):le_uint()
                            local crc_calc = crc24_lsb(tvb, bstart, ssz)
                            bt:add(f.pb_pbcs, tvb(bstart + ssz - 3, 3), crc_rx)
                            bt:add(f.pb_crc_calc, tvb(bstart + ssz - 3, 3), crc_calc)
                            bt:add(f.pb_crc_ok, tvb(bstart + ssz - 3, 1), crc_calc == crc_rx)
                        end
                        blk = blk + spin * ssz
                    end
                end
                return tvb:len()
            elseif sof_dt >= 4 then
                root:add_expert_info(PI_MALFORMED, PI_WARN,
                    T("帧子类型为保留值(表7 仅定义 0-3)",
                      "Frame Subtype Is Reserved Value (Table 7 Defines 0-3 Only)"))
                return tvb:len()
            end

            -- sof_dt == 0 数据帧(表7): 现状逻辑保持不变
            -- HDC 2.0 表7: 调制方式(10,1)/参数(10,2-6)/PB个数 2b 编码(10,7)+(11,0)
            -- 分集拷贝:参数=TMI 编号查表;动态加载:参数=物理块类型编号(表8)
            local mod_mode = read_bits(tvb, 10*8+1, 1)
            local mod_param = read_bits(tvb, 10*8+2, 5)
            pb_count = sof_pb_num_decode(read_bits(tvb, 10*8+7, 1) + read_bits(tvb, 11*8, 1) * 2)
            if mod_mode == 0 then
                pbsz = sof_pb_size(mod_param, 0)
            else
                pbsz = sof_dynamic_pb_size(mod_param)
            end
        end

        -- 逐 PB 块解析: 头(1B) + 体(pbsz-4) + CRC24(3B)
        -- MAC 帧解析基准: 多块时 MSDU 跨物理块(中间夹块尾CRC24/下块头),
        -- 用"块体逻辑视图"把重组坐标映射回原帧 — 不生成新数据源, hex 始终完整显示原始帧
        local mac_tvb = tvb
        local mac_off = 17  -- 单块路径: 第一块体起始 = FCH16 + 头1 (块体连续, 直接用原帧)
        if pbsz > 0 and pb_count >= 1 and pb_count <= 4 then
            local blocks_done = 0
            for i = 0, pb_count - 1 do
                local bstart = 16 + i * pbsz
                if bstart + pbsz > tvb:len() then break end
                local blk_tree = root:add(gw, tvb(bstart, pbsz),
                    string.format(T("物理块 %d", "PB %d"), i))
                blk_tree:add(f.pb_size, tvb(bstart, pbsz), pbsz)
                blk_tree:add(f.pb_seq, tvb(bstart, 1))
                blk_tree:add(f.pb_sof, tvb(bstart, 1))
                blk_tree:add(f.pb_eof, tvb(bstart, 1))
                -- 体: 头后 pbsz-4 字节 (先整体标记, padding 后面再切)
                blk_tree:add(f.pb_body, tvb(bstart + 1, pbsz - 4))
                -- CRC24: 块末 3 字节 (小端), 校验前 pbsz-3 字节
                local crc_rx = tvb(bstart + pbsz - 3, 3):le_uint()
                local crc_calc = crc24_lsb(tvb, bstart, pbsz)
                blk_tree:add(f.pb_pbcs, tvb(bstart + pbsz - 3, 3), crc_rx)
                blk_tree:add(f.pb_crc_calc, tvb(bstart + pbsz - 3, 3), crc_calc)
                blk_tree:add(f.pb_crc_ok, tvb(bstart + pbsz - 3, 1), crc_calc == crc_rx)
                blocks_done = blocks_done + 1
            end
            if blocks_done == pb_count and pb_count > 1 then
                mac_tvb = make_block_view(tvb, 17, pbsz, pb_count)
                mac_off = 0
            end
        else
            -- 无法查表时, 退化为旧行为: 仅读首块头
            local pb_off = 16
            local pb_tree = root:add(gw, tvb(pb_off, 1), T("物理块头", "PB Header"))
            pb_tree:add(f.pb_seq, tvb(pb_off, 1))
            pb_tree:add(f.pb_sof, tvb(pb_off, 1))
            pb_tree:add(f.pb_eof, tvb(pb_off, 1))
        end

        if mac_off < mac_tvb:len() then
            local version = read_bits(mac_tvb, mac_off*8, 4)
            local mac_tree = root:add(gw, mac_tvb(mac_off), T("MAC 帧", "MAC Frame"))
            local msdu_off
            if version == 0 then
                local hdr_len = dissect_std_mac_hdr(mac_tvb, mac_tree, mac_off)
                msdu_off = mac_off + hdr_len
            elseif version == 1 then
                -- 单跳帧(表3,4B 头): 消息类型 0=无线发现列表(表91) / 1=信道评估参数
                -- 更新(表106-108) / 2=载波发现列表(表62) / 128=应用层 / 129=IPv4
                local hdr_len = dissect_sh_mac_hdr(mac_tvb, mac_tree, mac_off)
                msdu_off = mac_off + hdr_len
                -- 单跳 MSDU 长度(表3, 11bit @byte2): IE 解析上界(不含尾部 MSDU CRC32 4B)
                local sh_msdu_len = read_bits(mac_tvb, mac_off*8+2*8, 11)
                local msdu_end = msdu_off + sh_msdu_len
                local msg_type = mac_tvb(mac_off+1, 1):uint()
                if msg_type == 0 then
                    dissect_rfdl(mac_tvb, mac_tree, msdu_off, false, msdu_end)
                elseif msg_type == 2 then
                    dissect_rfdl(mac_tvb, mac_tree, msdu_off, true, msdu_end)
                elseif msg_type == 1 then
                    if msdu_off < mac_tvb:len() then
                        dissect_ch_eval(mac_tvb, mac_tree, msdu_off)
                    end
                elseif msg_type == 129 then
                    if msdu_off < mac_tvb:len() then
                        mac_tree:add(gw, mac_tvb(msdu_off), T("IPv4 报文", "IPv4 Packet"))
                    end
                elseif msg_type ~= 128 then
                    -- 其他类型保留: hex 展示
                    if msdu_off < mac_tvb:len() then
                        mac_tree:add(f.rfdl_ie_data, mac_tvb(msdu_off),
                            string.format(T("保留类型 %d 载荷", "Reserved type %d payload"), msg_type))
                    end
                end
                -- 单跳 MSDU CRC32 (覆盖 MSDU, 不含 4B 单跳头): 展示并校验
                if msdu_end + 4 <= mac_tvb:len() then
                    local crc_rx = mac_tvb(msdu_end, 4):le_uint()
                    -- crc32_le(tvb,off,len) 校验前 len-4 字节: 传入长度须含 4B CRC 本身
                    local crc_calc = crc32_le(mac_tvb, msdu_off, sh_msdu_len + 4)
                    add_val(mac_tree, f.sh_msdu_crc, mac_tvb, msdu_end, 4, crc_rx)
                    mac_tree:add(f.sh_msdu_crc_ok, mac_tvb(msdu_end, 1), crc_calc == crc_rx)
                end
                return tvb:len()
            else
                msdu_off = mac_off + 16
            end

            local msdu_type = mac_tvb(mac_off+7, 1):uint()
            local msdu_len = read_bits(mac_tvb, mac_off*8+8*8, 11)

            -- 方向判断: OSTEI=1(源CCO) 且 ODTEI!=0xFFF → 下行; 否则上行
            -- 当前发出者 src_tei != OSTEI → 中继 Relay
            if version == 0 and mac_off + 16 <= mac_tvb:len() then
                local ostei = read_bits(mac_tvb, mac_off*8+4, 12)
                local odtei = read_bits(mac_tvb, mac_off*8+2*8, 12)
                -- 原始目标地址列: ODTEI 格式化 + MAC 映射
                local ods
                if odtei == 0xFFF then
                    ods = T("广播 (TEI 4095)", "Broadcast (TEI 4095)")
                elseif odtei == 1 then
                    ods = T("CCO (TEI 1)", "CCO (TEI 1)")
                else
                    ods = string.format(T("STA (TEI %d)", "STA (TEI %d)"), odtei)
                end
                local odmac = lookup_tei_mac(nid, odtei)
                if odmac then ods = ods .. " [" .. odmac .. "]" end
                tree:add(f.col_orig_dst, mac_tvb(mac_off+2, 2), ods)
                local oss
                if ostei == 0xFFF then
                    oss = T("广播 (TEI 4095)", "Broadcast (TEI 4095)")
                elseif ostei == 1 then
                    oss = T("CCO (TEI 1)", "CCO (TEI 1)")
                else
                    oss = string.format(T("STA (TEI %d)", "STA (TEI %d)"), ostei)
                end
                local osmac = lookup_tei_mac(nid, ostei)
                if osmac then oss = oss .. " [" .. osmac .. "]" end
                tree:add(f.col_orig_src, mac_tvb(mac_off, 2), oss)
                local dir_mark = ""
                if ostei == 1 and odtei ~= 0xFFF then
                    dir_mark = T(" ↓下行", " ↓Downlink")
                elseif ostei ~= 1 then
                    dir_mark = T(" ↑上行", " ↑Uplink")
                end
                if src_tei and ostei and src_tei ~= ostei then
                    dir_mark = dir_mark .. " Relay"
                end
                if dir_mark ~= "" then
                    pinfo.cols.info = tostring(pinfo.cols.info) .. dir_mark
                end
            end

            -- 管理消息
            if msdu_type == 0 and msdu_off + 4 <= mac_tvb:len() then
                local mgmt_tree = mac_tree:add(gw, mac_tvb(msdu_off), T("管理消息", "Management Message"))
                local mmtype = dissect_mgmt_hdr(mac_tvb, mgmt_tree, msdu_off)
                -- info 列追加管理消息类型
                local mt_name = mgmt_type_vals[mmtype] or ""
                local cur_info = tostring(pinfo.cols.info)
                if mt_name ~= "" then
                    pinfo.cols.info = cur_info .. string.format(" %s", mt_name)
                else
                    pinfo.cols.info = cur_info .. string.format(" MMTYPE=0x%04x", mmtype)
                end
                -- 消息体 = MSDU 去掉 4 字节管理消息头
                local body_off = msdu_off + 4
                local body_len = msdu_len - 4
                if body_len > 0 then
                    local avail = mac_tvb:len() - body_off
                    if avail > 0 then
                        -- 子视图(坐标平移到消息体起点, off 从 0 起; 不生成新数据源)
                        local body_tvb = view_slice(mac_tvb, body_off)
                        local ok, err = pcall(dissect_mgmt_body, body_tvb, mgmt_tree, 0, mmtype)
                        if not ok then
                            mgmt_tree:add_expert_info(PI_MALFORMED, PI_WARN,
                                T("管理消息体解析失败(可能截断): ", "Management message body parse failed (possibly truncated): ") .. tostring(err))
                        end
                    end
                end
            end

            -- 应用层报文 (msdu_type=48): APP_BASE = 端口号 + 报文ID + 控制字
            if msdu_type == 48 and msdu_off + 4 <= mac_tvb:len() then
                local app_tree = mac_tree:add(gw, mac_tvb(msdu_off), T("应用层报文", "Application Layer Packet"))
                app_tree:add(f.app_port, mac_tvb(msdu_off, 1))
                local packet_id = read_bits(mac_tvb, (msdu_off + 1) * 8, 16)
                app_tree:add(f.app_packet_id, mac_tvb(msdu_off + 1, 2), packet_id)
                app_tree:add(f.app_ctrl_word, mac_tvb(msdu_off + 3, 1))
                -- 应用层载荷 = MSDU 去掉 4 字节 APP_BASE
                local app_payload_len = msdu_len - 4
                if app_payload_len > 0 and msdu_off + 4 + app_payload_len <= mac_tvb:len() then
                    add_span(app_tree, f.app_payload, mac_tvb, msdu_off + 4, app_payload_len)
                end
                -- info 列追加报文 ID 说明
                local pid_name = app_packet_id_vals[packet_id] or ""
                local cur_info = tostring(pinfo.cols.info)
                if pid_name ~= "" then
                    pinfo.cols.info = cur_info .. string.format(" APP[%s]", pid_name)
                else
                    pinfo.cols.info = cur_info .. string.format(" APP[ID=0x%04x]", packet_id)
                end
            end

            -- ICV CRC32 在 MSDU 末尾: 校验 MSDU(msdu_off..icv_off, 不含 MAC 帧头)
            local icv_off = msdu_off + msdu_len
            if msdu_len > 0 and icv_off + 4 <= mac_tvb:len() then
                local icv_rx = read_bits(mac_tvb, icv_off * 8, 32)
                local icv_calc = crc32_le(mac_tvb, msdu_off, msdu_len + 4)
                tree:add(f.mac_icv, mac_tvb(icv_off, 4), icv_rx)
                tree:add(f.mac_icv_calc, mac_tvb(icv_off, 4), icv_calc)
                tree:add(f.mac_icv_ok, mac_tvb(icv_off, 1), icv_calc == icv_rx)
            end

            -- padding: 重组流中 MAC 帧(头+MSDU+ICV)结束到末块块体终点的填充区
            if mac_off == 0 then
                local pad_start = msdu_off + msdu_len + 4  -- ICV 之后
                if pad_start < mac_tvb:len() then
                    add_span(root, f.pb_padding, mac_tvb, pad_start, nil)
                end
            end
        end
    end

    return tvb:len()
end

-- =========================================================================
-- 注册:仅注册协议名(供 packet-gw_2022.lua 按 FCH 标准版本号委托调用),
-- 不注册 wtap_encap —— 入口分发在 packet-gw_2022.lua(版本 0=1.0 / 1=2.0)
-- =========================================================================

