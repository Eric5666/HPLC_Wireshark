-- lang-path-test: Wireshark Lua 插件加载期“语言文件路径”回归测试
--
-- 背景: 四个 dissector 在加载阶段读 Wireshark 界面语言文件决定字段名语言。旧代码写死
--   os.getenv("APPDATA") .. "\\Wireshark\\language"
-- Linux/macOS 无 APPDATA ⇒ getenv 返回 nil ⇒ 拼接抛错 ⇒ 整个插件加载失败。
--
-- 做法: 不依赖 Wireshark。用万能 stub 顶替 Proto/ProtoField/Field/DissectorTable 等全局,
-- 替换 os.getenv / package.config / io.open / io.popen / Dir 模拟各平台环境,逐个 dofile 插件,
-- 记录插件尝试打开的 language 文件路径与 Proto 描述的语言(中文/英文)。
--
-- 用法: lua test_lang_path.lua <wireshark_support_plugins 目录>
-- 退出码: 0 全部通过, 1 有失败
local PLUGIN_DIR = arg[1] or "wireshark_support_plugins"
local PLUGINS = { "packet-gw_2022.lua", "packet-gw_2026.lua", "packet-nw_2021.lua", "packet-nw_2026.lua" }

local real_getenv, real_open, real_popen = os.getenv, io.open, io.popen
local real_config = package.config
local WIN_CONFIG = "\\\n;\n?\n!\n-\n"
local NIX_CONFIG = "/\n;\n?\n!\n-\n"

-- ---------- 万能 stub: 可索引/可调用/可运算, 足够让插件顶层代码跑完 ----------
local stub_mt = {}
local function new_stub() return setmetatable({}, stub_mt) end
stub_mt.__index = function(t, k) local s = new_stub(); rawset(t, k, s); return s end
stub_mt.__call = function() return new_stub() end
for _, mm in ipairs({ "__add", "__sub", "__mul", "__div", "__mod", "__unm", "__idiv",
                      "__band", "__bor", "__bxor", "__shl", "__shr", "__bnot", "__concat" }) do
    stub_mt[mm] = function() return new_stub() end
end
stub_mt.__len = function() return 0 end
stub_mt.__eq = function() return false end
stub_mt.__lt = function() return false end
stub_mt.__le = function() return false end
stub_mt.__tostring = function() return "<stub>" end

-- ---------- 场景 ----------
-- env: 模拟的环境变量; win: 是否 Windows 分隔符; dir: Dir.personal_config_path 行为
--   nil = 无 Dir 全局, "ok" = 返回 /wsconf/<file>, "throw" = 抛错
-- files: 模拟文件系统 {path = 内容}
-- expect_path: 期望插件打开的语言文件路径(nil = 不应打开任何 language 文件)
-- expect_english: 期望 Proto 描述的语言
local SCEN = {
    { name = "linux: 无 APPDATA, 仅 HOME, 文件 language: zh_CN",
      env = { HOME = "/home/u" }, files = { ["/home/u/.config/wireshark/language"] = "language: zh_CN\n" },
      expect_path = "/home/u/.config/wireshark/language", expect_english = false },
    { name = "linux: XDG_CONFIG_HOME 优先于 HOME",
      env = { HOME = "/home/u", XDG_CONFIG_HOME = "/xdg" }, files = { ["/xdg/wireshark/language"] = "language: zh\n" },
      expect_path = "/xdg/wireshark/language", expect_english = false },
    { name = "linux: XDG_CONFIG_HOME 为空串 ⇒ 回落 HOME",
      env = { HOME = "/home/u", XDG_CONFIG_HOME = "" }, files = {},
      expect_path = "/home/u/.config/wireshark/language", expect_english = true },
    { name = "macOS 同 linux: HOME 下 ~/.config/wireshark, 文件 language: en",
      env = { HOME = "/Users/u", LANG = "zh_CN.UTF-8" }, files = { ["/Users/u/.config/wireshark/language"] = "language: en_US\n" },
      expect_path = "/Users/u/.config/wireshark/language", expect_english = true },
    { name = "linux: 环境变量全不设, 无 Dir ⇒ 不打开文件、回退默认语言、不报错",
      env = {}, files = {}, expect_path = nil, expect_english = true },
    { name = "linux: 全不设 + LANG=zh ⇒ 回退系统语言中文",
      env = { LANG = "zh_CN.UTF-8" }, files = {}, expect_path = nil, expect_english = false },
    { name = "linux: Wireshark Dir.personal_config_path 可用 ⇒ 优先于 XDG/HOME",
      env = { HOME = "/home/u", XDG_CONFIG_HOME = "/xdg" }, dir = "ok", files = { ["/wsconf/language"] = "language: zh_CN\n" },
      expect_path = "/wsconf/language", expect_english = false },
    { name = "linux: Dir.personal_config_path 抛错 ⇒ pcall 兜住, 回落 HOME",
      env = { HOME = "/home/u" }, dir = "throw", files = {},
      expect_path = "/home/u/.config/wireshark/language", expect_english = true },
    { name = "windows: %APPDATA%\\Wireshark\\language",
      env = { APPDATA = "C:\\Users\\u\\AppData\\Roaming" }, win = true,
      files = { ["C:\\Users\\u\\AppData\\Roaming\\Wireshark\\language"] = "language: zh_CN\n" },
      expect_path = "C:\\Users\\u\\AppData\\Roaming\\Wireshark\\language", expect_english = false },
    { name = "windows: 无 APPDATA、无 Dir ⇒ 不打开文件, 不报错",
      env = { HOME = "C:\\Users\\u" }, win = true, files = {}, expect_path = nil, expect_english = true },
    -- system_is_chinese(): 非 Windows 只看 LC_ALL > LC_MESSAGES > LANG(> LANGUAGE), 绝不 io.popen("reg query ... 2>nul")
    -- (POSIX shell 会把 2>nul 当成重定向到 cwd 下名为 nul 的文件并创建它)
    { name = "linux: LC_ALL=zh_CN 覆盖 LANG=en_US ⇒ 中文",
      env = { LC_ALL = "zh_CN.UTF-8", LANG = "en_US.UTF-8" }, files = {}, expect_path = nil, expect_english = false },
    { name = "linux: LC_ALL=C 覆盖 LANG=zh_CN ⇒ 英文",
      env = { LC_ALL = "C", LANG = "zh_CN.UTF-8" }, files = {}, expect_path = nil, expect_english = true },
    { name = "linux: LC_MESSAGES=zh_TW 覆盖 LANG=en_US ⇒ 中文",
      env = { LC_MESSAGES = "zh_TW.UTF-8", LANG = "en_US.UTF-8" }, files = {}, expect_path = nil, expect_english = false },
    { name = "linux: 仅 LANGUAGE=zh_CN:en ⇒ 中文",
      env = { LANGUAGE = "zh_CN:en" }, files = {}, expect_path = nil, expect_english = false },
    { name = "macOS: language 文件 system ⇒ 跟随 LANG=zh, 不调 reg query",
      env = { HOME = "/Users/u", LANG = "zh_CN.UTF-8" }, files = { ["/Users/u/.config/wireshark/language"] = "language: system\n" },
      expect_path = "/Users/u/.config/wireshark/language", expect_english = false },
    { name = "windows: 无 LANG ⇒ 查注册表 LocaleName=zh-CN ⇒ 中文",
      env = { APPDATA = "C:\\A" }, win = true, reg = "    LocaleName    REG_SZ    zh-CN\r\n",
      files = {}, expect_path = "C:\\A\\Wireshark\\language", expect_english = false, expect_reg = true },
    { name = "windows: 无 LANG ⇒ 查注册表 LocaleName=en-US ⇒ 英文",
      env = { APPDATA = "C:\\A" }, win = true, reg = "    LocaleName    REG_SZ    en-US\r\n",
      files = {}, expect_path = "C:\\A\\Wireshark\\language", expect_english = true, expect_reg = true },
    { name = "环境变量覆盖仍优先(HPLC_RF_LANG / NW_2021_LANG = zh), 不读文件",
      env = { HPLC_RF_LANG = "zh", NW_2021_LANG = "zh", HOME = "/home/u" },
      files = { ["/home/u/.config/wireshark/language"] = "language: en\n" },
      expect_path = nil, expect_english = false },
}

local function is_english(s) return type(s) == "string" and not s:find("[\128-\255]") end

local function run_one(plugin, sc)
    local opened, popens, proto_desc = {}, {}, nil
    local env = sc.env
    -- 新的全局环境: 真实标准库 + stub 兜底 + 受控的 Dir/Proto
    local G = {}
    for k, v in pairs(_G) do G[k] = v end
    G._G = G
    G.os = setmetatable({ getenv = function(k) return env[k] end }, { __index = os })
    G.io = setmetatable({
        open = function(path, mode)
            if type(path) == "string" and path:match("language$") then
                opened[#opened + 1] = path
                local c = sc.files[path]
                if not c then return nil, path .. ": No such file or directory" end
                return { read = function() return c end, close = function() end }
            end
            return real_open(path, mode)   -- 与真实 io.open 一致: path 为 nil 时抛 bad argument
        end,
        -- 不真的执行命令: 记录调用; sc.reg 为模拟的 reg query 输出
        popen = function(cmd)
            popens[#popens + 1] = tostring(cmd)
            if sc.reg then
                local out = sc.reg
                return { read = function() return out end, close = function() return true end }
            end
            return nil
        end,
    }, { __index = io })
    G.package = setmetatable({ config = sc.win and WIN_CONFIG or NIX_CONFIG }, { __index = package })
    if sc.dir == "ok" then
        G.Dir = { personal_config_path = function(f) return "/wsconf/" .. (f or "") end }
    elseif sc.dir == "throw" then
        G.Dir = { personal_config_path = function() error("personal_config_path unavailable") end }
    end
    G.Proto = function(name, desc)
        if proto_desc == nil then proto_desc = desc end
        return new_stub()
    end
    setmetatable(G, { __index = function(_, k)
        if k == "Dir" then return nil end
        return new_stub()
    end })
    local chunk, err = loadfile(PLUGIN_DIR .. "/" .. plugin, "t", G)
    if not chunk then return false, "loadfile: " .. tostring(err) end
    local ok, perr = pcall(chunk)
    if not ok then return false, "加载报错: " .. tostring(perr) end
    local got = opened[1]
    if #opened > 1 then return false, "打开了多个 language 文件: " .. table.concat(opened, ", ") end
    if got ~= sc.expect_path then
        return false, string.format("语言文件路径 期望 %s 实际 %s", tostring(sc.expect_path), tostring(got))
    end
    -- 非 Windows 一律不得 io.popen(旧代码在 Linux/macOS 跑 reg query ... 2>nul, 在 cwd 生成 nul 文件)
    if not sc.win and #popens > 0 then
        return false, "非 Windows 调用了 io.popen: " .. table.concat(popens, " | ")
    end
    if sc.expect_reg then
        if #popens ~= 1 or not popens[1]:find("reg query", 1, true) then
            return false, "Windows 应恰好查一次注册表, 实际 popen: " .. (#popens > 0 and table.concat(popens, " | ") or "(无)")
        end
    end
    if is_english(proto_desc) ~= sc.expect_english then
        return false, string.format("语言 期望 %s 实际 %s (Proto 描述: %s)",
            sc.expect_english and "英文" or "中文", is_english(proto_desc) and "英文" or "中文", tostring(proto_desc))
    end
    return true, tostring(got)
end

local fails, total = 0, 0
for _, sc in ipairs(SCEN) do
    print("== " .. sc.name)
    for _, p in ipairs(PLUGINS) do
        total = total + 1
        local ok, msg = run_one(p, sc)
        print(string.format("  %s %-20s %s", ok and "PASS" or "FAIL", p, msg))
        if not ok then fails = fails + 1 end
    end
end
-- ---------- 真实 io.popen: 非 Windows 加载插件后 cwd 不得出现 nul 文件 ----------
-- run.sh 在一个空的临时目录里运行本脚本(arg[2] = "real-popen-cwd-ok")。这里不替换 io.popen,
-- 环境变量全空(让插件走到 system_is_chinese 的注册表分支): 旧代码会真的执行
-- `reg query ... 2>nul`, /bin/sh 把 stderr 重定向到 ./nul 并创建该文件。
if package.config:sub(1, 1) ~= "\\" and arg[2] == "real-popen-cwd-ok" then
    print("== 真实 io.popen: 非 Windows 加载后 cwd 无 nul 文件")
    local pre = real_open("nul", "r")
    if pre then pre:close(); os.remove("nul") end
    for _, p in ipairs(PLUGINS) do
        total = total + 1
        local G = {}
        for k, v in pairs(_G) do G[k] = v end
        G._G = G
        G.os = setmetatable({ getenv = function() return nil end }, { __index = os })
        G.Proto = function() return new_stub() end
        setmetatable(G, { __index = function(_, k) if k == "Dir" then return nil end return new_stub() end })
        local chunk, err = loadfile(PLUGIN_DIR .. "/" .. p, "t", G)
        local ok, perr = false, err
        if chunk then ok, perr = pcall(chunk) end
        local nul = real_open("nul", "r")
        local msg
        if not ok then
            msg = "加载报错: " .. tostring(perr)
        elseif nul then
            msg = "cwd 生成了 nul 文件(执行了 reg query ... 2>nul)"
        end
        if nul then nul:close(); os.remove("nul") end
        print(string.format("  %s %-20s %s", msg and "FAIL" or "PASS", p, msg or "no nul"))
        if msg then fails = fails + 1 end
    end
end

-- 防止 stub 环境泄漏到宿主
assert(os.getenv == real_getenv and io.open == real_open and io.popen == real_popen and package.config == real_config)
print(string.format("RESULT: %s (%d/%d passed, %d failures)", fails == 0 and "ALL PASS" or "FAIL", total - fails, total, fails))
os.exit(fails == 0 and 0 or 1)
