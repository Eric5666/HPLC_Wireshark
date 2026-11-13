/// @file lua_backend.cpp
#include "lua_backend.h"

#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QImage>
#include <QPainter>

#include "plugin_env.h"
#include "script_painter.h"

extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
}

/// @brief 单次脚本调用的指令计数(lua_getextraspace 存其指针,协程继承)
struct LuaBudget {
    quint64 used = 0;
    quint64 limit = 0;
    lua_State* main = nullptr;  ///< 主线程(超限时一并切逐条触发)
};

namespace {
// ---- 指令预算(M10):每个脚本入口一次 pcall 的指令数上限 ----
// count hook 每 kLuaHookStep 条 VM 指令触发一次,累计超过预算即在脚本内
// 抛 Lua 错误;死循环(含 pcall 包裹的死循环:超限后每次 hook 都再抛)
// 在有限时间内结束,宿主进程不再被单个插件占满 CPU。
constexpr int kLuaHookStep = 1000;
constexpr quint64 kDefaultLuaInstrBudget = 200000000ull;  // ~1-3 s
/// @brief 每次调用的指令预算;环境变量 BPLC_LUA_INSTR_BUDGET 可覆盖(测试用)
quint64 lua_instr_budget() {
    bool ok = false;
    const quint64 v = qEnvironmentVariable("BPLC_LUA_INSTR_BUDGET").toULongLong(&ok);
    return (ok && v >= quint64(kLuaHookStep)) ? v : kDefaultLuaInstrBudget;
}
LuaBudget* budget_of(lua_State* L) {
    return *static_cast<LuaBudget**>(lua_getextraspace(L));
}
void budget_hook(lua_State* L, lua_Debug*) {
    LuaBudget* b = budget_of(L);
    if (!b) return;
    const int step = lua_gethookcount(L);
    b->used += quint64(step > 0 ? step : kLuaHookStep);
    if (b->used > b->limit) {
        // 超限后把主线程和当前协程都切到“每条指令都触发”:错误若被脚本内
        // pcall/xpcall/协程接住,外层下一条指令立即再抛,最终逃出脚本入口
        if (b->main) lua_sethook(b->main, budget_hook, LUA_MASKCOUNT, 1);
        lua_sethook(L, budget_hook, LUA_MASKCOUNT, 1);
        luaL_error(L, "instruction budget exceeded (%I instructions per call)",
                   static_cast<lua_Integer>(b->limit));
    }
    if (step != kLuaHookStep)  // 上次超限遗留的逐条触发:新一次调用恢复步长
        lua_sethook(L, budget_hook, LUA_MASKCOUNT, kLuaHookStep);
}
/// @brief 所有脚本入口统一走这里:清零本次预算再 lua_pcall
int guarded_pcall(lua_State* L, int nargs, int nresults) {
    if (LuaBudget* b = budget_of(L)) b->used = 0;
    lua_sethook(L, budget_hook, LUA_MASKCOUNT, kLuaHookStep);
    return lua_pcall(L, nargs, nresults, 0);
}
// QByteArray → Lua 数组表(1-based),留在栈顶
void push_byte_table(lua_State* L, const QByteArray& b) {
    lua_newtable(L);
    for (int i = 0; i < b.size(); ++i) {
        lua_pushinteger(L, static_cast<unsigned char>(b[i]));
        lua_seti(L, -2, i + 1);
    }
}
// 栈顶错误 → QString 并清栈
QString pop_lua_error(lua_State* L) {
    QString e = QString::fromUtf8(lua_tostring(L, -1));
    lua_pop(L, 1);
    return e;
}
// QVariant → Lua 值压栈(保留 bool/number/string 类型)
void push_qvariant(lua_State* L, const QVariant& v) {
    switch (v.typeId()) {
    case QMetaType::Bool:
        lua_pushboolean(L, v.toBool());
        break;
    case QMetaType::Int:
    case QMetaType::UInt:
    case QMetaType::LongLong:
    case QMetaType::ULongLong:
    case QMetaType::Double:
        lua_pushnumber(L, v.toDouble());
        break;
    default:
        lua_pushstring(L, v.toString().toUtf8().constData());
        break;
    }
}

// TopoEventKind → Lua 可读字符串
const char* topo_kind_name_lua(TopoEventKind k) {
    switch (k) {
    case TopoEventKind::DiscoverList:   return "discoverList";
    case TopoEventKind::AssocReq:       return "assocReq";
    case TopoEventKind::AssocCnf:       return "assocCnf";
    case TopoEventKind::AssocGatherInd: return "assocGatherInd";
    case TopoEventKind::AssocInd:       return "assocInd";
    case TopoEventKind::ChangeProxyReq: return "changeProxyReq";
    case TopoEventKind::ChangeProxyCnf: return "changeProxyCnf";
    case TopoEventKind::LeaveInd:      return "leaveInd";
    case TopoEventKind::SuccessRate:    return "successRate";
    case TopoEventKind::CcoRestart:     return "ccoRestart";
    case TopoEventKind::StaRestart:     return "staRestart";
    case TopoEventKind::ChannelInfo:    return "channelInfo";
    case TopoEventKind::PowerOff:       return "powerOff";
    case TopoEventKind::PowerOn:        return "powerOn";
    default:                           return "other";
    }
}

// MAC 48-bit → "aa:bb:cc:dd:ee:ff"(帧内字节序,与原版 TopoWindow 一致)
QString format_mac_lua(quint64 v) {
    QString s;
    for (int i = 0; i < 6; ++i) {
        s += QStringLiteral("%1").arg((v >> (8 * i)) & 0xFF, 2, 16, QChar('0'));
        if (i < 5) s += QLatin1Char(':');
    }
    return s;
}
inline void push_mac_field(lua_State* L, quint64 mac, const char* key) {
    const QByteArray m = format_mac_lua(mac).toUtf8();
    lua_pushlstring(L, m.constData(), m.size());
    lua_setfield(L, -2, key);
}

// TopoEvent → Lua evt 表,留在栈顶
void push_topo_event_table(lua_State* L, const TopoEvent& e) {
    lua_newtable(L);
    lua_pushstring(L, topo_kind_name_lua(e.kind));
    lua_setfield(L, -2, "kind");
    lua_pushinteger(L, e.nid);
    lua_setfield(L, -2, "nid");
    // ccoMac:无 CCO 的事件置 nil(零 MAC 不发 "00:.." 字符串,避免脚本误判)
    if (e.cco_mac != 0)
        push_mac_field(L, e.cco_mac, "ccoMac");
    else {
        lua_pushnil(L);
        lua_setfield(L, -2, "ccoMac");
    }
    lua_newtable(L);  // nodes: {{tei, mac}...}
    for (int i = 0; i < e.nodes.size(); ++i) {
        lua_newtable(L);
        lua_pushinteger(L, e.nodes[i].tei);
        lua_setfield(L, -2, "tei");
        push_mac_field(L, e.nodes[i].mac, "mac");
        lua_seti(L, -2, i + 1);
    }
    lua_setfield(L, -2, "nodes");
    lua_newtable(L);  // routes: {{child, parent}...}
    for (int i = 0; i < e.routes.size(); ++i) {
        lua_newtable(L);
        lua_pushinteger(L, e.routes[i].first);
        lua_setfield(L, -2, "child");
        lua_pushinteger(L, e.routes[i].second);
        lua_setfield(L, -2, "parent");
        lua_seti(L, -2, i + 1);
    }
    lua_setfield(L, -2, "routes");
    lua_newtable(L);  // upRoutes: {{sta, nextHop}...},仅 RouteType=3
    for (int i = 0; i < e.up_routes.size(); ++i) {
        lua_newtable(L);
        lua_pushinteger(L, e.up_routes[i].first);
        lua_setfield(L, -2, "sta");
        lua_pushinteger(L, e.up_routes[i].second);
        lua_setfield(L, -2, "nextHop");
        lua_seti(L, -2, i + 1);
    }
    lua_setfield(L, -2, "upRoutes");
    lua_pushinteger(L, e.discover_src_tei);
    lua_setfield(L, -2, "discoverSrcTei");
    lua_newtable(L);  // neighborTeis
    for (int i = 0; i < e.neighbor_teis.size(); ++i) {
        lua_pushinteger(L, e.neighbor_teis[i]);
        lua_seti(L, -2, i + 1);
    }
    lua_setfield(L, -2, "neighborTeis");
    lua_newtable(L);  // leaves: {"aa:bb:.."...}
    for (int i = 0; i < e.leaves.size(); ++i) {
        const QByteArray m = format_mac_lua(e.leaves[i]).toUtf8();
        lua_pushlstring(L, m.constData(), m.size());
        lua_seti(L, -2, i + 1);
    }
    lua_setfield(L, -2, "leaves");
    lua_newtable(L);  // commRates: {{tei, down, up}...}
    for (int i = 0; i < e.comm_rates.size(); ++i) {
        lua_newtable(L);
        lua_pushinteger(L, e.comm_rates[i].tei);
        lua_setfield(L, -2, "tei");
        lua_pushinteger(L, e.comm_rates[i].down);
        lua_setfield(L, -2, "down");
        lua_pushinteger(L, e.comm_rates[i].up);
        lua_setfield(L, -2, "up");
        lua_seti(L, -2, i + 1);
    }
    lua_setfield(L, -2, "commRates");
    lua_pushboolean(L, e.is_rf);
    lua_setfield(L, -2, "isRf");
    lua_pushinteger(L, e.restart_count);
    lua_setfield(L, -2, "restartCount");
    const QByteArray desc = e.desc.toUtf8();
    lua_pushlstring(L, desc.constData(), desc.size());
    lua_setfield(L, -2, "desc");
    lua_pushnumber(L, static_cast<lua_Number>(e.epoch_ms));
    lua_setfield(L, -2, "epochMs");
    lua_pushnumber(L, static_cast<lua_Number>(e.frame_index));
    lua_setfield(L, -2, "frameIndex");
}

// ---- Lua 绘图绑定: p 表的 C 函数,QPainter* 经 upvalue 传入 ----
namespace {
ScriptPainter* painter_upvalue(lua_State* L) {
    return static_cast<ScriptPainter*>(lua_touserdata(L, lua_upvalueindex(1)));
}
int l_set_pen(lua_State* L) {
    painter_upvalue(L)->set_pen(QString::fromUtf8(luaL_checkstring(L, 1)),
                                luaL_optnumber(L, 2, 1.0));
    return 0;
}
int l_set_brush(lua_State* L) {
    painter_upvalue(L)->set_brush(QString::fromUtf8(luaL_checkstring(L, 1)));
    return 0;
}
int l_no_brush(lua_State* L) {
    painter_upvalue(L)->no_brush();
    return 0;
}
int l_no_pen(lua_State* L) {
    painter_upvalue(L)->no_pen();
    return 0;
}
int l_set_font(lua_State* L) {
    painter_upvalue(L)->set_font(QString::fromUtf8(luaL_checkstring(L, 1)),
                                 static_cast<int>(luaL_checkinteger(L, 2)),
                                 lua_toboolean(L, 3));
    return 0;
}
int l_clear(lua_State* L) {
    painter_upvalue(L)->clear(QString::fromUtf8(luaL_checkstring(L, 1)));
    return 0;
}
int l_draw_line(lua_State* L) {
    painter_upvalue(L)->draw_line(luaL_checknumber(L, 1), luaL_checknumber(L, 2),
                                  luaL_checknumber(L, 3), luaL_checknumber(L, 4));
    return 0;
}
int l_draw_rect(lua_State* L) {
    painter_upvalue(L)->draw_rect(luaL_checknumber(L, 1), luaL_checknumber(L, 2),
                                  luaL_checknumber(L, 3), luaL_checknumber(L, 4));
    return 0;
}
int l_fill_rect(lua_State* L) {
    painter_upvalue(L)->fill_rect(luaL_checknumber(L, 1), luaL_checknumber(L, 2),
                                  luaL_checknumber(L, 3), luaL_checknumber(L, 4),
                                  QString::fromUtf8(luaL_checkstring(L, 5)));
    return 0;
}
int l_draw_ellipse(lua_State* L) {
    painter_upvalue(L)->draw_ellipse(luaL_checknumber(L, 1), luaL_checknumber(L, 2),
                                     luaL_checknumber(L, 3), luaL_checknumber(L, 4));
    return 0;
}
int l_draw_text(lua_State* L) {
    painter_upvalue(L)->draw_text(luaL_checknumber(L, 1), luaL_checknumber(L, 2),
                                  QString::fromUtf8(luaL_checkstring(L, 3)));
    return 0;
}
int l_text_width(lua_State* L) {
    lua_pushnumber(L, painter_upvalue(L)->text_width(
                          QString::fromUtf8(luaL_checkstring(L, 1))));
    return 1;
}
int l_draw_point(lua_State* L) {
    painter_upvalue(L)->draw_point(luaL_checknumber(L, 1), luaL_checknumber(L, 2));
    return 0;
}
int l_draw_icon(lua_State* L) {
    painter_upvalue(L)->draw_icon(QString::fromUtf8(luaL_checkstring(L, 1)),
                                  luaL_checknumber(L, 2), luaL_checknumber(L, 3),
                                  luaL_checknumber(L, 4), luaL_checknumber(L, 5));
    return 0;
}
const luaL_Reg kPainterFuncs[] = {
    {"set_pen", l_set_pen}, {"set_brush", l_set_brush},
    {"no_brush", l_no_brush}, {"no_pen", l_no_pen},
    {"set_font", l_set_font}, {"clear", l_clear},
    {"draw_line", l_draw_line}, {"draw_rect", l_draw_rect},
    {"fill_rect", l_fill_rect}, {"draw_ellipse", l_draw_ellipse},
    {"draw_text", l_draw_text}, {"text_width", l_text_width},
    {"draw_point", l_draw_point},
    {"draw_icon", l_draw_icon},
    {nullptr, nullptr}
};
/// @brief 压入绘图 p 表(函数 upvalue 绑定 bridge)
void push_painter_table(lua_State* L, ScriptPainter* bridge) {
    lua_newtable(L);
    lua_pushlightuserdata(L, bridge);
    luaL_setfuncs(L, kPainterFuncs, 1);
}
} // namespace
} // namespace

namespace {
// ===== 插件 Lua 沙箱 =====
// 插件脚本来自市场/离线包,不可信:只开放 base/package/coroutine/table/string/
// math/utf8 与 os 的只读时间函数;不开放 io/debug、os.execute/exit/remove/rename/
// getenv/tmpname/setlocale、C 模块加载(package.loadlib/cpath/C searcher);
// dofile/loadfile 只能读插件目录内的文件;load/loadfile/dofile 只接受文本 chunk
// (恶意字节码可绕过 Lua VM 校验)。环境变量请用 host.getEnv。

/// 解析插件目录内的脚本路径(相对路径相对插件目录);越界返回空串
QString sandbox_plugin_path(lua_State* L, const char* fname) {
    const QString dir = QString::fromUtf8(lua_tostring(L, lua_upvalueindex(1)));
    const QString root = QFileInfo(dir).canonicalFilePath();
    const QString path = QDir(dir).absoluteFilePath(QString::fromUtf8(fname));
    const QString real = QFileInfo(path).canonicalFilePath();
    if (root.isEmpty() || real.isEmpty() ||
        !real.startsWith(root + QLatin1Char('/')))
        return QString();
    return real;
}

/// loadfile(filename [, mode [, env]]):仅插件目录内、仅文本 chunk
int l_sandbox_loadfile(lua_State* L) {
    const char* fname = luaL_optstring(L, 1, nullptr);
    const bool has_env = !lua_isnone(L, 3);
    if (!fname) {
        luaL_pushfail(L);
        lua_pushliteral(L, "loadfile: stdin is not available to plugins");
        return 2;
    }
    const QString path = sandbox_plugin_path(L, fname);
    if (path.isEmpty()) {
        luaL_pushfail(L);
        lua_pushfstring(L, "loadfile: '%s' is outside the plugin directory", fname);
        return 2;
    }
    const QByteArray p = path.toUtf8();  // 与入口脚本加载同口径
    if (luaL_loadfilex(L, p.constData(), "t") != LUA_OK) {
        luaL_pushfail(L);
        lua_insert(L, -2);
        return 2;  // nil, message
    }
    if (has_env) {
        lua_pushvalue(L, 3);
        if (!lua_setupvalue(L, -2, 1)) lua_pop(L, 1);  // 设为首个 upvalue(_ENV)
    }
    return 1;
}

/// dofile(filename):仅插件目录内、仅文本 chunk
int l_sandbox_dofile(lua_State* L) {
    const char* fname = luaL_checkstring(L, 1);
    const QString path = sandbox_plugin_path(L, fname);
    if (path.isEmpty())
        return luaL_error(L, "dofile: '%s' is outside the plugin directory", fname);
    lua_settop(L, 1);
    const QByteArray p = path.toUtf8();  // 与入口脚本加载同口径
    if (luaL_loadfilex(L, p.constData(), "t") != LUA_OK) return lua_error(L);
    lua_call(L, 0, LUA_MULTRET);
    return lua_gettop(L) - 1;
}

/// load(chunk [, chunkname [, mode [, env]]]):转调原 load,mode 强制 "t"
int l_sandbox_load(lua_State* L) {
    const bool has_env = lua_gettop(L) >= 4;  // 不传 env 时保持「无 env」语义
    lua_settop(L, 4);                         // chunk, chunkname, mode, env(缺省补 nil)
    lua_pushvalue(L, lua_upvalueindex(1));    // 原 load
    lua_pushvalue(L, 1);
    lua_pushvalue(L, 2);
    lua_pushliteral(L, "t");
    if (has_env) lua_pushvalue(L, 4);
    lua_call(L, has_env ? 4 : 3, LUA_MULTRET);
    return lua_gettop(L) - 4;
}

/// require 的 Lua 文件搜索器:按 package.path 查找,但只加载插件目录内的文本 chunk
int l_sandbox_lua_searcher(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    lua_settop(L, 1);
    lua_getglobal(L, LUA_LOADLIBNAME);   // 2
    lua_getfield(L, 2, "searchpath");    // 3
    lua_pushstring(L, name);
    lua_getfield(L, 2, "path");
    lua_call(L, 2, 2);                   // 3: filename | nil, 4: 未找到说明
    if (lua_isnil(L, 3)) {
        lua_pushvalue(L, 4);
        return 1;
    }
    const char* fname = lua_tostring(L, 3);
    const QString path = sandbox_plugin_path(L, fname);
    if (path.isEmpty()) {
        lua_pushfstring(L, "\n\tmodule file '%s' is outside the plugin directory", fname);
        return 1;
    }
    const QByteArray p = path.toUtf8();  // 与入口脚本加载同口径
    if (luaL_loadfilex(L, p.constData(), "t") != LUA_OK)
        return luaL_error(L, "error loading module '%s' from file '%s':\n\t%s",
                          name, fname, lua_tostring(L, -1));
    lua_pushvalue(L, 3);  // 第二返回值:文件名(传给模块)
    return 2;
}

/// 打开受限标准库并装好沙箱(替代 luaL_openlibs)
void open_sandboxed_libs(lua_State* L, const QString& plugin_dir) {
    static const luaL_Reg kLibs[] = {
        {LUA_GNAME, luaopen_base},          {LUA_LOADLIBNAME, luaopen_package},
        {LUA_COLIBNAME, luaopen_coroutine}, {LUA_TABLIBNAME, luaopen_table},
        {LUA_STRLIBNAME, luaopen_string},   {LUA_MATHLIBNAME, luaopen_math},
        {LUA_UTF8LIBNAME, luaopen_utf8},    {LUA_OSLIBNAME, luaopen_os},
        {nullptr, nullptr}};
    for (const luaL_Reg* lib = kLibs; lib->func; ++lib) {
        luaL_requiref(L, lib->name, lib->func, 1);
        lua_pop(L, 1);
    }
    // os:只保留 clock/date/difftime/time
    lua_getglobal(L, LUA_OSLIBNAME);
    for (const char* k : {"execute", "exit", "getenv", "remove", "rename",
                          "setlocale", "tmpname"}) {
        lua_pushnil(L);
        lua_setfield(L, -2, k);
    }
    lua_pop(L, 1);

    const QByteArray dir = QDir(plugin_dir).absolutePath().toUtf8();
    // package:require 只搜插件目录内的 Lua 文件;禁止 C 模块
    lua_getglobal(L, LUA_LOADLIBNAME);
    lua_pushfstring(L, "%s/?.lua;%s/?/init.lua", dir.constData(), dir.constData());
    lua_setfield(L, -2, "path");
    lua_pushliteral(L, "");
    lua_setfield(L, -2, "cpath");
    lua_pushnil(L);
    lua_setfield(L, -2, "loadlib");
    lua_getfield(L, -1, "searchers");  // {preload, Lua, C, Croot} → preload + 受限 Lua 搜索器
    if (lua_istable(L, -1)) {
        for (lua_Integer i = luaL_len(L, -1); i > 2; --i) {
            lua_pushnil(L);
            lua_seti(L, -2, i);
        }
        lua_pushstring(L, dir.constData());
        lua_pushcclosure(L, l_sandbox_lua_searcher, 1);
        lua_seti(L, -2, 2);
    }
    lua_pop(L, 2);

    // base:dofile/loadfile 限插件目录;load 只收文本
    lua_pushstring(L, dir.constData());
    lua_pushcclosure(L, l_sandbox_loadfile, 1);
    lua_setglobal(L, "loadfile");
    lua_pushstring(L, dir.constData());
    lua_pushcclosure(L, l_sandbox_dofile, 1);
    lua_setglobal(L, "dofile");
    lua_getglobal(L, "load");
    lua_pushcclosure(L, l_sandbox_load, 1);
    lua_setglobal(L, "load");
}
}  // namespace

LuaBackend::LuaBackend() = default;

LuaBackend::~LuaBackend() {
    shutdown();
}

bool LuaBackend::initialize(const PluginManifest& m, QString* err) {
    if (m.api_version != 1) {
        *err = QStringLiteral("api_version mismatch");
        return false;
    }
    m_lua = luaL_newstate();
    if (!m_lua) {
        *err = QStringLiteral("luaL_newstate failed");
        return false;
    }
    m_budget.reset(new LuaBudget);
    m_budget->limit = lua_instr_budget();
    m_budget->main = m_lua;
    *static_cast<LuaBudget**>(lua_getextraspace(m_lua)) = m_budget.get();
    lua_sethook(m_lua, budget_hook, LUA_MASKCOUNT, kLuaHookStep);
    m_plugin_dir = m.dir_path;
    open_sandboxed_libs(m_lua, m_plugin_dir);   // 受限标准库(不再 luaL_openlibs)

    // 加载时再做一次包含检查(防 manifest 校验后入口被替换为越界符号链接)
    const QString lua_path = plugin_contained_entry_path(m.dir_path, m.runtime, m.entry);
    if (lua_path.isEmpty()) {
        *err = QStringLiteral("entry outside plugin dir: %1").arg(m.entry);
        return false;
    }
    const QByteArray path_utf8 = lua_path.toUtf8();
    if (luaL_loadfilex(m_lua, path_utf8.constData(), "t") != LUA_OK) {  // 只收文本(拒字节码)
        *err = QStringLiteral("load %1: %2").arg(m.entry, pop_lua_error(m_lua));
        return false;
    }
    if (guarded_pcall(m_lua, 0, 0) != LUA_OK) {
        *err = QStringLiteral("run %1: %2").arg(m.entry, pop_lua_error(m_lua));
        return false;
    }

    // get_info()
    lua_getglobal(m_lua, "get_info");
    if (!lua_isfunction(m_lua, -1)) {
        *err = QStringLiteral("missing function get_info()");
        lua_pop(m_lua, 1);
        return false;
    }
    if (guarded_pcall(m_lua, 0, 1) != LUA_OK) {
        *err = QStringLiteral("get_info: %1").arg(pop_lua_error(m_lua));
        return false;
    }
    if (!lua_istable(m_lua, -1)) {
        *err = QStringLiteral("get_info() must return a table");
        lua_pop(m_lua, 1);
        return false;
    }
    m_protocol_id = table_str("protocolId");
    m_display_name = table_str("displayName");
    lua_pop(m_lua, 1);
    if (m_protocol_id.isEmpty()) {
        *err = QStringLiteral("get_info() missing protocolId");
        return false;
    }
    if (m_protocol_id != m.protocol_id) {
        *err = QStringLiteral("protocolId mismatch: manifest=%1 script=%2")
                   .arg(m.protocol_id, m_protocol_id);
        return false;
    }

    lua_getglobal(m_lua, "parse");
    if (!lua_isfunction(m_lua, -1)) {
        *err = QStringLiteral("missing function parse(frame)");
        lua_pop(m_lua, 1);
        return false;
    }
    lua_pop(m_lua, 1);  // 每次 parse 重新取(脚本可能热替换)

    // 图形函数(可选,manifest graphics=true 时必需)
    lua_getglobal(m_lua, "render");
    m_has_graphics = lua_isfunction(m_lua, -1);
    lua_pop(m_lua, 1);
    if (m.graphics && !m_has_graphics) {
        *err = QStringLiteral("manifest graphics=true but missing function render(p,w,h)");
        return false;
    }

    // 全局 request_redraw():脚本主动请求重绘
    LuaBackend* self = this;
    lua_pushlightuserdata(m_lua, self);
    lua_pushcclosure(m_lua, [](lua_State* L) -> int {
        auto* backend = static_cast<LuaBackend*>(lua_touserdata(L, lua_upvalueindex(1)));
        if (backend->m_redraw_cb) backend->m_redraw_cb();
        return 0;
    }, 1);
    lua_setglobal(m_lua, "request_redraw");

    // host 界面控制表:host.jumpToFrame(frameIndex)
    // + 插件设置 host.getSetting(key, default)
    // + 公共环境变量 host.getEnv(name)
    lua_newtable(m_lua);
    lua_pushlightuserdata(m_lua, self);
    lua_pushcclosure(m_lua, [](lua_State* L) -> int {
        auto* backend = static_cast<LuaBackend*>(lua_touserdata(L, lua_upvalueindex(1)));
        const qint64 idx = static_cast<qint64>(lua_tonumber(L, 1));
        if (backend->m_host_jump_cb) backend->m_host_jump_cb(idx);
        return 0;
    }, 1);
    lua_setfield(m_lua, -2, "jumpToFrame");
    lua_pushlightuserdata(m_lua, self);
    lua_pushcclosure(m_lua, [](lua_State* L) -> int {
        auto* backend = static_cast<LuaBackend*>(lua_touserdata(L, lua_upvalueindex(1)));
        const QString key =
            QString::fromUtf8(lua_tostring(L, 1));
        QVariant def;
        if (!lua_isnoneornil(L, 2)) {
            if (lua_isboolean(L, 2))
                def = QVariant(bool(lua_toboolean(L, 2)));
            else if (lua_isnumber(L, 2))
                def = QVariant(lua_tonumber(L, 2));
            else
                def = QVariant(QString::fromUtf8(lua_tostring(L, 2)));
        }
        const QVariant v =
            plugin_setting_value(backend->m_plugin_dir, key, def);
        push_qvariant(L, v.isValid() ? v : def);
        return 1;
    }, 1);
    lua_setfield(m_lua, -2, "getSetting");
    lua_pushlightuserdata(m_lua, self);
    lua_pushcclosure(m_lua, [](lua_State* L) -> int {
        auto* backend = static_cast<LuaBackend*>(lua_touserdata(L, lua_upvalueindex(1)));
        const QString name =
            QString::fromUtf8(lua_tostring(L, 1));
        lua_pushstring(
            L, plugin_env_value(name, backend->m_plugin_dir,
                                backend->m_ui_english).toUtf8().constData());
        return 1;
    }, 1);
    lua_setfield(m_lua, -2, "getEnv");
    lua_setglobal(m_lua, "host");
    return true;
}

void LuaBackend::shutdown() {
    if (m_lua) { lua_close(m_lua); m_lua = nullptr; }
    m_budget.reset();
    m_has_graphics = false;
}

QString LuaBackend::protocol_id() const {
    return m_protocol_id;
}

bool LuaBackend::has_graphics() const {
    return m_has_graphics;
}

QSize LuaBackend::graphics_preferred_size() const {
    return QSize(400, 300);
}

QImage LuaBackend::render_graphics(int w, int h, QString* err) {
    if (!m_has_graphics) {
        *err = QStringLiteral("no graphics");
        return QImage();
    }
    if (w <= 0 || h <= 0 || w > 4096 || h > 4096) {
        *err = QStringLiteral("bad size");
        return QImage();
    }
    QImage img(w, h, QImage::Format_ARGB32);
    img.fill(Qt::white);
    QPainter painter(&img);
    painter.setRenderHint(QPainter::Antialiasing);
    ScriptPainter bridge(&painter);

    lua_getglobal(m_lua, "render");
    if (!lua_isfunction(m_lua, -1)) {
        *err = QStringLiteral("render() not found");
        lua_pop(m_lua, 1);
        return QImage();
    }
    push_painter_table(m_lua, &bridge);
    lua_pushinteger(m_lua, w);
    lua_pushinteger(m_lua, h);
    if (guarded_pcall(m_lua, 3, 0) != LUA_OK) {
        *err = QStringLiteral("render: %1").arg(pop_lua_error(m_lua));
        return QImage();
    }
    painter.end();
    return img;
}

bool LuaBackend::handle_graphics_event(const GraphicsEvent& e, QString* err) {
    if (!m_has_graphics) return false;
    lua_getglobal(m_lua, "on_event");
    if (!lua_isfunction(m_lua, -1)) {
        lua_pop(m_lua, 1);
        return false;
    }
    lua_pushinteger(m_lua, static_cast<int>(e.type));
    lua_pushinteger(m_lua, e.x);
    lua_pushinteger(m_lua, e.y);
    lua_pushinteger(m_lua, e.button);
    lua_pushinteger(m_lua, e.modifiers);
    lua_pushinteger(m_lua, e.delta_y);
    if (guarded_pcall(m_lua, 6, 1) != LUA_OK) {
        *err = QStringLiteral("on_event: %1").arg(pop_lua_error(m_lua));
        return false;
    }
    const bool redraw = lua_toboolean(m_lua, -1);
    lua_pop(m_lua, 1);
    return redraw;
}

QString LuaBackend::table_str(const char* key, const QString& d) {
    QString r = d;
    if (lua_getfield(m_lua, -1, key) == LUA_TSTRING)
        r = QString::fromUtf8(lua_tostring(m_lua, -1));
    lua_pop(m_lua, 1);
    return r;
}

quint64 LuaBackend::table_uint(const char* key, quint64 d) {
    quint64 r = d;
    if (lua_isinteger(m_lua, lua_getfield(m_lua, -1, key)))
        r = static_cast<quint64>(lua_tointeger(m_lua, -1));
    else if (lua_isnumber(m_lua, -1))
        r = static_cast<quint64>(lua_tonumber(m_lua, -1));
    lua_pop(m_lua, 1);
    return r;
}

bool LuaBackend::convert_fields(QVector<MsduFieldNode>* out, QString* err) {
    if (!lua_istable(m_lua, -1)) {
        *err = QStringLiteral("fields must be a table");
        return false;
    }
    const lua_Integer n = luaL_len(m_lua, -1);
    for (lua_Integer i = 1; i <= n; ++i) {
        lua_geti(m_lua, -1, i);  // field 表
        if (!lua_istable(m_lua, -1)) {
            *err = QStringLiteral("field #%1 must be a table").arg(i);
            lua_pop(m_lua, 1);
            return false;
        }
        MsduFieldNode node;
        node.name = table_str("name");
        node.value = table_str("value");
        // relStart/relLen 可选
        lua_getfield(m_lua, -1, "relStart");
        node.rel_start = lua_isinteger(m_lua, -1)
            ? static_cast<int>(lua_tointeger(m_lua, -1)) : -1;
        lua_pop(m_lua, 1);
        lua_getfield(m_lua, -1, "relLen");
        node.rel_len = lua_isinteger(m_lua, -1)
            ? static_cast<int>(lua_tointeger(m_lua, -1)) : 0;
        lua_pop(m_lua, 1);
        // children 可选(递归)
        if (lua_getfield(m_lua, -1, "children") == LUA_TTABLE) {
            if (!convert_fields(&node.children, err)) {
                lua_pop(m_lua, 2);  // children + field
                return false;
            }
        }
        lua_pop(m_lua, 1);  // children 或 nil
        lua_pop(m_lua, 1);  // field 表
        out->append(node);
    }
    return true;
}

ParseResult LuaBackend::parse(const BplcFrame& frame, MsduState& msdu,
                              const ParseFilter& filter, QString* err) {
    Q_UNUSED(msdu);   // Phase2:Lua 插件不支持跨帧重组
    Q_UNUSED(filter);
    ParseResult r;
    r.meta = frame.meta;
    r.raw_wire = frame.raw_wire;
    r.arrival_us = frame.arrival_us;
    r.payload_for_log = frame.data;

    lua_getglobal(m_lua, "parse");
    if (!lua_isfunction(m_lua, -1)) {
        *err = QStringLiteral("parse() not found");
        lua_pop(m_lua, 1);
        r.accept = false; r.reject_reason = *err;
        return r;
    }
    // frame 表
    lua_newtable(m_lua);
    push_byte_table(m_lua, frame.data);
    lua_setfield(m_lua, -2, "data");
    push_byte_table(m_lua, frame.raw_wire);
    lua_setfield(m_lua, -2, "rawWire");
    lua_pushnumber(m_lua, static_cast<lua_Number>(frame.arrival_us));
    lua_setfield(m_lua, -2, "arrivalUs");
    // 主程序解码信息(单入口):帧序号/时间戳/本帧拓扑事件(无事件=nil)
    lua_pushnumber(m_lua, static_cast<lua_Number>(frame.decoded_index));
    lua_setfield(m_lua, -2, "index");
    lua_pushnumber(m_lua, static_cast<lua_Number>(frame.decoded_epoch_ms));
    lua_setfield(m_lua, -2, "epochMs");
    if (frame.topo_event.kind != TopoEventKind::Other) {
        push_topo_event_table(m_lua, frame.topo_event);
    } else {
        lua_pushnil(m_lua);
    }
    lua_setfield(m_lua, -2, "topoEvent");
    // 标量透传:主程序解析真值(接受状态/MPDU/MSDU 摘要)
    lua_pushboolean(m_lua, frame.accepted);
    lua_setfield(m_lua, -2, "accepted");
    lua_pushstring(m_lua, frame.error_reason.toUtf8().constData());
    lua_setfield(m_lua, -2, "rejectReason");
    lua_newtable(m_lua);  // mpdu
    lua_pushboolean(m_lua, true);
    lua_setfield(m_lua, -2, "ok");
    lua_pushinteger(m_lua, frame.mpdu.frame_type);
    lua_setfield(m_lua, -2, "frameType");
    lua_pushinteger(m_lua, frame.mpdu.src_tei);
    lua_setfield(m_lua, -2, "srcTei");
    lua_pushinteger(m_lua, frame.mpdu.dst_tei);
    lua_setfield(m_lua, -2, "dstTei");
    lua_pushinteger(m_lua, frame.mpdu.net_id);
    lua_setfield(m_lua, -2, "netId");
    lua_pushinteger(m_lua, frame.mpdu.net_type);
    lua_setfield(m_lua, -2, "netType");
    lua_pushboolean(m_lua, frame.mpdu.fch_crc_ok);
    lua_setfield(m_lua, -2, "fchCrcOk");
    lua_pushboolean(m_lua, frame.mpdu.pb_crc_ok);
    lua_setfield(m_lua, -2, "pbCrcOk");
    lua_setfield(m_lua, -2, "mpdu");
    lua_pushboolean(m_lua, frame.msdu_present);
    lua_setfield(m_lua, -2, "msduPresent");
    lua_pushstring(m_lua, frame.msdu_summary.toUtf8().constData());
    lua_setfield(m_lua, -2, "msduSummary");

    if (guarded_pcall(m_lua, 1, 1) != LUA_OK) {
        *err = QStringLiteral("parse: %1").arg(pop_lua_error(m_lua));
        r.accept = false; r.reject_reason = *err;
        return r;
    }
    if (!lua_istable(m_lua, -1)) {
        *err = QStringLiteral("parse() must return a table");
        lua_pop(m_lua, 1);
        r.accept = false; r.reject_reason = *err;
        return r;
    }

    lua_getfield(m_lua, -1, "accept");
    r.accept = lua_toboolean(m_lua, -1);
    lua_pop(m_lua, 1);
    if (!r.accept) {
        r.reject_reason = table_str("rejectReason",
                                    QStringLiteral("rejected by plugin"));
        lua_pop(m_lua, 1);  // result 表
        return r;
    }

    // mpdu 可选
    if (lua_getfield(m_lua, -1, "mpdu") == LUA_TTABLE) {
        r.mpdu.frame_type = static_cast<quint8>(table_uint("frameType"));
        r.mpdu.src_tei = static_cast<quint16>(table_uint("srcTei"));
        r.mpdu.dst_tei = static_cast<quint16>(table_uint("dstTei"));
        r.mpdu.net_id = static_cast<quint32>(table_uint("netId"));
    } else if (!frame.data.isEmpty()) {
        r.mpdu.frame_type = 1;
    }
    lua_pop(m_lua, 1);  // mpdu 或 nil

    r.msdu.present = true;
    r.msdu.summary = table_str("summary");
    if (lua_getfield(m_lua, -1, "fields") == LUA_TTABLE) {
        if (!convert_fields(&r.msdu.tree, err)) {
            lua_pop(m_lua, 2);  // fields + result
            r.accept = false; r.reject_reason = *err;
            r.msdu.tree.clear();
            return r;
        }
    }
    lua_pop(m_lua, 1);  // fields 或 nil
    lua_pop(m_lua, 1);  // result 表
    return r;
}

QString LuaBackend::call_text_function(const char* name, QString* err) {
    lua_getglobal(m_lua, name);
    if (!lua_isfunction(m_lua, -1)) {
        lua_pop(m_lua, 1);
        *err = QStringLiteral("function %1 not found").arg(QLatin1String(name));
        return QString();
    }
    if (guarded_pcall(m_lua, 0, 1) != LUA_OK) {
        *err = QStringLiteral("%1: %2")
                   .arg(QLatin1String(name), pop_lua_error(m_lua));
        return QString();
    }
    QString s;
    if (lua_isstring(m_lua, -1))
        s = QString::fromUtf8(lua_tostring(m_lua, -1));
    else
        *err = QStringLiteral("%1 must return a string").arg(QLatin1String(name));
    lua_pop(m_lua, 1);
    return s;
}

void LuaBackend::notify_frame_selected(qint64 frameIndex, bool force_history) {
    lua_getglobal(m_lua, "on_frame_selected");
    if (!lua_isfunction(m_lua, -1)) {
        lua_pop(m_lua, 1);
        return;  // 脚本不关心帧选中:静默忽略
    }
    lua_pushinteger(m_lua, static_cast<lua_Integer>(frameIndex));
    lua_pushboolean(m_lua, force_history);
    if (guarded_pcall(m_lua, 2, 0) != LUA_OK) {
        qWarning() << "LuaBackend::notify_frame_selected:"
                   << pop_lua_error(m_lua);
    }
}
