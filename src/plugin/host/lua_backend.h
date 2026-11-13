/// @file lua_backend.h
/// @brief LuaBackend:内嵌 Lua 5.4 运行 Lua 插件
/// @details Lua 插件 API v1(与 JS API 对齐,表用 {}):
///   function get_info() -> { protocolId = "X", displayName = "..." }
///   function parse(frame) -> {
///     accept = true, rejectReason = "...", summary = "...",
///     mpdu = { frameType = 1, srcTei = 2, dstTei = 3 },
///     fields = { { name="..", value="..", relStart=0, relLen=1,
///                   children = { ... } }, ... }
///   }
///   frame = { data = {byte,...}, rawWire = {byte,...}, arrivalUs = number,
///             index = number,     -- 主程序帧序号(1-based;0=独立测试无解码)
///             epochMs = number,    -- 解析出的帧时刻(epoch ms)
///             topoEvent = evt/nil } -- 本帧的拓扑事件,无事件时为 nil
/// 拓扑事件(主解析器产出,挂在 frame.topoEvent,单入口,无独立侧信道):
///   evt = {
///     kind = "discoverList"|"assocReq"|"assocCnf"|"assocGatherInd"|"assocInd"|
///            "changeProxyReq"|"changeProxyCnf"|"leaveInd"|"successRate"|
///            "ccoRestart"|"staRestart"|"other",
///     nid = number, ccoMac = "aa:bb:cc:dd:ee:ff" 或 nil,  -- nil=本事件不带 CCO
///     nodes = { { tei, mac }, ... },
///     routes = { { child, parent }, ... },
///     upRoutes = { { sta, nextHop }, ... },  -- 仅 RouteType=3 代理主路径
///     discoverSrcTei = number, neighborTeis = { tei, ... },
///     leaves = { "aa:bb:..", ... },
///     commRates = { { tei, down, up }, ... },
///     isRf = bool, restartCount = number,  -- -1=未知
///     desc = string, epochMs = number, frameIndex = number
///   }
/// 主界面控制(Phase4):
///   host.jumpToFrame(frameIndex)  -- 主帧列表定位到指定帧(选中+居中)
/// 主界面 → 插件通知:
///   on_frame_selected(frameIndex, forceHistory)  -- 主帧列表选中变化;
///     forceHistory=true 时强制历史冻结(双击),否则插件按是否为最新帧
///     自行决定 live/历史;未定义时静默忽略
/// @note 安全边界是进程隔离 + 受限标准库(无 io/debug/os.execute,require 限插件目录,
///       拒字节码);每次脚本调用有指令预算(默认 2 亿条,超限抛 Lua 错误)。
#ifndef BPLC_LUA_BACKEND_H
#define BPLC_LUA_BACKEND_H

#include "plugin_backend.h"

#include <functional>
#include <memory>

struct lua_State;
struct LuaBudget;

/// @brief Lua 插件后端
class LuaBackend : public IPluginBackend {
public:
    LuaBackend();
    ~LuaBackend() override;

    bool initialize(const PluginManifest& m, QString* err) override;
    void shutdown() override;
    QString protocol_id() const override;
    ParseResult parse(const BplcFrame& frame, MsduState& msdu,
                      const ParseFilter& filter, QString* err) override;
    // topoEvent 挂在 parse(frame) 的 frame.topoEvent 上(单入口,无独立侧信道)

    // ---- 图形(Phase3) ----
    bool has_graphics() const override;
    QSize graphics_preferred_size() const override;
    QImage render_graphics(int w, int h, QString* err) override;
    bool handle_graphics_event(const GraphicsEvent& e, QString* err) override;

    // ---- 脚本函数调用 ----
    QString call_text_function(const char* name, QString* err) override;

    // ---- 主界面 → 插件通知 ----
    /// @brief 调用脚本全局函数 on_frame_selected(frameIndex, forceHistory)
    void notify_frame_selected(qint64 frameIndex, bool force_history) override;

private:
    /// @brief 在 panic 跳转点保护下执行 body;发生 Lua panic 时返回 false、
    ///        标记本插件不可用(之后所有入口直接报错),宿主进程不 abort
    bool run_protected(const std::function<void()>& body, QString* err);
    bool initialize_impl(const PluginManifest& m, QString* err);
    ParseResult parse_impl(const BplcFrame& frame, MsduState& msdu,
                           const ParseFilter& filter, QString* err);
    QImage render_graphics_impl(int w, int h, QString* err);
    bool handle_graphics_event_impl(const GraphicsEvent& e, QString* err);
    QString call_text_function_impl(const char* name, QString* err);
    void notify_frame_selected_impl(qint64 frameIndex, bool force_history);

    /// @brief Lua fields 表(数组) → MsduFieldNode 树(递归)。表在栈顶
    bool convert_fields(QVector<MsduFieldNode>* out, QString* err);
    /// @brief 取表字段的字符串/整数(字段不存在给缺省)
    QString table_str(const char* key, const QString& d = QString());
    quint64 table_uint(const char* key, quint64 d = 0);

    lua_State* m_lua = nullptr;
    std::unique_ptr<LuaBudget> m_budget;  ///< 每次调用的指令预算(count hook 读写)
    bool m_has_graphics = false;
    bool m_panicked = false;  ///< 发生过 Lua panic:状态不可再用
    QString m_plugin_dir;  ///< 插件目录(设置/环境变量用)
    QString m_protocol_id;
    QString m_display_name;
};

#endif // BPLC_LUA_BACKEND_H
