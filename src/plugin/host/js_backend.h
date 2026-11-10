/// @file js_backend.h
/// @brief JsBackend:QJSEngine 运行 JS 插件
/// @details JS 插件 API v1:
///   function get_info() -> { protocolId: "X", displayName: "..." }
///   function parse(frame) -> {
///     accept: bool, rejectReason?: string, summary?: string,
///     mpdu?: { frameType, srcTei, dstTei, netId },
///     fields?: [{ name, value, relStart?, relLen?, children?: [...] }]
///   }
///   frame = { data: [byte...], rawWire: [byte...], arrivalUs: number,
///             index: number,        // 主程序帧序号(1-based;0=独立测试无解码)
///             epochMs: number,      // 解析出的帧时刻(epoch ms)
///             topoEvent: evt|null,  // 本帧的拓扑事件,无事件时为 null
///             // 标量透传(主程序解析真值,插件无需重解析):
///             accepted: bool,       // 主程序是否接受该帧
///             rejectReason: string,  // 丢弃原因(accepted=false 时)
///             mpdu: { ok, frameType, srcTei, dstTei, netId, netType,
///                     fchCrcOk, pbCrcOk },
///             msduPresent: bool,    // 是否携带完整 MSDU
///             msduSummary: string }  // MSDU 概要,如 "MMeDiscoverNodeList"
/// 拓扑事件(主解析器产出,挂在 frame.topoEvent,单入口,无独立侧信道):
///   evt = {
///     kind: "discoverList"|"assocReq"|"assocCnf"|"assocGatherInd"|"assocInd"|
///           "changeProxyReq"|"changeProxyCnf"|"leaveInd"|"successRate"|
///           "ccoRestart"|"staRestart"|"other",
///     nid: number, ccoMac: "aa:bb:cc:dd:ee:ff"|null,  // null=本事件不带 CCO
///     nodes: [{ tei, mac }],                 // TEI→MAC 学习对
///     routes: [{ child, parent }],           // (子 TEI, 父/代理 TEI)
///     upRoutes: [{ sta, nextHop }],          // 上行路由(仅 RouteType=3 代理主路径)
///     discoverSrcTei: number, neighborTeis: [tei...],
///     leaves: ["aa:bb:.."],                  // 离网节点 MAC
///     commRates: [{ tei, down, up }],        // 成功率 %
///     isRf: bool, restartCount: number,      // -1=未知
///     desc: string, epochMs: number, frameIndex: number
///   }
/// 主界面控制(Phase4):
///   host.jumpToFrame(frameIndex)  // 主帧列表定位到指定帧(选中+居中)
/// 主界面 → 插件通知:
///   on_frame_selected(frameIndex, forceHistory)  // 主帧列表选中变化;
///     forceHistory=true 时强制历史冻结(双击),否则插件按是否为最新帧
///     自行决定 live/历史;未定义时静默忽略
/// 图形 API(Phase3, manifest graphics=true 时):
///   function render(p, w, h)  // p: ScriptPainter
///   function on_event(type, x, y, button, modifiers, delta) -> bool(needs_redraw)
///   type: 0=press 1=release 2=move 3=wheel 4=resize 5=leave 6=dblclick
/// @note JS 插件不支持 SOF 跨帧重组(Phase2 限制),MsduState 透传不使用。
#ifndef BPLC_JS_BACKEND_H
#define BPLC_JS_BACKEND_H

#include <QJSEngine>
#include <QJSValue>
#include <QObject>

#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>

#include "plugin_backend.h"

/// @brief request_redraw 的 QObject 桥(Qt6.5 QJSEngine 无 newFunction)
class RedrawHelper : public QObject {
    Q_OBJECT
public:
    std::function<void()> cb;
public slots:
    void request() { if (cb) cb(); }
};

/// @brief host 界面控制对象的 QObject 桥:host.jumpToFrame(frameIndex)
///        + 插件设置 host.getSetting(key, defaultValue)
///        + 公共环境变量 host.getEnv(name)
class HostHelper : public QObject {
    Q_OBJECT
public:
    std::function<void(qint64)> jump_cb;
    std::function<QVariant(const QString&, const QVariant&)> setting_cb;
    std::function<QString(const QString&)> env_cb;
    std::function<void(const QString&, const QStringList&,
                       const QList<QStringList>&)> table_cb;
public slots:
    void jumpToFrame(double index) { if (jump_cb) jump_cb(static_cast<qint64>(index)); }
    QVariant getSetting(const QString& key, const QVariant& defaultValue = QVariant()) {
        if (setting_cb) return setting_cb(key, defaultValue);
        return defaultValue;
    }
    QString getEnv(const QString& name) {
        if (env_cb) return env_cb(name);
        return QString();
    }
    /// @brief 请求主界面弹出独立表格窗口(title=标题, columns=列头, rows=二维行数据)
    void showTable(const QString& title, const QJSValue& columns,
                   const QJSValue& rows);
};

/// @brief JS 插件后端
/// @brief JS 调用看门狗(M10):每次脚本入口 arm(),超时由后台线程调用
///        QJSEngine::setInterrupted(true) 打断死循环;disarm() 复位中断标志。
/// @details 一个后台线程常驻(不按调用新建);超时默认 3000 ms,环境变量
///          BPLC_JS_CALL_TIMEOUT_MS 可覆盖(测试用)。setInterrupted 线程安全。
class JsWatchdog {
public:
    explicit JsWatchdog(QJSEngine* engine);
    ~JsWatchdog();
    JsWatchdog(const JsWatchdog&) = delete;
    JsWatchdog& operator=(const JsWatchdog&) = delete;

    void arm();
    /// @return true=本次调用因超时被打断
    bool disarm();
    int timeout_ms() const { return m_timeout_ms; }

private:
    void run();

    QJSEngine* m_engine;  ///< 不拥有
    int m_timeout_ms = 3000;
    std::mutex m_mu;
    std::condition_variable m_cv;
    bool m_armed = false;
    bool m_fired = false;
    bool m_quit = false;
    quint64 m_gen = 0;  ///< 每次 arm 自增,区分不同调用
    std::thread m_thread;
};

class JsBackend : public IPluginBackend {
public:
    JsBackend() = default;  // m_watchdog 由默认成员初始化绑定 m_engine
    ~JsBackend() override = default;

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
    /// @details 函数未定义时静默忽略;脚本异常记入调试输出,不中断喂帧
    void notify_frame_selected(qint64 frameIndex, bool force_history) override;

private:
    bool convert_fields(const QJSValue& js_fields, QVector<MsduFieldNode>* out,
                        QString* err);
    /// @brief 脚本异常 → err;被看门狗打断时给出超时说明
    bool check_error(const QJSValue& v, QString* err,
                     const QString& ctx) const;

    /// @brief 一次脚本入口的看门狗作用域(构造 arm,析构 disarm)
    struct CallGuard {
        explicit CallGuard(JsWatchdog& w) : wd(w) { wd.arm(); }
        ~CallGuard() { wd.disarm(); }
        JsWatchdog& wd;
    };

    QJSEngine m_engine;
    JsWatchdog m_watchdog{&m_engine};  ///< 声明在 m_engine 之后:先于引擎析构
    QJSValue m_parse_fn;
    QJSValue m_render_fn;
    QJSValue m_on_event_fn;
    RedrawHelper* m_redraw_helper = nullptr;  ///< engine 拥有
    HostHelper* m_host_helper = nullptr;      ///< engine 拥有
    QString m_plugin_dir;  ///< 插件目录(设置/环境变量用)
    bool m_has_graphics = false;
    QString m_protocol_id;
    QString m_display_name;
};

#endif // BPLC_JS_BACKEND_H
