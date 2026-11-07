/// @file mainwindow.h
/// @brief 主窗口
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTimer>
#include <QByteArray>
#include <QHash>
#include <QList>
#include <QVector>
#include <atomic>
#include "serialreader.h"
#include "framedispatcher.h"
#include "local_plugin_engine.h"

class QDockWidget;
class QTabWidget;
#include "iprotocolparser.h"
#include "commconfigdialog.h"
#include "topo_state.h"

class QComboBox;
class UpdateMirrorResolver;
class QToolBar;
class QToolButton;
class QLineEdit;
class QLabel;
class QTableView;
class QTreeWidget;
class QPlainTextEdit;
class QSplitter;
class QStatusBar;
class QCheckBox;
class QPushButton;
class QDragEnterEvent;
class QDropEvent;

class PacketListModel;
class HexView;
class ProtocolTree;
class TopoWindow;
struct PacketEntry;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    /// @brief 加载插件目录:主界面调用插件并展示各插件功能界面
    void load_plugins(const QString& dir);
    /// @brief 加载多个插件目录(市场安装目录 + 开发/命令行目录,按序叠加)
    void load_plugin_dirs(const QStringList& dirs);
    /// @brief 拖放文件导入(按扩展名判定回放/裸hex)
    void start_file_import(const QString& path);
    /// @brief 自动化测试:加载插件→回放 bin→各插件面板截图到 shot_dir→退出
    void run_plugin_autotest(const QString& plugins_dir, const QString& bin,
                             const QString& shot_dir);

private slots:
    void on_start();
    void on_stop();
    void on_pause();
    void on_clear();
    void on_export();
    void on_settings();
    void on_apply_filter();
    void on_goto();   ///< 跳转到指定序号帧(goto 输入框)
    void on_parsed(const ParseResult& r);
    void on_status_message(const QString& s);
    void on_error(const QString& e);
    void on_row_activated(const PacketEntry& e);
    void on_topo_request_live();       ///< Topo 窗口"回到实时"按钮
    void update_topo_history(qint64 frame_index, qint64 frame_ms); ///< 帧点击 → TOPO 回放/实时切换
    void enter_topo_history(qint64 frame_index, qint64 frame_ms);  ///< 帧双击 → 强制历史追溯(冻结,不跟随实时)
    void on_topo_request_history(qint64 frame_index, qint64 frame_ms); ///< TOPO 路由表双击 → 追溯到该帧
    void jump_packet_to_frame(qint64 frame_index); ///< TOPO 双击 → 主帧列表定位到该帧(选中+居中,清过滤)
    void show_plugin_table(const QString& title, const QStringList& columns,
                           const QList<QStringList>& rows); ///< 插件 host.showTable → 弹独立表格窗口
    void replay_topo_history();        ///< 按 m_topo_hist_frame 重放日志生成冻结快照
    void on_ranges_selected(const QList<QPair<int, int>>& ranges, const QByteArray& copy_bytes);
    void on_flush_buffer();
    void refresh_status_bar();
    void on_check_finished(const QString& url);   // 检查更新结束(QSimpleUpdater)
    void on_mirror_resolved(const QString& effectiveUrl, const QString& prefix); // 更新加速解析完成 → 正式发起检查
    void on_plugin_loaded(const PluginLoadedInfo& info);  // 插件就绪 → 建功能面板
    void on_choose_plugin_dir();                  // 插件菜单:选择插件目录
    void on_open_plugin_market();                 // 插件菜单:插件市场

protected:
    void dragEnterEvent(QDragEnterEvent* event) override;
    void dropEvent(QDropEvent* event) override;

private:
    void build_ui();
    void wire_signals();
    PacketEntry make_entry(const ParseResult& r, qint64 now);
    void enqueue_entry(PacketEntry&& e);
    void check_for_updates(bool silent);   // 检查更新(silent=true:启动静默检查)
    void rebuild_dispatcher();             // 协议切换立即生效:停止+清空+重建解析器
    void reset_dispatcher();               // 停止旧解析+重建 dispatcher(拖放导入/协议切换共用)
    bool confirm_protocol_rebuild();       // 协议变更提示,返回是否立即生效
    void update_selection_delta();  // 选中两行算时间差(NTB 优先,与本地差>3s 时降级本地时间)
    void open_topo_window();        // 打开/聚焦拓扑独立窗口(多 NID 下拉切换)
    void setup_plugin_ui();         // 插件 dock/菜单/引擎(主界面调用插件展示功能界面)
    void connect_plugin_feed();     // m_reader frame_ready → 插件引擎(重建 reader 时重连)
    void autotest_shoot_tabs();     // 自动化测试:逐 tab 截图后退出

    QToolBar*      m_toolbar;
    QToolButton*   m_btn_start;
    QToolButton*   m_btn_stop;
    QToolButton*   m_btn_pause;
    QToolButton*   m_btn_clear;
    QToolButton*   m_btn_export;
    QToolButton*   m_btn_settings;
    QToolButton*   m_btn_topo;
    QToolButton*   m_btn_update;   ///< 发现新版本时显示的"立即更新"按钮(菜单栏右上角,默认隐藏)
    UpdateMirrorResolver* m_mirror_resolver = nullptr; ///< 更新下载加速解析器(每次检查重建,防并发链重叠)
    QString        m_last_check_url;   ///< 本次检查实际使用的清单地址(可能带代理前缀)
    bool           m_check_silent = true; ///< 本次检查是否静默(启动自动检查)
    QLineEdit*     m_edt_filter;
    QToolButton*   m_btn_apply_filter;
    QLineEdit*     m_edt_goto;   ///< 跳转帧序号输入框(应用按钮右侧)
    QToolButton*   m_btn_goto;   ///< 跳转按钮

    QSplitter*     m_splitter_main;
    QTableView*    m_table_packets;
    QSplitter*     m_splitter_bottom;
    ProtocolTree*  m_tree_protocol;
    HexView*       m_hex_view;
    QLabel*        m_lbl_hex_title;
    QSplitter*     m_split_hex;       ///< HexView | 原始报文 水平分离
    QPlainTextEdit* m_raw_view;       ///< 原始串口帧(0x3C...0x3E)只读文本(常显)
    QByteArray     m_raw_bytes;       ///< 当前帧原始字节(右键复制用)

    QLabel*        m_status_left;
    QLabel*        m_status_mid;    ///< 状态栏中间:选中两行时间差显示
    QLabel*        m_status_right;

    SerialReader*    m_reader;
    FrameDispatcher* m_dispatch;
    PacketListModel* m_model;
    LocalPluginEngine* m_plugin_engine = nullptr; ///< 主界面内置插件引擎(进程内后端)
    QDockWidget*  m_plugin_dock = nullptr;        ///< 插件功能面板 dock
    QAction*      m_act_show_plugin = nullptr;    ///< 菜单「显示插件面板」勾选项
    QTabWidget*   m_plugin_tabs = nullptr;        ///< 每个插件一个 tab
    QMap<QString, QWidget*> m_plugin_panels;      ///< pid → 功能面板
    QStringList   m_plugin_search_dirs;           ///< 插件搜索目录(市场安装目录+命令行目录)
    QString       m_autotest_shots;               ///< 非空:自动化测试截图目录
    bool          m_autotest_shooting = false;      ///< 截图序列是否已启动(防重入)
    TopoWindow*    m_topo_window = nullptr;       ///< 拓扑独立窗口(懒创建)
    QHash<quint32, TopoState> m_topo_states;      ///< NID → 拓扑状态(实时累积)
    QVector<TopoLogItem> m_topo_log;              ///< 拓扑事件日志(帧序;供历史回放)
    QVector<TopoRestartSample> m_topo_restart_log; ///< 逐帧重启采样日志(帧序;供历史回放)
    QHash<quint32, TopoState> m_topo_hist_states; ///< 回放快照:重放到选中帧的拓扑(冻结显示)
    bool   m_topo_hist_active = false;            ///< TOPO 历史回放(冻结)模式
    qint64 m_topo_hist_frame = 0;                 ///< 回放到的帧序号
    qint64 m_topo_hist_ms = 0;                    ///< 回放帧时刻(epoch ms)
    qint64 m_topo_hist_replayed = -1;             ///< 回放水位:快照已覆盖到的帧(增量回放用;-1=需全量重建)

    QTimer*          m_flush_timer;
    QTimer*          m_status_timer;
    QList<PacketEntry> m_pending;
    QMutex           m_pending_mutex;
    bool             m_paused;
    bool             m_exporting;      ///< 导出中(on_flush_buffer 暂停 append 进模型)
    bool             m_follow_bottom;  ///< 是否自动滚动到最新帧(用户滚离底部则暂停)

    quint32          m_last_ntb;     ///< 上一帧帧内 NTB(tick),Delta 统一用 NTB 差
    bool             m_have_last_ntb;
    int              m_index_counter;
    std::atomic<int> m_pending_count{0};  ///< pending 帧数(原子,阈值触发同步 flush 用)
};

#endif // MAINWINDOW_H
