/// @file plugin_autotest.h
/// @brief 插件自动化截图测试(测试侧,不编进产品)
/// @details 加载插件 → 回放 bin → 等插件线程排空 → 逐个插件面板截图 →
///          选中一帧带 MSDU 的报文后截主窗口 → 退出。
///          仅在 qmake CONFIG+=plugin_autotest 时编译(定义 BPLC_PLUGIN_AUTOTEST),
///          由主程序命令行 --replay <bin> --plugin-autotest <shot_dir> 触发。
#ifndef BPLC_PLUGIN_AUTOTEST_H
#define BPLC_PLUGIN_AUTOTEST_H

#include <QObject>
#include <QString>

class MainWindow;
class QTimer;

class PluginAutotest : public QObject {
    Q_OBJECT
public:
    /// @param window   被测主窗口(本对象挂为其子对象,随窗口销毁)
    /// @param shot_dir 截图输出目录(不存在则创建)
    PluginAutotest(MainWindow* window, const QString& shot_dir);

    /// @brief 启动:等插件加载完成再回放 bin,回放结束排空后截图并退出
    void start(const QString& plugins_dir, const QString& bin);

private:
    void on_load_finished(const QString& bin);
    void on_reader_finished();
    void poll_idle();
    void shoot_tick();
    void shoot_tabs();

    MainWindow* m_window = nullptr;
    QString     m_shot_dir;
    bool        m_reader_seen = false;      ///< 已处理首个 finished(只处理一次)
    QTimer*     m_poll = nullptr;           ///< 排空轮询(500ms)
    int         m_waits = 0;                ///< 轮询次数(超时兜底 10min)
    QTimer*     m_shoot_timer = nullptr;    ///< 逐 tab 截图节拍(1.5s)
    bool        m_shooting = false;         ///< 截图序列是否已启动(防重入)
    int         m_tab_count = 0;            ///< 启动截图时的 tab 数
    int         m_tab_index = -1;           ///< 当前显示的 tab
    bool        m_field_shot_done = false;  ///< 已选中字段树示例帧
};

#endif  // BPLC_PLUGIN_AUTOTEST_H
