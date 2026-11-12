/// @file replay_gui.h
/// @brief 真实帧回灌 GUI 工具:把 0x3C 抓包 bin 回灌进 4 个示例插件并可视化结果
#ifndef BPLC_REPLAY_GUI_H
#define BPLC_REPLAY_GUI_H

#include <QMainWindow>
#include <QThread>
#include <QImage>
#include <QVector>
#include <QStringList>
#include <atomic>

class QLineEdit;
class QPushButton;
class QCheckBox;
class QSpinBox;
class QProgressBar;
class QTabWidget;
class QLabel;
class QTableWidget;
class QTextEdit;

/// @brief 单个插件的回灌结果(工作线程 → GUI 线程传递)
struct PluginReplayResult {
    QString name;
    bool    ok = false;
    QString error;
    int     accept = 0;
    int     reject = 0;
    qint64  elapsed_ms = 0;
    QString last_summary;
    QImage  final_image;   ///< topo 插件最终渲染图
    QString extra_text;    ///< report JSON
    struct Alarm { int frame_no; QString problem; QString detail; };
    QVector<Alarm> alarms; ///< diag 插件告警(上限截断)
};

/// @brief 回灌工作线程:拆帧 → 逐插件 parse → 收集结果
class ReplayWorker : public QThread {
    Q_OBJECT
public:
    struct Job {
        QString     examples_dir;
        QString     bin_path;
        QStringList plugins;
        int         max_frames = 0;  ///< 0=全部
    };
    explicit ReplayWorker(const Job& job, QObject* parent = nullptr);
    void request_stop();

signals:
    void progress(int done, int total);
    void log_line(const QString& s);
    void topo_preview(const QImage& img, int done);
    void finished(const QVector<PluginReplayResult>& results);

protected:
    void run() override;

private:
    Job m_job;
    std::atomic<bool> m_stop{false};
};

class ReplayMainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit ReplayMainWindow(QWidget* parent = nullptr);

private slots:
    void on_browse();
    void on_start();
    void on_stop();
    void on_progress(int done, int total);
    void on_log(const QString& s);
    void on_topo_preview(const QImage& img, int done);
    void on_finished(const QVector<PluginReplayResult>& results);

private:
    void log(const QString& s);
    void set_running(bool running);

    QLineEdit*   m_ed_bin = nullptr;
    QLineEdit*   m_ed_examples = nullptr;
    QCheckBox*   m_ck_topo = nullptr;
    QCheckBox*   m_ck_diag = nullptr;
    QCheckBox*   m_ck_report = nullptr;
    QSpinBox*    m_sp_max = nullptr;
    QPushButton* m_btn_start = nullptr;
    QPushButton* m_btn_stop = nullptr;
    QProgressBar* m_progress = nullptr;

    QLabel*      m_lb_topo = nullptr;
    QTextEdit*   m_te_topo_stat = nullptr;
    QTableWidget* m_tw_diag = nullptr;
    QTextEdit*   m_te_report = nullptr;
    QTextEdit*   m_te_log = nullptr;

    ReplayWorker* m_worker = nullptr;
};

/// @brief 按串口拆帧语义从 bin 数据中提取 0x3C...0x3E 线帧(含哨兵,转义原样)
QList<QByteArray> split_wire_frames(const QByteArray& data, int max_n);

/// @brief 注册本工具的英文词典(供 main / 测试驱动调用)
void replay_gui_register_en();

#endif  // BPLC_REPLAY_GUI_H
