/// @file capturecontroller.h
/// @brief 采集控制:SerialReader + FrameDispatcher 的生命周期与连线
/// @details 负责开始/停止采集或回放、重建解析器(协议切换/拖放导入),
///          并把 Reader 状态与解析结果转发给界面;界面只连本对象的信号,
///          重建 dispatcher 时无需重新连线。
#ifndef BPLC_CAPTURECONTROLLER_H
#define BPLC_CAPTURECONTROLLER_H

#include <QObject>
#include <QString>
#include "serialreader.h"
#include "entrybuilder.h"

class FrameDispatcher;
class FrameStatistics;

class CaptureController : public QObject {
    Q_OBJECT
public:
    explicit CaptureController(QObject* parent = nullptr);

    /// @brief 底层 Reader(插件/自动化测试观察 finished 与背压额度用)
    SerialReader* reader() const { return m_reader; }
    /// @brief 当前 dispatcher 的帧统计
    FrameStatistics* statistics() const;
    /// @brief 采集/回放是否运行中
    bool is_running() const { return m_reader->is_running(); }

    /// @brief 按配置开始采集/回放
    void start(const ReaderConfig& cfg) { m_reader->start(cfg); }
    /// @brief 停止采集/回放(abort 打断同步回放循环)
    void stop() { m_reader->stop(); }
    /// @brief 停止旧解析线程并按 config.ini 协议重建 dispatcher
    /// @details 丢弃积压帧、重置 MSDU 重组与统计;回放忙碌时不同步 delete,
    ///          shutdown 后 deleteLater 异步销毁。
    void reset_dispatcher();

    /// @brief 读取 config.ini [reader] 采集配置
    static ReaderConfig load_config();
    /// @brief 保存采集配置到 config.ini [reader]
    static void save_config(const ReaderConfig& cfg);

signals:
    /// @brief 一帧解析完成(已排队到 GUI 线程;重建 dispatcher 后自动切到新实例)
    void parsed(const PreparedEntryPtr& p);
    void status_message(const QString& s);
    void error_occurred(const QString& e);
    void progress_percent(int p);

private:
    void create_dispatcher();

    SerialReader*    m_reader = nullptr;
    FrameDispatcher* m_dispatch = nullptr;
};

#endif  // BPLC_CAPTURECONTROLLER_H
