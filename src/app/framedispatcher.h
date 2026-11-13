/// @file framedispatcher.h
/// @brief 帧分发与统计容器
#ifndef BPLC_FRAMEDISPATCHER_H
#define BPLC_FRAMEDISPATCHER_H

#include "iprotocolparser.h"
#include "entrybuilder.h"
#include "frame_credit.h"
#include "statistics.h"
#include <QObject>
#include <QThread>
#include <atomic>
#include <memory>

class DispatcherWorker : public QObject {
    Q_OBJECT
public:
    explicit DispatcherWorker(std::unique_ptr<IProtocolParser> parser,
                              QObject* parent = nullptr);
    /// @brief 请求停止:置位后 on_frame 立即返回不再解析(供 shutdown 快速清空积压帧)
    void request_stop() { m_stopped.store(true); }
    /// @brief 背压额度(线程启动前设置):停止后跳过的帧在此归还
    void set_flow_credit(std::shared_ptr<FrameCredit> c) { m_credit = std::move(c); }

public slots:
    /// @param credit_gen 帧的背压额度代号(随 frame_ready 透传),解析完/跳过时按此归还
    void on_frame(const BplcFrame& frame, quint64 credit_gen);
    /// @brief 回放/采集结束(经队列投递,晚于所有 frame_ready):输出解析异常汇总
    void on_replay_finished();

signals:
    /// @brief 一帧解析完成:条目已在解析线程预构建(共享指针投递,无逐字段拷贝)
    void parsed(const PreparedEntryPtr& p);
    void stats_updated(qint64 total, qint64 dropped);

private:
    std::unique_ptr<IProtocolParser> m_parser;
    MsduState   m_msdu;
    std::atomic<bool> m_stopped{false};
    std::atomic<quint64> m_frame_count{0};  ///< 已解析帧数(日志统计)
    std::atomic<quint64> m_parse_us{0};     ///< parse 累计耗时(µs)
    std::shared_ptr<FrameCredit> m_credit;  ///< 背压额度(可空)
};

class FrameDispatcher : public QObject {
    Q_OBJECT
public:
    explicit FrameDispatcher(QObject* parent = nullptr);
    ~FrameDispatcher() override;

    FrameStatistics* statistics() { return &m_stats; }

    void connect_source(QObject* source);
    /// @brief 接入数据源的背压额度:每帧解析结果在 GUI 线程 on_parsed 后归还
    /// @details 无可用解析器(无 worker)时不接入,额度保持不限流,避免 Reader 永远等待。
    void set_flow_credit(std::shared_ptr<FrameCredit> credit);
    void disconnect_source(QObject* source);
    /// @brief 立即停止解析:断开 worker 信号并退出解析线程;
    ///        供重建 dispatcher 时快速让旧线程停止处理积压帧。
    void shutdown();

signals:
    /// @brief 转发解析线程预构建的条目(GUI 线程,统计与背压额度已处理)
    void parsed(const PreparedEntryPtr& p);
    void stats_updated();

private slots:
    void on_parsed(const PreparedEntryPtr& p);

private:
    QThread*            m_thread;
    DispatcherWorker*   m_worker;
    FrameStatistics     m_stats;
    std::atomic<quint64> m_total{0};
    std::atomic<quint64> m_dropped{0};
    std::shared_ptr<FrameCredit> m_credit;  ///< 背压额度(可空)
};

#endif  // BPLC_FRAMEDISPATCHER_H
