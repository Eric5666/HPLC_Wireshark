/// @file frame_credit.h
/// @brief Reader → 解析 → GUI 帧流的在途上限(背压)
/// @details Reader 线程每发一帧先 acquire 一个额度,GUI 线程收到该帧的解析结果
///          (FrameDispatcher::on_parsed)时 release。在途帧达到上限时 Reader 阻塞,
///          回放内存峰值与跨线程事件队列长度不再随文件大小增长。
///          防死锁:acquire 按 50 ms 分片等待并检查中止标志,stop() 总能在有限
///          时间内打断;更换解析器或新会话开始时 reset() 回收丢失的额度。
///          未接入消费者(enabled=false,如无可用解析器、单元测试)时不限流。
///          只对文件回放(FilePlayback/RawHex)限流;实时串口走 acquire_nowait 不阻塞。
#ifndef BPLC_IO_FRAME_CREDIT_H
#define BPLC_IO_FRAME_CREDIT_H

#include <QMutex>
#include <QMutexLocker>
#include <QWaitCondition>
#include <atomic>
#include <functional>

class FrameCredit {
public:
    static constexpr int kDefaultMaxInFlight = 4096;

    explicit FrameCredit(int max_in_flight = kDefaultMaxInFlight) : m_max(max_in_flight) {}

    /// @brief 接入/断开消费者;断开时唤醒等待方,之后 acquire 不再阻塞
    void set_enabled(bool on) {
        QMutexLocker lk(&m_lock);
        m_enabled = on;
        m_cv.wakeAll();
    }

    /// @brief 取一个额度(Reader 线程);在途已满则等待
    /// @param aborted 返回 true 表示放弃(stop/会话结束),此时不得发帧
    /// @return true=可发帧;false=已中止
    bool acquire(const std::function<bool()>& aborted) {
        QMutexLocker lk(&m_lock);
        while (m_enabled && m_in_flight >= m_max) {
            if (aborted()) return false;
            m_cv.wait(&m_lock, 50);
        }
        if (aborted()) return false;
        ++m_in_flight;
        return true;
    }

    /// @brief 记一个在途额度但从不等待(实时串口:读串口绝不能被背压阻塞,
    ///        否则驱动缓冲溢出静默丢字节);计数仍与 release 配平
    void acquire_nowait() {
        QMutexLocker lk(&m_lock);
        ++m_in_flight;
    }

    /// @brief 归还一个额度(消费者处理完一帧;任意线程)
    void release() {
        QMutexLocker lk(&m_lock);
        if (m_in_flight > 0) --m_in_flight;
        m_cv.wakeOne();
    }

    /// @brief 清零在途计数(新会话/更换解析器:旧帧的额度不会再归还)
    void reset() {
        QMutexLocker lk(&m_lock);
        m_in_flight = 0;
        m_cv.wakeAll();
    }

    int in_flight() const {
        QMutexLocker lk(&m_lock);
        return m_in_flight;
    }
    int max_in_flight() const { return m_max; }

private:
    mutable QMutex m_lock;
    QWaitCondition m_cv;
    const int m_max;
    int m_in_flight = 0;
    bool m_enabled = false;
};

#endif // BPLC_IO_FRAME_CREDIT_H
