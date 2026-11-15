/// @file frame_credit.h
/// @brief Reader → 解析 → GUI 帧流的在途上限(背压)
/// @details Reader 线程每发一帧先 acquire 一个额度,GUI 线程收到该帧的解析结果
///          (FrameDispatcher::on_parsed)时 release。在途帧达到上限时 Reader 阻塞,
///          回放内存峰值与跨线程事件队列长度不再随文件大小增长。
///          防死锁:acquire 按 50 ms 分片等待并检查中止标志,stop() 总能在有限
///          时间内打断;更换解析器或新会话开始时 reset() 回收丢失的额度。
///          未接入消费者(enabled=false,如无可用解析器、单元测试)时不限流。
///          只对文件回放(FilePlayback/RawHex)限流;实时串口走 acquire_nowait 不阻塞。
///          会话隔离:额度按"代"(generation)记账。acquire/acquire_nowait 返回当前代号,
///          该代号随 frame_ready(frame, credit_gen) 透传到消费者,release(gen) 只在
///          gen 仍是当前代时才归还;reset() 使代号 +1,旧会话迟到的 release 一律作废,
///          不会扣减新会话的在途计数。代号比对与计数增减在同一把锁内完成。
#ifndef BPLC_IO_FRAME_CREDIT_H
#define BPLC_IO_FRAME_CREDIT_H

#include <QMutex>
#include <QMutexLocker>
#include <QWaitCondition>
#include <QtGlobal>
#include <atomic>
#include <functional>

class FrameCredit {
public:
    static constexpr int kDefaultMaxInFlight = 4096;
    /// @brief 未占额度的帧代号(帧默认值;release(kNoGeneration) 恒为空操作)
    static constexpr quint64 kNoGeneration = 0;

    explicit FrameCredit(int max_in_flight = kDefaultMaxInFlight) : m_max(max_in_flight) {}

    /// @brief 接入/断开消费者;断开时唤醒等待方,之后 acquire 不再阻塞
    void set_enabled(bool on) {
        QMutexLocker lk(&m_lock);
        m_enabled = on;
        m_cv.wakeAll();
    }

    /// @brief 取一个额度(Reader 线程);在途已满则等待
    /// @param aborted 返回 true 表示放弃(stop/会话结束),此时不得发帧
    /// @param gen_out 成功时写入本额度所属的代号(帧须携带它,归还时原样交回)
    /// @return true=可发帧;false=已中止
    bool acquire(const std::function<bool()>& aborted, quint64* gen_out = nullptr) {
        QMutexLocker lk(&m_lock);
        while (m_enabled && m_in_flight >= m_max) {
            if (aborted()) return false;
            m_cv.wait(&m_lock, 50);
        }
        if (aborted()) return false;
        ++m_in_flight;
        if (gen_out) *gen_out = m_gen;
        return true;
    }

    /// @brief 记一个在途额度但从不等待(实时串口:读串口绝不能被背压阻塞,
    ///        否则驱动缓冲溢出静默丢字节);计数仍与 release 配平
    /// @return 本额度所属的代号
    quint64 acquire_nowait() {
        QMutexLocker lk(&m_lock);
        ++m_in_flight;
        return m_gen;
    }

    /// @brief 归还一个额度(消费者处理完一帧;任意线程)
    /// @param gen 该帧 acquire 时拿到的代号;不是当前代(旧会话/已 reset)则忽略
    void release(quint64 gen) {
        QMutexLocker lk(&m_lock);
        if (gen == kNoGeneration || gen != m_gen) return;   // 过期额度:不碰新会话计数
        if (m_in_flight > 0) {                               // 防下溢
            --m_in_flight;
            m_cv.wakeOne();
        }
    }

    /// @brief 清零在途计数并开启新一代(新会话/更换解析器:旧帧的额度作废)
    void reset() {
        QMutexLocker lk(&m_lock);
        m_in_flight = 0;
        if (++m_gen == kNoGeneration) ++m_gen;   // 回绕时跳过 0
        m_cv.wakeAll();
    }

    /// @brief 当前代号(测试/诊断用)
    quint64 generation() const {
        QMutexLocker lk(&m_lock);
        return m_gen;
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
    quint64 m_gen = 1;   ///< 当前代号(从 1 起,0 保留给"未占额度")
    bool m_enabled = false;
};

#endif // BPLC_IO_FRAME_CREDIT_H
