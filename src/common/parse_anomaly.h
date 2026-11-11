/// @file parse_anomaly.h
/// @brief 协议解析"丢弃/异常/降级"点的限流诊断日志(现场排查用,不改任何解析行为)
/// @details 解析器各 msdu_parser 在越界/未知类型/位图溢出/CRC 失败等点调用
///          pa::warn(protocol:kind, msg);相同 key 在 1 秒内最多落 1 条 WARN,
///          其余累计 suppressed。回放结束时主程序调 pa::summarize() 输出
///          按类别汇总。线程安全(解析线程写 / 回放线程读用 QMutex 串行)。
///          本模块只打日志,绝不改变 accept/present/字段树等任何判定与返回值。
#ifndef BPLC_PARSE_ANOMALY_H
#define BPLC_PARSE_ANOMALY_H

#include <QDateTime>
#include <QHash>
#include <QMutex>
#include <QString>
#include <QStringList>
#include "QsLog.h"

namespace pa {

/// @brief 单个异常类别的限流计数
struct Counter {
    qint64 last_ms   = 0;  ///< 上次实际输出 WARN 的时间戳(epoch ms;0=从未输出)
    qint64 suppressed = 0; ///< 1 秒窗口内被合并抑制的条数
    qint64 total      = 0; ///< 该类别累计触发次数(含被抑制的)
};

/// @brief 全局限流表(进程级;跨翻译单元共享,经内联函数局部静态保证单实例)
inline QHash<QString, Counter>& counters() {
    static QHash<QString, Counter> c;
    return c;
}

/// @brief 保护 counters 的互斥锁(解析线程与回放线程可能并发访问)
inline QMutex& mutex() {
    static QMutex m;
    return m;
}

/// @brief 记录一条异常(限流:同 key 1 秒内最多 1 条 WARN,其余 suppressed)
/// @param key  异常类别键,约定 "协议:类别" 例如 "nw_2026:ie_overflow"
/// @param msg  单条详情(含类型/长度/偏移/声明 vs 实际等)
inline void warn(const QString& key, const QString& msg) {
    QMutexLocker lock(&mutex());
    Counter& c = counters()[key];
    ++c.total;
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    if (c.last_ms == 0 || now - c.last_ms >= 1000) {
        if (c.suppressed > 0) {
            QLOG_WARN() << "parse anomaly [" << key << "]: " << msg
                        << " (suppressed " << c.suppressed << ")";
        } else {
            QLOG_WARN() << "parse anomaly [" << key << "]: " << msg;
        }
        c.suppressed = 0;
        c.last_ms = now;
    } else {
        ++c.suppressed;
    }
}

/// @brief 回放结束汇总:输出 total + 按类别计数,并清空(供下一轮回放)
inline void summarize() {
    QMutexLocker lock(&mutex());
    qint64 total = 0;
    QStringList kinds;
    for (auto it = counters().constBegin(); it != counters().constEnd(); ++it) {
        total += it->total;
        kinds << QStringLiteral("%1=%2").arg(it.key()).arg(it->total);
    }
    if (total > 0) {
        QLOG_WARN() << "parse anomalies: total=" << total
                    << " by kind: " << kinds.join(QStringLiteral(", "));
    }
    counters().clear();
}

} // namespace pa

#endif  // BPLC_PARSE_ANOMALY_H
