/// @file statistics.h
/// @brief 帧类型统计:BEACON/SOF/ACK/COORD × HPLC/HRF
/// @details 内部 QHash<int, qint64> + QMutex,UI 端 500ms 拉一次 snapshot。
#ifndef BPLC_STATISTICS_H
#define BPLC_STATISTICS_H

#include <QObject>
#include <QHash>
#include <QMutex>

class FrameStatistics : public QObject {
    Q_OBJECT
public:
    enum Key {
        KEY_BEACON_HPLC,
        KEY_BEACON_HRF,
        KEY_SOF_HPLC,
        KEY_SOF_HRF,
        KEY_ACK_HPLC,
        KEY_ACK_HRF,
        KEY_COORD_HPLC,
        KEY_COORD_HRF,
        KEY_OTHER,
        KEY_DROPPED,
        KEY_MSDU_COMPLETE,
        KEY_COUNT
    };
    Q_ENUM(Key)

    explicit FrameStatistics(QObject* parent = nullptr);

    void increment(Key k, qint64 n = 1);
    void reset();

    QHash<int, qint64> snapshot() const;
    qint64 total() const;

private:
    mutable QMutex   m_mutex;
    QHash<int, qint64> m_counts;
};

#endif  // BPLC_STATISTICS_H
