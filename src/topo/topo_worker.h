#ifndef BPLC_TOPO_WORKER_H
#define BPLC_TOPO_WORKER_H

#include "topo_state.h"
#include <QObject>
#include <QMap>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QTemporaryDir>
#include <QThread>
#include <functional>

struct TopoFrameInput {
    qint64 frame_index = 0;
    qint64 epoch_ms = 0;
    quint32 net_id = 0;
    bool is_rf = false;
    QVector<TopoEvent> events;
    bool has_channel_info = false;
    quint16 reporter_tei = 0;
    TopoEvent channel_event;
    quint16 frame_src_tei = 0;
    quint16 frame_dst_tei = 0;
    bool msdu_present = false;
    quint16 msdu_src_tei = 0;
    quint64 msdu_src_mac = 0;
    int restart_count = -1;
    TopoEventKind frame_kind = TopoEventKind::Other;
};
Q_DECLARE_METATYPE(TopoFrameInput)
Q_DECLARE_METATYPE(TopoState)
using TopoStateMap = QHash<quint32, TopoState>;
Q_DECLARE_METATYPE(TopoStateMap)

struct TopoFramePage {
    quint64 request_id = 0;
    qint64 offset = 0;
    qint64 total = 0;
    bool ok = true;          ///< false:查询出错(items 为空,error 为原因),不是"没有数据"
    QString error;
    QVector<TopoFrameInput> items;
};
Q_DECLARE_METATYPE(TopoFramePage)

struct TopoAnomalyPage {
    quint64 request_id = 0;
    quint32 nid = 0;
    qint64 offset = 0;
    qint64 total = 0;
    bool ok = true;          ///< false:查询出错(items 为空,error 为原因),不是"没有数据"
    QString error;
    QVector<TopoAnomaly> items;
};
Q_DECLARE_METATYPE(TopoAnomalyPage)

/// Serializes topology state mutations and replay off the GUI thread. SQLite owns the
/// append-only session event history; a small bounded set of implicit-share snapshots
/// accelerates late-frame rebuilds without retaining the full log in RAM.
class TopoReplayWorker final : public QObject {
    Q_OBJECT
public:
    explicit TopoReplayWorker(QString database_path = QString(), int checkpoint_interval = 256,
                              int max_checkpoints = 8, QObject* parent = nullptr);
    ~TopoReplayWorker() override;

public slots:
    void initialize();
    void submit_frame(const TopoFrameInput& frame);
    // Emits a replayed value snapshot; event and anomaly projections are bounded.
    void request_history(quint64 request_id, qint64 target_frame, qint64 target_ms, bool active);
    void publish_live_snapshot();
    void request_frame_page(quint64 request_id, qint64 offset, int limit);
    void request_anomaly_page(quint64 request_id, quint32 nid, qint64 offset, int limit);
    void clear();
    void shutdown();

signals:
    void storage_ready(const QString& database_path);
    void live_state_changed(quint32 nid, const TopoState& state);
    void live_states_reset(const TopoStateMap& states);
    void history_ready(quint64 request_id, qint64 target_frame, qint64 target_ms,
                       bool active, const TopoStateMap& states);
    void history_failed(quint64 request_id, qint64 target_frame, qint64 target_ms,
                        bool active, const QString& message);
    void worker_error(const QString& message);
    void frame_page_ready(const TopoFramePage& page);
    void anomaly_page_ready(const TopoAnomalyPage& page);

private:
    struct StoredFrame { qint64 frame_index = 0; qint64 row_id = 0; QByteArray payload; };
    bool open_store();
    bool insert_frame(const TopoFrameInput& frame);
    bool visit_frames(qint64 after_frame, qint64 through_frame,
                      const std::function<bool(const TopoFrameInput&)>& visitor);
    bool clear_store();
    bool apply_frame(const TopoFrameInput& frame, TopoStateMap& states,
                     QSet<quint32>* changed_nids = nullptr, bool persist_anomalies = false);
    bool persist_anomalies(quint32 nid, TopoState& state, qint64 frame_index);
    void maybe_checkpoint(qint64 frame_index);
    void rebuild_live_from(qint64 frame_index);
    bool state_at(qint64 target_frame, TopoStateMap& states);
    QByteArray encode_frame(const TopoFrameInput& frame) const;
    bool decode_frame(const QByteArray& bytes, TopoFrameInput& frame) const;
    void report_store_error(const QString& message);
    void report_db_error(const QString& operation, const QString& detail);

    QString m_requested_db_path;
    QString m_database_path;
    QTemporaryDir* m_temp_dir = nullptr;
    int m_checkpoint_interval = 256;
    int m_max_checkpoints = 8;
    QSqlDatabase m_db;
    QSqlQuery m_insert_query;
    QString m_connection_name;
    TopoStateMap m_live_states;
    QMap<qint64, TopoStateMap> m_checkpoints;
    qint64 m_last_applied_frame = -1;
    bool m_store_failed = false;
    bool m_store_error_reported = false;
    QString m_last_insert_error;
    bool m_frame_store_failing = false;   ///< 当前处于连续入库失败中(只报一次)
    QString m_store_error_message;
};

#endif  // BPLC_TOPO_WORKER_H
