#ifndef BPLC_TOPO_CONTROLLER_H
#define BPLC_TOPO_CONTROLLER_H

#include "topo_worker.h"
#include <QObject>
#include <QThread>

/// GUI-thread facade for topology processing. Owns the worker thread and is the
/// only API used by application code; all worker traffic is queued and typed.
class TopoController final : public QObject {
    Q_OBJECT
public:
    explicit TopoController(QObject* parent = nullptr);
    ~TopoController() override;

    // Request a value snapshot over the signal interface; callers never borrow model storage.
    void request_live_snapshot();

public slots:
    void submit_frame(const TopoFrameInput& frame);
    void request_history(quint64 request_id, qint64 target_frame, qint64 target_ms, bool active);
    void request_frame_page(quint64 request_id, qint64 offset, int limit);
    void request_anomaly_page(quint64 request_id, quint32 nid, qint64 offset, int limit);
    void clear();

signals:
    void frame_submitted(const TopoFrameInput& frame);
    void history_requested(quint64 request_id, qint64 target_frame, qint64 target_ms, bool active);
    void frame_page_requested(quint64 request_id, qint64 offset, int limit);
    void anomaly_page_requested(quint64 request_id, quint32 nid, qint64 offset, int limit);
    void clear_requested();
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
    QThread m_thread;
    TopoReplayWorker* m_worker = nullptr;
};

#endif  // BPLC_TOPO_CONTROLLER_H
