#include "topo_controller.h"
#include <QMetaObject>
#include <QDebug>

TopoController::TopoController(QObject* parent) : QObject(parent) {
    qRegisterMetaType<TopoFrameInput>("TopoFrameInput");
    qRegisterMetaType<TopoState>("TopoState");
    qRegisterMetaType<TopoStateMap>("TopoStateMap");
    qRegisterMetaType<TopoFramePage>("TopoFramePage");
    qRegisterMetaType<TopoAnomalyPage>("TopoAnomalyPage");
    m_worker = new TopoReplayWorker;
    m_worker->moveToThread(&m_thread);
    connect(&m_thread, &QThread::started, m_worker, &TopoReplayWorker::initialize);
    connect(this, &TopoController::frame_submitted, m_worker, &TopoReplayWorker::submit_frame, Qt::QueuedConnection);
    connect(this, &TopoController::history_requested, m_worker, &TopoReplayWorker::request_history, Qt::QueuedConnection);
    connect(this, &TopoController::frame_page_requested, m_worker, &TopoReplayWorker::request_frame_page, Qt::QueuedConnection);
    connect(this, &TopoController::anomaly_page_requested, m_worker, &TopoReplayWorker::request_anomaly_page, Qt::QueuedConnection);
    connect(this, &TopoController::clear_requested, m_worker, &TopoReplayWorker::clear, Qt::QueuedConnection);
    connect(m_worker, &TopoReplayWorker::live_state_changed, this, &TopoController::live_state_changed, Qt::QueuedConnection);
    connect(m_worker, &TopoReplayWorker::live_states_reset, this, &TopoController::live_states_reset, Qt::QueuedConnection);
    connect(m_worker, &TopoReplayWorker::history_ready, this, &TopoController::history_ready, Qt::QueuedConnection);
    connect(m_worker, &TopoReplayWorker::history_failed, this, &TopoController::history_failed, Qt::QueuedConnection);
    connect(m_worker, &TopoReplayWorker::frame_page_ready, this, &TopoController::frame_page_ready, Qt::QueuedConnection);
    connect(m_worker, &TopoReplayWorker::anomaly_page_ready, this, &TopoController::anomaly_page_ready, Qt::QueuedConnection);
    connect(m_worker, &TopoReplayWorker::worker_error, this, &TopoController::worker_error, Qt::QueuedConnection);
    connect(&m_thread, &QThread::finished, m_worker, &QObject::deleteLater);
    m_thread.start();
}

TopoController::~TopoController() {
    if (m_thread.isRunning()) {
        if (m_worker) QMetaObject::invokeMethod(m_worker, "shutdown", Qt::BlockingQueuedConnection);
        m_thread.quit();
        if (!m_thread.wait(5000)) {
            // 有界首等:超时只告警不放弃(强杀/析构仍在跑的 QThread 都更糟),随后继续等到退出
            qWarning() << "TopoController: thread still running after 5000 ms, waiting for it to finish";
            m_thread.wait();
        }
        m_worker = nullptr;
    }
}

void TopoController::submit_frame(const TopoFrameInput& frame) { emit frame_submitted(frame); }
void TopoController::request_history(quint64 id, qint64 frame, qint64 ms, bool active) {
    emit history_requested(id, frame, ms, active);
}
void TopoController::request_frame_page(quint64 id, qint64 offset, int limit) {
    emit frame_page_requested(id, offset, limit);
}
void TopoController::request_anomaly_page(quint64 id, quint32 nid, qint64 offset, int limit) {
    emit anomaly_page_requested(id, nid, offset, limit);
}
void TopoController::clear() { emit clear_requested(); }
void TopoController::request_live_snapshot() {
    if (m_worker) QMetaObject::invokeMethod(m_worker, "publish_live_snapshot", Qt::QueuedConnection);
}
