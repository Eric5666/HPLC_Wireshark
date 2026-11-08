#include "topo_worker.h"
#include "topo_controller.h"
#include "topo_input.h"

#include <QCoreApplication>
#include <QFileInfo>
#include <QEventLoop>
#include <QThread>
#include <QTimer>
#include <atomic>
#include <algorithm>
#include <cstdio>

namespace {
int failures = 0;
#define CHECK(label, expr) do { \
    const bool ok = (expr); \
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", label); \
    if (!ok) ++failures; \
} while (0)

constexpr quint32 kNid = 0x12;
constexpr quint32 kRestartOnlyNid = 0x13;
constexpr quint16 kTei = 5;
constexpr quint64 kMac = 0x123456789abcULL;

TopoEvent node_event(TopoEventKind kind, qint64 frame) {
    TopoEvent e;
    e.kind = kind;
    e.nid = kNid;
    e.epoch_ms = 1000 + frame;
    e.frame_index = frame;
    e.sender_mac = kMac;
    if (kind == TopoEventKind::LeaveInd)
        e.leaves.append(kMac);
    else
        e.nodes.append({kTei, kMac});
    return e;
}

TopoFrameInput event_frame(qint64 frame, TopoEventKind kind) {
    TopoFrameInput f;
    f.frame_index = frame;
    f.epoch_ms = 1000 + frame;
    f.net_id = kNid;
    f.events.append(node_event(kind, frame));
    f.msdu_present = true;
    f.msdu_src_tei = kTei;
    f.msdu_src_mac = kMac;
    f.restart_count = -1;
    f.frame_kind = kind;
    return f;
}

TopoFrameInput association_frame(qint64 frame, quint64 mac) {
    TopoFrameInput f = event_frame(frame, TopoEventKind::AssocCnf);
    TopoEvent& event = f.events[0];
    event.sender_mac = mac;
    event.nodes[0].mac = mac;
    f.msdu_src_mac = mac;
    return f;
}

TopoFrameInput ordinary_frame(qint64 frame) {
    TopoFrameInput f;
    f.frame_index = frame;
    f.epoch_ms = 1000 + frame;
    f.net_id = kNid;
    f.frame_src_tei = kTei;
    f.msdu_present = true;
    f.msdu_src_tei = kTei;
    f.msdu_src_mac = kMac;
    f.restart_count = -1;
    f.frame_kind = TopoEventKind::Other;
    return f;
}

TopoFrameInput restart_sample_frame(qint64 frame, int restart_count) {
    TopoFrameInput f;
    f.frame_index = frame;
    f.epoch_ms = 1000 + frame;
    f.net_id = kRestartOnlyNid;
    f.msdu_present = true;
    f.msdu_src_tei = kTei;
    f.msdu_src_mac = kMac + 1;
    f.restart_count = restart_count;
    f.frame_kind = TopoEventKind::Other;
    return f;
}
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QThread worker_thread;
    auto* worker = new TopoReplayWorker(QString(), 2, 4);
    worker->moveToThread(&worker_thread);
    QObject::connect(&worker_thread, &QThread::started, worker, &TopoReplayWorker::initialize);

    QEventLoop loop;
    QTimer timeout;
    timeout.setSingleShot(true);
    QObject::connect(&timeout, &QTimer::timeout, &loop, &QEventLoop::quit);

    bool got_history_3 = false;
    bool got_history_4 = false;
    bool reset_after_late_insert = false;
    bool history3_offline = false;
    bool history4_online = false;
    bool restart_only_nid_survives_checkpoint = false;
    bool temp_database_created = false;
    std::atomic<bool> signal_emitted_on_worker{false};

    QObject::connect(worker, &TopoReplayWorker::storage_ready, &app,
        [&](const QString& path) { temp_database_created = !path.isEmpty() && QFileInfo::exists(path); },
        Qt::QueuedConnection);
    QObject::connect(worker, &TopoReplayWorker::live_state_changed, &app,
        [&] { signal_emitted_on_worker.store(QThread::currentThread() == &worker_thread); },
        Qt::DirectConnection);
    QObject::connect(worker, &TopoReplayWorker::live_states_reset, &app,
        [&](const QHash<quint32, TopoState>&) { reset_after_late_insert = true; },
        Qt::QueuedConnection);
    QObject::connect(worker, &TopoReplayWorker::worker_error, &app,
        [&](const QString& message) { std::fprintf(stderr, "worker error: %s\n", qPrintable(message)); ++failures; },
        Qt::QueuedConnection);
    QObject::connect(worker, &TopoReplayWorker::history_ready, &app,
        [&](quint64, qint64 target, qint64, bool, const QHash<quint32, TopoState>& states) {
            const auto it = states.constFind(kNid);
            if (target == 3) {
                got_history_3 = true;
                history3_offline = it != states.cend() && it->nodes.contains(kTei)
                    && it->nodes.value(kTei).status == NodeStatus::Offline;
            } else if (target == 4) {
                got_history_4 = true;
                history4_online = it != states.cend() && it->nodes.contains(kTei)
                    && it->nodes.value(kTei).status == NodeStatus::Online;
            } else if (target == 8) {
                const auto restart = states.constFind(kRestartOnlyNid);
                restart_only_nid_survives_checkpoint = restart != states.cend()
                    && restart->events.isEmpty() && restart->first_seen_frame < 0
                    && restart->nodes.isEmpty() && restart->has_event_history
                    && restart->has_topology_content();
            }
            if (got_history_3 && got_history_4 && restart_only_nid_survives_checkpoint) loop.quit();
        }, Qt::QueuedConnection);

    worker_thread.start();
    timeout.start(10000);
    QMetaObject::invokeMethod(worker, [=] {
        worker->submit_frame(event_frame(1, TopoEventKind::AssocCnf));
        worker->submit_frame(event_frame(3, TopoEventKind::LeaveInd));
        worker->submit_frame(ordinary_frame(4));
        // Delayed frame 2 arrives after 4: the worker inserts it by frame order and rebuilds.
        worker->submit_frame(event_frame(2, TopoEventKind::AssocReq));
        // A restart-only NID has no first_seen_frame or nodes. Its restart event must
        // keep it visible even after the frame-8 checkpoint drops the event projection.
        worker->submit_frame(restart_sample_frame(6, 1));
        worker->submit_frame(restart_sample_frame(8, 2));
        worker->request_history(1, 3, 1003, true);
        worker->request_history(2, 4, 1004, true);
        worker->request_history(3, 8, 1008, true);
    }, Qt::QueuedConnection);
    loop.exec();

    CHECK("worker created temporary SQLite database", temp_database_created);
    CHECK("live state signal emitted on topology worker thread", signal_emitted_on_worker.load());
    CHECK("late frame caused live-state rebuild notification", reset_after_late_insert);
    CHECK("history at frame 3 is offline after leave indication", got_history_3 && history3_offline);
    CHECK("history at frame 4 is online after ordinary data revival", got_history_4 && history4_online);
    CHECK("restart-only NID stays visible when checkpoint omits event rows",
          restart_only_nid_survives_checkpoint);

    QMetaObject::invokeMethod(worker, "shutdown", Qt::BlockingQueuedConnection);
    worker_thread.quit();
    worker_thread.wait();
    delete worker;


    // Exercise the service API without a MainWindow: it owns its worker and publishes
    // copied state through signals, never a borrowed model pointer.
    bool controller_update = false;
    bool controller_history_ready = false;
    bool controller_live_snapshot = false;
    int controller_event_count = 0;
    bool frame_page_ok = false;
    bool anomaly_page_ok = false;
    {
        TopoController controller;
        QEventLoop controller_loop;
        QTimer controller_timeout;
        controller_timeout.setSingleShot(true);
        QObject::connect(&controller_timeout, &QTimer::timeout, &controller_loop, &QEventLoop::quit);
        QObject::connect(&controller, &TopoController::live_state_changed, &app,
            [&](quint32 nid, const TopoState& state) {
                if (!controller_update) {
                    controller_update = nid == kNid && state.nodes.contains(kTei);
                    controller.request_history(7001, 5000, 6000, true);
                }
            });
        QObject::connect(&controller, &TopoController::live_states_reset, &app,
            [&](const TopoStateMap& states) {
                const auto it = states.constFind(kNid);
                controller_live_snapshot = it != states.cend() && it->nodes.contains(kTei)
                    && it->nodes.value(kTei).mac == kMac + 1;
                if (frame_page_ok && anomaly_page_ok && controller_live_snapshot)
                    controller_loop.quit();
            });
        QObject::connect(&controller, &TopoController::history_ready, &app,
            [&](quint64 request_id, qint64 target_frame, qint64, bool, const TopoStateMap& states) {
                if (request_id != 7001 || target_frame != 5000) return;
                const auto it = states.constFind(kNid);
                if (it != states.cend()) controller_event_count = it->events.size();
                controller_history_ready = true;
                controller.request_frame_page(7002, 4999, 5);
                controller.request_anomaly_page(7003, kNid, 0, 2);
            });
        QObject::connect(&controller, &TopoController::frame_page_ready, &app,
            [&](const TopoFramePage& page) {
                if (page.request_id != 7002) return;
                frame_page_ok = page.total == 5001 && page.items.size() == 2
                    && page.items.first().frame_index == 5000;
                if (frame_page_ok && anomaly_page_ok && controller_live_snapshot) controller_loop.quit();
            });
        QObject::connect(&controller, &TopoController::anomaly_page_ready, &app,
            [&](const TopoAnomalyPage& page) {
                if (page.request_id != 7003) return;
                anomaly_page_ok = page.total == 1 && page.items.size() == 1
                    && page.items.first().kind == TopoAnomalyKind::TeiMultipleMac;
                if (frame_page_ok && anomaly_page_ok && controller_live_snapshot) controller_loop.quit();
            });
        // Standalone service stress: no MainWindow, 5k ordered events persisted/replayed.
        for (qint64 frame = 1; frame <= 5000; ++frame)
            controller.submit_frame(event_frame(frame, TopoEventKind::AssocCnf));
        TopoFrameInput conflict = event_frame(5001, TopoEventKind::AssocCnf);
        conflict.events[0].nodes[0].mac = kMac + 1;
        conflict.events[0].sender_mac = kMac + 1;
        conflict.msdu_src_mac = kMac + 1;
        controller.submit_frame(conflict);
        controller.request_live_snapshot();
        controller_timeout.start(10000);
        controller_loop.exec();
    }
    CHECK("controller API works without MainWindow", controller_update && controller_history_ready);
    CHECK("controller publishes a fresh live-state snapshot on request", controller_live_snapshot);
    CHECK("checkpoint snapshots keep only a bounded recent event projection",
          controller_event_count > 0 && controller_event_count <= 4096);
    CHECK("SQLite frame history is exposed as a bounded page", frame_page_ok);
    CHECK("anomaly records persist in SQLite and page independently", anomaly_page_ok);

    bool anomaly_history_survives_replay = false;
    {
        TopoController controller;
        QEventLoop stress_loop;
        QTimer stress_timeout;
        stress_timeout.setSingleShot(true);
        QObject::connect(&stress_timeout, &QTimer::timeout, &stress_loop, &QEventLoop::quit);
        QObject::connect(&controller, &TopoController::anomaly_page_ready, &app,
            [&](const TopoAnomalyPage& page) {
                if (page.request_id != 8001) return;
                anomaly_history_survives_replay = page.total == 1 && page.items.size() == 1
                    && page.items.first().kind == TopoAnomalyKind::TeiMultipleMac
                    && page.items.first().mac == kMac + 5001
                    && page.items.first().last_frame == 5001
                    && page.items.first().trips >= 5001;
                stress_loop.quit();
            });
        for (qint64 frame = 1; frame <= 5001; ++frame)
            controller.submit_frame(association_frame(frame, kMac + quint64(frame)));
        // Insert a late frame, forcing a full derived-history rebuild after >4096
        // distinct anomaly subjects have fallen out of TopoState's bounded projection.
        controller.submit_frame(association_frame(2500, kMac + 100000));
        controller.request_anomaly_page(8001, kNid, 0, 1);
        stress_timeout.start(30000);
        stress_loop.exec();
    }
    CHECK("SQLite keeps one up-to-date aggregate when anomaly MAC fields change and after replay",
          anomaly_history_survives_replay);

    TopoState bounded_history;
    for (int i = 1; i <= 5000; ++i) {
        TopoEvent event = node_event(TopoEventKind::AssocCnf, i);
        bounded_history.apply(event);
    }
    CHECK("in-memory recent event history is capped at 4096", bounded_history.events.size() == 4096);

    TopoState bounded_anomalies;
    bounded_anomalies.nid = kNid;
    quint16 latest_anomaly_tei = 0;
    qint64 anomaly_frame = 0;
    for (int i = 1; i <= 5000; ++i) {
        const quint16 tei = quint16(i + 1);
        latest_anomaly_tei = tei;
        const qint64 epoch = 1000 + ++anomaly_frame;
        bounded_anomalies.note_restart_count(tei, false, 3, epoch, anomaly_frame);
        bounded_anomalies.note_restart_count(tei, false, 2, epoch + 1, ++anomaly_frame);
        bounded_anomalies.note_restart_count(tei, false, 3, epoch + 2, ++anomaly_frame);
    }
    CHECK("in-memory anomaly projection is capped at 4096", bounded_anomalies.anomalies.size() == 4096);
    const auto recent_anomaly = std::find_if(bounded_anomalies.anomalies.cbegin(), bounded_anomalies.anomalies.cend(),
        [&](const TopoAnomaly& a) { return a.kind == TopoAnomalyKind::RestartCountOscillation && a.tei == latest_anomaly_tei; });
    const int most_recent_trips = recent_anomaly == bounded_anomalies.anomalies.cend() ? 0 : recent_anomaly->trips;
    bounded_anomalies.note_restart_count(latest_anomaly_tei, false, 2, 900000, ++anomaly_frame);
    bounded_anomalies.note_restart_count(latest_anomaly_tei, false, 3, 900001, ++anomaly_frame);
    const auto merged_anomaly = std::find_if(bounded_anomalies.anomalies.cbegin(), bounded_anomalies.anomalies.cend(),
        [&](const TopoAnomaly& a) { return a.kind == TopoAnomalyKind::RestartCountOscillation && a.tei == latest_anomaly_tei; });
    CHECK("recent anomaly can still merge after oldest entries are evicted",
          bounded_anomalies.anomalies.size() == 4096 && most_recent_trips == 1
          && merged_anomaly != bounded_anomalies.anomalies.cend() && merged_anomaly->trips >= 2);

    PacketEntry packet;
    packet.index = 77; packet.epoch_ms = 7700; packet.mpdu.net_id = kNid;
    packet.mpdu.src_tei = kTei; packet.protocol = kProtocolNw2021; packet.meta.is_rf = true;
    packet.msdu.present = true; packet.msdu.msdu_src_tei = kTei; packet.msdu.msdu_src_mac = kMac;
    packet.msdu.topo_event.kind = TopoEventKind::AssocCnf;
    packet.msdu.topo_event.link_type = LinkTypeRf;
    packet.msdu.topo_extra_events.append(node_event(TopoEventKind::LeaveInd, 77));
    packet.msdu.simple_head = true;
    packet.msdu.topo_event.neighbor_rates.append({kTei, 88});
    const TopoFrameInput normalized = make_topo_frame_input(packet);
    CHECK("topology input mapper normalizes events outside MainWindow",
          normalized.frame_index == 77 && normalized.net_id == kNid
          && normalized.events.size() == 2 && normalized.events[0].is_rf_known
          && normalized.events[0].is_rf && normalized.events[0].frame_index == 77);
    CHECK("topology input mapper preserves channel observations",
          normalized.has_channel_info && normalized.reporter_tei == kTei
          && normalized.channel_event.nid == kNid);

    std::printf("RESULT: %s failures: %d\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
