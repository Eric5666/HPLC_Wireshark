#include "topo_worker.h"
#include "topo_controller.h"
#include "topo_input.h"

#include <QCoreApplication>
#include <QFileInfo>
#include <QEventLoop>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QThread>
#include <QTimer>
#include <QTemporaryDir>
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

TopoFrameInput association_frame_for(qint64 frame, quint16 tei, quint64 mac) {
    TopoFrameInput f = association_frame(frame, mac);
    f.events[0].nodes[0].tei = tei;
    f.msdu_src_tei = tei;
    return f;
}

TopoFrameInput restart_frame_for(qint64 frame, quint32 nid, quint16 tei,
                                 quint64 mac, int restart_count) {
    TopoFrameInput f;
    f.frame_index = frame;
    f.epoch_ms = 1000 + frame;
    f.net_id = nid;
    f.msdu_present = true;
    f.msdu_src_tei = tei;
    f.msdu_src_mac = mac;
    f.restart_count = restart_count;
    f.frame_kind = TopoEventKind::Other;
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

    bool target_anomaly_evicted_from_projection = false;
    bool evicted_anomaly_aggregate_preserved_before_replay = false;
    bool evicted_anomaly_aggregate_values_latest_before_replay = false;
    bool evicted_anomaly_aggregate_preserved_after_replay = false;
    bool evicted_anomaly_aggregate_values_latest_after_replay = false;
    int eviction_snapshot_count = -1;
    bool eviction_setup_started = false;
    {
        TopoController controller;
        QEventLoop eviction_loop;
        QTimer eviction_timeout;
        eviction_timeout.setSingleShot(true);
        QObject::connect(&eviction_timeout, &QTimer::timeout, &eviction_loop, &QEventLoop::quit);
        QObject::connect(&controller, &TopoController::live_states_reset, &app,
            [&](const TopoStateMap& states) {
                if (eviction_setup_started) return;
                const auto state = states.constFind(kNid);
                if (state == states.cend()) return;
                eviction_setup_started = true;
                eviction_snapshot_count = state->anomalies.size();
                const auto target = std::find_if(state->anomalies.cbegin(), state->anomalies.cend(),
                    [](const TopoAnomaly& a) {
                        return a.kind == TopoAnomalyKind::TeiMultipleMac && a.tei == 100;
                    });
                target_anomaly_evicted_from_projection = target == state->anomalies.cend();

                // Reintroduce the evicted TEI-keyed aggregate with a new MAC and a
                // changed restart-count transition, then query before/after replay.
                TopoFrameInput recurrence = association_frame_for(20466, 100, 0x1000000000002ULL);
                recurrence.epoch_ms = 900; // clock correction must not rewrite first_ms
                recurrence.events[0].epoch_ms = recurrence.epoch_ms;
                recurrence.restart_count = 3;
                controller.submit_frame(recurrence);
                controller.request_anomaly_page(8002, kNid, 0, 5000);
            });
        QObject::connect(&controller, &TopoController::anomaly_page_ready, &app,
            [&](const TopoAnomalyPage& page) {
                if (page.request_id == 8002) {
                    const auto it = std::find_if(page.items.cbegin(), page.items.cend(), [](const TopoAnomaly& a) {
                        return a.kind == TopoAnomalyKind::TeiMultipleMac && a.tei == 100;
                    });
                    evicted_anomaly_aggregate_preserved_before_replay = it != page.items.cend()
                        && it->trips == 2 && it->first_frame == 2 && it->first_ms == 1002
                        && it->last_frame == 20466 && it->last_ms == 900
                        && it->mac == 0x1000000000002ULL && it->mac_old == 0x1000000000001ULL;
                    const auto restart = std::find_if(page.items.cbegin(), page.items.cend(), [](const TopoAnomaly& a) {
                        return a.kind == TopoAnomalyKind::RestartCountOscillation && a.tei == 100;
                    });
                    evicted_anomaly_aggregate_values_latest_before_replay = restart != page.items.cend()
                        && restart->trips == 3 && restart->first_frame == 5 && restart->first_ms == 1005
                        && restart->last_frame == 20466 && restart->last_ms == 900
                        && restart->value_from == 2 && restart->value_to == 3;

                    TopoFrameInput late;
                    late.frame_index = 8195;
                    late.epoch_ms = 9195;
                    late.net_id = kNid;
                    controller.submit_frame(late);
                    controller.request_anomaly_page(8003, kNid, 0, 5000);
                    return;
                }
                if (page.request_id != 8003) return;
                const auto it = std::find_if(page.items.cbegin(), page.items.cend(), [](const TopoAnomaly& a) {
                    return a.kind == TopoAnomalyKind::TeiMultipleMac && a.tei == 100;
                });
                evicted_anomaly_aggregate_preserved_after_replay = it != page.items.cend()
                    && it->trips == 2 && it->first_frame == 2 && it->first_ms == 1002
                    && it->last_frame == 20466 && it->last_ms == 900
                    && it->mac == 0x1000000000002ULL && it->mac_old == 0x1000000000001ULL;
                const auto restart = std::find_if(page.items.cbegin(), page.items.cend(), [](const TopoAnomaly& a) {
                    return a.kind == TopoAnomalyKind::RestartCountOscillation && a.tei == 100;
                });
                evicted_anomaly_aggregate_values_latest_after_replay = restart != page.items.cend()
                    && restart->trips == 3 && restart->first_frame == 5 && restart->first_ms == 1005
                    && restart->last_frame == 20466 && restart->last_ms == 900
                    && restart->value_from == 2 && restart->value_to == 3;
                eviction_loop.quit();
            });

        // Frame 1 establishes TEI 100 / MAC A; frame 2 changes it to MAC B and
        // creates the target anomaly with trips=1 and first_frame=2. Then 4096
        // distinct TEI subjects each change MAC once, producing one TeiMultipleMac
        // key; each then has a restart-count oscillation, producing a second distinct
        // key. Together these 4096 newer subjects truly evict TEI 100.
        controller.submit_frame(association_frame_for(1, 100, 0x1000000000000ULL));
        controller.submit_frame(association_frame_for(2, 100, 0x1000000000001ULL));
        // Keep a second aggregate with meaningful value_from/value_to fields. Its
        // last pre-eviction transition is 3->2; recurrence must replace that with 2->3.
        controller.submit_frame(restart_frame_for(3, kNid, 100, 0x1000000000001ULL, 3));
        controller.submit_frame(restart_frame_for(4, kNid, 100, 0x1000000000001ULL, 2));
        controller.submit_frame(restart_frame_for(5, kNid, 100, 0x1000000000001ULL, 3));
        controller.submit_frame(restart_frame_for(6, kNid, 100, 0x1000000000001ULL, 2));
        qint64 frame = 7;
        for (int i = 0; i < 2048; ++i) {
            const quint16 tei = quint16(200 + i);
            controller.submit_frame(association_frame_for(frame++, tei, 0x300000000000ULL + quint64(i) * 2));
            controller.submit_frame(association_frame_for(frame++, tei, 0x300000000001ULL + quint64(i) * 2));
            for (int restart_count : {3, 2, 3}) {
                TopoFrameInput sample;
                sample.frame_index = frame++;
                sample.epoch_ms = 1000 + sample.frame_index;
                sample.net_id = kNid;
                sample.msdu_present = true;
                sample.msdu_src_tei = tei;
                sample.msdu_src_mac = 0x300000000001ULL + quint64(i) * 2;
                sample.restart_count = restart_count;
                controller.submit_frame(sample);
            }
        }
        controller.request_live_snapshot();
        eviction_timeout.start(60000);
        eviction_loop.exec();
    }
    std::printf("DIAG eviction_snapshot_count=%d evicted=%d before_replay=%d latest_values_before=%d after_replay=%d latest_values_after=%d\n",
                eviction_snapshot_count, target_anomaly_evicted_from_projection,
                evicted_anomaly_aggregate_preserved_before_replay,
                evicted_anomaly_aggregate_values_latest_before_replay,
                evicted_anomaly_aggregate_preserved_after_replay,
                evicted_anomaly_aggregate_values_latest_after_replay);
    CHECK("old anomaly is truly evicted from the 4096-entry in-memory projection",
          eviction_snapshot_count == 4096 && target_anomaly_evicted_from_projection);
    CHECK("SQLite retains trips, original first fields, and latest fields after eviction",
          evicted_anomaly_aggregate_preserved_before_replay);
    CHECK("SQLite replaces latest value fields after an evicted aggregate recurs",
          evicted_anomaly_aggregate_values_latest_before_replay);
    CHECK("late-frame replay rebuild preserves the same anomaly aggregate",
          evicted_anomaly_aggregate_preserved_after_replay
          && evicted_anomaly_aggregate_values_latest_after_replay);

    bool rebuild_failure_triggered = false;
    bool rebuild_rollback_preserved_old_index = false;
    bool rebuild_test_timed_out = false;
    {
        QTemporaryDir db_dir;
        const QString db_path = db_dir.filePath(QStringLiteral("rebuild-rollback.sqlite3"));
        QThread rebuild_thread;
        auto* rebuild_worker = new TopoReplayWorker(db_path, 2, 4);
        rebuild_worker->moveToThread(&rebuild_thread);
        QObject::connect(&rebuild_thread, &QThread::started,
                         rebuild_worker, &TopoReplayWorker::initialize);
        QEventLoop rebuild_loop;
        QTimer rebuild_timeout;
        rebuild_timeout.setSingleShot(true);
        QObject::connect(&rebuild_timeout, &QTimer::timeout, &rebuild_loop, [&] {
            rebuild_test_timed_out = true;
            rebuild_loop.quit();
        });
        bool rebuild_store_ready = false;
        QString rebuild_db_path;
        QObject::connect(rebuild_worker, &TopoReplayWorker::storage_ready, &app,
            [&](const QString& path) {
                rebuild_store_ready = true;
                rebuild_db_path = path;
                QMetaObject::invokeMethod(rebuild_worker, [rebuild_worker] {
                    rebuild_worker->submit_frame(association_frame_for(1, 5, 0x5000));
                    rebuild_worker->submit_frame(association_frame_for(2, 5, 0x5001));
                    rebuild_worker->submit_frame(association_frame_for(3, 6, 0x6000));
                    rebuild_worker->submit_frame(association_frame_for(4, 6, 0x6001));
                    rebuild_worker->request_anomaly_page(9101, kNid, 0, 10);
                }, Qt::QueuedConnection);
            }, Qt::QueuedConnection);
        QObject::connect(rebuild_worker, &TopoReplayWorker::anomaly_page_ready, &app,
            [&](const TopoAnomalyPage& page) {
                if (page.request_id != 9101) return;
                const auto tei5 = std::find_if(page.items.cbegin(), page.items.cend(), [](const TopoAnomaly& a) {
                    return a.kind == TopoAnomalyKind::TeiMultipleMac && a.tei == 5;
                });
                const auto tei6 = std::find_if(page.items.cbegin(), page.items.cend(), [](const TopoAnomaly& a) {
                    return a.kind == TopoAnomalyKind::TeiMultipleMac && a.tei == 6;
                });
                if (page.total != 2 || tei5 == page.items.cend() || tei6 == page.items.cend()) {
                    ++failures;
                    std::printf("FAIL transaction rollback fixture has two baseline anomaly rows\n");
                    rebuild_loop.quit();
                    return;
                }

                // Open the worker store through a second QtSql connection and
                // install the failure trigger there; the worker keeps its own
                // connection open on the same WAL database.
                QSqlDatabase trigger_db = QSqlDatabase::addDatabase(
                    QStringLiteral("QSQLITE"), QStringLiteral("topo-probe-trigger"));
                trigger_db.setDatabaseName(rebuild_db_path);
                if (!trigger_db.open()) {
                    ++failures;
                    std::printf("FAIL open topology DB to install replay failure trigger\n");
                    rebuild_loop.quit();
                    return;
                }
                QSqlQuery trigger_query(trigger_db);
                trigger_query.exec(QStringLiteral("PRAGMA busy_timeout=2000"));
                if (!trigger_query.exec(QStringLiteral(
                        "CREATE TRIGGER fail_rebuild_tei6 BEFORE INSERT ON topo_anomalies "
                        "WHEN NEW.tei=6 BEGIN SELECT RAISE(ABORT,'injected replay rebuild failure'); END;"))) {
                    std::fprintf(stderr, "trigger install failed: %s\n",
                                 qPrintable(trigger_query.lastError().text()));
                    trigger_db.close();
                    trigger_db = QSqlDatabase();
                    QSqlDatabase::removeDatabase(QStringLiteral("topo-probe-trigger"));
                    ++failures;
                    std::printf("FAIL install topology replay failure trigger\n");
                    rebuild_loop.quit();
                    return;
                }
                trigger_db.close();
                trigger_db = QSqlDatabase();
                QSqlDatabase::removeDatabase(QStringLiteral("topo-probe-trigger"));

                // A duplicate/out-of-order frame invokes full replay. TEI 5 is
                // inserted first during rebuild; TEI 6 then fails, so rollback
                // must discard partial writes and restore both baseline rows.
                QMetaObject::invokeMethod(rebuild_worker, [rebuild_worker] {
                    rebuild_worker->submit_frame(ordinary_frame(3));
                }, Qt::QueuedConnection);
            });
        QObject::connect(rebuild_worker, &TopoReplayWorker::worker_error, &app,
            [&](const QString& message) {
                rebuild_failure_triggered = message.contains(QStringLiteral("persist topology anomalies"));
                if (!rebuild_failure_triggered) {
                    ++failures;
                    std::fprintf(stderr, "unexpected rebuild test worker error: %s\n", qPrintable(message));
                    rebuild_loop.quit();
                    return;
                }
                QSqlDatabase check_db = QSqlDatabase::addDatabase(
                    QStringLiteral("QSQLITE"), QStringLiteral("topo-probe-check"));
                check_db.setDatabaseName(rebuild_db_path);
                if (check_db.open()) {
                    QSqlQuery check_query(check_db);
                    check_query.prepare(QStringLiteral(
                        "SELECT COUNT(*),COALESCE(SUM(trips),0),MIN(first_frame),MAX(last_frame) "
                        "FROM topo_anomalies WHERE nid=?"));
                    check_query.bindValue(0, kNid);
                    if (check_query.exec() && check_query.next()) {
                        rebuild_rollback_preserved_old_index = check_query.value(0).toInt() == 2
                            && check_query.value(1).toInt() == 2
                            && check_query.value(2).toLongLong() == 2
                            && check_query.value(3).toLongLong() == 4;
                    }
                }
                check_db.close();
                check_db = QSqlDatabase();
                QSqlDatabase::removeDatabase(QStringLiteral("topo-probe-check"));
                rebuild_loop.quit();
            }, Qt::QueuedConnection);

        rebuild_thread.start();
        rebuild_timeout.start(10000);
        rebuild_loop.exec();
        if (rebuild_store_ready) {
            QMetaObject::invokeMethod(rebuild_worker, "shutdown", Qt::BlockingQueuedConnection);
            rebuild_thread.quit();
            rebuild_thread.wait();
            delete rebuild_worker;
        } else {
            rebuild_thread.quit();
            rebuild_thread.wait();
            delete rebuild_worker;
        }
    }
    CHECK("failed replay rebuild is injected after a partial anomaly-index insert",
          rebuild_failure_triggered && !rebuild_test_timed_out);
    CHECK("replay rebuild rollback preserves the previous complete SQLite anomaly index",
          rebuild_rollback_preserved_old_index);

    bool open_history_failure_reported = false;
    bool open_history_ready_emitted = false;
    bool open_history_test_timed_out = false;
    {
        QTemporaryDir db_dir;
        QThread thread;
        // Using an existing directory as the database filename deterministically
        // makes QSQLITE::open() fail without relying on filesystem permissions.
        auto* worker = new TopoReplayWorker(db_dir.path(), 2, 4);
        worker->moveToThread(&thread);
        QObject::connect(&thread, &QThread::started, worker, &TopoReplayWorker::initialize);
        QEventLoop loop;
        QTimer timeout;
        timeout.setSingleShot(true);
        QObject::connect(&timeout, &QTimer::timeout, &loop, [&] {
            open_history_test_timed_out = true;
            loop.quit();
        });
        QObject::connect(worker, &TopoReplayWorker::worker_error, &app,
            [worker](const QString& message) {
                if (message.contains(QStringLiteral("Cannot open topology SQLite store"))) {
                    QMetaObject::invokeMethod(worker, [worker] {
                        worker->request_history(9201, 42, 4200, true);
                    }, Qt::QueuedConnection);
                }
            }, Qt::QueuedConnection);
        QObject::connect(worker, &TopoReplayWorker::history_ready, &app,
            [&](quint64, qint64, qint64, bool, const TopoStateMap&) {
                open_history_ready_emitted = true;
                loop.quit();
            }, Qt::QueuedConnection);
        QObject::connect(worker, &TopoReplayWorker::history_failed, &app,
            [&](quint64 request_id, qint64 target_frame, qint64 target_ms, bool active,
                const QString& message) {
                open_history_failure_reported = request_id == 9201 && target_frame == 42
                    && target_ms == 4200 && active
                    && message.contains(QStringLiteral("Cannot open topology SQLite store"));
                loop.quit();
            }, Qt::QueuedConnection);
        thread.start();
        timeout.start(10000);
        loop.exec();
        QMetaObject::invokeMethod(worker, "shutdown", Qt::BlockingQueuedConnection);
        thread.quit();
        thread.wait();
        delete worker;
    }
    CHECK("history request reports database-open failure with request identity and reason",
          open_history_failure_reported && !open_history_ready_emitted
          && !open_history_test_timed_out);

    bool reconstruction_history_failure_reported = false;
    bool reconstruction_history_ready_emitted = false;
    bool reconstruction_test_timed_out = false;
    bool reconstruction_table_dropped = false;
    {
        QTemporaryDir db_dir;
        const QString db_path = db_dir.filePath(QStringLiteral("history-reconstruction.sqlite3"));
        QThread thread;
        auto* worker = new TopoReplayWorker(db_path, 2, 4);
        worker->moveToThread(&thread);
        QObject::connect(&thread, &QThread::started, worker, &TopoReplayWorker::initialize);
        QEventLoop loop;
        QTimer timeout;
        timeout.setSingleShot(true);
        QObject::connect(&timeout, &QTimer::timeout, &loop, [&] {
            reconstruction_test_timed_out = true;
            loop.quit();
        });
        QObject::connect(worker, &TopoReplayWorker::storage_ready, &app,
            [worker](const QString&) {
                QMetaObject::invokeMethod(worker, [worker] {
                    worker->submit_frame(association_frame_for(1, 5, 0x5000));
                    worker->request_frame_page(9202, 0, 10);
                }, Qt::QueuedConnection);
            }, Qt::QueuedConnection);
        QObject::connect(worker, &TopoReplayWorker::frame_page_ready, &app,
            [&](const TopoFramePage& page) {
                if (page.request_id != 9202) return;
                if (page.total != 1) {
                    loop.quit();
                    return;
                }
                {
                    QSqlDatabase failure_db = QSqlDatabase::addDatabase(
                        QStringLiteral("QSQLITE"), QStringLiteral("topo-probe-history-failure"));
                    failure_db.setDatabaseName(db_path);
                    if (failure_db.open()) {
                        QSqlQuery failure_query(failure_db);
                        reconstruction_table_dropped = failure_query.exec(
                            QStringLiteral("DROP TABLE topo_frames"));
                    }
                    failure_db.close();
                    failure_db = QSqlDatabase();
                    QSqlDatabase::removeDatabase(QStringLiteral("topo-probe-history-failure"));
                }
                if (!reconstruction_table_dropped) {
                    loop.quit();
                    return;
                }
                QMetaObject::invokeMethod(worker, [worker] {
                    worker->request_history(9203, 1, 1001, true);
                }, Qt::QueuedConnection);
            }, Qt::QueuedConnection);
        QObject::connect(worker, &TopoReplayWorker::history_ready, &app,
            [&](quint64 request_id, qint64, qint64, bool, const TopoStateMap&) {
                if (request_id == 9203) {
                    reconstruction_history_ready_emitted = true;
                    loop.quit();
                }
            }, Qt::QueuedConnection);
        QObject::connect(worker, &TopoReplayWorker::history_failed, &app,
            [&](quint64 request_id, qint64 target_frame, qint64 target_ms, bool active,
                const QString& message) {
                if (request_id != 9203) return;
                reconstruction_history_failure_reported = target_frame == 1 && target_ms == 1001
                    && active && message.contains(QStringLiteral("read topology frames"));
                loop.quit();
            }, Qt::QueuedConnection);
        thread.start();
        timeout.start(10000);
        loop.exec();
        QMetaObject::invokeMethod(worker, "shutdown", Qt::BlockingQueuedConnection);
        thread.quit();
        thread.wait();
        delete worker;
    }
    CHECK("history request reports state-reconstruction failure instead of hanging",
          reconstruction_table_dropped && reconstruction_history_failure_reported
          && !reconstruction_history_ready_emitted && !reconstruction_test_timed_out);

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
