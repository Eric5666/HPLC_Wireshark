#include "topo_worker.h"
#include "packetentry_serialize.h"
#include "sqlite3.h"
#include <QDataStream>
#include <QDir>
#include <QFileInfo>
#include <QTemporaryDir>

namespace {
constexpr quint32 kFrameBlobVersion = 1;
constexpr quint32 kMaxStoredVector = 100000;
using SqliteDb = sqlite3;
using SqliteStmt = sqlite3_stmt;

QByteArray encode_event(const TopoEvent& event) {
    QByteArray bytes;
    QDataStream stream(&bytes, QIODevice::WriteOnly);
    stream.setVersion(QDataStream::Qt_6_0);
    pser::StrPool pool;
    pool.intern(event.desc);
    stream << quint32(1) << event.desc;
    pser::write_topo_event(stream, event, pool);
    return stream.status() == QDataStream::Ok ? bytes : QByteArray();
}

bool decode_event(const QByteArray& bytes, TopoEvent& event) {
    QDataStream stream(bytes);
    stream.setVersion(QDataStream::Qt_6_0);
    quint32 count = 0;
    stream >> count;
    if (count != 1) return false;
    QVector<QString> strings;
    strings.reserve(1);
    QString value;
    stream >> value;
    strings.append(value);
    pser::read_topo_event(stream, event, strings);
    return stream.status() == QDataStream::Ok && stream.atEnd();
}
}

TopoReplayWorker::TopoReplayWorker(QString database_path, int checkpoint_interval,
                                   int max_checkpoints, QObject* parent)
    : QObject(parent), m_requested_db_path(std::move(database_path)),
      m_checkpoint_interval(qMax(1, checkpoint_interval)),
      m_max_checkpoints(qMax(1, max_checkpoints)) {}

TopoReplayWorker::~TopoReplayWorker() { shutdown(); }

void TopoReplayWorker::initialize() {
    if (!open_store()) return;
    emit storage_ready(m_database_path);
}

bool TopoReplayWorker::open_store() {
    if (m_db) return true;
    if (m_store_failed) return false;
    if (m_requested_db_path.isEmpty()) {
        m_temp_dir = new QTemporaryDir(QDir::tempPath() + QStringLiteral("/hplc-topology-XXXXXX"));
        if (!m_temp_dir->isValid()) {
            delete m_temp_dir; m_temp_dir = nullptr;
            report_store_error(QStringLiteral("Cannot create temporary topology database directory"));
            return false;
        }
        m_database_path = m_temp_dir->filePath(QStringLiteral("topology.sqlite3"));
    } else {
        m_database_path = m_requested_db_path;
        QDir().mkpath(QFileInfo(m_database_path).absolutePath());
    }
    SqliteDb* db = nullptr;
    // sqlite3_open16 uses SQLite's default READWRITE|CREATE flags. All access is
    // serialized on this worker thread, so a NOMUTEX connection is unnecessary.
    const int rc = sqlite3_open16(m_database_path.utf16(), &db);
    if (rc != SQLITE_OK) {
        const QString reason = db ? QString::fromUtf8(sqlite3_errmsg(db)) : QStringLiteral("open failed");
        if (db) sqlite3_close(db);
        report_store_error(QStringLiteral("Cannot open topology SQLite store: %1").arg(reason));
        return false;
    }
    m_db = db;
    sqlite3_exec(db, "PRAGMA journal_mode=WAL", nullptr, nullptr, nullptr);
    sqlite3_exec(db, "PRAGMA synchronous=NORMAL", nullptr, nullptr, nullptr);
    const char* schema = "CREATE TABLE IF NOT EXISTS topo_frames ("
                         "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                         "frame_index INTEGER NOT NULL, payload BLOB NOT NULL);"
                         "CREATE INDEX IF NOT EXISTS topo_frames_order "
                         "ON topo_frames(frame_index,id);"
                         "CREATE TABLE IF NOT EXISTS topo_anomalies ("
                         "nid INTEGER NOT NULL, merge_key TEXT NOT NULL, kind INTEGER NOT NULL,"
                         "tei INTEGER NOT NULL, tei_old INTEGER NOT NULL, mac INTEGER NOT NULL,"
                         "mac_old INTEGER NOT NULL, is_rf INTEGER NOT NULL, trips INTEGER NOT NULL,"
                         "value_from INTEGER NOT NULL, value_to INTEGER NOT NULL,"
                         "first_ms INTEGER NOT NULL, last_ms INTEGER NOT NULL,"
                         "first_frame INTEGER NOT NULL, last_frame INTEGER NOT NULL,"
                         "UNIQUE(nid,merge_key));"
                         "CREATE INDEX IF NOT EXISTS topo_anomalies_order "
                         "ON topo_anomalies(nid,last_frame DESC);";
    char* error = nullptr;
    if (sqlite3_exec(db, schema, nullptr, nullptr, &error) != SQLITE_OK) {
        const QString reason = QString::fromUtf8(error ? error : sqlite3_errmsg(db));
        sqlite3_free(error);
        report_store_error(QStringLiteral("Cannot initialize topology SQLite schema: %1").arg(reason));
        shutdown();
        return false;
    }
    SqliteStmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, "INSERT INTO topo_frames(frame_index,payload) VALUES(?1,?2)",
                           -1, &stmt, nullptr) != SQLITE_OK) {
        report_sqlite_error(QStringLiteral("prepare frame insert"));
        shutdown();
        return false;
    }
    m_insert_stmt = stmt;
    return true;
}

QByteArray TopoReplayWorker::encode_frame(const TopoFrameInput& frame) const {
    QByteArray bytes;
    QDataStream s(&bytes, QIODevice::WriteOnly);
    s.setVersion(QDataStream::Qt_6_0);
    s << kFrameBlobVersion << frame.frame_index << frame.epoch_ms << frame.net_id << frame.is_rf;
    s << quint32(frame.events.size());
    for (const TopoEvent& e : frame.events) s << encode_event(e);
    s << frame.has_channel_info << frame.reporter_tei;
    if (frame.has_channel_info) s << encode_event(frame.channel_event);
    s << frame.frame_src_tei << frame.frame_dst_tei << frame.msdu_present
      << frame.msdu_src_tei << frame.msdu_src_mac << qint32(frame.restart_count)
      << quint8(frame.frame_kind);
    return s.status() == QDataStream::Ok ? bytes : QByteArray();
}

bool TopoReplayWorker::decode_frame(const QByteArray& bytes, TopoFrameInput& frame) const {
    QDataStream s(bytes);
    s.setVersion(QDataStream::Qt_6_0);
    quint32 version = 0, count = 0;
    s >> version >> frame.frame_index >> frame.epoch_ms >> frame.net_id >> frame.is_rf >> count;
    if (version != kFrameBlobVersion || count > kMaxStoredVector) return false;
    frame.events.clear();
    frame.events.reserve(int(count));
    for (quint32 i = 0; i < count; ++i) {
        QByteArray blob; TopoEvent e;
        s >> blob;
        if (!decode_event(blob, e)) return false;
        frame.events.append(std::move(e));
    }
    s >> frame.has_channel_info >> frame.reporter_tei;
    if (frame.has_channel_info) {
        QByteArray blob; s >> blob;
        if (!decode_event(blob, frame.channel_event)) return false;
    }
    quint8 kind = 0;
    qint32 rc = -1;
    s >> frame.frame_src_tei >> frame.frame_dst_tei >> frame.msdu_present
      >> frame.msdu_src_tei >> frame.msdu_src_mac >> rc >> kind;
    frame.restart_count = rc;
    frame.frame_kind = static_cast<TopoEventKind>(kind);
    return s.status() == QDataStream::Ok && s.atEnd();
}

bool TopoReplayWorker::insert_frame(const TopoFrameInput& frame) {
    if (!open_store()) return false;
    const QByteArray blob = encode_frame(frame);
    if (blob.isEmpty()) {
        report_store_error(QStringLiteral("Could not encode topology frame %1").arg(frame.frame_index));
        return false;
    }
    SqliteStmt* stmt = static_cast<SqliteStmt*>(m_insert_stmt);
    sqlite3_reset(stmt); sqlite3_clear_bindings(stmt);
    sqlite3_bind_int64(stmt, 1, frame.frame_index);
    sqlite3_bind_blob(stmt, 2, blob.constData(), blob.size(), SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        report_sqlite_error(QStringLiteral("insert topology frame"));
        return false;
    }
    return true;
}

bool TopoReplayWorker::visit_frames(qint64 after_frame, qint64 through_frame,
                                    const std::function<bool(const TopoFrameInput&)>& visitor) {
    SqliteDb* db = static_cast<SqliteDb*>(m_db);
    if (!db || m_store_failed) return false;
    SqliteStmt* stmt = nullptr;
    const char* sql = through_frame < 0
        ? "SELECT frame_index,payload FROM topo_frames WHERE frame_index>?1 ORDER BY frame_index,id"
        : "SELECT frame_index,payload FROM topo_frames WHERE frame_index>?1 AND frame_index<=?2 ORDER BY frame_index,id";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        report_sqlite_error(QStringLiteral("prepare frame query"));
        return false;
    }
    sqlite3_bind_int64(stmt, 1, after_frame);
    if (through_frame >= 0) sqlite3_bind_int64(stmt, 2, through_frame);
    int rc = SQLITE_ROW;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        TopoFrameInput frame;
        frame.frame_index = sqlite3_column_int64(stmt, 0);
        const auto* data = static_cast<const char*>(sqlite3_column_blob(stmt, 1));
        const int size = sqlite3_column_bytes(stmt, 1);
        if (!data || size <= 0 || !decode_frame(QByteArray(data, size), frame)) {
            sqlite3_finalize(stmt);
            report_store_error(QStringLiteral("Corrupt topology frame in replay store"));
            return false;
        }
        if (!visitor(frame)) {
            sqlite3_finalize(stmt);
            return false;
        }
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        report_sqlite_error(QStringLiteral("read topology frames"));
        return false;
    }
    return true;
}

bool TopoReplayWorker::apply_frame(const TopoFrameInput& f, TopoStateMap& states,
                                   QSet<quint32>* changed, bool write_anomalies) {
    if (f.net_id == 0) return true;
    bool touched = false;
    auto mark = [&] { touched = true; };
    for (const TopoEvent& e : f.events) {
        if (e.kind == TopoEventKind::Other || e.nid == 0) continue;
        TopoState& ts = states[e.nid];
        ts.apply(e);
        mark();
    }
    if (f.has_channel_info) {
        auto it = states.find(f.net_id);
        if (it != states.end()) {
            it->apply_channel_info(f.reporter_tei, f.channel_event);
            mark();
        }
    }
    if (f.msdu_present)
        ensure_restart_sample_state(states, f.net_id, f.restart_count);
    auto it = states.find(f.net_id);
    if (it != states.end()) {
        TopoState& ts = it.value();
        const quint16 tei = f.frame_src_tei ? f.frame_src_tei : f.frame_dst_tei;
        if (ts.note_frame_medium(tei, f.is_rf)) mark();
        if (ts.note_rf_capable(f.frame_src_tei, f.is_rf)) mark();
        if (f.msdu_present
            && ts.note_restart_count(f.msdu_src_tei, f.is_rf, f.restart_count,
                                     f.epoch_ms, f.frame_index)) mark();
        bool did_revive = false;
        if (f.msdu_present
            && ts.note_restart_origin(f.net_id, f.msdu_src_tei, f.msdu_src_mac,
                                      f.restart_count, f.epoch_ms, f.frame_index,
                                      f.is_rf, true, f.frame_kind, &did_revive)) mark();
        if (f.msdu_src_mac) {
            auto pit = ts.pending.find(f.msdu_src_mac);
            if (pit != ts.pending.end() && !pit.value().is_rf_known) {
                pit.value().is_rf = f.is_rf;
                pit.value().is_rf_known = true;
                mark();
            }
        }
    }
    if (touched && changed) changed->insert(f.net_id);
    if (touched && write_anomalies) {
        auto state = states.find(f.net_id);
        if (state != states.end() && !persist_anomalies(f.net_id, state.value(), f.frame_index)) return false;
    }
    return true;
}

bool TopoReplayWorker::persist_anomalies(quint32 nid, TopoState& state, qint64 frame_index) {
    SqliteDb* db = static_cast<SqliteDb*>(m_db);
    if (!db || m_store_failed) return false;
    SqliteStmt* stmt = nullptr;
    // The bounded in-memory projection may evict an aggregate. Persist only the
    // not-yet-written trip delta and let SQLite merge it into the durable row.
    // Replacing a row with the projection's local count would lose older history.
    const char* sql = "INSERT INTO topo_anomalies"
        "(nid,merge_key,kind,tei,tei_old,mac,mac_old,is_rf,trips,value_from,value_to,first_ms,last_ms,first_frame,last_frame)"
        " VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)"
        " ON CONFLICT(nid,merge_key) DO UPDATE SET"
        " kind=excluded.kind,tei=excluded.tei,tei_old=excluded.tei_old,"
        " mac=excluded.mac,mac_old=excluded.mac_old,is_rf=excluded.is_rf,"
        " trips=topo_anomalies.trips+excluded.trips,"
        " value_from=excluded.value_from,value_to=excluded.value_to,"
        // First occurrence fields are immutable after insertion. Frame order is
        // authoritative; timestamps can move backwards when clocks are corrected.
        " last_ms=excluded.last_ms,last_frame=excluded.last_frame";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        report_sqlite_error(QStringLiteral("prepare anomaly upsert"));
        return false;
    }
    bool ok = true;
    for (TopoAnomaly& a : state.anomalies) {
        // Persist only aggregates touched by this input frame. Rewriting the bounded UI
        // projection would both be quadratic and lose older rows after a replay rebuild.
        if (a.last_frame != frame_index) continue;
        const int trips_delta = a.trips - a.persisted_trips;
        if (trips_delta <= 0) continue;
        sqlite3_reset(stmt); sqlite3_clear_bindings(stmt);
        const QByteArray merge_key = topo_anomaly_merge_key(nid, a).toUtf8();
        sqlite3_bind_int64(stmt, 1, nid);
        sqlite3_bind_text(stmt, 2, merge_key.constData(), merge_key.size(), SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 3, int(a.kind));
        sqlite3_bind_int(stmt, 4, a.tei);
        sqlite3_bind_int(stmt, 5, a.tei_old);
        sqlite3_bind_int64(stmt, 6, sqlite3_int64(a.mac));
        sqlite3_bind_int64(stmt, 7, sqlite3_int64(a.mac_old));
        sqlite3_bind_int(stmt, 8, a.is_rf ? 1 : 0);
        sqlite3_bind_int(stmt, 9, trips_delta);
        sqlite3_bind_int(stmt, 10, a.value_from);
        sqlite3_bind_int(stmt, 11, a.value_to);
        sqlite3_bind_int64(stmt, 12, a.first_ms);
        sqlite3_bind_int64(stmt, 13, a.last_ms);
        sqlite3_bind_int64(stmt, 14, a.first_frame);
        sqlite3_bind_int64(stmt, 15, a.last_frame);
        if (sqlite3_step(stmt) != SQLITE_DONE) { ok = false; break; }
        a.persisted_trips = a.trips;
    }
    sqlite3_finalize(stmt);
    if (!ok) report_sqlite_error(QStringLiteral("persist topology anomalies"));
    return ok;
}

namespace {
TopoStateMap checkpoint_state(const TopoStateMap& live_states) {
    TopoStateMap snapshot = live_states;
    for (auto it = snapshot.begin(); it != snapshot.end(); ++it) {
        // Event rows are a display projection, not topology state needed to replay.
        // Preserve the boolean summary before dropping rows so an event-only NID remains visible.
        it->has_event_history = it->has_event_history || !it->events.isEmpty();
        it->events.clear();
        // Keep the bounded anomaly aggregates: TopoState uses these as its replay-time
        // deduplication/index state; the complete derived history is separately in SQLite.
    }
    return snapshot;
}
}

void TopoReplayWorker::maybe_checkpoint(qint64 frame_index) {
    if (frame_index <= 0 || frame_index % m_checkpoint_interval != 0) return;
    m_checkpoints.insert(frame_index, checkpoint_state(m_live_states));
    while (m_checkpoints.size() > m_max_checkpoints) m_checkpoints.erase(m_checkpoints.begin());
}

void TopoReplayWorker::submit_frame(const TopoFrameInput& frame) {
    if (frame.net_id == 0 || frame.frame_index <= 0) return;
    const bool stored = insert_frame(frame);
    if (frame.frame_index <= m_last_applied_frame) {
        if (stored) rebuild_live_from(frame.frame_index);
        else report_store_error(QStringLiteral("Cannot rebuild live topology after an out-of-order frame because the replay store is unavailable"));
        return;
    }
    QSet<quint32> changed;
    apply_frame(frame, m_live_states, &changed, stored);
    m_last_applied_frame = frame.frame_index;
    if (stored) maybe_checkpoint(frame.frame_index);
    for (quint32 nid : changed) emit live_state_changed(nid, m_live_states.value(nid));
}

void TopoReplayWorker::rebuild_live_from(qint64 frame_index) {
    Q_UNUSED(frame_index);
    SqliteDb* db = static_cast<SqliteDb*>(m_db);
    if (!db || m_store_failed) return;

    // The derived anomaly index is rebuilt from the authoritative ordered frame log.
    // Keep the previous complete index visible if reading or inserting any row fails.
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) != SQLITE_OK) {
        report_sqlite_error(QStringLiteral("begin topology replay rebuild"));
        return;
    }
    if (sqlite3_exec(db, "DELETE FROM topo_anomalies", nullptr, nullptr, nullptr) != SQLITE_OK) {
        const QString detail = QString::fromUtf8(sqlite3_errmsg(db));
        sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
        report_store_error(QStringLiteral("Topology SQLite reset anomaly index before replay failed: %1").arg(detail));
        return;
    }

    TopoStateMap rebuilt;
    QMap<qint64, TopoStateMap> rebuilt_checkpoints;
    qint64 last_frame = -1;
    const bool read_ok = visit_frames(-1, -1, [&](const TopoFrameInput& f) {
        if (!apply_frame(f, rebuilt, nullptr, true)) return false;
        last_frame = qMax(last_frame, f.frame_index);
        if (f.frame_index > 0 && f.frame_index % m_checkpoint_interval == 0) {
            rebuilt_checkpoints.insert(f.frame_index, checkpoint_state(rebuilt));
            while (rebuilt_checkpoints.size() > m_max_checkpoints)
                rebuilt_checkpoints.erase(rebuilt_checkpoints.begin());
        }
        return true;
    });
    if (!read_ok || m_store_failed) {
        // SQLite error reporting may set m_store_failed, but rollback must still run
        // directly on the open connection to preserve the old materialized index.
        if (sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr) != SQLITE_OK) {
            const QString detail = QString::fromUtf8(sqlite3_errmsg(db));
            report_store_error(QStringLiteral("Topology SQLite rollback after replay failure failed: %1").arg(detail));
        }
        return;
    }
    if (sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK) {
        const QString detail = QString::fromUtf8(sqlite3_errmsg(db));
        sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
        report_store_error(QStringLiteral("Topology SQLite commit replay rebuild failed: %1").arg(detail));
        return;
    }

    m_live_states = std::move(rebuilt);
    m_checkpoints = std::move(rebuilt_checkpoints);
    m_last_applied_frame = last_frame;
    emit live_states_reset(m_live_states);
}

bool TopoReplayWorker::state_at(qint64 target_frame, TopoStateMap& states) {
    states.clear();
    if (target_frame < 0) return true;
    auto cp = m_checkpoints.upperBound(target_frame);
    qint64 base_frame = -1;
    if (cp != m_checkpoints.begin()) {
        --cp;
        base_frame = cp.key();
        states = cp.value();
    }
    return visit_frames(base_frame, target_frame,
                        [&](const TopoFrameInput& f) { return apply_frame(f, states); });
}

void TopoReplayWorker::publish_live_snapshot() { emit live_states_reset(m_live_states); }

void TopoReplayWorker::request_frame_page(quint64 request_id, qint64 offset, int limit) {
    TopoFramePage page;
    page.request_id = request_id;
    page.offset = qMax<qint64>(0, offset);
    limit = qBound(1, limit, 500);
    if (!open_store()) { emit frame_page_ready(page); return; }
    SqliteDb* db = static_cast<SqliteDb*>(m_db);
    SqliteStmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM topo_frames", -1, &stmt, nullptr) != SQLITE_OK) {
        report_sqlite_error(QStringLiteral("count topology frames")); emit frame_page_ready(page); return;
    }
    if (sqlite3_step(stmt) == SQLITE_ROW) page.total = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    if (sqlite3_prepare_v2(db, "SELECT payload FROM topo_frames ORDER BY frame_index,id LIMIT ?1 OFFSET ?2", -1, &stmt, nullptr) != SQLITE_OK) {
        report_sqlite_error(QStringLiteral("prepare topology frame page")); emit frame_page_ready(page); return;
    }
    sqlite3_bind_int(stmt, 1, limit); sqlite3_bind_int64(stmt, 2, page.offset);
    int rc = SQLITE_ROW;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const auto* data = static_cast<const char*>(sqlite3_column_blob(stmt, 0));
        const int size = sqlite3_column_bytes(stmt, 0);
        TopoFrameInput frame;
        if (!data || size <= 0 || !decode_frame(QByteArray(data, size), frame)) {
            sqlite3_finalize(stmt); report_store_error(QStringLiteral("Corrupt topology frame in page query"));
            emit frame_page_ready(page); return;
        }
        page.items.append(std::move(frame));
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) report_sqlite_error(QStringLiteral("read topology frame page"));
    emit frame_page_ready(page);
}

void TopoReplayWorker::request_anomaly_page(quint64 request_id, quint32 nid, qint64 offset, int limit) {
    TopoAnomalyPage page;
    page.request_id = request_id; page.nid = nid; page.offset = qMax<qint64>(0, offset);
    limit = qBound(1, limit, 500);
    if (!open_store()) { emit anomaly_page_ready(page); return; }
    SqliteDb* db = static_cast<SqliteDb*>(m_db);
    SqliteStmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM topo_anomalies WHERE nid=?1", -1, &stmt, nullptr) != SQLITE_OK) {
        report_sqlite_error(QStringLiteral("count topology anomalies")); emit anomaly_page_ready(page); return;
    }
    sqlite3_bind_int64(stmt, 1, nid);
    if (sqlite3_step(stmt) == SQLITE_ROW) page.total = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    const char* sql = "SELECT kind,tei,tei_old,mac,mac_old,is_rf,trips,value_from,value_to,first_ms,last_ms,first_frame,last_frame "
                      "FROM topo_anomalies WHERE nid=?1 ORDER BY last_frame DESC LIMIT ?2 OFFSET ?3";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        report_sqlite_error(QStringLiteral("prepare topology anomaly page")); emit anomaly_page_ready(page); return;
    }
    sqlite3_bind_int64(stmt, 1, nid); sqlite3_bind_int(stmt, 2, limit); sqlite3_bind_int64(stmt, 3, page.offset);
    int rc = SQLITE_ROW;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        TopoAnomaly a;
        a.kind = static_cast<TopoAnomalyKind>(sqlite3_column_int(stmt, 0));
        a.tei = quint16(sqlite3_column_int(stmt, 1)); a.tei_old = quint16(sqlite3_column_int(stmt, 2));
        a.mac = quint64(sqlite3_column_int64(stmt, 3)); a.mac_old = quint64(sqlite3_column_int64(stmt, 4));
        a.is_rf = sqlite3_column_int(stmt, 5) != 0; a.trips = sqlite3_column_int(stmt, 6);
        a.persisted_trips = a.trips;
        a.value_from = sqlite3_column_int(stmt, 7); a.value_to = sqlite3_column_int(stmt, 8);
        a.first_ms = sqlite3_column_int64(stmt, 9); a.last_ms = sqlite3_column_int64(stmt, 10);
        a.first_frame = sqlite3_column_int64(stmt, 11); a.last_frame = sqlite3_column_int64(stmt, 12);
        page.items.append(a);
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) report_sqlite_error(QStringLiteral("read topology anomaly page"));
    emit anomaly_page_ready(page);
}

void TopoReplayWorker::request_history(quint64 request_id, qint64 target_frame,
                                       qint64 target_ms, bool active) {
    if (!open_store()) return;
    QHash<quint32, TopoState> states;
    if (!state_at(target_frame, states)) return;
    emit history_ready(request_id, target_frame, target_ms, active, states);
}

bool TopoReplayWorker::clear_store() {
    SqliteDb* db = static_cast<SqliteDb*>(m_db);
    return !db || sqlite3_exec(db, "DELETE FROM topo_frames; DELETE FROM topo_anomalies;", nullptr, nullptr, nullptr) == SQLITE_OK;
}

void TopoReplayWorker::clear() {
    if (!clear_store()) report_sqlite_error(QStringLiteral("clear topology store"));
    m_live_states.clear();
    m_checkpoints.clear();
    m_last_applied_frame = -1;
    emit live_states_reset(m_live_states);
}

void TopoReplayWorker::shutdown() {
    if (m_insert_stmt) {
        sqlite3_finalize(static_cast<SqliteStmt*>(m_insert_stmt));
        m_insert_stmt = nullptr;
    }
    if (m_db) {
        sqlite3_close(static_cast<SqliteDb*>(m_db));
        m_db = nullptr;
    }
    delete m_temp_dir;
    m_temp_dir = nullptr;
}

void TopoReplayWorker::report_store_error(const QString& message) {
    m_store_failed = true;
    if (m_store_error_reported) return;
    m_store_error_reported = true;
    emit worker_error(message);
}

void TopoReplayWorker::report_sqlite_error(const QString& operation) {
    auto* db = static_cast<SqliteDb*>(m_db);
    const QString detail = db ? QString::fromUtf8(sqlite3_errmsg(db)) : QStringLiteral("database unavailable");
    report_store_error(QStringLiteral("Topology SQLite %1 failed: %2").arg(operation, detail));
}
