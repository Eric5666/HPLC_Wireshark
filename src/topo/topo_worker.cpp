#include "topo_worker.h"
#include "packetentry_serialize.h"
#include <QAtomicInt>
#include <QDataStream>
#include <QDir>
#include <QFileInfo>
#include <QSqlError>
#include <QTemporaryDir>

namespace {
constexpr quint32 kFrameBlobVersion = 1;
constexpr quint32 kMaxStoredVector = 100000;
QAtomicInt s_connection_counter;

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
    if (m_db.isOpen()) return true;
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
    // One QSQLITE connection per worker instance, opened on this thread only.
    // All access is serialized on this worker thread.
    m_connection_name = QStringLiteral("topo-replay-%1").arg(s_connection_counter.fetchAndAddRelaxed(1));
    QSqlDatabase db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), m_connection_name);
    db.setDatabaseName(m_database_path);
    if (!db.open()) {
        const QString reason = db.lastError().text();
        db = QSqlDatabase();
        QSqlDatabase::removeDatabase(m_connection_name);
        m_connection_name.clear();
        report_store_error(QStringLiteral("Cannot open topology SQLite store: %1").arg(reason));
        return false;
    }
    m_db = db;
    QSqlQuery pragma(m_db);
    pragma.exec(QStringLiteral("PRAGMA journal_mode=WAL"));
    pragma.exec(QStringLiteral("PRAGMA synchronous=NORMAL"));
    // QSqlQuery executes one statement per exec(), so the schema is split into
    // separate statements instead of a single multi-statement string.
    static const char* const kSchemaStatements[] = {
        "CREATE TABLE IF NOT EXISTS topo_frames ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "frame_index INTEGER NOT NULL, payload BLOB NOT NULL)",
        "CREATE INDEX IF NOT EXISTS topo_frames_order "
        "ON topo_frames(frame_index,id)",
        "CREATE TABLE IF NOT EXISTS topo_anomalies ("
        "nid INTEGER NOT NULL, merge_key TEXT NOT NULL, kind INTEGER NOT NULL,"
        "tei INTEGER NOT NULL, tei_old INTEGER NOT NULL, mac INTEGER NOT NULL,"
        "mac_old INTEGER NOT NULL, is_rf INTEGER NOT NULL, trips INTEGER NOT NULL,"
        "value_from INTEGER NOT NULL, value_to INTEGER NOT NULL,"
        "first_ms INTEGER NOT NULL, last_ms INTEGER NOT NULL,"
        "first_frame INTEGER NOT NULL, last_frame INTEGER NOT NULL,"
        "UNIQUE(nid,merge_key))",
        "CREATE INDEX IF NOT EXISTS topo_anomalies_order "
        "ON topo_anomalies(nid,last_frame DESC)",
    };
    for (const char* statement : kSchemaStatements) {
        QSqlQuery query(m_db);
        if (!query.exec(QString::fromLatin1(statement))) {
            report_store_error(QStringLiteral("Cannot initialize topology SQLite schema: %1")
                                   .arg(query.lastError().text()));
            shutdown();
            return false;
        }
    }
    m_insert_query = QSqlQuery(m_db);
    if (!m_insert_query.prepare(QStringLiteral("INSERT INTO topo_frames(frame_index,payload) VALUES(?,?)"))) {
        report_db_error(QStringLiteral("prepare frame insert"), m_insert_query.lastError().text());
        shutdown();
        return false;
    }
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
    // 历史已标记不可用(入库失败/清库失败)时不再往库里追加帧,等成功清库后恢复
    if (m_store_failed || !open_store()) return false;
    const QByteArray blob = encode_frame(frame);
    if (blob.isEmpty()) {
        report_store_error(QStringLiteral("Could not encode topology frame %1").arg(frame.frame_index));
        return false;
    }
    m_insert_query.bindValue(0, frame.frame_index);
    m_insert_query.bindValue(1, blob);
    if (!m_insert_query.exec()) {
        // 入库失败:库内历史从此缺帧,历史回放标记为不可用(与 main 一致);
        // report_store_error 只报一次,后续帧不再刷屏
        report_db_error(QStringLiteral("insert topology frame"), m_insert_query.lastError().text());
        return false;
    }
    return true;
}

bool TopoReplayWorker::visit_frames(qint64 after_frame, qint64 through_frame,
                                    const std::function<bool(const TopoFrameInput&)>& visitor) {
    if (!m_db.isOpen() || m_store_failed) return false;
    QSqlQuery query(m_db);
    const QString sql = through_frame < 0
        ? QStringLiteral("SELECT frame_index,payload FROM topo_frames WHERE frame_index>? ORDER BY frame_index,id")
        : QStringLiteral("SELECT frame_index,payload FROM topo_frames WHERE frame_index>? AND frame_index<=? ORDER BY frame_index,id");
    if (!query.prepare(sql)) {
        report_db_error(QStringLiteral("prepare frame query"), query.lastError().text());
        return false;
    }
    query.bindValue(0, after_frame);
    if (through_frame >= 0) query.bindValue(1, through_frame);
    if (!query.exec()) {
        report_db_error(QStringLiteral("read topology frames"), query.lastError().text());
        return false;
    }
    while (query.next()) {
        TopoFrameInput frame;
        frame.frame_index = query.value(0).toLongLong();
        const QByteArray data = query.value(1).toByteArray();
        if (data.isEmpty() || !decode_frame(data, frame)) {
            report_store_error(QStringLiteral("Corrupt topology frame in replay store"));
            return false;
        }
        if (!visitor(frame)) return false;
    }
    if (query.lastError().type() != QSqlError::NoError) {
        report_db_error(QStringLiteral("read topology frames"), query.lastError().text());
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
    if (!m_db.isOpen() || m_store_failed) return false;
    // The bounded in-memory projection may evict an aggregate. Persist only the
    // not-yet-written trip delta and let SQLite merge it into the durable row.
    // Replacing a row with the projection's local count would lose older history.
    const QString sql = QStringLiteral(
        "INSERT INTO topo_anomalies"
        "(nid,merge_key,kind,tei,tei_old,mac,mac_old,is_rf,trips,value_from,value_to,first_ms,last_ms,first_frame,last_frame)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT(nid,merge_key) DO UPDATE SET"
        " kind=excluded.kind,tei=excluded.tei,tei_old=excluded.tei_old,"
        " mac=excluded.mac,mac_old=excluded.mac_old,is_rf=excluded.is_rf,"
        " trips=topo_anomalies.trips+excluded.trips,"
        " value_from=excluded.value_from,value_to=excluded.value_to,"
        // First occurrence fields are immutable after insertion. Frame order is
        // authoritative; timestamps can move backwards when clocks are corrected.
        " last_ms=excluded.last_ms,last_frame=excluded.last_frame");
    QSqlQuery query(m_db);
    if (!query.prepare(sql)) {
        report_db_error(QStringLiteral("prepare anomaly upsert"), query.lastError().text());
        return false;
    }
    bool ok = true;
    for (TopoAnomaly& a : state.anomalies) {
        // Persist only aggregates touched by this input frame. Rewriting the bounded UI
        // projection would both be quadratic and lose older rows after a replay rebuild.
        if (a.last_frame != frame_index) continue;
        const int trips_delta = a.trips - a.persisted_trips;
        if (trips_delta <= 0) continue;
        query.bindValue(0, nid);
        query.bindValue(1, topo_anomaly_merge_key(nid, a));
        query.bindValue(2, int(a.kind));
        query.bindValue(3, a.tei);
        query.bindValue(4, a.tei_old);
        query.bindValue(5, QVariant::fromValue<quint64>(a.mac));
        query.bindValue(6, QVariant::fromValue<quint64>(a.mac_old));
        query.bindValue(7, a.is_rf ? 1 : 0);
        query.bindValue(8, trips_delta);
        query.bindValue(9, a.value_from);
        query.bindValue(10, a.value_to);
        query.bindValue(11, a.first_ms);
        query.bindValue(12, a.last_ms);
        query.bindValue(13, a.first_frame);
        query.bindValue(14, a.last_frame);
        if (!query.exec()) { ok = false; break; }
        a.persisted_trips = a.trips;
    }
    if (!ok) report_db_error(QStringLiteral("persist topology anomalies"), query.lastError().text());
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
    // 实时拓扑总是推进(与 main 一致);入库失败只影响历史回放,错误由 report_store_error 报一次
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
    if (!m_db.isOpen() || m_store_failed) return;

    // The derived anomaly index is rebuilt from the authoritative ordered frame log.
    // Keep the previous complete index visible if reading or inserting any row fails.
    QSqlQuery query(m_db);
    if (!query.exec(QStringLiteral("BEGIN IMMEDIATE"))) {
        report_db_error(QStringLiteral("begin topology replay rebuild"), query.lastError().text());
        return;
    }
    if (!query.exec(QStringLiteral("DELETE FROM topo_anomalies"))) {
        const QString detail = query.lastError().text();
        QSqlQuery rollback(m_db);
        rollback.exec(QStringLiteral("ROLLBACK"));
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
        // The database error is reported by visit_frames/persist_anomalies, but
        // rollback must still run directly on the open connection to preserve
        // the old materialized index.
        QSqlQuery rollback(m_db);
        if (!rollback.exec(QStringLiteral("ROLLBACK"))) {
            report_store_error(QStringLiteral("Topology SQLite rollback after replay failure failed: %1")
                                   .arg(rollback.lastError().text()));
        }
        return;
    }
    if (!query.exec(QStringLiteral("COMMIT"))) {
        const QString detail = query.lastError().text();
        QSqlQuery rollback(m_db);
        rollback.exec(QStringLiteral("ROLLBACK"));
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
    // 出错时 ok=false + error,不再与"真的没有数据"的空页混淆
    auto fail = [&](const QString& message) {
        page.ok = false; page.error = message; page.items.clear();
        emit frame_page_ready(page);
    };
    if (!open_store()) {
        fail(m_store_error_message.isEmpty() ? QStringLiteral("Topology replay store is unavailable")
                                             : m_store_error_message);
        return;
    }
    QSqlQuery count_query(m_db);
    if (!count_query.exec(QStringLiteral("SELECT COUNT(*) FROM topo_frames"))) {
        report_db_error(QStringLiteral("count topology frames"), count_query.lastError().text());
        fail(QStringLiteral("Topology SQLite %1 failed: %2").arg(QStringLiteral("count topology frames"), count_query.lastError().text())); return;
    }
    if (count_query.next()) page.total = count_query.value(0).toLongLong();
    QSqlQuery query(m_db);
    if (!query.prepare(QStringLiteral("SELECT payload FROM topo_frames ORDER BY frame_index,id LIMIT ? OFFSET ?"))) {
        report_db_error(QStringLiteral("prepare topology frame page"), query.lastError().text());
        fail(QStringLiteral("Topology SQLite %1 failed: %2").arg(QStringLiteral("prepare topology frame page"), query.lastError().text())); return;
    }
    query.bindValue(0, limit); query.bindValue(1, page.offset);
    if (!query.exec()) {
        report_db_error(QStringLiteral("prepare topology frame page"), query.lastError().text());
        fail(QStringLiteral("Topology SQLite %1 failed: %2").arg(QStringLiteral("prepare topology frame page"), query.lastError().text())); return;
    }
    while (query.next()) {
        const QByteArray data = query.value(0).toByteArray();
        TopoFrameInput frame;
        if (data.isEmpty() || !decode_frame(data, frame)) {
            report_store_error(QStringLiteral("Corrupt topology frame in page query"));
            fail(QStringLiteral("Corrupt topology frame in page query")); return;
        }
        page.items.append(std::move(frame));
    }
    if (query.lastError().type() != QSqlError::NoError) {
        report_db_error(QStringLiteral("read topology frame page"), query.lastError().text());
        fail(QStringLiteral("Topology SQLite read topology frame page failed: %1").arg(query.lastError().text()));
        return;
    }
    emit frame_page_ready(page);
}

void TopoReplayWorker::request_anomaly_page(quint64 request_id, quint32 nid, qint64 offset, int limit) {
    TopoAnomalyPage page;
    page.request_id = request_id; page.nid = nid; page.offset = qMax<qint64>(0, offset);
    limit = qBound(1, limit, 500);
    auto fail = [&](const QString& message) {
        page.ok = false; page.error = message; page.items.clear();
        emit anomaly_page_ready(page);
    };
    if (!open_store()) {
        fail(m_store_error_message.isEmpty() ? QStringLiteral("Topology replay store is unavailable")
                                             : m_store_error_message);
        return;
    }
    QSqlQuery count_query(m_db);
    if (!count_query.prepare(QStringLiteral("SELECT COUNT(*) FROM topo_anomalies WHERE nid=?"))) {
        report_db_error(QStringLiteral("count topology anomalies"), count_query.lastError().text());
        fail(QStringLiteral("Topology SQLite %1 failed: %2").arg(QStringLiteral("count topology anomalies"), count_query.lastError().text())); return;
    }
    count_query.bindValue(0, nid);
    if (!count_query.exec()) {
        report_db_error(QStringLiteral("count topology anomalies"), count_query.lastError().text());
        fail(QStringLiteral("Topology SQLite %1 failed: %2").arg(QStringLiteral("count topology anomalies"), count_query.lastError().text())); return;
    }
    if (count_query.next()) page.total = count_query.value(0).toLongLong();
    QSqlQuery query(m_db);
    if (!query.prepare(QStringLiteral("SELECT kind,tei,tei_old,mac,mac_old,is_rf,trips,value_from,value_to,first_ms,last_ms,first_frame,last_frame "
                                      "FROM topo_anomalies WHERE nid=? ORDER BY last_frame DESC LIMIT ? OFFSET ?"))) {
        report_db_error(QStringLiteral("prepare topology anomaly page"), query.lastError().text());
        fail(QStringLiteral("Topology SQLite %1 failed: %2").arg(QStringLiteral("prepare topology anomaly page"), query.lastError().text())); return;
    }
    query.bindValue(0, nid); query.bindValue(1, limit); query.bindValue(2, page.offset);
    if (!query.exec()) {
        report_db_error(QStringLiteral("prepare topology anomaly page"), query.lastError().text());
        fail(QStringLiteral("Topology SQLite %1 failed: %2").arg(QStringLiteral("prepare topology anomaly page"), query.lastError().text())); return;
    }
    while (query.next()) {
        TopoAnomaly a;
        a.kind = static_cast<TopoAnomalyKind>(query.value(0).toInt());
        a.tei = quint16(query.value(1).toInt()); a.tei_old = quint16(query.value(2).toInt());
        a.mac = quint64(query.value(3).toLongLong()); a.mac_old = quint64(query.value(4).toLongLong());
        a.is_rf = query.value(5).toInt() != 0; a.trips = query.value(6).toInt();
        a.persisted_trips = a.trips;
        a.value_from = query.value(7).toInt(); a.value_to = query.value(8).toInt();
        a.first_ms = query.value(9).toLongLong(); a.last_ms = query.value(10).toLongLong();
        a.first_frame = query.value(11).toLongLong(); a.last_frame = query.value(12).toLongLong();
        page.items.append(a);
    }
    if (query.lastError().type() != QSqlError::NoError) {
        report_db_error(QStringLiteral("read topology anomaly page"), query.lastError().text());
        fail(QStringLiteral("Topology SQLite read topology anomaly page failed: %1").arg(query.lastError().text()));
        return;
    }
    emit anomaly_page_ready(page);
}

void TopoReplayWorker::request_history(quint64 request_id, qint64 target_frame,
                                       qint64 target_ms, bool active) {
    if (!open_store()) {
        const QString message = m_store_error_message.isEmpty()
            ? QStringLiteral("Topology replay store is unavailable") : m_store_error_message;
        emit history_failed(request_id, target_frame, target_ms, active, message);
        return;
    }
    QHash<quint32, TopoState> states;
    if (!state_at(target_frame, states)) {
        const QString message = m_store_error_message.isEmpty()
            ? QStringLiteral("Topology history could not be reconstructed") : m_store_error_message;
        emit history_failed(request_id, target_frame, target_ms, active, message);
        return;
    }
    emit history_ready(request_id, target_frame, target_ms, active, states);
}

bool TopoReplayWorker::clear_store() {
    if (!m_db.isOpen()) return true;
    // 两张表在同一事务里清:任一失败整体回滚,不留"帧清了异常没清"的半状态
    m_insert_query.finish();
    QSqlQuery query(m_db);
    auto fail = [&](const QString& detail) {
        QSqlQuery rollback(m_db);
        rollback.exec(QStringLiteral("ROLLBACK"));
        // 每次清库失败都要让用户知道(report_store_error 只报一次)
        emit worker_error(QStringLiteral("Topology SQLite clear topology store failed: %1").arg(detail));
        return false;
    };
    if (!query.exec(QStringLiteral("BEGIN IMMEDIATE"))) return fail(query.lastError().text());
    if (!query.exec(QStringLiteral("DELETE FROM topo_frames"))) return fail(query.lastError().text());
    if (!query.exec(QStringLiteral("DELETE FROM topo_anomalies"))) return fail(query.lastError().text());
    if (!query.exec(QStringLiteral("COMMIT"))) return fail(query.lastError().text());
    return true;
}

void TopoReplayWorker::clear() {
    // 调用方(MainWindow::on_clear)清空后帧序号从 1 重新开始。清库失败时若保留
    // m_last_applied_frame,此后每帧都被当作乱序帧触发全量回放,打满 worker。
    // 因此无论清库成败,内存实时状态都随之重置;清库失败时库内仍是旧帧,与新的
    // 帧序号不再一致,历史回放标记为不可用(rebuild/回放均被挡住,不会回放风暴),
    // 直到下次清库成功才恢复。
    const bool store_open = m_db.isOpen();
    const bool cleared = clear_store();
    m_live_states.clear();
    m_checkpoints.clear();
    m_last_applied_frame = -1;
    if (!cleared) {
        m_store_failed = true;
        m_store_error_message = QStringLiteral("Topology history is unavailable because clearing the replay store failed");
        m_store_error_reported = true;   // clear_store 已上报具体原因
    } else if (store_open) {
        // 库已清空、实时状态随之重置,两者重新一致:此前入库失败造成的"历史不可用"到此为止
        m_store_failed = false;
        m_store_error_reported = false;
        m_store_error_message.clear();
    }
    emit live_states_reset(m_live_states);
}

void TopoReplayWorker::shutdown() {
    m_insert_query.finish();
    m_insert_query = QSqlQuery();
    if (m_db.isOpen()) m_db.close();
    m_db = QSqlDatabase();
    if (!m_connection_name.isEmpty()) {
        QSqlDatabase::removeDatabase(m_connection_name);
        m_connection_name.clear();
    }
    delete m_temp_dir;
    m_temp_dir = nullptr;
}

void TopoReplayWorker::report_store_error(const QString& message) {
    m_store_failed = true;
    m_store_error_message = message;
    if (m_store_error_reported) return;
    m_store_error_reported = true;
    emit worker_error(message);
}

void TopoReplayWorker::report_db_error(const QString& operation, const QString& detail) {
    report_store_error(QStringLiteral("Topology SQLite %1 failed: %2").arg(operation, detail));
}
