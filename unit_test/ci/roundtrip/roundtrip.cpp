/// @file roundtrip.cpp
/// @brief 实际 ReaderWorker、Delta 计算及批量/流式导出器的回归验证。
#include <QCoreApplication>
#include <QBuffer>
#include <QDebug>
#include <QTemporaryDir>
#include <algorithm>
#include "serialreader.h"
#include "playbackwriter.h"
#include "packetentry_serialize.h"

class ReaderWorkerTestAccess {
public:
    static QVector<PacketEntry> serial(const QByteArray& input, quint32 previous_ntb,
                                      qint64 previous_time, qint64 local_gap_ms,
                                      bool first = false) {
        ReaderWorker worker;
        worker.m_cfg.mode = ReaderMode::SerialPort;
        worker.m_last_ntb = previous_ntb;
        worker.m_last_ft = previous_time;
        worker.m_last_local_ms = first ? 0 : QDateTime::currentMSecsSinceEpoch() - local_gap_ms;
        worker.m_pending_seg_start = first;
        quint32 last_ntb = previous_ntb;
        bool have_last_ntb = !first;
        QVector<PacketEntry> entries;
        QObject::connect(&worker, &ReaderWorker::frame_ready, [&](const BplcFrame& frame) {
            PacketEntry e;
            e.meta = frame.meta;
            e.meta.timestamp = playback::raw_wire_ntb(frame.raw_wire);
            e.delta_us = playback::next_delta_us(e.meta, last_ntb, have_last_ntb);
            e.raw_wire = frame.raw_wire;
            e.raw_bytes = frame.data.mid(10);
            e.epoch_ms = frame.meta.frame_time.toMSecsSinceEpoch();
            entries.append(e);
        });
        worker.m_in_buf = input;
        worker.try_extract_frame();
        return entries;
    }
};

namespace {
int failures = 0;

void check(bool ok, const QString& name) {
    qInfo().noquote() << (ok ? "PASS" : "FAIL") << name;
    if (!ok) ++failures;
}

QVector<PacketEntry> read(const QByteArray& input, ReaderMode mode) {
    QTemporaryDir dir;
    QFile file(dir.filePath("input"));
    if (!file.open(QIODevice::WriteOnly) || file.write(input) != input.size()) {
        check(false, "create replay input");
        return {};
    }
    file.close();
    ReaderConfig cfg;
    cfg.mode = mode;
    cfg.file_path = file.fileName();
    quint32 last_ntb = 0;
    bool have_last_ntb = false;
    QVector<PacketEntry> entries;
    ReaderWorker worker;
    QObject::connect(&worker, &ReaderWorker::error_occurred,
                     [](const QString& error) { check(false, error); });
    QObject::connect(&worker, &ReaderWorker::frame_ready, [&](const BplcFrame& frame) {
        PacketEntry e;
        e.meta = frame.meta;
        e.meta.timestamp = playback::raw_wire_ntb(frame.raw_wire);
        e.delta_us = playback::next_delta_us(e.meta, last_ntb, have_last_ntb);
        e.raw_wire = frame.raw_wire;
        e.raw_bytes = frame.data.mid(10);
        e.epoch_ms = frame.meta.frame_time.toMSecsSinceEpoch();
        entries.append(e);
    });
    worker.start_reading(cfg);
    check(std::all_of(entries.cbegin(), entries.cend(), [](const PacketEntry& e) {
        return !e.meta.seg_start;
    }), "file replay never sets serial seg_start");
    return entries;
}

QByteArray wire(quint32 ntb, int padding = 0) {
    QByteArray data = QByteArray::fromHex("14000000000000000200");
    const quint16 dlen = quint16(20 + padding);
    data[0] = char(dlen & 0xFF);
    data[1] = char(dlen >> 8);
    for (int i = 0; i < 4; ++i) data[2 + i] = char(ntb >> (8 * i));
    data += QByteArray::fromHex("02d5a1cd10013000012b0000009f0e21");
    data += QByteArray(padding, char(0xAA));
    return QByteArray(1, char(0x3C)) + playback::escape_frame_data(data) + char(0x3E);
}

QByteArray time_line(qint64 ms) {
    return "TIME: " + QDateTime::fromMSecsSinceEpoch(ms)
                             .toString("yyyy-MM-dd HH:mm:ss.zzz").toUtf8() + '\n';
}

QByteArray streamed(const QVector<PacketEntry>& entries, bool hex) {
    QByteArray bytes;
    QBuffer out(&bytes);
    out.open(QIODevice::WriteOnly);
    if (hex) {
        playback::RawHexWriter writer(&out);
        for (const auto& e : entries) writer.add(e);
    } else {
        playback::PlaybackBinWriter writer(&out);
        for (const auto& e : entries) writer.add(e);
    }
    return bytes;
}

void bin_roundtrip(const QByteArray& input, const QVector<PacketEntry>& entries) {
    check(playback::build_playback_bin(entries) == input, "bin playback -> bin equals source");
    check(streamed(entries, false) == input, "streaming bin export equals source");
    const QByteArray hex = playback::build_raw_hex_text(entries);
    check(streamed(entries, true) == hex, "streaming and batch hex exports agree");
    const auto reread = read(hex, ReaderMode::RawHex);
    check(reread.size() == entries.size(), "hex replay preserves frame count");
    check(playback::build_playback_bin(reread) == input, "bin -> hex -> bin equals source bytes");
    check(streamed(reread, false) == input, "bin -> hex -> streaming bin equals source bytes");
}

void regressions() {
    const qint64 base = QDateTime(QDate(2026, 9, 7), QTime(18, 43, 0, 123)).toMSecsSinceEpoch();
    const qint64 later = base + 600000;
    const QByteArray first = wire(1000);
    const QByteArray second = wire(26000);
    const QByteArray tag = playback::bcd_time_tag(base);
    const QByteArray tag2 = playback::bcd_time_tag(later);

    for (int split = 0; split <= 8; ++split) {
        qInfo() << "BCD bytes before read boundary:" << split;
        QByteArray input = tag;
        const int target = 8 + 1024 * 1024 - split;
        quint32 ntb = 1000;
        QByteArray last;
        while (input.size() + wire(ntb).size() <= target) {
            last = wire(ntb);
            input += last;
            ntb += 25000;
        }
        // 延长最后一帧,精确对齐标注,文件不混入会被读取器丢弃的噪声。
        const int padding = target - input.size();
        input.chop(last.size());
        last = wire(ntb - 25000, padding);
        input += last + tag2 + wire(ntb);
        const auto entries = read(input, ReaderMode::FilePlayback);
        check(!entries.isEmpty() && entries.last().meta.replay_time_tag
                  && entries.last().epoch_ms == later, "boundary BCD resets segment time");
        bin_roundtrip(input, entries);
    }

    {
        const QByteArray input = time_line(base) + playback::hex_line_of(first)
                                 + time_line(later)
                                 + playback::hex_line_of(second)
                                 + playback::hex_line_of(wire(51000));
        const auto entries = read(input, ReaderMode::RawHex);
        check(entries.size() == 3 && entries[0].epoch_ms == base
                  && entries[1].epoch_ms == later && entries[1].meta.replay_time_tag
                  && entries[2].epoch_ms == later + 1 && !entries[2].meta.replay_time_tag,
              "intermediate TIME header resets next frame and following time base");
        check(entries.size() == 3 && entries[0].delta_us == 0
                  && entries[1].delta_us == 0 && entries[2].delta_us == 1000,
              "intermediate TIME resets Delta and following frame advances normally");
        const QByteArray bin = tag + first + tag2 + second + wire(51000);
        check(streamed(entries, false) == bin, "hex -> bin retains annotation time and position");
        const auto bin_entries = read(bin, ReaderMode::FilePlayback);
        check(bin_entries.size() == 3 && bin_entries[1].epoch_ms == later
                  && bin_entries[1].meta.replay_time_tag && bin_entries[2].epoch_ms == later + 1
                  && !bin_entries[2].meta.replay_time_tag,
              "intermediate bin BCD resets next frame and following time base");
        check(bin_entries.size() == 3 && bin_entries[0].delta_us == 0
                  && bin_entries[1].delta_us == 0 && bin_entries[2].delta_us == 1000,
              "intermediate bin BCD resets Delta and following frame advances normally");
        bin_roundtrip(bin, bin_entries);
        QVector<PacketEntry> stored;
        check(pser::decode_block(pser::encode_block(entries), stored)
                  && stored.size() == 3 && stored[1].meta.replay_time_tag && !stored[1].meta.seg_start
                  && stored[1].epoch_ms == later && streamed(stored, false) == bin,
              "segment and export survive disk-block round-trip");
    }

    for (ReaderMode mode : {ReaderMode::FilePlayback, ReaderMode::RawHex}) {
        const bool hex = mode == ReaderMode::RawHex;
        const QByteArray gap = wire(1000 + 61u * 25000000u);
        const QByteArray input = hex ? time_line(base) + playback::hex_line_of(first)
                                                        + playback::hex_line_of(gap)
                                    : tag + first + gap;
        const qint64 before = QDateTime::currentMSecsSinceEpoch();
        const auto entries = read(input, mode);
        const qint64 after = QDateTime::currentMSecsSinceEpoch();
        check(entries.size() == 2 && !entries[1].meta.replay_time_tag
                  && entries[1].epoch_ms >= before && entries[1].epoch_ms <= after,
              "missing intermediate annotation uses local time without seg_start");
        check(streamed(entries, hex) == input, "fallback does not invent export annotation");
        const QByteArray bin = tag + first + gap;
        bin_roundtrip(bin, entries);
        if (entries.size() != 2) continue;
        auto extra = entries;
        extra[1].meta.seg_start = true;
        check(streamed(extra, hex) != input, "adding seg_start at fallback changes exported file");
    }

    const auto invalid = read(time_line(base) + playback::hex_line_of(first)
                                 + "TIME: 2026-02-31 18:43:00.123\n"
                                 + playback::hex_line_of(second), ReaderMode::RawHex);
    check(invalid.size() == 2 && invalid.last().epoch_ms == base + 1
              && !invalid.last().meta.replay_time_tag, "invalid TIME date does not reset segment");
    const auto no_header = read(playback::hex_line_of(first), ReaderMode::RawHex);
    check(no_header.size() == 1 && !no_header[0].meta.replay_time_tag
              && no_header[0].delta_us == 0,
          "headerless hex does not invent an existing annotation");
}

void delta_regressions() {
    const qint64 base = QDateTime(QDate(2026, 9, 7), QTime(18, 43, 0, 123)).toMSecsSinceEpoch();
    for (bool header : {false, true}) {
        for (quint32 first_ntb : {0u, 25000000u, 0xffffffffu}) {
            const QByteArray input = (header ? time_line(base) : QByteArray())
                + playback::hex_line_of(wire(first_ntb))
                + playback::hex_line_of(wire(first_ntb + 25000));
            const auto entries = read(input, ReaderMode::RawHex);
            check(entries.size() == 2 && entries[0].meta.timestamp == first_ntb
                      && entries[0].delta_us == 0 && entries[1].delta_us == 1000,
                  QString("first Delta is zero and next is 1ms: TIME=%1 NTB=%2")
                      .arg(header).arg(first_ntb));
            if (entries.size() != 2) continue;
            check(entries[0].meta.replay_time_tag == header
                      && !entries[1].meta.replay_time_tag,
                  "Delta initialization does not invent replay annotations");
            auto different_delta = entries;
            different_delta[0].delta_us = 1000000;
            different_delta[1].delta_us = 500000;
            const QByteArray bin = streamed(entries, false);
            const QByteArray hex = streamed(entries, true);
            check(streamed(different_delta, false) == bin
                      && playback::build_playback_bin(different_delta) == bin
                      && streamed(different_delta, true) == hex
                      && playback::build_raw_hex_text(different_delta) == hex,
                  "changing Delta leaves batch/streaming bin and hex bytes unchanged");
            QVector<PacketEntry> stored;
            check(pser::decode_block(pser::encode_block(entries), stored)
                      && stored.size() == 2 && stored[0].delta_us == 0
                      && stored[1].delta_us == 1000 && streamed(stored, false) == bin
                      && streamed(stored, true) == hex,
                  "correct Delta and unchanged exports survive disk cache");
        }
    }

    for (bool clear : {false, true}) {
        quint32 last_ntb = 1000;
        bool have_last_ntb = true;
        PhysicalMeta meta;
        meta.timestamp = 26000;
        check(playback::next_delta_us(meta, last_ntb, have_last_ntb) == 1000,
              "Delta has a previous frame before capture reset");
        have_last_ntb = false;
        if (clear) last_ntb = 0;
        meta.timestamp = 25000000;
        const qint64 first = playback::next_delta_us(meta, last_ntb, have_last_ntb);
        meta.timestamp += 25000;
        check(first == 0 && playback::next_delta_us(meta, last_ntb, have_last_ntb) == 1000,
              clear ? "clear resets Delta history" : "new capture resets Delta history");
    }

    struct Case {
        const char* name;
        quint32 previous;
        quint32 current;
        qint64 expected;
    };
    const Case cases[] = {
        {"normal", 1000, 26000, 1000},
        {"zero", 1000, 1000, 0},
        {"backward", 1000, 999, 0},
        {"exactly 60s", 1000, 1000u + 60u * 25000000u, 60000000},
        {"beyond 60s", 1000, 1001u + 60u * 25000000u, 0},
        {"signed limit", 1000, 1000u + 0x80000000u, 0},
        {"short u32 wrap", 0xfffff000u, 0xfffff000u + 25000u, 1000},
    };
    for (const auto& c : cases) {
        quint32 last_ntb = c.previous;
        bool have_last_ntb = true;
        PhysicalMeta meta;
        meta.timestamp = c.current;
        check(playback::next_delta_us(meta, last_ntb, have_last_ntb) == c.expected
                  && last_ntb == c.current && have_last_ntb,
              QString("Delta keeps existing NTB rules: %1").arg(c.name));
    }
}

void serial_regressions() {
    const qint64 base = QDateTime(QDate(2026, 9, 7), QTime(18, 43, 0, 123)).toMSecsSinceEpoch();
    struct Case {
        const char* name;
        quint32 previous_ntb;
        quint32 ticks;
        qint64 local_gap_ms;
        bool reset;
    };
    const Case cases[] = {
        {"normal", 1000, 25000, 1, false},
        {"below 60s", 1000, 59u * 25000000u, 59000, false},
        {"exactly 60s", 1000, 60u * 25000000u, 60000, false},
        {"one tick beyond 60s", 1000, 60u * 25000000u + 1, 60000, true},
        {"61s matching local gap", 1000, 61u * 25000000u, 61000, true},
        {"zero NTB delta", 1000, 0, 1, true},
        {"backward NTB", 100000, quint32(-25000), 1, true},
        {"signed delta limit", 1000, 0x80000000u, 85899, true},
        {"short u32 wrap", 0xfffff000u, 25000, 1, false},
        {"local/NTB mismatch", 1000, 25000000, 4000, true},
        {"long local gap", 1000, 25000, 171801, true},
    };
    for (const auto& c : cases) {
        qInfo() << "Serial timeline:" << c.name;
        const quint32 ntb = c.previous_ntb + c.ticks;
        const QByteArray first = wire(c.previous_ntb);
        const QByteArray current = wire(ntb);
        const QByteArray next = wire(ntb + 25000);
        const qint64 before = QDateTime::currentMSecsSinceEpoch();
        auto entries = ReaderWorkerTestAccess::serial(current + next, c.previous_ntb,
                                                      base, c.local_gap_ms);
        const qint64 after = QDateTime::currentMSecsSinceEpoch();
        check(entries.size() == 2, "serial input preserves frame count");
        if (entries.size() != 2) continue;
        check(entries[0].meta.seg_start == c.reset && !entries[0].meta.replay_time_tag
                  && !entries[1].meta.seg_start && !entries[1].meta.replay_time_tag,
              "serial reset marks only the new segment first frame");
        check(c.reset ? entries[0].epoch_ms >= before && entries[0].epoch_ms <= after
                      : entries[0].epoch_ms == base + playback::ntb_to_us(c.ticks) / 1000,
              "serial time uses local reset or valid NTB advance");
        check(entries[1].epoch_ms == entries[0].epoch_ms + 1,
              "following serial frame advances from new time base");
        check(entries[0].delta_us == (c.reset ? 0 : playback::ntb_to_us(c.ticks))
                  && entries[1].delta_us == 1000,
              "serial segment resets Delta without changing following interval");
        PacketEntry previous;
        previous.raw_wire = first;
        previous.raw_bytes = QByteArray::fromHex("02d5");
        previous.epoch_ms = base;
        previous.meta.seg_start = true;
        entries.prepend(previous);
        const QByteArray expected_bin = playback::bcd_time_tag(base) + first
            + (c.reset ? playback::bcd_time_tag(entries[1].epoch_ms) : QByteArray()) + current + next;
        const QByteArray expected_hex = time_line(base) + playback::hex_line_of(first)
            + (c.reset ? time_line(entries[1].epoch_ms) : QByteArray())
            + playback::hex_line_of(current) + playback::hex_line_of(next);
        check(streamed(entries, false) == expected_bin
                  && playback::build_playback_bin(entries) == expected_bin,
              "serial bin export writes BCD exactly at new time base");
        check(streamed(entries, true) == expected_hex
                  && playback::build_raw_hex_text(entries) == expected_hex,
              "serial hex export writes TIME exactly at new time base");
        QVector<PacketEntry> stored;
        check(pser::decode_block(pser::encode_block(entries), stored)
                  && streamed(stored, false) == expected_bin && streamed(stored, true) == expected_hex,
              "serial segment timestamp survives disk cache");
        bin_roundtrip(expected_bin, read(expected_bin, ReaderMode::FilePlayback));
    }
    const auto first = ReaderWorkerTestAccess::serial(wire(1000), 0, 0, 0, true);
    check(first.size() == 1 && first[0].meta.seg_start && !first[0].meta.replay_time_tag
              && first[0].delta_us == 0,
          "serial start/resume first frame remains a new segment");
}

void fixtures(const QString& bin_path, const QString& hex_path) {
    QFile bin(bin_path), hex(hex_path);
    if (!bin.open(QIODevice::ReadOnly) || !hex.open(QIODevice::ReadOnly)) {
        check(false, "open fixture files");
        return;
    }
    const QByteArray src_bin = bin.readAll();
    QByteArray src_hex = hex.readAll();
    bin_roundtrip(src_bin, read(src_bin, ReaderMode::FilePlayback));
    const auto entries = read(src_hex, ReaderMode::RawHex);
    const auto reread = read(streamed(entries, false), ReaderMode::FilePlayback);
    src_hex.replace("\r\n", "\n");
    check(streamed(reread, true) == src_hex, "canonical fixture hex -> bin -> hex");
}
}  // namespace

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    regressions();
    delta_regressions();
    serial_regressions();
    if (argc == 3) fixtures(app.arguments()[1], app.arguments()[2]);
    else if (argc != 1) { qWarning() << "usage: roundtrip [bin txt]"; return 2; }
    qInfo() << "RESULT:" << (failures == 0 ? "PASS" : "FAIL") << "failures:" << failures;
    return failures == 0 ? 0 : 1;
}
