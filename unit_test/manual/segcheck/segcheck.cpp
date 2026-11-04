/// @file segcheck.cpp
/// @brief 回放 bin → 复刻 serialreader 文件回放 seg_start 判定 → 导出裸 hex,
///        检查第 76705 帧前是否有 TIME: 时间戳行。
#include <QCoreApplication>
#include <QFile>
#include <QBuffer>
#include <QDateTime>
#include <QDate>
#include <QTime>
#include <cstdio>
#include "bplcframe.h"
#include "playbackwriter.h"

static qint64 bcd_ms_of(const QByteArray& b) {
    if (b.size() < 8) return -1;
    auto d = [&](int i) { return (quint8)b[i]; };
    for (int i = 0; i < 8; ++i)
        if ((d(i) >> 4) > 9 || (d(i) & 0xF) > 9) return -1;
    int yr = 2000 + (d(0) >> 4) * 10 + (d(0) & 0xF);
    int mo = (d(1) >> 4) * 10 + (d(1) & 0xF);
    int dy = (d(2) >> 4) * 10 + (d(2) & 0xF);
    int hh = (d(3) >> 4) * 10 + (d(3) & 0xF);
    int mi = (d(4) >> 4) * 10 + (d(4) & 0xF);
    int ss = (d(5) >> 4) * 10 + (d(5) & 0xF);
    int ms100 = (d(6) >> 4) * 10 + (d(6) & 0xF);
    int ms_lo = (d(7) >> 4) * 10 + (d(7) & 0xF);
    if (mo < 1 || mo > 12 || dy < 1 || dy > 31 || hh > 23 || mi > 59 || ss > 59) return -1;
    return QDateTime(QDate(yr, mo, dy), QTime(hh, mi, ss, ms100 * 100 + ms_lo)).toMSecsSinceEpoch();
}

int main(int argc, char* argv[]) {
    if (argc < 2) { std::printf("usage: segcheck <bin>\n"); return 1; }
    QFile f(QString::fromLocal8Bit(argv[1]));
    if (!f.open(QIODevice::ReadOnly)) { std::printf("open fail\n"); return 1; }
    QByteArray buf = f.readAll();
    f.close();

    int pos = 0;
    qint64 base_ms = -1;
    bool first = false;
    if (buf.size() >= 8 && playback::looks_like_bcd8(buf)) {
        base_ms = bcd_ms_of(buf.left(8));
        pos = 8;
        first = true;
    }

    QBuffer out;
    out.open(QIODevice::WriteOnly);
    playback::RawHexWriter w(&out);

    quint32 last_ntb = 0;
    qint64 last_ft = 0;
    int frame_idx = 0;
    const int target = 76705;  // 1-based
    bool target_has_time = false;
    int target_bcd_before = 0;   // 该帧前紧邻 8B BCD 标注数
    int seg_start_count = 0;

    while (pos < buf.size()) {
        // 段间 8B BCD 标注(与 try_consume_bcd_tag 同构)
        if (buf.size() - pos >= 8 && (quint8)buf[pos] != 0x3C
            && playback::looks_like_bcd8(buf.mid(pos, 8))) {
            base_ms = bcd_ms_of(buf.mid(pos, 8));
            first = true;
            pos += 8;
            continue;
        }
        if ((quint8)buf[pos] != 0x3C) { pos++; continue; }
        int idx = buf.indexOf(char(0x3E), pos + 1);
        if (idx < 0) break;
        QByteArray body = buf.mid(pos + 1, idx - pos - 1);
        QByteArray wire;
        wire.append(char(0x3C)).append(body).append(char(0x3E));
        QByteArray unesc;
        for (int i = 0; i < body.size(); ++i) {
            quint8 b = (quint8)body[i];
            if (b == 0x3D && i + 1 < body.size()) {
                ++i;
                unesc.append(char(0xFF - (quint8)body[i]));
            } else unesc.append(char(b));
        }
        quint32 ntb = 0;
        if (unesc.size() >= 6)
            ntb = (quint32)(quint8)unesc[2] | ((quint32)(quint8)unesc[3] << 8)
                | ((quint32)(quint8)unesc[4] << 16) | ((quint32)(quint8)unesc[5] << 24);
        qint64 arrival;
        bool seg = false;
        if (first) {
            arrival = base_ms;
            seg = true;
            first = false;
        } else {
            qint64 dn = (qint32)(ntb - last_ntb);
            if (dn > 0 && dn <= playback::kMaxNtbGapTicks)
                arrival = last_ft + playback::ntb_to_us((quint32)dn) / 1000;
            else
                arrival = last_ft;   // NTB 断点:仅换本地时刻,不标 seg(兜底已去)
            // seg 保持 false
        }
        last_ntb = ntb;
        last_ft = arrival;

        frame_idx++;
        if (seg) seg_start_count++;
        qint64 before = out.pos();
        PacketEntry e;
        e.raw_wire = wire;
        e.raw_bytes = unesc;
        e.meta.seg_start = seg;
        e.meta.timestamp = ntb;
        e.epoch_ms = arrival;
        w.add(e);
        if (frame_idx == target) {
            QByteArray chunk = out.data().mid(before);
            target_has_time = chunk.startsWith("TIME:");
            if (!seg && before >= 8 && playback::looks_like_bcd8(buf.mid(pos - 8, 8)))
                target_bcd_before = 1;
        }
        pos = idx + 1;
    }

    out.close();
    QByteArray result = out.data();
    int time_lines = 0;
    for (const QByteArray& line : result.split('\n'))
        if (line.startsWith("TIME:")) time_lines++;

    std::printf("frames=%d TIME_lines=%d seg_start_count=%d\n",
                frame_idx, time_lines, seg_start_count);
    std::printf("frame #%d has TIME: before = %s\n",
                target, target_has_time ? "YES" : "NO");
    return 0;
}
