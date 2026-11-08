/// @file playbackwriter.h
/// @brief 把已捕获帧写成"回放 bin"格式(与 SerialReader 文件回放同构)
/// @details 每帧 = 0x3C + 转义(data) + 0x3E;
///          data = [dlen2LE][ts4LE][phr_mcs][option][channel][isRF][MPDU]。
///          读取端(serialreader try_extract_frame)只按 0x3C/0x3E 切帧并对
///          0x3D 反转义,dlen 字段不校验;因此 dlen 填 MPDU+6 即可被重新解析。
///
///          导出的文件在 data 最前面带 8 字节 BCD 绝对时间标签
///          (年月日时分秒毫秒,与解码器 has_time_tag 头同构):
///          data = [bcd_time8][dlen2LE][ts4LE][phr][option][channel][isRF][MPDU]。
///          原始捕获时刻;老文件(无该字段)回退到本地时间。
#ifndef PLAYBACKWRITER_H
#define PLAYBACKWRITER_H

#include "bplcframe.h"
#include <QVector>
#include <QDateTime>
#include <QIODevice>

namespace playback {

/// @brief 是否为合法 BCD 字节(两个 4bit 位均 <=9)
inline bool bcd_ok(quint8 byte, int max_dec) {
    const int lo = byte & 0x0F;
    const int hi = byte >> 4;
    return hi <= 9 && lo <= 9 && (hi * 10 + lo) <= max_dec;
}

/// @brief 8 字节是否为独立 BCD 时间标注(段头/段间,不含帧体)
/// @note  合法 BCD 的两个 nibble 均 <=9,故 0x3C/0x3D/0x3E 不可能出现在标注内。
inline bool looks_like_bcd8(const QByteArray& d) {
    if (d.size() < 8) return false;
    const auto at = [&d](int i) { return static_cast<quint8>(d[i]); };
    // yy(00-99) mo(1-12) dd(1-31) hh(0-23) mm(0-59) ss(0-59) msH(0-9) msL(0-99)
    if (!bcd_ok(at(0), 99)) return false;
    if (!bcd_ok(at(1), 12) || at(1) == 0) return false;
    if (!bcd_ok(at(2), 31) || at(2) == 0) return false;
    if (!bcd_ok(at(3), 23)) return false;
    if (!bcd_ok(at(4), 59)) return false;
    if (!bcd_ok(at(5), 59)) return false;
    if (!bcd_ok(at(6), 9)) return false;   // 毫秒百位
    if (!bcd_ok(at(7), 99)) return false;
    return true;
}

/// @brief 自动识别帧 data 开头是否带 8B BCD 时间标签(旧格式,帧体 ≥28B)
/// @note  仅旧格式逐帧 BCD 标签识别用(无 raw_wire 数据的 frame_to_playback
///        回退路径 + viewtest 往返测试);新格式段头/段间标注用 looks_like_bcd8。
inline bool looks_like_bcd_time(const QByteArray& d) {
    if (d.size() < 28) return false;
    return looks_like_bcd8(d);
}

inline QByteArray escape_frame_data(const QByteArray& data) {
    QByteArray esc;
    esc.reserve(data.size() + 8);
    for (char c : data) {
        const quint8 b = static_cast<quint8>(c);
        if (b == 0x3C || b == 0x3E || b == 0x3D) {   // 0x3D + (0xFF ^ b)
            esc.append(char(0x3D)).append(char(0xFF - b));
        } else {
            esc.append(c);
        }
    }
    return esc;
}

/// @brief 严格反转义:0x3D 后只允许 0xC3/0xC2/0xC1,分别还原为 0x3C/0x3D/0x3E。
/// @return 是否完整且合法;悬空或非法转义时清空输出并返回 false。
inline bool unescape_frame_data(const QByteArray& esc, QByteArray& out) {
    out.clear();
    out.reserve(esc.size());
    for (int i = 0; i < esc.size(); ++i) {
        const quint8 b = static_cast<quint8>(esc[i]);
        if (b != 0x3D) {
            out.append(esc[i]);
            continue;
        }
        if (i + 1 >= esc.size()) {
            out.clear();
            return false;
        }
        const quint8 escaped = static_cast<quint8>(esc[++i]);
        if (escaped != 0xC3 && escaped != 0xC2 && escaped != 0xC1) {
            out.clear();
            return false;
        }
        out.append(char(0xFF - escaped));
    }
    return true;
}

/// @brief 便捷反转义;非法转义返回空数组(需要区分合法空载荷时用 bool 重载)。
inline QByteArray unescape_frame_data(const QByteArray& esc) {
    QByteArray out;
    if (!unescape_frame_data(esc, out)) out.clear();
    return out;
}

// —— 时间轴/NTB 约定 ——
// NTB 为 u32,40 ns/tick(25 MHz);u32 约 171 s 回绕一次。
// 相邻帧 NTB 差须在合理范围(长时间无报文会跨越 u32 回绕/多段,差不可信)。
// 超过该阈值视为"断段",需用新的 8B 时间标注。
const qint64 kMaxNtbGapTicks = 25000000LL * 60;   // 25M tick/s × 60 s(1.5e9,< 2^31)
inline qint64 ntb_to_us(quint32 dn) { return qint64(dn) * 40 / 1000; }   // tick(40ns) → µs
inline qint64 next_delta_us(const PhysicalMeta& meta, quint32& last_ntb, bool& have_last_ntb) {
    qint64 delta_us = 0;
    if (have_last_ntb && !meta.seg_start && !meta.replay_time_tag) {
        const qint64 dn = qint32(meta.timestamp - last_ntb);
        if (dn > 0 && dn <= kMaxNtbGapTicks)
            delta_us = ntb_to_us(quint32(dn));
    }
    last_ntb = meta.timestamp;
    have_last_ntb = true;
    return delta_us;
}
/// @brief 实时串口断段阈值:本地接收时间差超过 NTB u32 回绕周期(≈171.8s)
///        即视为断段(设备长时间无报文/NTB 已回绕,时间轴不可比)
const qint64 kMaxLocalGapMs = 171800;   // 2^32 tick / 25 MHz ≈ 171.8 s

/// @brief 从 raw_wire(0x3C...0x3E)取帧内 NTB(体 data[2..5],LE);无则 0
inline quint32 raw_wire_ntb(const QByteArray& wire) {
    if (wire.size() < 3) return 0;
    const QByteArray inner = unescape_frame_data(wire.mid(1, wire.size() - 2));
    if (inner.size() < 6) return 0;
    return (quint32)(quint8)inner[2]
         | (quint32)(quint8)inner[3] << 8
         | (quint32)(quint8)inner[4] << 16
         | (quint32)(quint8)inner[5] << 24;
}

/// @brief 字节 → "xx xx ..." 空格分隔 hex 行(裸 hex 时间标注行)
inline QByteArray hex_line_of(const QByteArray& b) {
    QByteArray line;
    for (char c : b)
        line += QStringLiteral(" 0x%1")
                    .arg(quint8(c), 2, 16, QChar('0')).toLatin1();
    if (!line.isEmpty()) line = line.mid(1);   // 去行首空格
    line += '\n';
    return line;
}

/// @brief epoch_ms → 8B BCD 时间标签(本地时间,与解码器 has_time_tag 同构)
inline QByteArray bcd_time_tag(qint64 epoch_ms) {
    const QDateTime dt = QDateTime::fromMSecsSinceEpoch(epoch_ms);
    const QDate date = dt.date();
    const QTime time = dt.time();
    const auto bcd = [](int v) { return static_cast<char>(((v / 10) << 4) | (v % 10)); };
    QByteArray out;
    out.reserve(8);
    out.append(bcd(date.year() - 2000)).append(bcd(date.month()))
       .append(bcd(date.day())).append(bcd(time.hour()))
       .append(bcd(time.minute())).append(bcd(time.second()))
       .append(bcd(time.msec() / 100))          // 毫秒百位(0-9)
       .append(bcd(time.msec() % 100));          // 毫秒低两位(0-99)
    return out;
}

/// @brief 单帧 → 回放 bin 帧字节(含 0x3C/0x3E 转义与 8B 起始时间标签)
inline QByteArray frame_to_playback(const PacketEntry& e) {
    // raw_bytes = 纯 MPDU(串口/回放/裸 hex 导入均已在解析层剥去封装头)
    const QByteArray mpdu = e.raw_bytes;
    if (mpdu.isEmpty()) return {};

    // dlen = 数据长度字段(2B LE,反转义后偏移 0-1)。定义:从 phr_mcs 字段
    // (偏移 6)到帧末的字节数 = 物理元数据 4B + MPDU 长(与固件帧 dlen=MPDU+4
    // 一致)。本监控器读取端不校验该字段,仅按 0x3C/0x3E 切帧。
    // ts 域 = epoch ms 低 32 位(导出时刻);绝对时刻由 8B BCD 时间标签承载
    const quint16 dlen = quint16(mpdu.size() + 4);
    const quint32 ts   = quint32(e.epoch_ms & 0xFFFFFFFFu);
    QByteArray data;
    data.reserve(mpdu.size() + 18);
    // 起始(帧)时间标签:回放时据此恢复原始捕获时刻
    data.append(bcd_time_tag(e.epoch_ms));
    data.append(char(dlen & 0xFF)).append(char(dlen >> 8));
    data.append(char(ts & 0xFF)).append(char((ts >> 8) & 0xFF))
        .append(char((ts >> 16) & 0xFF)).append(char((ts >> 24) & 0xFF));
    data.append(char(e.meta.phr_mcs)).append(char(e.meta.option))
        .append(char(e.meta.channel)).append(char(e.meta.is_rf ? 1 : 0));
    data.append(mpdu);

    QByteArray out;
    out.append(char(0x3C));
    out.append(escape_frame_data(data));
    out.append(char(0x3E));
    return out;
}

/// @brief 全部帧 → 完整回放 bin 文件内容(空帧自动跳过)
/// @details 实时串口断段认 seg_start,回放原有标注认 replay_time_tag,
///          不用 NTB 差兜底(多设备 NTB
///          基准不同,差不可靠)。段首前写 8B BCD 标注,帧本身 raw_wire 原样。
inline QByteArray build_playback_bin(const QVector<PacketEntry>& entries) {
    QByteArray buf;
    buf.reserve(entries.size() * 72);
    bool have = false;
    for (const PacketEntry& e : entries) {
        if (!e.raw_wire.isEmpty()) {
            if (!have || e.meta.seg_start || e.meta.replay_time_tag)
                buf.append(bcd_time_tag(e.epoch_ms));   // 段起点标注
            buf.append(e.raw_wire);
            have = true;
        } else {
            const QByteArray fr = frame_to_playback(e);
            if (!fr.isEmpty()) buf.append(fr);
        }
    }
    return buf;
}

/// @brief 导出裸数据 hex 文本(与 RawHex 导入对称,每行一完整 0x3C 原始帧):
///        [0x3C][esc(data)][0x3E],data = [dlen 2B][ts 4B=NTB tick]
///        [phr_mcs][option][channel][isRF][MPDU]。
///        回放端识别 0x3C 行 → 反转义还原 data;ts 为 NTB(与 bin 同构,
///        时间轴按 NTB 差推进,无逐帧绝对时刻)。
inline QByteArray build_raw_hex_text(const QVector<PacketEntry>& entries) {
    QByteArray buf;
    bool    have = false;
    for (const PacketEntry& e : entries) {
        if (e.raw_bytes.isEmpty()) continue;
        // 段起点/断段:在该帧前写一行 TIME: 文本时间戳(该帧本地时刻)
        const QByteArray ts_hdr =
            QStringLiteral("TIME: %1\n")
                .arg(QDateTime::fromMSecsSinceEpoch(e.epoch_ms)
                         .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz")))
                .toUtf8();
        if (e.raw_wire.isEmpty() || !have || e.meta.seg_start || e.meta.replay_time_tag) {
            // 无 raw_wire / 首帧 / 串口段首 / 回放原有标注:标注一次
            buf.append(ts_hdr);
        }
        // 帧字节:优先 raw_wire 原样(与 bin 导出一致,保证 round-trip 无损);
        // 无 raw_wire(旧数据)才重新构造
        QByteArray frame;
        if (!e.raw_wire.isEmpty()) {
            frame = e.raw_wire;   // 0x3C + 转义体 + 0x3E 原样
        } else {
            const QByteArray mpdu = e.raw_bytes;
            const quint16 dlen = quint16(mpdu.size() + 4);
            const quint32 ts   = e.meta.timestamp;   // NTB tick
            QByteArray data;
            data.reserve(mpdu.size() + 10);
            data.append(char(dlen & 0xFF)).append(char(dlen >> 8));
            data.append(char(ts & 0xFF)).append(char((ts >> 8) & 0xFF))
                .append(char((ts >> 16) & 0xFF)).append(char((ts >> 24) & 0xFF));
            data.append(char(e.meta.phr_mcs)).append(char(e.meta.option))
                .append(char(e.meta.channel)).append(char(e.meta.is_rf ? 1 : 0));
            data.append(mpdu);
            frame.reserve(data.size() + 2);
            frame.append(char(0x3C));
            frame.append(escape_frame_data(data));
            frame.append(char(0x3E));
        }
        QByteArray line;
        for (char c : frame)
            line += QStringLiteral(" 0x%1")
                        .arg(quint8(c), 2, 16, QChar('0')).toLatin1();
        buf.append(line.mid(1));   // 去掉行首空格
        buf.append('\n');
        have = !e.raw_wire.isEmpty();
    }
    return buf;
}

/// @brief 流式回放 bin writer:保留回放原有标注,串口新段写起始时间。
///        用于磁盘换页模型下按序遍历全部帧导出,避免一次性载入内存。
class PlaybackBinWriter {
public:
    explicit PlaybackBinWriter(QIODevice* dev) : dev_(dev), have_(false) {}

    void add(const PacketEntry& e) {
        if (!e.raw_wire.isEmpty()) {
            if (!have_ || e.meta.seg_start || e.meta.replay_time_tag)
                dev_->write(bcd_time_tag(e.epoch_ms));   // 段起点标注
            dev_->write(e.raw_wire);
            have_ = true;
        } else {
            const QByteArray fr = frame_to_playback(e);
            if (!fr.isEmpty()) dev_->write(fr);
        }
    }

private:
    QIODevice* dev_;
    bool       have_;
};

/// @brief 流式裸 hex writer:串口新段/回放原有标注前写 TIME: 行,
///        帧字节 raw_wire 原样(与批量 build_raw_hex_text 一致)。
class RawHexWriter {
public:
    explicit RawHexWriter(QIODevice* dev) : dev_(dev), have_(false) {}

    void add(const PacketEntry& e) {
        if (e.raw_bytes.isEmpty()) return;
        const QByteArray ts_hdr =
            QStringLiteral("TIME: %1\n")
                .arg(QDateTime::fromMSecsSinceEpoch(e.epoch_ms)
                         .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz")))
                .toUtf8();
        if (e.raw_wire.isEmpty() || !have_ || e.meta.seg_start || e.meta.replay_time_tag) {
            dev_->write(ts_hdr);
        }
        // 帧字节:优先 raw_wire 原样(round-trip 无损);无 raw_wire 才重新构造
        QByteArray frame;
        if (!e.raw_wire.isEmpty()) {
            frame = e.raw_wire;
        } else {
            const QByteArray mpdu = e.raw_bytes;
            const quint16 dlen = quint16(mpdu.size() + 4);
            const quint32 ts   = e.meta.timestamp;   // NTB tick
            QByteArray data;
            data.reserve(mpdu.size() + 10);
            data.append(char(dlen & 0xFF)).append(char(dlen >> 8));
            data.append(char(ts & 0xFF)).append(char((ts >> 8) & 0xFF))
                .append(char((ts >> 16) & 0xFF)).append(char((ts >> 24) & 0xFF));
            data.append(char(e.meta.phr_mcs)).append(char(e.meta.option))
                .append(char(e.meta.channel)).append(char(e.meta.is_rf ? 1 : 0));
            data.append(mpdu);
            frame.reserve(data.size() + 2);
            frame.append(char(0x3C));
            frame.append(escape_frame_data(data));
            frame.append(char(0x3E));
        }
        QByteArray line;
        for (char c : frame)
            line += QStringLiteral(" 0x%1")
                        .arg(quint8(c), 2, 16, QChar('0')).toLatin1();
        dev_->write(line.mid(1));
        dev_->write("\n");
        have_ = !e.raw_wire.isEmpty();
    }

private:
    QIODevice* dev_;
    bool       have_;
};

}  // namespace playback

#endif // PLAYBACKWRITER_H
