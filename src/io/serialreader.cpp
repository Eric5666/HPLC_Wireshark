/// @file serialreader.cpp
/// @brief ReaderWorker + SerialReader 实现
#include "serialreader.h"
#include "i18n.h"
#include "playbackwriter.h"
#include "QsLog.h"
#include <QSerialPortInfo>
#include <QRegularExpression>
#include <QDateTime>
#include <QDebug>
#include <QElapsedTimer>
#include <chrono>

ReaderWorker::ReaderWorker(QObject* parent) : QObject(parent),
    m_serial(nullptr), m_file(nullptr),
    m_get3c(false), m_frame_rx_us(0), m_playback_base_ms(-1), m_first_frame(false),
    m_last_ntb(0), m_last_ft(0), m_running(false), m_abort(false), m_active(false),
    m_raw_base_ms(-1),
    m_hex_seg_first(false), m_hex_seg_base_ts(0), m_hex_seg_base_us(0),
    m_last_local_ms(0), m_pending_seg_start(false), m_file_size(0), m_last_progress(-1),
    m_frame_count(0) {}

ReaderWorker::~ReaderWorker() {
    stop_reading();
}

void ReaderWorker::abort() {
    m_abort.store(true);
}

void ReaderWorker::start_reading(const ReaderConfig& cfg) {
    if (m_running) stop_reading();
    if (m_file) {
        m_file->close();
        delete m_file;
        m_file = nullptr;
    }
    m_cfg = cfg;
    m_abort.store(false);
    m_active.store(true);   // 采集/回放开始(串口/文件/裸hex 均计入)
    m_in_buf.clear();
    m_get3c = false;
    m_last_local_ms = 0;   // 每次启动重置断段判断基准
    m_pending_seg_start = true;   // 新采集段首帧标 seg_start(含停止→恢复)

    if (cfg.mode == ReaderMode::SerialPort) {
        m_serial = new QSerialPort(this);
        m_serial->setPortName(cfg.serial_name);
        m_serial->setBaudRate(cfg.baud_rate);
        m_serial->setDataBits(cfg.data_bits);
        m_serial->setParity(cfg.parity);
        m_serial->setStopBits(cfg.stop_bits);
        m_serial->setFlowControl(QSerialPort::NoFlowControl);
        if (!m_serial->open(QIODevice::ReadOnly)) {
            emit error_occurred(trl::L("打开串口失败: %1").arg(m_serial->errorString()));
            m_active.store(false);
            return;
        }
        connect(m_serial, &QSerialPort::readyRead, this, &ReaderWorker::on_serial_ready_read);
        emit status_message(trl::L("串口 %1 @ %2 已打开").arg(cfg.serial_name).arg(cfg.baud_rate));
    } else if (cfg.mode == ReaderMode::FilePlayback) {
        m_file = new QFile(cfg.file_path, this);
        if (!m_file->open(QIODevice::ReadOnly)) {
            emit error_occurred(trl::L("打开文件失败: %1").arg(m_file->errorString()));
            delete m_file;
            m_file = nullptr;
            m_active.store(false);
            return;
        }
        m_file_size = m_file->size();
        m_last_progress = -1;
        // 新 bin:文件头 8B BCD 时间标注(首帧本地时刻,独立于帧);读取并跳过
        m_playback_base_ms = -1;
        m_first_frame = true;
        QByteArray head = m_file->peek(8);
        if (head.size() == 8 && bcd_ms_of(head) >= 0) {   // 强校验(BCD 且日期合法)
            m_playback_base_ms = bcd_ms_of(head);
            m_file->seek(8);
        }
        emit status_message(trl::L("文件回放: %1").arg(cfg.file_path));
        QLOG_INFO() << "replay start:" << cfg.file_path << m_file_size << "bytes";
        QElapsedTimer replay_t;
        replay_t.start();
        m_frame_count = 0;
        // 一次性读完整文件(不用 timer,快速回放);每块 1MB,切帧即时 emit
        while (!m_file->atEnd()) {
            if (m_abort.load()) break;   // 立即响应 stop()(切协议重建等)
            QByteArray chunk = m_file->read(1024 * 1024);
            if (chunk.isEmpty()) break;
            m_in_buf.append(chunk);
            try_extract_frame();
            // 回放进度百分比(按已读字节/文件总大小,仅变化时上报)
            if (m_file_size > 0) {
                const int percent = int(m_file->pos() * 100 / m_file_size);
                if (percent != m_last_progress) {
                    m_last_progress = percent;
                    emit progress_percent(percent);
                }
            }
        }
        m_file->close();
        delete m_file;
        m_file = nullptr;
        QLOG_INFO() << "replay end:" << m_frame_count << "frames, read+split elapsed"
                    << replay_t.elapsed() << "ms";
        emit progress_percent(100);
        emit status_message(trl::L("文件回放结束"));
        emit finished();
        m_active.store(false);
        return;
    } else if (cfg.mode == ReaderMode::RawHex) {
        m_file = new QFile(cfg.file_path, this);
        if (!m_file->open(QIODevice::ReadOnly | QIODevice::Text)) {
            emit error_occurred(trl::L("打开文件失败: %1").arg(m_file->errorString()));
            delete m_file;
            m_file = nullptr;
            m_active.store(false);
            return;
        }
        emit status_message(trl::L("裸 hex 模式: %1").arg(cfg.file_path));
        m_raw_base_ms = -1;   // 未给出时间头 → 首帧用本地时刻作基准,段内按 NTB 差推进
        m_hex_seg_first = true;
        while (!m_file->atEnd()) {
            if (m_abort.load()) break;   // 立即响应 stop()
            QByteArray line = m_file->readLine().trimmed();
            if (line.isEmpty()) continue;
            // 时间头行(首帧时间文本,如 TIME: 2026-09-07 18:43:00.123)
            const qint64 hdr_ms = parse_time_header(line);
            if (hdr_ms >= 0) { m_raw_base_ms = hdr_ms; m_hex_seg_first = true; continue; }
            process_raw_hex_line(line);
        }
        m_file->close();
        delete m_file;
        m_file = nullptr;
        emit finished();
        m_active.store(false);
        return;
    }

    m_running = true;
}

void ReaderWorker::stop_reading() {
    m_running = false;
    m_active.store(false);
    m_abort.store(true);
    if (m_serial)   { m_serial->close(); m_serial->deleteLater(); m_serial = nullptr; }
    if (m_file)     { m_file->close(); m_file->deleteLater(); m_file = nullptr; }
    emit finished();
}

namespace {
// 帧体最多 4 KiB,避免损坏/恶意输入使串口缓冲持续增长。
constexpr int kMaxFrameBodyBytes = 4 * 1024;

// 单调高精度时钟(µs):帧起始分节符 0x3C 到达打点
qint64 steady_us() {
    return qint64(std::chrono::duration_cast<std::chrono::microseconds>(
                      std::chrono::steady_clock::now().time_since_epoch())
                      .count());
}
}  // namespace

void ReaderWorker::on_serial_ready_read() {
    if (!m_serial) return;
    QByteArray chunk = m_serial->readAll();
    if (chunk.isEmpty()) return;
    // “读到第一个字符是 0x3C”即帧起始到达:缓冲无残留(上一帧已收完)且
    // 新数据首字节为 0x3C 时,此刻就是该帧起点;后续同批内的帧起点由
    // try_extract_frame 逐 0x3C 发现打点
    if (!m_get3c && m_in_buf.isEmpty() && quint8(chunk[0]) == 0x3C)
        m_frame_rx_us = steady_us();
    m_in_buf.append(chunk);
    try_extract_frame();
}

bool ReaderWorker::try_consume_bcd_tag() {
    // 仅文件回放有段间 8B 标注;合法 BCD 不含 0x3C/0x3D/0x3E,不会误吃帧哨兵
    if (m_cfg.mode != ReaderMode::FilePlayback || m_in_buf.size() < 8)
        return false;
    const qint64 ms = bcd_ms_of(m_in_buf.left(8));
    if (ms < 0) return false;
    m_playback_base_ms = ms;
    m_first_frame = true;
    m_last_ntb = 0;
    m_in_buf.remove(0, 8);
    return true;
}

void ReaderWorker::emit_drop_frame(const QByteArray& wire, const QString& reason,
                                   qint64 arrival_us, const QByteArray& data) {
    BplcFrame drop;
    drop.data = data;
    drop.raw_wire = wire;
    drop.meta.frame_time = QDateTime::currentDateTime();
    drop.meta.epoch_ms = drop.meta.frame_time.toMSecsSinceEpoch();
    drop.meta.frame_ts_is_ntb = true;
    drop.meta.local_rx_ms = QDateTime::currentMSecsSinceEpoch();
    drop.arrival_us = arrival_us;
    drop.accepted = false;
    drop.error_reason = reason;
    ++m_frame_count;
    emit frame_ready(drop);
}

void ReaderWorker::try_extract_frame() {
    while (!m_in_buf.isEmpty()) {
        if (!m_get3c) {
            // 段间 8B 标注可能独占本段缓冲(0x3C 在下一次 1024B read)
            if (try_consume_bcd_tag())
                continue;

            int idx = m_in_buf.indexOf(char(0x3C));
            if (idx < 0) {
                // 文件块末尾可能是下一段 BCD 的前 1~7B,留待下次 read 补齐。
                if (m_cfg.mode == ReaderMode::FilePlayback && m_in_buf.size() < 8)
                    return;
                // 无 0x3C:剔除 1 字节,回到循环顶重新匹配 8B BCD(滑窗对齐帧头)
                m_in_buf.remove(0, 1);
                continue;
            }
            if (idx > 0) {
                // 0x3C 前紧贴完整 8B 标注(标注前允许有噪声)
                if (m_cfg.mode == ReaderMode::FilePlayback && idx >= 8
                    && bcd_ms_of(m_in_buf.mid(idx - 8, 8)) >= 0) {
                    if (idx > 8)
                        m_in_buf.remove(0, idx - 8);
                    if (!try_consume_bcd_tag() && m_in_buf.size() >= 8)
                        m_in_buf.remove(0, 8);
                    continue;
                }
                // 1~7B 前缀不可能是完整标注:合法 BCD 不含 0x3C,
                // 半截标注且尚无 0x3C 已在 idx<0 分支等待。
                // 串口/回放都立刻丢掉,否则已缓冲的完整帧被卡住。
                m_in_buf.remove(0, idx);
                continue;
            }
            // idx == 0:3C 在缓冲开头。验证是否为假帧头——
            // 帧体中的 0x3C/0x3E/0x3D 均已 0x3D 转义(第二字节为补码
            // 0xC3/0xC1/0xC2),故线上裸 0x3C 只可能是帧头,不会误判体字节。
            // 若 3C 后先遇到另一个裸 0x3C(而非 3E),说明第一个 3C 是孤立的假帧头。
            // 新口径:第一个 3C 到第二个裸 3C 之间的数据不再静默丢弃,而是作为
            // 灰色 DROP 行发出(不进解析器,见 DispatcherWorker::on_frame 旁路),
            // 随后以第二个 3C 为帧头重新对齐;两 3C 紧贴(中间无数据)时不发空行。
            // 次 0x3C 本身即证明首头为假,无需等 0x3E 到达即可判 DROP;
            // 尚无次 0x3C(或 0x3E 更早)时仍按真帧头等待/成帧。
            const int next_3c = m_in_buf.indexOf(char(0x3C), idx + 1);
            const int next_3e = m_in_buf.indexOf(char(0x3E), idx + 1);
            if (next_3c >= 0 && (next_3e < 0 || next_3c < next_3e)) {
                if (next_3c > 1) {
                    BplcFrame drop;
                    drop.data = playback::unescape_frame_data(m_in_buf.mid(1, next_3c - 1));
                    // wire 补一个合成 0x3E 闭合,使导出流仍成帧;中间字节本身
                    // 不含裸 0x3C/0x3E(否则次哨兵会更早),故补闭合不改语义
                    drop.raw_wire = m_in_buf.left(next_3c);
                    drop.raw_wire.append(char(0x3E));
                    drop.meta.frame_time = QDateTime::currentDateTime();  // 垃圾无可信时间,回退本地时刻
                    drop.meta.epoch_ms = drop.meta.frame_time.toMSecsSinceEpoch();
                    drop.meta.frame_ts_is_ntb = true;
                    drop.arrival_us = (m_cfg.mode == ReaderMode::SerialPort) ? steady_us() : 0;
                    drop.accepted = false;
                    drop.error_reason = trl::L("DROP:双 0x3C 成帧垃圾");
                    // 不碰时间链(m_last_ntb/m_last_ft/m_first_frame):垃圾无可信 NTB,
                    // 下一真帧的时间仍以前一真帧为基准(commit 3 的解析器锚点同理)
                    ++m_frame_count;
                    drop.meta.local_rx_ms = QDateTime::currentMSecsSinceEpoch();  // 收帧本地时刻(回退显示时间用)
                    emit frame_ready(drop);
                }
                m_in_buf.remove(0, next_3c);
                continue;
            }
            m_in_buf.remove(0, 1);
            m_get3c = true;
            // 帧起始分节符 0x3C 的本地接收时刻(单调 µs):
            // 批内后续帧/缓冲中发现的起点在此打点(实时串口);文件回放不填
            if (m_cfg.mode == ReaderMode::SerialPort)
                m_frame_rx_us = steady_us();
            continue;
        }
        // 等 0x3E 时先遇裸 0x3C:当前帧头必为假(合法帧体内的 0x3C 均已 0x3D
        // 转义为 0x3D 0xC3,线上不可能出现裸 0x3C)。已缓冲体 + 假头按 DROP
        // 发出,从新 0x3C 重对齐;覆盖跨 read 分片的双 0x3C(首 0x3C 到达时
        // 次 0x3C 尚无,只能先按真头等)。体为空(两 0x3C 紧贴)时不发空行。
        const int idx3c = m_in_buf.indexOf(char(0x3C));
        const int idx3e = m_in_buf.indexOf(char(0x3E));
        const bool next_is_start = idx3c >= 0 && (idx3e < 0 || idx3c < idx3e);
        const int boundary = next_is_start ? idx3c : idx3e;
        if (boundary < 0) {
            if (m_in_buf.size() <= kMaxFrameBodyBytes) return;
            QByteArray drop_wire(1, char(0x3C));
            drop_wire.append(m_in_buf.left(kMaxFrameBodyBytes));
            drop_wire.append(char(0x3E));
            emit_drop_frame(drop_wire, trl::L("DROP:未闭合帧超过最大长度"), m_frame_rx_us);
            m_in_buf.clear();
            m_get3c = false;
            continue;
        }
        if (boundary > kMaxFrameBodyBytes) {
            QByteArray drop_wire(1, char(0x3C));
            drop_wire.append(m_in_buf.left(kMaxFrameBodyBytes));
            drop_wire.append(char(0x3E));
            emit_drop_frame(drop_wire, trl::L("DROP:帧超过最大长度"), m_frame_rx_us);
            if (next_is_start)
                m_in_buf.remove(0, idx3c);  // 保留下一个裸 0x3C 作为重同步起点
            else
                m_in_buf.remove(0, idx3e + 1);
            m_get3c = false;
            continue;
        }
        if (idx3c >= 0 && (idx3e < 0 || idx3c < idx3e)) {
            if (idx3c > 0) {
                BplcFrame drop;
                drop.data = playback::unescape_frame_data(m_in_buf.left(idx3c));
                drop.raw_wire = QByteArray(1, char(0x3C)) + m_in_buf.left(idx3c);
                drop.raw_wire.append(char(0x3E));
                drop.meta.frame_time = QDateTime::currentDateTime();
                drop.meta.epoch_ms = drop.meta.frame_time.toMSecsSinceEpoch();
                drop.meta.frame_ts_is_ntb = true;
                drop.arrival_us = m_frame_rx_us;
                drop.accepted = false;
                drop.error_reason = trl::L("DROP:双 0x3C 成帧垃圾");
                ++m_frame_count;
                drop.meta.local_rx_ms = QDateTime::currentMSecsSinceEpoch();  // 收帧本地时刻(回退显示时间用)
                emit frame_ready(drop);
            }
            m_in_buf.remove(0, idx3c);
            m_get3c = false;
            continue;
        }
        int idx = idx3e;
        if (idx < 0) return;
        QByteArray frame = m_in_buf.left(idx);
        m_in_buf.remove(0, idx + 1);
        m_get3c = false;

        // 原始串口帧(0x3C...0x3E,含哨兵与 0x3D 转义原样):所有 0x3C 帧均保留
        // (实时串口与回放 bin 同为 0x3C 数据 → 原始报文列一致显示);
        // 裸 hex 文本无哨兵,在 process_raw_hex_line 单独处理
        QByteArray wire;
        wire.reserve(frame.size() + 2);
        wire.append(char(0x3C)).append(frame).append(char(0x3E));

        // 反转义 0x3D
        QByteArray unesc;
        if (!playback::unescape_frame_data(frame, unesc)) {
            emit_drop_frame(wire, trl::L("DROP:非法或悬空的 0x3D 转义"), m_frame_rx_us);
            continue;
        }

        // 旧格式兼容:帧体 data 开头带 8B 逐帧 BCD 标签(无 raw_wire 时
        // frame_to_playback 的回退格式) → 剥离并重建 raw_wire,统一为新格式。
        // 不剥离的后果:raw_wire 含帧内 BCD,再次导出时该帧走 raw_wire 分支,
        // 段首(seg_start)会在帧外再写一个 8B 段标注 → 同一帧带双重 BCD 标签。
        if (playback::looks_like_bcd_time(unesc)) {
            const QByteArray stripped = unesc.mid(8);
            wire.clear();
            wire.append(char(0x3C))
                .append(playback::escape_frame_data(stripped))
                .append(char(0x3E));
            unesc = stripped;
        }

        // 新口径:MPDU 短于 FCH(16B)的完整 0x3C...0x3E 帧不再送解析器,
        // 由 reader 直接标 DROP(灰行、不解析)。data 布局为 len2+NTB4+媒介4+
        // MPDU,故 MPDU<16 ⟺ data<26;此门与解析器 MPDU_BASE 16B 门同口径。
        // 不碰时间链(理由同双 0x3C DROP);NTB/链路位尽力保留,供显示参考。
        if (unesc.size() < 26) {
            BplcFrame drop;
            drop.data = unesc;
            drop.raw_wire = wire;
            drop.meta.frame_time = QDateTime::currentDateTime();
            drop.meta.epoch_ms = drop.meta.frame_time.toMSecsSinceEpoch();
            drop.meta.frame_ts_is_ntb = true;
            if (unesc.size() >= 6) {
                drop.meta.timestamp = (quint32)(quint8)unesc[2]
                    | ((quint32)(quint8)unesc[3] << 8)
                    | ((quint32)(quint8)unesc[4] << 16)
                    | ((quint32)(quint8)unesc[5] << 24);
            }
            if (unesc.size() >= 10)
                drop.meta.is_rf = ((quint8)unesc[9] != 0);
            drop.arrival_us = m_frame_rx_us;
            drop.accepted = false;
            drop.error_reason = trl::L("DROP:帧长小于 FCH(16B)");
            ++m_frame_count;
            drop.meta.local_rx_ms = QDateTime::currentMSecsSinceEpoch();  // 收帧本地时刻(回退显示时间用)
            emit frame_ready(drop);
            continue;
        }

        BplcFrame bf;
        // 新 bin:时间轴以帧内 NTB(u32,40 µs)差推进——
        //   首帧  frame_time = 文件头/段 8B 标注时刻
        //   后续帧 frame_time = 上一帧 frame_time + (本帧 NTB − 上一帧 NTB)×40 µs
        //   帧间 NTB 差超出合理范围(长时间无报文/跨 u32 回绕)→ 用本地时刻,不
        //   沿用上一帧 NTB(本帧为断点,重置链)
        if (m_playback_base_ms >= 0) {
            // 极短帧(<6B,无帧内 NTB):ntb=0,时间轴走断点分支(本地时刻)
            const quint32 ntb = (unesc.size() >= 6)
                ? (quint32)(quint8)unesc[2] | ((quint32)(quint8)unesc[3] << 8)
                  | ((quint32)(quint8)unesc[4] << 16) | ((quint32)(quint8)unesc[5] << 24)
                : 0;
            if (m_first_frame) {
                bf.meta.frame_time = QDateTime::fromMSecsSinceEpoch(m_playback_base_ms);
                m_last_ft = m_playback_base_ms;
                m_last_ntb = ntb;
                m_first_frame = false;
                bf.meta.replay_time_tag = true;
            } else {
                const qint64 dn = (qint32)(ntb - m_last_ntb);   // 回绕安全
                if (dn > 0 && dn <= playback::kMaxNtbGapTicks) {
                    const qint64 ft_ms = m_last_ft + playback::ntb_to_us(quint32(dn)) / 1000;
                    bf.meta.frame_time = QDateTime::fromMSecsSinceEpoch(ft_ms);
                    m_last_ft = ft_ms;
                } else {
                    bf.meta.frame_time = QDateTime::currentDateTime();  // 断点:本地时刻
                    m_last_ft = bf.meta.frame_time.toMSecsSinceEpoch();
                }
                m_last_ntb = ntb;
            }
        } else {
            // 实时串口:frame_time 以帧内 NTB 差推进(与回放一致,统一时间轴);
            // 首帧/断点(长时间无报文或 NTB 跳变)以本地接收时刻为基准重置
            const qint64 now_ms = QDateTime::currentMSecsSinceEpoch();
            if (m_cfg.mode == ReaderMode::SerialPort) {
                // 帧内 NTB(实时串口也读取,用于 NTB 差 vs 本地时间差一致性判段)
                const quint32 ntb = (unesc.size() >= 6)
                    ? (quint32)(quint8)unesc[2] | ((quint32)(quint8)unesc[3] << 8)
                      | ((quint32)(quint8)unesc[4] << 16) | ((quint32)(quint8)unesc[5] << 24)
                    : 0;
                const qint64 dn = (qint32)(ntb - m_last_ntb);   // 回绕安全
                if (m_pending_seg_start) {          // 新采集段首帧(停止→恢复/首帧)
                    bf.meta.seg_start = true;
                    m_pending_seg_start = false;
                } else if (m_last_local_ms != 0) {
                    const qint64 local_delta_ms = now_ms - m_last_local_ms;
                    if (local_delta_ms > playback::kMaxLocalGapMs) {
                        bf.meta.seg_start = true;   // 长时间无报文 → 断段
                    } else {
                        // NTB 差 vs 本地时间差一致性:两者差 ≥3s 视为断段
                        // (设备 NTB 回绕/跳变,而本地接收时间仍连续时)
                        const qint64 ntb_delta_ms = dn * 40 / 1000000;  // tick→ms
                        if (qAbs(local_delta_ms - ntb_delta_ms) >= 3000)
                            bf.meta.seg_start = true;
                    }
                }
                // frame_time 推进:非首帧、NTB 差有效、非断点 → 上一帧 + NTB 差;
                // 否则(首帧/断点/NTB 异常)以本地接收时刻重置时间链
                const bool advance = (m_last_local_ms != 0)
                                     && (dn > 0 && dn <= playback::kMaxNtbGapTicks)
                                     && !bf.meta.seg_start;
                if (advance) {
                    const qint64 ft_ms = m_last_ft + playback::ntb_to_us(quint32(dn)) / 1000;
                    bf.meta.frame_time = QDateTime::fromMSecsSinceEpoch(ft_ms);
                    m_last_ft = ft_ms;
                } else {
                    bf.meta.seg_start = true;
                    bf.meta.frame_time = QDateTime::fromMSecsSinceEpoch(now_ms);
                    m_last_ft = now_ms;
                }
                m_last_local_ms = now_ms;
                m_last_ntb = ntb;
            } else {
                bf.meta.frame_time = QDateTime::fromMSecsSinceEpoch(now_ms);
            }
        }
        bf.arrival_us = m_frame_rx_us;   // 0x3C 起始高精度接收时刻(实时)
        bf.meta.local_rx_ms = QDateTime::currentMSecsSinceEpoch();  // 收帧本地时刻(解析器回退显示时间用)
        bf.raw_wire   = wire;            // 原始串口帧原样(调试复制)
        // 帧 ts 域语义(2026-09 统一):ts 一律为 NTB tick(25kHz,40ns),
        // 无论实时串口(设备填)还是文件回放(bin/裸 hex 导出均写 NTB)
        bf.meta.frame_ts_is_ntb = true;
        // 8B 标注在文件头/段间,帧体无逐帧 BCD;不做旧版每帧 BCD 兼容检测
        bf.meta.has_time_tag = false;
        bf.data = unesc;
        ++m_frame_count;
        emit frame_ready(bf);
    }
}

void ReaderWorker::process_raw_hex_line(const QByteArray& line) {
    // TIME 时间行由 start_reading 消费;此处解析每行一个完整 0x3C...0x3E 帧。
    // 支持 "0x01 0xd5 …" 或 "01 d5…" 写法;帧间由行分隔定界。
    QByteArray raw;
    QByteArray s = line;
    const QList<QByteArray> toks = s.replace(',', ' ').split(' ');
    for (const QByteArray& t0 : toks) {
        QByteArray t = t0.trimmed();
        if (t.isEmpty()) continue;
        if ((t.startsWith("0x") || t.startsWith("0X")) && t.size() >= 3)
            t.remove(0, 2);
        if (t.size() < 2 || (t.size() % 2) != 0) return;   // 非纯 hex → 跳过整行
        for (int i = 0; i < t.size(); i += 2) {
            bool ok = false;
            int v = t.mid(i, 2).toInt(&ok, 16);
            if (!ok) return;
            raw.append(char(v));
        }
    }
    // 至少 ts4+media4+1B MPDU,否则无法构成可解析帧
    if (raw.size() < 9) return;

    // 仅支持完整 0x3C 原始帧行(导出 v1.0.13+ 格式);其它行格式忽略
    if ((quint8)raw[0] != 0x3C || (quint8)raw[raw.size() - 1] != 0x3E) return;

    {
        QByteArray body = raw.mid(1, raw.size() - 2);
        QByteArray data;
        if (!playback::unescape_frame_data(body, data)) return;
        // dlen(2B)+NTB(4B)+媒介字段(4B)+至少 1B MPDU;在读取 data[2..5] 前验证长度。
        if (data.size() < 11) return;
        // 时间:ts 统一 NTB tick(25kHz,40ns)。段首帧用 TIME 头(m_raw_base_ms)
        // 作基准,无 TIME 头则用首帧本地时刻作基准;段内按自段首累计 NTB 差
        // ×40ns 统一换算为 µs(单次除法,避免逐帧 ms 截断累计漂移,µs 级准确);
        // 断段(差超阈值/回绕)回退本地时刻并重建基准。
        const quint32 ts_le2 = (quint32)(quint8)data[2]
                             | (quint32)(quint8)data[3] << 8
                             | (quint32)(quint8)data[4] << 16
                             | (quint32)(quint8)data[5] << 24;
        const qint64 now_ms = QDateTime::currentMSecsSinceEpoch();
        const qint64 now_us = now_ms * 1000;
        qint64 t2_us;
        bool replay_time_tag = false;
        if (m_hex_seg_first) {
            const qint64 base_ms = (m_raw_base_ms >= 0) ? m_raw_base_ms : now_ms;
            t2_us = base_ms * 1000;
            m_hex_seg_base_ts = ts_le2;
            m_hex_seg_base_us = t2_us;
            m_hex_seg_first = false;
            replay_time_tag = m_raw_base_ms >= 0;
        } else {
            const qint64 dn = (qint32)(ts_le2 - m_hex_seg_base_ts);  // 自段首累计 tick
            if (dn > 0 && dn <= playback::kMaxNtbGapTicks)
                t2_us = m_hex_seg_base_us + playback::ntb_to_us((quint32)dn);
            else {
                // 断段:回退本地,并以本帧重建基准
                t2_us = now_us;
                m_hex_seg_base_ts = ts_le2;
                m_hex_seg_base_us = t2_us;
            }
        }

        BplcFrame bf;
        bf.meta.from_raw = false;
        bf.meta.has_time_tag = false;
        bf.meta.frame_ts_is_ntb = true;
        bf.meta.replay_time_tag = replay_time_tag;
        bf.meta.frame_time = QDateTime::fromMSecsSinceEpoch(t2_us / 1000);
        bf.arrival_us = t2_us;
        bf.meta.local_rx_ms = QDateTime::currentMSecsSinceEpoch();  // 收帧本地时刻(解析器回退显示时间用)
        bf.raw_wire   = raw;   // 0x3C...0x3E 原样
        bf.data       = data;  // 反转义后的 [dlen][ts][media][MPDU]
        emit frame_ready(bf);
        return;
    }
}

qint64 ReaderWorker::parse_time_header(const QByteArray& line) {
    // 兼容 "TIME: 2026-09-07 18:43:00.123" / "TIME: 2026-09-07 18:43:00" /
    // 直接 "2026-09-07 18:43:00.123"(样本 TIME: 行后还可能跟其它说明文字)
    static const QRegularExpression re(
        QStringLiteral("(\\d{4}-\\d{2}-\\d{2})[ T](\\d{2}):(\\d{2}):(\\d{2})"
                       "(?:\\.(\\d{1,3}))?"));
    const QRegularExpressionMatch m = re.match(QLatin1String(line));
    if (!m.hasMatch()) return -1;
    const QDate date = QDate::fromString(m.captured(1), QStringLiteral("yyyy-MM-dd"));
    const QTime time(m.captured(2).toInt(), m.captured(3).toInt(),
                     m.captured(4).toInt(), m.captured(5).isEmpty() ? 0
                                        : m.captured(5).leftJustified(3, '0').toInt());
    if (!date.isValid() || !time.isValid()) return -1;
    return QDateTime(date, time).toMSecsSinceEpoch();
}

qint64 ReaderWorker::bcd_ms_of(const QByteArray& b) {
    // 8B BCD:[年-2000][月][日][时][分][秒][毫秒百位][毫秒低2]→ 本地 epoch ms
    if (!playback::looks_like_bcd8(b)) return -1;
    auto d2 = [](quint8 x) { return int((x >> 4) * 10 + (x & 0x0F)); };
    const QDate date(2000 + d2(quint8(b[0])), d2(quint8(b[1])), d2(quint8(b[2])));
    const QTime time(d2(quint8(b[3])), d2(quint8(b[4])), d2(quint8(b[5])));
    if (!date.isValid() || !time.isValid()) return -1;
    const int ms = d2(quint8(b[6])) * 100 + d2(quint8(b[7]));
    return QDateTime(date, time).addMSecs(ms).toMSecsSinceEpoch();
}

SerialReader::SerialReader(QObject* parent) : QObject(parent), m_thread(nullptr), m_worker(nullptr) {
    m_thread = new QThread(this);
    m_worker = new ReaderWorker();
    m_worker->moveToThread(m_thread);
    connect(m_thread, &QThread::finished, m_worker, &QObject::deleteLater);

    connect(this, &SerialReader::request_start, m_worker, &ReaderWorker::start_reading);
    connect(this, &SerialReader::request_stop,  m_worker, &ReaderWorker::stop_reading);

    connect(m_worker, &ReaderWorker::frame_ready,    this, &SerialReader::on_frame);
    connect(m_worker, &ReaderWorker::status_message, this, &SerialReader::on_status);
    connect(m_worker, &ReaderWorker::error_occurred, this, &SerialReader::on_error);
    connect(m_worker, &ReaderWorker::progress_percent, this, &SerialReader::on_progress);
    connect(m_worker, &ReaderWorker::finished, this, &SerialReader::finished);

    m_thread->start();
}

SerialReader::~SerialReader() {
    stop();
    m_thread->quit();
    m_thread->wait(2000);
}

bool SerialReader::start(const ReaderConfig& cfg) {
    emit request_start(cfg);
    return true;
}

void SerialReader::stop() {
    // 立即置中止标志(GUI 线程直调,无需等待 worker 事件循环):
    // 文件/裸 hex 回放是同步 while 循环,必须靠原子标志打断,否则停不住。
    if (m_worker) m_worker->abort();
    emit request_stop();   // 异步清理资源(close 文件/串口)
}

bool SerialReader::is_running() const {
    return m_worker && m_worker->is_active();
}

void SerialReader::on_frame(BplcFrame f) { emit frame_ready(f); }
void SerialReader::on_status(QString s) { emit status_message(s); }
void SerialReader::on_error(QString e)  { emit error_occurred(e); }
void SerialReader::on_progress(int p)   { emit progress_percent(p); }
namespace {
// 中→英注册(文件级:数据源状态/错误消息)
struct I18nRegSerialReader {
    I18nRegSerialReader() {
        trl::register_en("打开串口失败: %1", "Failed to open serial port: %1");
        trl::register_en("串口 %1 @ %2 已打开", "Serial port %1 @ %2 opened");
        trl::register_en("打开文件失败: %1", "Failed to open file: %1");
        trl::register_en("文件回放: %1", "File replay: %1");
        trl::register_en("裸 hex 模式: %1", "Raw hex mode: %1");
        trl::register_en("文件回放结束", "File replay ended");
        trl::register_en("DROP:双 0x3C 成帧垃圾", "DROP: framing garbage between two 0x3C");
        trl::register_en("DROP:帧长小于 FCH(16B)", "DROP: frame shorter than FCH (16B)");
        trl::register_en("DROP:非法或悬空的 0x3D 转义", "DROP: invalid or dangling 0x3D escape");
        trl::register_en("DROP:未闭合帧超过最大长度", "DROP: unterminated frame exceeds maximum size");
        trl::register_en("DROP:帧超过最大长度", "DROP: frame exceeds maximum size");
    }
};
const I18nRegSerialReader g_i18n_reg_serialreader;
}  // namespace
