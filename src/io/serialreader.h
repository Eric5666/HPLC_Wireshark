/// @file serialreader.h
/// @brief ReaderWorker + SerialReader:后台切帧的两种封装
/// @details ReaderConfig 是用户配置;ReaderMode 区分串口/文件/裸 hex。
///          ReaderWorker 在独立 QThread 跑,SerialReader 仅做线程包装。
#ifndef SERIALREADER_H
#define SERIALREADER_H

#include <QObject>
#include <QThread>
#include <QSerialPort>
#include <QFile>
#include <QTimer>
#include <QString>
#include <QMetaType>
#include <atomic>

#include "ringbuffer.h"
#include "bplcframe.h"

enum class ReaderMode {
    SerialPort,
    FilePlayback,
    RawHex
};

struct ReaderConfig {
    ReaderMode mode;
    QString    serial_name;
    qint32     baud_rate;
    QSerialPort::DataBits data_bits;
    QSerialPort::StopBits stop_bits;
    QSerialPort::Parity   parity;
    QString    file_path;

    ReaderConfig()
        : mode(ReaderMode::SerialPort),
          baud_rate(460800),
          data_bits(QSerialPort::Data8),
          stop_bits(QSerialPort::OneStop),
          parity(QSerialPort::NoParity) {}
};
Q_DECLARE_METATYPE(ReaderConfig)

class ReaderWorker : public QObject {
    Q_OBJECT
public:
    explicit ReaderWorker(QObject* parent = nullptr);
    ~ReaderWorker() override;

    /// @brief 立即请求中止文件/裸 hex 回放(原子标志,线程安全);
    ///        供 GUI 线程在 stop() 时直接调用,无需等待事件循环。
    void abort();
    /// @brief 是否正在采集/回放(线程安全;串口打开、文件/裸hex 回放期间为真)
    bool is_active() const { return m_active.load(); }

public slots:
    void start_reading(const ReaderConfig& cfg);
    void stop_reading();

signals:
    void frame_ready(BplcFrame frame);
    void status_message(QString msg);
    void error_occurred(QString err);
    void finished();
    void progress_percent(int percent);   ///< 文件回放进度(0-100)

private slots:
    void on_serial_ready_read();

private:
    friend class ReaderWorkerTestAccess;
    void try_extract_frame();
    void emit_drop_frame(const QByteArray& wire, const QString& reason,
                         qint64 arrival_us, const QByteArray& data = QByteArray());
    void process_raw_hex_line(const QByteArray& line);
    /// @brief 解析裸 hex 文本头行时间(TIME: / ISO 文本),失败返回 -1
    qint64 parse_time_header(const QByteArray& line);
    /// @brief 8B BCD 时间标注 → epoch ms(文件头/段间;非法返回 -1)
    qint64 bcd_ms_of(const QByteArray& bcd8);
    /// @brief 文件回放:缓冲开头若为完整 8B BCD 段标注则消费并重置时间轴
    bool try_consume_bcd_tag();
    /// @brief 缓冲内最后一个合法 8B BCD 标注的偏移;无则 -1(O(n),无 0x3C 时整段丢弃用)
    int last_bcd_tag_offset(const QByteArray& buf);

    QSerialPort* m_serial;
    QFile*       m_file;
    QByteArray   m_in_buf;
    bool         m_get3c;
    qint64       m_frame_rx_us;   ///< 当前帧起始 0x3C 的单调 µs 接收时刻(实时)
    qint64       m_playback_base_ms;  ///< 回放 bin 当前段 8B BCD 标注(首帧/断段本地时刻;-1=无)
    bool         m_first_frame;   ///< 回放首帧标志(首帧用标注时间)
    quint32      m_last_ntb;      ///< 上一帧帧内 NTB(回放时间轴 tick 差)
    qint64       m_last_ft;       ///< 上一帧 frame_time(回放时间轴基准)
    bool         m_running;
    std::atomic<bool> m_abort;   ///< 中止回放标志(GUI 线程 stop() 直接置位,while 循环检查)
    std::atomic<bool> m_active;  ///< 正在采集/回放(串口/文件/裸hex 均置位;供 is_running 查询)
    qint64       m_raw_base_ms;   ///< 裸 hex 文本首帧时间(epoch ms;-1=未给出,回退本地)
    bool         m_hex_seg_first; ///< 裸 hex 当前段首帧标志(段首用 TIME 头时间)
    quint32      m_hex_seg_base_ts;  ///< 裸 hex 段首帧 ts4(NTB tick,累计差分基准)
    qint64       m_hex_seg_base_us;  ///< 裸 hex 段首帧时刻(epoch µs,累计差分基准)
    qint64       m_last_local_ms; ///< 实时串口上一帧本地接收时刻(断段判断)
    bool         m_pending_seg_start; ///< 实时串口新采集段首帧待标 seg_start(停止→恢复/首帧)
    qint64       m_file_size;     ///< 回放文件总大小(字节,算进度用)
    int          m_last_progress; ///< 上次上报的进度百分比(节流,避免重复刷)
    qint64       m_frame_count;   ///< 本次回放已切出的帧数(日志统计用)
    ReaderConfig m_cfg;
};

class SerialReader : public QObject {
    Q_OBJECT
public:
    explicit SerialReader(QObject* parent = nullptr);
    ~SerialReader() override;

    bool start(const ReaderConfig& cfg);
    void stop();
    bool is_running() const;   ///< 是否正在采集/回放(转发 worker 状态)

signals:
    void request_start(ReaderConfig cfg);
    void request_stop();
    void frame_ready(BplcFrame frame);
    void status_message(QString msg);
    void error_occurred(QString err);
    void progress_percent(int percent);
    void finished();   ///< 采集/回放结束(worker 完成)

private slots:
    void on_frame(BplcFrame f);
    void on_status(QString s);
    void on_error(QString e);
    void on_progress(int p);

private:
    QThread*      m_thread;
    ReaderWorker* m_worker;
};

#endif // SERIALREADER_H
