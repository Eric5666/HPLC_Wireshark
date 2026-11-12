/// @file capturecontroller.cpp
/// @brief 采集控制实现
#include "capturecontroller.h"

#include "framedispatcher.h"
#include "appconfig.h"

CaptureController::CaptureController(QObject* parent) : QObject(parent) {
    m_reader = new SerialReader(this);
    create_dispatcher();
    connect(m_reader, &SerialReader::status_message,
            this,     &CaptureController::status_message);
    connect(m_reader, &SerialReader::error_occurred,
            this,     &CaptureController::error_occurred);
    connect(m_reader, &SerialReader::progress_percent,
            this,     &CaptureController::progress_percent);
}

FrameStatistics* CaptureController::statistics() const {
    return m_dispatch ? m_dispatch->statistics() : nullptr;
}

/// @brief 新建 dispatcher 并接入 Reader(帧源 + 背压额度)与 parsed 转发
void CaptureController::create_dispatcher() {
    m_dispatch = new FrameDispatcher(this);   // 按 config.ini 协议实例化解析器
    m_dispatch->connect_source(m_reader);
    m_dispatch->set_flow_credit(m_reader->flow_credit());   // 背压:在途帧上限
    // 排队投递(与原 MainWindow::on_parsed 的 QueuedConnection 一致):
    // 重建时断开旧 dispatcher 即不再转发其结果
    connect(m_dispatch, &FrameDispatcher::parsed,
            this,       &CaptureController::parsed,
            Qt::QueuedConnection);
}

void CaptureController::reset_dispatcher() {
    // 回放忙碌时不能同步 delete(析构里 wait 会卡 GUI 直至崩溃):
    // shutdown 立即断开 worker 信号 + 退出解析线程(停止处理积压帧、
    // 停止向 GUI 投递 parsed),再断外部连接并 deleteLater 异步销毁。
    if (m_dispatch) {
        m_dispatch->shutdown();
        m_dispatch->disconnect_source(m_reader);
        m_dispatch->disconnect(this);
        m_dispatch->deleteLater();
        m_dispatch = nullptr;
    }
    create_dispatcher();
}

ReaderConfig CaptureController::load_config() {
    ReaderConfig c;                       // 来源:config.ini [reader]
    int mode = appcfg::reader_mode();
    c.mode = ReaderMode(mode);
    c.serial_name = appcfg::reader_com();
    c.baud_rate   = appcfg::reader_baud();
    c.file_path   = appcfg::reader_file();
    return c;
}

void CaptureController::save_config(const ReaderConfig& c) {
    appcfg::set_reader(int(c.mode), c.serial_name, c.baud_rate,
                       c.file_path);
}
