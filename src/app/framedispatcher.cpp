/// @file framedispatcher.cpp
/// @brief 帧分发器实现
#include "framedispatcher.h"
#include "protocolfactory.h"
#include "appconfig.h"
#include "parse_anomaly.h"
#include "QsLog.h"

#include <QElapsedTimer>
#include <QDebug>

namespace {
/// @brief 协议变体 → 短名(异常日志 key 前缀,与各 parser 硬编码一致)
QString proto_name(ProtocolVariant v) {
    switch (v) {
        case ProtocolVariant::GW_2022: return QStringLiteral("gw_2022");
        case ProtocolVariant::NW_2021: return QStringLiteral("nw_2021");
        case ProtocolVariant::GW_2026: return QStringLiteral("gw_2026");
        case ProtocolVariant::NW_2026: return QStringLiteral("nw_2026");
    }
    return QStringLiteral("unknown");
}
} // namespace

DispatcherWorker::DispatcherWorker(std::unique_ptr<IProtocolParser> parser,
                                   QObject* parent)
    : QObject(parent), m_parser(std::move(parser)) {}

void DispatcherWorker::on_replay_finished() {
    // 经队列投递到 worker 线程,晚于全部 frame_ready → 此刻积压帧已解析完,汇总计数完整
    pa::summarize();
}

void DispatcherWorker::on_frame(const BplcFrame& frame, quint64 credit_gen) {
    if (m_stopped.load()) {          // 已停止:立即返回,快速清空积压帧
        if (m_credit) m_credit->release(credit_gen);
        return;
    }
    QElapsedTimer t; t.start();
    ParseResult r;
    if (!frame.error_reason.isEmpty() || !frame.accepted) {
        // reader 已判定的成帧垃圾(DROP):不进解析器,直接合成拒收结果。
        // mpdu/msdu 值初始化全零,保证行着色走灰(DROP)而不触发红 clause;
        // msdu 重组状态不被垃圾污染(重组链只见真帧)。
        r.protocol = m_parser->variant();
        r.meta = frame.meta;
        r.raw_wire = frame.raw_wire;
        r.arrival_us = frame.arrival_us;
        r.accept = false;
        r.reject_reason = frame.error_reason;
        r.mpdu = MpduInfo();
        r.msdu = MsduInfo();
        r.beacon = MsduInfo();
    } else {
        // 显示时间上下文:行序号(分发器帧计数,即该帧将填入的行号) + 本地时间
        // (reader 成帧时采样,经此透传;未带时现取。解析线程现取会含队列积压
        // 延迟,回退行与后续链时间整体偏晚,故以收帧时刻为准)
        DisplayContext ctx;
        ctx.row_index = m_frame_count.load() + 1;
        ctx.now_ms = frame.meta.local_rx_ms > 0
            ? frame.meta.local_rx_ms
            : QDateTime::currentMSecsSinceEpoch();
        m_parser->set_display_context(ctx);
        // 解析时不过滤(仅显示过滤):传默认空过滤,内置解析器不再读取过滤字段
        r = m_parser->parse(frame, m_msdu, ParseFilter{});
    }
    // 帧级拒绝留痕(限流):协议 + 帧序号 + 原因,便于现场排查帧被丢弃的根因
    if (!r.accept && !r.reject_reason.isEmpty())
        pa::warn(proto_name(r.protocol) + QStringLiteral(":frame_rejected"),
                 QStringLiteral("idx=%1 reason=%2")
                     .arg(m_frame_count.load() + 1).arg(r.reject_reason));
    r.meta.seg_start = frame.meta.seg_start;
    r.meta.replay_time_tag = frame.meta.replay_time_tag;
    // 条目在解析线程预构建(字段移动 + 搜索文本 + 插件模板),GUI 线程只补序号/时间
    PreparedEntryPtr prepared = prepare_entry(std::move(r));
    prepared->credit_gen = credit_gen;   // 额度代号透传到 GUI 归还处
    emit parsed(prepared);
    // 不再忙等限速:Reader 侧的在途额度(FrameCredit,GUI 处理完解析结果才归还)
    // 把 Reader → 解析 → GUI 的积压限制在固定帧数内,错协议快解析也不会淹没 GUI。
    // 累计统计:每 5 万帧打一条进度,定位回灌卡顿在哪个环节
    const quint64 n = m_frame_count.fetch_add(1) + 1;
    m_parse_us.fetch_add(quint64(t.nsecsElapsed() / 1000));
    if (n % 50000 == 0) {
        QLOG_INFO() << "parse progress:" << n << "frames, cumulative parse"
                    << (m_parse_us.load() / 1000) << "ms";
    }
}

FrameDispatcher::FrameDispatcher(QObject* parent)
    : QObject(parent), m_thread(nullptr), m_worker(nullptr) {
    // 按 config.ini 协议选择实例化解析器(内置国网/南网,或插件协议)
    // 协议键统一转大写为注册表 id: "gw_2022"→"GW_2022",插件协议直接存大写 id
    auto parser = make_parser_by_id(appcfg::protocol().toUpper());
    if (!parser)  // 未知协议回退国网 2026
        parser = make_parser_by_id(QStringLiteral("GW_2026"));
    if (!parser) {  // 国网 2026 亦缺失(注册表损坏):不建 worker/线程,防 on_frame 空指针解引用
        QLOG_FATAL() << "FrameDispatcher: no parser available (registry broken), worker not started";
        return;  // m_thread/m_worker 保持 nullptr,析构/shutdown/disconnect 均已判空
    }
    m_thread = new QThread(this);
    m_worker = new DispatcherWorker(std::move(parser));
    m_worker->moveToThread(m_thread);
    connect(m_thread, &QThread::finished, m_worker, &QObject::deleteLater);
    connect(m_worker, &DispatcherWorker::parsed,
            this,     &FrameDispatcher::on_parsed,
            Qt::QueuedConnection);
    m_thread->start();
}

FrameDispatcher::~FrameDispatcher() {
    if (m_thread) {
        // 不用 terminate():线程可能正持有 pa::mutex/分配器锁,强杀后退出时死锁或堆损坏。
        // 置停止标志后积压帧直接跳过,quit 在当前这一帧解析完即返回(内置解析器 µs 级,
        // 插件解析受 IPC 超时约束),因此无超时等待是有界的。
        if (m_worker) m_worker->request_stop();
        m_thread->quit();
        if (!m_thread->wait(5000)) {
            // 有界首等:超时只告警不放弃(强杀/析构仍在跑的 QThread 都更糟),随后继续等到退出
            qWarning() << "FrameDispatcher: thread still running after 5000 ms, waiting for it to finish";
            m_thread->wait();
        }
    }
}

void FrameDispatcher::connect_source(QObject* source) {
    if (!m_worker) return;  // 构造时无可用解析器(见构造):不接信号,帧自然不流入
    connect(source, SIGNAL(frame_ready(BplcFrame,quint64)),
            m_worker, SLOT(on_frame(BplcFrame,quint64)),
            Qt::QueuedConnection);
    // 回放/采集结束信号同样排队投递:worker 按 FIFO 先解析完积压帧再汇总,
    // 避免回放线程早于解析线程汇总导致计数不全
    connect(source, SIGNAL(finished()),
            m_worker, SLOT(on_replay_finished()),
            Qt::QueuedConnection);
}

void FrameDispatcher::set_flow_credit(std::shared_ptr<FrameCredit> credit) {
    m_credit = std::move(credit);
    if (!m_credit) return;
    if (!m_worker) {                 // 无解析线程:没有消费者归还额度,不能限流
        m_credit->set_enabled(false);
        m_credit = nullptr;
        return;
    }
    // worker 已在解析线程:排队过去设置,避免跨线程写 shared_ptr
    DispatcherWorker* w = m_worker;
    std::shared_ptr<FrameCredit> c = m_credit;
    QMetaObject::invokeMethod(w, [w, c]() { w->set_flow_credit(c); }, Qt::QueuedConnection);
    m_credit->reset();
    m_credit->set_enabled(true);
}

void FrameDispatcher::disconnect_source(QObject* source) {
    if (source && m_worker)
        disconnect(source, nullptr, m_worker, nullptr);
}

void FrameDispatcher::shutdown() {
    // 立即断开 worker→本对象的所有信号连接(含 parsed),并退出解析线程:
    // request_stop 置停止标志让 on_frame 直接返回(不清算积压帧),
    // 再 quit,线程快速退出、不再向 GUI 投递 parsed 事件。
    if (m_worker) {
        m_worker->request_stop();
        disconnect(m_worker, nullptr, this, nullptr);
    }
    if (m_thread) m_thread->quit();
    // 在途帧随旧解析线程丢弃,额度不会再归还:清零并暂停限流,直到新 dispatcher 接入
    if (m_credit) {
        m_credit->set_enabled(false);
        m_credit->reset();
        m_credit = nullptr;
    }
}

void FrameDispatcher::on_parsed(const PreparedEntryPtr& p) {
    // GUI 已接手这一帧:按帧所属代号归还背压额度(旧会话迟到的结果自动作废)
    if (m_credit) m_credit->release(p->credit_gen);
    const PacketEntry& e = p->entry;
    m_total.fetch_add(1);
    if (!e.accepted) m_dropped.fetch_add(1);

    FrameStatistics::Key key = FrameStatistics::KEY_OTHER;
    if (e.accepted) {
        bool rf = e.meta.is_rf;
        switch (e.mpdu.frame_type) {
            case 0: key = rf ? FrameStatistics::KEY_BEACON_HRF : FrameStatistics::KEY_BEACON_HPLC; break;
            case 1: key = rf ? FrameStatistics::KEY_SOF_HRF    : FrameStatistics::KEY_SOF_HPLC;    break;
            case 2: key = rf ? FrameStatistics::KEY_ACK_HRF    : FrameStatistics::KEY_ACK_HPLC;    break;
            case 3: key = rf ? FrameStatistics::KEY_COORD_HRF  : FrameStatistics::KEY_COORD_HPLC;  break;
        }
        m_stats.increment(key);
        if (!e.msdu_body.isEmpty()) m_stats.increment(FrameStatistics::KEY_MSDU_COMPLETE);
    } else {
        m_stats.increment(FrameStatistics::KEY_DROPPED);
    }

    emit parsed(p);
    emit stats_updated();
}
