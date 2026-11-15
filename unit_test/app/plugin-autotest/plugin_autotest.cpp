/// @file plugin_autotest.cpp
/// @brief 插件自动化截图测试实现(测试侧,经 MainWindow 公开测试接口驱动)
#include "plugin_autotest.h"

#include "mainwindow.h"
#include "capturecontroller.h"
#include "local_plugin_engine.h"
#include "packetlistmodel.h"
#include "plugin_market.h"
#include "plugin_panels.h"

#include <QApplication>
#include <QDebug>
#include <QDir>
#include <QTabWidget>
#include <QTimer>

PluginAutotest::PluginAutotest(MainWindow* window, const QString& shot_dir)
    : QObject(window), m_window(window), m_shot_dir(shot_dir) {}

void PluginAutotest::start(const QString& plugins_dir, const QString& bin) {
    qInfo() << "[autotest] start, bin=" << bin << "shots=" << m_shot_dir;
    QDir().mkpath(m_shot_dir);
    // 等插件加载完成再开始回放
    connect(m_window->plugin_engine(), &LocalPluginEngine::load_finished, this,
            [this, bin]() { on_load_finished(bin); });
    m_window->load_plugin_dirs(QStringList() << plugins_dir
                                             << PluginMarket::default_install_dir());
}

void PluginAutotest::on_load_finished(const QString& bin) {
    qInfo() << "[autotest] load_finished, starting import";
    disconnect(m_window->plugin_engine(), &LocalPluginEngine::load_finished,
               this, nullptr);
    m_window->start_file_import(bin);
    qInfo() << "[autotest] import started";
    // 回放结束 → 轮询插件线程排空(只处理一次,finished 可能发多次)
    connect(m_window->capture()->reader(), &SerialReader::finished,
            this, &PluginAutotest::on_reader_finished);
}

void PluginAutotest::on_reader_finished() {
    if (m_reader_seen) return;
    m_reader_seen = true;
    qInfo() << "[autotest] reader finished";
    disconnect(m_window->capture()->reader(), &SerialReader::finished,
               this, &PluginAutotest::on_reader_finished);
    m_poll = new QTimer(this);
    m_poll->setInterval(500);
    connect(m_poll, &QTimer::timeout, this, &PluginAutotest::poll_idle);
    m_poll->start();
}

void PluginAutotest::poll_idle() {
    ++m_waits;
    // 首个 finished 可能来自 start_file_import 里 stop() 的旧会话;
    // 背压下回放不再瞬间读完,须等 reader 结束且在途帧全部交给 GUI
    CaptureController* cap = m_window->capture();
    const bool idle = m_window->plugin_engine()->is_idle()
        && !cap->is_running()
        && cap->reader()->flow_credit()->in_flight() == 0;
    if (!idle && m_waits <= 1200) return;  // 排空或 10min 超时
    m_poll->stop();
    m_poll->deleteLater();
    m_poll = nullptr;
    qInfo() << "[autotest] idle, waits=" << m_waits
            << "tabs=" << m_window->plugin_tabs()->count();
    shoot_tabs();
}

/// @brief 逐 tab 截图(每个 tab 显示 1.5s 等面板刷新后再抓)
void PluginAutotest::shoot_tabs() {
    if (m_shooting) return;  // 只跑一次
    m_shooting = true;
    qInfo() << "[autotest] shoot start";
    m_tab_count = m_window->plugin_tabs()->count();
    m_tab_index = -1;
    m_field_shot_done = false;
    m_shoot_timer = new QTimer(this);
    m_shoot_timer->setInterval(1500);
    connect(m_shoot_timer, &QTimer::timeout, this, &PluginAutotest::shoot_tick);
    m_shoot_timer->start();
}

void PluginAutotest::shoot_tick() {
    QTabWidget* tabs = m_window->plugin_tabs();
    qInfo() << "[autotest] shoot tick i=" << m_tab_index << "n=" << m_tab_count;
    // 先抓上一个 tab(已显示 1.5s,面板刷新完成)
    if (m_tab_index >= 0 && m_tab_index < tabs->count()) {
        QWidget* tab = tabs->widget(m_tab_index);
        const QString pid = m_window->plugin_id_of(tab);
        tab->grab().save(QStringLiteral("%1/plugin_%2.png").arg(m_shot_dir, pid));
    }
    ++m_tab_index;
    if (m_tab_index >= m_tab_count) {
        // 先选中一帧带 MSDU 的报文,让底部字段树/hex 有内容,下一拍再截 main.png
        if (!m_field_shot_done) {
            m_field_shot_done = true;
            PacketListModel* model = m_window->packet_model();
            qint64 target = 0;
            const qint64 total = model ? model->total_count() : 0;
            for (qint64 f = 1; f <= total; ++f) {
                PacketEntry e;
                if (model->entry_at(int(f - 1), e)
                    && e.msdu.present && !e.msdu.summary.isEmpty()) {
                    target = f;
                    break;
                }
            }
            if (target < 1) target = total;  // 兜底:最后一帧
            m_window->jump_packet_to_frame(target);
            qInfo() << "[autotest] select frame for field view:" << target;
            return;
        }
        m_shoot_timer->stop();
        m_shoot_timer->deleteLater();
        m_shoot_timer = nullptr;
        m_window->grab().save(QStringLiteral("%1/main.png").arg(m_shot_dir));
        qApp->quit();
        return;
    }
    // 显示下一个 tab 并触发一次刷新
    tabs->setCurrentIndex(m_tab_index);
    QWidget* tab = tabs->widget(m_tab_index);
    if (auto* tp = qobject_cast<TopoPluginPanel*>(tab)) tp->refresh_now();
    else if (auto* rp = qobject_cast<ReplayPluginPanel*>(tab)) rp->refresh_now();
    else if (auto* rep = qobject_cast<ReportPluginPanel*>(tab)) rep->generate_now();
}
