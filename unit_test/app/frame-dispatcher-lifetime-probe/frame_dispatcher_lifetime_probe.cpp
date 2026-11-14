/// @file frame_dispatcher_lifetime_probe.cpp
/// @brief FrameDispatcher 反复 构造→shutdown()→处理延迟删除→析构(切换协议/重连时的重建路径)。
///        旧实现 shutdown 提前 quit 使 worker 经 finished→deleteLater 先被删,析构再
///        request_stop() 即释放后使用(ASan heap-use-after-free)。修复后应 0 报错。
#include <QCoreApplication>
#include <QThread>
#include <cstdio>

#include "framedispatcher.h"

// 本探针不喂帧,on_frame 不会走到 prepare_entry;给个桩免得链接整个 UI(entrybuilder→topo)
PreparedEntryPtr prepare_entry(ParseResult&&) { return PreparedEntryPtr(); }

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    constexpr int kRounds = 50;
    for (int i = 0; i < kRounds; ++i) {
        auto* d = new FrameDispatcher();
        d->shutdown();
        // 让 QThread::finished 及其可能挂的 deleteLater 全部投递并执行
        for (int k = 0; k < 5; ++k) {
            QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
            QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
            QThread::msleep(1);
        }
        delete d;
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    }
    // 不调 shutdown 直接析构的路径也走一遍
    for (int i = 0; i < 10; ++i) delete new FrameDispatcher();
    std::printf("frame_dispatcher_lifetime_probe: OK (%d rounds, 0 failures)\n", kRounds);
    return 0;
}
