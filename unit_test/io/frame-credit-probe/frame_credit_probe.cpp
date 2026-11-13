/// @file frame_credit_probe.cpp
/// @brief M7 回归:Reader → 消费者 背压与中止
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QFile>
#include <QTemporaryFile>
#include <QThread>
#include <atomic>
#include <cstdio>
#ifdef Q_OS_LINUX
#include <fcntl.h>
#include <pty.h>
#include <termios.h>
#include <unistd.h>
#include <QMetaObject>
#endif
#include "frame_credit.h"
#include "serialreader.h"

static int g_fail = 0;
static void check(bool ok, const char* what) {
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++g_fail;
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    // ① 未接入消费者:不限流
    {
        FrameCredit c(4);
        int ok = 0;
        for (int i = 0; i < 100; ++i) ok += c.acquire([] { return false; });
        check(ok == 100, "disabled credit never blocks");
    }
    // ② 接入后到上限阻塞;中止 → 放弃(有界时间)
    {
        FrameCredit c(4);
        c.set_enabled(true);
        for (int i = 0; i < 4; ++i) c.acquire([] { return false; });
        std::atomic<bool> abort{false};
        std::atomic<int> result{-1};
        QThread* t = QThread::create([&] { result = c.acquire([&] { return abort.load(); }) ? 1 : 0; });
        t->start();
        QThread::msleep(150);
        check(result.load() == -1, "acquire blocks when in-flight is at the cap");
        QElapsedTimer tm; tm.start();
        abort = true;
        t->wait();
        check(result.load() == 0 && tm.elapsed() < 500, "abort releases a blocked acquire within 500 ms");
        delete t;
    }
    // ③ release / reset / disable 都能解除阻塞
    for (int mode = 0; mode < 3; ++mode) {
        FrameCredit c(2);
        c.set_enabled(true);
        c.acquire([] { return false; });
        c.acquire([] { return false; });
        std::atomic<int> result{-1};
        QThread* t = QThread::create([&] { result = c.acquire([] { return false; }) ? 1 : 0; });
        t->start();
        QThread::msleep(80);
        if (mode == 0) c.release(); else if (mode == 1) c.reset(); else c.set_enabled(false);
        t->wait(2000);
        static const char* names[] = {"release unblocks", "reset unblocks", "disable unblocks"};
        check(result.load() == 1, names[mode]);
        delete t;
    }
    // ④ 真实 ReaderWorker:慢消费者下在途帧不超过上限;stop 打断阻塞的回放
    {
        QFile sample(QStringLiteral(BPLC_REPO_DIR "/unit_test/ci/roundtrip/roundtrip_test.bin"));
        sample.open(QIODevice::ReadOnly);
        const QByteArray frames = sample.readAll();
        QTemporaryFile f;
        f.open(); f.write(frames); f.close();
        auto credit = std::make_shared<FrameCredit>(64);
        credit->set_enabled(true);
        std::atomic<int> emitted{0};
        std::atomic<int> max_seen{0};
        std::atomic<ReaderWorker*> worker{nullptr};
        ReaderConfig cfg;
        cfg.mode = ReaderMode::FilePlayback;
        cfg.file_path = f.fileName();
        QThread* th = QThread::create([&] {
            ReaderWorker w;
            w.set_flow_credit(credit);
            QObject::connect(&w, &ReaderWorker::frame_ready, &w, [&](const BplcFrame&) {
                ++emitted;
                const int n = credit->in_flight();
                if (n > max_seen) max_seen = n;
            });
            worker = &w;
            w.start_reading(cfg);
            worker = nullptr;
        });
        th->start();
        // 慢消费者:每 1 ms 归还 1 个额度,共 300 个
        for (int i = 0; i < 300; ++i) { QThread::msleep(1); credit->release(); }
        const int before_stop = emitted.load();
        check(max_seen.load() <= 64, "in-flight frames never exceed the cap");
        check(before_stop < 2457 && before_stop >= 64, "reader is throttled by a slow consumer");
        QElapsedTimer tm; tm.start();
        if (ReaderWorker* w = worker.load()) w->abort();
        const bool done = th->wait(3000);
        std::printf("  emitted=%d max_in_flight=%d stop_latency=%lld ms\n", before_stop,
                    max_seen.load(), (long long)tm.elapsed());
        check(done && tm.elapsed() < 1000, "stop interrupts a reader blocked on credit");
        delete th;
    }
#ifdef Q_OS_LINUX
    // ⑤ 实时串口(pty 模拟):消费者完全不归还额度,Reader 仍持续读串口、不被背压阻塞
    //    (阻塞会让驱动缓冲溢出静默丢字节)。修复前在途达到上限即停读。
    {
        QFile sample(QStringLiteral(BPLC_REPO_DIR "/unit_test/ci/roundtrip/roundtrip_test.bin"));
        sample.open(QIODevice::ReadOnly);
        const QByteArray frames = sample.readAll();
        int master = -1, slave = -1;
        char slave_name[256] = {0};
        const bool pty_ok = ::openpty(&master, &slave, slave_name, nullptr, nullptr) == 0;
        if (!pty_ok) {
            std::printf("SKIP live serial case: openpty failed\n");
        } else {
            termios tio{};
            tcgetattr(slave, &tio); cfmakeraw(&tio); tcsetattr(slave, TCSANOW, &tio);
            constexpr int kCap = 16;
            auto credit = std::make_shared<FrameCredit>(kCap);
            credit->set_enabled(true);
            std::atomic<int> emitted{0};
            QThread th;
            auto* w = new ReaderWorker;
            w->set_flow_credit(credit);
            w->moveToThread(&th);
            QObject::connect(&th, &QThread::finished, w, &QObject::deleteLater);
            QObject::connect(w, &ReaderWorker::frame_ready, w, [&](const BplcFrame&) { ++emitted; },
                             Qt::DirectConnection);
            th.start();
            ReaderConfig cfg;
            cfg.mode = ReaderMode::SerialPort;
            cfg.serial_name = QString::fromLocal8Bit(slave_name);
            cfg.baud_rate = 115200;
            QMetaObject::invokeMethod(w, [w, cfg] { w->start_reading(cfg); }, Qt::QueuedConnection);
            QThread::msleep(200);
            // 写端非阻塞:Reader 若停读,pty 缓冲写满后写入停滞
            ::fcntl(master, F_SETFL, ::fcntl(master, F_GETFL) | O_NONBLOCK);
            qint64 written = 0;
            QElapsedTimer tm; tm.start();
            while (written < frames.size() && tm.elapsed() < 5000) {
                const ssize_t n = ::write(master, frames.constData() + written,
                                          size_t(qMin<qint64>(4096, frames.size() - written)));
                if (n > 0) written += n; else QThread::msleep(2);
            }
            QThread::msleep(300);
            const int got = emitted.load();
            std::printf("  live serial: written=%lld/%lld emitted=%d in_flight=%d (cap %d)\n",
                        (long long)written, (long long)frames.size(), got, credit->in_flight(), kCap);
            check(written == frames.size(), "live serial: reader keeps draining the port with no credit returned");
            check(got > 4 * kCap, "live serial: frames are not throttled by the in-flight cap");
            w->abort();   // 修复前 Reader 可能阻塞在 acquire:先中止再停,探针不至于挂死
            QMetaObject::invokeMethod(w, [w] { w->stop_reading(); }, Qt::BlockingQueuedConnection);
            th.quit(); th.wait(3000);
            ::close(master); ::close(slave);
        }
    }
#endif
    std::printf("frame_credit_probe: %s (%d failures)\n", g_fail ? "FAIL" : "OK", g_fail);
    return g_fail ? 1 : 0;
}
