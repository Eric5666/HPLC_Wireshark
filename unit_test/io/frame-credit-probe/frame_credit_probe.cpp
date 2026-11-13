/// @file frame_credit_probe.cpp
/// @brief M7 回归:Reader → 消费者 背压与中止
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QFile>
#include <QTemporaryFile>
#include <QThread>
#include <QMutex>
#include <atomic>
#include <cstdio>
#include <deque>
#include <random>
#include <vector>
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
        if (mode == 0) c.release(c.generation()); else if (mode == 1) c.reset(); else c.set_enabled(false);
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
        std::atomic<int> bad_gen{0};
        const quint64 gen = credit->generation();
        std::atomic<ReaderWorker*> worker{nullptr};
        ReaderConfig cfg;
        cfg.mode = ReaderMode::FilePlayback;
        cfg.file_path = f.fileName();
        QThread* th = QThread::create([&] {
            ReaderWorker w;
            w.set_flow_credit(credit);
            QObject::connect(&w, &ReaderWorker::frame_ready, &w, [&](const BplcFrame&, quint64 g) {
                ++emitted;
                if (g != gen) ++bad_gen;
                const int n = credit->in_flight();
                if (n > max_seen) max_seen = n;
            });
            worker = &w;
            w.start_reading(cfg);
            worker = nullptr;
        });
        th->start();
        // 慢消费者:每 1 ms 归还 1 个额度,共 300 个
        for (int i = 0; i < 300; ++i) { QThread::msleep(1); credit->release(gen); }
        const int before_stop = emitted.load();
        check(bad_gen.load() == 0, "playback frames carry the credit generation in effect");
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
            std::atomic<int> bad_gen{0};
            const quint64 gen = credit->generation();
            QThread th;
            auto* w = new ReaderWorker;
            w->set_flow_credit(credit);
            w->moveToThread(&th);
            QObject::connect(&th, &QThread::finished, w, &QObject::deleteLater);
            QObject::connect(w, &ReaderWorker::frame_ready, w,
                             [&](const BplcFrame&, quint64 g) { ++emitted; if (g != gen) ++bad_gen; },
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
            check(bad_gen.load() == 0, "live serial: frames carry the credit generation in effect");
            w->abort();   // 修复前 Reader 可能阻塞在 acquire:先中止再停,探针不至于挂死
            QMetaObject::invokeMethod(w, [w] { w->stop_reading(); }, Qt::BlockingQueuedConnection);
            th.quit(); th.wait(3000);
            ::close(master); ::close(slave);
        }
    }
#endif
    // ⑥ 会话隔离(a):旧会话 acquire N → reset(新会话)→ 新会话取满上限 →
    //    旧会话 N 个迟到的 release 到达:新会话在途数不变,且仍在上限处阻塞(不超限)。
    //    修复前 release 不分会话,迟到归还扣减新会话计数,新会话可越过上限再发 N 帧。
    {
        constexpr int kCap = 8, kOld = 5;
        FrameCredit c(kCap);
        c.set_enabled(true);
        std::vector<quint64> old_gens;
        for (int i = 0; i < kOld; ++i) {
            quint64 g = 0;
            c.acquire([] { return false; }, &g);
            old_gens.push_back(g);
        }
        c.reset();                                     // 新会话开始
        quint64 new_gen = 0;
        for (int i = 0; i < kCap; ++i) c.acquire([] { return false; }, &new_gen);
        for (quint64 g : old_gens) c.release(g);       // 旧会话解析结果迟到
        std::printf("  stale: old_gen=%llu new_gen=%llu in_flight=%d (cap %d)\n",
                    (unsigned long long)old_gens.front(), (unsigned long long)new_gen,
                    c.in_flight(), kCap);
        check(c.in_flight() == kCap, "stale releases from the old session leave the new session's count unchanged");
        std::atomic<bool> abort{false};
        std::atomic<int> result{-1};
        QThread* t = QThread::create([&] { result = c.acquire([&] { return abort.load(); }) ? 1 : 0; });
        t->start();
        QThread::msleep(150);
        check(result.load() == -1, "new session still blocks at the cap after stale releases");
        c.release(new_gen);                            // 新会话自己的归还才解除阻塞
        t->wait(2000);
        check(result.load() == 1, "a current-generation release unblocks the new session");
        delete t;
        // 防下溢:多余归还(含当前代)不会让计数为负
        for (int i = 0; i < 3 * kCap; ++i) c.release(new_gen);
        check(c.in_flight() == 0, "extra releases never drive the count below zero");
        c.release(FrameCredit::kNoGeneration);
        check(c.in_flight() == 0, "release of an untracked frame (generation 0) is a no-op");
    }
    // ⑦ 会话隔离(b)压力:多轮会话,每轮留下未归还的旧额度;旧额度的迟到 release 由独立线程
    //    随机穿插在新会话的 acquire/release 之间(固定种子)。真实在途帧数(生产者发出、消费者
    //    尚未归还)任何时刻都不超过上限,且最终计数为 0。
    {
        constexpr int kCap = 16, kRounds = 6, kPerRound = 4000, kLeftover = kCap / 2;
        auto credit = std::make_shared<FrameCredit>(kCap);
        credit->set_enabled(true);
        std::mt19937 rng(20261114u);
        std::vector<quint64> stale;                    // 历轮遗留的旧代额度(按帧记)
        std::atomic<int> real_in_flight{0};
        std::atomic<int> max_real{0};
        for (int round = 0; round < kRounds; ++round) {
            credit->reset();                           // 新会话
            real_in_flight = 0;
            QMutex qlock;
            std::deque<quint64> queue;                 // 生产者 → 消费者(帧及其代号)
            std::atomic<bool> producer_done{false};
            std::vector<quint64> stale_now = stale;
            std::shuffle(stale_now.begin(), stale_now.end(), rng);
            const unsigned stale_seed = rng();
            const unsigned cons_seed = rng();
            QThread* prod = QThread::create([&] {
                for (int i = 0; i < kPerRound; ++i) {
                    quint64 g = 0;
                    if (!credit->acquire([] { return false; }, &g)) break;
                    const int n = ++real_in_flight;
                    int m = max_real.load();
                    while (n > m && !max_real.compare_exchange_weak(m, n)) {}
                    QMutexLocker lk(&qlock);
                    queue.push_back(g);
                }
                producer_done = true;
            });
            QThread* cons = QThread::create([&] {
                std::mt19937 r(cons_seed);
                for (;;) {
                    quint64 g = 0;
                    bool have = false;
                    {
                        QMutexLocker lk(&qlock);
                        if (!queue.empty()) { g = queue.front(); queue.pop_front(); have = true; }
                    }
                    if (!have) {
                        if (producer_done.load()) {
                            QMutexLocker lk(&qlock);
                            if (queue.empty()) break;
                        }
                        QThread::yieldCurrentThread();
                        continue;
                    }
                    if (r() % 8 == 0) QThread::yieldCurrentThread();
                    --real_in_flight;                  // 先减真实在途,再归还额度
                    credit->release(g);
                }
            });
            QThread* stl = QThread::create([&] {
                std::mt19937 r(stale_seed);
                // 每个旧额度随机重复归还 1~3 次,穿插在新会话流量中
                for (quint64 g : stale_now) {
                    const int reps = 1 + int(r() % 3);
                    for (int k = 0; k < reps; ++k) {
                        for (unsigned y = r() % 64; y > 0; --y) QThread::yieldCurrentThread();
                        credit->release(g);
                    }
                }
            });
            prod->start(); cons->start(); stl->start();
            prod->wait(); cons->wait(); stl->wait();
            delete prod; delete cons; delete stl;
            if (credit->in_flight() != 0)
                std::printf("  round %d: in_flight=%d after drain\n", round, credit->in_flight());
            // 本轮结束前再取一批不归还:成为下一轮的"旧会话迟到额度"
            if (round + 1 < kRounds) {
                for (int i = 0; i < kLeftover; ++i) {
                    quint64 g = 0;
                    credit->acquire([] { return false; }, &g);
                    stale.push_back(g);
                }
            }
        }
        std::printf("  stress: rounds=%d stale_frames=%zu max_real_in_flight=%d (cap %d) final=%d\n",
                    kRounds, stale.size(), max_real.load(), kCap, credit->in_flight());
        check(max_real.load() <= kCap, "stress: real in-flight never exceeds the cap with interleaved stale releases");
        check(credit->in_flight() == 0 && real_in_flight.load() == 0, "stress: final in-flight count is 0");
    }
    // ⑧ 会话隔离(c):实时串口 acquire_nowait 路径不受影响 —— 从不阻塞、返回当前代号、
    //    计数照常与本代 release 配平;换代后旧代归还同样作废
    {
        constexpr int kCap = 4;
        FrameCredit c(kCap);
        c.set_enabled(true);
        const quint64 g0 = c.generation();
        QElapsedTimer tm; tm.start();
        bool gens_ok = true;
        for (int i = 0; i < 100; ++i) gens_ok = gens_ok && c.acquire_nowait() == g0;
        check(tm.elapsed() < 200 && c.in_flight() == 100 && gens_ok,
              "live serial: acquire_nowait never blocks past the cap and returns the current generation");
        c.reset();
        const quint64 g1 = c.acquire_nowait();
        for (int i = 0; i < 100; ++i) c.release(g0);
        check(g1 != g0 && c.in_flight() == 1, "live serial: stale releases do not touch the new session");
        c.release(g1);
        check(c.in_flight() == 0, "live serial: current-generation release still balances the count");
    }
    std::printf("frame_credit_probe: %s (%d failures)\n", g_fail ? "FAIL" : "OK", g_fail);
    return g_fail ? 1 : 0;
}
