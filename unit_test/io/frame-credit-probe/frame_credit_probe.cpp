/// @file frame_credit_probe.cpp
/// @brief M7 回归:Reader → 消费者 背压与中止
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QFile>
#include <QTemporaryFile>
#include <QThread>
#include <atomic>
#include <cstdio>
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
    std::printf("frame_credit_probe: %s (%d failures)\n", g_fail ? "FAIL" : "OK", g_fail);
    return g_fail ? 1 : 0;
}
