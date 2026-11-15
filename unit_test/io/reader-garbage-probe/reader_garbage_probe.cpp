/// @file reader_garbage_probe.cpp
/// @brief M5 回归:回放/串口切帧遇大段无 0x3C 数据时线性丢弃;BCD 段标注语义不变;abort 块内生效
#include <QCoreApplication>
#include <QDateTime>
#include <QElapsedTimer>
#include <QFile>
#include <QRandomGenerator>
#include <QTemporaryDir>
#include <QThread>
#include <cstdio>
#include "serialreader.h"

static int g_fail = 0;
static void check(bool ok, const char* what) {
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++g_fail;
}

/// 随机垃圾(无 0x3C);no_bcd=true 时每字节高半字节 ≥ 0xA,保证其中不会偶然出现合法 BCD 标注
static QByteArray garbage(int n, quint32 seed, bool no_bcd = false) {
    QRandomGenerator rng(seed);
    QByteArray g(n, Qt::Uninitialized);
    for (int i = 0; i < n; ++i) {
        char c = char(no_bcd ? 0xA0 + rng.bounded(0x60) : rng.bounded(256));
        if (c == char(0x3C)) c = 0;
        g[i] = c;
    }
    return g;
}

/// 2026-11-11 08:30:15.250 的 8B BCD 段标注
static QByteArray bcd_tag() {
    return QByteArray::fromHex("2611110830150250");
}

class ReaderWorkerTestAccess {
public:
    struct Run { int frames; qint64 first_epoch; qint64 ms; int retained; };
    static Run file(const QByteArray& input) {
        QTemporaryDir dir;
        QFile f(dir.filePath("in.bin"));
        f.open(QIODevice::WriteOnly); f.write(input); f.close();
        ReaderWorker w;
        ReaderConfig cfg;
        cfg.mode = ReaderMode::FilePlayback;
        cfg.file_path = f.fileName();
        Run r{0, -1, 0, 0};
        QObject::connect(&w, &ReaderWorker::frame_ready, [&](const BplcFrame& fr) {
            if (r.frames++ == 0) r.first_epoch = fr.meta.frame_time.toMSecsSinceEpoch();
        });
        QElapsedTimer t; t.start();
        w.start_reading(cfg);
        r.ms = t.elapsed();
        return r;
    }
    static Run serial(const QByteArray& input) {
        ReaderWorker w;
        w.m_cfg.mode = ReaderMode::SerialPort;
        Run r{0, -1, 0, 0};
        QObject::connect(&w, &ReaderWorker::frame_ready, [&](const BplcFrame&) { ++r.frames; });
        QElapsedTimer t; t.start();
        w.m_in_buf = input;
        w.try_extract_frame();
        r.ms = t.elapsed();
        r.retained = w.m_in_buf.size();
        return r;
    }
    /// 在线程里回放,主线程 delay_ms 后 abort,返回 abort→返回 的耗时
    static qint64 abort_latency(const QByteArray& input, int delay_ms, int* frames_out) {
        QTemporaryDir dir;
        QFile f(dir.filePath("in.bin"));
        f.open(QIODevice::WriteOnly); f.write(input); f.close();
        ReaderConfig cfg;
        cfg.mode = ReaderMode::FilePlayback;
        cfg.file_path = f.fileName();
        std::atomic<int> frames{0};
        std::atomic<ReaderWorker*> worker{nullptr};
        QThread* th = QThread::create([&]() {
            ReaderWorker w;   // 在回放线程里创建,子对象同线程
            QObject::connect(&w, &ReaderWorker::frame_ready, &w,
                             [&](const BplcFrame&) { ++frames; });
            worker = &w;
            w.start_reading(cfg);
            worker = nullptr;
        });
        th->start();
        while (!worker.load() && !th->isFinished()) QThread::usleep(100);
        QThread::msleep(delay_ms);
        QElapsedTimer t; t.start();
        if (ReaderWorker* w = worker.load()) w->abort();   // 与 SerialReader::stop 同:跨线程直接置标志
        th->wait();
        const qint64 ms = t.elapsed();
        delete th;
        *frames_out = frames.load();
        return ms;
    }
};

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QFile sample(QStringLiteral(BPLC_REPO_DIR "/unit_test/ci/roundtrip/roundtrip_test.bin"));
    if (!sample.open(QIODevice::ReadOnly)) { std::puts("FAIL open roundtrip_test.bin"); return 1; }
    const QByteArray frames = sample.readAll();
    using A = ReaderWorkerTestAccess;

    const A::Run base = A::file(frames);
    std::printf("  baseline: %d frames in %lld ms\n", base.frames, (long long)base.ms);
    check(base.frames > 100, "baseline sample replays");

    // ① 4 MB 无 0x3C 垃圾 + 样本:旧实现每 1 MB 块约 1e12 次比较(数小时),新实现线性
    {
        const A::Run r = A::file(garbage(4 * 1024 * 1024, 1) + frames);
        std::printf("  garbage+sample: %d frames in %lld ms\n", r.frames, (long long)r.ms);
        check(r.ms < 5000, "4 MB garbage replay finishes in < 5 s");
        check(r.frames == base.frames, "all sample frames still extracted after garbage");
    }

    // ② 整块(1 MB 读块)无 0x3C 的垃圾中夹 BCD 段标注:标注仍生效(首帧时间取标注),与逐字节滑窗一致
    {
        const QByteArray body = frames.mid(8);   // 去掉样本自带的 8B 文件头标注
        const A::Run plain = A::file(bcd_tag() + body);
        const A::Run noisy = A::file(garbage(300000, 2) + bcd_tag() + garbage(1200000, 3, true) + body);
        const qint64 tag_ms = QDateTime(QDate(2026, 11, 11), QTime(8, 30, 15, 250)).toMSecsSinceEpoch();
        check(plain.first_epoch == tag_ms, "plain tag sets first frame time");
        std::printf("  first epoch plain=%lld noisy=%lld\n", (long long)plain.first_epoch,
                    (long long)noisy.first_epoch);
        check(plain.first_epoch > 0 && noisy.first_epoch == plain.first_epoch,
              "BCD tag inside garbage still sets the segment time");
        check(noisy.frames == plain.frames, "frame count unchanged with tagged garbage");
    }

    // ③ 串口模式:2 MB 垃圾一次清空
    {
        const A::Run r = A::serial(garbage(2 * 1024 * 1024, 4));
        check(r.ms < 2000 && r.retained == 0 && r.frames == 0, "serial garbage dropped at once");
    }

    // ④ abort 在块内生效(20 份样本 ≈ 4.7 MB 帧数据)
    {
        QByteArray big;
        for (int i = 0; i < 20; ++i) big += frames;
        int got = 0;
        const qint64 ms = A::abort_latency(big, 5, &got);
        std::printf("  abort latency %lld ms, %d frames before stop\n", (long long)ms, got);
        check(ms < 1000, "abort stops replay within 1 s");
    }

    // ⑤ L5:start() 紧跟 stop(),worker 稍后处理 start 也不得回放(旧实现整文件回放完)
    {
        QByteArray big;
        for (int i = 0; i < 20; ++i) big += frames;
        QTemporaryDir dir;
        QFile f(dir.filePath("big.bin"));
        f.open(QIODevice::WriteOnly); f.write(big); f.close();
        ReaderConfig cfg;
        cfg.mode = ReaderMode::FilePlayback;
        cfg.file_path = f.fileName();
        SerialReader r;
        int got = 0;
        QObject::connect(&r, &SerialReader::frame_ready, [&](const BplcFrame&) { ++got; });
        r.start(cfg);
        r.stop();
        QElapsedTimer t; t.start();
        while (t.elapsed() < 800) { app.processEvents(); QThread::msleep(5); }
        check(got == 0, "stop right after start cancels the queued start");
        // 再次 start:新会话完整回放
        got = 0;
        r.start(cfg);
        t.restart();
        while (got < base.frames * 20 && t.elapsed() < 30000) { app.processEvents(); QThread::msleep(1); }
        std::printf("  second session frames=%d\n", got);
        check(got == base.frames * 20, "a later start replays the whole file");

        // ⑥ L4:回放被背压阻塞(无消费者归还额度)时析构,必须很快返回且不 qFatal
        auto* r2 = new SerialReader;
        r2->flow_credit()->set_enabled(true);
        r2->start(cfg);
        QThread::msleep(100);   // 4096 帧后阻塞在额度上
        QElapsedTimer td; td.start();
        delete r2;
        std::printf("  destroy while blocked: %lld ms\n", (long long)td.elapsed());
        check(td.elapsed() < 1000, "SerialReader destructor returns promptly while replay is blocked");
    }

    std::printf("reader_garbage_probe: %s (%d failures)\n", g_fail ? "FAIL" : "OK", g_fail);
    return g_fail ? 1 : 0;
}
