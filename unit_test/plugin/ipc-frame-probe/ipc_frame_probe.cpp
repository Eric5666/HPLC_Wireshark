/// @file ipc_frame_probe.cpp
/// @brief M1 回归:IPC 帧长上限与 qint64 比较
#include "ipc/plugin_ipc.h"

#include <QElapsedTimer>
#include <cstdio>

using plugin_ipc::FrameTake;

static int g_fail = 0;
static void check(bool ok, const char* what) {
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++g_fail;
}

static QByteArray hdr(quint32 len) {
    QByteArray b;
    b.append(char(len >> 24)).append(char(len >> 16)).append(char(len >> 8)).append(char(len));
    return b;
}

/// 模拟收包循环,返回最后结果;循环次数受限,防死循环
static FrameTake drain(QByteArray& buf, int& frames) {
    frames = 0;
    for (int i = 0; i < 1000; ++i) {
        QByteArray f;
        const FrameTake t = plugin_ipc::try_take_frame(buf, f);
        if (t != FrameTake::Ok) return t;
        ++frames;
    }
    return FrameTake::Ok;   // 超过 1000 次:视为死循环
}

int main() {
    QElapsedTimer tm; tm.start();
    // 合法帧
    {
        QByteArray b = hdr(3) + QByteArray("\x0b\x01\x02", 3) + hdr(1) + QByteArray("\x15", 1);
        int n = 0;
        check(drain(b, n) == FrameTake::NeedMore && n == 2 && b.isEmpty(), "two valid frames consumed");
    }
    // 半帧
    {
        QByteArray b = hdr(10) + QByteArray(5, 'x');
        int n = 0;
        check(drain(b, n) == FrameTake::NeedMore && n == 0 && b.size() == 9, "partial frame waits");
        QByteArray s = hdr(1).left(2);
        check(drain(s, n) == FrameTake::NeedMore, "partial header waits");
    }
    // 旧代码:4 + 0xFFFFFFFC 回绕为 0,remove(0,0) 原地死循环
    const quint32 bad[] = {0xFFFFFFFCu, 0xFFFFFFFFu, 0x80000000u, 0x7FFFFFFFu,
                           0x7FFFFFFCu, quint32(plugin_ipc::kMaxIpcFrame + 1), 0u};
    for (quint32 len : bad) {
        QByteArray b = hdr(len) + QByteArray(64, 'y');
        int n = 0;
        const FrameTake t = drain(b, n);
        char msg[96];
        std::snprintf(msg, sizeof msg, "len=0x%08X rejected as Bad", len);
        check(t == FrameTake::Bad && n == 0, msg);
    }
    // 上限本身合法(只要求等待,不分配)
    {
        QByteArray b = hdr(quint32(plugin_ipc::kMaxIpcFrame)) + QByteArray(16, 'z');
        int n = 0;
        check(drain(b, n) == FrameTake::NeedMore, "len=kMaxIpcFrame waits for data");
    }
    // 合法帧后紧跟坏帧:先取出合法帧,再报 Bad
    {
        QByteArray b = hdr(1) + QByteArray("\x15", 1) + hdr(0xFFFFFFFCu) + QByteArray(8, 'q');
        int n = 0;
        check(drain(b, n) == FrameTake::Bad && n == 1, "valid frame then bad frame");
    }
    check(tm.elapsed() < 2000, "finished quickly (no spin)");
    std::printf("ipc_frame_probe: %s (%d failures)\n", g_fail ? "FAIL" : "OK", g_fail);
    return g_fail ? 1 : 0;
}
