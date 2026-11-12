// crash_handler.h - 崩溃转储模块唯一对外接口
//
// 设计目标:
//   1. 与业务代码解耦:业务侧只调 CrashHandler::install() 一行,其他零侵入。
//   2. 后端可插拔:编译期通过 qmake CONFIG 选择后端,运行时按 Options 选择。
//   3. 无 Qt 依赖:纯 C++11,便于移植到其他工程。
//
// 编译开关 (qmake):
//   CONFIG += crash_sentry    编译 sentry-native 后端
//   CONFIG += crash_crashpad  编译 crashpad 原生后端
//   两个开关独立,可同时开(运行时按 Options::backend 选择其一)。
//
// 后端行为:
//   - sentry:   崩溃时生成 minidump,经 crashpad_handler 上传到 Sentry 服务(DSN)。
//               DSN 为空时仅本地落盘,不上传。
//   - crashpad: 崩溃时生成 minidump 到 database_path;配了 DSN/upload_url 则
//               由 crashpad_handler 自动上报到该地址,否则只本地落盘,
//               用户手动取回分析。
#ifndef BPLC_CRASH_HANDLER_H
#define BPLC_CRASH_HANDLER_H

#include <string>

class CrashHandler {
public:
    struct Options {
        // 要启用的后端:"sentry" | "crashpad" | "auto"(默认)。
        // "auto":优先 sentry(若编译了),其次 crashpad。
        std::string backend = "auto";
        // Sentry DSN,如 "http://key@host:9000/1"。为空则 sentry 后端只本地落盘。
        // crashpad 后端:为空则只本地落盘;非空时自动派生 minidump 上报地址并上传
        // (见 upload_url)。
        std::string dsn;
        // crashpad 后端专用上报地址,如 "https://host/api/1/minidump/?sentry_key=key"。
        // 为空且 dsn 非空时,从 DSN 自动派生 Sentry minidump 上报地址;
        // 两者都为空时只本地落盘,不上传。
        std::string upload_url;
        // 崩溃数据库/dump 落盘目录。为空则用 "./crashpad_db"。
        std::string database_path;
        // 发行版本,如 "1.2.2",写入崩溃报告便于区分版本。
        std::string release;
        // 随崩溃上报的自定义键值(产品名等),可选。
        std::string product_name = "BPLC_STA_Monitor";
    };

    // 安装崩溃处理器。返回实际启用的后端名("sentry"/"crashpad"),空串=未启用。
    // 只能调一次;重复调用返回首次结果。
    static std::string install(const Options& opts);

    // 关闭(程序正常退出前调用,刷新上报队列)。
    static void shutdown();

    // 手动落一份非崩溃 minidump(后端已激活且为 crashpad 时;否则空操作)。
    // 工具接口:仅 Windows 有效;Linux 为空操作(abort 路径改由 crashpad
    // 自带 SIGABRT 捕获兜底,不再经此接口)。不要在 qFatal/信号路径调它,
    // 否则与 abort 路径重复落 dump。
    static void dump_without_crash();

    // 编译期是否包含某后端("sentry"/"crashpad")。
    static bool has_backend(const char* name);

private:
    CrashHandler() = delete;
};

#endif  // BPLC_CRASH_HANDLER_H
