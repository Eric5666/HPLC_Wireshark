// crash_backend.h - 后端实现内部接口(不对外,只给 crash_handler.cpp 用)
//
// 每个 backend_*.cpp 实现对应的一对函数;未编译的后端由 backend_stub.cpp
// 提供空实现,保证链接通过。
#ifndef BPLC_CRASH_BACKEND_H
#define BPLC_CRASH_BACKEND_H

#include "crash_handler.h"

#include <string>

std::string backend_sentry_install(const CrashHandler::Options& opts);
std::string backend_crashpad_install(const CrashHandler::Options& opts);
void backend_sentry_shutdown();
void backend_crashpad_shutdown();
// SIGABRT 兜底(abort()/Qt qFatal 触发 SIGABRT → 抓上下文落 dump);仅 crashpad 后端。
void backend_crashpad_install_abort_hook();
// 手动 dump(Qt qFatal 钩子用);仅 crashpad 后端。
void backend_crashpad_dump_without_crash();

#endif  // BPLC_CRASH_BACKEND_H
