// crash_util.h - 内部小工具(无 Qt 依赖)
#ifndef BPLC_CRASH_UTIL_H
#define BPLC_CRASH_UTIL_H

#include <string>

namespace crash_util {

// 当前可执行文件所在目录(末尾不带分隔符)。失败返回空串。
std::string exe_dir();

// 确保目录存在(递归创建)。成功返回 true。
bool ensure_dir(const std::string& path);

// 路径拼接
std::string join(const std::string& a, const std::string& b);

// Sentry DSN "http(s)://<key>@<host>[:port]/<project>" 派生 minidump 上报地址
// "http(s)://<host>[:port]/api/<project>/minidump/?sentry_key=<key>"。
// DSN 格式不对返回空串(调用方视为不上报)。
std::string sentry_dsn_to_minidump_url(const std::string& dsn);

} // namespace crash_util

#endif  // BPLC_CRASH_UTIL_H
