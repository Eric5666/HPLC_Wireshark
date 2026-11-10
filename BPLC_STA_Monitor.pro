QT       += core gui serialport widgets concurrent sql
CONFIG   += c++17 \
           windows

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = BPLC_STA_Monitor
TEMPLATE = app

DEFINES += QT_DEPRECATED_WARNINGS
# 生产抓断言:release(QT_NO_DEBUG)下 Q_ASSERT 被编译掉,这里强制编译进来,
# 配合 crash 钩子把断言失败转成 minidump(2026-10-27 用户拍板)
DEFINES += QT_FORCE_ASSERTS

# 消除第三方库的编译警告(crashpad 头文件 unused-parameter / miniz.c type-limits)
QMAKE_CXXFLAGS += -Wno-unused-parameter
QMAKE_CFLAGS += -Wno-type-limits

# Windows 资源:exe 文件图标 + 程序版本信息
RC_ICONS = icons/app.ico
VERSION = 2.0.1
QMAKE_TARGET_PRODUCT = "BPLC STA Monitor"
QMAKE_TARGET_DESCRIPTION = "BPLC/HRF protocol STA frame monitor"
QMAKE_TARGET_COPYRIGHT = "Copyright (c) 2026 aron566"
RESOURCES += BPLC_STA_Monitor.qrc

# Qt 6.11 win32 GUI app 默认自动链接 libQt6EntryPoint,该库要求 qMain()
# 所以主函数用 qMain(名字)(没有 Qt 宏展开,真是函数符号名)

# 模块依赖顺序(从底层到顶层):
#   updater  <- 无依赖(第三方自包含,放在最前)
#   common  <- protocol, io
#   io      <- app
#   ui      <- app
#   protocol <- app
#   crash   <- 无依赖(纯 C++,与业务解耦;后端由 CONFIG+=crash_sentry/crash_crashpad 选择)
# 默认启用 crashpad 后端(本地落盘,无外部服务依赖)。
# 关闭默认: qmake "CONFIG+=crash_no_default";改用 sentry: qmake "CONFIG+=crash_no_default crash_sentry"。
# 注意:不能用 qmake "CONFIG-=crash_crashpad" 来关默认 —— 命令行 -= 在 .pro
# 求值前处理,删不掉下面这行默认加上的开关,crash.pri 的 contains() 照样看到它
# (2026-09-30 实测:CI 矩阵 none/sentry-only 组合因此实际编进了 crashpad)。
# 所以默认改用"可退出的默认":命令行 += 的标记在 .pro 求值时可见。
!contains(CONFIG, crash_no_default): CONFIG += crash_crashpad
# 崩溃后端需要符号化:按编译器保留调试信息,打包时分离符号
#   MinGW(g++): DWARF 内嵌 exe → 链接不 strip,打包存带符号 exe + addr2line 符号化
#   MSVC(cl):   PDB 独立文件 → /Zi 编译 + /DEBUG 链接产 PDB,打包 dump_syms 提取 .sym
CONFIG(crash_crashpad)|CONFIG(crash_sentry) {
    win32-msvc* {
        QMAKE_CXXFLAGS_RELEASE += /Zi
        QMAKE_CFLAGS_RELEASE += /Zi
        QMAKE_LFLAGS_RELEASE += /DEBUG
    }
    win32-g++ {
        QMAKE_CXXFLAGS_RELEASE += -g
        QMAKE_CFLAGS_RELEASE += -g
        # qmake release 默认 QMAKE_LFLAGS_RELEASE=-Wl,-s 会剥掉 DWARF,去掉它
        QMAKE_LFLAGS_RELEASE -= -Wl,-s
    }
    else:unix {
        # Linux:恢复 622fb9c 之前的行为,release 保留 -g 供 crashpad 符号化
        QMAKE_CXXFLAGS_RELEASE += -g
        QMAKE_CFLAGS_RELEASE += -g
    }
}
# QsLog 轻量日志库(3rdparty,文件轮转 + 调试输出)
include(3rdparty/qslog/QsLog.pri)
include(src/updater/updater.pri)
include(src/common/common.pri)
include(src/protocol/protocol.pri)
include(src/io/io.pri)
include(src/ui/ui.pri)
include(src/topo/topo.pri)
include(src/crash/crash.pri)
include(src/plugin/plugin.pri)
include(src/plugin/app_integration/app_integration.pri)
include(src/plugin/market/market.pri)
include(src/app/app.pri)

# main.cpp 在工程根目录,不在任何模块里
SOURCES += main.cpp
HEADERS +=
TARGET = BPLC_STA_Monitor  # 重置(模块里设置过)

qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
else: target.path = $$[QT_INSTALL_BINS]/$${TARGET}

!isEmpty(target.path): INSTALLS += target
