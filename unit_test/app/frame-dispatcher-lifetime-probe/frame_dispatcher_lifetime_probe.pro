# FrameDispatcher 生命周期回归(77b89dc):shutdown() 提前 quit 线程后再析构,
# 旧实现 worker 已被 deleteLater、析构再调 request_stop 即释放后使用。
# 建议以 ASan 构建运行: qmake CONFIG+=sanitizer CONFIG+=sanitize_address
QT       += core gui widgets serialport
CONFIG   += c++17 console
CONFIG   -= app_bundle
TARGET    = frame_dispatcher_lifetime_probe
TEMPLATE  = app

REPO = $$PWD/../../..
INCLUDEPATH += $$REPO/src $$REPO/src/app $$REPO/src/common $$REPO/src/io $$REPO/src/protocol $$REPO/src/protocol/common $$REPO/3rdparty/qslog
include($$REPO/3rdparty/qslog/QsLog.pri)
include($$REPO/src/protocol/protocol.pri)

SOURCES += frame_dispatcher_lifetime_probe.cpp \
           $$REPO/src/app/framedispatcher.cpp \
           $$REPO/src/common/i18n.cpp
HEADERS += $$REPO/src/app/framedispatcher.h
