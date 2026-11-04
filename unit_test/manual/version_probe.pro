QT       += core gui serialport
CONFIG   += c++17 console
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets
CONFIG   -= app_bundle

TARGET = version_probe
TEMPLATE = app

INCLUDEPATH += $$PWD/../../src
INCLUDEPATH += $$PWD/../../3rdparty/qslog

# FunctorDestination 是 QObject(QsLogDest.cpp 引用),moc 需处理其头文件
HEADERS += ../../3rdparty/qslog/QsLogDestFunctor.h

# 与 headless_test 相同依赖:common + protocol(含 gw_2026/gw_2022 全部)
include($$PWD/../../src/common/common.pri)
include($$PWD/../../src/protocol/protocol.pri)

SOURCES += \
    version_probe.cpp \
    ../../3rdparty/qslog/QsLog.cpp \
    ../../3rdparty/qslog/QsLogDest.cpp \
    ../../3rdparty/qslog/QsLogDestConsole.cpp \
    ../../3rdparty/qslog/QsLogDestFile.cpp
