QT       += core gui serialport
CONFIG   += c++17 console
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets
CONFIG   -= app_bundle
TARGET = zero_cross_unit_test
TEMPLATE = app
DEFINES += QT_DEPRECATED_WARNINGS
INCLUDEPATH += $$PWD/../../src
INCLUDEPATH += $$PWD/../../3rdparty/qslog
include($$PWD/../../src/common/common.pri)
include($$PWD/../../src/protocol/protocol.pri)
SOURCES += \
    zero_cross_unit_test.cpp \
    ../../3rdparty/qslog/QsLog.cpp \
    ../../3rdparty/qslog/QsLogDest.cpp \
    ../../3rdparty/qslog/QsLogDestConsole.cpp \
    ../../3rdparty/qslog/QsLogDestFile.cpp \
    ../../3rdparty/qslog/QsLogDestFunctor.cpp
HEADERS += \
    ../../src/common/bplcframe.h \
    ../../src/protocol/gw_protocol/gw_2022/gw_2022_parser.h \
    ../../src/protocol/statistics.h \
    ../../3rdparty/qslog/QsLogDestFunctor.h
