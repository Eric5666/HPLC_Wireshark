QT       += core gui widgets concurrent
CONFIG   += c++17 console
CONFIG   -= app_bundle

TARGET = tree_dispatch_check
TEMPLATE = app

DEFINES += QT_DEPRECATED_WARNINGS

INCLUDEPATH += $$PWD/../../src
INCLUDEPATH += $$PWD/../../src/ui
INCLUDEPATH += $$PWD/../../3rdparty/qslog

# ProtocolTree 依赖 protocol(工厂/构建器)+ common;不含 io/app(无主程序)
include($$PWD/../../src/common/common.pri)
include($$PWD/../../src/protocol/protocol.pri)

SOURCES += \
    tree_dispatch_check.cpp \
    ../../src/ui/protocoltree.cpp \
    ../../src/ui/packetlistmodel.cpp \
    ../../3rdparty/qslog/QsLog.cpp \
    ../../3rdparty/qslog/QsLogDest.cpp \
    ../../3rdparty/qslog/QsLogDestConsole.cpp \
    ../../3rdparty/qslog/QsLogDestFile.cpp \
    ../../3rdparty/qslog/QsLogDestFunctor.cpp

HEADERS += \
    ../../src/common/bplcframe.h \
    ../../src/ui/protocoltree.h \
    ../../src/ui/packetlistmodel.h \
    ../../3rdparty/qslog/QsLogDestFunctor.h
