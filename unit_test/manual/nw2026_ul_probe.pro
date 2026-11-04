QT = core gui widgets
CONFIG += console c++17
CONFIG -= app_bundle
TEMPLATE = app
TARGET = nw2026_ul_probe
REPO = $$PWD/../..
INCLUDEPATH += $$REPO/src $$REPO/src/protocol $$REPO/src/protocol/common $$REPO/3rdparty/qslog
SOURCES += $$PWD/nw2026_ul_probe.cpp \
           $$REPO/3rdparty/qslog/QsLog.cpp \
           $$REPO/3rdparty/qslog/QsLogDest.cpp \
           $$REPO/3rdparty/qslog/QsLogDestConsole.cpp \
           $$REPO/3rdparty/qslog/QsLogDestFile.cpp \
           $$REPO/3rdparty/qslog/QsLogDestFunctor.cpp
include($$REPO/src/common/common.pri)
include($$REPO/src/protocol/nw_protocol/nw_2021/nw_2021.pri)
include($$REPO/src/protocol/nw_protocol/nw_2026/nw_2026.pri)
SOURCES += $$REPO/src/protocol/protocol_tree_builder.cpp \
           $$REPO/src/protocol/protocolfactory.cpp
HEADERS += $$REPO/src/protocol/iprotocolparser.h \
           $$REPO/src/protocol/protocol_tree_builder.h \
           $$REPO/3rdparty/qslog/QsLogDestFunctor.h
