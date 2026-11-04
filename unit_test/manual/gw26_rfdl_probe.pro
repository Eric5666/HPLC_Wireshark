QT = core
CONFIG += console c++17
CONFIG -= app_bundle
TEMPLATE = app
TARGET = gw26_rfdl_probe
REPO = $$PWD/../..
INCLUDEPATH += $$REPO/src $$REPO/src/protocol $$REPO/src/protocol/common $$REPO/src/protocol/gw_protocol/gw_2026 $$REPO/3rdparty/qslog
SOURCES += $$PWD/gw26_rfdl_probe.cpp \
           $$REPO/src/protocol/gw_protocol/gw_2026/gw_2026_msdu_parser.cpp \
           $$REPO/3rdparty/qslog/QsLog.cpp \
           $$REPO/3rdparty/qslog/QsLogDest.cpp \
           $$REPO/3rdparty/qslog/QsLogDestConsole.cpp \
           $$REPO/3rdparty/qslog/QsLogDestFile.cpp \
           $$REPO/3rdparty/qslog/QsLogDestFunctor.cpp
HEADERS += $$REPO/src/common/bplcframe.h \
           $$REPO/src/protocol/gw_protocol/gw_2026/gw_2026_msdu_parser.h \
           $$REPO/3rdparty/qslog/QsLogDestFunctor.h
include($$REPO/src/common/common.pri)
include($$REPO/src/protocol/common/common.pri)
