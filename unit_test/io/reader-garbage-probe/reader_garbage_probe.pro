# 回放切帧性能/中止探针(M5):无 0x3C 的大段垃圾必须线性时间丢弃,stop() 能在块内打断
QT       += core serialport
QT       -= gui
CONFIG   += c++17 console
CONFIG   -= app_bundle
TARGET    = reader_garbage_probe
TEMPLATE  = app

REPO = $$PWD/../../..
DEFINES += BPLC_REPO_DIR=\\\"$$REPO\\\"
INCLUDEPATH += $$REPO/src/common $$REPO/src/io

include($$REPO/3rdparty/qslog/QsLog.pri)
include($$REPO/src/common/common.pri)

SOURCES += reader_garbage_probe.cpp \
           $$REPO/src/io/serialreader.cpp
HEADERS += $$REPO/src/io/serialreader.h
