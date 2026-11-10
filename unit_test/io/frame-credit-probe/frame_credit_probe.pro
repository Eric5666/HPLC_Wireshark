# 帧流背压探针(M7):FrameCredit 在途上限、中止不死锁、reset/disable 解除阻塞;
# 以及 ReaderWorker 回放在消费者慢时被限流、stop 能打断阻塞的 Reader
QT       += core serialport
QT       -= gui
CONFIG   += c++17 console
CONFIG   -= app_bundle
TARGET    = frame_credit_probe
TEMPLATE  = app

REPO = $$PWD/../../..
DEFINES += BPLC_REPO_DIR=\\\"$$REPO\\\"
INCLUDEPATH += $$REPO/src/common $$REPO/src/io

include($$REPO/3rdparty/qslog/QsLog.pri)
include($$REPO/src/common/common.pri)

SOURCES += frame_credit_probe.cpp \
           $$REPO/src/io/serialreader.cpp
HEADERS += $$REPO/src/io/serialreader.h $$REPO/src/io/frame_credit.h
