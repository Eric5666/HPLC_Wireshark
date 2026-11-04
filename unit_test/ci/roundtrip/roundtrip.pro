QT       += core serialport
QT       -= gui
CONFIG   += c++17 console
CONFIG   -= app_bundle
TARGET    = roundtrip
TEMPLATE  = app

INCLUDEPATH += $$PWD/../../../src/common \
               $$PWD/../../../src/io

include($$PWD/../../../3rdparty/qslog/QsLog.pri)
include($$PWD/../../../src/common/common.pri)

SOURCES += $$PWD/roundtrip.cpp \
           $$PWD/../../../src/io/serialreader.cpp
HEADERS += $$PWD/../../../src/io/serialreader.h
