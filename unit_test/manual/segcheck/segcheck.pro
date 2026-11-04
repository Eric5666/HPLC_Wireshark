QT       += core
CONFIG   += c++17 console
CONFIG   -= app_bundle
TARGET    = segcheck
TEMPLATE  = app

INCLUDEPATH += $$PWD/../../../src/common \
               $$PWD/../../../src/io

SOURCES += $$PWD/segcheck.cpp
