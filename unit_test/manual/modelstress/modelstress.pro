QT       += core gui widgets concurrent
CONFIG   += c++17 console
CONFIG   -= app_bundle
TARGET    = modelstress
TEMPLATE  = app

INCLUDEPATH += $$PWD/../../../src/common \
               $$PWD/../../../src/ui

HEADERS += $$PWD/../../../src/ui/packetlistmodel.h
SOURCES += $$PWD/modelstress.cpp \
           $$PWD/../../../src/ui/packetlistmodel.cpp
