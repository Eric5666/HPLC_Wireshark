QT += core gui widgets concurrent
CONFIG += console c++17
CONFIG -= app_bundle
TEMPLATE = app
TARGET = autofit_real_check
INCLUDEPATH += $$PWD/../../src/common $$PWD/../../src/ui
SOURCES += autofit_real_check.cpp $$PWD/../../src/ui/packetlistmodel.cpp
HEADERS += $$PWD/../../src/ui/packetlistmodel.h
