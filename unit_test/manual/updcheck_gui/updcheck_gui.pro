QT += core gui widgets network
CONFIG += c++17
CONFIG -= app_bundle
TARGET = updcheck_gui
TEMPLATE = app
include(../../../src/updater/updater.pri)
SOURCES += main.cpp
