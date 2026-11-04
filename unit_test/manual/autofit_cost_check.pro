QT += core
QT -= gui
CONFIG += console c++17
CONFIG -= app_bundle
TEMPLATE = app
TARGET = autofit_cost_check
INCLUDEPATH += $$PWD/../../src/common
SOURCES += autofit_cost_check.cpp
