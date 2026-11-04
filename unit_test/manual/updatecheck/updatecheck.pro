# updatecheck 端到端验证:检查更新 → 自动确认 → 下载(离屏)
QT += core gui widgets network
CONFIG += c++17 console
CONFIG -= app_bundle

TARGET = updatecheck
TEMPLATE = app

include(../../../src/updater/updater.pri)

SOURCES += updatecheck.cpp
