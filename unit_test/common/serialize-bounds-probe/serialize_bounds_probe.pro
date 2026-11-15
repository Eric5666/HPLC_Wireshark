# 盘块反序列化边界探针(L8):损坏计数/过深嵌套/截断/随机变异不触发巨量分配或栈溢出
QT = core
CONFIG += console c++17
CONFIG -= app_bundle
TARGET = serialize_bounds_probe
TEMPLATE = app

REPO = $$PWD/../../..
INCLUDEPATH += $$REPO/src/common
SOURCES += serialize_bounds_probe.cpp
