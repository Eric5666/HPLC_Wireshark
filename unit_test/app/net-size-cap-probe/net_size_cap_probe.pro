# 下载大小上限探针(CVE-2026-116337 缓解):netcap::cap_reply_size 对超大/无限/gzip 膨胀响应必须 abort
QT = core network
CONFIG += console c++17
CONFIG -= app_bundle
TARGET = net_size_cap_probe
TEMPLATE = app

REPO = $$PWD/../../..
INCLUDEPATH += $$REPO/src/app
HEADERS += $$REPO/src/app/net_size_cap.h
SOURCES += net_size_cap_probe.cpp
LIBS += -lz
