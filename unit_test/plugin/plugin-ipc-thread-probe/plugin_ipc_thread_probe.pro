# PluginManager 跨线程 IPC 回归探针(H6):worker 线程连续 parse_via_plugin,
# GUI 线程同时跑事件循环(readyRead/心跳)与图形请求,响应不得被串读/丢失
QT += core gui widgets network
CONFIG += console c++17
CONFIG -= app_bundle
TARGET = plugin_ipc_thread_probe
TEMPLATE = app

REPO = $$PWD/../../..
DEFINES += BPLC_REPO_DIR=\\\"$$REPO\\\"
INCLUDEPATH += $$REPO/src $$REPO/src/common $$REPO/src/protocol $$REPO/src/protocol/common
include($$REPO/src/plugin/plugin.pri)

SOURCES += plugin_ipc_thread_probe.cpp \
    $$REPO/src/protocol/protocolfactory.cpp
HEADERS += $$REPO/src/protocol/protocolfactory.h
