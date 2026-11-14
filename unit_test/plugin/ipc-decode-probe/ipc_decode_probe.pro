# 插件 IPC 反序列化防护回归探针(M2 + Qt 容器计数):主程序解码插件宿主发来的
# ParseResponse 时,字段树深度/节点数、所有容器计数都须受限,损坏响应 ⇒ 停用插件
QT += core gui widgets network
CONFIG += console c++17
CONFIG -= app_bundle
TARGET = ipc_decode_probe
TEMPLATE = app

REPO = $$PWD/../../..
DEFINES += BPLC_REPO_DIR=\\\"$$REPO\\\"
INCLUDEPATH += $$REPO/src $$REPO/src/plugin $$REPO/src/common $$REPO/src/protocol $$REPO/src/protocol/common
include($$REPO/src/plugin/plugin.pri)

SOURCES += ipc_decode_probe.cpp \
    $$REPO/src/protocol/protocolfactory.cpp
HEADERS += $$REPO/src/protocol/protocolfactory.h
