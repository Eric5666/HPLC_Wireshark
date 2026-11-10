# IPC 帧长上限回归探针(M1):plugin_ipc::try_take_frame 对非法/超大帧长必须拒绝且不死循环
QT = core
CONFIG += console c++17
CONFIG -= app_bundle
TARGET = ipc_frame_probe
TEMPLATE = app

REPO = $$PWD/../../..
INCLUDEPATH += $$REPO/src $$REPO/src/plugin
SOURCES += ipc_frame_probe.cpp
