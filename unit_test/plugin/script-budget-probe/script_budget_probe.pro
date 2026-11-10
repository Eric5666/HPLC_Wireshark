# M10 脚本执行预算探针:Lua 死循环被指令预算打断、JS 死循环被看门狗打断
QT += core gui qml
QT -= widgets
CONFIG += console c++17
CONFIG -= app_bundle
TARGET = script_budget_probe
TEMPLATE = app

REPO = $$PWD/../../..
DEFINES += BPLC_REPO_DIR=\\\"$$REPO\\\"
INCLUDEPATH += $$REPO/src/plugin $$REPO/src/common $$REPO/src/protocol \
               $$REPO/src/plugin/plugin_api $$REPO/src/plugin/host

SOURCES += script_budget_probe.cpp \
    $$REPO/src/plugin/host/lua_backend.cpp \
    $$REPO/src/plugin/host/js_backend.cpp \
    $$REPO/src/plugin/host/native_backend.cpp \
    $$REPO/src/plugin/host/plugin_backend.cpp \
    $$REPO/src/plugin/host/script_painter.cpp

HEADERS += $$REPO/src/plugin/host/plugin_backend.h \
    $$REPO/src/plugin/host/lua_backend.h \
    $$REPO/src/plugin/host/js_backend.h \
    $$REPO/src/plugin/host/native_backend.h \
    $$REPO/src/plugin/host/script_painter.h

# Lua 5.4.6(内嵌,缺失时自动获取/构建)
include($$REPO/src/plugin/lua_bundle.pri)
