# 插件入口包含检查 + 更新清单缺 sha256 回退探针
QT += core gui qml
QT -= widgets
CONFIG += console c++17
CONFIG -= app_bundle
TARGET = entry_containment_probe
TEMPLATE = app

REPO = $$PWD/../../..
INCLUDEPATH += $$REPO/src/plugin $$REPO/src/common $$REPO/src/protocol \
               $$REPO/src/plugin/plugin_api $$REPO/src/plugin/host $$REPO/src/updater

SOURCES += entry_containment_probe.cpp \
    $$REPO/src/plugin/host/lua_backend.cpp \
    $$REPO/src/plugin/host/js_backend.cpp \
    $$REPO/src/plugin/host/native_backend.cpp \
    $$REPO/src/plugin/host/plugin_backend.cpp \
    $$REPO/src/plugin/host/script_painter.cpp

HEADERS += $$REPO/src/plugin/host/plugin_backend.h \
    $$REPO/src/plugin/host/lua_backend.h \
    $$REPO/src/plugin/host/js_backend.h \
    $$REPO/src/plugin/host/native_backend.h \
    $$REPO/src/plugin/host/script_painter.h \
    $$REPO/src/updater/update_integrity.h

# Lua 5.4.9(内嵌,缺失时自动获取/构建)
include($$REPO/src/plugin/lua_bundle.pri)
