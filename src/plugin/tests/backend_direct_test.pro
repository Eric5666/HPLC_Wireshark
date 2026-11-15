QT += core gui qml
QT -= widgets
CONFIG += c++17 console
CONFIG -= app_bundle
TARGET = backend_direct_test
TEMPLATE = app

INCLUDEPATH += $$PWD/.. $$PWD/../../common $$PWD/../../protocol $$PWD/../plugin_api $$PWD/../host

SOURCES += backend_direct_test.cpp \
    ../host/js_backend.cpp \
    ../host/lua_backend.cpp \
    ../host/native_backend.cpp \
    ../host/plugin_backend.cpp \
    ../host/script_painter.cpp

HEADERS += ../host/plugin_backend.h \
    ../host/js_backend.h \
    ../host/lua_backend.h \
    ../host/native_backend.h \
    ../host/script_painter.h

# Lua 5.4.9 (bundled)
# Lua 5.4.9(内嵌,缺失时自动获取/构建,与 bplc-plugin-host 同源)
include(../lua_bundle.pri)
