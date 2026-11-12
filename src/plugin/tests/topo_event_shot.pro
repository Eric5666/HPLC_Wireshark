QT += core gui qml
QT -= widgets
CONFIG += c++17 console
CONFIG -= app_bundle
TARGET = topo_event_shot
TEMPLATE = app

INCLUDEPATH += $$PWD/.. $$PWD/../../common $$PWD/../../protocol $$PWD/../plugin_api $$PWD/../host

SOURCES += topo_event_shot.cpp \
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
LUA_SRC = $$PWD/../../../3rdparty/lua-5.4.9/src
INCLUDEPATH += $$LUA_SRC
LIBS += $$LUA_SRC/liblua.a

# 节点图标(与主程序 TopoWindow 同源),供 ScriptPainter::draw_icon
RESOURCES += ../host/plugin_icons.qrc
