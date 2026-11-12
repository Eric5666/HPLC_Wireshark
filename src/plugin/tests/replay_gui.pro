QT += core gui widgets qml
CONFIG += c++17
CONFIG -= app_bundle
TARGET = replay_gui
TEMPLATE = app

INCLUDEPATH += $$PWD/.. $$PWD/../../common $$PWD/../../protocol $$PWD/../plugin_api $$PWD/../host

SOURCES += replay_gui_main.cpp \
    replay_gui.cpp \
    ../../common/i18n.cpp \
    ../host/js_backend.cpp \
    ../host/lua_backend.cpp \
    ../host/native_backend.cpp \
    ../host/plugin_backend.cpp \
    ../host/script_painter.cpp

HEADERS += replay_gui.h \
    ../host/plugin_backend.h \
    ../host/js_backend.h \
    ../host/lua_backend.h \
    ../host/native_backend.h \
    ../host/script_painter.h

# Lua 5.4.9 (bundled)
LUA_SRC = $$PWD/../../../3rdparty/lua-5.4.9/src
INCLUDEPATH += $$LUA_SRC
LIBS += $$LUA_SRC/liblua.a

# 本地持久 GL 开发链接(系统只有 libGL.so.1,缺 libGL.so)
LOCAL_LIB = $$HOME/workspace/build_deps/lib
exists($$LOCAL_LIB/libGL.so) {
    LIBS += -L$$LOCAL_LIB
}
