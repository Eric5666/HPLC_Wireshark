# 插件市场安全回归探针(H2 插件名路径穿越 / H3 zip 解包;市场安装不做 sha256 校验)
QT += core network
QT -= gui
CONFIG += console c++17
CONFIG -= app_bundle
TARGET = market_safety_probe
TEMPLATE = app

REPO = $$PWD/../../..
INCLUDEPATH += $$REPO/src/plugin/market $$REPO/src/plugin/plugin_api \
               $$REPO/src/app $$REPO/src/common $$REPO/3rdparty/miniz

SOURCES += market_safety_probe.cpp \
    $$REPO/src/plugin/market/plugin_market.cpp \
    $$REPO/src/app/updatemirror.cpp \
    $$REPO/src/common/i18n.cpp \
    $$REPO/3rdparty/miniz/miniz.c \
    $$REPO/3rdparty/miniz/miniz_tdef.c \
    $$REPO/3rdparty/miniz/miniz_tinfl.c \
    $$REPO/3rdparty/miniz/miniz_zip.c

HEADERS += $$REPO/src/plugin/market/plugin_market.h \
    $$REPO/src/app/updatemirror.h $$REPO/src/app/appconfig.h
