QT += core network
QT -= gui
CONFIG += c++17 console
CONFIG -= app_bundle
TARGET = market_test
TEMPLATE = app

INCLUDEPATH += $$PWD/../market $$PWD/../plugin_api $$PWD/../../app $$PWD/../../common $$PWD/../../../3rdparty/miniz

SOURCES += market_test.cpp \
    ../market/plugin_market.cpp \
    ../../app/updatemirror.cpp \
    ../../common/i18n.cpp \
    $$PWD/../../../3rdparty/miniz/miniz.c \
    $$PWD/../../../3rdparty/miniz/miniz_tdef.c \
    $$PWD/../../../3rdparty/miniz/miniz_tinfl.c \
    $$PWD/../../../3rdparty/miniz/miniz_zip.c

HEADERS += ../market/plugin_market.h ../../app/updatemirror.h ../../app/appconfig.h
