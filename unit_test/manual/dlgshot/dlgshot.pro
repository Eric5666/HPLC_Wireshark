QT += core gui widgets serialport
CONFIG += c++17 console
CONFIG -= app_bundle
TARGET = dlgshot
TEMPLATE = app

INCLUDEPATH += ../../../src \
               ../../../src/app \
               ../../../src/common \
               ../../../src/io

# commconfigdialog 依赖:ReaderConfig(bplcframe.h)/i18n/appconfig/theme
SOURCES += dlgshot.cpp \
           ../../../src/app/commconfigdialog.cpp \
           ../../../src/app/theme.cpp \
           ../../../src/common/i18n.cpp

HEADERS += ../../../src/app/commconfigdialog.h

RESOURCES += ../../../src/app/qdarkstyle/darkstyle.qrc \
