QT += core network
CONFIG += c++17 console
CONFIG -= app_bundle
TARGET = mirror_probe
TEMPLATE = app
R = $$PWD/../../../src/app
INCLUDEPATH += $$R
HEADERS += $$R/updatemirror.h $$R/appconfig.h $$R/net_size_cap.h
SOURCES += main.cpp \
           $$R/updatemirror.cpp
