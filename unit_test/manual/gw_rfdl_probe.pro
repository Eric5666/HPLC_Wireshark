QT = core
CONFIG += console c++17
CONFIG -= app_bundle
TEMPLATE = app
TARGET = gw_rfdl_probe
REPO = $$PWD/../..
INCLUDEPATH += $$REPO/src $$REPO/src/protocol $$REPO/src/protocol/common $$REPO/src/protocol/gw_protocol/gw_2022
SOURCES += $$PWD/gw_rfdl_probe.cpp \
           $$REPO/src/protocol/gw_protocol/gw_2022/gw_2022_msdu_parser.cpp
HEADERS += $$REPO/src/common/bplcframe.h \
           $$REPO/src/protocol/gw_protocol/gw_2022/gw_2022_msdu_parser.h
include($$REPO/src/common/common.pri)
include($$REPO/src/protocol/common/common.pri)
