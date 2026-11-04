QT = core gui widgets
CONFIG += console c++17
CONFIG -= app_bundle
TEMPLATE = app
TARGET = nw_frame_probe
REPO = $$PWD/../..
INCLUDEPATH += $$REPO/src $$REPO/src/protocol $$REPO/src/protocol/common
SOURCES += $$PWD/nw_frame_probe.cpp
include($$REPO/src/common/common.pri)
include($$REPO/src/protocol/nw_protocol/nw_2021/nw_2021.pri)
SOURCES += $$REPO/src/protocol/protocol_tree_builder.cpp
HEADERS += $$REPO/src/protocol/iprotocolparser.h \
           $$REPO/src/protocol/protocol_tree_builder.h
