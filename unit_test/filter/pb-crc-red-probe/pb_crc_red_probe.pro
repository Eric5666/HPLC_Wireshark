# pb-crc-red-probe:PB 块 CRC 失败时 NW/GW 解析 + 标红口径回归(用户 2026-11 裁决)
QT += core gui widgets concurrent
CONFIG += c++17 console
CONFIG -= app_bundle
TEMPLATE = app
TARGET = pb_crc_red_probe
win32: QMAKE_LFLAGS += -mconsole

R = $$clean_path($$PWD/../../..)
DEFINES += REPO_ROOT=\\\"$$R\\\"
INCLUDEPATH += $$R/src $$R/src/common $$R/src/io $$R/src/ui $$R/src/protocol $$R/src/protocol/common \
               $$R/src/protocol/nw_protocol/nw_2021 $$R/src/protocol/nw_protocol/nw_2026 \
               $$R/src/protocol/gw_protocol/gw_2022 $$R/src/protocol/gw_protocol/gw_2022/beacon \
               $$R/src/protocol/gw_protocol/gw_2022/sof $$R/src/protocol/gw_protocol/gw_2022/coord \
               $$R/src/protocol/gw_protocol/gw_2022/ack $$R/src/protocol/gw_protocol/gw_2026 \
               $$R/src/protocol/gw_protocol/gw_2026/beacon $$R/src/protocol/gw_protocol/gw_2026/sof \
               $$R/src/protocol/gw_protocol/gw_2026/coord $$R/src/protocol/gw_protocol/gw_2026/ack \
               $$R/3rdparty/qslog
HEADERS += $$R/src/ui/packetlistmodel.h $$R/3rdparty/qslog/QsLogDestFunctor.h
SOURCES += pb_crc_red_probe.cpp \
           $$files($$R/src/protocol/nw_protocol/nw_2021/*.cpp) \
           $$files($$R/src/protocol/nw_protocol/nw_2026/*.cpp) \
           $$files($$R/src/protocol/gw_protocol/gw_2022/*.cpp) \
           $$files($$R/src/protocol/gw_protocol/gw_2022/beacon/*.cpp) \
           $$files($$R/src/protocol/gw_protocol/gw_2022/sof/*.cpp) \
           $$files($$R/src/protocol/gw_protocol/gw_2022/ack/*.cpp) \
           $$files($$R/src/protocol/gw_protocol/gw_2022/coord/*.cpp) \
           $$files($$R/src/protocol/gw_protocol/gw_2026/*.cpp) \
           $$files($$R/src/protocol/gw_protocol/gw_2026/beacon/*.cpp) \
           $$files($$R/src/protocol/gw_protocol/gw_2026/sof/*.cpp) \
           $$files($$R/src/protocol/gw_protocol/gw_2026/ack/*.cpp) \
           $$files($$R/src/protocol/gw_protocol/gw_2026/coord/*.cpp) \
           $$R/src/protocol/protocol_tree_builder.cpp \
           $$R/src/protocol/protocolfactory.cpp \
           $$R/src/ui/packetlistmodel.cpp \
           $$R/src/common/i18n.cpp \
           $$R/3rdparty/qslog/QsLog.cpp $$R/3rdparty/qslog/QsLogDest.cpp $$R/3rdparty/qslog/QsLogDestConsole.cpp \
           $$R/3rdparty/qslog/QsLogDestFile.cpp $$R/3rdparty/qslog/QsLogDestFunctor.cpp
