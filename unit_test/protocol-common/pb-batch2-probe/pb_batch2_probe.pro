# 第 2 批修复回归探针(SPEC-batch2:OFDMA 多站状态 / TEI-MAC 反向索引)
QT += core gui widgets concurrent
CONFIG += console c++17
CONFIG -= app_bundle
TARGET = pb_batch2_probe
TEMPLATE = app

REPO = $$PWD/../../..
INCLUDEPATH += $$REPO/src $$REPO/src/common $$REPO/src/protocol \
               $$REPO/src/protocol/common \
               $$REPO/src/protocol/gw_protocol/gw_2022 \
               $$REPO/src/protocol/gw_protocol/gw_2022/sof \
               $$REPO/src/protocol/gw_protocol/gw_2022/beacon \
               $$REPO/src/protocol/gw_protocol/gw_2022/ack \
               $$REPO/src/protocol/gw_protocol/gw_2022/coord \
               $$REPO/src/protocol/gw_protocol/gw_2026 \
               $$REPO/src/protocol/gw_protocol/gw_2026/sof \
               $$REPO/src/protocol/gw_protocol/gw_2026/beacon \
               $$REPO/src/protocol/gw_protocol/gw_2026/ack \
               $$REPO/src/protocol/gw_protocol/gw_2026/coord \
               $$REPO/src/protocol/nw_protocol/nw_2021 \
               $$REPO/src/protocol/nw_protocol/nw_2026 \
               $$REPO/src/ui $$REPO/src/topo \
               $$REPO/3rdparty/qslog
DEFINES += QsLog_STATIC

HEADERS += $$REPO/src/ui/packetlistmodel.h \
    $$REPO/3rdparty/qslog/QsLog.h \
    $$REPO/3rdparty/qslog/QsLogDest.h \
    $$REPO/3rdparty/qslog/QsLogDestFile.h \
    $$REPO/3rdparty/qslog/QsLogDestFunctor.h \
    $$REPO/3rdparty/qslog/QsLogDestConsole.h

SOURCES += pb_batch2_probe.cpp \
    $$REPO/src/ui/packetlistmodel.cpp \
    $$REPO/src/protocol/protocol_tree_builder.cpp \
    $$REPO/src/protocol/gw_protocol/gw_2026/gw_2026_parser.cpp \
    $$REPO/src/protocol/gw_protocol/gw_2026/gw_2026_msdu_parser.cpp \
    $$REPO/src/protocol/gw_protocol/gw_2026/beacon/gw_2026_beacon_parser.cpp \
    $$REPO/src/protocol/gw_protocol/gw_2026/sof/gw_2026_sof_parser.cpp \
    $$REPO/src/protocol/gw_protocol/gw_2026/ack/gw_2026_ack_parser.cpp \
    $$REPO/src/protocol/gw_protocol/gw_2026/coord/gw_2026_coord_parser.cpp \
    $$REPO/src/protocol/gw_protocol/gw_2026/gw_2026_tree.cpp \
    $$REPO/src/protocol/gw_protocol/gw_2022/gw_2022_parser.cpp \
    $$REPO/src/protocol/gw_protocol/gw_2022/gw_2022_msdu_parser.cpp \
    $$REPO/src/protocol/gw_protocol/gw_2022/beacon/gw_2022_beacon_parser.cpp \
    $$REPO/src/protocol/gw_protocol/gw_2022/sof/gw_2022_sof_parser.cpp \
    $$REPO/src/protocol/gw_protocol/gw_2022/ack/gw_2022_ack_parser.cpp \
    $$REPO/src/protocol/gw_protocol/gw_2022/coord/gw_2022_coord_parser.cpp \
    $$REPO/src/protocol/gw_protocol/gw_2022/gw_2022_tree.cpp \
    $$REPO/src/protocol/nw_protocol/nw_2026/nw_2026_parser.cpp \
    $$REPO/src/protocol/nw_protocol/nw_2026/nw_2026_msdu_parser.cpp \
    $$REPO/src/protocol/nw_protocol/nw_2026/nw_2026_beacon_parser.cpp \
    $$REPO/src/protocol/nw_protocol/nw_2026/nw_2026_tree.cpp \
    $$REPO/src/protocol/nw_protocol/nw_2021/nw_2021_parser.cpp \
    $$REPO/src/protocol/nw_protocol/nw_2021/nw_2021_msdu_parser.cpp \
    $$REPO/src/protocol/nw_protocol/nw_2021/nw_2021_beacon_parser.cpp \
    $$REPO/src/protocol/nw_protocol/nw_2021/nw_2021_tree.cpp \
    $$REPO/src/common/i18n.cpp \
    $$REPO/3rdparty/qslog/QsLog.cpp \
    $$REPO/3rdparty/qslog/QsLogDest.cpp \
    $$REPO/3rdparty/qslog/QsLogDestConsole.cpp \
    $$REPO/3rdparty/qslog/QsLogDestFile.cpp \
    $$REPO/3rdparty/qslog/QsLogDestFunctor.cpp
