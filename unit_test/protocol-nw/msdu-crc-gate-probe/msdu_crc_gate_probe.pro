QT += core gui widgets concurrent
CONFIG += c++17 console
CONFIG -= app_bundle
CONFIG -= windows
QMAKE_LFLAGS += -mconsole
TEMPLATE = app
TARGET = msdu_crc_gate_probe

R = $$PWD/../../..
INCLUDEPATH += $$R/src $$R/src/common $$R/src/io $$R/src/ui $$R/src/protocol $$R/src/protocol/common \
               $$R/src/protocol/nw_protocol/nw_2021 $$R/src/protocol/nw_protocol/nw_2026 \
               $$R/src/protocol/gw_protocol/gw_2022 $$R/src/protocol/gw_protocol/gw_2022/beacon \
               $$R/src/protocol/gw_protocol/gw_2022/sof $$R/src/protocol/gw_protocol/gw_2022/coord \
               $$R/src/protocol/gw_protocol/gw_2022/ack $$R/src/protocol/gw_protocol/gw_2026 \
               $$R/src/protocol/gw_protocol/gw_2026/beacon $$R/src/protocol/gw_protocol/gw_2026/sof \
               $$R/src/protocol/gw_protocol/gw_2026/coord $$R/src/protocol/gw_protocol/gw_2026/ack \
               $$R/3rdparty/qslog

DEFINES += FIXTURE_PATH=\\\"$$R/unit_test/frames/frame-probe/nw_log_tail_pb_crc_fail.bin\\\" \
           GW_FIXTURE_PATH=\\\"$$R/unit_test/frames/frame-probe/gw2026_ofdma_sim.bin\\\" \
           WIRE_FIXTURE=\\\"$$R/unit_test/frames/frame-probe/nw_log_tail_wire_escaped.bin\\\"
HEADERS += $$R/src/ui/packetlistmodel.h \
           $$R/3rdparty/qslog/QsLogDestFunctor.h

SOURCES += msdu_crc_gate_probe.cpp \
           $$R/src/protocol/nw_protocol/nw_2021/nw_2021_parser.cpp \
           $$R/src/protocol/nw_protocol/nw_2021/nw_2021_msdu_parser.cpp \
           $$R/src/protocol/nw_protocol/nw_2021/nw_2021_beacon_parser.cpp \
           $$R/src/protocol/nw_protocol/nw_2026/nw_2026_parser.cpp \
           $$R/src/protocol/nw_protocol/nw_2026/nw_2026_msdu_parser.cpp \
           $$R/src/protocol/nw_protocol/nw_2026/nw_2026_beacon_parser.cpp \
           $$R/src/protocol/gw_protocol/gw_2026/gw_2026_parser.cpp \
           $$R/src/protocol/gw_protocol/gw_2026/gw_2026_msdu_parser.cpp \
           $$R/src/protocol/gw_protocol/gw_2026/gw_2026_tree.cpp \
           $$R/src/protocol/gw_protocol/gw_2026/beacon/gw_2026_beacon_parser.cpp \
           $$R/src/protocol/gw_protocol/gw_2026/sof/gw_2026_sof_parser.cpp \
           $$R/src/protocol/gw_protocol/gw_2026/coord/gw_2026_coord_parser.cpp \
           $$R/src/protocol/gw_protocol/gw_2026/ack/gw_2026_ack_parser.cpp \
           $$R/src/protocol/gw_protocol/gw_2022/gw_2022_parser.cpp \
           $$R/src/protocol/gw_protocol/gw_2022/gw_2022_msdu_parser.cpp \
           $$R/src/protocol/gw_protocol/gw_2022/gw_2022_tree.cpp \
           $$R/src/protocol/gw_protocol/gw_2022/beacon/gw_2022_beacon_parser.cpp \
           $$R/src/protocol/gw_protocol/gw_2022/sof/gw_2022_sof_parser.cpp \
           $$R/src/protocol/gw_protocol/gw_2022/coord/gw_2022_coord_parser.cpp \
           $$R/src/protocol/gw_protocol/gw_2022/ack/gw_2022_ack_parser.cpp \
           $$R/src/protocol/protocol_tree_builder.cpp \
           $$R/src/ui/packetlistmodel.cpp \
           $$R/src/common/i18n.cpp \
           $$R/3rdparty/qslog/QsLog.cpp \
           $$R/3rdparty/qslog/QsLogDest.cpp \
           $$R/3rdparty/qslog/QsLogDestConsole.cpp \
           $$R/3rdparty/qslog/QsLogDestFile.cpp \
           $$R/3rdparty/qslog/QsLogDestFunctor.cpp \
           $$R/3rdparty/qslog/QsLogDestFunctor.h
