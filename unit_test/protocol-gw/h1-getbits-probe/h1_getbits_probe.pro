QT += core gui widgets
CONFIG += c++17 console
CONFIG -= app_bundle
TARGET = h1_getbits_probe
TEMPLATE = app
R = $$PWD/../../../src
INCLUDEPATH += $$R $$R/common $$R/protocol $$R/protocol/common \
               $$R/protocol/gw_protocol/gw_2026 $$R/protocol/gw_protocol/gw_2026/sof \
               $$R/protocol/gw_protocol/gw_2026/beacon $$R/protocol/gw_protocol/gw_2026/coord \
               $$R/protocol/gw_protocol/gw_2026/ack \
               $$R/protocol/gw_protocol/gw_2022 $$R/protocol/gw_protocol/gw_2022/sof \
               $$R/protocol/gw_protocol/gw_2022/beacon $$R/protocol/gw_protocol/gw_2022/coord \
               $$R/protocol/gw_protocol/gw_2022/ack $$R/ui \
               $$PWD/../../../3rdparty/qslog
SOURCES += main.cpp \
           $$R/protocol/gw_protocol/gw_2026/gw_2026_parser.cpp \
           $$R/protocol/gw_protocol/gw_2026/sof/gw_2026_sof_parser.cpp \
           $$R/protocol/gw_protocol/gw_2026/beacon/gw_2026_beacon_parser.cpp \
           $$R/protocol/gw_protocol/gw_2026/coord/gw_2026_coord_parser.cpp \
           $$R/protocol/gw_protocol/gw_2026/ack/gw_2026_ack_parser.cpp \
           $$R/protocol/gw_protocol/gw_2026/gw_2026_msdu_parser.cpp \
           $$R/protocol/gw_protocol/gw_2026/gw_2026_tree.cpp \
           $$R/protocol/gw_protocol/gw_2026/gw_2026_provider.cpp \
           $$R/protocol/gw_protocol/gw_2022/gw_2022_parser.cpp \
           $$R/protocol/gw_protocol/gw_2022/sof/gw_2022_sof_parser.cpp \
           $$R/protocol/gw_protocol/gw_2022/beacon/gw_2022_beacon_parser.cpp \
           $$R/protocol/gw_protocol/gw_2022/coord/gw_2022_coord_parser.cpp \
           $$R/protocol/gw_protocol/gw_2022/ack/gw_2022_ack_parser.cpp \
           $$R/protocol/gw_protocol/gw_2022/gw_2022_msdu_parser.cpp \
           $$R/protocol/protocolfactory.cpp \
           $$R/protocol/protocol_tree_builder.cpp \
           $$R/ui/protocoltree.cpp \
           $$R/common/i18n.cpp \
           $$PWD/../../../3rdparty/qslog/QsLog.cpp \
           $$PWD/../../../3rdparty/qslog/QsLogDest.cpp \
           $$PWD/../../../3rdparty/qslog/QsLogDestConsole.cpp \
           $$PWD/../../../3rdparty/qslog/QsLogDestFile.cpp \
           $$PWD/../../../3rdparty/qslog/QsLogDestFunctor.cpp
include($$R/protocol/nw_protocol/nw_2026/nw_2026.pri)
include($$R/protocol/nw_protocol/nw_2021/nw_2021.pri)  # nw_2026_parser 委托 nw_2021_parser
HEADERS += $$R/ui/protocoltree.h \
           $$PWD/../../../3rdparty/qslog/QsLog.h \
           $$PWD/../../../3rdparty/qslog/QsLogDest.h \
           $$PWD/../../../3rdparty/qslog/QsLogDestConsole.h \
           $$PWD/../../../3rdparty/qslog/QsLogDestFile.h \
           $$PWD/../../../3rdparty/qslog/QsLogDestFunctor.h \
           $$PWD/../../../3rdparty/qslog/QsLogLevel.h
!isEmpty(SANITIZERS) {
    QMAKE_CXXFLAGS += -fsanitize=$$SANITIZERS -fno-omit-frame-pointer
    QMAKE_LFLAGS += -fsanitize=$$SANITIZERS
}
