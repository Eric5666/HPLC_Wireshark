QT = core gui widgets
CONFIG += console c++17
CONFIG -= app_bundle
TEMPLATE = app
TARGET = nw_mme_test
REPO = $$PWD/../../..
INCLUDEPATH += $$REPO/src/common $$REPO/src/protocol $$REPO/src/protocol/nw_protocol/nw_2021 $$REPO/3rdparty/qslog
isEmpty(PARSER): PARSER = $$REPO/src/protocol/nw_protocol/nw_2021/nw_2021_msdu_parser.cpp
SOURCES += $$PWD/nw_mme_test.cpp $$PARSER $$REPO/src/common/i18n.cpp \
           $$REPO/src/protocol/protocol_tree_builder.cpp \
           $$REPO/3rdparty/qslog/QsLog.cpp \
           $$REPO/3rdparty/qslog/QsLogDest.cpp \
           $$REPO/3rdparty/qslog/QsLogDestConsole.cpp \
           $$REPO/3rdparty/qslog/QsLogDestFile.cpp \
           $$REPO/3rdparty/qslog/QsLogDestFunctor.cpp
HEADERS += $$REPO/3rdparty/qslog/QsLogDestFunctor.h
!isEmpty(SANITIZERS) {
    QMAKE_CXXFLAGS += -fsanitize=$$SANITIZERS -fno-omit-frame-pointer
    QMAKE_LFLAGS += -fsanitize=$$SANITIZERS
}
