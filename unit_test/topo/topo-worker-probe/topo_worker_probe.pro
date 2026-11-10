QT += core sql
QT -= gui
CONFIG += console c++17
CONFIG -= app_bundle
TEMPLATE = app
TARGET = topo_worker_probe

REPO_ROOT = $$clean_path($$PWD/../../..)
INCLUDEPATH += \
    $$REPO_ROOT/src/common \
    $$REPO_ROOT/src/protocol/common \
    $$REPO_ROOT/src/topo \
    $$REPO_ROOT/3rdparty/qslog

SOURCES += \
    main.cpp \
    $$REPO_ROOT/src/topo/topo_state.cpp \
    $$REPO_ROOT/src/topo/topo_worker.cpp \
    $$REPO_ROOT/src/topo/topo_input.cpp \
    $$REPO_ROOT/src/topo/topo_controller.cpp \
    $$REPO_ROOT/src/common/i18n.cpp \
    $$REPO_ROOT/3rdparty/qslog/QsLog.cpp \
    $$REPO_ROOT/3rdparty/qslog/QsLogDest.cpp \
    $$REPO_ROOT/3rdparty/qslog/QsLogDestConsole.cpp \
    $$REPO_ROOT/3rdparty/qslog/QsLogDestFile.cpp \
    $$REPO_ROOT/3rdparty/qslog/QsLogDestFunctor.cpp

HEADERS += \
    $$REPO_ROOT/src/topo/topo_state.h \
    $$REPO_ROOT/src/topo/topo_worker.h \
    $$REPO_ROOT/src/topo/topo_input.h \
    $$REPO_ROOT/src/topo/topo_controller.h \
    $$REPO_ROOT/3rdparty/qslog/QsLogDestFunctor.h
