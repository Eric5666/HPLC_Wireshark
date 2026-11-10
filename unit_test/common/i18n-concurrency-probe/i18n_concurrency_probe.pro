# i18n 并发探针(M6):解析线程并发 trl::L 查找时 GUI 线程运行期 register_en 不崩溃、不读错
# CONFIG+=tsan 时用 ThreadSanitizer 构建
QT = core
CONFIG += console c++17
CONFIG -= app_bundle
TARGET = i18n_concurrency_probe
TEMPLATE = app

REPO = $$PWD/../../..
INCLUDEPATH += $$REPO/src/common
SOURCES += i18n_concurrency_probe.cpp $$REPO/src/common/i18n.cpp
tsan {
    QMAKE_CXXFLAGS += -fsanitize=thread -g -O1
    QMAKE_LFLAGS += -fsanitize=thread
}
