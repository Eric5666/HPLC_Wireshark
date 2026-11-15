# 盘块落盘竞态探针(M2/M3/M4):未就绪块读内存副本、过滤/导出快照不漏块、clear 后会话隔离、
# 异步过滤完成回调遵守 QAbstractItemModel 约定(QAbstractItemModelTester)
QT       += core gui widgets concurrent testlib
CONFIG   += c++17 console
CONFIG   -= app_bundle
TARGET    = paging_race_probe
TEMPLATE  = app

REPO = $$PWD/../../..
INCLUDEPATH += $$REPO/src/common $$REPO/src/ui $$REPO/src $$REPO/src/protocol
HEADERS += $$REPO/src/ui/packetlistmodel.h
SOURCES += paging_race_probe.cpp \
           $$REPO/src/common/i18n.cpp \
           $$REPO/src/ui/packetlistmodel.cpp
