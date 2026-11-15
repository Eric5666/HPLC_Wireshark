QT += core network
CONFIG += c++17 console
CONFIG -= app_bundle
TARGET = mirror_probe_fb
TEMPLATE = app
# fb 变体:编译仓库里真实的 src/app/updatemirror.cpp(不再维护分叉副本),
# 只在编译期把前两个区域识别源指向不可达地址,强制走 ipwho.is 回退链路。
A = $$PWD/../../../../src/app
INCLUDEPATH += $$A
DEFINES += BPLC_MIRROR_TRACE_URL=\\\"https://invalid.example.com/trace\\\" \
           BPLC_MIRROR_COUNTRY_IS_URL=\\\"https://invalid.example.com/\\\"
HEADERS += $$A/updatemirror.h $$A/appconfig.h $$A/net_size_cap.h
SOURCES += $$PWD/../main.cpp $$A/updatemirror.cpp
