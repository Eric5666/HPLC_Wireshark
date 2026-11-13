# updater.pri — 自包含第三方更新检查模块(QSimpleUpdater,上游源码原样)
#
# 来源:  https://github.com/alex-spataru/QSimpleUpdater  (MIT License)
# 说明:  Qt6 兼容的"检查更新"库:内置 JSON 更新清单解析 + 下载器 +
#        AuthenticateDialog/Downloader 两个 .ui 对话框。文件保持上游原貌,
#        不做本地风格改造;许可副本见本目录 LICENSE.md。
# 同步基线:上游 master e474328(2026-10-16);本地补丁——
#        Updater.cpp 的 clipped_changelog 裁剪、downloadUrl 镜像前缀、
#        update.json 1 MB 上限;Downloader 的 sha256 校验与 512 MB 安装包上限
#        (均有「本地修改/local extension」标注,同步时按标注重打)。
#
# 用法:  #include "QSimpleUpdater.h"
#        updater()->setModuleVersion("app", appVersion);
#        updater()->setUpdateURL("app", "https://your-host/update.json");
#        updater()->checkForUpdates();
#        更新清单 JSON 格式参见上游 README(按平台分节的 "updates" 对象)。

QT += network

# QSU_INCLUDE_MOC=1:.cpp 末尾内联 #include "moc_*.cpp"，moc 符号直接编进对应 .o。
# 头文件保留在 HEADERS 以触发 moc 生成；实测干净构建无重复定义
# （64daf01 担心的重复问题未在干净构建复现）。
INCLUDEPATH += $$PWD/include

DEFINES += QSU_INCLUDE_MOC=1

SOURCES += \
    $$PWD/QSimpleUpdater.cpp \
    $$PWD/Updater.cpp \
    $$PWD/Downloader.cpp \
    $$PWD/AuthenticateDialog.cpp

HEADERS += \
    $$PWD/include/QSimpleUpdater.h \
    $$PWD/Updater.h \
    $$PWD/Downloader.h \
    $$PWD/update_integrity.h \
    $$PWD/AuthenticateDialog.h

FORMS += \
    $$PWD/Downloader.ui \
    $$PWD/AuthenticateDialog.ui

RESOURCES += $$PWD/resources/qsimpleupdater.qrc
