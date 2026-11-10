# app.pri - 应用层:主窗口 + 配置对话框 + 帧分发器
#
# 模块内文件:
#   - mainwindow.h/.cpp            QMainWindow + 三栏组装
#   - commconfigdialog.h/.cpp     通讯口设置对话框
#   - framedispatcher.h/.cpp      解析线程 + 统计 + 跨模块编排
#
# 依赖:common, protocol, io, ui(全模块)

HEADERS += \
    $$PWD/mainwindow.h \
    $$PWD/commconfigdialog.h \
    $$PWD/framedispatcher.h \
    $$PWD/appconfig.h \
    $$PWD/updatemirror.h \
    $$PWD/net_size_cap.h \
    $$PWD/theme.h

SOURCES += \
    $$PWD/mainwindow.cpp \
    $$PWD/commconfigdialog.cpp \
    $$PWD/framedispatcher.cpp \
    $$PWD/updatemirror.cpp \
    $$PWD/theme.cpp

# QDarkStyleSheet 深色主题资源(MIT,见 qdarkstyle/LICENSE.rst)
RESOURCES += $$PWD/qdarkstyle/darkstyle.qrc

INCLUDEPATH += $$PWD
