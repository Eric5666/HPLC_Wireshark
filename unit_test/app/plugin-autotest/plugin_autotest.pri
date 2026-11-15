# plugin_autotest.pri - 插件自动化截图测试(测试侧,不进产品构建)
#
# 用法:qmake BPLC_STA_Monitor.pro CONFIG+=plugin_autotest
#       ./BPLC_STA_Monitor --replay <bin> --plugin-autotest <shot_dir> [--plugins-dir <dir>]
# 回放结束后给各插件面板及主窗口截图,保存到 shot_dir 后退出。
# 未加 CONFIG+=plugin_autotest 时主程序忽略 --plugin-autotest(仅告警)。

DEFINES += BPLC_PLUGIN_AUTOTEST

HEADERS += \
    $$PWD/plugin_autotest.h

SOURCES += \
    $$PWD/plugin_autotest.cpp

INCLUDEPATH += $$PWD
