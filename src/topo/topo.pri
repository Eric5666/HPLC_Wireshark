# topo.pri - 拓扑模块(独立窗口:拓扑图 + 路由变更表 + TEI→MAC 表)
#
# Topology service/model/replay/storage are independent from MainWindow; the window
# consumes value snapshots and update signals. Frame-to-topology normalization lives here too.
#
# 模块内文件:
#   - topo_state.h/.cpp     单 NID 拓扑状态(节点/路由/事件历史)
#   - topo_window.h/.cpp    独立窗口 + 层次拓扑图 + 两张表

HEADERS += \
    $$PWD/topo_state.h \
    $$PWD/topo_input.h \
    $$PWD/topo_window.h \
    $$PWD/topo_worker.h \
    $$PWD/topo_controller.h

SOURCES += \
    $$PWD/topo_state.cpp \
    $$PWD/topo_input.cpp \
    $$PWD/topo_window.cpp \
    $$PWD/topo_worker.cpp \
    $$PWD/topo_controller.cpp

INCLUDEPATH += $$PWD
