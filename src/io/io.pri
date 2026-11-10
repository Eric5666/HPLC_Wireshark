# io.pri - 数据源:串口/文件回放/裸 hex 导入
#
# 模块内文件:
#   - serialreader.h/.cpp        ReaderWorker + SerialReader(线程化包装)
#   - rawframeimporter.h/.cpp   裸 hex 文件一次性预读(备用)
#
# 依赖:common(bplcframe.h, ringbuffer.h), QtSerialPort

QT += serialport

HEADERS += \
    $$PWD/serialreader.h \
    $$PWD/frame_credit.h \
    $$PWD/rawframeimporter.h

SOURCES += \
    $$PWD/serialreader.cpp \
    $$PWD/rawframeimporter.cpp

INCLUDEPATH += $$PWD
