# common.pri - 公共数据结构 + 中/英显示翻译
#
# 模块内文件:
#   - bplcframe.h    帧/元信息/条目定义
#   - i18n.h/.cpp    运行时中文/英文显示翻译(L()/register_en)
#   - mac_format.h   48-bit MAC u64 格式化唯一实现(四处旧拷贝委托于此)
#
# 依赖:QtCore(QByteArray/QString/QDateTime)

HEADERS += \
    $$PWD/bplcframe.h \
    $$PWD/mac_format.h \
    $$PWD/i18n.h

SOURCES += \
    $$PWD/i18n.cpp

INCLUDEPATH += $$PWD
