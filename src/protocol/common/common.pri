# common.pri - 协议公共工具(位域/CRC/BCD/字段树/协议变体)
#
# 模块内文件(协议无关,国网/南网共用,永远不变):
#   - protocolvariant.h  协议变体枚举(GW_2022 / NW_2021)
#   - fieldtools.h       位域取值/设置 + hex/MAC 格式化
#   - crc.h              CRC32 / CRC24
#   - bcd.h              BCD 编解码
#   - fieldspec.h        字段树构建工具(FieldSpec/add_fields/group/annotate_unit)
#   - pb_assembler.h     多物理块(PB)组装(逐块 CRC24/块体提取/聚合级联拆分,header-only)
#   - nw_app_bid.h/.cpp  南网应用层业务标识(表9)/传输方向(表8)释义,nw_2021 与 nw_2026 共用

HEADERS += \
    $$PWD/protocolvariant.h \
    $$PWD/fieldtools.h \
    $$PWD/crc.h \
    $$PWD/bcd.h \
    $$PWD/fieldspec.h \
    $$PWD/pb_assembler.h \
    $$PWD/nw_app_bid.h \
    $$PWD/msdu_crc_state.h

INCLUDEPATH += $$PWD
