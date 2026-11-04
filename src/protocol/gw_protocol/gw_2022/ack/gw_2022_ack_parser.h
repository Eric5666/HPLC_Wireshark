/// @file ackparser.h
/// @brief ACK 帧解析模块声明(选择确认帧:FCH ExtFrameType 0=选择确认,其他=保留)
/// @details 按表25/表36,扩展帧类型仅 0=选择确认帧,其余为保留;无网络搜索/同步/切频分支。
#ifndef GW_2022_ACKPARSER_H
#define GW_2022_ACKPARSER_H

#include "bplcframe.h"

namespace gw_2022_ackp {

/// @brief 解析 ACK 帧 FCH 字段(相对 FCH 起点;ExtFrameType 于 bit(12,0,4))
/// @param p  MPDU 数据指针(自 FrameType 起)
/// @param m  [out] 填充 ack_ext_type 及对应分支字段
void parse_fch(const quint8* p, MpduInfo& m);

}  // namespace gw_2022_ackp

#endif // GW_2022_ACKPARSER_H
