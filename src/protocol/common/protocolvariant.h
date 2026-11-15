/// @file protocolvariant.h
/// @brief 协议变体枚举(国网/南网 × 版本),贯穿解析/展示/序列化
/// @details 命名规范:协议缩写(大写)+ 版本年份。
///   - GW_2022:国网双模标准 2022(202203),现单协议栈
///   - NW_2021:南网双模 2021 报批版
/// @note 未来协议升级 = 新增枚举值 + 对应 *_YYYY 实现目录。
#ifndef BPLC_PROTOCOLVARIANT_H
#define BPLC_PROTOCOLVARIANT_H

/// @brief 协议变体(协议 + 版本)。取值命名遵循 <协议缩写>_<版本年份>。
enum class ProtocolVariant {
    GW_2022,   ///< 国网双模标准 2022(202203) HDC 1.0协议
    NW_2021,   ///< 南网双模 2021 报批版 BPLC协议
    GW_2026,   ///< 国网双模 2026(下一代,全面兼容旧) HDC 2.0协议
    NW_2026    ///< 南网 SPLC协议 2026(下一代,全面兼容旧)
};

#endif  // BPLC_PROTOCOLVARIANT_H
