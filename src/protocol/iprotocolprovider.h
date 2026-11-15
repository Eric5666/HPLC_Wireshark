/// @file iprotocolprovider.h
/// @brief 协议提供者抽象:一个协议(内置或插件)对自身的完整描述
/// @details 注册表只认本接口,界面/工厂/分派层都不再硬编码协议名:
///          - 协议下拉框由 id + display_name_zh/en + order 生成(顺序也由协议自述);
///          - make_parser_by_id(按 id) / make_tree_builder(按 variant) 查本表;
///          - 插件实现同一接口即可同时提供"解析器 + 字段树 + 显示名"。
///          内置协议在各自 <proto>_provider.cpp 里静态自注册(见各协议目录)。
#ifndef BPLC_IPROTOCOLPROVIDER_H
#define BPLC_IPROTOCOLPROVIDER_H

#include "common/protocolvariant.h"
#include <QString>
#include <memory>

class IProtocolParser;
class IProtocolTreeBuilder;

/// @brief 协议提供者(注册表条目)
class IProtocolProvider {
public:
    virtual ~IProtocolProvider() = default;

    /// @brief 唯一 id(大写,如 "GW_2026");也是 config.ini general/protocol 键的大写形式
    virtual QString id() const = 0;
    /// @brief 界面显示名(中文/英文);英文缺省回退中文
    virtual QString display_name_zh() const = 0;
    virtual QString display_name_en() const { return display_name_zh(); }
    /// @brief 界面排序(小在前):内置 10/20/30/40,插件缺省 200
    virtual int order() const { return 200; }
    /// @brief 本协议对应的变体(帧协议身份 / 字段树分派键)
    virtual ProtocolVariant variant() const = 0;

    /// @brief 创建解析器实例(调用方拥有所有权)
    virtual std::unique_ptr<IProtocolParser> create_parser() const = 0;
    /// @brief 创建字段树构建器实例;返回 nullptr = 不提供(界面只显示公共节点)
    /// @note 插件协议产出的字段树走 ParseResult.msdu.tree(MsduFieldNode),
    ///       不构造 QTreeWidget,因此插件一般返回 nullptr。
    virtual std::unique_ptr<IProtocolTreeBuilder> create_tree_builder() const = 0;
};

#endif  // BPLC_IPROTOCOLPROVIDER_H
