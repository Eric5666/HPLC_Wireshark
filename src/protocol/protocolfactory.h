/// @file protocolfactory.h
/// @brief 协议注册表:协议提供者(解析器 + 字段树 + 显示名)的登记与实例化
/// @details 一个 "协议" 由 IProtocolProvider 自描述(见 iprotocolprovider.h):
///          内置四协议在各自 <proto>_provider.cpp 静态自注册;插件协议由
///          PluginManager 在握手成功后注册(显示名取自 plugin.json)。
///            - make_parser_by_id   :按协议 id 取解析器(插件经 IPC 代理)
///            - make_tree_builder   :按变体取字段树构建器(声明在 protocol_tree_builder.h)
///            - registered_protocols:界面枚举协议(按 order 升序,顺序由协议自述)
#ifndef BPLC_PROTOCOLFACTORY_H
#define BPLC_PROTOCOLFACTORY_H

#include "iprotocolparser.h"
#include "iprotocolprovider.h"

#include <QVector>
#include <functional>
#include <memory>

/// @brief 解析器工厂函数(只需提供解析器的场景,如插件)
using ParserFactoryFn = std::function<std::unique_ptr<IProtocolParser>()>;

/// @brief 协议提供者指针(注册表快照;可安全跨调用持有,注销后对象仍有效)
using ProtocolProviderPtr = std::shared_ptr<IProtocolProvider>;

/// @brief 注册协议(同 id 重复注册时后者覆盖前者)
void register_protocol(ProtocolProviderPtr provider);
/// @brief 注销协议(插件卸载时调用)
void unregister_protocol(const QString& protocol_id);

/// @brief 已注册协议快照(按 order 升序,同 order 按 id)
QVector<ProtocolProviderPtr> registered_protocols();
/// @brief 按 id 查协议(大小写不敏感);未注册返回空
ProtocolProviderPtr find_protocol(const QString& protocol_id);
/// @brief 已注册协议 id 列表(大写)
QStringList registered_protocol_ids();

/// @brief 按协议 id 实例化解析器。返回 nullptr = 未知协议。
std::unique_ptr<IProtocolParser> make_parser_by_id(const QString& protocol_id);

// ── 插件便捷接口:只提供解析器(插件侧不构造 QTreeWidget,故无字段树构建器) ──
/// @brief 注册"仅解析器"的协议;display_zh/en 用于界面协议列表
void register_parser_provider(const QString& protocol_id,
                              const QString& display_zh,
                              const QString& display_en,
                              ParserFactoryFn fn,
                              int order = 200);
/// @brief 兼容旧接口:显示名回退为协议 id
void register_parser(const QString& protocol_id, ParserFactoryFn fn);
/// @brief 兼容旧接口:同 unregister_protocol
void unregister_parser(const QString& protocol_id);

#endif  // BPLC_PROTOCOLFACTORY_H
