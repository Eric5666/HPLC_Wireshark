/// @file plugin_ipc.h
/// @brief 插件 IPC 协议定义(主程序 ↔ bplc-plugin-host)
/// @details 传输:QLocalSocket;帧格式:[quint32 总长][quint8 消息类型][QDataStream 载荷]
///          QDataStream 版本固定为 Qt_6_5,保证主程序与 host 一致。
#ifndef BPLC_PLUGIN_IPC_H
#define BPLC_PLUGIN_IPC_H

#include <QByteArray>
#include <QCoreApplication>
#include <QDataStream>
#include <QString>
#include <QtGlobal>

namespace plugin_ipc {

/// @brief 插件 API 版本(主程序与 host 握手时校验,不一致则拒绝)
constexpr int kApiVersion = 1;

/// @brief IPC 载荷序列化格式版本(plugin_serialization 的 QDataStream 算子布局)
/// @details 与 kApiVersion 分开:kApiVersion 是插件清单声明的 API 级别,本项
///          只约束 app↔host 之间的载荷布局。布局变更必须升版,握手时随
///          Hello 一并校验,不一致则拒绝连接——不做跨版本布局兼容,避免
///          新旧两端按不同布局静默错位反序列化。
///          v1:旧布局(MsduInfo 无 route_hops_left、ParseResult 无 protocol)
///          v2:MsduInfo 增 route_hops_left、ParseResult 增 protocol
///          v3:三线合流并集,MpduInfo 增 pb_num_field(GW 线载波块数/无线大小码)
///          v4:MpduInfo 增 beacon_rsv(信标保留原始值)
///          v5:MpduInfo 增 pblen(南网无线载荷PB大小索引)
///          v6:MpduInfo 增 mcs(无线 MCS)
///          v7:ParseResult 增 dissect_fields(插件通用字段树);MpduInfo 删死字段
///             pb_index/coord_option/ack_search_freq
constexpr int kWireFormatVersion = 7;

/// @brief QDataStream 序列化版本(双方必须一致)
constexpr int kStreamVersion = QDataStream::Qt_6_5;

/// @brief IPC 消息类型
enum class MsgType : quint8 {
    Hello = 1,          ///< host→app: {api_version:int, plugin_id:QString}
    HelloAck = 2,       ///< app→host: {ok:bool, reason:QString}
    ParseRequest = 10,  ///< app→host: {seq:quint64, frame:BplcFrame, msdu:MsduState, filter:ParseFilter}
    ParseResponse = 11, ///< host→app: {seq:quint64, result:ParseResult, msdu:MsduState}
    Ping = 20,          ///< app→host: {seq:quint64} 心跳
    Pong = 21,          ///< host→app: {seq:quint64}
    Shutdown = 30,      ///< app→host: 优雅退出
    Error = 40,         ///< host→app: {seq:quint64, message:QString} 解析异常等
    // 图形插件(Phase3)
    RenderRequest = 50,  ///< app→host: {seq:quint64, width:int, height:int} 请求重绘
    RenderResponse = 51, ///< host→app: {seq:quint64, ok:bool, image:QImage} 图片(PNG 压缩字节经 QDataStream)
    GraphicsEventMsg = 52, ///< app→host: {seq:quint64, event:GraphicsEvent} 鼠标/滚轮/缩放
    EventAck = 53,       ///< host→app: {seq:quint64, needs_redraw:bool}
    RequestRedraw = 54,  ///< host→app: {} 插件主动请求重绘(如动画/数据更新)
};

/// @brief 单帧上限(类型字节 + 载荷),超过视为协议错误
/// @details 帧头长度来自对端进程,不可信。上限按最大图形帧(PNG 压缩 QImage)留足余量。
constexpr qint64 kMaxIpcFrame = 16 * 1024 * 1024;

/// @brief try_take_frame 的结果
enum class FrameTake {
    Ok,        ///< 取出一帧,out 为 [type][payload]
    NeedMore,  ///< 数据不足,等待更多字节
    Bad,       ///< 帧长为 0 或超过 kMaxIpcFrame:调用方必须断开连接
};

/// @brief 从接收缓冲取出一帧 [quint32 len][len 字节]
/// @details 主程序与 host 共用。长度统一按 qint64 比较,避免 4 + len 回绕。
/// @param buf 接收缓冲,成功时移除已取出的字节
/// @param out 输出帧(不含长度头)
/// @return 见 FrameTake
inline FrameTake try_take_frame(QByteArray& buf, QByteArray& out) {
    if (buf.size() < 4) return FrameTake::NeedMore;
    const auto* p = reinterpret_cast<const uchar*>(buf.constData());
    const qint64 len = (qint64(p[0]) << 24) | (qint64(p[1]) << 16) |
                       (qint64(p[2]) << 8) | qint64(p[3]);   // QDataStream 大端
    if (len < 1 || len > kMaxIpcFrame) return FrameTake::Bad;
    if (qint64(buf.size()) < 4 + len) return FrameTake::NeedMore;
    out = buf.mid(4, qsizetype(len));
    buf.remove(0, qsizetype(4 + len));
    return FrameTake::Ok;
}

/// @brief 本机 socket 名(主程序按插件 id 生成唯一名)
/// @param plugin_id 插件 id
inline QString socketName(const QString& plugin_id) {
    return QStringLiteral("bplc_plugin_%1_%2")
        .arg(plugin_id)
        .arg(QCoreApplication::applicationPid());
}

} // namespace plugin_ipc

#endif // BPLC_PLUGIN_IPC_H
