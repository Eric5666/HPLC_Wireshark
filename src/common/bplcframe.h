/// @file bplcframe.h
/// @brief BPLC/HPLC+HRF 上位机协议帧的基础数据结构定义
/// @details 本文件定义三块内容:
///   - PhysicalMeta:从物理层剥头后提取的元信息(时间戳/信道/媒介等)
///   - BplcFrame:一帧经哨兵切分+反转义后的完整载荷(送入解析器)
///   - MpduInfo:MPDU 控制头解析结果(展示层用)
///   - PacketEntry:Wireshark 风格 PacketList 的一行条目
/// @note 不依赖 Qt MOC,可被非 Qt 模块 include
/// @author BPLC_STA_QtMonitor
/// @date 2026-09-05
#ifndef BPLC_BPLCFRAME_H
#define BPLC_BPLCFRAME_H

#include <climits>
#include <QByteArray>
#include <QDateTime>
#include <QPair>
#include <QString>
#include <QStringList>
#include <QVector>

#include "mac_format.h"  // 48-bit MAC 格式化唯一实现(同目录)

/// 链路类型取值:南网 SPLC-4 表79 / BPLC-2 表160;国网 HDC1.0 表61、表72 / HDC2.0 表56、表58 含义列
/// —— 两家定义完全一致(0=高速载波链路 1=无线链路),故置于 common 层共用
enum LinkTypeValue : quint8 {
    LinkTypeHplc    = 0,    ///< 高速载波链路
    LinkTypeRf      = 1,    ///< 无线链路
    LinkTypeUnknown = 0xFF, ///< 未定(⚠️ 本机约定,非协议值:该域仅 1bit,协议只可能 0/1)
};

/// TEI 相关常量(12bit 域)
constexpr quint16 kTeiCco       = 1;      ///< CCO 的 TEI(南网「TEI固定为1」/ HDC2.0 5.3.3.1 同)
constexpr quint16 kTeiBroadcast = 0xFFF;  ///< 广播报文 TEI(南网「广播报文TEI为0xFFF」/ HDC2.0 5.3.3.1 同)
constexpr quint16 kTeiInvalid   = 0xFFFF; ///< 无效/未分配(⚠️ 本机哨兵,超出 12bit 域,协议无此值)
/// 重启次数无效(协议 4bit 域 0-15;0xFF 为本机哨兵,非协议值)
constexpr quint8  kRestartCountInvalid = 0xFF;
/// 非管理消息(non-MMe)的 mme_type 标记(本机约定;MMe 类型域 16bit)
constexpr quint16 kMMeTypeNone         = 0xFFFF;

/// @brief MSDU 跨帧重组状态(SOF 多 PB 块)
struct MsduState {
    QByteArray buffer;
    int        received_count;
    int        expected_len;
    bool       complete;
    int        reasm_proto;   ///< 在途分片所属代际(-1 无;0=HDC1.0 委托;1=HDC2.0 原生):
                              ///< 代际切换时清缓冲,防止 1.0/2.0 分片混拼出一个坏 MSDU

    MsduState() : received_count(0), expected_len(0), complete(false), reasm_proto(-1) {}
};

/// @brief 物理层元信息
struct PhysicalMeta {
    quint32  timestamp;       ///< STA 端 NTB 同步计数,25 kHz tick(40 µs/tick)
    quint8   phr_mcs;         ///< HRF 物理头速率(PLC 帧此字段为占位 0)
    quint8   option;          ///< HRF option(1=1M/2=500k/3=200k;PLC 占位)
    quint16  channel;         ///< HRF:信道索引;PLC:频段号(0-3)
    bool     is_rf;           ///< false=PLC 载波;true=HRF 无线
    bool     has_time_tag;    ///< 是否携带 8 字节 BCD 时间标签(has_time_tag=1)
    QDateTime frame_time;     ///< 帧时间(BCD 解码或 PC 本地时间)
    qint64    epoch_ms;       ///< frame_time 的 epoch ms 缓存(热路径避免 toMSecsSinceEpoch 时区转换)
    qint64    local_rx_ms;    ///< reader 成帧完成时取的本地 wall clock(epoch ms),
                              ///< 供解析器回退显示时间用;不序列化,仅内存透传
                              ///< (解析线程收到时若为 0 则回退现取)
    bool     from_raw;        ///< 是否为裸 hex 文本导入(无哨兵封装)
    bool     frame_ts_is_ntb; ///< ts 域为 NTB tick(实时串口;25kHz,40µs);
                              ///< false=文件回放(ts=epoch ms 低 32 位,毫秒级)
    bool     seg_start;       ///< 仅实时串口:新采集段首帧(Delta 不计算)
    bool     replay_time_tag; ///< 仅文件回放:本帧前有原文件的 BCD/TIME 标注

    PhysicalMeta()
        : timestamp(0), phr_mcs(0), option(0), channel(0),
          is_rf(false), has_time_tag(false), epoch_ms(0), local_rx_ms(0),
          from_raw(false), frame_ts_is_ntb(false), seg_start(false), replay_time_tag(false) {}
};

/// @brief 一帧完整载荷(经哨兵切分 + 0x3D 反转义后),完整定义见 TopoEvent 之后
struct BplcFrame;

/// @brief 多站点 PB 分组（GW_2026 OFDMA 表10/11、TDA 表12/13）
/// @details 单站点数据帧(表7)不走此结构，仍用 MpduInfo 的 pb_num/pb_size/平铺 pb_heads。
struct SofStationPb {
    quint16 tei        = 0;   ///< 该目的站点 TEI（表10 (5,4,12) / 表11/13 各站 TEI）
    quint8  copy_mode  = 0;   ///< 分集拷贝模式原始值（5bit；表10 (11,3,5) / 表11 (2,0,5) / 表13 (3,0,5)）
    quint8  pb_num     = 0;   ///< 该站点 PB 个数（OFDMA 1-2，表10 (11,2,1)/表11 (2,5,1)；TDA 恒 1）
    quint16 pb_size    = 0;   ///< 每块字节数（OFDMA 72/136，5.2.5.7；TDA 按 TMI 表）
    int     block_base = 0;   ///< 该站点首块在 raw 中的偏移
    QVector<quint8> pb_heads;   ///< 各块头字节（国网 PB 头 1B：bit7=END bit6=START 低6位=seq）
    QVector<bool>   pb_crc_oks; ///< 各块 CRC24 结果
    QByteArray      msdu;       ///< 该站点重组 MSDU（首块 START 到末块 END）
};

/// @brief MPDU 控制头解析结果(展示层使用)
struct MpduInfo {
    quint8  frame_type;    ///< 定界符类型:0=BEACON 1=SOF 2=ACK 3=COORD 5=SEARCH 6=SWITCH
    quint8  net_type;      ///< 网络类型(0/1)
    quint32 net_id;        ///< 24-bit 网络标识
    quint8  version;       ///< 标准版本号(0/1)
    quint16 src_tei;       ///< 源 TEI(BEACON/SOF/ACK 解析后)
    quint16 dst_tei;       ///< 目的 TEI(SOF/ACK 解析后)
    quint8  link_id;       ///< SOF 链路标识符(8-bit)
    quint16 frame_len;     ///< 帧长(12-bit,SOF;载波表19 ×10µs / 无线表30 ×100µs)
    quint8  pb_num;        ///< 生效物理块个数(SOF;载波=字段值 1-4,无线固定 1)
    quint8  pb_num_field;  ///< SOF 原始 PB 字段值:GW=字节9 bit4-7(载波块数表19/无线大小码表29);NW_2021 载波=字节7 bit0-3 线 PBNum(归一门覆盖 pb_num 前留存)
    quint8  pblen;         ///< 南网无线载荷PB大小索引(表130:0-5=16/40/72/136/264/520;载波/国网无效,填 0)
    quint8  mcs;           ///< 无线 MCS(国网表28 / 南网表129:0-6=分集/调制/码率;载波无此字段,填 0)
    quint16 symbol_num;    ///< 符号数 9-bit(载波 SOF 表19;无线 SOF 表30 该位段为保留,存原始值、不参与解析)
    bool    bc_flag;       ///< SOF 广播标志位
    bool    re_send_flag;  ///< SOF 重发标志位
    bool    encryp_flag;   ///< SOF 加密标志位
    quint8  tmi;           ///< SOF 字节11 bit4-7 原始值:载波=分集拷贝基本模式(表19)/无线=MCS(表28)
    quint8  tmi_ext;       ///< 分集拷贝扩展模式(载波 SOF 表19;无线 SOF 表30 该位段为保留,存原始值、不参与解析)
    quint16 pb_size;       ///< PB 块大小(载波=TMI查表 72/136/264/520;无线=载荷PB大小表29 16/40/72/136/264/520)
    bool    fch_crc_ok;    ///< 控制头 CRC24 校验结果
    bool    fch_crc_checked = false;  ///< FCH CRC24 是否真的校验过(false=未校验,不得据此标红/显示 FAIL)
    bool    pb_crc_ok;     ///< PB 块 CRC24 校验结果(SOF 时,全部块)
    quint8  pb_head;       ///< PB 头原始字节(bit7=END bit6=START 低6位=seq;SOF 时,首块)
    QVector<quint8> pb_heads;    ///< 各 PB 块头原始字节(按块序,SOF 时)
    QVector<bool>   pb_crc_oks;  ///< 各 PB 块 CRC24 校验结果(按块序,SOF 时)

    // ---- BEACON(帧内时间戳/相线)----
    quint32 beacon_timestamp; ///< 信标帧内时间戳 32-bit(b4..b7)
    quint8  beacon_line;      ///< 相线 2-bit(b11,1):0=Unknown 1=A 2=B 3=C
    quint16 beacon_rsv;       ///< 信标保留原始值(无线表27 (10,4,16) / 载波表17 (11,3,9);不参与解析)

    // ---- BEACON 载荷区(16B FCH 之后,经 PBSize 定位)----
    quint8  beacon_type;      ///< 信标类型 3-bit(载荷区 0,0):0=STA 1=PCO 2=CCO
    quint8  beacon_netsn;     ///< 组网序列号(载荷区 1,0,8)
    quint64 beacon_cco_mac;   ///< CCO MAC 48-bit(载荷区 2,0,48,帧序显示)
    quint32 beacon_period_cnt;///< 信标周期计数(载荷区 8,0,32)
    quint8  beacon_rf_channel;///< 无线信道号(载荷区 12,0,8)
    quint8  beacon_rf_option; ///< 无线 Option(载荷区 13,0,2;GW_2026 表38)
    quint8  beacon_mech_state;   ///< 信标机制状态 1-bit(GW_2026 表38 (13,2)):0=固定信标 1=竞争信标
    quint8  beacon_discover_en;  ///< 发现信标发送使能 1-bit(GW_2026 表38 (13,3)):0=未使能 1=使能
    int     beacon_item_num;  ///< 管理条目总数(载荷区 20 处 1B)

    // ---- GW_2026 SOF 载波新增字段(表7 数据帧可变区域;GW_2022 不填) ----
    // HDC 2.0 载波 SOF 重写:帧长后为 帧子类型/TF 描述/FCH 符号数/调制方式与参数/
    // 2b 编码 PB 个数/频段标识/增益/动态加载表ID;链路标识符移至 MAC 帧头 byte15。
    quint8  sof_data_type;    ///< SOF 帧子类型 3-bit(表7 (7,0,3)):0=数据帧 1=信道探测 2=OFDMA下行 3=TDA下行
    quint8  sof_tf_symbol_pos;///< TF符号位置 2-bit(表7 (7,3,2)):0=不携带TF 1=数据载荷之前 2=数据载荷之后
    quint8  sof_tf_symbol_num;///< TF符号数 3-bit(表7 (7,5,3)):1-5=4/6/8/10/12 符号,其他保留
    quint8  sof_fch_sym_num;  ///< FCH符号数 2-bit(表7 (9,7,2) 跨字节):0=短FCH 1=标准FCH 2=长FCH
    quint8  sof_mod_mode;     ///< 数据载荷调制方式标识 1-bit(表7 (10,1)):0=分集拷贝模式 1=动态加载模式
    quint8  sof_mod_param;    ///< 数据载荷调制参数 5-bit(表7 (10,2,5)):分集拷贝=XXX.41 TMI编号/动态加载=物理块类型(表8)
    quint8  sof_band;         ///< TF与数据载荷频段标识 3-bit(表7 (11,4,6),取值表49):0-2/4-6=频段,3/7=保留
    quint8  sof_gain;         ///< 数据载荷增益 4-bit(表7 (11,7)+(12,0-2)):1.0000-1.9375 增幅配置值
    quint8  sof_load_table_id;///< 动态加载表ID标识 1-bit(表7 (12,3))
    // ---- GW_2026 载波信标(表5)新增字段 ----
    quint8  beacon_fch_sym;   ///< 载波信标 FCH符号数 2-bit(表5 (11,3,2)):0=短FCH 1=标准FCH 2=长FCH
    // ---- GW_2026 ACK 载波(表14 选择确认不反馈SNR)新增字段 ----
    quint8  ack_bru_snr_flag; ///< BRU SNR 反馈标志 1-bit(表14 (4,0)):0=不反馈 1=反馈
    quint8  ack_sat_id_flag;  ///< SAT ID 正确标志 1-bit(表14 (4,1)):0=SAT ID正确/无需 1=SAT ID不正确
    quint8  ack_remain_sta_num; ///< 剩余站点数 2-bit(表14 (8,0,2)):0-3=0-3 个站点

    // ---- GW_2026 多站点 PB 分组(OFDMA 表10/11、TDA 表12/13) ----
    QVector<SofStationPb> sof_stations;   ///< 多站点帧的逐站点 PB 分组(空=单站点/数据帧/探测帧)

    // ---- COORD(网间协调帧)----
    quint16 coord_duration;   ///< 协调时隙占用时长 16-bit(ms)
    quint16 coord_shift;      ///< 下次时隙偏移 16-bit(ms)
    quint32 coord_neighbour_nid; ///< 邻居网络号 24-bit
    quint8  coord_rf_channel; ///< 无线信道号 8-bit(表26 本网络无线信道编号)
    quint8  coord_rsv0;       ///< 保留 4-bit(表26 字节12 bit0-3)
    quint16 coord_rsv1;       ///< 保留 10-bit(表26 字节4-5)
    quint8  coord_rsv2;       ///< 保留 1-bit(表26 字节7 bit0)
    quint8  coord_rsv3;       ///< 保留 4-bit(表26 字节7 bit4-7)
    // 南网 NW_2021 COORD 额外字段(国网填 0)
    quint8  coord_band_end_flag;    ///< 频段时隙结束标志 1-bit(南网)
    quint16 coord_band_end_offset;  ///< 频段时隙结束偏移 16-bit(南网,×4ms)
    quint16 coord_band_start_offset;///< 频段时隙开始偏移 16-bit(南网,×4ms)

    // ---- ACK 扩展帧类型(FCH byte12 bit0-3)----
    // 国网 GW_2022(表25/表36):0=选择确认帧,其余保留。
    // 南网 NW_2021(表21):0=选择确认帧,1=网络搜索帧(抄控器),2=同步帧(抄控器),其余保留。
    quint8  ack_ext_type;     ///< ACK 扩展类型
    quint8  ack_rx_res;       ///< RxRes 4-bit:0=接收成功(所有 PB CRC 通过) 1=接收失败(≥1 块 CRC 未过)
    quint8  ack_rx_status;    ///< RxStatus 4-bit:PB CRC 通过位图(bit i=第 i+1 块)
    quint8  ack_rx_pb_num;    ///< 接收 PB 数 3-bit
    quint8  ack_rsv0;         ///< RSV0 5-bit(8,3,5)
    quint8  ack_channel_quality; ///< 信道质量 8-bit(dB)
    quint8  ack_sta_load;     ///< STA 负载 8-bit
    quint8  ack_rsv1;         ///< RSV1 8-bit(11,0,8)
    quint64 ack_dst_addr;     ///< 目标 MAC 48-bit(南网 NW_2021 网络搜索帧)
    quint16 ack_search_tei;   ///< 网络搜索帧 STA TEI 12-bit(南网)
    quint32 ack_sync_timestamp; ///< 同步帧时间戳 32-bit(南网)
    quint16 ack_sync_tei;     ///< 同步帧 TEI 12-bit(南网)

    MpduInfo()
        : frame_type(0), net_type(0), net_id(0), version(0),
          src_tei(0), dst_tei(0), link_id(0), frame_len(0),
          pb_num(0), pb_num_field(0), pblen(0), mcs(0), symbol_num(0), bc_flag(false), re_send_flag(false),
          encryp_flag(false), tmi(0), tmi_ext(0), pb_size(0),
          fch_crc_ok(false), fch_crc_checked(false), pb_crc_ok(false), pb_head(0),
          beacon_timestamp(0), beacon_line(0), beacon_rsv(0),
          beacon_type(0), beacon_netsn(0), beacon_cco_mac(0),
          beacon_period_cnt(0), beacon_rf_channel(0), beacon_rf_option(0),
          beacon_mech_state(0), beacon_discover_en(0),
          beacon_item_num(0),
          sof_data_type(0), sof_tf_symbol_pos(0), sof_tf_symbol_num(0),
          sof_fch_sym_num(0), sof_mod_mode(0), sof_mod_param(0),
          sof_band(0), sof_gain(0), sof_load_table_id(0),
          beacon_fch_sym(0),
          ack_bru_snr_flag(0), ack_sat_id_flag(0), ack_remain_sta_num(0),
          coord_duration(0), coord_shift(0), coord_neighbour_nid(0),
          coord_rf_channel(0), coord_rsv0(0),
          coord_rsv1(0), coord_rsv2(0), coord_rsv3(0),
          coord_band_end_flag(0),
          coord_band_end_offset(0), coord_band_start_offset(0),
          ack_ext_type(0), ack_rx_res(0), ack_rx_status(0), ack_rx_pb_num(0),
          ack_rsv0(0), ack_channel_quality(0), ack_sta_load(0), ack_rsv1(0),
          ack_dst_addr(0),
          ack_search_tei(0),
          ack_sync_timestamp(0), ack_sync_tei(0) {}

    /// @brief 取 FrameType 对应的可读字符串
    QString frame_type_name() const {
        switch (frame_type) {
            case 0: return QStringLiteral("BEACON");
            case 1: return QStringLiteral("SOF");
            case 2: return QStringLiteral("ACK");
            case 3: return QStringLiteral("COORD");
            case 5: return QStringLiteral("SEARCH");
            case 6: return QStringLiteral("SWITCH");
            default: return QStringLiteral("UNKNOWN(%1)").arg(frame_type);
        }
    }
};

/// @brief 一个解析出的字段(层级节点;自递归树)
struct MsduFieldNode {
    QString       name;      ///< 字段名(含 [Nbit] 标注)
    QString       value;     ///< 值文本
    QVector<MsduFieldNode> children;  ///< 子字段(分组/数组条目)
    int           rel_start; ///< 相对 msdu_body 的起始字节(-1=无对应字节,如分组头)
    int           rel_len;   ///< 覆盖字节数

    MsduFieldNode() : rel_start(-1), rel_len(0) {}
};

/// @brief 管理帧携带的 TEI→MAC 学习对(供列表 TEI→MAC 映射表建立)
struct TeiMacPair {
    quint16 tei;   ///< TEI(12-bit)
    quint64 mac;   ///< MAC 48-bit
};

/// @brief 拓扑事件类型(对应驱动拓扑变化的管理消息)
enum class TopoEventKind {
    DiscoverList,   ///< 发现列表(单节点快照:TEI/MAC/代理/层级)
    AssocReq,       ///< 关联请求(STA 正在入网)
    AssocCnf,       ///< 关联确认(STA 已入网)
    AssocGatherInd, ///< 关联汇总指示(批量站点入网)
    AssocInd,       ///< 关联指示(南网;拓扑语义等同关联确认)
    ChangeProxyReq, ///< 代理变更请求(STA 请求换代理;仅记录,待确认后更新拓扑)
    ChangeProxyCnf, ///< 代理变更确认(STA 换代理)
    LeaveInd,       ///< 离网指示(STA 离网)
    SuccessRate,    ///< 成功率上报(STA 与上级的上下行通讯成功率)
    CcoRestart,     ///< CCO 重启(发现列表重启次数变化;仅 TopoState 内部生成,警告记录)
    StaRestart,     ///< STA 重启(关联请求重启次数变化;仅 TopoState 内部生成,警告记录)
    Other,
    ChannelInfo,    ///< 信道观测(单跳帧信道观测恢复离线节点;仅 TopoState 内部生成,复活记录)
    PowerOff,       ///< 断电事件(南网停上电事件上报;受影响节点断电离线)
    PowerOn         ///< 上电事件(南网停上电事件上报;只记录,不改状态、不复活)
};

/// @brief 通讯成功率信息(成功率上报条目;down/up 为百分比 0-100)
struct CommRateInfo {
    quint16 tei = 0;
    quint8  down = 0; ///< 下行成功率 %(CCO/代理 → STA)
    quint8  up = 0;   ///< 上行成功率 %(STA → CCO/代理)
};

/// @brief 信号强度量化值 → dBm 估计(取所在档位下限;RSSI 标注函数的数值版)
/// @details 8bit 表148:RSSI = v-111;4bit 表149:档位下限查表(0 档取 -105,15 档取 0);
///          6bit 表225:档位下限 -110+2(v-1)(0 档取 -110,63 档取 14)
inline int rssi_bits_to_dbm(int width, quint64 v) {
    if (width == 8) return int(v) - 111;
    if (width == 4) {
        static const int kLo[14] = {-105, -95, -86, -80, -74, -68, -62,
                                    -56, -48, -42, -36, -30, -20, -10};
        if (v == 0)  return -105;
        if (v >= 15) return 0;
        return kLo[v - 1];
    }
    if (width != 6) return INT_MIN;  // 未知 width(非 4/6/8):无有效 dBm,调用方跳过追加
    if (v == 0)  return -110;
    if (v >= 63) return 14;
    return -110 + 2 * int(v) - 2;
}

/// @brief 从一帧管理消息提取的拓扑事件(协议无关;协议解析器在关键帧填充,
///        拓扑窗口消费。kind==Other 表示非拓扑相关帧)
struct TopoEvent {
    TopoEventKind kind = TopoEventKind::Other;
    quint32 nid = 0;
    quint64 cco_mac = 0;                        ///< 本帧携带 CCO MAC(0=无)
    QVector<TeiMacPair> nodes;                  ///< TEI→MAC 学习对
    QVector<QPair<quint16, quint16>> routes;    ///< (子 TEI, 父/代理 TEI)
    QVector<QPair<quint16, quint16>> up_routes; ///< 上行路由:(STA TEI, 下一跳 TEI),发现列表 UpRoute 条目(南网/国网)
    quint16 discover_src_tei = 0;             ///< 发现列表发送方 TEI(0=无)
    QVector<quint16> neighbor_teis;           ///< 发现列表位图邻居 TEI 列表(发送方见 discover_src_tei)
    bool neighbor_teis_present = false;       ///< 本帧是否携带位图版邻居列表(全 0 位图也置位,以清空旧邻居)
    QVector<quint64> leaves;                    ///< 离网节点 MAC 列表
    QVector<CommRateInfo> comm_rates;           ///< 成功率上报条目(SuccessRate 事件)
    bool is_rf = false;                         ///< 接入方式:false=PLC 载波;true=HRF 无线
    bool is_rf_known = false;                   ///< is_rf 是否明确判定(链路类型字段/物理层介质);false=未知(默认载波)
    QVector<QPair<quint16, int>> rssi_entries;  ///< 邻居信号强度(TEI→dBm 估计;RF 发现列表信道信息,dBm 取档位下限)
    QVector<QPair<quint16, quint8>> neighbor_rates;  ///< 邻居 TEI → 接收率%(RFDL UpRate;方向=邻居→我,即上行成功率)
    QVector<QPair<quint16, qint16>> neighbor_snrs;   ///< 邻居 TEI → SNR(dB;组合类型含 SNR 时,无则不入表)
    quint16 proxy_tei = kTeiInvalid;    ///< 代理 TEI(表217/表126 站点属性 byte6-7,12bit;0xFFFF=无)
    qint16  proxy_up_rate = -1;    ///< 代理上行接收率%(表217 byte9 / 表126 ProxyUpRcvRate;-1=无)
    qint16  proxy_down_rate = -1;  ///< 代理下行接收率%(表217 byte10 / 表126 ProxyDownRcvRate)
    qint16  min_link_rate = -1;    ///< 链路最小接收率%(表217 byte11 / 表126 MinRcvRate)
    quint8  rf_hop = 0;            ///< RF 跳数(表217/表126 byte8 高4bit)
    quint8  rf_role = 0;           ///< 角色(表217/表126 byte7 高4bit;0未知/1站点/2代理站点/4中央协调器)
    int link_type = -1;                         ///< 链路类型(SPLC-4 表79 / BPLC-2 表160:0=高速载波链路 1=无线链路;-1=帧内无此字段)
    quint8 module_type = 0xFF;                  ///< 模块类型(关联请求,BPLC-2 表164/SPLC-4 表84:0=HPLC单模/1=双模HPLC+RF/2=无线单模;0xFF=无)
    QVector<QPair<quint16, quint8>> node_link_types; ///< 路由表(表55/56)每节点入网链路类型:(TEI,0=载波/1=无线),关联确认/指示帧权威
    qint32 proxy_comm_rate = -1;      ///< 与代理站点通信成功率(表77 byte16-19,32bit;取值范围0-100,超出无效;-1=无)
    qint32 proxy_down_comm_rate = -1; ///< 与代理站点下行通信成功率(表77 byte20-23,32bit;同上)
    qint16 min_comm_rate = -1;        ///< 最小通信成功率(表77 byte36,8bit;-1=无)
    QVector<quint16> child_teis;                ///< 子站点 TEI 列表(代理变更确认 0x003B 位图置位)
    int restart_count = -1;                     ///< 发送方重启次数(南网 MAC 帧头 4-bit;-1=未知/无)
    quint64 sender_mac = 0;                     ///< 本跳发送方 MAC(MSDU 头源 MAC;0=无;STA 重启按发送方建基线)
    QString desc;                               ///< 变更说明(路由变更了什么)
    qint64 epoch_ms = 0;                        ///< 时间点(epoch ms)
    qint64 frame_index = -1;                    ///< 来源帧序号(PacketEntry::index;路由表显示与双击追溯用)
};

/// @brief 送入解析器/插件的一帧
/// @details SerialReader 只填充 meta/data/raw_wire 等原始字段;主程序
///          EntryBuilder(解析线程预构建 + GUI 补序号)完成协议解析后补 decoded_* 与 topo_event,
///          再喂给插件引擎 —— 插件拿到的永远是"解析好的帧"(单入口 parse)。
struct BplcFrame {
    PhysicalMeta meta;            ///< 物理层元信息(由 SerialReader 填充部分)
    QByteArray   data;            ///< 反转义 + 去哨兵后的净荷(含 isRF 字节 + PDU)
    QString      error_reason;    ///< 非空:该帧被丢弃时附带原因
    qint64       arrival_us;      ///< PC 收到帧起始分节符(0x3C)的单调高精度时刻
                                  ///< (µs;仅实时串口填充,文件回放=0 → Delta 用文件时间戳)
    QByteArray   raw_wire;        ///< 原始串口帧(0x3C...0x3E 含哨兵与 0x3D 转义,原样)

    // ---- 主程序解析后填充(插件可见) ----
    qint64    decoded_index = 0;    ///< 主程序帧序号(1-based;0=原始帧,未解码)
    qint64    decoded_epoch_ms = 0; ///< 解析出的帧时刻(epoch ms;0=未知)
    TopoEvent topo_event;           ///< 本帧携带的拓扑事件(kind=Other 表示无)
    // ---- 标量透传:主程序已解析好的单值,插件直接取用,无需重解析 ----
    bool     accepted = true;       ///< 主程序是否接受该帧(false=丢弃,原因见 error_reason)
    MpduInfo mpdu;                  ///< MPDU 解析结果(主程序真值;替代插件侧重复解析)
    QString  msdu_summary;          ///< MSDU 概要(如 "MMeDiscoverNodeList";无 MSDU 为空)
    bool     msdu_present = false;  ///< 本帧是否携带完整 MSDU(重组完成)

    BplcFrame() : arrival_us(0) {}
};
Q_DECLARE_METATYPE(BplcFrame)

/// @brief MSDU 解析结果(由 GW_2022_MsduParser 填充)
struct MsduInfo {
    int cascade_break_len = -1;  ///< 聚合:级联流中声明长度越界的级联数据块长度(-1=无;树层标注用)
    bool    present;         ///< 本帧携带完整 MSDU(重组完成)
    bool    simple_head;     ///< 是否为 MSDU_BASE_S 简头(单跳)
    quint16 msdu_seq;        ///< MSDU 序号(MSDU_BASE 的 MSDUIndex,16-bit)
    int     msdu_src_tei;    ///< 原始发起 TEI(MSDU 头 SourceTEI;-1=无/简头)
    int     msdu_dst_tei;    ///< 原始终点 TEI(MSDU 头 DestinationTEI;-1=无/简头)
    int     msdu_send_type;  ///< 发送类型(MSDU 头 bit:0单播 1全网广播 2本地广播 3代理广播;-1=无)
    quint64 msdu_src_mac;    ///< 源 MAC 48-bit(MSDU 头 MACAddrFlag=1 时;0=无)
    quint64 msdu_dst_mac;    ///< 目的 MAC 48-bit(MSDU 头 MACAddrFlag=1 时;0=无)
    quint64 sta_mac;         ///< 报文体携带的 STA MAC(如关联请求 STAMACAddr;0=无)
    // 南网 NW_2021 MSDU 头字段(国网填 0)
    quint32 vlan_tag;            ///< VLAN 标签 32-bit(南网 MSDU 长头)
    quint16 msdu_type;           ///< MSDU 类型 16-bit(南网 MSDU 长头)
    quint8  restart_count;       ///< 重启次数 4-bit(国网 MSDU 头/南网 MAC 帧头);0xFF=未知/无此字段(=kRestartCountInvalid 本机哨兵)
    quint8  broadcast_direction; ///< 广播方向(南网 MAC 帧头 4-bit / 国网 MSDU_BASE 2-bit;表7:1下行/2上行,南网 0=保留/国网 0=双向;0xFF=未知/无此字段)
    quint8  route_hops_left;     ///< 路由剩余跳数/跳数(国网 MSDU_BASE RouteHopsLeftNum 4-bit / 南网 MAC 帧头 RouteHop 4-bit;0xFF=未知/无此字段)
    quint8  business_id;         ///< 应用层 BID(业务标识;非应用层报文=0xFF,供整行着色)
    quint8  app_packet_type;     ///< 应用层帧类型域 4-bit(南网表4;非 NW 应用层=0xFF)
    quint16 mme_type;            ///< 管理消息 MMe 类型(16bit;非管理消息=0xFFFF=kMMeTypeNone 本机约定,供整行着色)
    quint8  trans_direction_flag; ///< APP 业务报文头 TransDirectionFlag(byte1 bit7,表8:0下行/1上行;非 APP=0xFF,P2P Dir 列)
    int     total_len;       ///< MSDU 帧总长(头+数据+CRC,不含 PB 填充;-1=未知)
    bool    cascade;         ///< 聚合帧级联拆分(SPLC 表47/48;msdu_body=级联体流,
                              ///< tree=Cascade MAC Frame 组,rel 相对级联体流)
    QString summary;         ///< 概要,如 "MMeDiscoverNodeList" / "APP EventPacket"
    QVector<MsduFieldNode> tree;  ///< 字段树(协议树直接挂载显示)
    QVector<TeiMacPair> tei_mac_pairs; ///< 本帧携带的 TEI→MAC 学习对(发现列表等)
    QVector<TeiMacPair> orig_srcs;   ///< 聚合/多站点帧各段/各站的原始源(TEI,MAC),按段/站序、去重;仅帧级无原始 TEI 时收集,帧级有源或单段帧时为空(走原单源逻辑);TEI-only 段(短头 MACAddrFlag=0)亦收集,MAC 为 0,显示只出 STA-N(不进 tei_mac_pairs)
    QVector<TeiMacPair> orig_dsts;   ///< 聚合/多站点帧各段/各站的原始目的(TEI,MAC),按段/站序、去重;仅帧级无原始目的 TEI 时收集,帧级有目的或单段帧时为空(走原单目的逻辑;与 orig_srcs 镜像,用户 2026-10-29 定);TEI-only 段同源规则,MAC 为 0 时显示只出 STA-N
    TopoEvent topo_event;        ///< 拓扑事件(关键管理消息填充;kind=Other 表示无)
    QVector<TopoEvent> topo_extra_events; ///< 多站点合并的后续拓扑事件:topo_event=首事件,本字段=其余事件;消费全部事件必须两者都读

    MsduInfo() : present(false), simple_head(false), msdu_seq(0),
                 msdu_src_tei(-1), msdu_dst_tei(-1), msdu_send_type(-1),
                 msdu_src_mac(0), msdu_dst_mac(0), sta_mac(0),
                 vlan_tag(0), msdu_type(0), restart_count(kRestartCountInvalid),
                 broadcast_direction(0xFF), route_hops_left(0xFF),
                 business_id(0xFF), app_packet_type(0xFF),
                 mme_type(kMMeTypeNone), trans_direction_flag(0xFF),
                 total_len(-1), cascade(false) {}
};

/// @brief 追加摘要片段(顶层 summary 拼接统一入口)
/// @details 空摘要直接设值,非空用 " | " 分隔——消除前导空格,保证
///          MSDU Type 列左对齐(用户需求 2026-10)
inline void append_summary(MsduInfo& out, const QString& text) {
    if (text.isEmpty()) return;
    out.summary = out.summary.isEmpty()
                      ? text : out.summary + QStringLiteral(" | ") + text;
}

/// @brief 通用解剖字段节点(自递归树)
/// @details 协议插件返回、主界面统一渲染(与 MsduFieldNode 同层,避免
///          common → plugin 的反向依赖)。坐标以 PacketEntry::raw_bytes
///          (=ParseResult::payload_for_log)为基准,与 Hex 高亮同一坐标系;
///          插件若剥离了媒介前缀,须自行把 start 加回剥离长度。
/// @note  不进换页盘块(渲染派生数据)。实测字段树使盘块 1000 条从 26 KB
///        涨到 720 KB(27×),且每次读一条都要重建整棵树 → 列宽/滚动路径变慢。
struct DissectField {
    QString name;                ///< 字段名(位域带 [Nbit] 标注,约定同 MsduFieldNode)
    QString value;               ///< 格式化值文本
    int     start = -1;          ///< raw_bytes 中的字节偏移,-1=无字节映射
    int     len   = 0;           ///< 覆盖字节数
    quint8  severity = 0;        ///< 0=无 1=提示 2=警告 3=错误(仅影响前景色)
    QVector<DissectField> children;

    DissectField() = default;
    DissectField(const QString& n, const QString& v, int s = -1, int l = 0)
        : name(n), value(v), start(s), len(l) {}
};

/// @brief PacketEntry::protocol 取值(与 protocol/common/protocolvariant.h 的 ProtocolVariant 对应)
constexpr quint8 kProtocolGw2022 = 0;  ///< 国网双模标准 2022 HDC 1.0
constexpr quint8 kProtocolNw2021 = 1;  ///< 南网双模 2021 报批版 BPLC
constexpr quint8 kProtocolGw2026 = 2;  ///< 国网双模 2026 HDC 2.0 (下一代)
constexpr quint8 kProtocolNw2026 = 3;  ///< 南网 SPLC 2026(下一代)
/// 插件协议帧标记位:高位=该帧由插件解析,低 7 位仍是内置协议编号
/// (用于着色/过滤等场景的协议回退判定;比较时须先掩掉高位,如 (p & 0x7F) == kProtocolXxx)
constexpr quint8 kProtocolPluginBit = 0x80;

/// @brief Wireshark 风格 PacketList 的一行条目
struct PacketEntry {
    int          index;        ///< 序号(从 1 开始累加)
    qint64       epoch_ms;     ///< PC 收到时刻(epoch ms)
    qint64       delta_us;     ///< 与上一帧的时间差(µs;NTB 40µs 分辨,不可比时=ms×1000)
    bool         accepted;     ///< true=accepted, false=dropped(CRC 错或格式异常)
    QString      reason;       ///< dropped 时填原因
    QByteArray   raw_wire;     ///< 原始串口帧(0x3C...0x3E 原样,含转义;调试/复制用)
    PhysicalMeta meta;         ///< 物理层元信息
    MpduInfo     mpdu;         ///< MPDU 解析结果
    quint8       protocol;     ///< 协议标识:kProtocolGw2022/kProtocolNw2021(决定广播方向 0 值语义)
    QByteArray   msdu_body;    ///< 重组后的 MSDU body(若完成)
    MsduInfo     msdu;         ///< MSDU/MAC 层字段解析(若重组完成)
    MsduInfo     beacon;       ///< BEACON 载荷区字段解析(仅 BEACON 帧)
    int          msdu_raw_base;///< MSDU body 在 raw_bytes 中的偏移;-1=不在本帧(跨帧重组)
    QByteArray   raw_bytes;    ///< 原始字节,用于 HexView 显示
    QString      search_text;  ///< 可搜索全文缓存(小写;EntryBuilder/反序列化时填充,过滤匹配用)
    QVector<DissectField> dissect_fields; ///< 插件通用字段树(内置解析为空;仅协议树视图消费,不落盘)

    PacketEntry()
        : index(0), epoch_ms(0), delta_us(0), accepted(false),
          protocol(kProtocolGw2022), msdu_raw_base(-1) {}
};

/// @brief 生成可搜索全文中除帧序号外的部分(小写)
/// @details 只依赖解析派生字段(accepted/reason/meta/mpdu/msdu),不依赖 GUI 线程
///          才确定的帧序号,因此可在解析线程预先构建;完整文本见 make_search_text。
inline QString make_search_text_tail(const PacketEntry& e) {
    QStringList parts;
    if (!e.accepted) {
        parts << QStringLiteral("drop") << QStringLiteral("err");
        parts << e.reason.toLower();
        return parts.join(QLatin1Char(' '));
    }
    parts << (e.meta.is_rf ? QStringLiteral("hrf") : QStringLiteral("hplc"))
          << QStringLiteral("plc");
    parts << e.mpdu.frame_type_name().toLower();
    parts << (e.mpdu.src_tei == kTeiCco ? QStringLiteral("cco")
            : e.mpdu.src_tei != 0      ? QStringLiteral("sta-%1").arg(e.mpdu.src_tei)
            : e.meta.is_rf ? QStringLiteral("hrf") : QStringLiteral("plc"));
    parts << (e.mpdu.dst_tei == kTeiBroadcast ? QStringLiteral("broadcast")
            : e.mpdu.dst_tei == kTeiCco ? QStringLiteral("cco")
            : e.mpdu.dst_tei != 0      ? QStringLiteral("sta-%1").arg(e.mpdu.dst_tei)
                                       : QStringLiteral("*"));
    const QString nid = QString::number(e.mpdu.net_id, 16);
    parts << nid << QStringLiteral("0x%1").arg(nid);
    parts << QString::number(e.mpdu.src_tei) << QString::number(e.mpdu.dst_tei);
    if (e.msdu.present) parts << e.msdu.summary.toLower();
    // Orig Src 列内容亦可搜:前提条件与显示一致——帧级有源时只列帧级源,
    // 无源时列各段/各站源;sta- 词供等值谓词按整词匹配,MAC 串供子串及
    // MAC 模式展开后匹配。
    {
        QVector<TeiMacPair> srcs;
        auto add_src = [&](int tei, quint64 mac) {
            if (tei <= 0) return;
            for (const auto& p : srcs)
                if (p.tei == tei && p.mac == mac) return;
            srcs.append({(quint16)tei, mac});
        };
        if (e.msdu.msdu_src_tei > 0)
            add_src(e.msdu.msdu_src_tei, e.msdu.msdu_src_mac);
        else
            for (const auto& p : e.msdu.orig_srcs) add_src(p.tei, p.mac);
        for (const auto& p : srcs) {
            parts << QStringLiteral("sta-%1").arg(p.tei);
            // MAC u64 约定:低字节为首字节,格式见 common/mac_format.h
            if (p.mac) parts << format_mac_u64(p.mac);
        }
    }
    // Orig Dst 列内容亦可搜:与 Orig Src 镜像——帧级有目的时只列帧级目的,
    // 无目的时列各段/各站目的;sta- 词供等值谓词按整词匹配,MAC 串供子串及
    // MAC 模式展开后匹配。
    {
        QVector<TeiMacPair> dsts;
        auto add_dst = [&](int tei, quint64 mac) {
            if (tei <= 0) return;
            for (const auto& p : dsts)
                if (p.tei == tei && p.mac == mac) return;
            dsts.append({(quint16)tei, mac});
        };
        if (e.msdu.msdu_dst_tei > 0)
            add_dst(e.msdu.msdu_dst_tei, e.msdu.msdu_dst_mac);
        else
            for (const auto& p : e.msdu.orig_dsts) add_dst(p.tei, p.mac);
        for (const auto& p : dsts) {
            parts << QStringLiteral("sta-%1").arg(p.tei);
            if (p.mac) parts << format_mac_u64(p.mac);
        }
    }
    return parts.join(QLatin1Char(' '));
}

/// @brief 由帧序号与 make_search_text_tail 的结果拼出完整可搜索全文
/// @details 与 make_search_text 逐字节一致(尾部恒非空,分隔空格恒存在);
///          GUI 线程分配序号后只做这一次拼接,重活留在解析线程。
inline QString join_search_text(int index, const QString& tail) {
    return QString::number(index) + QLatin1Char(' ') + tail;
}

/// @brief 生成一行的可搜索全文(小写),供过滤器快速匹配;缓存于 PacketEntry::search_text
inline QString make_search_text(const PacketEntry& e) {
    return join_search_text(e.index, make_search_text_tail(e));
}

/// 南网 CCO 作为发起者/回应者的管理消息类型(值取自 nw_2026_msdu_parser.h:76/78/79;
/// 供 dir_display 排除 CCO 直发帧用——CCO 直发这些消息不算中继;表号=SPLC 第4部分报文格式)
enum NwCcoInitiatedMme : quint16 {
    NwCcoInitMmeAssocCnf       = 0x0031,  ///< 关联确认(表92)
    NwCcoInitMmeAssocInd       = 0x0034,  ///< 关联指示(表99)
    NwCcoInitMmeChangeProxyCnf = 0x0037,  ///< 代理变更确认(表108)
};

/// @brief Dir 列显示(界面列表 COL_DIR 与 CSV 导出共用):
///        广播报文(目的 TEI=0xFFF 且发送类型非单播)按 广播方向+剩余跳数 指示
///        ↓[R]N→ / ↑[R]N→ / [R]N→,方向未知/保留→*(中继→*R;广播中继且剩余跳数已知>1→RN→)
///        单播按 TEI 判定 ↑/↓(中继 ↑R/↓R)
///        中继判定 = MSDU 头源 TEI≠本跳 TEI,或合并帧任一有效原始源≠本跳发送方,
///        或 MMe 主体≠本跳发送方且非 CCO 发起类消息;本跳发送方为 0 不比较(不算不一致)
///        (CCO 作为发起者/回应者直发不算中继;CCO 当转发者仍标 R;CCO 原点被转发仍标 ↓R)
///        合并帧 present=false 且中继时方向未知,显示 *R;广播方向未知且中继时,
///        剩余跳数已知且>1(0xFF 为未知哨兵,不计)显示 RN→,否则中继仅标 *R。
inline QString dir_display(const PacketEntry& e) {
    // 合并帧中继:帧级无原始 TEI 且 orig_srcs 非空时,任一有效原始源 ≠ 本跳
    // 发送方即中继。发送方为 0 不比较(不算不一致);空源项 tei==0 跳过。
    // CCO 专支在后先行返回,故 CCO-only 合并帧可直接判定下行；若发送方
    // 非 0 且不是 CCO，仍由 merged_relay 追加 R。
    bool merged_relay = false;
    if (e.accepted && !e.msdu.simple_head && e.msdu.msdu_src_tei <= 0
        && !e.msdu.orig_srcs.isEmpty() && e.mpdu.src_tei != 0) {
        for (const auto& p : e.msdu.orig_srcs) {
            if (p.tei != 0 && p.tei != e.mpdu.src_tei) { merged_relay = true; break; }
        }
    }
    // 聚合/合并帧且原始源只有 CCO:整帧为 CCO 下行,Dir 显示下行标志。
    // (与 Orig Src 多源分支同门:帧级无原始 TEI 且 orig_srcs 非空;
    //  合并帧 present=false,故此分支须在 present 门之前。tei==0 的
    //  空源项跳过,须至少一项有效 CCO 且无其他源。若本跳发送方非 0
    //  且不是 CCO，则 CCO 源与发送方不一致，仍需追加 R；发送方为 0
    //  时不比较，保持裸 ↓。
    if (e.accepted && !e.msdu.simple_head && e.msdu.msdu_src_tei <= 0
        && !e.msdu.orig_srcs.isEmpty()) {
        bool has_cco = false;
        bool only_cco = true;
        for (const auto& p : e.msdu.orig_srcs) {
            if (p.tei == 0) continue;
            if (p.tei == kTeiCco) has_cco = true;
            else { only_cco = false; break; }
        }
        if (has_cco && only_cco)
            return QStringLiteral("\u2193") + (merged_relay ? QStringLiteral("R") : QString());
    }
    if (!e.accepted || !e.msdu.present || e.msdu.simple_head)
        return merged_relay ? QStringLiteral("*R") : QStringLiteral("*");
    const bool relay_orig = (e.mpdu.src_tei != 0)
                    && (e.msdu.msdu_src_tei > 0)
                    && (quint16(e.msdu.msdu_src_tei) != e.mpdu.src_tei);
    // 中继扩展:MMe 主体(sta_mac)≠ 本跳发送方(msdu_src_mac)的管理帧(代理转发)。
    // 排除 CCO 作为发起者/回应者直发的消息(不算中继):关联确认(表92)、关联指示(表99)、
    // 代理变更确认(表108);其余消息(站点间数据帧 mme_type=0xFFFF、CCO 转发的关联请求
    // 0x0030 等)CCO 当转发者仍标 R。枚举见 NwCcoInitiatedMme(dir_display 跨协议通用)。
    const bool cco_initiated = (e.mpdu.src_tei == kTeiCco)
                    && (e.msdu.mme_type == NwCcoInitMmeAssocCnf
                        || e.msdu.mme_type == NwCcoInitMmeAssocInd
                        || e.msdu.mme_type == NwCcoInitMmeChangeProxyCnf);
    const bool relay = relay_orig || merged_relay
                    || (e.msdu.sta_mac != 0 && e.msdu.msdu_src_mac != 0
                        && e.msdu.sta_mac != e.msdu.msdu_src_mac
                        && !cco_initiated);
    const quint8 bdir  = e.msdu.broadcast_direction;
    const quint8 hops  = e.msdu.route_hops_left;
    const bool   bcast = (e.msdu.msdu_dst_tei == kTeiBroadcast)
                      && (e.msdu.msdu_send_type != 0);  // 广播 = 广播目的地址 + 发送类型非单播
    // 广播方向未知时的中继显示:剩余跳数已知且>1 表示还要继续转发,用右箭头 RN→;
    // 否则中继仅标 *R;不中继为 *。(0xFF 未知、保留值、南网保留 0 三处共用;
    // 0xFF 为剩余跳数未知哨兵,不满足 >1。)
    const QString unknown_bcast_dir = (relay && hops != 0xFF && hops > 1)
        ? QStringLiteral("R") + QString::number(hops) + QStringLiteral("\u2192")
        : (relay ? QStringLiteral("*R") : QStringLiteral("*"));
    if (bcast && bdir == 1)       // 下行广播:↓[R]N→
        return QStringLiteral("\u2193") + (relay ? QStringLiteral("R") : QString())
               + QString::number(hops) + QStringLiteral("\u2192");
    if (bcast && bdir == 2)       // 上行广播:↑[R]N→
        return QStringLiteral("\u2191") + (relay ? QStringLiteral("R") : QString())
               + QString::number(hops) + QStringLiteral("\u2192");
    if (bcast && bdir == 0) {       // 双向/保留:国网表7 0=双向 / 南网表7 0=保留(非上下行)
        if ((e.protocol & 0x7F) == kProtocolNw2021 || (e.protocol & 0x7F) == kProtocolNw2026)   // 南网:0=保留 → 未知方向中继显示(见 unknown_bcast_dir,掩掉插件位后比较)
            return unknown_bcast_dir;
        return (relay ? QStringLiteral("R") : QString())
               + QString::number(hops) + QStringLiteral("\u2192");  // 国网:0=双向 → [R]N→
    }
    if (bcast && bdir == 0xFF)    // 未知/漏填(解析器未填广播方向)
        return unknown_bcast_dir;
    if (bcast)                    // 保留值(3-15)
        return unknown_bcast_dir;
    if (e.msdu.msdu_dst_tei == kTeiCco) return relay ? QStringLiteral("\u2191R") : QStringLiteral("\u2191");
    if (e.msdu.msdu_src_tei == kTeiCco) return relay ? QStringLiteral("\u2193R") : QStringLiteral("\u2193");
    // 站点间通讯 P2P(非 CCO):用应用层报文 TransDirectionFlag(表8 0=下行 1=上行)
    if (e.msdu.trans_direction_flag == 1) return relay ? QStringLiteral("\u2191R") : QStringLiteral("\u2191");
    if (e.msdu.trans_direction_flag == 0) return relay ? QStringLiteral("\u2193R") : QStringLiteral("\u2193");
    return relay ? QStringLiteral("*R") : QStringLiteral("*");  // 方向未知(标志未填/保留):中继仅标 R
}
Q_DECLARE_METATYPE(PacketEntry)

#endif  // BPLC_BPLCFRAME_H
