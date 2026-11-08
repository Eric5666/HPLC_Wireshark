/// @file topo_state.h
/// @brief 拓扑(Topo)状态模型:单 NID 网络的节点/路由累积状态 + 路由变更事件历史
/// @details 本模块独立于 app/io/ui,只依赖 common(bplcframe.h 的 TopoEvent/TeiMacPair)。
///          协议解析器在关键管理消息(关联请求/关联确认/代理变更/发现列表/离网指示)
///          解析时填充 MsduInfo::topo_event(首事件)与 topo_extra_events(多站点后续事件);
///          TopoState 消费这些事件,累积为节点图 + 事件表(主界面逐个 apply)。
#ifndef TOPO_STATE_H
#define TOPO_STATE_H

#include "bplcframe.h"
#include <QHash>
#include <QSet>
#include <QString>
#include <QVector>

/// @brief 节点入网状态(对应拓扑图图标三态)
enum class NodeStatus {
    OnlineGoing, ///< 正在入网(STA 发起关联请求,尚未完成)
    Online,      ///< 已入网(关联确认/发现列表在网)
    Offline,     ///< 离线(离网指示)
};

/// @brief 单个节点的拓扑信息
struct TopoNode {
    quint16 tei = 0;
    quint64 mac = 0;
    quint16 parent_tei = kTeiInvalid; ///< 代理 TEI;1=CCO 直属;0=根(CCO 自身);0xFFFF=未知
    NodeStatus status = NodeStatus::OnlineGoing;
    qint64  last_seen_ms = 0;
    bool    is_rf = false;            ///< 首次观察到该 TEI 时帧的物理介质(false=载波 true=RF);
                                      ///  仅首次写入并锁定,不表示入网链路 —— 入网链路看 link_type;
                                      ///  双模标记看 rf_capable
    bool    is_rf_known = false;      ///< is_rf 是否已判定(方案②:仅首次/未知时写入,防事件帧外高频重写)
    int     rssi_dbm = 0;             ///< 无线信号强度(dBm 估计,档位下限;RF 发现列表信道信息)
    bool    rssi_known = false;       ///< rssi_dbm 是否有效(RF 帧携带过信号强度)
    qint16  proxy_up_rate = -1;       ///< 代理上行接收率%(表217/表126 站点属性;-1=无)
    qint16  proxy_down_rate = -1;     ///< 代理下行接收率%(表217/表126)
    qint16  min_link_rate = -1;       ///< 链路最小接收率%(表217/表126)
    quint8  rf_hop = 0;               ///< RF 跳数(表217/表126 byte8 高4bit)
    quint8  rf_role = 0;              ///< 角色(表217/表126 byte7 高4bit;0未知/1站点/2代理站点/4CCO)
    bool    proxy_rate_known = false; ///< 站点属性速率是否有效
    quint8  link_type = LinkTypeUnknown; ///< 入网链路类型(SPLC-4 表79 / BPLC-2 表160:0=载波链路 1=无线链路 0xFF=未定)
    bool    link_type_known = false;  ///< 入网链路是否已确定(权威帧赋值后锁定,不被后续帧翻转)
    bool    rf_capable = false;       ///< 双模标记:发送方发过 RF 帧,或入网链路为无线(权威/弱路径全算);
                                      ///  CCO 自己发过 RF 帧即双模(置位后不清除)
    qint32  proxy_comm_rate = -1;      ///< 与代理站点通信成功率(表77 byte16-19,32bit;0-100%;-1=无)
    qint32  proxy_down_comm_rate = -1; ///< 与代理站点下行通信成功率(表77 byte20-23,32bit)
    qint16  min_comm_rate = -1;        ///< 最小通信成功率(表77 byte36,8bit)
    bool    comm_rate_known = false;   ///< 来自 0x0055 载波发现列表(独立于 RFDL proxy_* 与 0x005E comm_rates)

    /// @brief 是否在线(非离线)
    bool online() const { return status != NodeStatus::Offline; }
};

/// @brief 异常/冲突类别(拓扑身份一致性与重启计数一致性)
/// @details 与路由变更事件表分离:这些不是"拓扑演进",而是"数据自相矛盾"的嫌疑,
///          单独一页签展示,避免与正常的关联/代理变更事件混在一起。
enum class TopoAnomalyKind {
    MacMultipleTei,          ///< 同一 MAC 对应不同 TEI(在线节点冲突;CCO/STA 角色切换不受离线状态限制)
    TeiMultipleMac,          ///< 同一 TEI 先后对应两个仍在线的 MAC(TEI 被两台设备占用)
    RestartCountOscillation, ///< 同一 TEI+介质的重启次数往返振荡(双实体共用 TEI/计数被复位)
    LinkCountMismatch,       ///< 同一 TEI 载波与无线的重启次数不同(两条链路各自计数)
    NidConflict,             ///< 同一 NID 下出现不同 CCO MAC(网络标识冲突)
};

/// @brief 一条异常/冲突记录(同类同主体合并到一行,trips 累加,防刷屏)
struct TopoAnomaly {
    TopoAnomalyKind kind = TopoAnomalyKind::MacMultipleTei;
    quint16 tei = 0;          ///< 相关 TEI(振荡项=发送方 TEI)
    quint16 tei_old = 0;      ///< 冲突中先出现的 TEI(MacMultipleTei 有意义;其它同 tei)
    quint64 mac = 0;          ///< 相关 MAC(0=无)
    quint64 mac_old = 0;      ///< 冲突中先出现的 MAC(TeiMultipleMac 有意义)
    bool    is_rf = false;    ///< 介质(振荡项有意义;false=载波 true=无线)
    int     trips = 0;        ///< 出现次数(冲突次数 / 往返次数)
    int     value_from = -1;  ///< 最近一次变化前值(振荡项;冲突项=旧 TEI/旧 MAC 数值无意义)
    int     value_to = -1;    ///< 最近一次变化后值(振荡项)
    qint64  first_ms = 0;     ///< 首次时间(epoch ms)
    qint64  last_ms = 0;      ///< 最近时间(epoch ms)
    qint64  first_frame = -1; ///< 首次来源帧序号
    qint64  last_frame = -1;  ///< 最近来源帧序号
};

/// Stable aggregate identity shared by in-memory merging and SQLite persistence.
QString topo_anomaly_merge_key(quint32 net_id, const TopoAnomaly& anomaly);

/// @brief (NID, MAC) 组合键:网络标识符用完整 quint32(GW HDC1.0 为 24bit,有效 1~16777215;
///        GW HDC2.0 为 16bit;南网 SNID 合并后 5bit),MAC 取低 48bit;两者都不截断,
///        仅高位不同的网络也不会串键(旧 quint64 打包只取 NID 低 16bit,已作废)。
struct NidMacKey {
    quint32 nid = 0;
    quint64 mac = 0;
    bool operator==(const NidMacKey &o) const { return nid == o.nid && mac == o.mac; }
};
/// @brief NidMacKey 的哈希:不调用 qHashMulti(不同 Qt 小版本可用性不一),直接整数混叠。
inline size_t qHash(const NidMacKey &k, size_t seed = 0) {
    size_t h = seed + size_t(0x9e3779b97f4a7c15ULL);
    h ^= size_t(k.nid) * size_t(0x9e3779b97f4a7c15ULL);
    h ^= size_t(quint32(k.mac)) + size_t(0x9e3779b97f4a7c15ULL) + (h << 6) + (h >> 2);
    h ^= size_t(quint32(k.mac >> 32)) + size_t(0x9e3779b97f4a7c15ULL) + (h << 6) + (h >> 2);
    return h;
}

/// @brief 在网节点数汇总(用户 2026-11-06 定稿口径)
/// @details 主数 online 仅统计 status == Online 的 STA,不含 CCO、不含入网中、
///          不含离线;入网中 online_going 含 pending(TEI 未分配的关联请求节点)。
struct TopoOnlineCounts {
    int online = 0;       ///< 已入网 STA 数(不含 CCO TEI=1)
    int online_going = 0; ///< 正在入网 STA 数(nodes 的 OnlineGoing + pending)
    int offline = 0;      ///< 离线 STA 数(不含 CCO TEI=1)
};

/// @brief 单个 NID 网络的拓扑状态(节点 + 路由 + 事件历史)
class TopoState {
public:
    quint32 nid = 0;
    quint64 cco_mac = 0;
    qint64 first_seen_ms = 0;     ///< 首次识别到该 NID 的帧时间戳(epoch ms;0=未知)
    qint64 first_seen_frame = -1; ///< 首次识别到该 NID 的帧序号(-1=未知)
    QHash<quint16, TopoNode> nodes; ///< TEI → 节点(含 CCO TEI=1)
    QHash<quint64, TopoNode> pending; ///< MAC → 正在入网节点(TEI 未分配,关联请求阶段)
    QHash<NidMacKey, quint16> mac_to_tei; ///< (NID, MAC) → TEI 快速索引(键 = nid_mac_key(NID, MAC),先分 NID 再分 MAC;离线标记按 MAC 查找;与 nodes 双向一致)
    QHash<quint16, CommRateInfo> comm_rates; ///< TEI → 通讯成功率(成功率上报)
    QHash<quint16, QVector<quint16>> neighbors; ///< TEI → 邻居 TEI 列表(发现列表位图,按帧更新)
    QHash<quint16, QHash<quint16, int>> neighbor_counts; ///< STA TEI → (邻居 TEI → 发现列表接收数,累计)
    QHash<quint16, QHash<quint16, quint8>> neighbor_rates; ///< 上报方 STA → (邻居 → 接收率%·方向=邻居→上报方,即上行)
    QHash<quint16, QHash<quint16, qint16>> neighbor_snrs;  ///< 上报方 STA → (邻居 → SNR dB)
    // These are bounded UI projections, not the authoritative history. The worker
    // persists every input frame and derived anomaly in SQLite and exposes paged reads.
    // Checkpoints omit events (which are not replay state); anomaly aggregates remain
    // because they are also the bounded deduplication state needed for deterministic replay.
    QVector<TopoEvent> events;      ///< UI 最近 4096 条事件；更早事件需从 SQLite 重建
    bool has_event_history = false; ///< 有过事件；检查点省略 events 后仍用于保留 NID
    QVector<TopoAnomaly> anomalies; ///< UI 最近 4096 个合并异常主体；更早记录需重建

    /// @brief 是否已有可在 TOPO 窗口展示的拓扑/事件内容。
    /// @details RestartCount 基线可先于任何拓扑事件建立；这种仅含采样基线的状态不应
    ///          在网络列表中表现为一个空拓扑。重启事件或异常产生后则应正常显示。
    bool has_topology_content() const {
        return first_seen_frame >= 0 || !nodes.isEmpty() || !pending.isEmpty()
            || has_event_history || !events.isEmpty() || !anomalies.isEmpty();
    }

    /// @brief 在网节点数汇总(用户 2026-11-06 定稿口径)
    /// @details 主数 online 仅统计 status == Online 的 STA:不含 CCO(TEI 固定为 1,
    ///          kTeiCco)、不含入网中(OnlineGoing / pending)、不含离线;入网中和离线
    ///          另行给出,供 TOPO 窗口显示"在网节点:N(入网中 X / 离线 Y)"。
    ///          TEI 复用等异常按 TEI 数计,不去重、不扣减(与拓扑图图标数一致)。
    /// @return 当前 NID 的 TopoOnlineCounts(本 TopoState 只属一个 NID,切 NID 不串数)
    TopoOnlineCounts online_counts() const;

    /// @brief 逐帧重启次数采样:同一 (TEI, 介质) 的取值回到曾经出现过的值即记一条往返振荡
    /// @details 判据(用户口径):任意一次反向变化即记。以该 (TEI, 介质) 已出现过的取值集合
    ///          为准——取值变成集合内旧值 ⇒ 记一次往返;变成从未见过的新值(如 2/3 之后首次
    ///          见到 4)⇒ 不记,但把 4 纳入集合,之后 4→2、2→4 仍按往返计。
    ///          仅采样 4-bit 重启次数(kRestartCountInvalid=无该字段则忽略)。
    /// @return 是否新增/更新了异常记录(UI 刷新节流用)
    bool note_restart_count(quint16 tei, bool is_rf, int rc,
                            qint64 epoch_ms, qint64 frame_index);

    /// @brief 逐帧重启次数采样(方案 B):全帧采样,按 (NID, 主体 MAC) 分键,变化即报重启
    /// @details 依据与口径:
    ///  - 重启次数是 MAC 帧头的 4-bit 计数器(国网 MSDU 头 / 南网 MAC 帧头),任何变化即视为重启,
    ///    天然处理 15→0 回绕(判据未改,仅扩采样点);
    ///  - **CCO 的 TEI 固定为 1**(南网规约 / HDC 2.0 5.3.3.1),故主体判定依据:
    ///    当前有效 src_tei 优先于旧身份;无有效源 TEI 时回退本 NID 最新映射/身份记忆;
    ///    CCO/STA 同 MAC 每次冲突均记录,并以最新信息覆盖;角色切换首帧重建基线;
    ///  - 基线按 (NID, MAC) 分键,STA/CCO 的不同 MAC 永不合并;不同 NID 的相同 MAC 也隔离。
    ///    无 MAC 的 CCO 样本使用 (NID, 0) 独立占位键;仅身份唯一时才可迁移旧占位值。
    ///    同一 NID 下确认到不同 CCO MAC 时记录 NID 冲突,且不再把无 MAC 样本归到任一 MAC;
    ///    事件 sender_mac 保留真实源 MAC,不归一;
    ///  - src_mac==0 时只有判为 CCO 才检测(归本 NID 的 CCO 基线);判为 STA 则不检测,
    ///    宁可不报,也不把计数记到别的主体名下;
    ///  - 已知代价:事件量上升(以前漏报的真实重启现在会报);CcoRestart/StaRestart 是插件 API 事件
    ///    (plugin/host/js_backend.cpp / lua_backend.cpp 映射为 ccoRestart/staRestart),
    ///    Lua/JS 侧若按事件条数统计会随之变化。
    /// @return 是否新增了重启事件或记录了身份冲突(UI 刷新用)
    /// @param[out] did_revive 不为空时置为本次调用是否发生了离线→在线复活;
    ///             供 MainWindow 逐帧采样日志补记用——无重启计数的帧不进采样日志,
    ///             但实时仍会复活(复活块在计数检查之前),只给真正复活的帧补记一条
    ///             采样(rc=0xFF),回放重走同一函数复现复活与原因。返回值语义不动。
    bool note_restart_origin(quint32 net_id, quint16 src_tei, quint64 src_mac, int rc,
                             qint64 epoch_ms, qint64 frame_index, bool is_rf, bool is_rf_known,
                             TopoEventKind frame_kind = TopoEventKind::Other,
                             bool* did_revive = nullptr);

    /// @brief 应用一个拓扑事件,增量更新节点/路由/入网状态并记录事件
        /// @brief 逐帧接入方式兜底(方案②):仅对"已存在且接入方式未确定"的节点写入
    /// @note  不建占位节点(避免数据帧/广播帧在拓扑里凭空生成 TEI 节点);不覆盖已确定值(防双模抖动)
    /// @return 是否实际发生写入(UI 刷新节流用)
    bool note_frame_medium(quint16 tei, bool is_rf) {
        if (!tei || tei == kTeiInvalid) return false;
        auto it = nodes.find(tei);
        if (it == nodes.end()) return false;   // 节点不存在 → 不建(等事件帧创建)
        if (it->is_rf_known) return false;     // 已确定 → 不覆盖(双模设备会来回跳)
        it->is_rf = is_rf;
        it->is_rf_known = true;
        return true;
    }
    /// @brief 双模标记:该 TEI 作为发送方发过 RF 帧则置 rf_capable(置位后永不清除)
    /// @note  判据取"发过"而非"收发过"(收到 RF 帧不能证明该节点有 RF 发射能力)
    /// @return 是否实际发生写入(UI 刷新节流用)
    bool note_rf_capable(quint16 src_tei, bool is_rf) {
        if (!src_tei || src_tei == kTeiInvalid || !is_rf) return false;
        auto it = nodes.find(src_tei);
        if (it == nodes.end() || it->rf_capable) return false;   // 已置位不清除
        it->rf_capable = true;
        return true;
    }
void apply(const TopoEvent& e);

    /// @brief 应用 RFDL(单跳帧)邻居信道信息:接收率/SNR 按上报方 STA 键控,rssi 更新节点属性
    /// @note 单跳帧 topo_event.kind=Other(不触发 apply()),其信道信息单独走此路径;
    ///       上报方 TEI 取自帧 FCH SrcTEI(单跳无中继,源=发送方)
    void apply_channel_info(quint16 reporter_tei, const TopoEvent& e);

    /// @brief 计算各节点层级(从 CCO=0 沿父链向下;不可达=-1)
    QHash<quint16, int> compute_levels() const;

    /// @brief (NID, MAC) → 组合键:NID 用完整 quint32、MAC 取低 48bit
    /// @note GW HDC1.0 的 NID 是 24bit(有效 1~16777215)、HDC2.0 是 16bit(有效 1~65535)、
    ///       NW SNID 合并后 5bit(有效 1~31),三者全取,不截断。
    static NidMacKey nid_mac_key(quint32 net_id, quint64 mac);

    /// @brief 取节点 MAC(TEI 未知返回 0)
    quint64 mac_of(quint16 tei) const;

private:
    /// @brief 维护 mac_to_tei 双向一致(处理"同一 MAC 先后对应不同 TEI"和"同一 TEI 先后对应不同 MAC")
    /// @details CCO(TEI=1)/STA 共用 MAC 时每次切换均记冲突并以最新有效 TEI 覆盖身份,
    ///          不受旧节点在线状态影响。其他 A/B 冲突沿用旧节点在线才计的口径。
    ///          角色切换重置该 (NID, MAC) 的 CCO/STA 重启基线,避免串角色误报。
    /// @return 是否记录了异常(逐帧调用侧据此刷新 UI)。
    ///          索引按 (NID, MAC) 分键(键 = nid_mac_key):同 MAC 在不同 NID 下可映射到
    ///          不同 TEI;nodes 表仍按 TEI 单键,故"同一 TEI 多 MAC"的节点侧校验仍读共享表,
    ///          删除旧映射时只删本 NID 的键,不动别 NID 的映射。
    bool index_mac(quint32 net_id, quint16 tei, quint64 mac, qint64 epoch_ms = 0, qint64 frame_index = -1);
    /// @brief 记录/合并一条异常(同类同主体合并,trips 累加,更新最近取值与时间)
    void note_anomaly(quint32 net_id, TopoAnomalyKind kind,
                      quint16 tei, quint64 mac, quint64 mac_old,
                      quint16 tei_old, bool is_rf, int from, int to,
                      qint64 epoch_ms, qint64 frame_index);

    /// @brief 某 (TEI, 介质) 的重启次数轨迹
    struct RcTrack {
        int prev = -1;      ///< 上一次取值(-1=尚无)
        int fwd_run = 0;    ///< 连续"规整前进(+1)"的步数:用于区分 4-bit 计数器回绕与相邻值振荡
        qint64 last_ms = 0; ///< 本链路最近一次采样的时间(新鲜度判断用;D 比较两侧要同新鲜)
        QSet<int> seen;     ///< 已出现过的取值集合(回到其中任意值即判往返;新值一律入集合)
    };
    QHash<quint32, RcTrack> m_rc_track; ///< (TEI<<1 | is_rf) → 重启次数轨迹
    /// @brief TEI → 最近一次记录的(载波 rc, 无线 rc)组合
    /// @details 防重复计数:同一组合反复出现只算一次;两链路计数恢复一致时清除,
    ///          之后再次不一致仍可记录(对应"次数"=差异出现过的不同组合数)。
    QHash<quint16, QPair<int, int>> m_link_pair;
    QHash<QString, int> m_anom_idx;     ///< 合并键 → anomalies 下标
    /// @brief 按 MAC 移除已存在的拓扑节点(设备重上电再次发起关联时先清旧状态)
    /// @details CCO(TEI=1)永不移除;同时清理该 TEI 的成功率残留与 MAC 索引。
    ///          索引按 (NID, MAC) 分键,只删本 NID 的映射。
    /// @return 是否移除了节点
    bool remove_node_by_mac(quint32 net_id, quint64 mac);

    /// @brief 重启次数基线(键 = nid_mac_key(NID, MAC),无 MAC 的 CCO 使用 MAC=0)
    /// @details 两个哈希都不能省 NID:
    ///          - CCO 旧实现是**单一全局值**(m_last_restart_count,已删除),多 NID 同时抓包时互相踩;
    ///          - STA 旧实现只有 MAC,不同 NID 下同 MAC 会串(用户 2026-11 口径:先分 NID,再分 MAC)。
    ///          身份记忆 m_cco_macs 同样按 (NID, MAC) 分键(键 = nid_mac_key),同 MAC 在
    ///          不同 NID 下的 CCO 身份互不串。
    QHash<NidMacKey, int> m_cco_restart_count;  ///< CCO 每 MAC 独立基线;(NID,0) 只用于无 MAC 样本
    QHash<NidMacKey, int> m_sta_restart_count;  ///< STA 主体基线(键 = (NID, 主体 MAC))

    /// @brief 主体身份判定(CCO/STA)的**唯一入口**:apply() 事件侧与逐帧采样侧都走这里,
    ///        避免两条路径判据集合不同导致同一次重启被报成 STA/CCO 两条(M1),
    ///        或 CCO 帧缺源 MAC 时被回落成"发现列表里第一个 STA"(M2)。
    /// @details 当前有效源 TEI 优先(1=CCO,其他单播 TEI=STA);无有效源 TEI 时,
    ///          回退本 NID 最新 TEI→MAC 索引和身份记忆,离线索引不得回灌记忆。
    ///          apply() 先学习当前事件映射,再做重启采样;当前节点映射覆盖过时 CCO 字段。
    ///          缺 MAC 的发现列表仍归本 NID 无 MAC CCO 基线。
    ///          discover_src_tei 是路由/位图条目的 STA TEI,不是发送方 TEI,不用于角色判定。
    /// @param[in] net_id 事件/NID(身份记忆按 (NID, MAC) 分键)
    /// @param[in] ev 事件上下文(可为 nullptr:逐帧路径没有 TopoEvent)
    /// @return true=CCO 主体
    bool resolve_is_cco(quint32 net_id, quint16 src_tei, quint64 mac, const TopoEvent* ev,
                        qint64 epoch_ms, qint64 frame_index);

    QSet<NidMacKey> m_offline_macs; ///< 离网后禁用旧身份回退;新有效 TEI/MAC 到达时解除
    QSet<NidMacKey> m_cco_macs;   ///< CCO 身份记忆(键 = nid_mac_key(NID, MAC),先分 NID 再分 MAC;防归属漂移)
    QHash<quint32, quint64> m_first_cco_mac; ///< 每 NID 首个已确认 CCO MAC,用于冲突行的稳定旧值

    /// @brief 取 CCO 样本可确认的 MAC；没有 MAC 且身份不唯一时返回 0。
    /// @details 优先级:当前主体 MAC > 当前事件 cco_mac > 无冲突时的已学到身份。
    ///          同 NID 记住多个 CCO MAC 后，无 MAC 样本必须使用 (NID, 0) 独立占位键。
    /// @return 规范 cco_mac,未知时为 0
    quint64 canonical_cco_mac(quint32 net_id, quint64 subject,
                              const TopoEvent& proto) const;

    /// @brief 重启变化记录(CCO/STA 共用实现):比较基线、变化即生成重启事件并更新基线
    /// @details CCO 基线按 (NID, MAC) 分离；(NID, 0) 只记录确实缺 MAC 的样本。
    ///          仅在 NID 下身份唯一时可把旧占位基线迁移到该 MAC；发生 NID 冲突后不再迁移。
    ///          事件 sender_mac 保留真实源 MAC(已知时即 cco_mac,未知时为 0)。
    /// @param[in] proto 事件模板(沿用其 nid/is_rf/来源信息),只有 kind/desc/restart_count/主体被改写
    /// @return 是否新增了重启事件
    bool note_restart_change(quint32 net_id, quint64 subject, bool is_cco, int rc,
                             qint64 epoch_ms, qint64 frame_index, const TopoEvent& proto);
};

/// @brief 拓扑事件回放日志条目(帧序号 → 事件;供 TOPO 历史回放调试)
struct TopoLogItem {
    qint64    frame_index = 0; ///< PacketEntry::index(1-based 全局帧序号)
    TopoEvent event;           ///< 已填充 nid/epoch_ms/is_rf 的完整事件
};

/// @brief 逐帧重启采样日志条目(帧序号 → 一次 RestartCount 采样;供 TOPO 历史回放)
/// @details 只记有效采样(MSDU 在、NID 有效、计数有效);变化与否都记——首帧只建基线,
///          回放时缺了它,后一帧的变化就报不出来。普通数据帧的重启只走这条日志,
///          不进拓扑事件日志(见 replay_topo_logs 的注释:重启事件本身不能进事件日志)。
struct TopoRestartSample {
    qint64  frame_index = 0;    ///< PacketEntry::index(1-based 全局帧序号)
    quint32 net_id = 0;         ///< 帧的 NID(0=无效,不记不重放)
    quint16 src_tei = 0;        ///< 帧头发送方 TEI(CCO 固定为 1)
    quint64 src_mac = 0;        ///< MSDU 头源 MAC(0=缺源 MAC)
    int     restart_count = -1; ///< MSDU 头重启次数 4-bit
    qint64  epoch_ms = 0;       ///< 帧时刻(epoch ms)
    bool    is_rf = false;      ///< 帧的物理介质(false=载波 true=RF)
    bool    is_rf_known = false;///< is_rf 是否已判定
    TopoEventKind frame_kind = TopoEventKind::Other; ///< 帧的事件 kind(离线复活原因:回放时
                                                     ///  复活记录的原因须与实时一致,缺省 Other
                                                     ///  即普通数据帧;仅内存日志用,不序列化)
};

/// @brief 单跳帧信道观测日志条目(帧序号 → 一次信道观测;供 TOPO 历史回放)
/// @details 只记有信道观测的单跳帧(与 MainWindow 逐帧块里调 apply_channel_info 完全
///          相同的守卫:simple_head + present + 邻居/rssi/proxy 数据);普通数据帧的信道
///          观测只走这条日志,不进拓扑事件日志(事件门只认 kind != Other)。回放时重调
///          apply_channel_info,复现 Online 翻转、last_seen 与邻居接收率/SNR/RSSI;
///          复活离线节点时留一条复活记录(kind=ChannelInfo,原因“信道观测”),回放重调
///          同一函数,记录与实时一致。仅内存日志用,不序列化。
struct TopoChannelSample {
    qint64 frame_index = 0;   ///< PacketEntry::index(1-based 全局帧序号)
    quint32 net_id = 0;       ///< 帧的 NID(0=无效,不记不重放)
    quint16 reporter_tei = 0; ///< 帧头发送方 TEI(apply_channel_info 的 reporter)
    qint64 epoch_ms = 0;      ///< 帧时刻(epoch ms;回放写 last_seen 用,与 event.epoch_ms 相同)
    TopoEvent event;          ///< 已填充 epoch_ms 的完整信道观测事件(回放用)
};

/// @brief 记录拓扑回放日志,并在改动已回放范围时使水位失效。
/// @details 正常的 MainWindow::make_entry 路径按递增帧号 O(1) 追加,同帧按调用顺序稳定追加。
///          若将来有调用路径违反帧序,则稳定插入以保护各构建类型的回放二分查找;这只修复日志顺序,
///          不表示实时拓扑状态支持迟到事件回滚。
template <typename LogEntry>
inline void record_topo_log_entry(QVector<LogEntry>& log, const LogEntry& item,
                                  qint64& replayed_frame) {
    if (log.isEmpty() || item.frame_index >= log.constLast().frame_index) {
        log.append(item);
    } else {
        // upper_bound:相同帧号的新条目排在既有条目之后,保持稳定顺序。
        int lo = 0;
        int hi = log.size();
        while (lo < hi) {
            const int mid = lo + (hi - lo) / 2;
            if (log[mid].frame_index <= item.frame_index) lo = mid + 1;
            else hi = mid;
        }
        log.insert(lo, item);
    }
    if (item.frame_index <= replayed_frame)
        replayed_frame = -1;
}

/// @brief 历史回放:拓扑事件日志 + 信道观测日志 + 逐帧重启采样日志按帧序合并重放到目标帧,生成冻结快照
/// @details 增量回放:replayed_frame 记录快照已覆盖到的帧;目标帧更大时只应用差量区间,
///          目标更小时(或水位失效)全量重建。日志由 record_topo_log_entry 按单调帧序维护,同帧
///          先应用拓扑事件,再信道观测,最后采样重启,与 MainWindow::make_entry 的实时顺序一致,两侧共用同一基线,
///          同一次重启只报一次。NID==0 的日志条目不重放。
/// @param[in] topo_log 拓扑事件日志(帧序)
/// @param[in] channel_log 单跳帧信道观测日志(帧序)
/// @param[in] restart_log 逐帧重启采样日志(帧序)
/// @param[in] target_frame 回放到该帧序号(含)
/// @param[in,out] replayed_frame 回放水位:快照已覆盖到的帧(-1=需全量重建;调用后置为目标帧)
/// @param[out] hist_states 回放快照:重放到目标帧的拓扑(冻结显示用)
void replay_topo_logs(const QVector<TopoLogItem>& topo_log,
                      const QVector<TopoChannelSample>& channel_log,
                      const QVector<TopoRestartSample>& restart_log,
                      qint64 target_frame, qint64& replayed_frame,
                      QHash<quint32, TopoState>& hist_states);

/// @brief 获取/创建供有效 RestartCount 采样使用的 NID 状态。
/// @details 普通 MSDU 可能先于任何拓扑管理事件到达；此时仍需保存重启计数基线。
///          不为 NID==0 或无效计数创建状态，且调用方仍须确认 MSDU 已解析。
/// @return 状态指针；输入不适合采样时返回 nullptr。
TopoState* ensure_restart_sample_state(QHash<quint32, TopoState>& states,
                                       quint32 net_id, int restart_count);

#endif // TOPO_STATE_H
