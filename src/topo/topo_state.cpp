/// @file topo_state.cpp
/// @brief 拓扑状态模型实现(节点/路由累积 + 层级计算)
#include "topo_state.h"
#include "i18n.h"
#include "mac_format.h"  // 48-bit MAC 格式化唯一实现(src/common)
#include "QsLog.h"

namespace {
constexpr int kMaxRecentEventsPerNetwork = 4096;
constexpr int kMaxRecentAnomaliesPerNetwork = 4096;

QString anomaly_key(quint32 net_id, const TopoAnomaly& anomaly) {
    switch (anomaly.kind) {
        case TopoAnomalyKind::MacMultipleTei:
            return QStringLiteral("A|%1").arg(anomaly.mac);
        case TopoAnomalyKind::TeiMultipleMac:
            return QStringLiteral("B|%1").arg(anomaly.tei);
        case TopoAnomalyKind::RestartCountOscillation:
            return QStringLiteral("C|%1|%2").arg(anomaly.tei).arg(anomaly.is_rf ? 1 : 0);
        case TopoAnomalyKind::LinkCountMismatch:
            return QStringLiteral("D|%1").arg(anomaly.tei);
        case TopoAnomalyKind::NidConflict:
            return QStringLiteral("E|%1").arg(net_id);
    }
    return QString();
}

void append_event(QVector<TopoEvent>& events, const TopoEvent& event) {
    if (events.size() == kMaxRecentEventsPerNetwork) events.remove(0);
    events.append(event);
}


/// @brief TopoState 内部生成的事件说明英文注册(与各 parser 的 register_en 解耦,本模块自维护)
struct I18nRegTopoState { I18nRegTopoState() {
    trl::register_en("警告CCO重启过！重启次数 %1→%2",
                     "Warning: CCO has rebooted! Restart count %1→%2");
    trl::register_en("警告STA重启过！STA %1 重启次数 %2→%3",
                     "Warning: STA has rebooted! STA %1 restart count %2→%3");
    trl::register_en("发现列表上行路由变化: %1",
                     "Discover list uplink route change: %1");
    trl::register_en("TEI=%1 下一跳%2→%3", "TEI=%1 next hop %2→%3");
    // 离线复活原因:kind 名沿用 topo_window.cpp 事件类型名的既有英文注册值,
    // 避免重复注册改写已有文案;新增的两项用 Title Case。
    trl::register_en("节点恢复在线（%1）", "Node Back Online (%1)");
    trl::register_en("发现列表", "Discover list");
    trl::register_en("关联确认", "Assoc confirm");
    trl::register_en("关联汇总指示", "Assoc gather indication");
    trl::register_en("关联指示", "Assoc indication");
    trl::register_en("代理变更请求", "Proxy change request");
    trl::register_en("代理变更", "Proxy change");
    trl::register_en("成功率上报", "Success Rate Report");
    trl::register_en("普通数据帧", "Ordinary Data Frame");
    trl::register_en("信道观测", "Channel Observation");
    trl::register_en("断电事件", "Power Off Event");
    trl::register_en("上电事件", "Power On Event");
} } i18n_reg_topo_state;

/// @brief 48-bit MAC 转冒号分隔小端字符串(唯一实现见 common/mac_format.h,本函数仅委托)
inline QString topo_mac_str(quint64 v) { return format_mac_u64(v); }

/// @brief 仅确认发送方已入网的帧可恢复在线;关联请求和离网帧另按状态机处理。
bool provides_online_evidence(TopoEventKind k) {
    switch (k) {
        case TopoEventKind::DiscoverList:
        case TopoEventKind::AssocCnf:
        case TopoEventKind::AssocGatherInd:
        case TopoEventKind::AssocInd:
        case TopoEventKind::ChangeProxyReq:
        case TopoEventKind::ChangeProxyCnf:
        case TopoEventKind::SuccessRate:
        case TopoEventKind::Other:
        case TopoEventKind::ChannelInfo:
            return true;
        default:
            return false;
    }
}

/// @brief 在线证据帧 kind → 复活原因词(与 topo_window 事件类型名保持一致)。
QString online_evidence_name(TopoEventKind k) {
    switch (k) {
        case TopoEventKind::DiscoverList:   return trl::L("发现列表");
        case TopoEventKind::AssocCnf:       return trl::L("关联确认");
        case TopoEventKind::AssocGatherInd: return trl::L("关联汇总指示");
        case TopoEventKind::AssocInd:       return trl::L("关联指示");
        case TopoEventKind::ChangeProxyReq: return trl::L("代理变更请求");
        case TopoEventKind::ChangeProxyCnf: return trl::L("代理变更");
        case TopoEventKind::SuccessRate:    return trl::L("成功率上报");
        case TopoEventKind::ChannelInfo:    return trl::L("信道观测");
        default:                            return trl::L("普通数据帧");
    }
}

/// @brief 离线→在线复活时留一条带原因的事件记录(路由变更表可见)。
/// @details apply() 的状态机翻转与 note_restart_origin 的逐帧复活共用:
///        只在真正 Offline→Online 跃迁时记一条,已在线帧不重复记;
///        kind=证据帧 kind、desc=复活原因、nodes=复活节点,复用 TopoEvent 现有字段,
///        不新增字段、不动序列化;回放重走同一路径,记录与实时一致。
void append_revival_record(QVector<TopoEvent>& events, quint32 nid, TopoEventKind kind,
                           quint16 tei, quint64 mac, quint64 sender_mac,
                           qint64 epoch_ms, qint64 frame_index) {
    TopoEvent re;
    re.nid = nid;
    re.kind = kind;
    re.nodes.append({tei, mac});
    re.sender_mac = sender_mac;
    re.epoch_ms = epoch_ms;
    re.frame_index = frame_index;
    re.desc = trl::L("节点恢复在线（%1）").arg(online_evidence_name(kind));
    append_event(events, re);
}

/// @brief 事件类型 → 状态更新;未明确表示在线/入网的事件不改状态。
/// @details 断电事件明确表示离线(PowerOff→Offline);上电事件只记录,不改状态
///          (PowerOn 不进 provides_online_evidence,绝不复活离线节点)。
bool status_for(TopoEventKind k, NodeStatus& status) {
    if (k == TopoEventKind::AssocReq) {
        status = NodeStatus::OnlineGoing;
        return true;
    }
    if (k == TopoEventKind::PowerOff) {
        status = NodeStatus::Offline;
        return true;
    }
    if (provides_online_evidence(k)) {
        status = NodeStatus::Online;
        return true;
    }
    return false;
}

/// @brief 入网链路类型赋值(用户拍板优先级):
///        1) 关联确认/关联指示/关联汇总指示 的 LinkType 字段权威,赋值即锁定
///        2) 无权威帧时取首个带 link_type 的事件(不锁);link_type==-1 回退物理媒介 e.is_rf
///        3) 都没有保持 0xFF(未定)
///        双模认定(用户 2026-10-28 定):入网链路为无线即双模节点,权威/弱路径全算,只认结果
static void assign_link_type(TopoNode& n, const TopoEvent& e) {
    if (n.link_type_known) return;
    // 权威帧:入网三帧 + 成功的代理变更确认(解析器层仅成功才填 link_type,
    // 失败事件不带 link_type,故此处无需再验 Result)
    const bool authoritative = (e.kind == TopoEventKind::AssocCnf
                                || e.kind == TopoEventKind::AssocInd
                                || e.kind == TopoEventKind::AssocGatherInd
                                || e.kind == TopoEventKind::ChangeProxyCnf);
    if (e.link_type >= 0) {
        if (authoritative) {
            n.link_type = (quint8)e.link_type;
            n.link_type_known = true;    // 权威:赋值即锁定
        } else if (n.link_type == LinkTypeUnknown) {
            n.link_type = (quint8)e.link_type;   // 首个为准,不锁,等权威帧覆盖
        }
    } else if (e.is_rf_known && n.link_type == LinkTypeUnknown) {
        n.link_type = e.is_rf ? LinkTypeRf : LinkTypeHplc;   // 回退物理媒介,不锁
    }
    if (n.link_type == LinkTypeRf) n.rf_capable = true;   // 无线链路即双模,权威/弱路径全算
    if (e.module_type == 1) n.rf_capable = true;   // 双模认定(关联请求模块类型=1,表164/表84),入网请求时刻即可知
    // 注:关联请求事件走 pending 分支,不经此函数;pending 分支内另行认定,晋升时保留。
}

} // namespace

void TopoState::note_anomaly(quint32 net_id, TopoAnomalyKind kind,
                            quint16 tei, quint64 mac, quint64 mac_old,
                            quint16 tei_old, bool is_rf, int from, int to,
                            qint64 epoch_ms, qint64 frame_index) {
    // Merge by category + subject, not changing values. Keep the in-memory projection
    // bounded; the full input frames are retained in SQLite and can rebuild this view.
    TopoAnomaly key_fields;
    key_fields.kind = kind;
    key_fields.mac = mac;
    key_fields.tei = tei;
    key_fields.is_rf = is_rf;
    const QString key = anomaly_key(net_id, key_fields);
    auto it = m_anom_idx.find(key);
    if (it == m_anom_idx.end()) {
        TopoAnomaly a;
        a.kind = kind;
        a.tei = tei;
        a.tei_old = tei_old ? tei_old : tei;
        a.mac = mac;
        a.mac_old = mac_old;
        a.is_rf = is_rf;
        a.trips = 1;
        a.value_from = from;
        a.value_to = to;
        a.first_ms = a.last_ms = epoch_ms;
        a.first_frame = a.last_frame = frame_index;
        if (anomalies.size() >= kMaxRecentAnomaliesPerNetwork) {
            anomalies.remove(0);
            m_anom_idx.clear();
            for (int i = 0; i < anomalies.size(); ++i)
                m_anom_idx.insert(anomaly_key(net_id, anomalies.at(i)), i);
        }
        anomalies.append(a);
        m_anom_idx.insert(key, anomalies.size() - 1);
        return;
    }
    TopoAnomaly& a = anomalies[it.value()];
    ++a.trips;
    a.value_from = from;
    a.value_to = to;
    // A/B 的 tei/tei_old 是"冲突两端":合并时必须一起更新,否则同一 MAC 在 TEI 3↔5
    // 反复冲突时 tei 会停在最早那个值,表格显示成 "5→5" 这种自指。
    // C/D 的 tei 是主体(振荡/差异所在的节点),保持首次出现的值不变。
    if (kind == TopoAnomalyKind::MacMultipleTei || kind == TopoAnomalyKind::TeiMultipleMac)
        a.tei = tei;
    if (mac) a.mac = mac;
    if (mac_old) a.mac_old = mac_old;
    if (tei_old) a.tei_old = tei_old;
    a.last_ms = epoch_ms;
    a.last_frame = frame_index;
}

namespace {
/// @brief 两链路计数比较(D)的新鲜度窗口
/// @details 4-bit 重启次数是慢变量:某条链路长时间无帧时其值早已不代表当前状态。
///          不做新鲜度判断会拿"载波最新值"和"无线很久以前的值"比,单介质运行/无线
///          长时间静默会持续假报 D,且恢复一致也无从清除。窗口内才比较。
constexpr qint64 kLinkCompareWindowMs = 30000;
}  // namespace

TopoState* ensure_restart_sample_state(QHash<quint32, TopoState>& states,
                                       quint32 net_id, int restart_count) {
    if (net_id == 0 || restart_count < 0 || restart_count == kRestartCountInvalid)
        return nullptr;
    auto it = states.find(net_id);
    if (it == states.end())
        it = states.insert(net_id, TopoState());
    it->nid = net_id;
    return &it.value();
}

void replay_topo_logs(const QVector<TopoLogItem>& topo_log,
                      const QVector<TopoChannelSample>& channel_log,
                      const QVector<TopoRestartSample>& restart_log,
                      qint64 target_frame, qint64& replayed_frame,
                      QHash<quint32, TopoState>& hist_states) {
    // 点到更早的帧,或新增记录覆盖已回放范围使水位失效(初始 -1):快照从零重建。
    // 注意:水位失效时必须清快照,否则从头重放会 double-apply(事件表翻倍)。
    if (replayed_frame < 0 || target_frame < replayed_frame) {
        hist_states.clear();
        replayed_frame = -1;
    }
    // 二分定位水位之后的第一条日志(三条日志都严格按帧序追加)
    int topo_i = 0, topo_hi = topo_log.size();
    while (topo_i < topo_hi) {
        const int mid = topo_i + (topo_hi - topo_i) / 2;
        if (topo_log[mid].frame_index <= replayed_frame) topo_i = mid + 1;
        else topo_hi = mid;
    }
    int channel_i = 0, channel_hi = channel_log.size();
    while (channel_i < channel_hi) {
        const int mid = channel_i + (channel_hi - channel_i) / 2;
        if (channel_log[mid].frame_index <= replayed_frame) channel_i = mid + 1;
        else channel_hi = mid;
    }
    int restart_i = 0, restart_hi = restart_log.size();
    while (restart_i < restart_hi) {
        const int mid = restart_i + (restart_hi - restart_i) / 2;
        if (restart_log[mid].frame_index <= replayed_frame) restart_i = mid + 1;
        else restart_hi = mid;
    }
    // 三条日志按帧序合并重放:同帧先应用拓扑事件,再信道观测,最后采样重启,与
    // MainWindow::make_entry 的实时顺序一致(事件侧先,信道侧中,逐帧侧后)。两侧共用同一基线,
    // 同一次重启只报一次;逐帧采样只建基线的首帧也必须重放,否则后一帧的变化在快照里报不出来。
    // 不能把重启事件本身也 append 进拓扑事件日志:回放 apply() 会从基线重新推导一次
    // 重启,同一事件会被记两遍。
    while (true) {
        const bool has_topo = topo_i < topo_log.size()
            && topo_log[topo_i].frame_index <= target_frame;
        const bool has_channel = channel_i < channel_log.size()
            && channel_log[channel_i].frame_index <= target_frame;
        const bool has_restart = restart_i < restart_log.size()
            && restart_log[restart_i].frame_index <= target_frame;
        if (!has_topo && !has_channel && !has_restart) break;
        // 同帧取最早者;帧号相等时拓扑事件优先,其次信道观测,最后逐帧采样。
        if (has_topo
            && (!has_channel || topo_log[topo_i].frame_index <= channel_log[channel_i].frame_index)
            && (!has_restart || topo_log[topo_i].frame_index <= restart_log[restart_i].frame_index)) {
            const TopoLogItem& it = topo_log[topo_i++];
            // 网络标识符不完整(NID==0)的旧日志事件不回放(不建空状态)
            if (it.event.nid == 0) continue;
            hist_states[it.event.nid].apply(it.event);
        } else if (has_channel
                   && (!has_restart || channel_log[channel_i].frame_index <= restart_log[restart_i].frame_index)) {
            const TopoChannelSample& s = channel_log[channel_i++];
            // 网络标识符不完整(NID==0)的观测不重放(不建空状态),与实时口径一致;
            // 实时侧无状态时跳过(不建占位),回放同样只对已有快照状态应用。
            if (s.net_id == 0) continue;
            auto hit = hist_states.find(s.net_id);
            if (hit == hist_states.end()) continue;
            hit->apply_channel_info(s.reporter_tei, s.event);
        } else {
            const TopoRestartSample& s = restart_log[restart_i++];
            // 网络标识符不完整(NID==0)的采样不重放(不建空状态),与实时口径一致
            if (s.net_id == 0) continue;
            TopoState& hs = hist_states[s.net_id];
            hs.nid = s.net_id;
            // 采样 kind 一并传入:回放里复活原因须与实时一致(否则管理帧复活会被错记成普通数据帧)。
            hs.note_restart_origin(s.net_id, s.src_tei, s.src_mac, s.restart_count,
                                   s.epoch_ms, s.frame_index, s.is_rf, s.is_rf_known,
                                   s.frame_kind);
        }
    }
    replayed_frame = target_frame;
}

bool TopoState::note_restart_count(quint16 tei, bool is_rf, int rc,
                                   qint64 epoch_ms, qint64 frame_index) {
    if (!tei || tei == kTeiInvalid) return false;
    if (rc < 0 || rc == kRestartCountInvalid) return false;   // 无该字段(单跳简头等)
    bool touched = false;
    const quint32 key = (quint32(tei) << 1) | (is_rf ? 1u : 0u);
    auto it = m_rc_track.find(key);
    if (it == m_rc_track.end()) {
        RcTrack t;
        t.prev = rc;
        t.last_ms = epoch_ms;
        t.seen.insert(rc);
        m_rc_track.insert(key, t);
    } else {
        RcTrack& t = it.value();
        const int prev = t.prev;
        t.last_ms = epoch_ms;              // 新鲜度:每次采样都刷新(值与上次相同也算新鲜)
        if (prev != rc) {
            t.prev = rc;
            // 4-bit 计数器的"回绕"(…→14→15→0)与"差 1 的双实体振荡"(9/10、11/10)在单步上
            // 无法区分,故不用单步 +1 做豁免,而用**连续前进步数** fwd_run 判回绕:
            //   回到出现过的旧值 ⇒ 记一次往返(用户口径:首变不计);
            //   唯一例外:连续前进 ≥2 步之后回到的值,视为 4-bit 计数器正常回绕,静默通过。
            // 新值一律入 seen(即使它是 forward),否则"只经规整递增到达过的值"永远无法成为
            // 可返回的旧值 —— 那会把 9/10 这类差 1 振荡整段吞掉。
            // 已知边界:…→15(非前进)之后单独一个 15→0,fwd_run=0 会被判成"回到旧值"而记录;
            //   抓包丢帧时无法区分正常回绕与跳变,宁可报。
            const bool forward = (rc == ((prev + 1) & 0x0F));
            if (t.seen.contains(rc)) {
                if (forward && t.fwd_run >= 2) {
                    // 连续前进后的回绕:不记
                } else {
                    note_anomaly(nid, TopoAnomalyKind::RestartCountOscillation, tei, mac_of(tei), 0, tei,
                                 is_rf, prev, rc, epoch_ms, frame_index);
                    touched = true;
                }
            } else {
                t.seen.insert(rc);
            }
            t.fwd_run = forward ? t.fwd_run + 1 : 0;
        }
    }
    // 两链路计数不同(用户口径):同一 TEI 载波与无线的重启次数各自计数,
    // 两个介质都已有取值且不相等时记一条(只提示,不判重启)。
    // 防刷屏:同一 (载波rc, 无线rc) 组合只计一次;恢复一致后清除,再不同仍可记。
    const quint32 other_key = (quint32(tei) << 1) | (is_rf ? 0u : 1u);
    const auto oit = m_rc_track.constFind(other_key);
    if (oit != m_rc_track.constEnd() && oit.value().prev >= 0) {
        // 新鲜度门:两侧最近采样时间相差超过窗口 ⇒ 不比较(也不清 D 状态,避免"陈旧值
        // 碰巧相等"把正在观察的差异误判为已恢复)
        const qint64 dt = epoch_ms - oit.value().last_ms;
        if (dt > kLinkCompareWindowMs || dt < -kLinkCompareWindowMs)
            return touched;
        const int plc_rc = is_rf ? oit.value().prev : rc;
        const int rf_rc  = is_rf ? rc : oit.value().prev;
        if (plc_rc != rf_rc) {
            const QPair<int, int> pair(plc_rc, rf_rc);
            const auto pit = m_link_pair.constFind(tei);
            if (pit == m_link_pair.constEnd() || pit.value() != pair) {
                note_anomaly(nid, TopoAnomalyKind::LinkCountMismatch, tei, mac_of(tei), 0, tei,
                             false, plc_rc, rf_rc, epoch_ms, frame_index);
                m_link_pair.insert(tei, pair);
                touched = true;
            }
        } else {
            m_link_pair.remove(tei);   // 两链路恢复一致
        }
    }
    return touched;
}

bool TopoState::index_mac(quint32 net_id, quint16 tei, quint64 mac, qint64 epoch_ms, qint64 frame_index) {
    if (!net_id || !mac || !tei || tei >= kTeiBroadcast) return false;
    // TEI=1 映射到达即判一次 CCO 身份:第二个不同的 CCO MAC 在此记 NID 冲突
    // (无重启计数的帧也走这里,D17u-n);身份判定与冲突记录见 resolve_is_cco。
    if (tei == kTeiCco)
        resolve_is_cco(net_id, kTeiCco, mac, nullptr, epoch_ms, frame_index);
    const NidMacKey key = nid_mac_key(net_id, mac);
    const quint16 old_tei = mac_to_tei.value(key,
        m_cco_macs.contains(key) ? kTeiCco : quint16(0));
    const bool role_conflict = old_tei && old_tei != tei
        && (old_tei == kTeiCco || tei == kTeiCco);
    bool touched = false;
    // CCO/STA 共用 MAC 始终算冲突(即使旧节点离线);每次反向切换继续累加 trips。
    // 当前帧/管理事件提供的有效 TEI 覆盖旧身份,不能再由 CCO 记忆反向覆盖它。
    if (old_tei && old_tei != tei) {
        auto nit = nodes.find(old_tei);
        const bool has_old_node = nit != nodes.end() && nit->mac == mac;
        if (role_conflict || (has_old_node && nit->status != NodeStatus::Offline)) {
            note_anomaly(net_id, TopoAnomalyKind::MacMultipleTei, tei, mac, 0, old_tei,
                         has_old_node && nit->is_rf, int(old_tei), int(tei), epoch_ms, frame_index);
            touched = true;
        }
        if (has_old_node) nit->mac = 0;
        if (role_conflict) {
            // 角色变更只建新基线,不把两种身份/实体的计数差当作重启。
            m_cco_restart_count.remove(key);
            m_sta_restart_count.remove(key);
        }
    }
    // 同一 TEI 换 MAC:保留既有的在线冲突提示,清掉旧 MAC 索引和身份记忆。
    auto nit = nodes.find(tei);
    if (nit != nodes.end()) {
        const quint64 old_mac = nit->mac;
        if (old_mac && old_mac != mac) {
            if (nit->status != NodeStatus::Offline) {
                note_anomaly(net_id, TopoAnomalyKind::TeiMultipleMac, tei, mac, old_mac, tei,
                             nit->is_rf, 0, 0, epoch_ms, frame_index);
                touched = true;
            }
            const NidMacKey old_key = nid_mac_key(net_id, old_mac);
            auto oit = mac_to_tei.find(old_key);
            if (oit != mac_to_tei.end() && oit.value() == tei) {
                mac_to_tei.erase(oit);
                m_cco_macs.remove(old_key);
                m_cco_restart_count.remove(old_key);
                m_sta_restart_count.remove(old_key);
            }
        }
    }
    mac_to_tei[key] = tei;
    m_offline_macs.remove(key);
    // 这里只学习最新身份,不改变节点在线状态。事件路径随后按事件语义更新状态;
    // 逐帧路径只允许非请求帧作为在线证据,由 note_restart_origin 单独处理。
    if (nit != nodes.end()) nit->mac = mac;
    if (tei == kTeiCco) {
        m_cco_macs.insert(key);
        if (nid == net_id) cco_mac = mac;
    } else {
        m_cco_macs.remove(key);
        if (nid == net_id && cco_mac == mac) cco_mac = 0;
    }
    return touched;
}

bool TopoState::remove_node_by_mac(quint32 net_id, quint64 mac) {
    if (!mac) return false;
    const auto iit = mac_to_tei.find(nid_mac_key(net_id, mac));
    if (iit == mac_to_tei.end()) return false;
    const quint16 old_tei = iit.value();
    if (old_tei == kTeiCco) return false;  // CCO 永不移除
    const auto nit = nodes.find(old_tei);
    if (nit == nodes.end() || nit.value().mac != mac) {
        mac_to_tei.erase(iit);  // 坏索引:删映射(与离线路径一致的回退策略)
        return false;
    }
    nodes.erase(nit);
    mac_to_tei.erase(iit);
    comm_rates.remove(old_tei);  // 旧 TEI 的成功率残留一并清理
    return true;
}

NidMacKey TopoState::nid_mac_key(quint32 net_id, quint64 mac) {
    // NID 用完整 quint32(24bit 全取)、MAC 取低 48bit;不截断,不串键。
    return NidMacKey{net_id, mac & 0xFFFFFFFFFFFFULL};
}

bool TopoState::resolve_is_cco(quint32 net_id, quint16 src_tei, quint64 mac,
                               const TopoEvent* ev, qint64 epoch_ms, qint64 frame_index) {
    bool cco = false;
    // 有效源 TEI 是当前帧身份,优先于历史记忆。0/广播/无效 TEI 不提供角色证据。
    if (src_tei && src_tei < kTeiBroadcast) {
        cco = (src_tei == kTeiCco);
    } else if (mac) {
        const NidMacKey key = nid_mac_key(net_id, mac);
        if (!m_offline_macs.contains(key)) {
            const quint16 tei = mac_to_tei.value(key, quint16(0));
            if (tei && tei != kTeiCco) {
                // 已映射到某 STA TEI:不是 CCO。
            } else if (m_cco_macs.contains(key)) {
                cco = true;
            } else if (tei == kTeiCco) {
                // 离网保留索引供历史展示/后续冲突比较,但不能用离线索引回灌身份记忆。
                const auto it = nodes.constFind(tei);
                if (it == nodes.constEnd() || it->mac != mac || it->status != NodeStatus::Offline)
                    cco = true;
            }
        }
    }
    // apply() 在采样前已学习当前事件的 CCO/TEI→MAC 信息;不再拿旧事件字段覆盖新索引。
    // 发现列表缺源 MAC 时仍按该 NID 的无 MAC CCO 主体采样,不落到首个 STA。
    if (!cco && !mac && ev && ev->kind == TopoEventKind::DiscoverList) cco = true;
    if (cco && mac) {
        const NidMacKey key = nid_mac_key(net_id, mac);
        if (!m_cco_macs.contains(key)) {
            quint64& first_mac = m_first_cco_mac[net_id];
            if (first_mac == 0) {
                first_mac = mac;
            } else if (first_mac != mac) {
                // 同一 NID 下第二个不同的 CCO MAC 是 NID 冲突,仍记住独立身份,
                // 但绝不把它与已有设备合并(异常行按 NID 合并,trips 按新 MAC 累加)。
                note_anomaly(net_id, TopoAnomalyKind::NidConflict, 0, mac, first_mac, 0,
                             false, 0, 0, epoch_ms, frame_index);
            }
            m_cco_macs.insert(key);  // 身份记忆按 (NID, MAC) 独立保留
        }
    }
    return cco;
}

quint64 TopoState::canonical_cco_mac(quint32 net_id, quint64 subject,
                                     const TopoEvent& proto) const {
    // 1. 当前主体 MAC:已判 CCO 且带源 MAC 时,源 MAC 就是 cco_mac。
    if (subject) return subject;
    // 2. 当前事件的 cco_mac 字段(apply() 事件侧:发现列表等常带 cco_mac)。
    if (proto.cco_mac) return proto.cco_mac;
    // 3. 多个 CCO MAC 已构成 NID 冲突时，无 MAC 样本不能借用单值 cco_mac 猜身份。
    quint64 found = 0;
    int count = 0;
    for (const NidMacKey& k : m_cco_macs) {
        if (k.nid == net_id && k.mac != 0) {
            found = k.mac;
            ++count;
        }
    }
    if (count > 1) return 0;
    // 4. 本状态已学到的 cco_mac(apply() 里 e.cco_mac 到达后写入成员)，仅在无身份冲突时使用。
    if (cco_mac) return cco_mac;
    // 5. 身份记忆里本 NID 唯一的那条(逐帧侧不写 cco_mac 成员,只能靠记忆找回)。
    if (count == 1) return found;
    return 0;  // 全部未知或身份冲突:无 MAC 样本独立使用 (NID, 0) 键。
}

bool TopoState::note_restart_change(quint32 net_id, quint64 subject, bool is_cco, int rc,
                                    qint64 epoch_ms, qint64 frame_index, const TopoEvent& proto) {
    // CCO 允许"无 MAC 主体"(subject==0 ⇒ 暂用占位键 (NID, 0));STA 必须有 MAC
    if ((!subject && !is_cco) || rc < 0 || rc == kRestartCountInvalid)
        return false;   // 0xFF=无该字段(单跳简头等)
    // CCO 基线按 (NID, MAC) 独立；缺 MAC 时用 (NID, 0) 专属占位键。
    // 仅在 NID 下尚未出现多个 CCO MAC 时，单一已知身份可承接旧占位基线；出现 NID 冲突后，
    // 无 MAC 样本留在占位键，已知 MAC 样本只读写自身基线。
    // STA 仍按 (NID, 主体 MAC) 分键(多 STA 共存,必须分主体)。
    quint64 key_subject = subject;
    if (is_cco) {
        key_subject = canonical_cco_mac(net_id, subject, proto);
        if (key_subject != 0) {
            const NidMacKey placeholder_key = nid_mac_key(net_id, 0);
            auto pit = m_cco_restart_count.find(placeholder_key);
            if (pit != m_cco_restart_count.end()) {
                int known_mac_count = 0;
                for (const NidMacKey& cco_key : m_cco_macs)
                    if (cco_key.nid == net_id && cco_key.mac != 0) ++known_mac_count;
                if (known_mac_count <= 1) {
                    const NidMacKey canon_key = nid_mac_key(net_id, key_subject);
                    if (!m_cco_restart_count.contains(canon_key))
                        m_cco_restart_count[canon_key] = pit.value();
                    m_cco_restart_count.erase(pit);
                }
            }
        }
    }
    const NidMacKey key = nid_mac_key(net_id, key_subject);
    QHash<NidMacKey, int>& base = is_cco ? m_cco_restart_count : m_sta_restart_count;
    const auto it = base.constFind(key);
    const bool changed = (it != base.constEnd() && it.value() != rc);
    const int prev = (it == base.constEnd()) ? -1 : it.value();
    base[key] = rc;   // 首次见到只建基线不报(与既有口径一致)
    if (!changed) return false;
    TopoEvent re = proto;
    re.nid = net_id;
    re.kind = is_cco ? TopoEventKind::CcoRestart : TopoEventKind::StaRestart;
    re.restart_count = rc;
    re.sender_mac = subject;  // 保留真实源 MAC(已知时即 cco_mac,未知时为 0),不再归一
    re.epoch_ms = epoch_ms;
    re.frame_index = frame_index;
    re.desc = is_cco
                  ? trl::L("警告CCO重启过！重启次数 %1→%2").arg(prev).arg(rc)
                  : trl::L("警告STA重启过！STA %1 重启次数 %2→%3")
                        .arg(topo_mac_str(subject)).arg(prev).arg(rc);
    append_event(events, re);
    return true;
}

bool TopoState::note_restart_origin(quint32 net_id, quint16 src_tei, quint64 src_mac, int rc,
                                    qint64 epoch_ms, qint64 frame_index,
                                    bool is_rf, bool is_rf_known, TopoEventKind frame_kind,
                                    bool* did_revive) {
    if (did_revive) *did_revive = false;
    // 网络标识符不完整(NID==0,两规约里 0 均无效)不采样:不建基线、不报重启。
    if (net_id == 0) return false;
    // 先判身份再学映射:新 CCO MAC 首次出现要在进 m_cco_macs 前记 NID 冲突;
    // 若先调 index_mac 学习,当前 MAC 已进身份记忆,冲突守卫会误判为已知身份而漏记。
    // resolve 不依赖本帧学习结果:有效源 TEI 直接定角色,无 TEI 时只读旧记忆。
    const bool is_cco = resolve_is_cco(net_id, src_tei, src_mac, nullptr,
                                       epoch_ms, frame_index);
    // 即使本帧没有重启计数,当前有效源 TEI/MAC 仍应覆盖旧角色并记录身份冲突。
    const bool conflict = index_mac(net_id, src_tei, src_mac, epoch_ms, frame_index);
    // 关联请求只表示正在申请入网,不能复活节点;代理变更请求来自已入网 STA,可作为
    // 在线证据。离网指示是明确的离线证据;关联确认、成功率及普通数据帧也可恢复节点。
    if (provides_online_evidence(frame_kind) && src_tei && src_mac) {
        auto nit = nodes.find(src_tei);
        if (nit != nodes.end() && nit->mac == src_mac) {
            // 离线→在线才是复活:留一条带原因的事件记录(路由变更表可见),
            // 只翻状态不留痕,回放与实时都会丢原因。已在线帧只更新 last_seen,不重复记。
            const bool revived = (nit->status == NodeStatus::Offline);
            nit->status = NodeStatus::Online;
            nit->last_seen_ms = epoch_ms;
            if (revived) {
                append_revival_record(events, net_id, frame_kind, src_tei, src_mac,
                                      src_mac, epoch_ms, frame_index);
                if (did_revive) *did_revive = true;
            }
        }
    }
    if (rc < 0 || rc == kRestartCountInvalid) return conflict;
    // 当前有效源 TEI 优先;无有效源 TEI 时才回退本 NID 最近身份。
    // STA 必须有 MAC 才能定位主体;唯一例外:CCO 帧缺源 MAC ⇒ 归本 NID 的 CCO 基线(subject=0)
    if (!src_mac && !is_cco) return conflict;
    TopoEvent proto;
    proto.is_rf = is_rf;
    proto.is_rf_known = is_rf_known;
    return note_restart_change(net_id, src_mac, is_cco, rc, epoch_ms, frame_index, proto) || conflict;
}

void TopoState::apply(const TopoEvent& e) {
    // 网络标识符不完整(NID==0,两规约里 0 均无效)的事件不进拓扑:不学节点、不记事件。
    if (e.nid == 0) return;
    nid = e.nid;
    NodeStatus event_status = NodeStatus::OnlineGoing;
    const bool has_event_status = status_for(e.kind, event_status);
    // 南网发现列表上行路由变化检测:若 UpRoute 条目的下一跳与当前父节点
    // 不同,则为拓扑变化,入表记录。必须在下方状态更新前判断。
    bool up_route_changed = false;
    QString up_route_desc;
    if (e.kind == TopoEventKind::DiscoverList && !e.up_routes.isEmpty()) {
        // 去重:同一 TEI 取最后一个 next_hop(最新值);避免同一帧多条目重复描述
        QHash<quint16, quint16> dedup;
        for (const auto& ur : e.up_routes)
            dedup[ur.first] = ur.second;
        QStringList changes;
        for (auto it = dedup.constBegin(); it != dedup.constEnd(); ++it) {
            const quint16 tei = it.key();
            const quint16 new_hop = it.value();
            const auto nit = nodes.find(tei);
            const quint16 old_parent = (nit == nodes.end()) ? 0 : nit.value().parent_tei;
            if (nit == nodes.end() || old_parent != new_hop) {
                up_route_changed = true;
                changes.append(trl::L("TEI=%1 下一跳%2→%3")
                    .arg(tei)
                    .arg(old_parent ? QString::number(old_parent) : QStringLiteral("-"))
                    .arg(new_hop));
                // 更新拓扑:父节点改为新的下一跳
                TopoNode& node = nodes[tei];
                node.tei = tei;
                node.parent_tei = new_hop;
                node.last_seen_ms = e.epoch_ms;
                if (node.status == NodeStatus::Offline)
                    append_revival_record(events, e.nid, TopoEventKind::DiscoverList,
                                          tei, node.mac, e.sender_mac,
                                          e.epoch_ms, e.frame_index);
                node.status = NodeStatus::Online;
            }
        }
        if (up_route_changed)
            up_route_desc = trl::L("发现列表上行路由变化: %1").arg(changes.join(QStringLiteral("; ")));
    }
    // 首次识别:记录该 NID 第一次出现的帧序号与时间戳(供 NID 下拉框区分新旧网络)
    if (first_seen_frame < 0) {
        first_seen_frame = e.frame_index;
        first_seen_ms = e.epoch_ms;
    }
    // CCO(TEI=1):根节点,父=0,始终已入网
    if (e.cco_mac) {
        cco_mac = e.cco_mac;
        index_mac(e.nid, 1, e.cco_mac, e.epoch_ms, e.frame_index);
        TopoNode& cco = nodes[1];
        cco.tei = 1;
        cco.mac = e.cco_mac;
        cco.parent_tei = 0;
        if (cco.status == NodeStatus::Offline)
            append_revival_record(events, e.nid, e.kind, 1, e.cco_mac, e.sender_mac,
                                  e.epoch_ms, e.frame_index);
        cco.status = NodeStatus::Online;
        cco.last_seen_ms = e.epoch_ms;
        // 方案②:仅首次已知介质写入并锁定(RF STA 事件不得翻转 CCO 介质;
        // 事件侧 is_rf_known 守卫仍保留,未知介质事件不覆盖)
        if (e.is_rf_known && !cco.is_rf_known) { cco.is_rf = e.is_rf; cco.is_rf_known = true; }
        // 双模认定(用户 2026-10-28 定):CCO 自己发过 RF 帧即双模;逐帧路径
        // (mainwindow note_rf_capable,src_tei==kTeiCco)已覆盖 CCO 发 RF 数据/信标,
        // 这里补事件帧路径(发送方 MAC==CCO MAC 的 RF 事件帧)
        if (e.is_rf_known && e.is_rf && e.sender_mac && e.sender_mac == e.cco_mac)
            cco.rf_capable = true;
    }
    // TEI→MAC 学习对(节点出现,按事件类型定入网状态)
    for (const TeiMacPair& p : e.nodes) {
        if (!p.mac) continue;
        if (p.tei == 0) {
            // 只有关联请求能创建 pending;其他事件的 TEI=0 不代表正在入网。
            if (e.kind != TopoEventKind::AssocReq) continue;
            // 正在入网(TEI 未分配):按 MAC 暂存 pending(关联请求阶段)。
            // 该 MAC 若已在拓扑中(设备重上电再次发起关联):先移除旧节点,
            // 再绘制当前"入网中"状态,避免同一 MAC 以"在线"+"入网中"
            // 两种状态同时出现在拓扑图中。
            remove_node_by_mac(e.nid, p.mac);
            TopoNode n;
            n.tei = 0;
            n.mac = p.mac;
            n.status = NodeStatus::OnlineGoing;
            n.last_seen_ms = e.epoch_ms;
            if (e.is_rf_known) { n.is_rf = e.is_rf; n.is_rf_known = true; }
            // 双模认定(关联请求模块类型=1,表164/表84):入网请求时刻即可知。
            // 关联请求走 pending 分支,不经 assign_link_type,故此处直接认定。
            if (e.module_type == 1) n.rf_capable = true;
            pending[p.mac] = n;
            continue;
        }
        index_mac(e.nid, p.tei, p.mac, e.epoch_ms, e.frame_index);
        TopoNode& n = nodes[p.tei];
        n.tei = p.tei;
        n.mac = p.mac;
        if (has_event_status) {
            if (n.status == NodeStatus::Offline && event_status == NodeStatus::Online)
                append_revival_record(events, e.nid, e.kind, p.tei, p.mac, e.sender_mac,
                                      e.epoch_ms, e.frame_index);
            n.status = event_status;
        }
        n.last_seen_ms = e.epoch_ms;
        if (e.is_rf_known) { n.is_rf = e.is_rf; n.is_rf_known = true; }
        assign_link_type(n, e);
        // 关联请求阶段已认定的双模标记随节点晋升保留(pending 节点本身将被移除)。
        auto pit = pending.constFind(p.mac);
        if (pit != pending.constEnd() && pit->rf_capable) n.rf_capable = true;
        // 若该 MAC 之前正在入网(关联请求),现已分配到 TEI → 移除 pending。
        // pending 的 key 恒等于 TopoNode.mac(写入处 pending[p.mac]=n),等价于哈希直接删除。
        pending.remove(p.mac);
    }
    // ---------------------------------------------------------------------
    // 重启检测(方案 B:采样点从「发现列表/关联请求」白名单扩到全帧;基线按 (NID, 主体 MAC) 分键)
    // 依据与口径:
    //  - 重启次数是 MAC 帧头的 4-bit 计数器(国网 MSDU 头 / 南网 MAC 帧头),任何变化即视为重启,
    //    天然处理 15→0 回绕 —— 判据未改,只扩采样点;restart_count<0(0xFF 哨兵:单跳简头等
    //    无该字段的帧)天然被排除。
    //  - 旧实现只在 DiscoverList 上采 CCO、只在 AssocReq 上采 STA,其它管理帧携带的计数变化
    //    完全看不到(实测漏报),故去掉事件种类白名单。
    //  - 先学习当前事件的 CCO/节点映射,再判主体角色,防新 STA 仍用旧 CCO 基线。
    //    当前有效 TEI 优先于历史记忆;角色切换已由 index_mac 记录冲突并重建基线。
    //  - 分键 = nid_mac_key(NID, 主体 MAC):CCO 旧基线是单一全局值(多 NID 互相踩),
    //    STA 旧基线只有 MAC(不同 NID 下同 MAC 会串);CCO 在 note_restart_change 里
    //    归一到 (NID, 已知 cco_mac)(未知时暂用 (NID, 0) 占位,已知后迁移,防基线裂成两条)。
    //  - 已知代价:事件量上升(以前漏报的真实重启现在会报),且 CcoRestart/StaRestart 是插件
    //    API 事件(plugin/host/js_backend.cpp:47、lua_backend.cpp:65 → ccoRestart/staRestart),
    //    Lua/JS 侧若按事件条数统计会变化。
    //  - 拓扑状态不清空:新的关联请求可能先于发现列表到达,清空会误删已重建的正确状态。
    // ---------------------------------------------------------------------
    if (e.restart_count >= 0) {
        quint64 subject = e.sender_mac;
        bool is_cco = false;
        if (subject) {
            // 有源 MAC:身份判定统一走 resolve_is_cco(事件侧无 TEI 信息 ⇒ 传 0)
            is_cco = resolve_is_cco(e.nid, quint16(0), subject, &e,
                                    e.epoch_ms, e.frame_index);
        } else {
            // 无源 MAC:先看能否按"无 MAC 的 CCO"归属(发现列表 = CCO 广播,实测缺陷 M2:
            // 旧实现直接回落 nodes 首条,把 CCO 的重启次数记到发现列表里第一个 STA 头上)
            is_cco = resolve_is_cco(e.nid, quint16(0), 0, &e,
                                    e.epoch_ms, e.frame_index);
            if (!is_cco) {
                // 既有口径保留(AssocReq 等:直接关联时主体即发送方):回落本事件 nodes 首条,
                // 再对该主体做一次身份判定(它可能就是 CCO 条目)
                for (const TeiMacPair& p : e.nodes) {
                    if (p.mac) { subject = p.mac; break; }
                }
                if (subject) is_cco = resolve_is_cco(e.nid, quint16(0), subject, &e,
                                                     e.epoch_ms, e.frame_index);
            }
        }
        if (subject || is_cco) {
            note_restart_change(e.nid, subject, is_cco, e.restart_count,
                                e.epoch_ms, e.frame_index, e);
        }
    }
    // 路由关系(子 TEI → 父/代理 TEI)
    for (const auto& r : e.routes) {
        if (!r.first) continue;
        TopoNode& n = nodes[r.first];
        n.tei = r.first;
        n.parent_tei = r.second;
        if (has_event_status) {
            if (n.status == NodeStatus::Offline && event_status == NodeStatus::Online)
                append_revival_record(events, e.nid, e.kind, r.first, n.mac, e.sender_mac,
                                      e.epoch_ms, e.frame_index);
            n.status = event_status;
        }
        n.last_seen_ms = e.epoch_ms;
        if (e.is_rf_known) { n.is_rf = e.is_rf; n.is_rf_known = true; }
        assign_link_type(n, e);
    }
    // 路由表(表55/56)每节点入网链路类型:仅 AssocCnf/AssocInd/AssocGatherInd 跑(只有它们填 node_link_types 字段);
    // 代理变更确认的权威性走 assign_link_type 一路,不经此循环;逐个赋值+锁定
    if (e.kind == TopoEventKind::AssocCnf || e.kind == TopoEventKind::AssocInd
        || e.kind == TopoEventKind::AssocGatherInd) {
        for (const auto& pr : e.node_link_types) {
            const quint16 tei = pr.first;
            if (!tei || tei == kTeiInvalid) continue;
            TopoNode& n = nodes[tei];
            n.tei = tei;
            if (n.link_type_known) continue;   // 已锁定不覆盖
            n.link_type = pr.second;
            n.link_type_known = true;
            if (n.link_type == LinkTypeRf) n.rf_capable = true;   // 双模认定:无线链路即双模
        }
    }
    // 载波发现列表(0x0055 表77)与代理站点通信成功率:独立于 RFDL proxy_* 与 0x005E comm_rates;
    // 值 0-100(超出无效=-1),任一有效即置 comm_rate_known;按发送方(sta_tei,即 e.nodes 单条目)落节点
    if (e.kind == TopoEventKind::DiscoverList
        && (e.proxy_comm_rate >= 0 || e.proxy_down_comm_rate >= 0 || e.min_comm_rate >= 0)) {
        for (const auto& p : e.nodes) {
            TopoNode& n = nodes[p.tei];
            n.proxy_comm_rate = e.proxy_comm_rate;
            n.proxy_down_comm_rate = e.proxy_down_comm_rate;
            n.min_comm_rate = e.min_comm_rate;
            n.comm_rate_known = true;
        }
    }
    // 邻居信号强度(RF 发现列表信道信息):仅更新已存在节点,不为纯 RSSI 建占位
    for (const auto& r : e.rssi_entries) {
        auto nit = nodes.find(r.first);
        if (nit == nodes.end()) continue;
        nit.value().rssi_dbm = r.second;
        nit.value().rssi_known = true;
    }
    // 子站点表(代理变更确认位图 0x003B):全库仅该 MMe 填 child_teis(见 nw_2026_msdu_parser
    // ChangeProxyBitmapCnf 的 bm_ok 分支);kind 门防未来别的帧同时填 child_teis+link_type
    // 时误建节点/误设接入方式
    const bool child_authoritative = (e.kind == TopoEventKind::ChangeProxyCnf);
    if (child_authoritative && e.link_type >= 0) {
        for (quint16 ctei : e.child_teis) {
            if (!ctei || ctei == kTeiInvalid) continue;   // 0=根(CCO 自身);0xFFFF=未知,均不建节点
            TopoNode& n = nodes[ctei];
            n.tei = ctei;
            if (n.status == NodeStatus::Offline)
                append_revival_record(events, e.nid, TopoEventKind::ChangeProxyCnf,
                                      ctei, n.mac, e.sender_mac,
                                      e.epoch_ms, e.frame_index);
            n.status = NodeStatus::Online; // 成功确认中的子 TEI 位图是当前在网证据
            n.last_seen_ms = e.epoch_ms;
            // 帧内链路类型:仅首次写入并锁定(方案②,后续事件不翻转);last_seen 为 0 时的补写不受影响
            if (!n.is_rf_known) { n.is_rf = (e.link_type == LinkTypeRf); n.is_rf_known = true; }
        }
    }
    // 断电事件上报(位图方式,表340):按 TEI 标记已存在节点离线,与 LeaveInd 同款
    // 处理(清 pending、清 CCO 身份记忆、记 m_offline_macs);MAC 未知(位图只给 TEI),
    // 故不走下方 e.leaves 循环(地址方式的电表 MAC 在解析层已填 leaves,走那条)。
    // 不存在的 TEI 直接跳过,不凭空建节点;上电事件(PowerOn)不改状态,不进此块。
    if (e.kind == TopoEventKind::PowerOff) {
        for (const TeiMacPair& p : e.nodes) {
            if (!p.tei) continue;   // 地址方式只有 MAC,走 leaves 循环
            auto nit = nodes.find(p.tei);
            if (nit == nodes.end()) continue;
            if (nit.value().mac) {
                pending.remove(nit.value().mac);
                m_cco_macs.remove(nid_mac_key(e.nid, nit.value().mac));
                m_offline_macs.insert(nid_mac_key(e.nid, nit.value().mac));
            }
            nit.value().status = NodeStatus::Offline;
            nit.value().last_seen_ms = e.epoch_ms;
        }
    }
    // 离网节点(按 (NID, MAC) 匹配,标记离线):先走 MAC→TEI 索引 O(1),索引不一致时回退线性扫描
    for (quint64 mac : e.leaves) {
        if (!mac) continue;
        // 明确离网同时结束该 MAC 尚未完成的入网状态,避免 pending 永久显示为“入网中”。
        pending.remove(mac);
        // 离网后该 MAC 可能在同一 NID 下被另一角色复用;仅清理本 NID 的 CCO 身份记忆,
        // 不影响其他 NID 下同 MAC 的身份。
        m_cco_macs.remove(nid_mac_key(e.nid, mac));
        m_offline_macs.insert(nid_mac_key(e.nid, mac));
        bool done = false;
        auto iit = mac_to_tei.find(nid_mac_key(e.nid, mac));
        if (iit != mac_to_tei.end()) {
            auto nit = nodes.find(iit.value());
            if (nit != nodes.end() && nit.value().mac == mac) {
                nit.value().status = NodeStatus::Offline;
                nit.value().last_seen_ms = e.epoch_ms;
                done = true;
            } else if (nit != nodes.end()) {
                // 节点存在但 MAC 不一致时才是坏索引。逐帧采样可能只建身份索引,
                // 尚未有拓扑节点;保留其历史 TEI 供下次角色冲突比较。
                mac_to_tei.erase(iit);
            }
        }
        if (!done) {
            for (auto it = nodes.begin(); it != nodes.end(); ++it) {
                if (it.value().mac == mac) {
                    it.value().status = NodeStatus::Offline;
                    it.value().last_seen_ms = e.epoch_ms;
                    break;
                }
            }
        }
    }
    // 通讯成功率(成功率上报,按 TEI 覆盖更新)
    for (const CommRateInfo& cr : e.comm_rates) {
        if (!cr.tei) continue;
        comm_rates[cr.tei] = cr;
    }
    // 邻居表(发现列表位图,按发送方 TEI 覆盖更新;同时累计各邻居出现次数供排序/信号强度)
    if (e.kind == TopoEventKind::DiscoverList && e.discover_src_tei) {
        neighbors[e.discover_src_tei] = e.neighbor_teis;
        auto& counts = neighbor_counts[e.discover_src_tei];
        for (quint16 nb : e.neighbor_teis)
            counts[nb]++;
    }
    // 记录路由变更事件(供底部表格):仅真正"变更"入表。
    // 发现列表(周期性快照)/成功率上报(通讯质量)不入路由变更表,
    // 但南网发现列表若携带上行路由条目且下一跳发生变化,则作为拓扑变化入表。
    // 代理变更请求仅记录(不更新拓扑),确认后更新拓扑。
    // 注意:发现列表携带的成功率仍会更新 comm_rates 状态(见上方),
    // 只是不作为一条路由变更记录入表。
    switch (e.kind) {
        case TopoEventKind::AssocReq:
        case TopoEventKind::AssocCnf:
        case TopoEventKind::AssocGatherInd:
        case TopoEventKind::AssocInd:
        case TopoEventKind::ChangeProxyReq:
        case TopoEventKind::ChangeProxyCnf:
        case TopoEventKind::LeaveInd:
        case TopoEventKind::PowerOff:
        case TopoEventKind::PowerOn:
            append_event(events, e);
            break;
        case TopoEventKind::DiscoverList:
            if (up_route_changed) {
                TopoEvent ev = e;
                if (!up_route_desc.isEmpty()) ev.desc = up_route_desc;
                append_event(events, ev);
            }
            break;
        default:
            break;
    }
}

void TopoState::apply_channel_info(quint16 reporter_tei, const TopoEvent& e) {
    if (!reporter_tei || reporter_tei == kTeiInvalid) return;
    const bool has_observation = e.proxy_tei != kTeiInvalid
        || e.proxy_up_rate >= 0 || e.proxy_down_rate >= 0
        || e.proxy_comm_rate >= 0 || e.proxy_down_comm_rate >= 0
        || e.min_comm_rate >= 0 || e.neighbor_teis_present
        || !e.neighbor_rates.isEmpty() || !e.neighbor_snrs.isEmpty()
        || !e.rssi_entries.isEmpty();
    if (!has_observation) return;
    // 有效帧携带该 reporter 的信道/站点属性,可证明其在线;同时恢复离线状态。
    // 离线→在线才是复活:留一条带原因的事件记录(kind=ChannelInfo,原因“信道观测”),
    // 已在线帧不重复记;回放重调同一函数,记录与实时一致。
    TopoNode& reporter = nodes[reporter_tei];
    if (reporter.tei == 0) reporter.tei = reporter_tei;
    const bool revived = (reporter.status == NodeStatus::Offline);
    const quint64 reporter_mac = reporter.mac;
    reporter.status = NodeStatus::Online;
    reporter.last_seen_ms = e.epoch_ms;
    if (revived)
        append_revival_record(events, nid, TopoEventKind::ChannelInfo, reporter_tei,
                              reporter_mac ? reporter_mac : e.sender_mac,
                              e.sender_mac, e.epoch_ms, e.frame_index);
    // 站点属性(表217/表126):代理上行/下行接收率、最小接收率、RF 跳数、角色 + parent_tei 校正
    // 站点属性直报的代理 TEI 比路由推导权威;节点不存在时据此建占位(站点属性自带 proxy/role 身份)
    if (e.proxy_tei != kTeiInvalid) {
        TopoNode& node = nodes[reporter_tei];   // operator[] 自动创建(站点属性即身份来源)
        if (node.tei == 0) node.tei = reporter_tei;
        node.is_rf = true;                       // RFDL 站点属性来自无线发现列表(无线媒介)
        node.is_rf_known = true;
        if (node.last_seen_ms == 0) node.last_seen_ms = e.epoch_ms;
        node.proxy_up_rate = e.proxy_up_rate;
        node.proxy_down_rate = e.proxy_down_rate;
        node.min_link_rate = e.min_link_rate;
        node.rf_hop = e.rf_hop;
        node.rf_role = e.rf_role;
        node.proxy_rate_known = true;
        // 站点属性直报的代理 TEI 比路由推导权威,用于校正 parent_tei
        if (e.proxy_tei != reporter_tei)
            node.parent_tei = e.proxy_tei;
    }
    // 表39 站点属性(7B,无代理TEI,仅成功率+BRU SNR):按 reporter_tei 落地(代理TEI 由 parent_tei 已知)
    if (e.proxy_up_rate >= 0 || e.proxy_down_rate >= 0
        || e.proxy_comm_rate >= 0 || e.proxy_down_comm_rate >= 0) {
        TopoNode& node = nodes[reporter_tei];
        if (node.tei == 0) node.tei = reporter_tei;
        if (node.last_seen_ms == 0) node.last_seen_ms = e.epoch_ms;
        if (e.proxy_up_rate >= 0) node.proxy_up_rate = e.proxy_up_rate;
        if (e.proxy_down_rate >= 0) node.proxy_down_rate = e.proxy_down_rate;
        if (e.proxy_comm_rate >= 0) node.proxy_comm_rate = e.proxy_comm_rate;
        if (e.proxy_down_comm_rate >= 0) node.proxy_down_comm_rate = e.proxy_down_comm_rate;
        if (e.proxy_up_rate >= 0 || e.proxy_down_rate >= 0) node.proxy_rate_known = true;
        if (e.proxy_comm_rate >= 0 || e.proxy_down_comm_rate >= 0) node.comm_rate_known = true;
    }
    // 邻居接收率/SNR:按上报方 STA 键控(方向=邻居→上报方,即上行成功率;下行查 neighbor_rates[nb][me])
    {
        auto& rates = neighbor_rates[reporter_tei];
        for (const auto& pr : e.neighbor_rates)
            rates[pr.first] = pr.second;
        auto& snrs = neighbor_snrs[reporter_tei];
        for (const auto& pr : e.neighbor_snrs)
            snrs[pr.first] = pr.second;
    }
    // 邻居信号强度(节点属性,仅更新已存在节点,不为纯 RSSI 建占位)
    for (const auto& r : e.rssi_entries) {
        auto nit = nodes.find(r.first);
        if (nit == nodes.end()) continue;
        nit.value().rssi_dbm = r.second;
        nit.value().rssi_known = true;
    }
    // 邻居表(位图版,discover_src_tei=reporter_tei):按发送方 TEI 覆盖更新 + 累计次数(供排序/信号强度)
    if (e.neighbor_teis_present) {
        neighbors[reporter_tei] = e.neighbor_teis;
        auto& counts = neighbor_counts[reporter_tei];
        for (quint16 nb : e.neighbor_teis) {
            if (!nb) continue;   // TEI 0 = 广播/保留,不计邻居次数
            counts[nb]++;
        }
    }
}

QHash<quint16, int> TopoState::compute_levels() const {
    QHash<quint16, int> lv;
    if (nodes.isEmpty()) return lv;
    lv[1] = 0;                 // CCO 层级 0
    // 迭代松弛:父层级已确定时子层级 = 父 + 1(容忍环路,最多节点数轮)
    for (int pass = 0; pass < nodes.size() + 1; ++pass) {
        bool changed = false;
        for (auto it = nodes.begin(); it != nodes.end(); ++it) {
            const quint16 tei = it.key();
            if (tei == kTeiCco) continue;
            const quint16 parent = it.value().parent_tei;
            if (parent == kTeiInvalid || !lv.contains(parent)) continue;
            const int nl = lv[parent] + 1;
            if (!lv.contains(tei) || lv[tei] != nl) { lv[tei] = nl; changed = true; }
        }
        if (!changed) break;
    }
    return lv;
}

TopoOnlineCounts TopoState::online_counts() const {
    TopoOnlineCounts counts;
    for (auto it = nodes.constBegin(); it != nodes.constEnd(); ++it) {
        if (it.key() == kTeiCco) continue;  // CCO(TEI 固定为 1)不计入在网节点数
        switch (it.value().status) {
            case NodeStatus::Online: ++counts.online; break;
            case NodeStatus::OnlineGoing: ++counts.online_going; break;
            case NodeStatus::Offline: ++counts.offline; break;
        }
    }
    // 正在入网但尚未分配 TEI 的节点只存在于 pending(关联请求阶段),
    // 与 nodes 里的 OnlineGoing 互不重叠,直接累加不重复计数。
    counts.online_going += pending.size();
    return counts;
}

quint64 TopoState::mac_of(quint16 tei) const {
    auto it = nodes.constFind(tei);
    return it == nodes.constEnd() ? 0 : it->mac;
}
