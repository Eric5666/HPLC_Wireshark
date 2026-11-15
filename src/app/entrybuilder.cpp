/// @file entrybuilder.cpp
/// @brief 帧列表条目构建实现
#include "entrybuilder.h"

#include "playbackwriter.h"
#include "topo_controller.h"
#include "topo_input.h"
#include "local_plugin_engine.h"

PreparedEntryPtr prepare_entry(ParseResult&& r) {
    PreparedEntryPtr p = PreparedEntryPtr::create();
    PacketEntry& e = p->entry;
    e.accepted  = r.accept;     // 拒收行 Info 列显示 reason,着色走灰/红判定
    e.reason    = std::move(r.reject_reason);
    e.meta      = r.meta;
    e.mpdu      = std::move(r.mpdu);
    // 协议身份来自解析器,非全局配置。
    // 映射统一走 entry_protocol_id():它保留插件位(0x80),否则插件帧会被当内置帧渲染。
    e.protocol  = entry_protocol_id(r.protocol);
    e.msdu_body = std::move(r.msdu_body);
    e.raw_wire  = r.raw_wire;              // 隐式共享:插件模板同用一份
    e.msdu      = std::move(r.msdu);       // MSDU/MAC 层字段树(SOF 重组完成时非空)
    e.beacon    = std::move(r.beacon);     // BEACON 载荷区字段树(BEACON 帧时非空)
    e.msdu_raw_base = r.msdu_raw_base;
    e.raw_bytes = std::move(r.payload_for_log);
    e.dissect_fields = std::move(r.dissect_fields);  // 插件解析器通用字段树(内置解析恒空)
    p->display_delta_us = r.display_delta_us;
    // 可搜索全文(除帧序号外)在解析线程预建,GUI 线程只拼序号
    p->search_tail = make_search_text_tail(e);

    // 插件喂帧模板:除帧序号/帧时刻外的字段均来自解析结果
    BplcFrame& pf = p->plugin_frame;
    pf.meta = e.meta;
    pf.raw_wire = e.raw_wire;
    pf.data = e.raw_wire.isEmpty() ? e.raw_bytes : e.raw_wire;
    pf.arrival_us = r.arrival_us;
    if (e.msdu.topo_event.kind != TopoEventKind::Other)
        pf.topo_event = e.msdu.topo_event;
    // 标量透传:主程序已解析好的单值直接给插件
    pf.accepted = e.accepted;
    pf.error_reason = e.reason;
    pf.mpdu = e.mpdu;
    pf.msdu_present = e.msdu.present;
    pf.msdu_summary = e.msdu.summary;
    return p;
}

PacketEntry EntryBuilder::build(PreparedEntry& p, qint64 now_ms) {
    PacketEntry e = std::move(p.entry);
    e.index = ++m_index_counter;
    // 带时间标签(回放导出的 bin)时用帧内绝对时刻,保证 Time/Delta/再导出
    // 均以原始捕获时间为基准;否则退化为本地接收时刻
    e.epoch_ms = e.meta.frame_time.isValid()
                     ? e.meta.epoch_ms : now_ms;   // 用 parse 时缓存的 epoch_ms,避免时区转换
    // Delta:内置解析器已在解析时算好显示 Delta(好帧锚点链,见 DisplayTimeAnchor),
    // 直接取用;插件解析器不算(-1)时沿用旧 NTB 差算法(m_last_ntb 链)。
    // 本地接收时间(0x3C 打点 arrival_us)只作 serialreader 断段(seg_start)
    // 判断参考,不参与 Delta 计算。
    e.delta_us = (p.display_delta_us >= 0)
        ? p.display_delta_us
        : playback::next_delta_us(e.meta, m_last_ntb, m_have_last_ntb);
    // Topology input normalization is owned by its module; we only forward it.
    if (m_topo_controller && e.mpdu.net_id != 0) {
        const TopoFrameInput topo_frame = make_topo_frame_input(e);
        m_topo_controller->submit_frame(topo_frame);
    }
    e.search_text = join_search_text(e.index, p.search_tail);   // 缓存可搜索全文,过滤匹配复用
    // 插件:喂"解析好的帧"(单入口 parse)——帧序号/时间戳/topoEvent 均已就绪,
    // 插件 topo 与原版共享同一份解码数据,不再走独立事件侧信道
    if (m_plugin_engine) {
        p.plugin_frame.decoded_index = e.index;
        p.plugin_frame.decoded_epoch_ms = e.epoch_ms;
        m_plugin_engine->feed_frame(p.plugin_frame);
    }
    return e;
}

void EntryBuilder::reset() {
    m_index_counter = 0;
    m_last_ntb = 0;
    m_have_last_ntb = false;
}
