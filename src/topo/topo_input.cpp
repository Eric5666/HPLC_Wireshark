#include "topo_input.h"

TopoFrameInput make_topo_frame_input(const PacketEntry& e) {
    TopoFrameInput frame;
    frame.frame_index = e.index;
    frame.epoch_ms = e.epoch_ms;
    frame.net_id = e.mpdu.net_id;
    frame.is_rf = e.meta.is_rf;
    frame.frame_src_tei = e.mpdu.src_tei;
    frame.frame_dst_tei = e.mpdu.dst_tei;
    frame.msdu_present = e.msdu.present;
    frame.msdu_src_tei = quint16(e.msdu.msdu_src_tei);
    frame.msdu_src_mac = e.msdu.msdu_src_mac;
    frame.restart_count = int(e.msdu.restart_count);
    frame.frame_kind = e.msdu.topo_event.kind;
    auto normalize = [&](TopoEvent& event) {
        event.nid = e.mpdu.net_id;
        if (event.nid == 0) return false;
        event.epoch_ms = e.epoch_ms;
        if (event.link_type >= 0) {
            event.is_rf = (event.link_type == LinkTypeRf);
            event.is_rf_known = true;
        } else if ((e.protocol & 0x7F) == kProtocolNw2021 || (e.protocol & 0x7F) == kProtocolNw2026) {
            event.is_rf = e.meta.is_rf;
            event.is_rf_known = true;
        } else if (!event.is_rf_known) {
            event.is_rf = e.meta.is_rf;
            event.is_rf_known = true;
        }
        event.frame_index = e.index;
        return true;
    };
    if (e.msdu.topo_event.kind != TopoEventKind::Other) {
        TopoEvent event = e.msdu.topo_event;
        if (normalize(event)) frame.events.append(std::move(event));
    }
    for (TopoEvent event : e.msdu.topo_extra_events) {
        if (event.kind != TopoEventKind::Other && normalize(event))
            frame.events.append(std::move(event));
    }
    const TopoEvent& channel = e.msdu.topo_event;
    if (e.mpdu.net_id != 0 && e.msdu.simple_head && e.msdu.present
        && (!channel.neighbor_rates.isEmpty() || !channel.neighbor_snrs.isEmpty()
            || !channel.rssi_entries.isEmpty() || channel.proxy_tei != kTeiInvalid)) {
        frame.has_channel_info = true;
        frame.reporter_tei = e.mpdu.src_tei;
        frame.channel_event = channel;
        frame.channel_event.epoch_ms = e.epoch_ms;
        frame.channel_event.frame_index = e.index;
        // Keep the decoded network id; single-hop observations often have no event NID.
        frame.channel_event.nid = e.mpdu.net_id;
    }
    return frame;
}
