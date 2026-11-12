#ifndef BPLC_TOPO_INPUT_H
#define BPLC_TOPO_INPUT_H

#include "topo_worker.h"
#include "bplcframe.h"

/// Convert one decoded packet into the immutable input consumed by the topology service.
/// This keeps protocol-field interpretation out of MainWindow and makes it testable.
TopoFrameInput make_topo_frame_input(const PacketEntry& entry);

#endif  // BPLC_TOPO_INPUT_H
