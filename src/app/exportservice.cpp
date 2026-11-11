/// @file exportservice.cpp
/// @brief 帧列表导出服务实现(回放 bin / 裸 hex 文本 / CSV 表格)
#include "exportservice.h"

#include "packetlistmodel.h"
#include "packetentry_serialize.h"
#include "playbackwriter.h"
#include "fieldtools.h"
#include "i18n.h"

#include <QDateTime>
#include <QFile>
#include <QFileDialog>
#include <QFutureWatcher>
#include <QStringConverter>
#include <QTextStream>
#include <QWidget>
#include <QtConcurrent>

namespace {
/// @brief 按全局顺序把快照的全部条目交给 fn:盘块(未就绪块用内存副本)+ 热区
/// @return 实际交出的条目数(读不到的块不计,调用方与 snap.total 比对)
template <typename Fn>
qint64 for_each_snapshot_entry(const PacketListModel::ExportSnapshot& snap, Fn&& fn) {
    qint64 n = 0;
    for (int b = 0; b < snap.block_paths.size(); ++b) {
        const PacketListModel::BlockMem mem = snap.block_mem.value(b);
        if (mem) {
            for (const PacketEntry& e : *mem) { fn(e); ++n; }
            continue;
        }
        QVector<PacketEntry> block;   // 独立文件句柄,线程安全
        if (!pser::read_block_file(snap.block_paths[b], block)) continue;
        for (const PacketEntry& e : block) { fn(e); ++n; }
    }
    for (const PacketEntry& e : snap.hot) { fn(e); ++n; }
    return n;
}

/// 导出格式
enum class ExportFormat { Bin, Text, Csv };

// TEI→MAC 映射表(与 PacketListModel 内部一致)
using TeiMacMap = QHash<quint32, QHash<quint16, quint64>>;

static quint64 csv_lookup_mac(const TeiMacMap& macs, quint32 nid, quint16 tei) {
    const auto it = macs.constFind(nid);
    if (it == macs.constEnd()) return 0;
    const auto jt = it->constFind(tei);
    return (jt == it->constEnd()) ? 0 : jt.value();
}

/// CSV 单元格转义(含逗号/引号/换行时双引号包裹,内部引号翻倍)
static QString csv_escape(const QString& s) {
    if (!s.contains(',') && !s.contains('"') && !s.contains('\n') && !s.contains('\r'))
        return s;
    QString t = s;
    t.replace('"', QStringLiteral("\"\""));
    return QLatin1Char('"') + t + QLatin1Char('"');
}

/// 复现 PacketListModel::data() 的列渲染,生成一行 CSV 单元格(与表格列一致)
static QStringList csv_row(const PacketEntry& e, const TeiMacMap& macs) {
    QStringList c;
    c << QString::number(e.index);
    // Time
    c << (e.meta.frame_time.isValid()
              ? e.meta.frame_time.toString(QStringLiteral("HH:mm:ss.zzz"))
              : QStringLiteral("%1 s").arg(e.epoch_ms / 1000.0, 0, 'f', 6));
    // Delta
    c << QStringLiteral("%1 s").arg(e.delta_us / 1e6, 0, 'f', 6);
    // Orig Src
    {
        QString s;
        if (e.accepted && e.msdu.present && !e.msdu.simple_head && e.msdu.msdu_src_tei > 0) {
            const int tei = e.msdu.msdu_src_tei;
            s = (tei == kTeiCco) ? QStringLiteral("CCO") : QStringLiteral("STA-%1").arg(tei);
            quint64 mac = e.msdu.msdu_src_mac;
            if (!mac) mac = csv_lookup_mac(macs, e.mpdu.net_id, quint16(tei));
            if (mac) s += QStringLiteral(" [%1]").arg(mac_str(mac));
        }
        c << s;
    }
    // Source
    {
        QString s;
        if (!e.accepted) {
            s = QStringLiteral("DROP");
        } else {
            const quint16 tei = e.mpdu.src_tei;
            if (e.mpdu.frame_type == 3 && tei == 0) {
                s = QStringLiteral("CCO");
                const quint64 mac = csv_lookup_mac(macs, e.mpdu.net_id, 1);
                if (mac) s += QStringLiteral(" [%1]").arg(mac_str(mac));
            } else if (tei != 0) {
                s = (tei == kTeiCco) ? QStringLiteral("CCO") : QStringLiteral("STA-%1").arg(tei);
                const quint64 mac = csv_lookup_mac(macs, e.mpdu.net_id, tei);
                if (mac) s += QStringLiteral(" [%1]").arg(mac_str(mac));
            } else if (e.msdu.sta_mac) {
                s = QStringLiteral("STA-X [%1]").arg(mac_str(e.msdu.sta_mac));
            } else {
                s = e.meta.is_rf ? QStringLiteral("RF") : QStringLiteral("PLC");
            }
        }
        c << s;
    }
    // Destination
    {
        QString s;
        if (!e.accepted) {
            s = e.reason;
        } else if (e.mpdu.dst_tei == kTeiBroadcast) {
            s = QStringLiteral("BROADCAST");
        } else {
            const quint16 tei = e.mpdu.dst_tei;
            if (tei != 0) {
                s = (tei == kTeiCco) ? QStringLiteral("CCO") : QStringLiteral("STA-%1").arg(tei);
                const quint64 mac = csv_lookup_mac(macs, e.mpdu.net_id, tei);
                if (mac) s += QStringLiteral(" [%1]").arg(mac_str(mac));
            } else {
                s = QStringLiteral("*");
            }
        }
        c << s;
    }
    // Orig Dst
    {
        QString s;
        if (e.accepted && e.msdu.present && !e.msdu.simple_head && e.msdu.msdu_dst_tei > 0) {
            const int tei = e.msdu.msdu_dst_tei;
            s = (tei == kTeiBroadcast) ? QStringLiteral("BCAST")
              : (tei == kTeiCco) ? QStringLiteral("CCO") : QStringLiteral("STA-%1").arg(tei);
            if (tei == kTeiBroadcast) {
                if (e.msdu.msdu_dst_mac) s += QStringLiteral(" [%1]").arg(mac_str(e.msdu.msdu_dst_mac));
            } else {
                quint64 mac = e.msdu.msdu_dst_mac;
                if (!mac) mac = csv_lookup_mac(macs, e.mpdu.net_id, quint16(tei));
                if (mac) s += QStringLiteral(" [%1]").arg(mac_str(mac));
            }
        }
        c << s;
    }
    // Dir
    c << dir_display(e);
    // Protocol
    c << (!e.accepted ? QStringLiteral("ERR")
                      : e.meta.is_rf ? QStringLiteral("RF") : QStringLiteral("HPLC"));
    // Frame Type
    c << (!e.accepted ? QStringLiteral("-") : e.mpdu.frame_type_name());
    // MSDU Type
    c << ((e.accepted && e.msdu.present) ? e.msdu.summary : QString());
    // MSDU Seq
    c << ((e.accepted && e.msdu.present) ? QString::number(e.msdu.msdu_seq) : QString());
    // Length
    c << QString::number(e.raw_bytes.size());
    // Info
    {
        QString s;
        if (!e.accepted) {
            s = e.reason;
        } else {
            const QString nid = QString::number(e.mpdu.net_id, 16).toUpper().rightJustified(6, QChar('0'));
            if (e.mpdu.frame_type == 0)
                s = QStringLiteral("NetID=0x%1 ts=%2").arg(nid).arg(e.meta.timestamp);
            else if (e.mpdu.frame_type == 1)
                // 无线帧无 TMI(南网无线表131 只有 MCS/PBLen),与 packetlistmodel SOF 摘要同口径
                s = QStringLiteral("NetID=0x%1 src=%2 dst=%3 %4=%5 PBNum=%6%7")
                        .arg(nid).arg(e.mpdu.src_tei).arg(e.mpdu.dst_tei)
                        .arg(e.meta.is_rf ? QStringLiteral("MCS") : QStringLiteral("TMI"))
                        .arg(e.meta.is_rf ? e.mpdu.mcs : e.mpdu.tmi)
                        .arg(e.mpdu.pb_num)
                        .arg(e.msdu_body.isEmpty() ? QString()
                                                   : QStringLiteral(" MSDU[%1B]").arg(e.msdu_body.size()));
            else
                s = QStringLiteral("NetID=0x%1 src=%2 dst=%3")
                        .arg(nid).arg(e.mpdu.src_tei).arg(e.mpdu.dst_tei);
        }
        c << s;
    }
    return c;
}

/// @brief 导出结果:实际处理的帧数与写文件是否成功
struct ExportResult {
    qint64 frames = 0;     ///< 交给 writer 的帧数(与快照总数比对,不符即有块丢失)
    bool   io_ok = false;  ///< 文件打开与写入均无错误
};

/// @brief 工作线程导出:遍历快照盘块 + 热区,流式写文件(不阻塞 GUI)
ExportResult run_export(const PacketListModel::ExportSnapshot& snap,
                        const QString& path, ExportFormat fmt) {
    ExportResult r;
    QFile out(path);
    if (!out.open(QIODevice::WriteOnly)) return r;
    if (fmt == ExportFormat::Text) {
        playback::RawHexWriter w(&out);
        r.frames = for_each_snapshot_entry(snap, [&w](const PacketEntry& e) { w.add(e); });
    } else if (fmt == ExportFormat::Bin) {
        playback::PlaybackBinWriter w(&out);
        r.frames = for_each_snapshot_entry(snap, [&w](const PacketEntry& e) { w.add(e); });
    } else {   // ExportFormat::Csv
        QTextStream ts(&out);
        // 本地编码存储(Windows 中文系统=GBK/ANSI 代码页),Excel 直接打开不乱码
        ts.setEncoding(QStringConverter::System);
        ts << QStringLiteral("#,Time,Delta,Orig Src,Source,Destination,Orig Dst,Dir,"
                             "Protocol,Frame Type,MSDU Type,MSDU Seq,Length,Info\n");
        const auto emit_row = [&](const PacketEntry& e) {
            const QStringList cells = csv_row(e, snap.tei_mac);
            for (int i = 0; i < cells.size(); ++i) {
                if (i) ts << ',';
                ts << csv_escape(cells[i]);
            }
            ts << '\n';
        };
        r.frames = for_each_snapshot_entry(snap, emit_row);
        ts.flush();
    }
    out.close();
    r.io_ok = out.error() == QFile::NoError;
    return r;
}
}  // namespace

ExportService::ExportService(QObject* parent) : QObject(parent) {}

void ExportService::export_model(QWidget* dialog_parent, PacketListModel* model) {
    if (!model) return;
    if (model->total_count() == 0) {
        emit status_changed(trl::L("无可导出的帧"));
        return;
    }
    // 三种导出格式:①回放 bin(0x3C 封装帧流+BCD 时间标签)
    // ②裸数据 hex 文本(每行一帧,无 0x3C/0x3E/0x3D 封装):
    //   [ts 4B LE][phr_mcs][option][channel][isRF][MPDU];回放(RawHex)
    //   按 ts 还原捕获时刻,缺失时回退本地时间
    // ③CSV 表格(每行内容,便于 Excel 排查;仅导出,不支持导入)
    QString selected;
    const QString filter = trl::L("回放文件 (*.bin)") + QStringLiteral(";;") +
                           trl::L("裸 hex 文本 (*.txt)") + QStringLiteral(";;") +
                           trl::L("CSV 表格 (*.csv)");
    QString f = QFileDialog::getSaveFileName(
        dialog_parent, trl::L("导出为文件"),
        "BPLC_" + QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss") +
            (selected.contains(QStringLiteral(".txt")) ? ".txt"
             : selected.contains(QStringLiteral(".csv")) ? ".csv" : ".bin"),
        filter, &selected);
    if (f.isEmpty()) return;
    ExportFormat fmt = ExportFormat::Bin;
    if (selected.contains(QStringLiteral(".txt"))) {
        fmt = ExportFormat::Text;
        if (!f.endsWith(QStringLiteral(".txt"), Qt::CaseInsensitive))
            f += QStringLiteral(".txt");
    } else if (selected.contains(QStringLiteral(".csv"))) {
        fmt = ExportFormat::Csv;
        if (!f.endsWith(QStringLiteral(".csv"), Qt::CaseInsensitive))
            f += QStringLiteral(".csv");
    } else if (!f.endsWith(QStringLiteral(".bin"), Qt::CaseInsensitive)) {
        f += QStringLiteral(".bin");
    }
    // 导出快照 + 工作线程流式导出(不阻塞界面)
    const PacketListModel::ExportSnapshot snap = model->make_export_snapshot();
    const qint64 total = model->total_count();
    m_exporting = true;   // 暂停 flush 进模型,保证快照一致 + 线程安全
    emit status_changed(trl::L("正在导出 %1 帧...").arg(total));

    auto* watcher = new QFutureWatcher<ExportResult>(this);
    connect(watcher, &QFutureWatcher<ExportResult>::finished, this,
            [this, watcher, f, total]() {
        m_exporting = false;
        const ExportResult res = watcher->result();
        watcher->deleteLater();
        QFile out(f);
        if (!res.io_ok) {
            emit status_changed(trl::L("导出失败:写入文件出错 → %1").arg(f));
        } else if (res.frames != total) {
            // 有盘块读不到:如实报告,不再声称导出了全部帧
            emit status_changed(trl::L("导出不完整:仅写出 %1 / %2 帧 → %3")
                                       .arg(res.frames).arg(total).arg(f));
        } else if (!out.exists() || out.size() == 0) {
            emit status_changed(trl::L("没有可写入的帧数据"));
        } else {
            emit status_changed(trl::L("已导出 %1 帧 → %2").arg(total).arg(f));
        }
    });
    watcher->setFuture(QtConcurrent::run([snap, f, fmt]() {
        return run_export(snap, f, fmt);
    }));
}

namespace {
// 中→英注册(文件级,导出相关条目)
struct I18nRegExportService {
    I18nRegExportService() {
        trl::register_en("导出为文件", "Export to file");
        trl::register_en("裸 hex 文本 (*.txt)", "Raw hex text (*.txt)");
        trl::register_en("回放文件 (*.bin)", "Replay files (*.bin)");
        trl::register_en("CSV 表格 (*.csv)", "CSV table (*.csv)");
        trl::register_en("正在导出 %1 帧...", "Exporting %1 frames...");
        trl::register_en("无可导出的帧", "No frames to export");
        trl::register_en("没有可写入的帧数据", "No frame data to write");
        trl::register_en("已导出 %1 帧 → %2", "Exported %1 frames → %2");
        trl::register_en("导出失败:写入文件出错 → %1", "Export failed: error writing file → %1");
        trl::register_en("导出不完整:仅写出 %1 / %2 帧 → %3", "Export incomplete: only %1 / %2 frames written → %3");
    }
};
const I18nRegExportService g_i18n_reg_export_service;
}  // namespace
