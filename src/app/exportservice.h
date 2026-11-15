/// @file exportservice.h
/// @brief 帧列表导出服务:选择导出格式/路径 + 工作线程流式写文件
/// @details 三种格式:回放 bin / 裸 hex 文本 / CSV 表格。导出在工作线程按
///          PacketListModel 快照流式写出,不阻塞界面;导出期间 is_exporting()
///          为真,调用方须暂停向模型 append(保证快照一致且线程安全)。
#ifndef BPLC_EXPORTSERVICE_H
#define BPLC_EXPORTSERVICE_H

#include <QObject>
#include <QString>

class QWidget;
class PacketListModel;

class ExportService : public QObject {
    Q_OBJECT
public:
    explicit ExportService(QObject* parent = nullptr);

    /// @brief 导出中(工作线程尚未结束)
    bool is_exporting() const { return m_exporting; }

    /// @brief 弹出保存对话框并启动后台导出
    /// @param dialog_parent 保存对话框父窗口
    /// @param model         数据来源(取导出快照;导出期间不得 append)
    void export_model(QWidget* dialog_parent, PacketListModel* model);

signals:
    /// @brief 导出进度/结果文案(状态栏左侧显示)
    void status_changed(const QString& text);

private:
    bool m_exporting = false;   ///< 导出中(调用方暂停 append 进模型)
};

#endif  // BPLC_EXPORTSERVICE_H
