/// @file hexview.h
/// @brief 16 字节/行格式的 hex+ASCII 视图控件
/// @details 高亮使用 QPlainTextEdit::setExtraSelections(文本选区),
///          由控件原生处理坐标/滚动/重绘,避免自绘 paintEvent 偏移问题。
#ifndef BPLC_HEXVIEW_H
#define BPLC_HEXVIEW_H

#include <QPlainTextEdit>
#include <QByteArray>
#include <QList>
#include <QPair>

class QContextMenuEvent;

class HexView : public QPlainTextEdit {
    Q_OBJECT
public:
    explicit HexView(QWidget* parent = nullptr);

    /// @brief 设置待显示的原始字节并重新渲染
    void set_data(const QByteArray& bytes);

    /// @brief 高亮 [start, start+len) 字节(hex 列)。传 (-1, 0) 清除高亮。
    void highlight_range(int start, int len);

    /// @brief 高亮多个不连续片段(跨块字段)。空列表=清除高亮。
    void highlight_ranges(const QList<QPair<int, int>>& ranges);

    /// @brief 设置字段的复制字节(重组内容);复制时优先用此,空则用高亮 raw 字节。
    void set_copy_bytes(const QByteArray& bytes);

    void clear();

    /// @brief 当前高亮区间拼接出的 raw 字节(无高亮返回空)
    QByteArray highlighted_bytes() const;

    /// @brief 实际复制内容:优先字段重组字节,否则高亮 raw 字节
    QByteArray copy_bytes() const;

protected:
    void contextMenuEvent(QContextMenuEvent* event) override;

private:
    /// @brief 计算第 byte_index 字节的 hex 首字符在文档中的位置
    /// @details 行格式: "0000  xx xx ... xx  xx ...  ascii\n"
    ///          每字节占 "xx " 3 字符,第 8 字节(col==7)后多 1 空格,
    ///          行首偏移列 4hex+2sp = 6 字符;行内容固定 72 字符 + '\n'。
    int char_offset_of_byte(int byte_index) const;

    void rebuild_highlight();

    QByteArray m_bytes;
    QList<QPair<int, int>> m_hl_ranges;  ///< 高亮片段列表(跨块多段)
    QByteArray m_copy_bytes;             ///< 复制字节(字段重组内容)

    void render_hex();
};

#endif  // BPLC_HEXVIEW_H
