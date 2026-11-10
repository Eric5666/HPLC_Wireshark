/// @file script_painter.cpp
#include "script_painter.h"

#include <QColor>
#include <QFont>
#include <QHash>
#include <QPainter>
#include <QPen>
#include <QPixmap>

ScriptPainter::ScriptPainter(QPainter* p, QObject* parent)
    : QObject(parent), m_p(p) {}

void ScriptPainter::set_pen(const QString& color, double width) {
    m_p->setPen(QPen(QColor(color), width));
}
void ScriptPainter::set_brush(const QString& color) {
    m_p->setBrush(QColor(color));
}
void ScriptPainter::no_brush() {
    m_p->setBrush(Qt::NoBrush);
}
void ScriptPainter::no_pen() {
    m_p->setPen(Qt::NoPen);
}
void ScriptPainter::set_font(const QString& family, int point_size,
                             bool bold) {
    // Empty family = "default font". QFont("") can resolve to a symbol font
    // on systems with odd fontconfig ordering, so pin a real default.
    QFont f(family.isEmpty() ? QStringLiteral("Sans") : family, point_size);
    f.setBold(bold);
    m_p->setFont(f);
}
void ScriptPainter::clear(const QString& color) {
    m_p->fillRect(m_p->window(), QColor(color));
}
void ScriptPainter::draw_line(double x1, double y1, double x2, double y2) {
    m_p->drawLine(QLineF(x1, y1, x2, y2));
}
void ScriptPainter::draw_rect(double x, double y, double w, double h) {
    m_p->drawRect(QRectF(x, y, w, h));
}
void ScriptPainter::fill_rect(double x, double y, double w, double h,
                               const QString& color) {
    m_p->fillRect(QRectF(x, y, w, h), QColor(color));
}
void ScriptPainter::draw_ellipse(double x, double y, double w, double h) {
    m_p->drawEllipse(QRectF(x, y, w, h));
}
void ScriptPainter::draw_text(double x, double y, const QString& text) {
    m_p->drawText(QPointF(x, y), text);
}
double ScriptPainter::text_width(const QString& text) {
    return m_p ? m_p->fontMetrics().horizontalAdvance(text) : 0.0;
}
void ScriptPainter::draw_point(double x, double y) {
    m_p->drawPoint(QPointF(x, y));
}

void ScriptPainter::set_clip(double x, double y, double w, double h) {
    m_p->setClipRect(QRectF(x, y, w, h));
}
void ScriptPainter::reset_clip() {
    m_p->setClipping(false);
}

/// @brief 绘制内置节点图标(与原版 TopoWindow 同源: :/icons/*.png)。
/// 资源缺失(如宿主进程未打包图标)时退化为彩色圆点,保证脚本不崩。
void ScriptPainter::draw_icon(const QString& name, double x, double y,
                              double w, double h) {
    static QHash<QString, QPixmap> cache;
    static const QHash<QString, QString> kRes = {
        {QStringLiteral("cco"),           QStringLiteral(":/icons/cco-router.png")},
        {QStringLiteral("meter_online"),  QStringLiteral(":/icons/electric-meter_online.png")},
        {QStringLiteral("meter_joining"), QStringLiteral(":/icons/electric-meter _online_going.png")},
        {QStringLiteral("meter_offline"), QStringLiteral(":/icons/electric-meter _offline.png")},
    };
    // 缓存只收内置图标名(至多 kRes.size() 项):脚本传入任意名字不再让
    // 缓存无界增长(M10);未知名字无资源可读,直接走退化圆点,无 IO。
    QPixmap pm;
    const QString res = kRes.value(name);
    if (!res.isEmpty()) {
        auto cit = cache.constFind(name);
        if (cit != cache.constEnd()) {
            pm = cit.value();
        } else {
            pm = QPixmap(res);
            cache.insert(name, pm);  // 失败也缓存(空 pixmap),避免重复 IO
        }
    }
    const QRectF r(x, y, w, h);
    if (!pm.isNull()) {
        m_p->drawPixmap(r, pm, QRectF(QPointF(0, 0), QSizeF(pm.size())));
        return;
    }
    // 退化:彩色圆点(cco 蓝 / 在线绿 / 入网中黄 / 离线灰)
    QColor c = Qt::gray;
    if (name == QLatin1String("cco")) c = QColor(86, 156, 214);
    else if (name == QLatin1String("meter_online")) c = QColor(46, 160, 67);
    else if (name == QLatin1String("meter_joining")) c = QColor(210, 153, 34);
    m_p->save();
    m_p->setPen(Qt::NoPen);
    m_p->setBrush(c);
    m_p->drawEllipse(r);
    m_p->restore();
}
