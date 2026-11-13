/// @file native_backend.cpp
#include "native_backend.h"
#include <QDir>
#include <QImage>
#include <QPainter>

NativeBackend::~NativeBackend() {
    shutdown();
}

bool NativeBackend::initialize(const PluginManifest& m, QString* err) {
    if (m.api_version != 1) {
        *err = QStringLiteral("api_version mismatch");
        return false;
    }
    const QString lib_path = plugin_contained_entry_path(m.dir_path, m.runtime, m.entry);
    if (lib_path.isEmpty()) {
        *err = QStringLiteral("entry outside plugin dir: %1").arg(m.entry);
        return false;
    }
    m_loader.setFileName(lib_path);
    QObject* inst = m_loader.instance();
    if (!inst) {
        *err = QStringLiteral("load failed: %1").arg(m_loader.errorString());
        return false;
    }
    m_instance = inst;   // 根实例由本后端拥有,shutdown 时先删后卸库
    // 解析器接口(可选:纯图形插件可不实现)
    m_plugin = qobject_cast<IProtocolParserPlugin*>(inst);
    // 图形接口(可选)
    m_graphics = qobject_cast<IGraphicsPlugin*>(inst);

    if (!m_plugin && !m_graphics) {
        *err = QStringLiteral("implements neither IProtocolParserPlugin nor IGraphicsPlugin");
        return false;
    }
    if (m_plugin) {
        if (!m_plugin->initialize()) {
            *err = QStringLiteral("plugin initialize() failed");
            return false;
        }
        m_parser = m_plugin->create_parser();
        if (!m_parser) {
            *err = QStringLiteral("create_parser() returned null");
            return false;
        }
        m_protocol_id = m_plugin->protocol_id();
    } else {
        // 纯图形插件:protocol_id 取清单
        m_protocol_id = m.protocol_id;
    }
    if (m.graphics && !m_graphics) {
        *err = QStringLiteral("manifest graphics=true but plugin has no IGraphicsPlugin");
        return false;
    }
    if (m_graphics) {
        // 注入重绘回调(经 backend 的 m_redraw_cb 转发)
        m_graphics->set_redraw_callback([this]() {
            if (m_redraw_cb) m_redraw_cb();
        });
    }
    return true;
}

void NativeBackend::shutdown() {
    delete m_parser;
    m_parser = nullptr;
    if (m_plugin) { m_plugin->shutdown(); m_plugin = nullptr; }
    m_graphics = nullptr;
    // 先删插件根实例再卸库:实例的虚表/回调驻留在 DLL 内,实例存活时
    // unload 即使成功也会留下悬空指针(渲染回调等会踩已卸载代码)。
    delete m_instance;
    m_instance = nullptr;
    if (m_loader.isLoaded() && !m_loader.unload())
        qWarning("NativeBackend: plugin unload failed: %s",
                 qPrintable(m_loader.errorString()));
}

QString NativeBackend::protocol_id() const {
    return m_protocol_id;
}

ParseResult NativeBackend::parse(const BplcFrame& frame, MsduState& msdu,
                                 const ParseFilter& filter, QString* err) {
    if (!m_parser) {
        *err = QStringLiteral("no parser");
        return ParseResult();
    }
    Q_UNUSED(err);
    return m_parser->parse(frame, msdu, filter);
}

bool NativeBackend::has_graphics() const {
    return m_graphics && m_graphics->has_graphics();
}

QSize NativeBackend::graphics_preferred_size() const {
    if (m_graphics) return m_graphics->preferred_size();
    return QSize(400, 300);
}

QImage NativeBackend::render_graphics(int w, int h, QString* err) {
    if (!m_graphics || !m_graphics->has_graphics()) {
        *err = QStringLiteral("no graphics");
        return QImage();
    }
    if (w <= 0 || h <= 0 || w > 4096 || h > 4096) {
        *err = QStringLiteral("bad size");
        return QImage();
    }
    QImage img(w, h, QImage::Format_ARGB32);
    img.fill(Qt::white);
    QPainter p(&img);
    p.setRenderHint(QPainter::Antialiasing);
    m_graphics->render(&p, w, h);
    p.end();
    return img;
}

bool NativeBackend::handle_graphics_event(const GraphicsEvent& e, QString* err) {
    if (!m_graphics || !m_graphics->has_graphics()) {
        *err = QStringLiteral("no graphics");
        return false;
    }
    return m_graphics->handle_event(e);
}

void NativeBackend::set_ui_dark(bool dark) {
    IPluginBackend::set_ui_dark(dark);
    if (m_graphics) m_graphics->set_dark(dark);
}
