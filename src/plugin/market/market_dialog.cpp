/// @file market_dialog.cpp
/// @brief 插件市场对话框实现(VS Code 扩展视图式布局)
#include "market_dialog.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QDir>
#include <QDoubleSpinBox>
#include <QFile>
#include <QFileDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QPainter>
#include <QPixmap>
#include <QPushButton>
#include <QScrollArea>
#include <QSpinBox>
#include <QSplitter>
#include <QTableWidget>
#include <QTabWidget>
#include <QTextBrowser>
#include <QVBoxLayout>

#include <climits>

#include "../../common/i18n.h"
#include "../plugin_api/plugin_env.h"

namespace {
// 中→英注册(文件级)
struct I18nRegMarket {
    I18nRegMarket() {
        trl::register_en("插件市场", "Plugin Marketplace");
        trl::register_en("搜索插件", "Search plugins");
        trl::register_en("%1 个插件", "%1 plugins");
        trl::register_en("全部", "All");
        trl::register_en("已安装", "Installed");
        trl::register_en("未安装", "Not installed");
        trl::register_en("已禁用", "Disabled");
        trl::register_en("已安装分组", "INSTALLED");
        trl::register_en("市场分组", "MARKETPLACE");
        trl::register_en("安装", "Install");
        trl::register_en("更新", "Update");
        trl::register_en("卸载", "Uninstall");
        trl::register_en("启用", "Enabled");
        trl::register_en("从文件安装...", "Install from file...");
        trl::register_en("刷新", "Refresh");
        trl::register_en("关闭", "Close");
        trl::register_en("版本", "Version");
        trl::register_en("作者", "Author");
        trl::register_en("分类", "Category");
        trl::register_en("平台", "Platforms");
        trl::register_en("全平台", "All platforms");
        trl::register_en("当前平台不支持", "Not supported on this platform");
        trl::register_en("ABI 不兼容", "ABI incompatible");
        trl::register_en("已安装版本", "Installed version");
        trl::register_en("可更新到", "Update available");
        trl::register_en("诊断", "Diagnosis");
        trl::register_en("报表", "Report");
        trl::register_en("图形", "Graphics");
        trl::register_en("协议解析", "Protocol");
        trl::register_en("正在加载市场...", "Loading marketplace...");
        trl::register_en("市场加载失败", "Marketplace load failed");
        trl::register_en("请选择插件包 (*.zip)", "Select plugin package (*.zip)");
        trl::register_en("插件包", "Plugin packages");
        trl::register_en("安装成功", "Installed successfully");
        trl::register_en("安装失败", "Install failed");
        trl::register_en("确定卸载该插件吗?", "Uninstall this plugin?");
        trl::register_en("需要重启插件加载才能生效(重新选择插件目录或重启程序)。",
                         "Takes effect after plugins are reloaded (reselect the plugin dir or restart).");
        trl::register_en("未选择插件", "No plugin selected");
        trl::register_en("更新时间", "Updated");
        trl::register_en("来源", "Source");
        trl::register_en("官方市场", "Official marketplace");
        trl::register_en("本地文件", "Local file");
        trl::register_en("未知", "Unknown");
        trl::register_en("README", "README");
        trl::register_en("设置", "Settings");
        trl::register_en("环境变量", "Environment");
        trl::register_en("正在加载 README...", "Loading README...");
        trl::register_en("README 加载失败", "README load failed");
        trl::register_en("暂无 README", "No README available");
        trl::register_en("安装后可配置该插件的独立设置。", "Install the plugin to configure its settings.");
        trl::register_en("该插件没有可配置项。", "This plugin has no configurable settings.");
        trl::register_en("保存", "Save");
        trl::register_en("设置已保存", "Settings saved");
        trl::register_en("设置保存失败", "Failed to save settings");
        trl::register_en("变量", "Variable");
        trl::register_en("值", "Value");
        trl::register_en("说明", "Description");
    }
};
static I18nRegMarket g_i18n_reg;

/// @brief 按名字哈希生成分类色块图标(首字母)
QPixmap letter_icon(const QString& name, int size) {
    QPixmap pm(size, size);
    pm.fill(Qt::transparent);
    uint h = qHash(name);
    const QColor bg = QColor::fromHsv(int(h % 360), 90, 200);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    p.setBrush(bg);
    p.setPen(Qt::NoPen);
    p.drawRoundedRect(0, 0, size, size, 6, 6);
    p.setPen(Qt::white);
    QFont f = p.font();
    f.setBold(true);
    f.setPointSize(size * 2 / 5);
    p.setFont(f);
    const QString ch = name.isEmpty() ? QStringLiteral("?")
                                      : name.left(1).toUpper();
    p.drawText(pm.rect(), Qt::AlignCenter, ch);
    return pm;
}

QString elide_one_line(const QString& s, int max_chars = 60) {
    const QString t = s.simplified();
    if (t.length() <= max_chars) return t;
    return t.left(max_chars - 1) + QChar(0x2026);
}

/// @brief 更新时间展示格式:ISO "2026-10-01T22:57:43Z" -> "2026-10-01 22:57"
QString format_updated_at(const QString& iso) {
    QString s = iso.trimmed();
    if (s.endsWith(QLatin1Char('Z'))) s.chop(1);
    s.replace(QLatin1Char('T'), QLatin1Char(' '));
    if (s.size() > 16 && s[16] == QLatin1Char(':')) s = s.left(16);
    return s;
}

}  // namespace

PluginMarketDialog::PluginMarketDialog(QWidget* parent)
    : QDialog(parent) {
    setup_ui();
    m_market = new PluginMarket(this);
    connect(m_market, &PluginMarket::feed_ready, this,
            &PluginMarketDialog::on_feed_ready);
    connect(m_market, &PluginMarket::feed_error, this,
            &PluginMarketDialog::on_feed_error);
    connect(m_market, &PluginMarket::text_ready, this,
            &PluginMarketDialog::on_text_ready);
    connect(m_market, &PluginMarket::text_error, this,
            &PluginMarketDialog::on_text_error);
    connect(m_market, &PluginMarket::install_progress, this,
            &PluginMarketDialog::on_install_progress);
    connect(m_market, &PluginMarket::install_finished, this,
            &PluginMarketDialog::on_install_finished);
    refresh_installed();
    on_refresh();
    rebuild_list();
}

void PluginMarketDialog::set_unload_cb(std::function<void()> cb) {
    if (m_market) m_market->unload_cb = std::move(cb);
}

void PluginMarketDialog::set_reload_cb(std::function<void()> cb) {
    if (m_market) m_market->reload_cb = std::move(cb);
}

void PluginMarketDialog::set_versions_text(const QString& t) {
    m_d_versions->setText(t);
    m_d_versions->setVisible(!t.isEmpty());
}

PluginMarketDialog::~PluginMarketDialog() = default;

void PluginMarketDialog::setup_ui() {
    setWindowTitle(trl::L("插件市场"));
    resize(1020, 640);

    auto* root = new QVBoxLayout(this);

    // 顶栏:搜索 + 过滤
    auto* top = new QHBoxLayout();
    m_search = new QLineEdit(this);
    m_search->setPlaceholderText(trl::L("搜索插件"));
    m_search->setClearButtonEnabled(true);
    connect(m_search, &QLineEdit::textChanged, this,
            &PluginMarketDialog::on_search_changed);
    m_filter = new QComboBox(this);
    m_filter->addItem(trl::L("全部"), 0);
    m_filter->addItem(trl::L("已安装"), 1);
    m_filter->addItem(trl::L("未安装"), 2);
    // 保证下拉框宽度能完整显示最长选项(参考 commconfigdialog 的做法),
    // 避免主题样式下文字被裁剪显示不全
    m_filter->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    m_filter->setMinimumContentsLength(8);
    connect(m_filter, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &PluginMarketDialog::on_filter_changed);
    top->addWidget(m_search, 1);
    top->addWidget(m_filter);
    root->addLayout(top);

    // 主体:左列表 + 右详情
    auto* split = new QSplitter(Qt::Horizontal, this);
    m_list = new QListWidget(split);
    m_list->setUniformItemSizes(false);
    m_list->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    connect(m_list, &QListWidget::currentItemChanged, this,
            [this](QListWidgetItem*, QListWidgetItem*) {
                on_selection_changed();
            });
    split->addWidget(m_list);

    auto* detail = new QWidget(split);
    auto* dl = new QVBoxLayout(detail);
    auto* head = new QHBoxLayout();
    m_d_icon = new QLabel(detail);
    m_d_icon->setFixedSize(56, 56);
    m_d_name = new QLabel(detail);
    {
        QFont f = m_d_name->font();
        f.setPointSize(f.pointSize() + 4);
        f.setBold(true);
        m_d_name->setFont(f);
    }
    m_d_name->setWordWrap(true);
    head->addWidget(m_d_icon);
    head->addWidget(m_d_name, 1);
    dl->addLayout(head);
    m_d_meta = new QLabel(detail);
    m_d_meta->setWordWrap(true);
    dl->addWidget(m_d_meta);
    auto* btns = new QHBoxLayout();
    m_btn_install = new QPushButton(trl::L("安装"), detail);
    m_btn_uninstall = new QPushButton(trl::L("卸载"), detail);
    m_chk_enabled = new QCheckBox(trl::L("启用"), detail);
    connect(m_btn_install, &QPushButton::clicked, this,
            &PluginMarketDialog::on_install_clicked);
    connect(m_btn_uninstall, &QPushButton::clicked, this,
            &PluginMarketDialog::on_uninstall_clicked);
    connect(m_chk_enabled, &QCheckBox::toggled, this,
            &PluginMarketDialog::on_enabled_toggled);
    btns->addWidget(m_btn_install);
    btns->addWidget(m_btn_uninstall);
    btns->addWidget(m_chk_enabled);
    btns->addStretch(1);
    dl->addLayout(btns);
    // 详情 tab: README(md) / 设置 / 环境变量
    m_tabs = new QTabWidget(detail);
    m_readme = new QTextBrowser(m_tabs);
    m_readme->setOpenExternalLinks(true);
    m_tabs->addTab(m_readme, trl::L("README"));
    m_settings_scroll = new QScrollArea(m_tabs);
    m_settings_scroll->setWidgetResizable(true);
    m_tabs->addTab(m_settings_scroll, trl::L("设置"));
    m_env_table = new QTableWidget(m_tabs);
    m_env_table->setColumnCount(3);
    m_env_table->setHorizontalHeaderLabels(
        {trl::L("变量"), trl::L("值"), trl::L("说明")});
    m_env_table->horizontalHeader()->setSectionResizeMode(
        2, QHeaderView::Stretch);
    m_env_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_env_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tabs->addTab(m_env_table, trl::L("环境变量"));
    dl->addWidget(m_tabs, 1);
    m_d_versions = new QLabel(detail);
    m_d_versions->setWordWrap(true);
    m_d_versions->setVisible(false);  // 为空时隐藏,不在布局里留空白行
    dl->addWidget(m_d_versions);
    split->addWidget(detail);
    split->setStretchFactor(0, 4);
    split->setStretchFactor(1, 6);
    root->addWidget(split, 1);

    m_status = new QLabel(this);
    root->addWidget(m_status);

    auto* bottom = new QHBoxLayout();
    auto* btn_file = new QPushButton(trl::L("从文件安装..."), this);
    auto* btn_refresh = new QPushButton(trl::L("刷新"), this);
    auto* btn_close = new QPushButton(trl::L("关闭"), this);
    connect(btn_file, &QPushButton::clicked, this,
            &PluginMarketDialog::on_install_from_file);
    connect(btn_refresh, &QPushButton::clicked, this,
            &PluginMarketDialog::on_refresh);
    connect(btn_close, &QPushButton::clicked, this, &QDialog::accept);
    bottom->addWidget(btn_file);
    bottom->addWidget(btn_refresh);
    bottom->addStretch(1);
    bottom->addWidget(btn_close);
    root->addLayout(bottom);
}

void PluginMarketDialog::refresh_installed() {
    m_installed = m_market->installed_plugins();
}

QString PluginMarketDialog::category_name(const QString& cat) const {
    if (cat == QStringLiteral("diagnosis")) return trl::L("诊断");
    if (cat == QStringLiteral("report")) return trl::L("报表");
    if (cat == QStringLiteral("graphics")) return trl::L("图形");
    if (cat == QStringLiteral("protocol")) return trl::L("协议解析");
    return cat;
}

void PluginMarketDialog::on_feed_ready(const QList<MarketPlugin>& plugins) {
    m_feed = plugins;
    rebuild_list();  // 末尾按实际列表行数更新计数(含平台过滤)
}

void PluginMarketDialog::on_feed_error(const QString& error) {
    m_status->setText(trl::L("市场加载失败") + QStringLiteral(": ") + error);
}

void PluginMarketDialog::on_install_progress(const QString& text) {
    m_status->setText(text);
}

void PluginMarketDialog::on_install_finished(bool ok, const QString& error,
                                             const QString& name) {
    Q_UNUSED(name);
    if (ok) {
        m_status->setText(trl::L("安装成功"));
        refresh_installed();
        rebuild_list();
    } else {
        m_status->setText(trl::L("安装失败") + QStringLiteral(": ") + error);
        QMessageBox::warning(this, trl::L("安装失败"), error);
    }
}

bool PluginMarketDialog::row_matches(const RowEntry& e) const {
    const int f = m_filter->currentData().toInt();
    if (f == 1 && !e.is_installed_group) return false;
    if (f == 2 && e.is_installed_group) return false;
    const QString q = m_search->text().trimmed().toLower();
    if (q.isEmpty()) return true;
    if (e.is_installed_group) {
        const InstalledPlugin& ip = m_installed[e.installed_index];
        return ip.manifest.name.toLower().contains(q) ||
               ip.manifest.display_name.toLower().contains(q) ||
               ip.manifest.display_name_en.toLower().contains(q) ||
               ip.manifest.author.toLower().contains(q);
    }
    const MarketPlugin& p = m_feed[e.feed_index];
    return p.name.toLower().contains(q) ||
           p.display_name.toLower().contains(q) ||
           p.display_name_en.toLower().contains(q) ||
           p.author.toLower().contains(q);
}

/// @brief 列表卡片:图标 + 名称/作者/描述 + 右侧状态徽标/更新按钮
QWidget* make_card(const QString& icon_key, const QString& title,
                   const QString& sub, const QString& desc,
                   const QString& badge, bool badge_update = false,
                   QPushButton** update_btn_out = nullptr) {
    auto* w = new QWidget();
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(6, 6, 6, 6);
    h->setSpacing(8);
    auto* icon = new QLabel(w);
    icon->setPixmap(letter_icon(icon_key, 40));
    icon->setFixedSize(40, 40);
    h->addWidget(icon, 0, Qt::AlignTop);
    auto* v = new QVBoxLayout();
    v->setSpacing(2);
    // 文本列:可收缩(Ignored),保证右侧按钮始终可见
    auto* t = new QLabel(QStringLiteral("<b>%1</b>").arg(title.toHtmlEscaped()), w);
    t->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    v->addWidget(t);
    auto* s = new QLabel(sub.toHtmlEscaped(), w);
    s->setEnabled(false);
    s->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    v->addWidget(s);
    auto* d = new QLabel(elide_one_line(desc).toHtmlEscaped(), w);
    d->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    v->addWidget(d);
    h->addLayout(v, 1);
    // 状态/更新:固定在卡片最右侧,不被长文本挤出
    if (badge_update && update_btn_out) {
        auto* btn = new QPushButton(trl::L("更新"), w);
        btn->setStyleSheet(QStringLiteral(
            "QPushButton { background-color: #1a72bb; color: #ffffff; "
            "border: none; border-radius: 3px; padding: 3px 14px; "
            "font-weight: bold; }"
            "QPushButton:hover { background-color: #259ae9; }"
            "QPushButton:pressed { background-color: #0f5a99; }"));
        btn->setCursor(Qt::PointingHandCursor);
        btn->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        h->addWidget(btn, 0, Qt::AlignVCenter);
        *update_btn_out = btn;
    } else if (!badge.isEmpty()) {
        auto* b = new QLabel(badge.toHtmlEscaped(), w);
        b->setStyleSheet(QStringLiteral(
            "QLabel { background-color: #6a6a6a; color: #ffffff; "
            "border-radius: 9px; padding: 2px 8px; "
            "font-weight: bold; font-size: 11px; }"));
        h->addWidget(b, 0, Qt::AlignVCenter);
    }
    return w;
}

void PluginMarketDialog::rebuild_list() {
    m_list->clear();
    m_rows.clear();
    const bool en = trl::enabled();

    auto add_header = [this](const QString& text) {
        auto* it = new QListWidgetItem(text, m_list);
        it->setFlags(Qt::NoItemFlags);
        QFont f = it->font();
        f.setBold(true);
        it->setFont(f);
        it->setBackground(QColor(0, 0, 0, 18));
    };

    // 已安装分组
    QList<RowEntry> inst_rows;
    for (int i = 0; i < m_installed.size(); ++i) {
        RowEntry e;
        e.is_installed_group = true;
        e.installed_index = i;
        e.name = m_installed[i].manifest.name;
        if (row_matches(e)) inst_rows.append(e);
    }
    if (!inst_rows.isEmpty()) {
        add_header(trl::L("已安装分组"));
        for (const RowEntry& e : inst_rows) {
            const InstalledPlugin& ip = m_installed[e.installed_index];
            const MarketVersion* upd =
                PluginMarket::update_for(ip, m_feed);
            bool badge_update = false;
            QString badge;
            if (upd) {
                badge_update = true;  // 左侧直接显示「更新」按钮
            } else if (!ip.enabled) {
                badge = trl::L("已禁用");
            }
            QPushButton* upd_btn = nullptr;
            auto* card = make_card(
                ip.manifest.name,
                plugin_display_name(ip.manifest, en),
                trl::L("作者") + ": " + ip.manifest.author + "  " +
                    trl::L("版本") + ": " + ip.manifest.version,
                plugin_description(ip.manifest, en), badge, badge_update,
                &upd_btn);
            if (upd_btn) {
                const QString name = ip.manifest.name;
                connect(upd_btn, &QPushButton::clicked, this,
                        [this, name]() {
                            m_current_name = name;
                            on_install_clicked();
                        });
            }
            auto* it = new QListWidgetItem(m_list);
            QSize _sh = card->sizeHint();
            _sh.setWidth(qMax(240, m_list->viewport()->width() - 4));
            it->setSizeHint(_sh);
            m_list->setItemWidget(it, card);
            m_rows.append(e);
            it->setData(Qt::UserRole, m_rows.size() - 1);
        }
    }

    // 市场分组(排除已安装)
    QSet<QString> installed_names;
    for (const InstalledPlugin& ip : m_installed)
        installed_names.insert(ip.manifest.name);
    QList<RowEntry> mkt_rows;
    for (int i = 0; i < m_feed.size(); ++i) {
        if (installed_names.contains(m_feed[i].name)) continue;
        // 平台过滤:当前运行平台无可用版本的插件不在市场中展示
        if (!m_feed[i].latest_compatible()) continue;
        RowEntry e;
        e.is_installed_group = false;
        e.feed_index = i;
        e.name = m_feed[i].name;
        if (row_matches(e)) mkt_rows.append(e);
    }
    if (!mkt_rows.isEmpty()) {
        add_header(trl::L("市场分组"));
        for (const RowEntry& e : mkt_rows) {
            const MarketPlugin& p = m_feed[e.feed_index];
            const MarketVersion* lat = p.latest_compatible();
            auto* card = make_card(
                p.name, p.localized_name(en),
                trl::L("作者") + ": " + p.author + "  " +
                    trl::L("版本") + ": " +
                    (lat ? lat->version : QStringLiteral("-")) + "  " +
                    trl::L("分类") + ": " + category_name(p.category),
                p.localized_desc(en), QString());
            auto* it = new QListWidgetItem(m_list);
            QSize _sh = card->sizeHint();
            _sh.setWidth(qMax(240, m_list->viewport()->width() - 4));
            it->setSizeHint(_sh);
            m_list->setItemWidget(it, card);
            m_rows.append(e);
            it->setData(Qt::UserRole, m_rows.size() - 1);
        }
    }
    if (m_list->count() > 0) {
        // 选中第一个可选行
        for (int i = 0; i < m_list->count(); ++i) {
            if (m_list->item(i)->flags() & Qt::ItemIsSelectable) {
                m_list->setCurrentRow(i);
                break;
            }
        }
    }
    m_status->setText(trl::L("%1 个插件").arg(m_rows.size()));
    update_detail();
}

void PluginMarketDialog::on_selection_changed() {
    update_detail();
}

void PluginMarketDialog::on_search_changed(const QString&) { rebuild_list(); }
void PluginMarketDialog::on_filter_changed(int) { rebuild_list(); }

void PluginMarketDialog::on_refresh() {
    m_status->setText(trl::L("正在加载市场..."));
    refresh_installed();
    m_market->fetch_feed(PluginMarket::default_feed_url());
    rebuild_list();
}

void PluginMarketDialog::on_install_from_file() {
    const QString zip = QFileDialog::getOpenFileName(
        this, trl::L("请选择插件包 (*.zip)"), QString(),
        trl::L("插件包") + QStringLiteral(" (*.zip)"));
    if (zip.isEmpty()) return;
    m_status->setText(trl::L("安装") + QStringLiteral("..."));
    m_market->install_from_file(zip);
}

QString PluginMarketDialog::source_label(const QString& source) const {
    if (source.isEmpty()) return trl::L("未知");
    if (source == QStringLiteral("file")) return trl::L("本地文件");
    // 官方市场:固定前缀(不用 default_feed_url(),它会被 BPLC_MARKET_FEED_URL 覆盖)
    if (source.startsWith(QStringLiteral(
            "https://raw.githubusercontent.com/aron566/BPLC_Plugin_Market/")))
        return trl::L("官方市场");
    return source;
}

void PluginMarketDialog::on_text_ready(const QString& url,
                                       const QString& text) {
    m_readme_cache[url] = text;
    if (url == m_readme_pending_url && !m_readme_pending_url.isEmpty()) {
        m_readme_pending_url.clear();
        m_readme->setMarkdown(text);
    }
}

void PluginMarketDialog::on_text_error(const QString& url,
                                      const QString& error) {
    Q_UNUSED(error);
    if (url == m_readme_pending_url && !m_readme_pending_url.isEmpty()) {
        m_readme_pending_url.clear();
        m_readme->setPlainText(trl::L("README 加载失败"));
    }
}

/// @brief README 解析链:已安装插件目录 README.md → feed readme_url → 描述
void PluginMarketDialog::update_readme_tab(const InstalledPlugin* ip,
                                           const MarketPlugin* mp) {
    m_readme_pending_url.clear();
    if (ip) {
        for (const char* fn : {"README.md", "readme.md"}) {
            QFile f(QDir(ip->dir).filePath(QString::fromLatin1(fn)));
            if (f.open(QIODevice::ReadOnly)) {
                m_readme->setMarkdown(QString::fromUtf8(f.readAll()));
                return;
            }
        }
    }
    const MarketPlugin* fmp = mp;
    if (!fmp && ip) {
        for (const MarketPlugin& p : m_feed) {
            if (p.name == ip->manifest.name) {
                fmp = &p;
                break;
            }
        }
    }
    if (fmp && !fmp->readme_url.isEmpty()) {
        const QString url = fmp->readme_url;
        if (m_readme_cache.contains(url)) {
            m_readme->setMarkdown(m_readme_cache.value(url));
        } else {
            m_readme->setPlainText(trl::L("正在加载 README..."));
            m_readme_pending_url = url;
            m_market->fetch_text(url, fmp->mirror_prefix);
        }
        return;
    }
    QString desc;
    if (ip)
        desc = plugin_description(ip->manifest, trl::enabled());
    else if (mp)
        desc = mp->localized_desc(trl::enabled());
    m_readme->setPlainText(
        desc.isEmpty() ? trl::L("暂无 README") : desc);
}

QWidget* PluginMarketDialog::make_setting_widget(const PluginSetting& s,
                                                const QVariant& cur) {
    if (s.type == QStringLiteral("boolean")) {
        auto* c = new QCheckBox();
        c->setChecked(cur.toBool());
        return c;
    }
    if (!s.enum_options.isEmpty()) {
        auto* cb = new QComboBox();
        cb->addItems(s.enum_options);
        const int idx = cb->findText(cur.toString());
        cb->setCurrentIndex(idx < 0 ? 0 : idx);
        return cb;
    }
    if (s.type == QStringLiteral("integer")) {
        auto* sp = new QSpinBox();
        sp->setMinimum(s.has_minimum ? int(s.minimum) : INT_MIN);
        sp->setMaximum(s.has_maximum ? int(s.maximum) : INT_MAX);
        sp->setValue(cur.toInt());
        return sp;
    }
    if (s.type == QStringLiteral("number")) {
        auto* sp = new QDoubleSpinBox();
        sp->setMinimum(s.has_minimum ? s.minimum : -1e12);
        sp->setMaximum(s.has_maximum ? s.maximum : 1e12);
        sp->setValue(cur.toDouble());
        return sp;
    }
    auto* le = new QLineEdit();
    le->setText(cur.toString());
    return le;
}

/// @brief 设置页:按 manifest settings schema 生成表单,值落盘 settings.json
void PluginMarketDialog::rebuild_settings_tab(const InstalledPlugin* ip) {
    m_setting_widgets.clear();
    m_setting_schema.clear();
    m_settings_dir.clear();
    delete m_settings_scroll->takeWidget();

    auto* page = new QWidget();
    auto* vl = new QVBoxLayout(page);
    if (!ip) {
        vl->addWidget(
            new QLabel(trl::L("安装后可配置该插件的独立设置。"), page));
        vl->addStretch(1);
    } else if (ip->manifest.settings.isEmpty()) {
        vl->addWidget(new QLabel(trl::L("该插件没有可配置项。"), page));
        vl->addStretch(1);
    } else {
        m_settings_dir = ip->dir;
        m_setting_schema = ip->manifest.settings;
        QVariantMap cur;
        QFile f(QDir(ip->dir).filePath(QStringLiteral("settings.json")));
        if (f.open(QIODevice::ReadOnly)) {
            const QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
            if (doc.isObject()) cur = doc.object().toVariantMap();
        }
        const bool en = trl::enabled();
        auto* form = new QFormLayout();
        for (const PluginSetting& s : m_setting_schema) {
            QWidget* w =
                make_setting_widget(s, cur.value(s.key, s.default_value));
            w->setToolTip(s.localized_desc(en));
            auto* lab = new QLabel(s.localized_title(en), page);
            lab->setToolTip(s.localized_desc(en));
            form->addRow(lab, w);
            m_setting_widgets[s.key] = w;
        }
        vl->addLayout(form);
        auto* btn_row = new QHBoxLayout();
        auto* save = new QPushButton(trl::L("保存"), page);
        connect(save, &QPushButton::clicked, this,
                &PluginMarketDialog::on_settings_save);
        btn_row->addStretch(1);
        btn_row->addWidget(save);
        vl->addLayout(btn_row);
        vl->addStretch(1);
    }
    m_settings_scroll->setWidget(page);
}

void PluginMarketDialog::on_settings_save() {
    if (m_settings_dir.isEmpty()) return;
    QVariantMap values;
    for (auto it = m_setting_widgets.constBegin();
         it != m_setting_widgets.constEnd(); ++it) {
        QWidget* w = it.value();
        if (auto* c = qobject_cast<QCheckBox*>(w))
            values[it.key()] = c->isChecked();
        else if (auto* cb = qobject_cast<QComboBox*>(w))
            values[it.key()] = cb->currentText();
        else if (auto* sp = qobject_cast<QSpinBox*>(w))
            values[it.key()] = sp->value();
        else if (auto* dsp = qobject_cast<QDoubleSpinBox*>(w))
            values[it.key()] = dsp->value();
        else if (auto* le = qobject_cast<QLineEdit*>(w))
            values[it.key()] = le->text();
    }
    QString err;
    if (plugin_write_settings(m_settings_dir, values, &err)) {
        m_status->setText(trl::L("设置已保存"));
    } else {
        m_status->setText(trl::L("设置保存失败") + QStringLiteral(": ") + err);
    }
}

/// @brief 环境变量页:宿主提供的公共环境变量一览
void PluginMarketDialog::rebuild_env_tab(const InstalledPlugin* ip) {
    const bool en = trl::enabled();
    const QList<PluginEnvVar> vars = plugin_common_env_vars();
    m_env_table->setRowCount(vars.size());
    const QString dir = ip ? ip->dir : QString();
    for (int i = 0; i < vars.size(); ++i) {
        const PluginEnvVar& v = vars[i];
        QString val = plugin_env_value(v.name, dir, en);
        if (v.name == QStringLiteral("BPLC_PLUGIN_DIR") && dir.isEmpty())
            val = trl::L("未安装");
        m_env_table->setItem(i, 0, new QTableWidgetItem(v.name));
        m_env_table->setItem(i, 1, new QTableWidgetItem(val));
        auto* d = new QTableWidgetItem(v.localized_desc(en));
        d->setToolTip(v.localized_title(en));
        m_env_table->setItem(i, 2, d);
    }
    m_env_table->resizeColumnsToContents();
}

void PluginMarketDialog::update_detail() {
    const bool en = trl::enabled();
    QListWidgetItem* cur = m_list->currentItem();
    const bool has_sel =
        cur && (cur->flags() & Qt::ItemIsSelectable) &&
        cur->data(Qt::UserRole).isValid();
    if (!has_sel) {
        m_current_name.clear();
        m_d_icon->clear();
        m_d_name->setText(trl::L("未选择插件"));
        m_d_meta->clear();
        set_versions_text(QString());
        m_readme->clear();
        rebuild_settings_tab(nullptr);
        rebuild_env_tab(nullptr);
        m_btn_install->setEnabled(false);
        m_btn_uninstall->setEnabled(false);
        m_chk_enabled->setEnabled(false);
        return;
    }
    const RowEntry& e = m_rows[cur->data(Qt::UserRole).toInt()];
    m_current_name = e.name;
    m_d_icon->setPixmap(letter_icon(e.name, 56));

    const InstalledPlugin* ip = nullptr;
    const MarketPlugin* mp = nullptr;
    if (e.is_installed_group) {
        ip = &m_installed[e.installed_index];
        const InstalledPlugin& p = *ip;
        m_d_name->setText(plugin_display_name(p.manifest, en));
        const QString upd =
            p.updated_at.isEmpty() ? p.installed_at : p.updated_at;
        m_d_meta->setText(
            trl::L("作者") + ": " + p.manifest.author + "\n" +
            trl::L("已安装版本") + ": " + p.manifest.version + "\n" +
            trl::L("更新时间") + ": " +
                (upd.isEmpty() ? trl::L("未知") : format_updated_at(upd)) + "\n" +
            trl::L("来源") + ": " + source_label(p.source));
        const MarketVersion* upd_v = PluginMarket::update_for(p, m_feed);
        if (upd_v) {
            set_versions_text(trl::L("可更新到") + ": " + upd_v->version);
            m_btn_install->setText(trl::L("更新"));
            m_btn_install->setEnabled(true);
        } else {
            set_versions_text(QString());
            m_btn_install->setEnabled(false);
            m_btn_install->setText(trl::L("安装"));
        }
        m_btn_uninstall->setEnabled(true);
        m_chk_enabled->setEnabled(true);
        m_chk_enabled->blockSignals(true);
        m_chk_enabled->setChecked(p.enabled);
        m_chk_enabled->blockSignals(false);
    } else {
        mp = &m_feed[e.feed_index];
        const MarketPlugin& p = *mp;
        const MarketVersion* lat = p.latest_compatible();
        m_d_name->setText(p.localized_name(en));
        // 区分「平台不支持」与「native ABI 不兼容」的提示
        const MarketVersion* lat_platform = nullptr;
        for (int i = p.versions.size() - 1; i >= 0; --i)
            if (PluginMarket::version_platform_ok(p.versions[i])) {
                lat_platform = &p.versions[i];
                break;
            }
        const QString plat_txt =
            lat ? (lat->platforms.isEmpty() ? trl::L("全平台")
                                            : lat->platforms.join(", "))
                : (lat_platform ? trl::L("ABI 不兼容")
                                : trl::L("当前平台不支持"));
        m_d_meta->setText(
            trl::L("作者") + ": " + p.author + "\n" +
            trl::L("版本") + ": " + (lat ? lat->version : "-") + "\n" +
            trl::L("更新时间") + ": " +
                ((lat && !lat->updated_at.isEmpty())
                     ? format_updated_at(lat->updated_at)
                     : trl::L("未知")) +
            "\n" + trl::L("分类") + ": " + category_name(p.category) + "\n" +
            trl::L("平台") + ": " + plat_txt + "\n" +
            trl::L("来源") + ": " + source_label(p.source));
        // 历史版本不展示:最新版本已在上面「版本」字段显示
        set_versions_text(QString());
        m_btn_install->setText(trl::L("安装"));
        m_btn_install->setEnabled(lat && PluginMarket::app_version_ok(
                                              lat->min_app_version));
        m_btn_uninstall->setEnabled(false);
        m_chk_enabled->setEnabled(false);
    }
    update_readme_tab(ip, mp);
    rebuild_settings_tab(ip);
    rebuild_env_tab(ip);
}

void PluginMarketDialog::on_install_clicked() {
    if (m_current_name.isEmpty()) return;
    // 已安装且有更新 → 装最新兼容版;未安装 → 装最新兼容版
    for (const MarketPlugin& p : m_feed) {
        if (p.name != m_current_name) continue;
        const MarketVersion* lat = p.latest_compatible();
        if (!lat) return;
        int idx = -1;
        for (int i = 0; i < p.versions.size(); ++i) {
            if (p.versions[i].version == lat->version) { idx = i; break; }
        }
        if (idx < 0) return;
        m_market->install_market_plugin(p, idx);
        return;
    }
}

void PluginMarketDialog::on_uninstall_clicked() {
    if (m_current_name.isEmpty()) return;
    if (QMessageBox::question(this, trl::L("卸载"),
                              trl::L("确定卸载该插件吗?")) !=
        QMessageBox::Yes)
        return;
    if (m_market->uninstall(m_current_name)) {
        m_status->setText(trl::L("安装成功"));
        refresh_installed();
        rebuild_list();
    }
}

void PluginMarketDialog::on_enabled_toggled(bool on) {
    if (m_current_name.isEmpty()) return;
    if (m_market->set_enabled(m_current_name, on)) {
        m_status->setText(
            trl::L("需要重启插件加载才能生效(重新选择插件目录或重启程序)。"));
        refresh_installed();
        rebuild_list();
    }
}
