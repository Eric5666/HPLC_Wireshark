/// @file i18n.cpp
/// @brief 轻量中/英翻译实现 + 通用界面词典
/// @details 文件级词典由各模块在匿名命名空间 register_en() 注册(见 i18n.h),
///          通用条目集中在本文件 en_dict 表。
#include "i18n.h"
#include <QHash>
#include <QCoreApplication>
#include <QReadLocker>
#include <QReadWriteLock>
#include <QWriteLocker>
#include <atomic>

namespace {

/// 通用 UI 词典(界面/状态/菜单;协议字段词典由各模块文件注册)
const struct { const char* zh; const char* en; } en_dict[] = {
    // ---- 主窗口/菜单 ----
    { "捕获(&C)", "&Capture" },
    { "开始", "Start" },
    { "停止", "Stop" },
    { "暂停", "Pause" },
    { "清空", "Clear" },
    { "导出...", "Export..." },
    { "分析(&A)", "&Analyze" },
    { "应用显示过滤器", "Apply display filter" },
    { "帮助(&H)", "&Help" },
    { "检查更新(&U)...", "Check for Updates(&U)..." },
    { "关于(&A)", "About(&A)" },
    { "正在检查更新…", "Checking for updates..." },
    { "发现新版本,请按提示下载更新", "New version found, download when prompted" },
    { "检查更新完成:暂无可更新版本(若网络不可达请检查连接)",
      "Update check done: up to date (check network if unreachable)" },
    { "关于 BPLC STA Monitor", "About BPLC STA Monitor" },
    { "打开仓库(&R)", "Open Repository(&R)" },
    { "BPLC/HRF 协议 STA 报文监控上位机(串口捕获 + 离线回放)。",
      "BPLC/HRF STA frame monitor (serial capture + offline replay)." },
    { "作者", "Author" },
    { "版本", "Version" },
    { "仓库", "Repository" },
    { "更新源:GitHub HPLC_Wireshark 仓库", "Updates: GitHub HPLC_Wireshark repo" },
    // ---- 状态栏 ----
    { "[状态] ", "[Status] " },
    { "Ready — Ctrl+E 开始捕获,Ctrl+L 清空", "Ready — Ctrl+E start capture, Ctrl+L clear" },
    { "Cleared", "Cleared" },
    { "配置已保存(Ctrl+E 开始捕获)", "Settings saved (Ctrl+E to start)" },
    { "无可导出的帧", "No frames to export" },
    { "导出失败:%1", "Export failed: %1" },
    { "导出写入失败", "Export write failed" },
    { "没有可写入的帧数据", "No frame data to write" },
    { "已导出 %1 帧 → %2", "Exported %1 frames → %2" },
    { "正在检查更新…", "Checking for updates..." },
    { "完整更新说明见仓库 Releases 页面", "Full release notes: see repo Releases page" },
    // ---- 主题/设置 ----
    { "主题/Theme:", "Theme:" },
    { "深色", "Dark" },
    { "浅色", "Light" },
    { "语言", "Language" },
    // ---- 右键菜单 ----
    { "无高亮字节可复制(先点击协议字段)",
      "Nothing to copy — click a protocol field first" },
    { "复制 Hex(%1 字节)", "Copy Hex (%1 bytes)" },
    { "复制为 0x 前缀(%1 字节)", "Copy as 0x-prefixed (%1 bytes)" },
    // ---- 表头/列表 ----
    { "帧类型", "Frame Type" },
    { "MSDU 类型", "MSDU Type" },
    { "MSDU 序号", "MSDU Seq" },
    { "总长度", "Total Length" },
    // ---- 过滤器 ----
    { "过滤器错误:%1", "Filter error: %1" },
    // ---- 拖放导入 ----
    { "导入", "Import" },
    { "不支持的文件类型(支持 .bin / .txt / .hex): %1",
      "Unsupported file type (.bin / .txt / .hex supported): %1" },
    { "正在捕获/回放中,请先点击停止后再拖入文件",
      "Capturing/replaying, please stop before dropping a file" },
};

/// @brief 词典 + 读写锁
/// @details 解析线程每个字段都在 trl::L 查找,GUI 线程运行期仍会注册(设置对话框里的
///          协议显示名、插件)。QHash 不支持并发读写(insert 触发 rehash 时读方会访问
///          已释放的桶),故读取加读锁、注册加写锁。函数内静态对象的初始化由 C++11
///          保证线程安全(取代旧的 static bool inited 惰性初始化)。
struct Dict {
    QReadWriteLock lock;
    QHash<QString, QString> map;
    Dict() {
        for (const auto& e : en_dict) map.insert(QString::fromUtf8(e.zh),
                                                 QString::fromUtf8(e.en));
    }
};

Dict& dict() {
    static Dict d;
    return d;
}

std::atomic<bool> g_en{false};

}  // namespace

namespace trl {

void set_enabled(bool enabled) { g_en.store(enabled, std::memory_order_relaxed); }

bool enabled() { return g_en.load(std::memory_order_relaxed); }

void register_en(const char* zh, const char* en) {
    const QString k = QString::fromUtf8(zh);
    const QString v = QString::fromUtf8(en);
    Dict& d = dict();
    {
        // 重复注册(如每次打开设置对话框)多数是同值:读锁判定后直接返回,不与解析线程争写锁
        QReadLocker rl(&d.lock);
        const auto it = d.map.constFind(k);
        if (it != d.map.constEnd() && it.value() == v) return;
    }
    QWriteLocker wl(&d.lock);
    d.map.insert(k, v);
}

QString L(const char* zh) {
    if (!g_en.load(std::memory_order_relaxed) || !zh) return QString::fromUtf8(zh);
    const QString k = QString::fromUtf8(zh);
    Dict& d = dict();
    QReadLocker rl(&d.lock);
    const auto it = d.map.constFind(k);
    return (it != d.map.constEnd()) ? it.value() : k;
}

}  // namespace trl
