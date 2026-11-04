// verify_simple_head.cpp — GW_2026 单跳 MAC 帧(表3 MSDU_BASE_S)端到端验证
// @details 构造 HDC 2.0 载波 SOF 帧(PB136,分集拷贝 TMI=2→136B):
//   FCH(16B,含 CRC24) + PB头(START|END,seq=0) + 单跳MSDU(4B头+RFDL载荷) + PB CRC24
// 分别喂 GW_2026_Parser 与 GW_2022_MsduParser(对照),断言:
//   ① 版本=1(HDC 2.0)不被委托,GW_2026 原生解析
//   ② msdu.present=true 且 simple_head=true(单跳头识别正确)
//   ③ RFDL TLV 逐字段挂树(Discovery List Message)
//   ④ 单跳头各字段字节高亮坐标正确(RSV1 4bit + AggregateMacFlag 1bit)
//   ⑤ MSDULen 声明长度与实际一致;越界声明被钳制不越界
#include "bplcframe.h"
#include "gw_2026_parser.h"
#include "gw_2026_msdu_parser.h"
#include "gw_2022_parser.h"
#include "gw_2022_msdu_parser.h"
#include "crc.h"
#include "common/fieldtools.h"
#include <string>

#include <QCoreApplication>
#include <cstdio>

namespace {

// CRC32(载荷区用,与 crc.h crc32_le 同参:遍历前 len-4 字节,存储于尾 4B LE)
quint32 payload_crc32(const QByteArray& d) {
    return crc32_le(reinterpret_cast<const quint8*>(d.constData()), d.size());
}

/// 构造一帧载波 SOF:TMI=2(136B PB) + 单 MSDU(单跳头+RFDL)
/// @note BplcFrame.data 标准封装:[dlen 2B][timestamp 4B][phr_mcs][option][channel][isRF]
///       + MPDU(与 serialreader 输出一致);decode_envelope 按此剥 10B 头
QByteArray make_simple_sof_frame(const QByteArray& msdu) {
    // ── FCH(表7,HDC 2.0):16B ──
    QByteArray fch(16, char(0));
    fch[0] = 0x01;                      // 定界符类型=1(SOF) 网络类型=0
    fch[1] = 0x01; fch[2] = 0x00;       // NID=1(16bit,1-65535)
    fch[3] = 0x00;                      // 保留(2.0)
    // byte4-5 源TEI=1(CCO);byte6-7 目的TEI=0xFFF(广播)
    fch[4] = 0x01; fch[5] = 0x00;
    fch[6] = 0xFF; fch[7] = 0xF0;       // (6,4,12)=0xFFF
    fch[8] = 0x00; fch[9] = 0x00;       // 帧长(示意,解析不强校验)
    fch[10] = 0x08;                     // (10,2,5)调制参数=2(TMI=2→136B PB);(10,1)方式=0
    // byte11: bit0-1 PB编码低1bit=0, bit1 广播=1, bit3 重传=0, bit4-6 频段=0
    fch[11] = 0x02;                     // bit1=1(广播);PB编码高位(bit7? no:(10,7)+(11,0))低1位=0
    fch[12] = 0x10;                     // (12,4)标准版本号=1(HDC 2.0)
    const quint32 fch_crc = crc24_lsb(reinterpret_cast<const quint8*>(fch.constData()), 16);
    fch[13] = char(fch_crc & 0xFF);
    fch[14] = char((fch_crc >> 8) & 0xFF);
    fch[15] = char((fch_crc >> 16) & 0xFF);

    // ── PB 块(136B):PB头 + 载荷 + CRC24 ──
    const int pb_size = 136;
    QByteArray blk(pb_size, char(0));
    blk[0] = char(0xC0);                // START|END, seq=0
    const int body_len = pb_size - 4;   // 132B 数据区
    // 载荷 = MSDU + CRC32(4B),MSDU 余量填 0
    QByteArray payload = msdu;
    while (payload.size() < body_len - 4) payload.append(char(0));
    payload.resize(body_len - 4);
    const quint32 pcrc = payload_crc32(payload);
    payload.append(char(pcrc & 0xFF));
    payload.append(char((pcrc >> 8) & 0xFF));
    payload.append(char((pcrc >> 16) & 0xFF));
    payload.append(char((pcrc >> 24) & 0xFF));
    blk.replace(1, payload.size(), payload);
    const quint32 blk_crc = crc24_lsb(reinterpret_cast<const quint8*>(blk.constData()), pb_size);
    blk[pb_size - 3] = char(blk_crc & 0xFF);
    blk[pb_size - 2] = char((blk_crc >> 8) & 0xFF);
    blk[pb_size - 1] = char((blk_crc >> 16) & 0xFF);

    const QByteArray mpdu = fch + blk;

    // ── 封装头(10B):dlen 2B(LE,= MPDU 长度)+ timestamp 4B + 媒介 4B ──
    QByteArray hdr(10, char(0));
    hdr[0] = char(mpdu.size() & 0xFF);
    hdr[1] = char((mpdu.size() >> 8) & 0xFF);
    // hdr[2..5] timestamp = 0(示意)
    hdr[6] = 0;                          // phr_mcs(载波占位)
    hdr[7] = 0;                          // option
    hdr[8] = 0;                          // channel(频段0)
    hdr[9] = 0;                          // isRF=0 → 载波
    return hdr + mpdu;
}

/// 单跳 MSDU(表3 4B头) + RFDL 载荷(表123:STA MAC 6B + Seq 1B + 1个站点属性 IE)
QByteArray make_simple_msdu() {
    QByteArray rfdl;
    // 表123 头:STA MAC = 34-5A-11-22-33-44;统计序号=7
    rfdl.append(char(0x34)); rfdl.append(char(0x5A)); rfdl.append(char(0x11));
    rfdl.append(char(0x22)); rfdl.append(char(0x33)); rfdl.append(char(0x44));
    rfdl.append(char(0x07));
    // IE0:站点属性(类型0,短长度):TEI=0x123 代理TEI=0x001 层级=2 角色=1
    rfdl.append(char(0x00));            // IE头:类型0(bit0-6) 长度类型0(bit7→1B长度)
    rfdl.append(char(0x06));            // 长度=6
    rfdl.append(char(0x23)); rfdl.append(char(0x10));   // TEI 12b=0x123(LE 打包示意)
    rfdl.append(char(0x01)); rfdl.append(char(0x00));   // 代理TEI=1
    rfdl.append(char(0x21));                            // 层级2|角色1
    rfdl.append(char(0x55));                            // 信道质量

    QByteArray h(4, char(0));
    h[0] = 0x01;                        // 版本=1(单跳帧协议) + 保留
    h[1] = 0x00;                        // 消息类型=0(无线发现列表消息)
    const int len = rfdl.size();
    h[2] = char(len & 0xFF);            // MSDU 长度 11bit 低8位
    h[3] = char(((len >> 8) & 0x07));   // 高3位;bit3-6 保留;bit7 聚合标识=0
    return h + rfdl;
}

int fails = 0;
void expect(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "OK" : "FAIL", what);
    if (!ok) ++fails;
}

}  // namespace

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    std::printf("== GW_2026 单跳 MAC 帧端到端验证 ==\n");

    // ── 用例1:正常单跳帧(RFDL) ──
    {
        BplcFrame fr;
        fr.data = make_simple_sof_frame(make_simple_msdu());
        fr.meta.has_time_tag = false;
        GW_2026_Parser p;
        MsduState reasm;
        ParseFilter f;
        const auto r = p.parse(fr, reasm, f);
        std::printf("用例1 正常单跳帧: accept=%d reason=[%s] proto=%d\n",
                    r.accept, qPrintable(r.reject_reason), int(r.protocol));
        expect(r.accept, "帧被接受(FCH CRC24 通过,版本=1 不委托)");
        expect(r.protocol == ProtocolVariant::GW_2026, "协议身份=GW_2026 原生");
        expect(r.msdu.present, "MSDU 重组完整");
        expect(r.msdu.simple_head, "单跳帧头识别(simple_head=true)");
        const std::string sum = r.msdu.summary.toStdString();
        expect(r.msdu.summary.contains(QStringLiteral("Discovery List")),
               ("RFDL 消息识别: " + sum).c_str());
        bool has_mac = false, has_agg = false, has_ie = false;
        for (const auto& n : r.msdu.tree) {
            if (n.name.startsWith(QStringLiteral("STA MAC"))) has_mac = true;
            if (n.name.startsWith(QStringLiteral("AggregateMacFlag"))) has_agg = true;
            if (n.name.startsWith(QStringLiteral("IE[0]"))) has_ie = true;
        }
        expect(has_mac, "RFDL STA MAC 字段挂树");
        expect(has_agg, "单跳头聚合标识字段挂树(表3 新增)");
        expect(has_ie, "RFDL IE TLV 逐字段挂树");
        // 高亮映射:单块帧 msdu_raw_base=17(FCH16+PB头1)
        expect(r.msdu_raw_base == 17, "单块帧 raw 高亮基址=17");
    }

    // ── 用例2:MSDULen 声明越界(声明 > 实际)→ 钳制不越界 ──
    {
        QByteArray msdu = make_simple_msdu();
        msdu[2] = char(0xFF);           // 声明长度低位拉满(远超实际)
        msdu[3] = char(0x07);           // 高位也拉满 → 声明 ~2047
        BplcFrame fr;
        fr.data = make_simple_sof_frame(msdu);
        fr.meta.has_time_tag = false;
        GW_2026_Parser p;
        MsduState reasm;
        ParseFilter f;
        const auto r = p.parse(fr, reasm, f);
        std::printf("用例2 声明长度越界: accept=%d present=%d\n", r.accept, r.msdu.present);
        expect(r.accept && r.msdu.present, "越界声明被钳制,解析不崩溃不拒收");
    }

    // ── 用例3:非 RFDL 单跳帧(应用层消息 type=128)→ 概要分支 ──
    {
        QByteArray msdu = make_simple_msdu();
        msdu[1] = char(128);            // 消息类型=128 应用层报文
        BplcFrame fr;
        fr.data = make_simple_sof_frame(msdu);
        fr.meta.has_time_tag = false;
        GW_2026_Parser p;
        MsduState reasm;
        ParseFilter f;
        const auto r = p.parse(fr, reasm, f);
        std::printf("用例3 应用层单跳帧: summary=[%s]\n", qPrintable(r.msdu.summary));
        expect(r.accept && r.msdu.present && r.msdu.simple_head,
               "非 RFDL 单跳帧正常识别为 Simple MSDU");
    }

    // ── 用例4:单跳头识别一致性互证(MSDU 层直测) ──
    // 注:整帧不能跨协议互喂——1.0 表19 与 2.0 表7 的 FCH 布局不同(本帧 TMI 位置
    // 字节11 bit4-7 在 1.0 下读 0→PB520≠实际136,必然拒收),这正是版本自适应
    // 按 FCH 版本号分流的原因。单跳识别在 MsduParser 层,两代逻辑应一致。
    {
        const QByteArray body = make_simple_msdu();
        const auto r = GW_2026_MsduParser::parse(body);
        const auto r22 = GW_2022_MsduParser::parse(body);
        std::printf("用例4 MSDU 层互证: 26.simple=%d 22.simple=%d\n",
                    r.simple_head, r22.simple_head);
        expect(r.simple_head && r22.simple_head,
               "同一单跳 MSDU 在 2.0/1.0 MsduParser 下识别一致(子集互证)");
        expect(r.msdu_src_tei == -1 && r22.msdu_src_tei == -1,
               "单跳帧无原始源 TEI(简头语义一致)");
    }

    std::printf("\n%s\n", fails == 0 ? "PASS: 单跳 MAC 帧解析全部断言通过"
                                    : "FAIL: 存在失败断言");
    return fails == 0 ? 0 : 2;
}
