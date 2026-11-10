// NW_2026 截断帧 pb_crc_ok 语义回归用例(定法 a)。
// 语义:pb_crc_ok = 全部声明块都已收到且 CRC24 通过(不只是已收块全过);
// 截断帧即使已收块全过也为 false,与红行谓词“含截断”意图一致。
// 构帧:SPLC 单站点载波 SOF version=2,声明 2 块 264B(TMI 9),块体为
// NW AssocReq MSDU(同 nw-crc-probe 的 build_nw_assoc)。
// 断言:
//   全 2 块好 CRC:pb_crc_ok=true,oks=[true,true];
//   声明 2 块仅收 1 好块:pb_crc_ok=false,oks=[true],摘要含“截断”;
//   声明 2 块收 0 块:pb_crc_ok=false,oks 为空;
//   2 块、第 2 块 CRC 翻转:pb_crc_ok=false,oks=[true,false](旧口径亦 false,防退化)。
// 未修复代码上第 2、3 用例失败(截断时 pb_crc_ok 仍为 true)。
#include <QCoreApplication>
#include <cstdio>
#include <cstring>
#include "nw_2026_parser.h"
#include "fieldtools.h"
#include "crc.h"

static quint64 mac6(quint8 a, quint8 b, quint8 c, quint8 d, quint8 e, quint8 f) {
    return (quint64)a | ((quint64)b << 8) | ((quint64)c << 16)
         | ((quint64)d << 24) | ((quint64)e << 32) | ((quint64)f << 40);
}
static void put_mac(quint8* p, quint64 mac) {
    for (int i = 0; i < 6; ++i) p[i] = (quint8)((mac >> (8 * i)) & 0xFF);
}
static void put_crc24(quint8* blk, int len) {
    const quint32 calc = crc24_lsb(blk, len);
    blk[len - 3] = calc & 0xFF;
    blk[len - 2] = (calc >> 8) & 0xFF;
    blk[len - 1] = (calc >> 16) & 0xFF;
}

// 与 nw-crc-probe 的 build_nw_assoc 同构:NW AssocReq MAC 帧 134B。
static QByteArray build_nw_assoc(int dst_tei, quint64 dst_mac, int src_tei,
                                 quint64 src_mac, int restart) {
    QByteArray mme(80, 0);
    quint8* m = reinterpret_cast<quint8*>(mme.data());
    m[0] = 0x01;                     // MMe version
    m[1] = 0x30; m[2] = 0x00;        // MMType 0x0030 ASSOCREQ (LE)
    put_mac(m + 6, src_mac);         // STAMAC at mme offset 6
    const int msdu_len = 18 + (int)mme.size();
    QByteArray f(32 + msdu_len + 4, 0);
    quint8* p = reinterpret_cast<quint8*>(f.data());
    p[0] = 0x02;                     // version 1, long head
    p[2] = quint8(msdu_len & 0xFF); p[3] = quint8((msdu_len >> 8) & 0xFF);
    p[4] = quint8(dst_tei & 0xFF);
    p[5] = quint8(((dst_tei >> 8) & 0x0F) | ((src_tei & 0x0F) << 4));
    p[6] = quint8((src_tei >> 4) & 0xFF);
    p[7] = quint8((restart & 0x0F) << 4);
    p[10] = 0xEE; p[11] = 0x64;
    put_mac(p + 12, dst_mac);        // SPLC-4 表7 目的 MAC bytes 12-17
    put_mac(p + 32, dst_mac);
    put_mac(p + 38, src_mac);
    p[44] = 0x00; p[45] = 0x81; p[46] = 0x00; p[47] = 0x00;  // VLAN 0x8100
    p[48] = 0xE1; p[49] = 0x88;                              // type 0x88E1
    memcpy(p + 50, mme.constData(), mme.size());
    // MSDU 帧尾 4B CRC32:与 append_msdu_crc 同语义(crc32_le 遍历 len-4 字节,
    // 存储在 payload_start(32, 长头)+payload_len 起的 4B,小端)。合成帧必须是"好载荷",
    // 否则新口径(MSDU CRC 正确才采信)会正确判坏载荷并清空 learning。
    const quint32 crc = crc32_le(p + 32, msdu_len + 4);
    p[32 + msdu_len + 0] = quint8(crc & 0xFF);
    p[32 + msdu_len + 1] = quint8((crc >> 8) & 0xFF);
    p[32 + msdu_len + 2] = quint8((crc >> 16) & 0xFF);
    p[32 + msdu_len + 3] = quint8((crc >> 24) & 0xFF);
    return f;
}

// 单站 PB:264B = 头 4B(agg=0 非聚合)+ 体 256B + 保留 1B + CRC24 3B。
static QByteArray build_block(const QByteArray& msdu, int seq, bool flip_crc) {
    QByteArray blk(264, 0);
    quint8* p = reinterpret_cast<quint8*>(blk.data());
    p[0] = quint8(seq & 0xFF); p[1] = quint8((seq >> 8) & 0xFF);
    p[2] = 0x00;                     // agg bit0 = 0:非聚合分支
    memcpy(p + 4, msdu.constData(), msdu.size());
    put_crc24(p, 264);
    if (flip_crc) p[263] ^= 0xFF;    // 末 CRC 字节翻转
    return blk;
}

// SPLC 单站点载波 SOF version=2(表23):FCH 16B + n 块,每块 264B。
// FCH:byte4 bit0=0(单站点)、bit1=0(非训练)、bits2-5=pb_num;
// byte5 bits3-5=频段 0;byte6 bit0=0(非 Bitloading)、bits1-5=TMI 9;
// byte12 高半=2(version 2)。
static QByteArray build_sof(int pb_num, const QVector<QByteArray>& blocks) {
    QByteArray f(16, 0);
    quint8* p = reinterpret_cast<quint8*>(f.data());
    p[0] = 0x01;                     // SOF, SNID 0
    set_bits(p, 1, 0, 12, 1);        // FCH 源 TEI = 1 (CCO)
    set_bits(p, 2, 4, 12, 0xFFF);    // FCH 目的 TEI = 广播
    p[4] = quint8((pb_num & 0x0F) << 2);
    p[6] = quint8(9 << 1);           // TMI 9 -> 264B
    set_bits(p, 8, 0, 12, 100);      // 帧长(显示用)
    p[12] = 0x20;                    // version 2
    put_crc24(p, 16);                // FCH CRC24
    for (const QByteArray& b : blocks) f.append(b);
    return f;
}

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    const quint64 cco   = mac6(0x02, 0, 0, 0, 0, 0x01);
    const quint64 sta27 = mac6(0x02, 0, 0, 0, 0, 0x27);
    const QByteArray body = build_nw_assoc(1, cco, 27, sta27, 5);
    int fails = 0;
    auto check = [&](const char* name, bool ok) {
        std::printf("%s: %s\n", name, ok ? "PASS" : "FAIL");
        if (!ok) ++fails;
    };
    NW_2026_Parser parser;
    ParseFilter filt;                // 默认全放行
    auto run = [&](const QByteArray& mpdu) {
        BplcFrame fr;
        fr.meta.from_raw = true;
        fr.data = QByteArray(1, char(0)) + mpdu;
        MsduState msdu;
        return parser.parse(fr, msdu, filt);
    };
    {
        // 全 2 块好 CRC
        const ParseResult r = run(build_sof(2, {build_block(body, 0, false),
                                                build_block(body, 1, false)}));
        check("control: accept", r.accept);
        check("control: pb_crc_ok", r.mpdu.pb_crc_ok);
        check("control: oks=[true,true]",
              r.mpdu.pb_crc_oks.size() == 2 && r.mpdu.pb_crc_oks[0] && r.mpdu.pb_crc_oks[1]);
    }
    {
        // 声明 2 块仅收 1 好块
        const ParseResult r = run(build_sof(2, {build_block(body, 0, false)}));
        check("trunc1: accept", r.accept);
        check("trunc1: pb_crc_ok=false", !r.mpdu.pb_crc_ok);
        check("trunc1: oks=[true]",
              r.mpdu.pb_crc_oks.size() == 1 && r.mpdu.pb_crc_oks[0]);
        check("trunc1: summary marks truncated",
              r.msdu.summary.contains(QString::fromUtf8("截断")));
    }
    {
        // 声明 2 块收 0 块
        const ParseResult r = run(build_sof(2, {}));
        check("trunc0: pb_crc_ok=false", !r.mpdu.pb_crc_ok);
        check("trunc0: oks empty", r.mpdu.pb_crc_oks.isEmpty());
    }
    {
        // 2 块、第 2 块 CRC 翻转(旧口径亦 false,防退化)
        const ParseResult r = run(build_sof(2, {build_block(body, 0, false),
                                                build_block(body, 1, true)}));
        check("badblk: pb_crc_ok=false", !r.mpdu.pb_crc_ok);
        check("badblk: oks=[true,false]",
              r.mpdu.pb_crc_oks.size() == 2 && r.mpdu.pb_crc_oks[0] && !r.mpdu.pb_crc_oks[1]);
    }
    std::printf(fails ? "RESULT: %d FAILURES\n" : "RESULT: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
