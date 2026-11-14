// RF SOF 保留位原值保留验证:保留位非 0 时 symbol_num/tmi_ext 应存原始值
#include <QCoreApplication>
#include <QByteArray>
#include <cstdio>
#include "bplcframe.h"
#include "gw_2022_sof_parser.h"
#include "common/fieldtools.h"

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    QByteArray body(16 + 72, 0);
    quint8* p = reinterpret_cast<quint8*>(body.data());
    p[0] = 0x01;
    set_bits(p, 4, 0, 12, 1);
    set_bits(p, 5, 4, 12, 2);
    set_bits(p, 8, 0, 12, 0x100);
    set_bits(p, 9, 4, 4, 2);      // 载荷PB大小 = 2 -> 72B
    p[10] = 0xAB;                  // 保留低 8 位
    set_bits(p, 11, 0, 1, 1);      // 保留最高位(bit0 of byte11)
    set_bits(p, 11, 4, 4, 3);      // MCS = 3
    set_bits(p, 12, 0, 4, 0x5);    // 保留 = 5
    set_bits(p, 12, 4, 4, 1);      // 标准版本号
    p[16] = 0xC0;
    MpduInfo info; MsduState msdu; QByteArray mb;
    QString err = gw_2022_sof::assemble(body, info, msdu, mb, 0xFF, true);
    const int expect_sym = 0xAB | (1 << 8);   // 427
    // 无线 SOF 的字节11 bit4-7(MCS,表28)存 MpduInfo::mcs;tmi 只用于载波(分集拷贝基本模式)。
    // 各解析器/树/导出均按 is_rf ? mcs : tmi 取值,旧断言 info.tmi == 3 是归集前的过时口径。
    bool ok = err.isEmpty() && info.pb_num == 1 && info.pb_size == 72
              && info.symbol_num == expect_sym && info.tmi_ext == 0x5 && info.mcs == 3;
    std::printf("[RF rsv] err='%s' sym=%d(exp %d) ext=%d(exp 5) pb_size=%d mcs=%d(exp 3) tmi=%d => %s\n",
                qPrintable(err), info.symbol_num, expect_sym, info.tmi_ext,
                info.pb_size, info.mcs, info.tmi, ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
