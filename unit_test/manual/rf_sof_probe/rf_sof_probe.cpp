// RF SOF 探针:验证无线 SOF(表30)载荷PB大小/MCS 与载波 SOF(表19)物理块个数/TMI 解析
#include <QCoreApplication>
#include <QByteArray>
#include <QString>
#include <cstdio>
#include "bplcframe.h"
#include "gw_2022_sof_parser.h"
#include "common/fieldtools.h"

static void set_frame_base(quint8* p) {
    p[0] = 0x01;                    // 定界符类型 SOF=1, 网络类型=0
    set_bits(p, 4, 0, 12, 1);       // 源TEI = 1 (CCO)
    set_bits(p, 5, 4, 12, 2);       // 目的TEI = 2
    p[7] = 0x00;                    // 链路标识符
    set_bits(p, 8, 0, 12, 0x100);   // 帧长
    set_bits(p, 11, 1, 1, 0);       // 广播
    set_bits(p, 11, 2, 1, 0);       // 重传
    set_bits(p, 11, 3, 1, 0);       // 加密
    set_bits(p, 12, 4, 4, 1);       // 标准版本号 = 1
}

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    int fails = 0;

    // 测试1: 无线 SOF, 载荷PB大小=3(136B), MCS=5
    {
        QByteArray body(16 + 136, 0);
        quint8* p = reinterpret_cast<quint8*>(body.data());
        set_frame_base(p);
        set_bits(p, 9, 4, 4, 3);    // 载荷PB大小 = 3 -> 136B
        set_bits(p, 11, 4, 4, 5);   // MCS = 5
        p[16] = 0xC0;               // PB 头 END|START
        MpduInfo info; MsduState msdu; QByteArray mb;
        QString err = gw_2022_sof::assemble(body, info, msdu, mb, 0xFF, true);
        bool ok = (info.pb_num == 1 && info.pb_size == 136
                   && info.pb_num_field == 3 && info.mcs == 5
                   && info.symbol_num == 0 && info.tmi_ext == 0);
        std::printf("[RF 136B] err='%s' pb_num=%d pb_size=%d field=%d mcs=%d sym=%d ext=%d => %s\n",
                    qPrintable(err), info.pb_num, info.pb_size, info.pb_num_field,
                    info.mcs, info.symbol_num, info.tmi_ext, ok ? "PASS" : "FAIL");
        if (!ok) ++fails;
    }
    // 测试2: 无线 SOF, 载荷PB大小=0(16B)
    {
        QByteArray body(16 + 16, 0);
        quint8* p = reinterpret_cast<quint8*>(body.data());
        set_frame_base(p);
        set_bits(p, 9, 4, 4, 0);    // 载荷PB大小 = 0 -> 16B
        set_bits(p, 11, 4, 4, 6);   // MCS = 6
        p[16] = 0xC0;
        MpduInfo info; MsduState msdu; QByteArray mb;
        QString err = gw_2022_sof::assemble(body, info, msdu, mb, 0xFF, true);
        bool ok = (info.pb_num == 1 && info.pb_size == 16 && info.pb_num_field == 0);
        std::printf("[RF 16B] err='%s' pb_size=%d field=%d => %s\n",
                    qPrintable(err), info.pb_size, info.pb_num_field, ok ? "PASS" : "FAIL");
        if (!ok) ++fails;
    }
    // 测试3: 无线 SOF, 载荷PB大小=6(越界保留) -> 应拒收
    {
        QByteArray body(16 + 520, 0);
        quint8* p = reinterpret_cast<quint8*>(body.data());
        set_frame_base(p);
        set_bits(p, 9, 4, 4, 6);    // 载荷PB大小 = 6 -> 保留(非法)
        set_bits(p, 11, 4, 4, 1);
        MpduInfo info; MsduState msdu; QByteArray mb;
        QString err = gw_2022_sof::assemble(body, info, msdu, mb, 0xFF, true);
        bool ok = (!err.isEmpty()); // 应拒收
        std::printf("[RF 越界] err='%s' pb_size=%d => %s\n",
                    qPrintable(err), info.pb_size, ok ? "PASS(拒收)" : "FAIL");
        if (!ok) ++fails;
    }
    // 测试4: 载波 SOF, 物理块个数=1, TMI=3(136B), 符号数=123
    {
        QByteArray body(16 + 136, 0);
        quint8* p = reinterpret_cast<quint8*>(body.data());
        set_frame_base(p);
        set_bits(p, 9, 4, 4, 1);    // 物理块个数 = 1
        set_bits(p, 10, 0, 9, 123); // 符号数 = 123
        set_bits(p, 11, 4, 4, 3);   // TMI = 3 -> 136B
        set_bits(p, 12, 0, 4, 0);   // TMI_EXT = 0
        p[16] = 0xC0;
        MpduInfo info; MsduState msdu; QByteArray mb;
        QString err = gw_2022_sof::assemble(body, info, msdu, mb, 0, false);
        bool ok = (info.pb_num == 1 && info.pb_size == 136
                   && info.pb_num_field == 1 && info.tmi == 3 && info.symbol_num == 123);
        std::printf("[PLC] err='%s' pb_num=%d pb_size=%d field=%d tmi=%d sym=%d => %s\n",
                    qPrintable(err), info.pb_num, info.pb_size, info.pb_num_field,
                    info.tmi, info.symbol_num, ok ? "PASS" : "FAIL");
        if (!ok) ++fails;
    }

    std::printf("RESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails;
}
