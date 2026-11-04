// 回灌测试: 验证 GW_2022 MMeZeroCrossNTBCollectInd (0x0B) TEI=12bit+RSV0=4bit
// 构造含过零采集指示帧的 bin 文件,用 headless_test 解析并校验输出

#include <QCoreApplication>
#include <QFile>
#include <QByteArray>
#include <QDebug>
#include <cstdio>
#include <cstdint>

// 哨兵切帧 + 反转义(与 headless_test.cpp 一致)
static QByteArray make_frame_bytes(quint8 mme_type_lo, quint8 mme_type_hi, const QByteArray& mme_payload) {
    // MSDU header (简化): Version=0, SrcTEI=1, DstTEI=4095, SendType=0, etc.
    // 实际只需要 MMType + payload 能被 msdu_parser 识别
    // 这里直接构造完整 MSDU:
    //   Byte0-1: Version(4b)+SrcTEI(12b) = 0x0001
    //   Byte2-3: DstTEI(12b)+SendType(4b) = 0xFFF0
    //   Byte4: MaxSendCountLimit(5b)+RSV0(3b) = 0x00
    //   Byte5-6: MSDUSeq = 0x0001
    //   Byte7: MSDUType=0 (Net Mgmt)
    //   Byte8-9: MSDULen(11b)+RestartCount(4b)+MainProxyFlag(1b) 
    // 简化: 直接用最小可解析结构
    
    QByteArray msdu;
    // SOF-like header fields (18 bytes before MMe)
    msdu.append(char(0x01)); // Version=0, SrcTEI high nibble=0
    msdu.append(char(0x00)); // SrcTEI low byte = 1
    msdu.append(char(0xFF)); // DstTEI = 4095
    msdu.append(char(0xF0)); // DstTEI high nibble + SendType=0
    msdu.append(char(0x00)); // MaxSendCountLimit=0, RSV0=0
    msdu.append(char(0x00)); msdu.append(char(0x01)); // MSDUSeq=1
    msdu.append(char(0x00)); // MSDUType=0 (Net Mgmt)
    
    int mme_len = 4 + mme_payload.size(); // MMType(2B) + RSV(2B) + payload
    // MSDULen(11b) + RestartCount(4b) + MainProxyFlag(1b) = 16 bits
    quint16 len_field = (quint16(mme_len) & 0x7FF); // 11 bits
    msdu.append(char(len_field & 0xFF));
    msdu.append(char((len_field >> 8) & 0x07));
    
    // RouteHopsTotalNum(4b)+RouteHopsLeftNum(4b)+BroadcastDirection(2b)+PathRepairFlag(1b)+MACAddrFlag(1b)+RSV1(12b)
    msdu.append(char(0x00)); // hops
    msdu.append(char(0x00)); // broadcast dir etc
    msdu.append(char(0x00)); msdu.append(char(0x00)); // RSV1
    
    // NetSN + RSV2 + RSV3
    msdu.append(char(0x01)); // NetSN
    msdu.append(char(0x00)); msdu.append(char(0x00)); // RSV2/3
    
    // MAC addresses (6B each) - skip if MACAddrFlag=0
    // Source MAC
    msdu.append(QByteArray::fromHex("010203040506"));
    // Dest MAC
    msdu.append(QByteArray::fromHex("ffffffffffff"));
    
    // MMe header: MMType(16b) + RSV(16b)
    msdu.append(char(mme_type_lo));
    msdu.append(char(mme_type_hi));
    msdu.append(char(0x00)); msdu.append(char(0x00)); // RSV
    
    // MMe payload
    msdu += mme_payload;
    
    // CRC32 placeholder (headless_test doesn't validate CRC on raw bin)
    msdu.append(char(0x00)); msdu.append(char(0x00));
    msdu.append(char(0x00)); msdu.append(char(0x00));
    
    // Wrap with sentinel 0x3C ... 0x3E + escape
    QByteArray escaped;
    for (int i = 0; i < msdu.size(); ++i) {
        quint8 b = static_cast<quint8>(msdu[i]);
        if (b == 0x3C || b == 0x3E || b == 0x3D) {
            escaped.append(char(0x3D));
            escaped.append(char(0xFF ^ b));
        } else {
            escaped.append(char(b));
        }
    }
    
    QByteArray frame;
    frame.append(char(0x3C));
    frame += escaped;
    frame.append(char(0x3E));
    return frame;
}

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    
    // Test case 1: STATEI=0x123 (12bit), RSV0=0x5 (4bit)
    // byte0 = 0x23 (low 8 bits of TEI)
    // byte1 = 0x51 (high 4 bits of TEI=0x1 in low nibble, RSV0=0x5 in high nibble)
    QByteArray payload1(8, char(0));
    payload1[0] = 0x23; // TEI bits 0-7
    payload1[1] = 0x51; // TEI bits 8-11 (0x1) + RSV0 (0x5)
    payload1[2] = 0xAA; // Mode
    payload1[3] = 0xBB; // Period
    payload1[4] = 0xCC; // Quantity
    payload1[5] = 0xDD; payload1[6] = 0xEE; payload1[7] = 0xFF; // RSV1
    
    QByteArray frame1 = make_frame_bytes(0x0B, 0x00, payload1); // MME_ZERO_CROSS_NTB_COLLECT_IND
    
    // Test case 2: STATEI=0xFFF (max 12bit), RSV0=0xF (max 4bit)
    QByteArray payload2(8, char(0));
    payload2[0] = 0xFF; // TEI bits 0-7 = 0xFF
    payload2[1] = 0xFF; // TEI bits 8-11 = 0xF + RSV0 = 0xF
    payload2[2] = 0x01; payload2[3] = 0x02; payload2[4] = 0x03;
    payload2[5] = 0x00; payload2[6] = 0x00; payload2[7] = 0x00;
    
    QByteArray frame2 = make_frame_bytes(0x0B, 0x00, payload2);
    
    // Write combined test bin
    // 输出路径:argv[1] 指定,否则写当前目录(跨平台,勿写死 Windows 盘符)
    QString out_path = (argc > 1) ? QString::fromLocal8Bit(argv[1])
                                  : QStringLiteral("zero_cross_tei_test.bin");
    QFile f(out_path);
    if (!f.open(QIODevice::WriteOnly)) {
        qCritical() << "Cannot write:" << out_path;
        return 1;
    }
    f.write(frame1);
    f.write(frame2);
    f.close();
    
    printf("Generated %lld bytes -> %s\n", (long long)(frame1.size() + frame2.size()), qPrintable(out_path));
    printf("Frame1: TEI_expected=0x123 (291), RSV0_expected=0x5\n");
    printf("Frame2: TEI_expected=0xFFF (4095), RSV0_expected=0xF\n");
    printf("Run: headless_test.exe (modify path or use this bin)\n");
    return 0;
}
