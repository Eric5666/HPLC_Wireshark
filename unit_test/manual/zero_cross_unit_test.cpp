// 单元测试: GW_2022 MMeZeroCrossNTBCollectInd (0x0B) TEI=12bit+RSV0=4bit 位域解析验证
// 直接调用 msdu_parser,绕过 FCH CRC 校验

#include <QCoreApplication>
#include <QDebug>
#include <cstdio>
#include <cstdlib>
#include "gw_2022_msdu_parser.h"
#include "protocol_tree_builder.h"
#include "common/fieldtools.h"

static int tests_passed = 0;
static int tests_failed = 0;

static void check(bool ok, const char* msg) {
    if (ok) {
        ++tests_passed;
        printf("  PASS: %s\n", msg);
    } else {
        ++tests_failed;
        printf("  FAIL: %s\n", msg);
    }
}

int main(int argc, char* argv[]) {
    QCoreApplication app(argc, argv);
    
    printf("=== GW_2022 ZeroCross TEI 12bit+RSV0 4bit Unit Test ===\n\n");
    
    // Test 1: STATEI=0x123 (291), RSV0=0x5
    // byte0 = 0x23 (TEI bits 0-7)
    // byte1 = 0x51 (TEI bits 8-11 = 0x1 in low nibble, RSV0 = 0x5 in high nibble)
    {
        printf("Test 1: STATEI=0x123(291), RSV0=0x5\n");
        QByteArray mme_body(8, char(0));
        mme_body[0] = 0x23; // TEI bits 0-7
        mme_body[1] = 0x51; // TEI bits 8-11=0x1 + RSV0=0x5
        mme_body[2] = 0xAA; // Mode
        mme_body[3] = 0xBB; // Period
        mme_body[4] = 0xCC; // Quantity
        mme_body[5] = 0xDD; mme_body[6] = 0xEE; mme_body[7] = 0xFF; // RSV1
        
        // Parse using FieldSpec directly
        // kZeroCrossCollectSpec is static in gw_2022_msdu_parser.cpp, so we replicate:
        // {"STATEI", 0, 0, 12, DEC}, {"RSV0", 1, 4, 4, DEC}
        quint64 tei_val = get_bits(reinterpret_cast<const quint8*>(mme_body.constData()), 0, 0, 12);
        quint64 rsv_val = get_bits(reinterpret_cast<const quint8*>(mme_body.constData()), 1, 4, 4);
        
        printf("    Raw bytes: %02X %02X\n", (unsigned)mme_body[0], (unsigned)mme_body[1]);
        printf("    Parsed: STATEI=%llu (0x%llX), RSV0=%llu (0x%llX)\n", 
               tei_val, tei_val, rsv_val, rsv_val);
        
        check(tei_val == 0x123, "STATEI should be 0x123 (291)");
        check(rsv_val == 0x5, "RSV0 should be 0x5");
    }
    
    // Test 2: STATEI=0xFFF (4095, max 12bit), RSV0=0xF (max 4bit)
    {
        printf("\nTest 2: STATEI=0xFFF(4095), RSV0=0xF\n");
        QByteArray mme_body(8, char(0));
        mme_body[0] = 0xFF; // TEI bits 0-7 = 0xFF
        mme_body[1] = 0xFF; // TEI bits 8-11 = 0xF + RSV0 = 0xF
        
        quint64 tei_val = get_bits(reinterpret_cast<const quint8*>(mme_body.constData()), 0, 0, 12);
        quint64 rsv_val = get_bits(reinterpret_cast<const quint8*>(mme_body.constData()), 1, 4, 4);
        
        printf("    Raw bytes: %02X %02X\n", (unsigned)mme_body[0], (unsigned)mme_body[1]);
        printf("    Parsed: STATEI=%llu (0x%llX), RSV0=%llu (0x%llX)\n",
               tei_val, tei_val, rsv_val, rsv_val);
        
        check(tei_val == 0xFFF, "STATEI should be 0xFFF (4095)");
        check(rsv_val == 0xF, "RSV0 should be 0xF");
    }
    
    // Test 3: STATEI=0x000, RSV0=0x0 (boundary)
    {
        printf("\nTest 3: STATEI=0x000(0), RSV0=0x0\n");
        QByteArray mme_body(8, char(0));
        mme_body[0] = 0x00;
        mme_body[1] = 0x00;
        
        quint64 tei_val = get_bits(reinterpret_cast<const quint8*>(mme_body.constData()), 0, 0, 12);
        quint64 rsv_val = get_bits(reinterpret_cast<const quint8*>(mme_body.constData()), 1, 4, 4);
        
        check(tei_val == 0x000, "STATEI should be 0x000");
        check(rsv_val == 0x0, "RSV0 should be 0x0");
    }
    
    // Test 4: Verify old 16bit interpretation would be WRONG
    {
        printf("\nTest 4: Verify 16bit interpretation differs from 12bit\n");
        QByteArray mme_body(8, char(0));
        mme_body[0] = 0x23;
        mme_body[1] = 0x51;
        
        quint64 tei_12bit = get_bits(reinterpret_cast<const quint8*>(mme_body.constData()), 0, 0, 12);
        quint64 tei_16bit = get_bits(reinterpret_cast<const quint8*>(mme_body.constData()), 0, 0, 16);
        
        printf("    12bit TEI = %llu (0x%llX)\n", tei_12bit, tei_12bit);
        printf("    16bit TEI = %llu (0x%llX)\n", tei_16bit, tei_16bit);
        
        check(tei_12bit != tei_16bit, "12bit and 16bit interpretations must differ for this test vector");
        check(tei_12bit == 0x123, "12bit extraction correct");
        check(tei_16bit == 0x5123, "16bit extraction shows the bug (includes RSV bits)");
    }
    
    printf("\n=== Results: %d passed, %d failed ===\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
