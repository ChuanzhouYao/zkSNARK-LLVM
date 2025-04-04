#include <iostream>
#include <cstdint>

// AES S-Box
static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b, 0xf2,0x6b,0x6f,0xc5, 0x30,0x01,0x67,0x2b, 0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d, 0xfa,0x59,0x47,0xf0, 0xad,0xd4,0xa2,0xaf, 0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26, 0x36,0x3f,0xf7,0xcc, 0x34,0xa5,0xe5,0xf1, 0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3, 0x18,0x96,0x05,0x9a, 0x07,0x12,0x80,0xe2, 0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a, 0x1b,0x6e,0x5a,0xa0, 0x52,0x3b,0xd6,0xb3, 0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed, 0x20,0xfc,0xb1,0x5b, 0x6a,0xcb,0xbe,0x39, 0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb, 0x43,0x4d,0x33,0x85, 0x45,0xf9,0x02,0x7f, 0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f, 0x92,0x9d,0x38,0xf5, 0xbc,0xb6,0xda,0x21, 0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec, 0x5f,0x97,0x44,0x17, 0xc4,0xa7,0x7e,0x3d, 0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc, 0x22,0x2a,0x90,0x88, 0x46,0xee,0xb8,0x14, 0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a, 0x49,0x06,0x24,0x5c, 0xc2,0xd3,0xac,0x62, 0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d, 0x8d,0xd5,0x4e,0xa9, 0x6c,0x56,0xf4,0xea, 0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e, 0x1c,0xa6,0xb4,0xc6, 0xe8,0xdd,0x74,0x1f, 0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66, 0x48,0x03,0xf6,0x0e, 0x61,0x35,0x57,0xb9, 0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11, 0x69,0xd9,0x8e,0x94, 0x9b,0x1e,0x87,0xe9, 0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d, 0xbf,0xe6,0x42,0x68, 0x41,0x99,0x2d,0x0f, 0xb0,0x54,0xbb,0x16
};

// AES Rcon数组
static const uint8_t Rcon[11] = { 
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

// GF(2^8)中乘以2的操作
[[circuit]]uint8_t* AES_encrypt(const uint8_t in[16], const uint8_t key[16]) {
    // 1. 将输入明文复制到状态数组中
    uint8_t state[16];
    for (int i = 0; i < 16; ++i)
        state[i] = in[i];

    // 2. 密钥扩展
    // 动态分配 176 字节的轮密钥数组
    uint8_t* roundKeys = new uint8_t[176];
    // 复制初始 16 字节密钥
    for (int i = 0; i < 16; ++i)
        roundKeys[i] = key[i];

    int bytesGenerated = 16;
    int rconIteration = 1;
    uint8_t temp[4];
    while (bytesGenerated < 176) {
        // 取上一组最后 4 字节
        for (int i = 0; i < 4; ++i)
            temp[i] = roundKeys[bytesGenerated - 4 + i];
        if (bytesGenerated % 16 == 0) {
            // 循环左移 1 字节
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            // 字节替换：用 sbox 替换每个字节
            for (int i = 0; i < 4; ++i)
                temp[i] = sbox[temp[i]];
            // 与 Rcon 异或
            temp[0] ^= Rcon[rconIteration];
            rconIteration++;
        }
        // 生成新 4 字节，并追加到轮密钥中
        for (int i = 0; i < 4; ++i) {
            roundKeys[bytesGenerated] = roundKeys[bytesGenerated - 16] ^ temp[i];
            bytesGenerated++;
        }
    }

    // 3. 初始轮：AddRoundKey（状态与前 16 字节轮密钥异或）
    for (int i = 0; i < 16; ++i)
        state[i] ^= roundKeys[i];

    // 4. 进行 9 轮常规操作
    for (int round = 1; round <= 9; ++round) {
        // 4.1 SubBytes：每个字节替换为 sbox 中对应的值
        for (int i = 0; i < 16; ++i)
            state[i] = sbox[state[i]];

        // 4.2 ShiftRows：按行移位
        {
            uint8_t tmp[16];
            // 第一行不变
            tmp[0]  = state[0];
            tmp[4]  = state[4];
            tmp[8]  = state[8];
            tmp[12] = state[12];

            // 第二行左移 1
            tmp[1]  = state[5];
            tmp[5]  = state[9];
            tmp[9]  = state[13];
            tmp[13] = state[1];

            // 第三行左移 2
            tmp[2]  = state[10];
            tmp[6]  = state[14];
            tmp[10] = state[2];
            tmp[14] = state[6];

            // 第四行左移 3
            tmp[3]  = state[15];
            tmp[7]  = state[3];
            tmp[11] = state[7];
            tmp[15] = state[11];

            // 将移位结果复制回 state
            for (int i = 0; i < 16; ++i)
                state[i] = tmp[i];
        }

        // 4.3 MixColumns：对每一列进行混合
        for (int i = 0; i < 4; ++i) {
            int col = i * 4;
            uint8_t a0 = state[col + 0];
            uint8_t a1 = state[col + 1];
            uint8_t a2 = state[col + 2];
            uint8_t a3 = state[col + 3];

            // 计算 xtime(x)= (x << 1) XOR (0x1B if (x & 0x80) else 0)
            uint8_t x0 = (a0 << 1) ^ ((a0 & 0x80) ? 0x1B : 0x00);
            uint8_t x1 = (a1 << 1) ^ ((a1 & 0x80) ? 0x1B : 0x00);
            uint8_t x2 = (a2 << 1) ^ ((a2 & 0x80) ? 0x1B : 0x00);
            uint8_t x3 = (a3 << 1) ^ ((a3 & 0x80) ? 0x1B : 0x00);

            uint8_t r0 = x0 ^ (a1 ^ x1) ^ a2 ^ a3;
            uint8_t r1 = a0 ^ x1 ^ (a2 ^ x2) ^ a3;
            uint8_t r2 = a0 ^ a1 ^ x2 ^ (a3 ^ x3);
            uint8_t r3 = (a0 ^ x0) ^ a1 ^ a2 ^ x3;

            state[col + 0] = r0;
            state[col + 1] = r1;
            state[col + 2] = r2;
            state[col + 3] = r3;
        }

        // 4.4 AddRoundKey：将当前状态与本轮密钥异或
        for (int i = 0; i < 16; ++i)
            state[i] ^= roundKeys[round * 16 + i];
    }

    // 5. 最后一轮（不进行 MixColumns）
    // 5.1 SubBytes
    for (int i = 0; i < 16; ++i)
        state[i] = sbox[state[i]];

    // 5.2 ShiftRows
    {
        uint8_t tmp[16];
        tmp[0]  = state[0];
        tmp[4]  = state[4];
        tmp[8]  = state[8];
        tmp[12] = state[12];

        tmp[1]  = state[5];
        tmp[5]  = state[9];
        tmp[9]  = state[13];
        tmp[13] = state[1];

        tmp[2]  = state[10];
        tmp[6]  = state[14];
        tmp[10] = state[2];
        tmp[14] = state[6];

        tmp[3]  = state[15];
        tmp[7]  = state[3];
        tmp[11] = state[7];
        tmp[15] = state[11];

        for (int i = 0; i < 16; ++i)
            state[i] = tmp[i];
    }

    // 5.3 AddRoundKey（第 10 轮密钥）
    for (int i = 0; i < 16; ++i)
        state[i] ^= roundKeys[10 * 16 + i];

    // 6. 分配新内存存放密文，并复制状态
    uint8_t* ciphertext = new uint8_t[16];
    for (int i = 0; i < 16; ++i)
        ciphertext[i] = state[i];

    // 释放动态分配的轮密钥内存

    return ciphertext;
}
