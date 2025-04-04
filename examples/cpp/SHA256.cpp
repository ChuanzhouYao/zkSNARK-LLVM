#include <cstdint>
#include <cstdio>

uint32_t Bit_ch(uint32_t a, uint32_t b, uint32_t c){
	return a * (b-c) + c;
}

uint32_t Bit_maj(uint32_t a, uint32_t b, uint32_t c){
	return (a & b) + c * (a + b + (-2 * (a & b)));
}
// SHA-256 实现（假设输入不超过一块，即最多 64 字节）
[[circuit]]uint32_t* sha256(const uint32_t* input) {
    // SHA-256 常量
    const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // 初始哈希值
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // 循环右移宏
    #define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

    // 计算总字节数并填充
    //size_t new_len = len * 4 + 1 + 8;
   // size_t total_blocks = (new_len + 63) / 64;



    // 处理块
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = input[i];  // 将填充数据复制到消息调度数组 w
    }

	
    // 扩展消息（将 16 个字扩展到 64 个字）
   
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = ROTR(w[i-15], 7) ^ ROTR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROTR(w[i-2], 17) ^ ROTR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    

    // 初始化工作变量
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3],
             e = h[4], f = h[5], g = h[6], temp = h[7];

    // 主循环
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
      // uint32_t ch = (e & f) ^ (~e & g);
        uint32_t ch = Bit_ch(e,f,g);
       // uint32_t ch = e * (f-g) + g;
        uint32_t temp1 = temp + S1 + ch + k[i] + w[i];
        uint32_t S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
      //  uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t maj =Bit_maj(a,b,c);
      //  uint32_t maj = (a & b) + c * (a + b - 2 * (a & b)); 
        uint32_t temp2 = S0 + maj;

        temp = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    // 更新哈希值
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += temp;

    #undef ROTR

    // 直接返回 h 数组，因为输入不超过一块
    uint32_t* result = new uint32_t[8];
    for (int i = 0; i < 8; ++i) {
        result[i] = h[i];
    }

    return result;  // 返回哈希值
}

