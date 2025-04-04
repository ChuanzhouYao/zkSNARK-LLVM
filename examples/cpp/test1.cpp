#include<cstdint>


[[circuit]] uint32_t* fortest(const uint32_t* a) {

    #define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = a[i];  // 将填充数据复制到消息调度数组 w
    }
    
    
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = ROTR(w[i-15], 7) ^ ROTR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROTR(w[i-2], 17) ^ ROTR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    
    uint32_t* result = new uint32_t[64];
    for (int i = 0; i < 64; ++i) {
        result[i] = w[i];
    }

    return result; 
}
