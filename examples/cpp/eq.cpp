#include<cstdint>

[[circuit]] uint32_t iftest(uint32_t a, uint32_t b) {

    uint32_t c=0;
    if(a==b) c=5;
    else c=10;
    return c;
}
