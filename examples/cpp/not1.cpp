#include<cstdint>


[[circuit]] uint32_t xor1(uint32_t a) {

    uint32_t c;
    c=~a;
    return c;
}
