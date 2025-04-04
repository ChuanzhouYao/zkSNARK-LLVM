#include<cstdint>


[[circuit]] uint8_t xor1(uint8_t a, uint8_t b, uint8_t c) {

    uint8_t d;
    //uint32_t e;
    d = a ^ 5;
    //e = (a&b)^(a&c)^(b&c);
   // d = c^(a&(b^c));
    //d=(a&10);
    
    return d;
}
