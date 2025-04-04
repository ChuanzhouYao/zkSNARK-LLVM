#include<cstdint>

[[circuit]] uint32_t div1(uint32_t a, uint32_t b) {

    uint32_t c;
    if(a != b) c=a*10;
    else c=b*5;
    return c ;
}
