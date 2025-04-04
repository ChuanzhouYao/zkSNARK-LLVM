#include<cstdint>


uint32_t Bit_ch(uint32_t a, uint32_t b, uint32_t c){
	return a * (b-c) + c;
}

uint32_t Bit_maj(uint32_t a, uint32_t b, uint32_t c){
	return (a & b) + c * (a + b + (-2 * (a & b)));
}

[[circuit]] uint32_t xor1(uint32_t a, uint32_t b, uint32_t c) {

    uint32_t d=a;
    uint32_t e=b;
    uint32_t f=c;
    uint32_t ch;
    uint32_t maj;
    for(int i=0 ;i<8;i++){
    
    maj=Bit_maj(d,e,f);
    //d = (a&b)^(~a&c);
    ch=Bit_ch(d,e,f);
    d=e;
    e=f;
    f=ch+maj;
    }
    return d+e+f;
}
