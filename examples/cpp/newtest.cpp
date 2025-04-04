#include<cstdint>


[[circuit]] uint8_t* fortest(const uint32_t* a) {

    uint8_t* result =new uint8_t[5];
    for(int i=0;i<5;i++)
    	result[i] = i; 
    	
    return result;
}
