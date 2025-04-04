#include<cstdint>


[[circuit]] uint32_t* fortest(const uint32_t* a,size_t len) {

    uint32_t* result =new uint32_t[5];
    uint32_t x;
    uint32_t y;
    size_t new_len = len + 4;
    for(int i=0;i<5;i++){
    	x = uint32_t(i);
    	y = uint32_t(i+1);
    	for(int j=0;j<5;j++){
    	    x = a[j] + x;
    	}
    	for(int j=4;j>=0;j--){
    	    y = a[j] * y;
    	}
    	result[i] = x+y;
    }
    return result;
}
