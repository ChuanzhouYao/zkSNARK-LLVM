#include<cstdint>
#include<algorithm>

#define SIZE 3 
//void verify_permutation(uint32_t*,uint32_t*){};

[[circuit]] uint32_t* fortest(const uint32_t* unsortedArray) {

    uint32_t* value =new uint32_t[SIZE];
    for(int i=0;i<SIZE;i++)
    	value[i] = unsortedArray[i];
    	 
    std::sort(value,value+SIZE);
    
    uint32_t* sortedArray = new uint32_t[SIZE];
    for(int i=0;i<SIZE;i++)
    	sortedArray[i] = value[i];
    	
    //verify_permutation(unsortedArray,sortedArray);
    	
    return sortedArray;
}
