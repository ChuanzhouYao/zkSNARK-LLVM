#include<cstdint>
#include<algorithm>

#define SIZE 32



[[circuit]] uint32_t* fortest(uint32_t* arr) {

//    uint32_t* value =new uint32_t[SIZE];
//    for(int i=0;i<SIZE;i++)
//    	value[i] = arr[i];
    	
     for (int i = 0; i < SIZE - 1; i++) {
     	for(int j=0;j< SIZE - 1;j++){
     		 int diff = arr[j] - arr[j + 1];
            // flag 为 1 时表示 arr[j] > arr[j+1]，需要交换；否则为 0
            int flag = (diff > 0);
            // 利用 flag 的 0/1 值进行交换操作
            arr[j] = arr[j] - diff * flag;   
            arr[j + 1] = arr[j + 1] + diff * flag;
    	}
    }
    return arr;
}
