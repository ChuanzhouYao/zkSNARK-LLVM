[[circuit]] int add100(int a[100], int b[100]) {

    int c= 0;
    for(int i=0 ; i < 100 ; ++i){
        c = c + a[i] + b[i]; 
    }
    return c ;
}
