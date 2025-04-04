[[circuit]] int mul100(int a[100], int b[100]) {

    int c= 1;
    for(int i=0 ; i < 100 ; ++i){
        c = c * a[i] * b[i]; 
    }
    return c ;
}
