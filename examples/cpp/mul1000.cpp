[[circuit]] int mul1000(int a[1000], int b[1000]) {

    int c= 1;
    for(int i=0 ; i < 1000 ; ++i){
        c = c * a[i] * b[i]; 
    }
    return c ;
}
