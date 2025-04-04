[[circuit]] int add10(int a[10], int b[10]) {

    int c= 0;
    for(int i=0 ; i < 10 ; ++i){
        c = c + a[i] + b[i]; 
    }
    return c ;
}
