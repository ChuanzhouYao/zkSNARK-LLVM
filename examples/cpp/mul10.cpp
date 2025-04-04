[[circuit]] int mul10(int a[10], int b[10]) {

    int c= 1;
    for(int i=0 ; i < 10 ; ++i){
        c = c * a[i] * b[i]; 
    }
    return c ;
}
