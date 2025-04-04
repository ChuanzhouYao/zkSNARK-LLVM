int pow_2(int a,int b) {
    int res = (a+b) * b;
    int re = res * a;
    return re+res;
}

[[circuit]] int int_arithmetic_example(int a, int b) {
    int c = (a + b) * a + b * (a + b) * (a + b);
    int d = (a + b) * b;
    const int constant = 77;
    return c * c * c * (b - a) + pow_2(c,d) + constant;
}
