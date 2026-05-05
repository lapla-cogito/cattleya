// gcc -g -no-pie main.c -o test_64bit_dbg
#include <stdio.h>

int factorial_function(int n) {
    if (n <= 1) return 1;
    return n * factorial_function(n - 1);
}

int fib(int n) {
    if (n <= 1) return n;
    return fib(n - 1) + fib(n - 2);
}

int main(void) {
    printf("fac=%d fib=%d\n", factorial_function(5), fib(10));
    return 0;
}
