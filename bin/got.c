// gcc got.c -no-pie -o got
#include <stdio.h>
#include <stdlib.h>

int secret(char* s) {
    if (s[0] == 's' && s[1] == 'e' && s[2] == 'c' && s[3] == 'r' && s[4] == 'e' && s[5] == 't' && s[6] == '?') {
        printf("secret function called\n");
    }

    return 0;
}

int main() {
    system("secret?\n");
}
