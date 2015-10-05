#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char s[512];
    sprintf(s, "cat %s", argv[1]);
    system(s);
}
