#include <unistd.h>

int main(int argc, char** argv[]) {
    char* argx[] = {NULL};
    execv("/utumno/utumno2", argx);
    return 0;
}

