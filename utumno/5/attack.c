#include <unistd.h>

int main(int argc, char** argv[]) {
    char* argx[] = {NULL};
    execv("/games/utumno/utumno5", argx);
    return 0;
}
