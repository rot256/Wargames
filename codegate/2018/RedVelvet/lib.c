#include <sys/types.h>

enum __ptrace_request {OKAY};

int puts(char* s) {
    return 0;
}

long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data) {
    return 0;
}
