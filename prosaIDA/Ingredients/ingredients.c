#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>

#define MAX_LINE 1024
#define MAX_INPUT 256

void __attribute__((noreturn)) handle_alarm(int sig __attribute__((unused))) {
    exit(0);
}

void handle_client() {
    struct {
        int space_left;
        int bytes_read;
        char input[MAX_INPUT];
        char line[MAX_LINE];
    } data;
    data.space_left = MAX_LINE;
    data.bytes_read = 0xe4ff;
    
    signal(SIGALRM, handle_alarm);
    alarm(60);

    memset(data.line, 0, MAX_LINE);
    while (data.space_left > 0) {
        if (fgets(data.input, MAX_INPUT - 1, stdin) == NULL) {
            exit(0);
        }
        data.input[strlen(data.input) - 1] = 0;
        if (strcmp(data.input, "end") == 0) {
            break;
        } else {
            if (data.line[0]) {
                strcat(data.line, ", ");
            }
            data.bytes_read = strlen(data.input);

            if (data.space_left - data.bytes_read > 0) {
                strcat(data.line, data.input);
                data.space_left -= data.bytes_read;
            }
        }
    }

    printf("Apparently this is a nice list of...stuff: %s\n", data.line);
}

int main(int argc __attribute__((unused)), char *argv[] __attribute__((unused))) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Give me a list of ingredients separated by newline. End with a line matching \"end\".\n");
    handle_client();
    return 0;
}
