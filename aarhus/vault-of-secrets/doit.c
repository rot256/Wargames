#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "usertable.c"

char* xor_and_add_crypt(char *dst,char *password,short opt) {
  size_t len;
  int i;
  int n;

  len = strlen(password);

  n = 0;
  i = 0;

  while (dst[(long)n] != 0) {

    dst[(long)n] = dst[(long)n] ^ password[(long)i];

    if (opt != 0) {
      password[(long)i] = password[(long)i] + (char)opt;
    }

    n = n + 1;
    i = (i + 1) % (int)len;
  }

  return dst;
}

char *magic_extend(char *buf) {
  int i;

  i = 0;
  while (buf[(long)i] != 0) {
    if ((buf[(long)i] < 'a') || ('m' < buf[(long)i])) {
      if ((buf[(long)i] < 'A') || ('M' < buf[(long)i])) {
        if ((buf[(long)i] < '0') || ('4' < buf[(long)i])) {
          if ((buf[(long)i] < 'n') || ('z' < buf[(long)i])) {
            if ((buf[(long)i] < 'N') || ('Z' < buf[(long)i])) {
              if (('4' < buf[(long)i]) && (buf[(long)i] < ':')) {
                buf[(long)i] = buf[(long)i] + -5;
              }
            }
            else {
              buf[(long)i] = buf[(long)i] + -0xd;
            }
          }
          else {
            buf[(long)i] = buf[(long)i] + -0xd;
          }
        }
        else {
          buf[(long)i] = buf[(long)i] + 5;
        }
      }
      else {
        buf[(long)i] = buf[(long)i] + '\r';
      }
    }
    else {
      buf[(long)i] = buf[(long)i] + '\r';
    }
    i = i + 1;
  }
  return buf;
}


char * decrypt_username(char *crypt_name) {
  char local_a[2];

  local_a[0] = 0x5a;
  local_a[1] = 0x00;

  xor_and_add_crypt(crypt_name, &local_a[0], 1);
  magic_extend(crypt_name);

  return crypt_name;
}

int main() {

    char prep[] = "[..PEP..]_";

    char* magic = magic_extend(prep);

    printf("magic: %s\n", magic);

    for (size_t user = 0; user < 3; user++) {

        char key[10];
        char* name = usertable + 0x50 * user;
        char* ct   = name + 0x10;

        decrypt_username(name);
        printf("username: %s\n", name);

        for (size_t i = 0; i < sizeof(key); i++) {
            key[i] = ct[i] ^ magic[i];
        }

        key[9] = 0;

        printf("key: %s\n", key);

        // truncate


        xor_and_add_crypt(ct, key, 0);

        printf("pt: %s\n", ct);
    }

    return 0;

    char ct[] = {
        0x10, 0x26, 0x20, 0x31,
        0x26, 0x26, 0x37, 0x1e,
        0x63, 0x66, 0x30, 0x00,
    };

    xor_and_add_crypt(ct, "C", 0);

    printf("%s\n", ct);
}
