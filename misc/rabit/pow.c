/* compile with: gcc -O3 proof-of-work.c -fopenmp  -lcrypto -o proof-of-work */

#include <openssl/sha.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  SHA_CTX c;

  if(argc != 2) {
    return 0;
  }

  SHA1_Init(&c);
  SHA1_Update(&c, argv[1], strlen(argv[1]));

  #pragma omp parallel for
  for(uint64_t n = 0; n <= 0xffffffff; n++) {
    SHA_CTX local;
    unsigned char out[20];
    memcpy(&local, &c, sizeof(c));
    SHA1_Update(&local, &n, 5);
    SHA1_Final(out, &local);
    if(out[17] == 0xff && out[18] == 0xff && out[19] == 0xff) {
      printf("%02lx%02lx%02lx%02lx%02lx\n", n&0xff, (n>>8) &0xff, (n>>16) & 0xff, (n>>24) & 0xff, (n >> 32) & 0xff);
      exit(0);
    }
  }

  return 0;
}
