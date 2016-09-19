#include <time.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
  char v15[512];
  int v3;
  int v12;
  int v8 = atoi(argv[1]);
  srand(v8);
  struct tm *v11;
  v11 = localtime((const time_t *)&v8);
  strftime(
    v15,
    0x40u,
    "It is now %H:%M:%S %z and I give you 30 seconds to win 100 consecutive coin tosses!",
    v11);
  int i;
  for ( i = 1; i <= 100; ++i )
  {
    v3 = rand();
    v12 = ((((unsigned int)((unsigned long long)v3 >> 32) >> 31) + (unsigned char)v3) & 1)
        - ((unsigned int)((unsigned long long)v3 >> 32) >> 31);
    printf("%d\n", v12);
  }
}
