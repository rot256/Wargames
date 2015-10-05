#include <stdio.h>
#include <sys/stat.h>

// modified by s0ttle 20150913

int main(int argc, char **argv)
{
    char buf[100];
    size_t len;
    char fixedbuf[10240];
    FILE *fh;
    struct stat sf;
    char *ptr = fixedbuf;
    int i;
    
    lstat("somefile", &sf);
    fh = fopen("somefile", "r");
    
    if(!fh || (sf.st_mode & 0xf000) == 0xa000) 
        return 0;

    while((len = fread(buf, 1, 100, fh)) > 0) {
        for(i = 0; i < len; i++) {
                // Disable output modifiers
            switch(buf[i]) {
                case 0xFF:
                case 0x00:
                case 0x01:
                    break;
                default:
                        *ptr = buf[i];
                        ptr++;
            }
        }
    }

    printf("%s", fixedbuf);

    fclose(fh);
}
