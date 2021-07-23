from pwn import *

context(
    arch='arm64v8'
)

r = list(range(0x20, 0x7F))

print(hexdump(asm('svc 0xff')))

exit(0)

for x1 in r:
    for x2 in r:
        for x3 in r:
            for x4 in r:
                print(disasm(bytes(chr(x1) + chr(x2) + chr(x3) + chr(x4), 'UTF-8')))
