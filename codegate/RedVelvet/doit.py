import angr

FLAG_LENGTH = 26

addr_after_gets = 0x401284
addr_exit       = 0x4007D0
addr_main       = 0x4011A9
addr_after_func = 0x401527

print 'creating project...'
proj  = angr.Project('./RedVelvet', custom_ld_path='.')
print proj

print 'creating state...'
st = proj.factory.full_init_state(args=['./RedVelvet'])
st.regs.rip = addr_main

stt = st.posix.files[0] # stdin

for _ in range(FLAG_LENGTH):
    c = stt.read_from(1)
    st.solver.add(c != 0)
    st.solver.add(c != '\n')

st.solver.add(stt.read_from(1) == '\n')
stt.seek(0)
stt.length = FLAG_LENGTH + 1

print 'create manager..'

sm = proj.factory.simulation_manager(st)

def step(n, sm):
    sm.move(from_stash='active', to_stash='deadended', filter_func=lambda s: s.addr == 0x400FAD)
    sm.move(from_stash='active', to_stash='deadended', filter_func=lambda s: s.addr == 0x4007D0)
    sm.move(from_stash='active', to_stash='found', filter_func=lambda s: 0x40158A > s.addr > 0x401522 )
    print 'active %03d:' % n, sm.active
    sm.step()

n = 0
sm.stashes['found'] = []
while len(sm.stashes['found']) == 0:
    step(n, sm)
    n += 1

st = sm.stashes['found'][0]

# brute force remaining using hash

import hashlib


hsh = '0a435f46288bb5a764d13fca6c901d3750cee73fd7689ce79ef6dc0ff8f380e5'
stt = st.posix.files[0] # stdin

assert len(hsh) == 64

while 1:
    val = stt.concretize()[:FLAG_LENGTH]
    h   = hashlib.sha256(val).hexdigest()
    print 'try: %s (%s)' % (val, h)
    if h == hsh:
        break
    sym = stt.read_from(FLAG_LENGTH)
    st.solver.add(sym != val)
    stt.seek(0)
