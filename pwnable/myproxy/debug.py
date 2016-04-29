from pwn import *

target = '192.168.122.105:1337'

p = process('/usr/bin/gdb')
p.sendline('target remote %s' % target)
p.sendline('b *0x080492A0')   # Log cleanup
p.sendline('ignore 1 5')
p.sendline('b *0x80492c0')    # First write
p.sendline('ignore 2 5')
p.sendline('b *0x80492d8')    # Second write
p.sendline('ignore 3 5')
p.sendline('info break')
p.sendline('c')
p.interactive()
