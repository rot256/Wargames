from pwn import *

conn = remote('crypto.chal.csaw.io', 1578)

def query(val):
    conn.recvuntil('Enter your username (no whitespace): ')
    conn.sendline(val)
    conn.recvuntil('Your Cookie is: ')
    ct = conn.recvuntil('\n').strip().decode('hex')
    assert len(ct) % 16 == 0
    return ct

def padx(n):
    return 'A' * n

known = 'flag{Crypt0_is_s0_h'

alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
numbs = '0123456789'
spec  = '.,-_{}#'
chars = alpha.lower() + alpha + numbs + spec
chars = filter(lambda x: x not in (' ', '\n', '\r'), map(chr, range(256)))


while 1:
    offset = 16 * (len(known) // 16)
    fill = padx(offset + 15 - len(known))
    tar = query(fill)[offset:offset + 16]

    for c in chars:
        g = query(fill + known + c)
        print known, c
        if g[offset:offset + 16] == tar:
            known += c
            break
    else:
        assert False, 'massive fail'
