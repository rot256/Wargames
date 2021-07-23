from pwn import *

t_low = 32
t_high = 128

chars = range(t_low, t_high)

def conn():
    return remote('story.2021.ctfcompetition.com', 1337)

def crc(s):
    assert '\n' not in s
    assert len(s) >= 256
    c = conn()
    c.recvuntil('Hello! Please tell me a fairy tale!')
    c.sendline(s)
    c.recvuntil('The CRC values of your text are [')
    l = str(c.recvuntil('].')[:-2], 'UTF-8').split(', ')
    return [int(v, 16) for v in l]


def print_xor():
    for a in chars:
        for b in chars:
            if a ^ b in chars:
                return (chr(a), chr(b), chr(a ^ b))


a, b, c = print_xor()

a_c = crc(a * 256)
b_c = crc(b * 256)
c_c = crc(c * 256)

print(a_c, b_c, c_c)
print(a, b, c)
print([x^y for (x, y) in zip(a_c,b_c)], c_c)


