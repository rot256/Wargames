from pwn import *

def encrypt(m, N):
    return pow(m, 2, N)

r = remote('rabit.pwning.xxx', 7763)
# r = remote('127.0.0.1', 7763)
r.recvuntil('Give me a string starting with ')
prefix = r.recvuntil(',')[:-1]

resp = subprocess.check_output(['./pow', prefix])
r.send(prefix + unhex(resp.strip()))

r.recvuntil('Welcome to the LSB oracle! N = ')
N = int(r.readline())
print N


r.recvuntil('Encrypted Flag:')
enc_flag = int(r.readline())

print 'Main part:'

acc = enc_flag
upper, lower = N, 0
blind = encrypt(2, N)
while (upper - lower) > 1:
    acc = acc * blind % N
    r.sendline(str(acc))
    s = int(r.readline().split(' ')[-1])
    assert s in (0, 1)
    if s == 0:
        upper = (upper + lower) // 2 + ((upper - lower) % 2)
    else:
        lower = (upper + lower) // 2
    print '%x' % upper
    print '%x' % lower

r.interactive()


