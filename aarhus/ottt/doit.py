from pwn import *

N = 10

local = False

if local:
    host = '127.0.0.1'
    port = 12002
else:
    host = '165.22.73.179'
    port = 704

conn = remote(host, port)
conn.sendline('3')
conn.recvuntil('Good luck!\n')

def round():

    # get matrix

    T2 = []
    for _ in range(N):
        line = conn.recvline().strip()
        T2.append(map(int, line.split(',')))
        assert len(T2[-1]) == N

    # get s and u

    s = int(conn.recvline())
    u = int(conn.recvline())

    return T2, s, u

def answer(v, T2uv):
    conn.recvuntil('v>')
    conn.sendline(str(v))

    conn.recvuntil('T2[u][v]>')
    conn.sendline(str(T2uv))

for _ in range(50):
    T2, s, u = round()

    print T2, s, u

    y = 4

    v = (y + s) % N

    answer(v, T2[u][v] + 1)

conn.interactive()
