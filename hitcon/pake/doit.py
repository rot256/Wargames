from pwn import *
from hashlib import sha512, sha1

'''
Extracts passwords from PAKE server
'''

'''
Heads:

11=13
10=15
'''

p = int('''
2853702329485239989809026491769982230023783615873322184937757867
5282616616142308243698229788844323124061946357688697147688990617
5870272573060319231258784649665194518832695848032181036303102119
3344326121727677106725603905962411362806784256240469884333105883
64872005613290545811367950034187020564546262381876467'''.replace('\n', ''))

q = p - 1

ps = []
for x in range(1, 17):
    ps.append(int(sha512(str(x)).hexdigest(), 16))
gs = map(lambda x: pow(x, 2, p), ps)
ax = {x: y for (x, y) in zip(range(1, 17), gs)}

DEBUG = False
SLOW = False

def get_conn():
    if DEBUG:
        c = process(['ruby', 'pake.rb'])
        return c
    c = remote('52.197.112.79', 20431)
    # c = process(['ruby', 'pake.rb'])
    c.recvuntil('prefix: ')
    prefix = c.recvuntil('\n').decode('base64')
    if SLOW:
        t = ''
        print 'Solving PoW'
        while 1:
            o = sha1(prefix + t).digest()
            if o.startswith('\x00\x00') and ord(o[2]) // 2 == 0:
                print o.encode('hex')
                break
            t = o
    else:
        # Gotta go fast
        if '\x00' in prefix:
            c.close()
            return get_conn()
        p = process(['./pow', prefix])
        t = p.recvall().strip().decode('hex')
        p.close()
    c.send(t.encode('base64'))
    c.recvuntil('Good job!')
    return c

def proxy(conn1, conn2, rounds):
    for i in range(0, rounds):
        conn1.recvuntil('Server send')
        conn2.recvuntil('Server send')
        bb1 = conn1.recvuntil('\n').strip()
        bb2 = conn2.recvuntil('\n').strip()
        # print 'BB1:', int(bb1)
        # print 'BB2:', int(bb2)
        conn1.sendline(bb2)
        conn2.sendline(bb1)

def guess(conn1, conn2, pw):
    g = ax[pw]
    print 'Guessing:', pw, g

    # Proxy
    """
    conn1.recvuntil('Server send')
    conn2.recvuntil('Server send')
    bb1 = conn1.recvuntil('\n').strip()
    conn2.sendline(bb1)
    """
    conn1.recvuntil('Server send')
    conn2.recvuntil('Server send')
    bb1 = conn1.recvuntil('\n').strip()
    bb2 = conn2.recvuntil('\n').strip()
    k1  = int(sha512(bb1).hexdigest(), 16)
    k2  = int(sha512(bb2).hexdigest(), 16)

    # Inject guess
    conn1.sendline(str(g)) 
    conn2.sendline(str(g)) 
    return k1, k2

def get_flag(conn):
    conn.recvuntil('Flag is (of course after encryption :D): ')
    return int(conn.recvuntil('\n'))

if __name__ == '__main__':
    passwords = open('out-passwords', 'w')
    N = 11
    for n in range(0, 11):
        for test in ax:
            print 'Round', n, ', trying:', hex(test)
            conn1 = get_conn()
            conn2 = get_conn()

            proxy(conn1, conn2, n)
            k1, k2 = guess(conn1, conn2, test)
            proxy(conn1, conn2, N - n - 1)

            flag1 = get_flag(conn1)
            flag2 = get_flag(conn2)

            diff1 = flag1 ^ k1
            diff2 = flag2 ^ k2

            conn1.close()
            conn2.close()

            if diff1 == diff2:
                print 'Password:', n, '=', hex(test)
                passwords.write(str(test) + '\n')
                break
            print 'Wrong guess'

        else:
            print 'Failed on index:', n
            exit(-1)
    passwords.close()
