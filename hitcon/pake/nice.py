
'''
Plays nice with the server to get the flag
'''

from doit import get_conn, ax, get_flag
from hashlib import sha512

passwords = [8, 15, 9, 15, 7, 7, 13, 14, 10, 15, 13]

'''
11=13
10=15
9=10
8=14
7=13
6=7
5=7
4=15
3=9
2=15
1=8
'''

conn = get_conn()

key = 0
for p in passwords:
    conn.recvuntil('Server send')
    bb = int(conn.recvuntil('\n').strip())
    conn.sendline(str(ax[p]))
    key ^= int(sha512(str(bb)).hexdigest(), 16)

flag = get_flag(conn)
print 'Raw:', flag
print 'Decrypted:', flag ^ key
s = '%x' % (flag ^ key)
if len(s) % 2 != 0:
    s = '0' + s
print 'String:', s.decode('hex')
