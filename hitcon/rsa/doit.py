from pwn import *
from liblll import *
from numpy import linalg

'''
Here is our attack baby:
http://www.chesworkshop.org/ches2011/presentations/Session%204/CHES2011_Session4_3.pdf
'''

def itob(a):
    a = '%x' % a
    if len(a) % 2 != 0:
        a = '0' + a
    return a.decode('hex')

def get_conn():
    conn = process(['ruby', 'rsa.rb'])
    return conn


def get_sign(x):
    conn = get_conn()
    flag = int(conn.recvline().decode('base64').encode('hex'), 16)
    conn.recvuntil('n = ')
    N = int(conn.recvuntil('\n'), 16)
    e = 0x10001
    conn.sendline(str(x))
    signed = int(conn.recvline())
    conn.close()
    return signed, N, e

# Gram-schmidt

def vec_dot(u, v):
    return sum([x*y for (x, y) in zip(u, v)])

def vec_scale(v, s):
    return [x*s for x in v]

def vec_add(u, v):
    return [x+y for x,y in zip(u, v)]

def vec_sub(u, v):
    return [x-y for x,y in zip(u, v)]

def vec_proj(u, v):
    vu = vec_dot(v, u)
    uu = vec_dot(u, u)
    return vec_scale(u, vu / uu)

def gram_schmidt(B):
    Q = []
    for v in B:
        g = v
        for u in Q:
            g = vec_sub(g, vec_proj(u,v))
        Q.append(g)
    return Q


# Obtain faulty signatures

dim = 10
sigs = set([])
for _ in range(dim):
    s, N, e = get_sign(0x1337)
    sigs.add(s)
sigs = list(sigs)

# Create lattice

k = 30200
lat = []
for n, sig in enumerate(sigs):
    row = [sig * k] + [0] * n + [1] + [0] * (dim - n - 1)
    lat.append(row)
mat = create_matrix(lat)

# Ortogonalize

print 'Running gram-schmidt'

print len(mat), len(mat[0])

mat = gram_schmidt(mat)

print mat

# Reduce basis

print 'Running LLL'

mat_reduced = lll_reduction(mat)

for r in mat:
    print r

print '-' * 20

for r in mat_reduced:
    print r
