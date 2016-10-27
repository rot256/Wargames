from random import randrange
from crypsis import rsa
from gmpy2 import invert

bads = [
    0x13371337,
    0x42225333,
    0x5422,
    0x7171,
    0x546262626
]

goods = [
    0x4535544354,
    0x43546349999,
    0x32323311568,
    0x75875654604965,
    0x6376475343,
    0x513396735
]

sk, pk = rsa.generate(1024)
p, q, d, N = sk

# good = (rsa.decrypt_crt(0x42424242, sk), N)
sigs = {}

for bad, good in zip(bads, goods):
    fk = N ^ randrange(2**16, 2**500)
    bk = (p, q, d, fk)
    sig = rsa.decrypt_crt(bad, bk)
    sigs[(sig, fk)] = (rsa.decrypt_crt(good, sk), N)

# print sigs

### ATTACK ###

def crt(pairs):
    x = 0
    M = 1
    for (_, z) in pairs:
        M *= z
    for y, z in pairs:
        c = M/z
        b = invert(c, z)
        x = (x + y * b * c) % M
    return x

"""
x = crt([
    (5, 7),
    (13, 23)
])

print x % 7
print x % 23
"""

v = []
for s, g in sigs.items():
    v.append(int(crt([s, g])))

k = 345273488246843624328673648623476328474829 # 942023802409839259256238567238556320199877874586563784634764375683764547365473654786394380098922222

M = []


from fractions import Fraction

for i, vi in enumerate(v):
    row = [k * vi] + ([0] * i) + [1] + ([0] * (len(v) - i - 1))
    row = map(lambda x: Fraction(x), row)
    M.append(row)

### LLL time : bitches ###

def print_matrix(m, name):
    print name
    for r in m:
        print r

from liblll import lll_reduction

print_matrix(M, 'M:')

Mr = lll_reduction(M)

print_matrix(Mr, 'Mr:')

Ms = [x[1:] for x in Mr]

print_matrix(Ms, 'Ms:')


k1 = 74385634756347465439475374765172563 # 716238129874897247894615317635178653875363187536781350385107359713876



