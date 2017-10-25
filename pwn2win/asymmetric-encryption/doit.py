from pwn import *
from gmpy2 import *

c = remote('200.136.213.110', 7777)

def kv():
    return c.recvline().strip().split(' = ')

def val():
    return eval(kv()[1])

def sage(path, args):
    p = process(['sage', path] + args)
    r = eval(p.readline().strip())
    p.close()
    return r

def dlog(h, g, p):
    return sage('dlog.sage', [str(h), str(g), str(p)])

def factor(n):
    return sage('factor.sage', [str(n)])

## Elgamal ##

q = val()
g = val()
h = val()

sk = dlog(h, g, q)
assert pow(g, sk, q) == h

print sk
print q # mod
print g # generator
print h # pub key

pub, ct = val()

ss = pow(pub, sk, q)
print 'ss:', ss

dec = invert(ss, q)
print 'dec:', dec

pt  = (dec * ct) % q
print 'pt:', pt

pt2 = pt * 3 + 32

tup = (int(pub), int((pt2 * ss) % q))

c.sendline(str(tup))
c.recvline()
c.recvline()

## RSA ##

print 'doing RSA'

n = val()
e = val()

assert e == 65537

p, q = tuple(map(lambda x: x[0], factor(n)))

print 'p:', p
print 'q:', q

d = invert(e, (p - 1) * (q - 1))

print 'd:', d

ct = val()
pt = pow(ct, d, n)

c.recvline()

pt2 = pt**5 + 2*pt + 41

c.sendline(str(pow(pt2, e, n)))
c.recvline()

## paillier ##

print 'paillier now'

n = val()
g = val()

print 'n:', n
print 'g:', g

assert g == n + 1, 'prob. not paillier'

p, q = tuple(map(lambda x: x[0], factor(n)))
lam  = (p - 1) * (q - 1)
mu   = invert(lam, n)

assert p*q == n

def dec(v):
    v = pow(v, lam, n*n)
    v = (v - 1) // n
    return (v * mu) % n

ct = val()
pt = dec(ct)

assert dec(pow(ct, 2, n*n)) == (pt * 2) % n

print 'p:', p
print 'q:', q
print '\\lambda:', lam
print '\\mu:', mu
print 'pt:', pt

# use homomorphic property

ct2 = ct
for _ in range(4):
    ct2 = pow(ct2, pt, n*n)

assert dec(ct2) == (pt ** 5) % n

c.sendline(str(ct2))
c.recvline()
c.recvline()


'''
Now using legit large numbers
Homomorhpic encryption 80s style!!!
'''

## Elgamal again ###

q  = val()
g  = val()
h  = val()

print 'q:', q
print 'g:', g
print 'h:', h

pub, ct = val()

pub2 = pub
ct2  = ct

for _ in range(6):
    pub2 = (pub2 * pub) % q
    ct2  = (ct2 * ct)   % q

c.sendline(str((pub2, ct2)))
c.recvline()
c.recvline()

## RSA again ###

n = val()
e = val()
ct = val()

ct2 = pow(31, e, n)
ct2 = (ct2 * ct) % n
ct2 = pow(ct2, 7, n)

c.sendline(str(ct2))
c.recvline()
c.recvline()

## Pallier again ##

n = val()
g = val()

print 'n:', n
print 'g:', g

assert g == n + 1, 'prob. not paillier'

cta = val()
ctb = val()
m   = n*n

print 'enc(a):', cta
print 'enc(b):', ctb

v1 = pow(cta, 31, m)
v2 = pow(ctb, 12, m)
v3 = pow(g, 56, m)

ct2 = (v1 * v2 * v3) % m

c.sendline(str(ct2))




c.interactive()
