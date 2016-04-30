#!/usr/bin/python2

import os
import struct
from pprint import pprint
from hashlib import sha1
from pwn import *

def cycleLen(data, place):
	seen = {};
	count = 0;
	while not place in seen:
		seen[place] = 1;
		count += 1;
		place = data[place];
	return count;

def realSign(data):
	res = 1;
	for i in range(256):
	    res *= cycleLen(data, i);
	return res;

byte = lambda x : struct.pack('B', x)

# p = remote('wob-key-e1g2l93c.9447.plumbing', 9447)
con = remote('127.0.0.1', 9449)

# Solve proof of work
"""
proof = p.recv(len('otPuwwUJJJjE'))
print 'Finding solution to "' + proof + '"...'
w = 0
while 1:
    t = proof + b64e(p32(w))[0:20]
    if sha1(t).digest().endswith('\x00\x00\x00'):
        break
    w += 1

print 'Found:', t
p.send(t)
"""

#

def send(con, bytes):
    con.recvline()
    con.recvline()
    con.recvline()
    bytes = ''.join(map(byte, bytes))
    con.sendline('1')
    con.send(b64e(bytes))
    return int(con.recvline())

# Create base (jails)

b = [n + 128 for n in range(128)]
base = send(con, b)

# Find an unused char

print 'Find unused value'

unused = None

def add1(l, index):
    l[index] += 1
    if l[index] >= 256:
        l[index] = 128
    return l


for i in range(0, 128):
    dex = add1(list(b), i)
    d = send(con, dex)
    if d == base * 2:
        unused = i + 128
        break

print 'Random unused index', unused

# Extract lengths of runs

print 'Finding length of cycles for index [0;128['

runs = []
r = list(b)
for i in range(0, 128):
    r[unused - 128] = i
    d = send(con, r)
    assert d % base == 0
    runs.append(d / base - 1)

# Extract outputs

def mk_chain(ptr):
    m = {}
    m[unused] = ptr
    chain = []
    l = None
    for i in range(128, 256):
        if i not in m:
            m[i] = l if l else i
            l = i
        chain.append(m[i])
    return chain

def lookup_chain(steps):

    s = {}
    s[unused] = 0
    for i in range(128, 256):
        if i != unused:
            s[i] = s[i - 1] + 1
        if s[i] == steps:
            return i



prop = []
maps = {}
null = send(con, mk_chain(128))

for n in range(0, 128):
    chain = mk_chain(n)
    r = send(con, chain)

    assert r % null == 0
    jumps = r / null - runs[n]

    val = lookup_chain(jumps)
    run = runs[n] - 2

    v = (run, val)
    if v in maps:
        maps[v].append(n)
    else:
        maps[v] = [n]
    prop.append((run, n, val))

prop.sort()

# [(run, index)]
# Map[(run, val)] = [indexes]

# Deduce rest based on runs lengths and hash values

print 'Attempt to find solution'

def solve(maps, prop, guess):
    if prop:
        (run, index, val) = prop[0]
        prop.pop(0)
    else:
        return guess
    if run == 0:
        guess[index] = [val]
    else:
        guess[index] = maps[run - 1, val]
    solve(maps, prop, guess)
    return guess

g = solve(dict(maps), prop, {})

for i in range(0, 128):
    print i, '=', g[i]

# Reduce possibilities

print 'Addtional reduction of possibilities'

def find_targets(l):
    if l >= 128:
        return set([l])
    tars = find_targets(g[l][0])
    for v in g[l][1:]:
        if find_targets(v) != tars:
            raise ValueError
    return tars

red = True
while red:
    red = False
    for k in g:
        if len(g[k]) > 1:
            for v in g[k]:
                if len(g[v]) > 1:
                    break
            else:
                red = True

                # Find target
                tar = find_targets(k)
                assert len(tar) == 1
                tar = list(tar)[0]

                # Run tests
                rs = []
                for v in g[k]:
                    b = [n + 128 for n in range(128)]
                    b[unused - 128] = k # Start test
                    b[tar - 128] = v    # Guess
                    r = send(con, b)
                    rs.append(r)

                # Extract lowest
                sums = zip(rs, g[k])
                (low, _) = min(sums)
                g[k] = []
                for x, y in sums:
                    if x == low:
                        g[k].append(y)

key = []
for i in range(0, 128):
    key += g[i]
print 'Key', key


# Lets sign something

print 'Signing...'

con.sendline('2')
con.recvline()
con.recvline()
con.recvline()

for i in range(0x11):
    print '>', con.recvline()
    data = con.recvline()
    print '>', data

    data = b64d(data)
    assert len(data) == 128
    n = realSign(key + map(ord, data))
    con.sendline(str(n))


con.interactive()

