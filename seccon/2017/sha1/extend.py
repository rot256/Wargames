import os
import sys
from hashlib import sha1
from pwn import *

# https://cryptopals.com/sets/7/challenges/52

def extend(data, size):
    import hlextend
    hsh = sha1(data).hexdigest()
    sha = hlextend.new('sha1')
    return sha.extend(data, 'A' * 1000, 0, hsh)

size = 2017 * 1024 + 32
# size = 1024 * 1024

with open(sys.argv[1], 'r') as f:
    s1 = f.read()

pad = 'A' * (size - len(s1))

tmp = '/tmp/%s' % os.urandom(16).encode('hex')

print 'pad:', tmp

with open(tmp, 'w') as f:
    f.write(pad)

print 'org hash   :', sha1(s1).hexdigest()
print 'org length :', len(s1)

p1 = process(['./hexpand/hexpand', '-t', 'sha1', '-s', sha1(s1).hexdigest(), '-l', str(len(s1)),  '-m', tmp])
a1 = p1.recvall()

assert '\n' not in a1

d1 = s1 + a1.decode('hex')

print 'new hash   :', sha1(d1).hexdigest()
print 'new length :', len(d1)

with open(sys.argv[2], 'w') as f:
    f.write(d1)
