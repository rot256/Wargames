import os
from Crypto.Cipher import ARC4

## Secret oracle internals ##

cookie = 'QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F'.decode('base64')
print cookie[:4]
print cookie[16:20]

## Public functions ##

def encrypt(req):
    key = os.urandom(16)
    rc4 = ARC4.new(key)
    return rc4.encrypt(req + cookie)

## Attack ##

bias_index = {
    15: 0xF0,
    31: 0xE0
}
bias_out = {k : '' for k in bias_index}
bias_map = {k : {v: 0 for v in range(0, 0x100)} for k in bias_index}
samples = 2**22

def run_bias(shift):
    global bias_index
    global bias_out
    global bias_map
    print 'Run'

    # Collect samples
    n = 0
    while n < samples:
        c = encrypt('A' * shift)
        for b in bias_index:
            try:
                v = ord(c[b])
                bias_map[b][v] += 1
            except IndexError:
                continue
        n += 1

    """
    for k in bias_map:
        print 'K:', k
        for v in bias_map[k]:
            print v, bias_map[k][v]
    """


    # Majority vote (democratic cryptoanalysis)
    bias_vote = {}
    for b in bias_index:
        acc = 0
        top, top_val = 0, None
        for v in bias_map[b]:
            if bias_map[b][v] > top:
                top = bias_map[b][v]
                top_val = v
            acc += bias_map[b][v]

        print 'VAL:', bias_index[b]
        print 'TOP:', top_val, 'with', top, 'of', acc / 256.
        bias_out[b] += chr(bias_index[b] ^ top_val)

    # Print result
    for o in bias_out:
        print o, bias_out[o]

for i in range(15, -1, -1):
    run_bias(i)
