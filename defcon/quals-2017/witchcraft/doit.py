import sys
from pwn import *

context(
    log_level = 'error'
)

knowns = ['']

while knowns:
    nknowns = []
    codes = {}
    for known in knowns:
        for v in range(32, 128):
            guess = known + chr(v)
            print len(knowns), sys.argv[1], guess
            p = process(sys.argv[1])
            p.sendline(guess)
            d = p.recvall().strip()
            if d != 'enter code:':
                with open(sys.argv[1] + '.txt', 'w') as f:
                    f.write(guess.encode('hex') + '\n')
                    f.write(guess + '\n')
                    f.write(d)
                print 'completed'
                exit(0)
            code = p.poll()
            try:
                codes[code].append(guess)
            except KeyError:
                codes[code] = [guess]
            p.close()

    minimal = min(map(len, codes.values()))
    for c, g in codes.items():
        if len(g) == minimal:
            nknowns += g
    knowns = nknowns

exit(0)
