import re
from pwn import *

# Mistakes were made

context.log_level = 'error'

def get_addresses(path):
    # Objdump all the segments
    res = {}
    o = ''
    p = process(['objdump', '-S', '-M', 'intel', path])
    while 1:
        try:
            o += p.recv(1024)
        except EOFError:
            break

    # Seg
    hex_rex = '([\dabcdef]*)'
    put_rex = '<puts@plt>\n'
    rex = put_rex + '.{0,1024}?' + put_rex
    seg = re.search(rex, o, flags = re.DOTALL).group(0)

    # Find start
    start = re.search(hex_rex + ':', seg).group(1)
    res['start'] = int(start, 16)

    # Find buf
    buf = re.findall('movzx  eax,.*?# ' + hex_rex, seg)
    res['buf'] = min(map(lambda x: int(x, 16), buf))

    # Find avoid
    avoid = re.search(hex_rex + ':', seg.split('\n')[-3]).group(1)
    res['avoid'] = int(avoid, 16)

    # Find target
    target = re.search('\n(.*)?<memcpy@plt>:', o).group(1)
    res['target'] = int(target, 16)

    # Find pad
    s = re.search('xor.{0,1024}?.xor.*?\n', o, flags = re.DOTALL).group(0)
    s = re.findall('xor.*?,.*?\n', s)
    s = map(lambda x: x.split(',')[-1], s)
    s = map(lambda x: int(x, 16) % 0xff, s)
    res['pad'] = map(chr, s)

    print 'Buf = 0x%x' % res['buf']
    print 'Start = 0x%x' % res['start']
    print 'Avoid = 0x%x' % res['avoid']
    print 'Target = 0x%x' % res['target']

    return res
