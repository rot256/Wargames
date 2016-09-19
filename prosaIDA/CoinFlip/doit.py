from pwn import *

context.terminal = 'urxvt'

# p = process('./coinflip')

p = remote('ctf2016.the-playground.dk', 13003)
p.recvuntil('It is now ')
stamp = p.recvuntil(' and I give')
print stamp

# Attach gdb

# gdb.attach(p, ''' ''')

# Convert to unix time
import time
import datetime
a = stamp.split(' ')[0]
h, m, s = map(int, a.split(':'))
today = datetime.date.today()
stamp = datetime.datetime(
    year = today.year,
    month = today.month,
    day = today.day,
    hour = h,
    minute = m,
    second = s
)
unix = int(time.mktime(stamp.timetuple()))
unix += 3600 * 2

r = process(['./rander', str(unix)])
flips = r.recvall().split('\n')
flips = map(lambda x: x.strip(), flips)
flips = filter(lambda x: x != '', flips)
flips = map(int, flips)

for f in flips:
    p.sendline('heads' if f == 0 else 'tails')

p.interactive()
