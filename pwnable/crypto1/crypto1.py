#!/usr/bin/python2

"""
    Produces credentials for pwnable crypto1 challange

    In short the attack works by continuously letting the next plaintext byte "fall into" a block where only one byte is known.
    Excactly like http://cryptopals.com/sets/2/challenges/12/ - even though CBC mode is used in this challange

    Rot256
"""

import time
import hashlib
from pwn import *

address = ('pwnable.kr', 9006)

# Remove verbose logging
context.log_level = 'error'

def send_request(user, pw):
	# p = process('./client.py')
	p = remote(*address)
	p.sendline(user)
	p.sendline(pw)
	while 1:
		l = p.recvline()
		if l.startswith('sending encrypted data'):
			p.close()
			return l[len('sending encrypted data'):].replace('(', '').replace(')', '').strip()

def get_cookie():
	chars = '1234567890abcdefghijklmnopqrstuvwxyz-_'
	out = ''
	user = '-'*14
	chop = 64
	run = True
	
	while run:
		for i in range(15, -1, -1):
			c = send_request(user, '-'*i)
			for n in chars:
				print '>', out + '[' + n + ']'
				o = send_request(user, '-'*i + '-' + out + n)
				if o[:chop] == c[:chop]:
					out += n
					break
			else:
				return out
		chop += 32


if __name__ == '__main__':
	# Extract cookie
	print 'Extracting cookie'
	print 'This might take a while...'
	cookie = get_cookie()
	print 'Found cookie:', '"' + cookie + '"'

	# Forge pw
	pw = hashlib.sha256('admin'+cookie).hexdigest()
	print 'Here are your credentials:'
	print 'ID:', 'admin'
	print 'PW:', pw