#!/usr/bin/env python3

from binascii import unhexlify
from Crypto import Random
from Crypto.Cipher import AES
from sys import argv

if len(argv) != 3:
	print('Usage: %s <Encryption key> <Encrypted file>' % argv[0])
	raise SystemExit

unpad = lambda s: s[:-s[-1]]

key = unhexlify(argv[1])

ciphertext = open(argv[2], 'rb').read()
iv = ciphertext[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = unpad(cipher.decrypt(ciphertext[16:]))
print(plaintext.decode('utf-8'))