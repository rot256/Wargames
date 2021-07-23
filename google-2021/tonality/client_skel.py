#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import pwnlib
import challenge_pb2
import struct
import sys

n = 115792089210356248762697446949407573529996955224135760342422259061068512044369

def handle_pow(tube):
  raise NotImplemented()

def read_message(tube, typ):
  n = struct.unpack('<L', tube.recvnb(4))[0]
  buf = tube.recvnb(n)
  msg = typ()
  msg.ParseFromString(buf)
  return msg

def write_message(tube, msg):
  buf = msg.SerializeToString()
  tube.send(struct.pack('<L', len(buf)))
  tube.send(buf)

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--port', metavar='P', type=int, default=1337, help='challenge #port')
  parser.add_argument(
      '--host', metavar='H', type=str, default='tonality.2021.ctfcompetition.com', help='challenge host')
  args = parser.parse_args()

  tube = pwnlib.tubes.remote.remote(args.host, args.port)
  print(tube.recvuntil('== proof-of-work: '))
  if tube.recvline().startswith(b'enabled'):
      handle_pow(tube)

  # Step 1: Hello.
  hello = read_message(tube, challenge_pb2.HelloResponse)
  print(hello)

  import hashlib

  m0 = b"Server says 1+1=2"
  m1 = b"Server says 1+1=3"

  z0 = int.from_bytes(hashlib.sha1(m0).digest(), 'big')
  z1 = int.from_bytes(hashlib.sha1(m1).digest(), 'big')

  print(z0, z1)

  d = (z0 * pow(z1, -1, n)) % n
  D = d

  print('d =', d)
  print('D =', D)

  assert (z0 * pow(d, -1, n)) % n == z1

  # Step 2: Sign.
  sign_req = challenge_pb2.SignRequest()
  sign_req.scalar = D.to_bytes((D.bit_length() + 7) // 8, 'big')
  write_message(tube, sign_req)

  sign_res = read_message(tube, challenge_pb2.SignResponse)
  print('Sign:', sign_res)

  # Create new signature
  sig = sign_res.message0_sig

  s = int.from_bytes(sig.s, 'big')
  s = s * pow(d, -1, n)
  s = s % n

  sig.s = s.to_bytes(byteorder='big', length=32)


  # Step 3: Verify.
  verify_req = challenge_pb2.VerifyRequest()
  verify_req.message1_sig.r = sig.r
  verify_req.message1_sig.s = sig.s
  write_message(tube, verify_req)

  verify_res = read_message(tube, challenge_pb2.VerifyResponse)
  print('Verify:', verify_res)
  return 0


if __name__ == '__main__':
  sys.exit(main())
