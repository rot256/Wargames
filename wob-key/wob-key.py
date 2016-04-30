#!/usr/bin/python

import time;
import random;
from signal import SIGTERM, SIGCHLD, signal, alarm

FLAG1 = '';
FLAG2 = '';

def cycleLen(data, place):
	seen = {};
	count = 0;
	while not place in seen:
		seen[place] = 1;
		count += 1;
		place = data[place];
	return count;

def realSign(data):
        from struct import unpack

        vs = map(ord, data)

	res = 1;
	for i in range(256):
		res *= cycleLen(map(ord, data), i);
	return res;


import base64, SocketServer, os, sys, hashlib;

class ServerHandler(SocketServer.BaseRequestHandler):

	def fail(self, message):
		self.request.sendall(message + "\n");
		self.request.close();

	def pow(self):
		proof = base64.b64encode(os.urandom(9));
		self.request.sendall(proof);
		test = self.request.recv(20);
		ha = hashlib.sha1();
		ha.update(test);
		if test[0:12] != proof or not ha.digest().endswith('\x00\x00\x00'):
			self.fail("Bad proof of work.");

	def sign(self, invalid):
		data = base64.b64decode(self.request.recv(172));
		if len(data) != 128:
			self.fail("Bad data");
			return;
		if data == invalid:
			self.fail("Same data");
			return;
		self.request.sendall(str(realSign(self.SECRET + data)) + "\n");

	def check(self):
		for i in range(0x10):
			compare = os.urandom(128);
			self.request.sendall("You need to sign:\n");
			self.request.sendall(base64.b64encode(compare) + "\n");
			sig = int(self.request.recv(620));
			if sig != realSign(self.SECRET + compare):
				return False;
		compare = ''.join(map(chr, range(128)));
		self.request.sendall("You need to sign:\n");
		self.request.sendall(base64.b64encode(compare) + "\n");
		sig = int(self.request.recv(620));
		return sig == realSign(self.SECRET + compare);

        def fake(self):
            y = [136, 43, 15, 253, 239, 143, 32, 107, 225, 139, 248, 126, 176, 119, 1, 252, 82, 236, 212, 220, 21, 103, 169, 151, 235, 208, 95, 185, 155, 27, 203, 98, 116, 25, 16, 122, 11, 190, 237, 246, 211, 151, 211, 172, 176, 215, 143, 61, 5, 218, 227, 6, 223, 69, 47, 38, 19, 178, 35, 239, 254, 235, 244, 6, 156, 171, 15, 81, 225, 176, 255, 59, 32, 177, 132, 105, 190, 81, 122, 246, 216, 119, 204, 244, 123, 148, 217, 80, 129, 135, 95, 20, 126, 252, 99, 210, 141, 10, 10, 159, 207, 73, 48, 87, 152, 101, 77, 50, 156, 120, 83, 162, 6, 32, 139, 143, 162, 129, 64, 186, 166, 91, 204, 203, 215, 94, 203, 187]
            return ''.join(map(chr, y))

	def handle(self):
		# self.pow();
		self.SECRET = os.urandom(128);
                # self.SECRET = self.fake()

                x = map(ord, self.SECRET)
                print x
                for i in range(0, 128):
                    try:
                        cycleLen(x, i)
                        print 'Not vuln'
                        break
                    except IndexError:
                        pass

		for i in range(0x10000):
                        print i
			self.request.sendall("\n1) Sign something\n2) Give me signiture of data\n");
			op = int(self.request.recv(2));
			if op == 1:
				self.sign('');
			elif op == 2:
				print i;
				if self.check():
					self.request.sendall(FLAG1);
					if i < 350:
						self.request.sendall(FLAG2);
				else:
					self.request.sendall("Failed signing\n");
				break;
			else:
				self.fail("Bad option");
				break;
		self.request.close();


class ThreadedServer(SocketServer.ForkingMixIn, SocketServer.TCPServer):
	pass;

if __name__ == "__main__":
	HOST = sys.argv[1];
	PORT = int(sys.argv[2]);

	FLAG1 = open('flag1.txt', 'r').read();
	FLAG2 = open('flag2.txt', 'r').read();
	server = ThreadedServer((HOST, PORT), ServerHandler);
	server.allow_reuse_address = True;
	server.serve_forever();
