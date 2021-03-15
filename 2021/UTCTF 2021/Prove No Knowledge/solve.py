from pwn import *
from sympy import mod_inverse
from random import randrange
host, port = "crypto.utctf.live", 4354

r = remote(host, port)
r.recvuntil("g: ")
g = int(r.recvline())
r.recvuntil("p: ")
p = int(r.recvline())
r.recvuntil("y: ")
y = int(r.recvline())

rn = 1

while rn < 257:
	if rn % 2:
		r.recvuntil("Send g^r mod p.")
		ran = randrange(p)
		r.sendline(str(pow(g, ran, p)))
		r.recvuntil("Send r.")
		r.sendline(str(ran))
	else:
		r.recvuntil("Send g^r mod p.")
		ran = randrange(p)
		C = (pow(g, ran, p) * mod_inverse(y, p)) % p
		r.sendline(str(C))
		r.recvuntil("Send (x + r) mod (p - 1).")
		r.sendline(str(ran))
	rn += 1
	print(f"round {rn} passed")
r.interactive()