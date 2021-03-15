# UTCTF 2021 - Prove No Knowledge

* **Category:** Crypto
* **Solves:** 75

## Challenge

> I've been trying to authenticate to this service, but I'm lacking enough information.

> nc crypto.utctf.live 4354

## Solution

As the name suggests, this challenge is centered around 0 knowledge proofs. Opening up the giving connection, we see that the user is requested to provide ` g^r mod p `, where g and p are provided. Additionally, the user is also provided ` y = g^x mod p `, where ` x ` is some secret. A quick google search leads to the wikipedia article on 0-knowledge proofs. In particular, there is a section about fooling another party into believing you can solve the DLP, namely, you know the secret x. So, the goal of this challenge will be to fool the server into believing we can always solve the DLP.

With this challenge, there are two scenarios that can happen. In either, the user is first requested to give the server ` g^r mod p `, which we can calculate, since we are given both ` g ` and ` p `. The question then becomes what ` r ` to use. In the first scenario, after sending ` g^r mod p `, the server requests ` r ` to verify if what you sent previously was correct. In this case, we can simply calculate ` r ` to be any value we want, send ` g^r mod p `, then ` r `. In the second scenario, after sending the first value, the server requests ` (x + r) mod (p-1) ` instead. The idea here is that ` g^((x + r) mod (p-1)) = g^x * g^r = yg^r mod p`, where the ` mod (p-1) ` is just there to simplify by Fermat's Little Theorem. So, the server intends to take our second input and check that it's equal to ` yg^r `, which we should only happen if we know ` x `. However, there is a way to fool the server: since we are given ` y `, we can simply calculate ` g^r = g^r' * y^-1 `, such that ` y * g^r = yg^r' * y^-1 = g^r' mod p `. Then, we can send this as  g^r mod p , and send ` (x + r) mod (p-1) = r' `, so that the server will verify our inputs. So, we have a way to fool the server in either scenario.

The main issue with this is that you have to guess which of the two scenarios will happen so that you can precompute values accordingly. However, most proper implementations of this check will use several randomized rounds so that you successively have to win many 50-50s to convince the server that you know the secret. Thus, it's normally effectively impossible to actually fool the server. However, this challenge doesn't have that defense; some quick testing quickly shows that the rounds simply alternate between the two scenarios, so it's trivial to fool the server on each check. I wrote the following script to do this automatically:

```python
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
```

`utflag{questions_not_random}`