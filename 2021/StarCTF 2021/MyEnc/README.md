# \*CTF 2021 - MyEnc

* **Category:** Crypto
* **Points:** 227

## Challenge 

> nc 52.163.228.53 8081

## Solution

I worked on this CTF with my teammates on Crusaders of Rust for our first team CTF of the year.

The following program is given to us: (handout.py)
```python
from Crypto.Util.number import getPrime,bytes_to_long
import time,urandom
from flag import flag
iv=bytes_to_long(urandom(256))
assert len(flag)==15
keystream=bin(int(flag.encode('hex'),16))[2:].rjust(8*len(flag),'0')
p=getPrime(1024)
q=getPrime(1024)
n=p*q
print "n:",n
cnt=0
while True:
	try:
		print 'give me a number:'
		m=int(raw_input())
	except:
		break
	ct=iv
	for i in range(1,8):
		if keystream[cnt]=='1': 
			ct+=pow(m^q,i**i**i,n)
			ct%=n
		cnt=(cnt+1)%len(keystream)
	print "done:",ct
```

The flag is converted to a keystream, and we are to figure out said keystream by looking at the ciphertexts it produces. Connecting to the provided connection also required solving a proof of work.

One of the first things I thought of on seeing this is that being able to send 0 as `m^q` will allow us to retrieve the iv, as 0 to any power is still 0. Additionally, by sending 1, we can retrieve the number of 1 bits in a block of the keystream, with each block being of length 7, from range(1,8). We can do this by simply subtracting the resulting ciphertext from sending `m^q` as 1 by the iv. The issue here is that in order to send 0 or 1, we need to know q, as `m^q` is m XOR q. So, we will be sending q and q XOR 1 for 0 and 1, respectively. The goal of the first part of this challenge is then to obtain q. It is also worth noting that my teammates and I also considered a few other potential approaches, like performing a side-channel attack, since `i**i**i` gets very large for even small numbers. We didn't end up following through with this.

As it turns out, because we can get `ct`s that contain information about q, it is not so difficult to find q, which my teammate and I found out after some thought over this challenge. The idea is as follows: if we send 0 as m, then ct will be `iv + xq mod n`, where x is some integer. The point is that the result of `pow(q,i**i**i,n)` will be equal to some multiple of q mod n, and anything true mod n will be true mod its factors, p and q. Thus, `pow(q,i**i**i,n)` will also be 0 mod q, which is simply a restatement that it's a multiple of q. Adding a few of these together for the bits of the keystream block that are 1s will naturally still be a multiple of q. If we call the ciphertext received from sending m = 0 as `k1`, then we could just take `gcd(k1,n)` to potentially get q, granted `k1` is not 0 mod n. However, it is not so simple, since we also have to take the randomly generated iv into account, which is likely not to be a multiple of q. So in reality, `k1 = iv mod q`. This issue can easily be resolved by just sending 0 again and getting `k2`, which will only be the same as `k1` if the two keystream blocks are the same, which is not likely. We can also get multiple pairs of `k1, k2`s, so this was not a concern. Naturally, `k2 = iv mod q` as well, so it is true that `k1 - k2 = 0 mod q`, and lifting to the integers tells us that `k1 - k2 = iq`, where i is some arbitrary integer. So setting `k = k1 - k2`, we can then take `gcd(k,n)` to get q. The code to do this was written by my teammate while I went to work on the next part:
```python
def factor_n(r,n):
	r.recvline()
	r.sendline("0")
	r.recvline()
	r.recvline()
	r.sendline("0")
	k1 = int(r.recvline().decode()[5:])
	r.recvline()
	r.sendline("0")
	r.recvline()
	r.sendline("0")
	r.recvline()
	k2 = int(r.recvline().decode()[5:])
	k = max([k1,k2]) - min([k1,k2])
	print("k:", k)
	print("n:", n)
	q = 0
	if gcd(k,n) != 1:
		q = gcd(k,n)
		print("q:", gcd(k,n))
		return n//q, q
	assert False, 'failed to get q'
```

The next part of this challenge involves a vulnerability caused by the keylength being relatively prime to the blocksize, being 120 (15 x 8) and 7 respectively. Looking at this part of the program:
```python
for i in range(1,8):
	if keystream[cnt]=='1': 
		ct+=pow(m^q,i**i**i,n)
		ct%=n
	cnt=(cnt+1)%len(keystream)
print "done:",ct
```
we can see that for each m sent, it looks at the first 7 bits of the keystream starting from index 0, then the next 7 bits, and so on, which is the why the blocksize is 7. The issue here is that because 120 is not divisible by 7, by sending multiple messages, precisely 120, we can look at blocks *starting from every single index from 0 to 119*. This would not be an issue if the blocksize was 8, as then each ct would correspond to blocks starting at index 0, 8, 16, ... 112, and 0 again, repeating. With 7, the starting indices for each block goes through 0, 7, 14, ... 112, 119, 6, 13 ... and so on, going through all the indices. This can be seen from the fact that the first nonzero multiple of 7 that is divible by 120 is 7 x 120 = 840, so 120 iterations will have to happen before `cnt` returns to 0. With this information in mind, I first retrieved the iv by sending `m = q`, then got the number of 1s per keystream block by sending `m = q^1`, with each block corresponding to a start index, and named the counts `sums`. I also had to adjust the index which the sum collection starts at to account for the requests already made up until that point from retrieving q and the iv, being a total of 5. So, the index that I start getting the number of 1s per block was 5 x 7 = 35. Here is the code I wrote to get `sums`:
```python
def solve_keystream(r,pay,iv, offset):
	sums = ['?']*keylength
	keystream = ['?']*keylength
	index = offset*blocksize
	print('started keystream crack...')
	for _ in tqdm(range(keylength)):
		r.recvuntil('give me a number:')
		r.sendline(pay)
		r.recvuntil('done:')
		sums[index % keylength] = int(r.recvline()) - int(iv)
		index += blocksize
	assert '?' not in sums
	print('sums retrieved')
	return get_keystream(sums,blocksize,keylength)
``` 
The implementation of `get_keystream` is the next point of discussion.

To work with `sums`, I considered a simpler example. Let's look at the binary string `01101011` of length 8, and suppose we used a blocksize of 7. Then the number of 1s per block starting from indeces 0,1,2, etc. would be 4,5,4,4,5,4,5,4. This is our `sums` for this example. The first thing of note is that from one `sum` to the next, there is at most a difference of 1. This makes sense, since going from one block to the next, 4 cases are possible:

* Lose a 1, gain a 1. Difference in # of 1s from previous block: 0
* Lose a 0, gain a 0. Difference: 0
* Lose a 1, gain 0. Difference: -1
* Lose a 0, gain a 1. Difference: 1

Looking at `sums` without knowing the original binary string, we can only distinguish the differences from one block to another. In the last 2 cases, this allows us to recover two bits of the binary string, but in the first 2 cases, where the difference is 0, we may not be able to distinguish between whether the bit lost and the bit gained were both 0 or both 1. Can we still recover the original binary string just from `sums`?

It turns out that we usually can, just by including a bit of other information. In the first two cases where the difference is 0, if we know the value of either the bit gained or the bit lost, we automatically know the other one to simply be the same. So we can run an algorithm on `sums` that continues until all the bits of the keystream are figured out. Here is my implementation:

```python
def get_keystream(sums, blocksize, keylength):
	keystream = ['?']*keylength
	index = 0
	while '?' in keystream:
		if keystream[index % keylength] != '?':
			index += 1
			continue
		diff = sums[(index+1)%keylength] - sums[index % keylength]
		if diff == 1:
			keystream[index % keylength] = 0
			keystream[(index+blocksize) % keylength] = 1
		elif diff == -1:
			keystream[index % keylength] = 1
			keystream[(index+blocksize) % keylength] = 0
		else:
			if keystream[(index + blocksize) % keylength] == 0:
				keystream[index % keylength] = 0
			elif keystream[(index + blocksize) % keylength] == 1:
				keystream[index % keylength] = 1
		index += 1
	return ''.join([str(n) for n in keystream])
```

The final solve script:
```python
from hashlib import sha256
from pwn import *
import itertools
import string
from math import gcd
from tqdm import tqdm
from Crypto.Util.number import long_to_bytes

charset = string.ascii_letters + string.digits
host, port = '52.163.228.53', 8081
keylength, blocksize = 120, 7

def proof_of_work(length, suffix, target):
	for prefix in itertools.product(charset, repeat=length):
		if sha256((''.join(prefix) + suffix).encode()).hexdigest() == target:
			return ''.join(prefix)

def solve_pow(r):
	question = r.recvuntil('Give me xxxx:').decode()
	question = question[:question.index('Give me xxxx:')].split(' == ')
	suffix, target = question[0][12:-1], question[1][:-1]
	prefix = proof_of_work(4,suffix,target)
	r.sendline(prefix)
	print('pow solved')

def factor_n(r,n):
	r.recvline()
	r.sendline("0")
	r.recvline()
	r.recvline()
	r.sendline("0")
	k1 = int(r.recvline().decode()[5:])
	r.recvline()
	r.sendline("0")
	r.recvline()
	r.sendline("0")
	r.recvline()
	k2 = int(r.recvline().decode()[5:])
	k = max([k1,k2]) - min([k1,k2])
	print("k:", k)
	print("n:", n)
	q = 0
	if gcd(k,n) != 1:
		q = gcd(k,n)
		print("q:", gcd(k,n))
		return n//q, q
	assert False, 'failed to get q'

def solve_keystream(r,pay,iv, offset):
	sums = ['?']*keylength
	keystream = ['?']*keylength
	index = offset*blocksize
	print('started keystream crack...')
	for _ in tqdm(range(keylength)):
		r.recvuntil('give me a number:')
		r.sendline(pay)
		r.recvuntil('done:')
		sums[index % keylength] = int(r.recvline()) - int(iv)
		index += blocksize
	assert '?' not in sums
	print('sums retrieved')
	return get_keystream(sums,blocksize,keylength)

def get_keystream(sums, blocksize, keylength):
	keystream = ['?']*keylength
	index = 0
	while '?' in keystream:
		if keystream[index % keylength] != '?':
			index += 1
			continue
		diff = sums[(index+1)%keylength] - sums[index % keylength]
		if diff == 1:
			keystream[index % keylength] = 0
			keystream[(index+blocksize) % keylength] = 1
		elif diff == -1:
			keystream[index % keylength] = 1
			keystream[(index+blocksize) % keylength] = 0
		else:
			if keystream[(index + blocksize) % keylength] == 0:
				keystream[index % keylength] = 0
			elif keystream[(index + blocksize) % keylength] == 1:
				keystream[index % keylength] = 1
		index += 1
	return ''.join([str(n) for n in keystream])

def main():
	r = remote(host,port)
	r.send('')
	#solving pow
	solve_pow(r)
	#recovering factors of n
	r.recvuntil('n:')
	n = int(r.recvline())
	p,q = factor_n(r,n) #only use q
	#recover iv
	r.recvuntil('give me a number:')
	r.sendline(str(q))
	r.recvuntil('done:')
	iv = str(int(r.recvline()))
	print('iv:', iv)
	pay = str(q^1)
	#recovering the keystream bits
	binflag = solve_keystream(r, pay, iv, 5)
	#flag get
	print(long_to_bytes(int(binflag, 2)))

main()
```
`*CTF{yOuG0t1T!}`

Fun challenge! Thank you \*CTF.