# \*CTF 2021 - GuessKey2

* **Category:** Crypto
* **Points:** 133

## Challenge

> I’m sorry 😦
> nc 52.163.228.53 8082

## Solution

This challenge is a sequel to GuessKey, which was solved quickly by my teammate. The only difference between the programs given in this challenge and GuessKey was the printing of the key.

GuessKey_Fix.py:
```python
from random import randint
import os
flag = 'fake flag'
N=64
key=randint(0,2**N)
# print key
key=bin(key)[2:].rjust(N,'0')
count=0
while True:
	p=0
	q=0
	new_key=''
	zeros=[0]
	for j in range(len(key)):
		if key[j]=='0':
			zeros.append(j)
	print(zeros)
	p=zeros[randint(0,len(zeros))-1]
	q=zeros[randint(0,len(zeros))-1]
	try:
		mask=int(raw_input("mask:"))
	except:
		exit(0)
	mask=bin(mask)[2:]
	if p>q:
		tmp=q
		q=p
		p=tmp
	print(p,q)
	cnt=0
	for j in range(0,N):
		if j in range(p,q+1):
			new_key+=str(int(mask[cnt])^int(key[j]))
		else:
			new_key+=key[j]
		cnt+=1
		cnt%=len(mask)
	key=new_key
	try:
		guess=int(raw_input("guess:"))
	except:
		exit(0)
	if guess==int(key,2):
		count+=1
		print 'Nice.'
	else:
		count=0
		print 'Oops.'
	if count>2:
		print flag
```

So the program sets the key as some unknown binary string of length 64, chooses two random indices where the key has 0s, asks for a user-given mask, and then uses said mask as a xor-key on the portion of the key between those two indices, inclusively. The user is then asked to give a guess for what the result of the the key being xor'ed as described above is. The user needs to guess the key 3 times correctly to get the flag.

From GuessKey1, the solution to which was just sending 0 as mask, we know that once we get the right key guessed, we can just send 0 twice more as mask to get the flag by just using the same guess. The question then is how to get to the right guess. How is this to be done? At a first glance, it may seem like this challenge needs you to brute force for the key to get at least 1 correct guess. But 2^64 is a really large number, so that's probably not it, especially since you have to consider waiting for each send-receive with the connection.

The vulnerability in this program is that it doesn't ask you to guess new-key, but asks you to guess key, and changes key into new key each time. This means that each time you send it a mask, the key is being modified. But, the indices which are being xor'ed are chosen randomly; is it still possible to make this work and make a predictable result for key?

Based on the fact that p and q are indices that are where there are 0s, I figured that sending 1 as mask to use 1 as the xor key would lead to something predictable, since doing so would be guaranteed to flip those 0s into 1s, and those indices wouldn't be chosen again unless they were later flipped again. I thought that maybe by doing this, all the 0 bits would eventually be flipped to 1s, and we could just guess a full 64-bit 1 string, corresponding to 2^64 - 1, each time until it was correct. I tested it locally, and lo and behold, it worked as predicted! Through some tests, I found that it usually took 50-200 iterations for the key to be converted to all 1s, which is perfectly manageable.

Solution script:
```python
from pwn import *
host, port = '52.163.228.53', 8082

def main():
	r = remote(host,port)
	r.send('')
	count = 0
	while True:
		res = r.recvuntil('mask:').decode()
		if 'Nice.' in res:
			break
		r.sendline('1')
		r.recvuntil('guess:')
		r.sendline(str(2**64-1))
		count += 1
		print(f'{count} tries')
	#key is all 1s
	r.sendline('0')
	r.recvuntil('guess:')
	r.sendline(str(2**64-1))
	r.recvuntil('mask:')
	r.sendline('0')
	r.recvuntil('guess:')
	r.sendline(str(2**64-1))
	r.interactive()

main()
```
`*CTF{27d30dad45523cbf88013674a4b5bd29}`