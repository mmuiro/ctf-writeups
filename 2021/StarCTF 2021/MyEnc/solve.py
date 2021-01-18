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