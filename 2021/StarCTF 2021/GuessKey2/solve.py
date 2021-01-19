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