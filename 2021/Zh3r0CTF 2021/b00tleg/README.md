# Zh3r0CTF 2021 - b00tleg
* **Category:** Crypto
* **Solves:** 26

# Challenge

> Source? Gotta comply to Indian CTF's crypto standards

> nc crypto.zh3r0.cf 1111

# Solution

Unfortunately, there's no source for this challenge. Connecting to the provided connection shows this:

> Welcome to your basic cryptanalysis tutorial

> There would be 8 levels, each level bringing something new on 
the plate. 

> I would be generous enough to let you encrypt any 
string of your choice. 

> Once you figure out the encryption, 
submit the flag to proceed to the next level.

We are then given an encrypted flag, and the option to either encrypt a message of our choosing, or submit what we think is the original unencrypted flag, like so:

```
Level: 1, encrypted flag: 69666d6d70217870736d6522214d667574216866752168706a6f68

[1] Encrypt
[2] Submit level flag
>>> 
```

So basically, our job is figure out what the encryption scheme is through repeatedly encrypting different messages, and then reverse it to get the original flag.

## Level 0

There were two level 1s, so we'll call this first one level 0. After a bit of testing by sending multiple hex strings of 0s, I figured out that it just adds 1 to the value of each byte in the message. So, we just take the encrypted flag and subtract 1 from each byte to get the original flag. Here is the code to do this:

```python
def level0(passed):
	print("Level 0")
	if not passed:
		r.recvuntil("Level: 1, encrypted flag: ")
		ef1 = r.recvline().decode()[:-1]
		r.recvuntil(">>> ")
		f1 = ""
		for i in range(0, len(ef1), 2):
			byte = int(ef1[i:i + 2], 16)
			byte -= 1
			f1 += hex(byte)[2:]
		print(f1)
		assert len(f1) == len(ef1)
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline(f1)
```
The flag: `hello world! Lets get going`

## Level 1

The encrypted flag for this level is just a number, rather than a hex string like the previous. So, it's likely that the message passed in is converted to a number and then something else is done to it. Sending `00` returns 0, so I suspected that it simply converts the hex to a number. Testing with a few more messages confirms this, so we just convert the given encrypted flag into hex and send it over. 
```python
def level1(passed):
	print("Level 1")
	if not passed:
		r.recvuntil("Level: 1, encrypted flag: ")
		ef1 = r.recvline().decode()[:-1]
		r.recvuntil(">>> ")
		f1 = hex(int(ef1))[2:]
		print(f1)
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline(f1)
```

The flag: `Nothing fancy, just standard bytes_to_int`

## Level 2

This is where the levels start requiring more work and consideration. Once again, I sent `00` first(in general, this is a good practice), and got a hex string of the same length back. Sending `01` and `02` got two more different hex strings of length 2, and the three do not differ from each other by a constant amount(mod 256, since these are 1 byte each), meaning that there isn't just simple addition happening. 

Next, I tried sending varied lengths of `00`, such as `0000`, etc.., and noticed that it got me the same hex string from before, but multiple times. It seemed like the encryption maps each individual byte to another byte, regardless of where each byte is in the message. So, we can simply construct a table for all possible 256 bytes to see what bytes map to what bytes. We can do this by encrypting each of `00`, `01`, `02`, ..., `ff`. We can then decrypt the encrypted flag by reversing the mapping.

```python
def level2(passed):
	print("Level 2")
	if not passed:
		r.recvuntil("Level: 2, encrypted flag: ")
		ef2 = r.recvline().decode()[:-1]
		table = [""]*256
		for i in range(256):
			r.recvuntil(">>> ")
			r.sendline("1")
			r.recvuntil("message in hex:")
			r.sendline(hex(i)[2:].zfill(2))
			key = int(r.recvline().decode()[:-1], 16)
			table[key] = hex(i)[2:].zfill(2)
			print(i)
		f2 = ""
		for i in range(0, len(ef2), 2):
			f2 += table[int(ef2[i:i + 2], 16)]
		assert len(f2) == len(ef2)
		print(f2)
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline(f2)
```

The flag: `mono substitutions arent that creative`

It's also worth noting here that re-opening the connection changed the encryption results for the same messages for level 2(and the remaining levels). However, the flags stay the same, so we can just send them over to regain our progress. That's also what the `passed` argument is for; once I got the flag once, I would just send the flag over for subsequent attempts.

## Level 3

Once again, I started off by sending `00`. Just like before, the encryption was a new hex string of the same length. Sending `01` and `02` also gave the same pattern as with level 2. Sending them again gave the same result, so it seemed like a mapping just like before was happening. 

However, sending `0000` showed a difference from before; the second byte returned was different from the first. It seemed to be more troublesome than level 2. At this point, I suspected 2 possibilities: the whole message is mapped to some other message of the same length, or each byte position(for example, the 1st vs the 2nd `00` in `0000`) has a different mapping table. 

The first option would be very difficult to brute-force to decrypt the encrypted flag, so I tried testing for the second scenario by sending `0100`. The second returned byte was the same as in `0000`, showing me that the likelihood of the second scenario was high. Testing a few more messages in a similar manner confirmed this theory.

Then the question becomes, how could I figure out the flag in a timely manner? One option is to simply create a table like with level 2, except for each byte position. However, this is something of a waste, because each table would only be used to decrypt a single byte of the encrypted flag. 

So instead, I just encrypted `00`, `01`, until I got the corresponding byte in the flag for each byte position. The byte that, when encrypted, matched the one in the encrypted flag, would be the original byte in the decrypted flag. To test the encryptions for byte position `x + 1`, I first put `x` `00`s and then the byte I wanted to encrypt(For example, `000001`, `000002`, etc.).

Notably, in the worst case this still would take `(# of bytes in the encrypted flag)*256` requests, and it's possible for the connection to close itself in this time. However, this isn't much of an issue because the flag itself never changes, even if the encryption does. So we can just keep track of which byte position we are on and start from there until we recover the entire flag. The following code simply assumes that this issue doesn't occur.

```python
def level3(passed):
	print("Level 3")
	if not passed:
		r.recvuntil("Level: 3, encrypted flag: ")
		ef3 = r.recvline().decode()[:-1]
		f3 = ""
		for i in range(0, len(ef3), 2):
			byte = ef3[i:i + 2]
			buff = "00" * (i // 2)
			for j in range(256):
				r.recvuntil(">>> ")
				r.sendline("1")
				r.recvuntil("message in hex:")
				r.sendline(buff + hex(j)[2:].zfill(2))
				target = r.recvline().decode()[:-1][-2:]
				if target == byte:
					f3 += hex(j)[2:].zfill(2)
					break
			print(i)
			print("flag so far: ", f3)
		assert len(f3) == len(ef3)
		print(f3)
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline(f3)
```

The flag: `creating different substitutions for each char`

## Level 4

Once again, I sent `00` first. Different from before, I got a hex string of twice the original length. Sending `0000` gave me a hex string of length 8, so it seems that the encryption does something to double the length of the original message. 

Then, I sent `01` and `02` again, with similar results. It seemed like it was a similar system to level 3, since the 2-byte blocks from `0000` were different from each other. So I thought that it was just an mapping from single bytes to 2-byte blocks instead of byte to byte like before.

However, sending `00` again revealed something troublesome; it gave me a result different from before, meaning that this encryption was non-deterministic. Even so, we are supposed to be able to decrypt the encrypted flag. Combining these two facts, I realized that the encrypted flag must be one of many possible encryptions of the original flag, using the same encryption system.

Based on this, the general approach would to be find which message the encrypted flag could be a possible encryption of. In order for this to be feasibly bruteable, I figured the encryption probably didn't map entire messages to encrypted messages, but rather encrypted byte-by-byte like previous stages. 

Additionally, after more various testing and thinking, I realized that it was likely that the system was not like in level 3 where the encryption was different per byte position, and instead a single mapping table was being used for all byte positions like in level 2. The main reasons I considered this where 1) with `256*256` possible 2-bytes, I would have to send up to `256*256*(# of 2-bytes in the encrypted flag)` requests, which would take a long time considering it's a remote connection (likely not feasible, especially with 3 levels remaining after) and 2) When encrypting longer messages like `00000000000000000000`, I noticed that occasionally the `00` bytes in different positions encrypted to the same 2-byte blocks.

With this in mind, I figured the encryption scheme was likely: Encrypt each byte to 1 of `x` 2-bytes, for each byte in the message. This scheme also requires for no two bytes to encrypt to any same 2-bytes(for example, `00` and `01` cannot both encrypt to `0e5f`), or else we would not be able to uniquely decrypt some messages. To test this, I sent long strings of `00`s and `01`s, and checked if they shared any 2-byte blocks. They didn't, confirming that my idea was likely correct.

Then, the approach would be pretty much the same as level 2: Build a table finding out which 2-byte blocks each byte encrypts to. The main problem with this is doing it the same way as in level 2 naively would be rather infeasible. For one, we don't know how many 2-byte blocks each byte individually maps to; it could be the same for all, or it could be different for all, so sending only one byte at a time doesn't seem like a good idea, since we wouldn't know when to move on to the next byte. 

Instead, I opted to send long strings of the same byte repeated, like I had done in my previous testing. Assuming my idea was correct, I could just use each individual message to collect a bunch of the mappings at a time, rather than wait in between requests. I did this a few times, and found that bytes seemed to map to 256 2-byte blocks each, which makes a lot of sense, since `256 * 256 / 256 = 256`. 

So my approach became: For each byte, send a few long messages of the byte repeated, and use it collect the possible blocks that byte maps to. Build the table this way, and then look at each 2-byte block in the encrypted flag, reverse the mapping, and get the original flag. I opted to use messages of 512 bytes, with 3 messages per byte, since that seemed to consistently find 254-256 mappings per byte, which was generally enough.

```python
def level4(passed):
	print("Level 4")
	if not passed:
		r.recvuntil("Level: 4, encrypted flag: ")
		ef4 = r.recvline().decode()[:-1]
		f4 = ""
		table = {}
		for n in range(256):
			for i in range(3):
				r.recvuntil(">>> ")
				r.sendline("1")
				r.recvuntil("message in hex:")
				r.sendline(hex(n)[2:].zfill(2) * 512)
				res = r.recvline().decode()[:-1]
				for j in range(0, len(res), 4):
					block = res[j:j + 4]
					if block not in table:
						table[block] = hex(n)[2:].zfill(2)
		for i in range(0, len(ef4), 4):
			block = ef4[i:i + 4]
			f4 += table[block]
		print(f4)
		assert len(f4) == len(ef4) // 2
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline(f4)
```

The flag: `Glad that you figured out the invariant`

## Level 5

Same idea as before, I first tried encrypting `00`. The encrypted result was a 10-byte long hex string, like so: `19b8803e8b19b5d39995`. Additionally, encrypting `00` a second time gave a different result, meaning the scheme was non-deterministic. Encrypting `0000` also gave a 10-byte hex string, which led me to think that there is some padding going on, since the encrypted flag was long(meaning it wasn't going to be that all encryptions result in a 10-byte long string). Encrypting a longer string of `00`s seemed to confirm this idea. It also led to another discovery; when encryting with a lot of `00`s, there seemed to be repetition in the encrypted result, like so: `e92583e282e92583e2abe92583e282`.

With this in mind, I then needed to figure out what the blocksize was. We can do this by just sending messages with an extra `00` at a time and checking for when the encryption result's length increases, and doing this, I found that the blocksize seemed to be 5 bytes. Additionally, the encryption result increased in increments of 5 bytes rather than 10, which was the initial size, meaning it was likely there was some sort of IV block of length 5 bytes. Based on this and the previous discovery of the patterns showing up with encrypting long `00` strings, I figured the scheme went something like this: generate an IV block of 5 bytes at the front, and for all subsequent blocks, do a byte-wise addition of the message bytes in the block to the IV block.

After a while of more testing with other messages(sending messages like `0102030405`, `aaaaaaaaaaa`, `1020304050`, and other messages of varying lengths), I found two more things; 1) Not only was there addition, but there was also subtraction sometimes; and 2) the IV block seemed to be the very last block, rather than the first.(However, the encrypted blocks were in the same order as in the message.) There happens to be a operation commonly used in cryptography that does byte-wise addition and subtraction at times: XOR. So, my idea for the scheme at this point was: Generate and IV block, and for each 5-byte block in the message(after padding), XOR that block with the IV block, and add it to the result. After all blocks are cleared, the IV block is appended to the end. This idea would also support decryption working with non-determinism, as we can always decrypt as long as we know the IV block.

```python
def level5(passed):
	print("Level 5")
	if not passed:
		r.recvuntil("Level: 5, encrypted flag: ")
		ef5 = r.recvline().decode()[:-1]
		f5 = ""
		base = ef5[-10:]
		for i in range(0, len(ef5) - 10, 10):
			block = ef5[i:i + 10]
			for j in range(0, len(block), 2):
				diff = int(base[j:j + 2], 16) ^ int(block[j:j + 2], 16)
				if diff in range(32, 128):
					f5 += hex(diff)[2:].zfill(2)
				else:
					break
		r.recvuntil(">>> ")
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline(f5)
```

Note that my code does byte-wise XORs, which gives the same result as block-wise XORs(since everything is bitwise in the end). This was due to the fact that I was caught up with the addition and subtraction idea for a while... and once I realized it could be XOR, I just modified that single line.

The flag: `Here we append the key with your shit, please dont tell anyone`

## Level 6

The first thing I noticed about this level was that it seemed to take a while for it to generate the encrypted flag. Sometimes the waiting time would be short, but other times it would be longer. Additionally, the encrypted flag was a number. Encrypting `00`, `01`, `02` gave `0`, `1`, and `8` respectively. It seems like the scheme was just to cube the message after converting it to an int. So, we could just take the cube root of the flag using sage. Or so I thought. Attempting to do so resulted in sage telling me that the encrypted flag was not a perfect cube.

When considering the time that it took to generate the encrypted flag, and the fact that the encrypted flag is different on each connection, this actually makes sense. The most likely scenario here is that the encryption does cubing modulo some large prime, where the prime generation is what took time. And with a different prime, if the original message is large enough, the encryption result will be different. Then, it's just about finding what that prime is. 

This is not difficult; we can just encrypt increasingly large messages until `result != message^3`. I increased the value of my messages by appending a `00` byte at the end(the same as multiplying the int value by 256). Find two messages that have `result != message^3`, take the differences of `message1^3 - result1` and `message2^3 - result2`, find their GCD, and factor to get the prime(since the GCD is likely to be a small multiple of the prime). Then, just used sage's `nth_root` function(have the encrypted flag as an element of `GF(p)`) to get the flag. I was a bit lazy with this, so instead I only used 1 message, and, figuring that a cube is quite small, just directly factored the difference `message^3 - result` to get the prime. The reason this(and the previous GCD method) works is because the encryption scheme is `E(x) = x^3 (mod p)`, so `x^3 - E(x) = 0 (mod p)`, meaning that the difference is a multiple of `p`, the prime in question.

```python
def level6(passed):
	print("Level 6")
	if not passed:
		r.recvuntil("Level: 6, encrypted flag: ")
		ef6= int(r.recvline().decode()[:-1])
		print(ef6)
		pay = "10"
		payint = int(pay, 16)
		r.recvuntil(">>> ")
		r.sendline("1")
		r.recvuntil("message in hex:")
		r.sendline(pay)
		res = r.recvline()[:-1].decode()
		while payint**3 == int(res):
			pay += "00"
			r.recvuntil(">>> ")
			r.sendline("1")
			r.recvuntil("message in hex:")
			r.sendline(pay)
			res = r.recvline()[:-1].decode()
			payint = int(pay, 16)
		mod = payint**3 - int(res)
		print(mod)
		# factor mod to get the prime(assume it was a prime modulo), then use sage nth_root to calculate root
		f6 = input("gimme the flag in hex> ")
		r.recvuntil(">>> ")
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline(f6)
```

The flag: `Cube modulo prime, any guesses what might be coming next?`

## Level 7

Same as the previous level, there is a delay before we receive the encrypted flag, and the encrypted flag differs each time. Seems like there is prime generation going on in the background again. Once again, I tried encrypting `00`, `01`, and `02` again. The former resulted in `0` and `1` again like before, but the latter resulted in a rather large number. It seems like it's still a power though, so we can take the log base 2 of the encryption of 2 to get that power. Trying this on multiple connections showed that this power varied, seemingly between around 60 and 150. In any case, it's not huge, so sage's `nth_root` can handle it fine.

Once again, the task is then to find the prime which is the modulo. I tried using the same semi-lazy approach as before(in retrospect, it definitely would have been simpler to just use the GCD method), which failed since multiplying a number by 256 and raising that to a high power would, as expected, result in a huge number, so the difference `message^3 - result` became very difficult to factor. I opted to just increase my messages's values by a small value at a time(multiplying by 1.1, converting to int, then to hexstring) from a base value of 256 so that the encryption result would still be small. It's not pretty, but it worked. The rest is the same as the previous level.

```python
def level7(passed):
	print("Level 7")
	if not passed:
		r.recvuntil("Level: 7, encrypted flag: ")
		ef7 = int(r.recvline().decode()[:-1])
		print(ef7)
		r.recvuntil(">>> ")
		r.sendline("1")
		r.recvuntil("message in hex:")
		r.sendline("02")
		power = int(log(int(r.recvline()[:-1].decode()), 2))
		print(power)
		pay = 256
		r.recvuntil(">>> ")
		r.sendline("1")
		r.recvuntil("message in hex:")
		r.sendline("0" + hex(pay)[2:])
		res = r.recvline()[:-1].decode()
		while pay**power == int(res):
			pay = int(1.1 * pay)
			r.recvuntil(">>> ")
			r.sendline("1")
			r.recvuntil("message in hex:")
			payload = hex(pay)[2:]
			if len(payload) % 2:
				r.sendline("0" + payload)
			else:
				r.sendline(payload)
			res = r.recvline()[:-1].decode()
		mod = pay**power - int(res)
		print(mod)
		# factor mod to get the prime(assume it was a prime modulo), then use sage nth_root to calculate root
		f7 = input("gimme the flag in hex> ")
		r.recvuntil(">>> ")
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline(f7)
```

It turns out the flag for this level is just the flag: `zh3r0{17_a1n7_much_bu7_1_4m_s0m37h1ng_0f_4_cryp74n4ly57_my53lf}`

Here is the full solve script(change the boolean values at the end to have the script re-do the solve for a given level):

```python
from pwn import *
from math import log

host, port = "crypto.zh3r0.cf", 1111

r = remote(host, port)
r.send("")
# Level 0
def level0(passed):
	print("Level 0")
	if not passed:
		r.recvuntil("Level: 1, encrypted flag: ")
		ef1 = r.recvline().decode()[:-1]
		r.recvuntil(">>> ")
		f1 = ""
		for i in range(0, len(ef1), 2):
			byte = int(ef1[i:i + 2], 16)
			byte -= 1
			f1 += hex(byte)[2:]
		print(f1)
		assert len(f1) == len(ef1)
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline(f1)
	else:
		r.recvuntil(">>> ")
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline("68656c6c6f20776f726c6421204c6574732067657420676f696e67")


# Level 1
def level1(passed):
	print("Level 1")
	if not passed:
		r.recvuntil("Level: 1, encrypted flag: ")
		ef1 = r.recvline().decode()[:-1]
		r.recvuntil(">>> ")
		f1 = hex(int(ef1))[2:]
		print(f1)
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline(f1)
	else:
		r.recvuntil(">>> ")
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline("4e6f7468696e672066616e63792c206a757374207374616e646172642062797465735f746f5f696e74")

# Level 2
def level2(passed):
	print("Level 2")
	if not passed:
		r.recvuntil("Level: 2, encrypted flag: ")
		ef2 = r.recvline().decode()[:-1]
		table = [""]*256
		for i in range(256):
			r.recvuntil(">>> ")
			r.sendline("1")
			r.recvuntil("message in hex:")
			r.sendline(hex(i)[2:].zfill(2))
			key = int(r.recvline().decode()[:-1], 16)
			table[key] = hex(i)[2:].zfill(2)
			print(i)
		f2 = ""
		for i in range(0, len(ef2), 2):
			f2 += table[int(ef2[i:i + 2], 16)]
		assert len(f2) == len(ef2)
		print(f2)
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline(f2)
	else:
		r.recvuntil(">>> ")
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline("6d6f6e6f20737562737469747574696f6e73206172656e742074686174206372656174697665")

# Level 3
def level3(passed):
	print("Level 3")
	if not passed:
		r.recvuntil("Level: 3, encrypted flag: ")
		ef3 = r.recvline().decode()[:-1]
		f3 = ""
		for i in range(0, len(ef3), 2):
			byte = ef3[i:i + 2]
			buff = "00" * (i // 2)
			for j in range(256):
				r.recvuntil(">>> ")
				r.sendline("1")
				r.recvuntil("message in hex:")
				r.sendline(buff + hex(j)[2:].zfill(2))
				target = r.recvline().decode()[:-1][-2:]
				if target == byte:
					f3 += hex(j)[2:].zfill(2)
					break
			print(i)
			print("flag so far: ", f3)
		assert len(f3) == len(ef3)
		print(f3)
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline(f3)
	else:
		r.recvuntil(">>> ")
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline("6372656174696e6720646966666572656e7420737562737469747574696f6e7320666f7220656163682063686172")

# Level 4
def level4(passed):
	print("Level 4")
	if not passed:
		r.recvuntil("Level: 4, encrypted flag: ")
		ef4 = r.recvline().decode()[:-1]
		f4 = ""
		table = {}
		for n in range(256):
			for i in range(3):
				r.recvuntil(">>> ")
				r.sendline("1")
				r.recvuntil("message in hex:")
				r.sendline(hex(n)[2:].zfill(2) * 512)
				res = r.recvline().decode()[:-1]
				for j in range(0, len(res), 4):
					block = res[j:j + 4]
					if block not in table:
						table[block] = hex(n)[2:].zfill(2)
		for i in range(0, len(ef4), 4):
			block = ef4[i:i + 4]
			f4 += table[block]
		print(f4)
		assert len(f4) == len(ef4) // 2
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline(f4)
	else:
		r.recvuntil(">>> ")
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline("476c6164207468617420796f752066696775726564206f75742074686520696e76617269616e74")

# Level 5
def level5(passed):
	print("Level 5")
	if not passed:
		r.recvuntil("Level: 5, encrypted flag: ")
		ef5 = r.recvline().decode()[:-1]
		f5 = ""
		base = ef5[-10:]
		for i in range(0, len(ef5) - 10, 10):
			block = ef5[i:i + 10]
			for j in range(0, len(block), 2):
				diff = int(base[j:j + 2], 16) ^ int(block[j:j + 2], 16)
				if diff in range(32, 128):
					f5 += hex(diff)[2:].zfill(2)
				else:
					break
		r.recvuntil(">>> ")
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline(f5)
	else:
		r.recvuntil(">>> ")
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline("4865726520776520617070656e6420746865206b6579207769746820796f757220736869742c20706c6561736520646f6e742074656c6c20616e796f6e65")

# Level 6
def level6(passed):
	print("Level 6")
	if not passed:
		r.recvuntil("Level: 6, encrypted flag: ")
		ef6= int(r.recvline().decode()[:-1])
		print(ef6)
		pay = "10"
		payint = int(pay, 16)
		r.recvuntil(">>> ")
		r.sendline("1")
		r.recvuntil("message in hex:")
		r.sendline(pay)
		res = r.recvline()[:-1].decode()
		while payint**3 == int(res):
			pay += "00"
			r.recvuntil(">>> ")
			r.sendline("1")
			r.recvuntil("message in hex:")
			r.sendline(pay)
			res = r.recvline()[:-1].decode()
			payint = int(pay, 16)
		mod = payint**3 - int(res)
		print(mod)
		# factor mod to get the prime(assume it was a prime modulo), then use sage nth_root to calculate root
		f6 = input("gimme the flag in hex> ")
		r.recvuntil(">>> ")
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline(f6)
	else:
		r.recvuntil(">>> ")
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline("43756265206d6f64756c6f207072696d652c20616e7920677565737365732077686174206d6967687420626520636f6d696e67206e6578743f")

# Level 7
def level7(passed):
	print("Level 7")
	if not passed:
		r.recvuntil("Level: 7, encrypted flag: ")
		ef7 = int(r.recvline().decode()[:-1])
		print(ef7)
		r.recvuntil(">>> ")
		r.sendline("1")
		r.recvuntil("message in hex:")
		r.sendline("02")
		power = int(log(int(r.recvline()[:-1].decode()), 2))
		print(power)
		pay = 256
		r.recvuntil(">>> ")
		r.sendline("1")
		r.recvuntil("message in hex:")
		r.sendline("0" + hex(pay)[2:])
		res = r.recvline()[:-1].decode()
		while pay**power == int(res):
			pay = int(1.1 * pay)
			r.recvuntil(">>> ")
			r.sendline("1")
			r.recvuntil("message in hex:")
			payload = hex(pay)[2:]
			if len(payload) % 2:
				r.sendline("0" + payload)
			else:
				r.sendline(payload)
			res = r.recvline()[:-1].decode()
		mod = pay**power - int(res)
		print(mod)
		# factor mod to get the prime(assume it was a prime modulo), then use sage nth_root to calculate root
		f7 = input("gimme the flag in hex> ")
		r.recvuntil(">>> ")
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline(f7) # got the flag
	else:
		r.recvuntil(">>> ")
		r.sendline("2")
		r.recvuntil("flag in hex:")
		r.sendline("7a683372307b31375f61316e375f6d7563685f6275375f315f346d5f73306d333768316e675f30665f345f6372797037346e346c7935375f6d7935336c667d")

level0(True)
level1(True)
level2(True)
level3(True)
level4(True)
level5(True)
level6(True)
level7(True)
r.interactive()
```

Also, I ran sage separate from this program, so that's something to keep in mind.

Although there was a good amount of bruting and the challenge concept is somewhat centered around guessing, I'd say the challenge wasn't bad for people looking to solidify some basic practices in cryptanalysis. My thanks to Zh3r0CTF.