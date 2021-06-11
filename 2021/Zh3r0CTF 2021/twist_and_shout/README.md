# Zh3r0CTF 2021 - twist\_and\_shout
* **Category:** Crypto
* **Solves:** 29

# Challenge

> Wise men once said, "Well, shake it up, baby, now Twist and shout come on and work it on out" I obliged, not the flag is as twisted as my sense of humour

> nc crypto.zh3r0.cf 5555

## Source

```python
from secret import flag
import os
import random

state_len = 624*4
right_pad = random.randint(0,state_len-len(flag))
left_pad = state_len-len(flag)-right_pad
state_bytes = os.urandom(left_pad)+flag+os.urandom(right_pad)
state = tuple( int.from_bytes(state_bytes[i:i+4],'big') for i in range(0,state_len,4) )
random.setstate((3,state+(624,),None))
outputs = [random.getrandbits(32) for i in range(624)]
print(*outputs,sep='\n')
```

# Solution

The challenge is about finding the original state of the random number generator, which will contain the flag. Python's `random` module uses a MT19337 Mersenne Twister. Given 624 outputs from the generator, we can find the state of the RNG at the start of the generation. The challenge comes from the fact that before any generation, the state of the RNG is "twisted", modifying the state, meaning that the state that we recover will be the state post-twist, not pre-twist. The goal seems to be to untwist the recovered state so that we can get the flag.

The final script used to solve the challenge was written by my teammate willwam845, and this writeup is mainly to explain the ideas involved in tackling this challenge.

## Recovering the RNG's state

With a bit of searching, it's not hard to find that you can reverse a Mersenne twister's state from 624 outputs and its index, which is 0 in this case, as the generation happens right after a twist. This is because when the index hits 624(which it is initialized to), the RNG first performs a twist, then sets its index to 0 before outputting anything.

When a Mersenne twister outputs values(specifically 32 bit outputs), it takes a look at the value at the current index in its state, then tempers it. The result of the temper is the output of the RNG. This means that if we can untemper the outputs, we can trivially recover the state of the RNG post-twist. This is what willwam ended up doing; I wasn't aware of how to reverse the temper function, so I simply used the same Mersenne twister solver that we used in the Real Mersenne challenge. A link to the writeup for that is [here](https://cor.team/posts/Zh3r0%20CTF%20V2%20-%20Real%20Mersenne), by Quintec. It showcases the usefulness of the solver more clearly. When comparing the two solves scripts at the end, just keep in mind that my use of the solver effectively has the same result as untempering all 624 values given by the server.

The source for the solver(it is not ours and is open source): [link](https://github.com/icemonster/symbolic_mersenne_cracker/)

## Undoing the twist

Here is the main substance of the challenge. We want to figure out how to untwist the recovered state of the RNG so that we can get the state with the flag. First, we looked around for the source of the twist function. Here is the one I ended up using:

```python
(w, n, m, r) = (32, 624, 397, 31)
a = 0x9908B0DF
(u, d) = (11, 0xFFFFFFFF)
(s, b) = (7, 0x9D2C5680)
(t, c) = (15, 0xEFC60000)
l = 18
f = 1812433253
lower_mask = 0x7FFFFFFF
upper_mask = 0x80000000

def twist(MT):
    for i in range(0, n):
        x = (MT[i] & upper_mask) + (MT[(i+1) % n] & lower_mask)
        xA = x >> 1
        if (x % 2) != 0:
            xA = xA ^ a
        MT[i] = MT[(i + m) % n] ^ xA
```

The original code is taken from [here](https://github.com/yinengy/Mersenne-Twister-in-Python/blob/master/MT19937.py). I just made some changes to the parameters as they are off from the Mersenne twister python's random module uses. Other twist functions we found were pretty much the same. (I later noticed pretty much the same twist code is also in the aforementioned mersenne cracker source.)

So, what the twist function does is for each value in the state, it takes its current value's top bit(`MT[i] & upper_mask`) and the bottom 31 bits of the next value in the state(`MT[(i+1) % n] & lower_mask`). It then cuts off the last bit of this (x >> 1), and based on that last bit, XORs the result with the parameter `a`. Finally, the value is replaced with all this XORed with the value in the state at an index `m` away.

Now, let's try reversing. We want to go backwards starting from the last value modified, being the one at index 623, and undo the XOR operations. Here is some psuedocode for the process(for reversing a single state at index i):

```
xA = MT[(i + m) % n] ^ MT[i] // undo MT[i] = MT[(i + m) % n] ^ xA
if pretwist_MT[(i+1) % n] was odd:
	xA ^= a // undo xA = xA ^ a
x = (xA << 1) + (last bit of pretwist_MT[(i+1) % n])
```

A few glaring issues immediately become apparent:

1. We don't know `MT[(i + m) % n]` for all values of `i`. To be precise, consider `i=0`. Then no twisting has occurred, and `MT[(i + m) % n]` is from the pre-twist state. In contrast, for index 623, it is the last value being twisted, so `MT[(i + m) % n]` uses an already twisted value, which we do have access to(from the recovered state). 

2. We don't know `pretwist_MT[(i+1) % n]`, so we don't know whether or not to do `xA ^= a` for sure. In exchange, we can assume the last bit, and check 2 possibilities each time. However, if we have to do this for every state, this becomes unfeasible, since with 624 states we'd have to check `2^624` possibilities to get the full state correct.

3. Based on our assumption for `x`, we actually get more information about `pretwist_MT[(i + 1) % n]` rather than `pretwist_MT[i]`.

With a bit of thinking, we can actually get around most of these issues, to some degree. For the first issue, we can simply check values of `i` for which `MT[(i + m) % n]` is an already twisted value. With `m = 397`, this would be from `i=227` to `i=623`. We don't have to necessarily worry about the other values, as we only have the untwist the parts of the state that include the flag. In other words, if we can succesfully untwist the aforementioned portion and the flag is in it, we're still good. Naturally, we can keep reconnecting until we get a result which has the flag in this portion.

For the second issue, we can actually "verify" if a single untwisted value is correct because we know the flag is readable, while the other values in the state are randomly generated and will not necessarily be readable(in fact, it is unlikely for them all the bytes in a 32-bit value to be readable this way). Being able to verify state values independently also drastically reduces the possibilities we have to check from `2^(624 - 227)` to `2*(624 - 277)`, which is easily feasible because we do that part locally. This is the idea that willwam came up with to complete the final stretch of the challenge.

For the third issue, since we get 31 bits of information about `pretwist_MT[(i + 1) % n]` and only one bit about `pretwist_MT[i]`, we can simply use each `x` from examining index `i` to determine the bottom 31 bits of `pretwist_MT[(i + 1) % n]`. Using this, we still don't know the top bit of `pretwist_MT[(i + 1) % n]`. However, just like before, we can simply test the two possibilities for it, increasing the possibilites to `4*(624 - 277)`. Naturally, this is still very feasible. 

One last thing to note: we don't actually need to check index 623 anymore, since `MT[(i + 1) % n]` will be `MT[0]`, which is already twisted. So, it won't tell us anything new.

Here is the script that I used:

```python
from Crypto.Util.number import long_to_bytes
from pwn import *
from z3 import *
from random import Random
from itertools import count
import time
import logging

logging.basicConfig(format='STT> %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

SYMBOLIC_COUNTER = count()

class Untwister:
    def __init__(self):
        name = next(SYMBOLIC_COUNTER)
        self.MT = [BitVec(f'MT_{i}_{name}', 32) for i in range(624)]
        self.index = 0
        self.solver = Solver()

    #This particular method was adapted from https://www.schutzwerk.com/en/43/posts/attacking_a_random_number_generator/
    def symbolic_untamper(self, solver, y):
        name = next(SYMBOLIC_COUNTER)

        y1 = BitVec(f'y1_{name}', 32)
        y2 = BitVec(f'y2_{name}' , 32)
        y3 = BitVec(f'y3_{name}', 32)
        y4 = BitVec(f'y4_{name}', 32)

        equations = [
            y2 == y1 ^ (LShR(y1, 11)),
            y3 == y2 ^ ((y2 << 7) & 0x9D2C5680),
            y4 == y3 ^ ((y3 << 15) & 0xEFC60000),
            y == y4 ^ (LShR(y4, 18))
        ]

        solver.add(equations)
        return y1

    def symbolic_twist(self, MT, n=624, upper_mask=0x80000000, lower_mask=0x7FFFFFFF, a=0x9908B0DF, m=397):
        '''
            This method models MT19937 function as a Z3 program
        '''
        MT = [i for i in MT] #Just a shallow copy of the state

        for i in range(n):
            x = (MT[i] & upper_mask) + (MT[(i+1) % n] & lower_mask)
            xA = LShR(x, 1)
            xB = If(x & 1 == 0, xA, xA ^ a) #Possible Z3 optimization here by declaring auxiliary symbolic variables
            MT[i] = MT[(i + m) % n] ^ xB

        return MT

    def get_symbolic(self, guess):
        name = next(SYMBOLIC_COUNTER)
        ERROR = 'Must pass a string like "?1100???1001000??0?100?10??10010" where ? represents an unknown bit'

        assert type(guess) == str, ERROR
        assert all(map(lambda x: x in '01?', guess)), ERROR
        assert len(guess) <= 32, "One 32-bit number at a time please"
        guess = guess.zfill(32)

        self.symbolic_guess = BitVec(f'symbolic_guess_{name}', 32)
        guess = guess[::-1]

        for i, bit in enumerate(guess):
            if bit != '?':
                self.solver.add(Extract(i, i, self.symbolic_guess) == bit)

        return self.symbolic_guess


    def submit(self, guess):
        '''
            You need 624 numbers to completely clone the state.
                You can input less than that though and this will give you the best guess for the state
        '''
        if self.index >= 624:
            name = next(SYMBOLIC_COUNTER)
            next_mt = self.symbolic_twist(self.MT)
            self.MT = [BitVec(f'MT_{i}_{name}', 32) for i in range(624)]
            for i in range(624):
                self.solver.add(self.MT[i] == next_mt[i])
            self.index = 0

        symbolic_guess = self.get_symbolic(guess)
        symbolic_guess = self.symbolic_untamper(self.solver, symbolic_guess)
        self.solver.add(self.MT[self.index] == symbolic_guess)
        self.index += 1

    def get_random(self):
        '''
            This will give you a random.Random() instance with the cloned state.
        '''
        logger.debug('Solving...')
        start = time.time()
        self.solver.check()
        model = self.solver.model()
        end = time.time()
        logger.debug(f'Solved! (in {round(end-start,3)}s)')

        #Compute best guess for state
        state = list(map(lambda x: model[x].as_long(), self.MT))
        result_state = (3, tuple(state+[self.index]), None)
        r = Random()
        r.setstate(result_state)
        return r

# parameters for python's random mersenne twister. Not all are used.
(w, n, m, r) = (32, 624, 397, 31)
a = 0x9908B0DF
(u, d) = (11, 0xFFFFFFFF)
(s, b) = (7, 0x9D2C5680)
(t, c) = (15, 0xEFC60000)
l = 18
f = 1812433253
lower_mask = 0x7FFFFFFF
upper_mask = 0x80000000
host, port = "crypto.zh3r0.cf", 5555

def get(MT):
	valids = ['']*624
	for i in range(228, 624):
		valids[i] = [] # for storing the bytes if they are all printable
		xA = MT[i-1] ^ MT[(i-1 + m) % 624]
		# possibilities..
		xA1, xA2 = xA, xA ^ a # 2 possibilities based on last bit of original x
		x1, x2 = xA1 << 1, (xA2 << 1) + 1
		p11, p12 = (x1 & lower_mask), (x1 & lower_mask) | upper_mask # 1st bit 0, 1
		p21, p22 = (x2 & lower_mask), (x2 & lower_mask) | upper_mask # 1st bit 0, 1
		for p in (p11, p12, p21, p22):
			if all([b in range(32, 128) for b in long_to_bytes(p)]): # are all the bytes in the untwisted value printable?
				valids[i].append(long_to_bytes(p).decode())
	return ''.join(sum(list(filter(lambda x: x, valids)), []))

# recover the state
ut = Untwister()
r = remote(host, port)
for i in range(624):
	ut.submit(bin(int(r.recvline().decode().strip('\n')))[2:].zfill(32))
prophet = ut.get_random()
state = list(prophet.getstate()[1][:-1])

# untwist and get the flag
print(get(state))
```

And for reference, the script that willwam used and got us the solve(I added some comments for clarity):
```python
from Crypto.Util.number import long_to_bytes
def untempering(y):
    y ^= (y >> 18)
    y ^= (y << 15) & 0xefc60000
    y ^= ((y <<  7) & 0x9d2c5680) ^ ((y << 14) & 0x94284000) ^ ((y << 21) & 0x14200000) ^ ((y << 28) & 0x10000000)
    y ^= (y >> 11) ^ (y >> 22)
    return y

def get_seeds(m0, m227):
    seeds = []
    # 2 possibilities based on last bit of assumed x. a = 0x9908b0df
    y_even = (m227 ^ m0) << 1
    y_odd = (((m227 ^ m0 ^ 0x9908b0df) << 1) & 0xffffffff) | 1
    for y in (y_even, y_odd):
        for oldm227_upperbit in (0, 0x80000000):
            for oldm228_upperbit in (0, 0x80000000):
                n = (y ^ oldm227_upperbit ^ oldm228_upperbit) & 0xffffffff
                seeds.append(n)
    return list(set(seeds))

data = [untempering(int(x)) for x in open("af.txt").read().split("\n")] # recovering the state post-twist
o = b""
for i in range(397):
  seeds = get_seeds(data[i],data[(i+227)%624])
  for s in seeds:
    if len(str(long_to_bytes(s))) < 9: # checking if the untwisted value is valid
      o += (long_to_bytes(s))        
      
print(o)
```
(Some code is taken from an old writeup [here](https://ctftime.org/writeup/7331).)
It seems that the `len(str(long_to_bytes(s))) < 9` condition was another way to check the validity of untwisted value.

The flag: `zh3r0{7h3_fu7ur3_m1gh7_b3_c4p71v471ng_bu7_n0w_y0u_kn0w_h0w_t0_l00k_a7_7h3_p457}`

Thanks to Zh3r0 CTF for the challenge!