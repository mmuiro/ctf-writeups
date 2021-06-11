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

def get_float(a, b):
    """
    Rebuild of random_rancom from randommodule.c
    uses two outsputs!
    """
    a = a >> 5
    b = b >> 6
    return (a*67108864.0+b)*(1.0/9007199254740992.0)

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


(w, n, m, r) = (32, 624, 397, 31)
a = 0x9908B0DF
(u, d) = (11, 0xFFFFFFFF)
(s, b) = (7, 0x9D2C5680)
(t, c) = (15, 0xEFC60000)
l = 18
f = 1812433253
lower_mask = 0x7FFFFFFF #int(bin(1 << r), 2) - 0b1
upper_mask = 0x80000000 #int(str(-~lower_mask)[-w:])
host, port = "crypto.zh3r0.cf", 5555

def get(MT):
	valids = ['']*624
	for i in range(228, 624):
		valids[i] = []
		xA = MT[i-1] ^ MT[(i-1 + m) % 624]
		# possibilities..
		xA1, xA2 = xA, xA ^ a
		x1, x2 = xA1 << 1, (xA2 << 1) + 1
		p11, p12 = (x1 & lower_mask), (x1 & lower_mask) | upper_mask # 1st bit 0, 1
		p21, p22 = (x2 & lower_mask), (x2 & lower_mask) | upper_mask # 1st bit 0, 1
		for p in (p11, p12, p21, p22):
			if all([b in range(32, 128) for b in long_to_bytes(p)]):
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