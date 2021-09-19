# CSAW CTF Quals 2021 - Bits

* **Category:** Crypto
* **Solves:** 24
* **Date:** Sep 18 2021

Last week, I participated in CSAW CTF Quals 2021 with Crusaders of Rust. We got 3rd overall and managed to place for finals! Here's a writeup on the crypto challenge I managed to solve (I slept while my teammate solved the other 4).

## Challenge

> I wrote this oracle in rust so that it can't sue companies over java stuff.
>
> Author: CryptoHack (`Robin_Jadoul` and `jack`)
>
> `nc crypto.chal.csaw.io 5010`

## Solution

Let's take a look at the provided source in `main.rs`.
```Rust
use std::io::BufRead;
use getrandom::getrandom;
use rug::{
    rand::{RandGen,RandState},
    Integer
};
use sha2::{Sha256,Digest};
use aes::{Aes256,Aes256Ctr,NewBlockCipher,cipher::{FromBlockCipher,StreamCipher}};
use generic_array::GenericArray;

// Secret sauce
// N = p*q; p ≡ q ≡ 3 (mod 4); p, q prime
use hardcore::{dlog, N, G, ORDER, FLAG};

struct SystemRandom;
impl RandGen for SystemRandom {
    fn gen(&mut self) -> u32 {
        let mut buf: [u8; 4] = [0; 4];
        let _ = getrandom(&mut buf).unwrap();
        ((buf[0] as u32) << 24) | ((buf[1] as u32) << 16) | ((buf[2] as u32) << 8) | (buf[3] as u32)
    }
}

fn encrypt_flag(shared: Integer) {
    let mut hasher = Sha256::new();
    hasher.update(shared.to_string());
    let key = hasher.finalize();
    let mut cipher = Aes256Ctr::from_block_cipher(
        Aes256::new_from_slice(&key.as_slice()).unwrap(),
        &GenericArray::clone_from_slice(&[0; 16])
        );
    let mut flag = FLAG.clone();
    cipher.apply_keystream(&mut flag);
    println!("FLAG = {}", flag.iter().map(|c| format!("{:02x}", c)).collect::<String>());
}

fn main() {
    println!("+++++++++++++++++++++++++++++++++++++++++++++++\n\
              + I hear there's a mythical oracle at Delphi. +\n\
              +++++++++++++++++++++++++++++++++++++++++++++++\n");
    let mut sysrng = SystemRandom;
    let mut rnd = RandState::new_custom(&mut sysrng);
    let d = Integer::from(&*ORDER).random_below(&mut rnd);
    let publ = Integer::from(&*G).pow_mod(&d, &*N).unwrap();
    let nbits = ORDER.significant_bits();
    let alice = Integer::from(&*G).pow_mod(&Integer::from(&*ORDER).random_below(&mut rnd), &*N).unwrap();
    println!("N = {}\nG = {}\npubl = {}\nalice = {}\nnbits = {}",
        *N,
        *G,
        publ,
        alice,
        nbits);
    encrypt_flag(alice.pow_mod(&d, &N).unwrap());
    for line in std::io::stdin().lock().lines() {
        let input = line.unwrap().parse::<Integer>().unwrap();
        match dlog(input.clone()) {
            None => println!("-1"),
            Some(x) => {
                assert!(G.clone().pow_mod(&x, &*N).unwrap() == input % &*N);
                assert!(x < *ORDER);
                assert!(x >= 0);
                println!("{}", x.get_bit(nbits - 123) as i32)
            }
        }
    }
}
```
It took me a bit to refresh on Rust, but here's a summary of what it does:
1. Imports parameters `N, G, ORDER` with a discrete log backdoor function `dlog`
2. Chooses a random integer `d < ORDER`, and calculates `publ = G^d mod N`
3. Calculates `alice = G^a mod N`, where `a` is another random integer
4. Publishes `N, G, publ, alice,` and `nbits` = # of bits of order
5. Encrypts the flag using `alice^d = G^(a*d) mod N` as the key of an AES-CTR cipher
6. Takes user input and solves the discrete log for each input `inp` such that `inp = G^x mod N`, and prints the `nbit - 123`th bit of `x` if `x` exists (there is not always a solution for every `x`). This uses the backdoor discrete log function.

It's a classic Diffie Hellman exchange with some strange bit oracle. While the parameters `N, G` are constant across all connections (and thus the dlog results will be as well), `alice, publ` differ each time. Our goal is to use the oracle in some way to either reveal all the bits of `a` or `d` (thereby letting us calculate the shared secret by simply taking either `alice^d` or `publ^a`), or gain access to the backdoor that the server is using. We ended up using the latter approach.

Let's try to get a sense of how the backdoor might work. The thing that stands out here is that the exponentiation is done `mod N`, which is a product of two large primes. So, there's a good chance we can just solve the discrete log for `publ` or `alice` over mods `p, q` and then use the Chinese Remainder Theorem (CRT) to solve it `mod N`. Then, we'll assume it's easy to solve the discrete log over those two primes, probably with `p-1, q-1` being very smooth. Then, one approach to get this backdoor is to factor `N`.

To factor `N`, we will be making use of the oracle. While the reason might not seem clear at first, it becomes clearer once we consider what the value of `ORDER` likely is. First of all, we see that the `d, a` generation are done as values less than `ORDER`, and `x`, the result of the discrete log of a user input, is also less than `ORDER`. Based on this and knowledge of terminology, we can reasonably assume `ORDER` is the value such that `G^ORDER = 1 mod N`.

Why does this matter to us? Well, since `N = p*q`, it's also true that for any `a` coprimes to `N`, `a^((p-1)*(q-1)) = a^phi(N) = 1 mod N`, stated in [Euler's Theorem](https://en.wikipedia.org/wiki/Euler%27s_theorem). It's a consequence of Fermat's Little Theorem applied to primes `p, q` and then using CRT to get a solution mod `N`. Since `G` is found to be very small at `2`, `ORDER` is likely either `phi(N)` or a large factor of it. And if we can recover `ORDER` and use it to recover `phi(N)`, then we can find the roots of the polynomial `f(x) = x^2 -(N - phi + 1)*x + N = x^2 -(p + q)*x + N = (x - p)*(x - q)` to factor `N` and use the supposed backdoor to find `d` or `a` from `alice` or `publ`, respectively.

Before discussing which how we can try and get `ORDER`, there's something important to note about this oracle which guided my thought process. It's that we can choose input so that we actually know the value of `x = dlog(input) mod N`. If we send `G^y mod N` as our input, we will naturally get `x = y` back. To be more precise though, it's going to be `x = y mod ORDER`, due to both the given restrictions on `x` and just how modular exponentiation works.

How do we recover `ORDER` using the oracle? There's a few ways, but the method that came to mind for me was an idea that was fresh from a recent homework assignment. The idea came from how a [successive-approximation ADC (SAR ADC)](https://en.wikipedia.org/wiki/Successive-approximation_ADC) works. The idea is pretty simple - for every bit in the value we want to measure, starting from the most significant bit, we suppose it is 1, then send it over to some oracle-like thing (in the SAR ADC case, the comparator). If the oracle responds with 0, then we know our current total value (in bits, 100000....000) is too large, so we know the first bit was not 1. Otherwise, we know the actual value is larger than our current value, so we keep the current bit as 1. The process is repeated for the following bits. Basically, at each step, we can determine the bit based on whether the result "overflows" (is larger than the value) or not. After going through all the bits, we should have `ORDER`.

How can we combine this with what we know to get `ORDER`? Well, notice that if `y < ORDER`, then `x = y mod ORDER` would have `x = y`, and if `y >= ORDER`, then `x = y` will no longer be true. So we can send `inp = G^y` using the SAR ADC-style binary search approach, starting with `y = 2^1006`. Then, if we can use the single-bit information the oracle gives us to somehow determine if `x = y` or not, we can get `ORDER`!

The question, then, is whether or not the server's oracle will actually help us with this. The server gives us the `nbits - 123 = 883`rd (`nbits` is 1006) of `x`, so we'll have to use this to figure out whether or not `y >= ORDER` or not. To determine if this works, let's start with the obvious. If `y < ORDER`, then `x = y`, and the 883rd bit of `x` will be the `883rd` bit of `y`. So, if the oracle returns the same bit as expected, assuming it would otherwise return the opposite bit, we can deduce if there was an overflow by adding the current bit. Looks like we have an a good idea for an approach - the question is, will it work? We need to consider what happens to the 883rd bit if there is an overflow.

To figure this out, I went and did some testing. Here's a brief look into my results. Consider if you have `y = 0b10000000000` and you are trying to binary search on `p = 0b01000010001`. Let's first consider if we are using bit 3 from the right (0 indexed) as the oracle. At this step, since `x = y mod p = 0b00111101111`. Maybe you notice something here: let's then try taking `x XOR p = 0b01111111110`. This is pretty suspicious - nearly all the bits are 1. Why is this?

Well, let's consider how we can rewrite `y mod p`. If `p < y < 2p`, then this is just `x = y - p`. In this case, `y = 2^10 = 0b1111111111 + 1`. Then we can rewrite `y - p` as `0b1111111111 - 0b1000010001 + 1 = flipbits(p) + 1`, where `flipbits(p)` is just `p` with all of its bits flipped, since being subtracted from a full block of `1`s of bitlength greater than or equal to your own bitlength is the same as XORing by that block of `1`s. Then, since the last bit of `p` is `1`, `x XOR p = 0b1111111110`. The case where `p` is even is a bit more troublesome, as it means the last series of bits of `1`s after the last bit in `x` are all flipped, resulting in a less clean result, but nonetheless still nice. For example, with `p = 0b1000010000`, we get `x = 0b0111110000`, `x XOR p = 0b1111100000`. The length of the `0`s series at the end of `x` depends on the number of consecutive `0`s at the end of `p`. We can safely assume that there won't be that many `0`s at the end of `p` in most cases (particularly, when we apply the ideas here to find `ORDER`), as that's pretty uncommon.

Now, let's generalize this a bit more. Assume we've found the top `t` bits of `p` in this process and we're currently looking at the next bit, such that `y = x*2^t + 2^(t-1), p = x*2^t + v`. Then, `y - p = x*2^t + 2^(t-1) - x*2^t - v = 2^(t-1) - v`. We're also under the assumption that this is the case where `y > p`, so `v < 2^(t-1)`. Then, we're just in the same situation as the previous example, except only applying to the bottom `t-1` bits. So we should have that `x XOR p` is a long series of `1`s in binary, with maybe a few `0`s at the end.

Why does this matter to us? Well, if `x XOR p` is mostly 1s, then `x ~ flipbits(p)`, and so the bit returned by the oracle should be the bit of `p` that we are looking at, flipped, if `y > p`. Applying this with `p = ORDER`, if we assume the 883rd bit of `ORDER` is `0`, if the current bit we add causes an "overflow", the oracle will return `1` - otherwise, it will return the 883rd bit of `y`. When we are searching for the bits above the 883rd bit, we will have the 883rd bit of `y` set to `0`, so it will return `0` when there is no overflow. If the 883rd bit of `ORDER` is `1` instead, well... we can get into that later. For simplicity's sake, let's stick with assuming it's `0`.

Now, under this assumption, we have a way to find the top `123` bits of `ORDER`. But we still need a way to get the bottom 883. Let's consider how we can do this, starting from the 883rd bit.

If we continue to apply our approach, at the 883rd bit, when we send over our `y`, assuming `ORDER` has the 883rd bit as `0`, `y > ORDER` will be true. However, the oracle will return `0` here instead of `1`, as the XOR only applies to the bottom 882 bits. To be more specific, `2^883 - v <  2^883`, so `x >> 883 = 0`. So it seems like a miscalculation will happen here. But does it really matter? If we assume the 883rd bit is `0`, then we techinically already know it. All that matters, then, is how it affects future calculations.

After the binary search mistakenly takes the 883rd bit incorrectly, how are the future bits determined by the search affected? It turns out, they more are less aren't. Why is this? First of all, we can tell that there will always be an 'overflow' for every `y` we send. So for every query after that point, `x = y - ORDER`. Now, let's assume (like we do in an induction proof) that for some `k` bits beyond the 883rd, we get all of them correct. We'll show that we'll get the `k+1`th bit correct. When considering the `k+1`th bit, two cases can happen: it's either `1`, or `0`. Let's dive into each case:
- If the `k+1`th bit beyond the 883rd bit is `1`, then we can write `x = y - ORDER = [x*2^884 + 2^883 + z*2^(883 - k) + 2^(883 - k - 1)] - [x*2^884 + 0 + z*2^(883 - k) + 2^(883 - k - 1) + v] = 2^883 - v`. Note that as long as `v` is positive (very unlikely for it to be 0, with the chance increasing for larger `k`, as it's basically the chance that the last bits are all `0`s), this value is less than `2^883`, meaning the 883rd bit of it will become 0. Since before, our oracle was determining whether to keep the current bit at 1 if the oracle returns 0, this gets the correct bit at this position.
- If the `k+1`th bit beyond is instead `0`, then we again write `x = y - ORDER = [x*2^884 + 2^883 + z*2^(883 - k) + 2^(883 - k - 1)] - [x*2^884 + 0 + z*2^(883 - k) + 0 + v] = 2^883 + 2^(883 - k - 1) - v`. Note that `v` is the bottom `2^(883 - k - 1)` bits of `ORDER`, so it is less than `2^(883 - k - 1)`, so we have `x > 2^883`, and the oracle will return 1. This tells our search that there was an overflow, and sets the current bit to `0`. It's correct!

In both cases, we'll get the right bit for the `k+1`th bit, assuming the first `k` are correct - nice! You can easily apply the same logic to make sure that the first bit beyond the 883rd will be gotten correctly, completing the proof by induction. This means that up until the end, where some of the bits may be incorrect (due to `ORDER` potentially being even), we'll get the right bits! We don't have to mind the bottom bits; we can just bruteforce them, and verify that `pow(G, ORDER, N) = 1`. We'll also have to remember to subtract `2^883` since that bit should be 0. Now, we just hope that the 883rd is actually `0` (this assumption made this idea feel kinda dumb).

By the way, it turns out that this method actually works as well even if that bit is `1`. It just returns about `ORDER * 2`, with a bruteforceable difference. If the reader wants, feel free to look into this. 😉

Here's my code for this attack idea. The code itself is pretty short.

```python
def binsearch(oracle, bits, pos):
    guess = 0
    for i in range(1, bits + 1)[::-1]:
        if not oracle(guess + 2**i):
            guess += 2**i
    return (guess ^^ 2**pos) + 2

def oracle(guess):
    r.sendline(str(pow(G, guess, N)).encode())
    return int(r.recvline())

o = binsearch(oracle, nbits, nbits - 123)
```
The line `return (guess ^^ 2**pos) + 2` is just the subtracting of `2^883`, and the `+ 2` is the result of bruting the last bits. It turns out that the `0` assumption was correct! Nice.

With a large divisor of `phi(N)`, we can try small multiples of `ORDER` to get candidate values for `phi(N)`, and using the method described at the beginning, we can factor `N`. Here's the code:
```python
def factor_N(o):
    k = 1
    while True:
        phi = k * o
        c = N - phi + 1
        P.<x> = PolynomialRing(ZZ)
        poly = x^2 - c*x + N
        roots = poly.roots(multiplicities=False)
        p, q = 2**1000, 2**1000 
        if roots:
            p, q = roots
        if N % p == 0:
            return p, q
        k += 1
p, q = factor_N(o)
```
From there, we can just solve the discrete log for `d` from `publ` in both of `p, q` and use CRT to solve it `mod N`. This is doable since, as we suspected, both `p-1, q-1` are smooth. (You could also solve the discrete_log directly in `N`, you'd just have to implement Pohlig-Hellman yourself. Though, that's not much of an issue.) Once that's done, we can get the shared secret, and get the flag.

(We spent around an hour struggling with dependencies before getting a Rust program to work. In the end, I just got a sage script working too.)

Here's the final script:
```python
import os
os.environ['PWNLIB_NOTERM'] = '1'
from pwn import *
from math import sqrt

from hashlib import sha256
from Crypto.Cipher import AES

host, port = 'crypto.chal.csaw.io', 5010
r = remote(host, port)

def getparams():
    r.recvuntil(b'N = ')
    N = int(r.recvline())
    r.recvuntil(b'G = ')
    G = int(r.recvline())
    r.recvuntil(b'publ = ')
    publ = int(r.recvline())
    r.recvuntil(b'alice = ')
    alice = int(r.recvline())
    r.recvuntil(b'nbits = ')
    nbits = int(r.recvline())
    r.recvuntil(b'FLAG = ')
    enc = bytes.fromhex(r.recvline().decode())
    return N, G, publ, alice, nbits, enc

def binsearch(oracle, bits, pos):
    guess = 0
    for i in range(1, bits + 1)[::-1]:
        if not oracle(guess + 2**i):
            guess += 2**i
    return (guess ^^ 2**pos) + 2

def oracle(guess):
    r.sendline(str(pow(G, guess, N)).encode())
    return int(r.recvline())

def factor_N(o):
    k = 1
    while True:
        phi = k * o
        c = N - phi + 1
        P.<x> = PolynomialRing(ZZ)
        poly = x^2 - c*x + N
        roots = poly.roots(multiplicities=False)
        p, q = 2**1000, 2**1000 
        if roots:
            p, q = roots
        if N % p == 0:
            return p, q
        k += 1


N, G, publ, alice, nbits, enc = getparams()
o = binsearch(oracle, nbits, nbits - 123)
p, q = factor_N(o)
publp, publq = publ % p, publ % q
publp, publq = GF(p)(publp), GF(q)(publq)
dp, dq = publp.log(G), publq.log(G)
d = crt([dp, dq], [p - 1, q - 1])
assert pow(G, d, N) == publ
shared = pow(alice, d, N)
key = sha256(str(shared).encode()).digest()
cipher = AES.new(key, mode=AES.MODE_CTR, nonce=bytes(15))
flag = cipher.decrypt(enc)
print(flag)
```

`flag{https://www.youtube.com/watch?v=uhTCeZasCmc%7D}`