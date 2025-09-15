---
layout: post
title: Why The Bear Has No Tail - TFC CTF 2025
date: 2025-08-31 11:12:00-0400
description: Cryptography in practice
tags: cryptography TFC CTF 2025 Mersenne Twister state recovery
categories: CTFs
---

Why The Bear Has No Tail was a 50 point cryptography challenge on [TFC CTF 2025](https://ctftime.org/event/2680) by the time the contest ended.

## Problem Description

It's 6am and I'm about to fall asleep cause we didn't have enough baby challenges apparently. Anyways, you see why the bear has no tail?

## Solution

We're given the following script:

```python
import random
from secret_stuff import FLAG

class Challenge():
    def __init__(self):
        self.n = 2**26
        self.k = 2000
        # self.words = [i for i in range(n)]
        # self.buf = random.choices(self.words, k=k)
        self.index = 0

    def get_sample(self):
        self.index += 1
        if self.index > self.k:
            print("Reached end of buffer")
        else:
            print("uhhh here is something but idk what u finna do with it: ", random.choices(range(self.n), k=1)[0])

    def get_flag(self):
        idxs = [i for i in range(256)]
        key = random.choices(idxs, k=len(FLAG))
        omlet = [ord(FLAG[i]) ^ key[i] for i in range(len(FLAG))]
        print("uhh ig I can give you this if you really want it... chat?", omlet)

    def loop(self):
        random.random()
        while True:
            print("what you finna do, huh?")
            print("1. guava")
            print("2. muava")
            choice = input("Enter your choice: ")
            if choice == "1":
                self.get_sample()
            elif choice == "2":
                self.get_flag()
            else:
                print("Invalid choice")


if __name__ == "__main__":
    c = Challenge()
    c.loop()
```

Looking at the code, we see two options:

* Sample a random element in the range [0, 2^26) up to 2000 times
* Query the XOR cipher-encrypted flag, where the key is formed by randomly choosing indices from [0, 256)

Recall that Python's random module implements Mersenne Twister (MT19937), and being able to sample 2000 consecutive outputs strongly suggests that a state recovery attack is the intended solution.  However, there are a few caveats: 

* Traditional state recovery attacks against MT19937 typically require at least 624 32-bit integer samples, but each sample here is truncated in a manner that preseves only 26 bits of information (and we haven't yet ascertained the structure of those 26 bits)
* The truncation itself is not guaranteed to be expressible in terms of bitwise operations, which might complicate recovery

Let's first examine the `random.choices()` call to better understand its idiosyncracies so we can verify the above.

`random.choices()` is implemented directly in Python:

```python
def choices(self, population, weights=None, *, cum_weights=None, k=1):
    """Return a k sized list of population elements chosen with replacement.

    If the relative weights or cumulative weights are not specified,
    the selections are made with equal probability.

    """
    random = self.random
    n = len(population)
    if cum_weights is None:
        if weights is None:
            floor = _floor
            n += 0.0    # convert to float for a small speed improvement
            return [population[floor(random() * n)] for i in _repeat(None, k)]
    ...
```

The call-site in the challenge code is `random.choices(range(self.n), k=1)`, and only the relevant branch is shown. 

Within this branch, we see a `floor(random() * n)` call, of which the actual implementation of `random.random()` is in C via `_random_Random_random_impl()`:

```C
static PyObject *
_random_Random_random_impl(RandomObject *self)
/*[clinic end generated code: output=117ff99ee53d755c input=26492e52d26e8b7b]*/
{
    uint32_t a=genrand_uint32(self)>>5, b=genrand_uint32(self)>>6;
    return PyFloat_FromDouble((a*67108864.0+b)*(1.0/9007199254740992.0));
}
```

There are two successive calls to `genrand_uint32`, which each generate 32-bit integers (call these x and y respectively); then 

$$ a = x \gg 5 \implies a \in [0, 2^{27})$$

$$ b = y \gg 6 \implies a \in [0, 2^{26}) $$

Furthermore, the constants 67108864 and 9007199254740992 correspond to 2^26 and 2^53, respectively.

Tying this back to the `floor(random() * n)` call in `random.choices()` (where n = 2^26 as in the challenge), we can obtain a mathematical representation of the output:

$$ a < 2^{27}, b < 2^{26} \implies \Big\lfloor \frac{a\cdot 2^{26} + b}{2^{53}} \cdot 2^{26}\Big\rfloor$$

$$ = \Big\lfloor\frac{a\cdot 2^{52} + b\cdot 2^{26}}{2^{53}}\Big\rfloor $$ 

$$ = \Big\lfloor\frac{a\cdot 2^{52} + b\cdot 2^{26}}{2^{53}}\Big\rfloor $$

$$ = \Big\lfloor\frac{a}{2} + \frac{b}{2^{27}}\Big\rfloor $$

$$ = \Big\lfloor\frac{a}{2} \Big\rfloor = x \gg 6 $$

This leads to a few key insights.  Every time we query a new sample:

* We get the 26 _most significant bits_ of the first word
* We get no information on the second word
* The truncation indeed reduces to a bitwise rshift

Together, these suggest [SymRandCracker](https://github.com/icemonster/symbolic_mersenne_cracker/tree/main) is suitable for recovering the MT19937 state, and furthermore, allow us to deduce the correct constraints to submit.  In our scenario, we want to submit two constraints per sample: the first being our left-padded 26 bit sample with 6 unknown least significant bits, and the second being 32 unknown (free) bits:

```python
ut = Untwister()
for sample in samples:
    #Just send stuff like "?11????0011?0110??01110????01???"
        #Where ? represents unknown bits
    ut.submit("{sample:026b}" + '?' * 6)
    ut.submit("?" * 32)

r2 = ut.get_random()
...
```

Once the solver recovers the RNG state, we can recover the key and XOR it with the flag.

All that remains is for us to implement the connection logic.  To be precise, the plan is to 

* Obtain ~1400 samples of truncated MT19937 output
* Run SymRandCracker on those samples, recovering a `random.Random` object with the initial state
* Request the encrypted flag
* Call `random.choices()` on the recovered RNG and indices, thereby recovering the key
* XOR the key with the flag and decrypt

The full script to do this proceeds:

```python
#!/usr/bin/env python3
from pwn import remote
import re
import ast, re
from main import Untwister

MENU_PROMPT = b"Enter your choice: "
ROUND_START = b"what you finna do, huh?"
END_OF_BUFFER = b"Reached end of buffer"
HOST = "the-bear-0307da4edd8dc924.challs.tfcctf.com"
PORT = 1337

SAMPLE_RE = re.compile(rb"idk what u finna do with it:\s*(\d+)")

def parse_sample(blob: bytes):
    if END_OF_BUFFER in blob:
        return None
    m = SAMPLE_RE.search(blob)
    if m:
        return int(m.group(1))
    ints = re.findall(rb"(\d+)", blob)
    if ints:
        return int(ints[-1])
    return None

def recover_flag(samples, encrypted_flag):
    ut = Untwister()

    # Submit each 32-bit tempered output with unknown high 6 bits.
    # Submit full 32-bit unknown
    for sample in samples:
        bits = f"{sample:026b}".replace("0b", "") + "?" * 6
        assert len(bits) == 32
        ut.submit(bits)
        ut.submit("?" * 32)

    r2 = ut.get_random()
    L = len(encrypted_flag)

    idxs = [i for i in range(256)]
    key = r2.choices(idxs, k=L)
    flag = "".join(chr(e ^ k) for e, k in zip(encrypted_flag, key))
    return flag

def solve():
    r = remote(HOST, PORT, ssl=True)
    samples = []
    try:
        r.recvuntil(MENU_PROMPT)
        for _ in range(1200):
            r.sendline(b"1")
            blob = r.recvuntil(ROUND_START)

            sample = parse_sample(blob)
            samples.append(sample)
            r.recvuntil(MENU_PROMPT)

        print(f"Collected {len(samples)} samples")
        r.sendline(b"2")
        blob = r.recvuntil(ROUND_START)

        # Extract the printed list from the blob
        m = re.search(rb"\[.*\]", blob, re.S)
        if not m:
            print("No omlet found")
            return
        omlet = ast.literal_eval(m.group().decode())
        print(omlet)
        print("Recovered flag: ", recover_flag(samples, omlet))
        r.recvuntil(MENU_PROMPT)
    finally:
        r.close()

if __name__ == "__main__":
    # Connect with TLS
    solve()
```

```
$ python3.10 solve.py
[+] Opening connection to the-bear-0307da4edd8dc924.challs.tfcctf.com on port 1337: Done
STT> Opening connection to the-bear-0307da4edd8dc924.challs.tfcctf.com on port 1337
STT> Opening connection to the-bear-0307da4edd8dc924.challs.tfcctf.com on port 1337: Trying 34.79.35.148
STT> Opening connection to the-bear-0307da4edd8dc924.challs.tfcctf.com on port 1337: Done
Collected 1400 samples
[138, 37, 134, 51, 109, 2, 41, 113, 108, 233, 15, 241, 80, 185, 149, 128, 106, 69, 155, 50, 162, 168, 39, 47, 79, 201, 76, 217, 245, 235, 142, 251, 200, 83, 246, 0, 79, 154, 68, 73, 77, 83, 19, 37, 194, 55, 12, 25, 249, 195, 8, 59, 46, 12, 145, 230, 143, 34, 243, 242, 239, 170, 66, 102, 151, 212, 157, 208, 71, 52, 112, 13, 15, 61, 245, 204, 243, 193, 70, 163, 48, 183, 182, 102, 211, 129, 58, 17, 55, 134, 227, 187, 5, 166, 225]
STT> Solving...
STT> Solved! (in 31.477s)
Recovered flag:  TFCCTF{nowu4r5987489579_ready_to_b3AAAt58435945_online_casions????!847857w89478954w93894829384}
```

## Flag

TFCCTF{nowu4r5987489579_ready_to_b3AAAt58435945_online_casions????!847857w89478954w93894829384}