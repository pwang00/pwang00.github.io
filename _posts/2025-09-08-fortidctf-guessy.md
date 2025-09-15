---
layout: post
title: Guessy - FortID CTF
date: 2025-08-31 11:12:00-0400
description: Cryptography in practice
tags: cryptography FortID CTF 2025 Paillier RSA Information theory
categories: CTFs
---

## Overview

This challenge was actually quite neat and drew on insights from public key cryptography and information theory.  

At a high level, we are given the source to a server that implements a 10-round protocol, where a secret is generated per-round and encrypted with [Paillier](https://en.wikipedia.org/wiki/Paillier_cryptosystem).  On each round, we are asked to submit 7 lists of numbers (each with even length), which are split into left and right halves. For each half, the server multiplies the corresponding numbers by the Paillier-encrypted secret, performs Pailler decryption on that result, and returns the product of their RSA encryptions.

```python
#!/usr/bin/python3

import math
import signal
import sys

from Crypto.Util.number import getPrime, inverse, getRandomRange

N_BITS = 512

class A:
    def __init__(self, bits = N_BITS):
        self.p = getPrime(bits // 2)
        self.q = getPrime(bits // 2)
        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.e = 0x10001
        self.d = pow(self.e, -1, self.phi)


    def encrypt(self, m):
        return pow(m, self.e, self.n)


    def decrypt(self, c):
        return pow(c, self.d, self.n)


class B:
    def __init__(self, bits = N_BITS):
        self.p = getPrime(bits // 2)
        self.q = getPrime(bits // 2)
        self.n = self.p * self.q
        self.n_sq = self.n * self.n
        self.g = self.n + 1
        self.lam = (self.p - 1) * (self.q - 1) // math.gcd(self.p - 1, self.q - 1)
        x = pow(self.g, self.lam, self.n_sq)
        L = (x - 1) // self.n
        self.mu = inverse(L, self.n)


    def encrypt(self, m):
        r = getRandomRange(1, self.n)
        while math.gcd(r, self.n) != 1:
            r = getRandomRange(1, self.n)
        c1 = pow(self.g, m, self.n_sq)
        c2 = pow(r, self.n, self.n_sq)
        return (c1 * c2) % self.n_sq


    def decrypt(self, c):
        x = pow(c, self.lam, self.n_sq)
        L = (x - 1) // self.n
        return (L * self.mu) % self.n


def err(msg):
    print(msg)
    exit(1)


def compute(e_secret, xs, a, b):
    ret = 1
    for x in xs:
        ret *= a.encrypt(b.decrypt(e_secret * x))
        ret %= a.n
    return ret


def ans(secret, qs, a, b):
    e_secret = b.encrypt(secret + 0xD3ADC0DE)
    for i in range(7):
        li = qs[i][:len(qs[i]) // 2]
        ri = qs[i][len(qs[i]) // 2:]

        print(f"{compute(e_secret, li, a, b)} {compute(e_secret, ri, a, b)}")


def test(t):
    print(f"--- Test #{t} ---")
    a = A()
    b = B()
    print(f"n = {b.n}")
    print("You can ask 7 questions:")

    qs = []
    for _ in range(7):
        l = list(map(int, input().strip().split()))
        if len(l) % 2 != 0:
            err("You must give me an even number of numbers!")
        if len(l) != len(set(l)):
            err("All numbers must be distinct!")
        qs.append(l)

    secret = getRandomRange(0, 2048)
    ans(secret, qs, a, b)

    print("Can you guess my secret?")
    user = int(input())

    if user != secret:
        err("Seems like you can't")
    else:
        print("Correct!")


def timeout_handler(signum, frame):
    print("Timeout!")
    sys.exit(1)

def main():
    signal.signal(signal.SIGALRM, timeout_handler)

    for i in range(10):
        test(i)

    flag = open('flag.txt', "r").read()
    print(f"Here you go: {flag}")

if __name__ == '__main__':
    main()
```

## Solution

Let's analyze the protocol implementation in more detail.  

Firstly, we note that classes `A` and `B` perform RSA and Paillier operations.  On every round, the server provides us with the Pailler modulus $$ n = pq $$.  This is important, because with $$ g = n + 1$$ known, we can construct an encryption oracle and generate arbitrary Paillier ciphertexts.  

Furthermore, Paillier encryption is additively homomorphic over plaintext: recall that any Paillier ciphertext has form $$c = g^m r^n \bmod{n^2} $$, where $$ r $$ is a randomizer chosen from $$[1, n - 1]$$ satisfying $$ \gcd(r, n) = 1 $$.  Pailler decryption is given by $$ m = L(c^\lambda \bmod{n^2}) \cdot \mu$$, where 

* $$ \mu = L(g^\lambda \bmod{n^2})^{-1} \bmod{n}$$ is a multiplier
* $$ \lambda $$ is the evaluation of the Carmichael function $$\lambda(n) = \text{lcm}(p - 1, q - 1) $$ for $$ n = pq $$
* $$ L(x) = \frac{x - 1}{n} $$ computes the discrete logarithm of $$(n + 1)^x \bmod n^2 $$

Let $$ c_1 = g^m_1 r_1^n \bmod{n^2} $$ and $$ c_2 = g^m_2 r_2^n \bmod{n^2} $$.  Then

$$ D(c_1 c_2) = L((c_1 c_2)^\lambda \bmod{n^2}) \cdot \mu \bmod{n} $$

$$ = L(g^{\lambda(m_1 + m_2)} r_1^{n\lambda} r_2^{n\lambda} \bmod{n^2}) \cdot (L(g^\lambda \bmod{n^2}))^{-1}\bmod{n} $$

$$ = L((n + 1)^{\lambda(m_1 + m_2)} \bmod{n^2}) \cdot (L((n + 1)^\lambda \bmod{n^2}))^{-1}\bmod{n} \,\,\,\,\,\,\,\,\,\, \text{(by Euler's theorem)} $$

$$ = L(1 + \lambda(m_1 + m_2)n) (L(1 + \lambda n))^{-1} \bmod{n}\,\,\,\,\,\,\,\,\,\, \text{(by binomial theorem)}$$

$$ = \lambda(m_1 + m_2) \cdot \lambda^{-1} \bmod{n}$$ 

$$ = m_1 + m_2 \bmod{n} $$

This additive homomorphism property will be extremely useful.  Observe that `ans` performs the Paillier encryption $$ c_x = E(x + A) $$, and `compute` performs the Paillier decryption $$ D(c_x\cdot c_i) $$, where $$ x $$ denotes the secret, $$ A $$ is the constant shift of `0xD3ADC0DE`, and $$ c_i $$ is a ciphertext we control.  Furthermore, the secret itself is drawn from a small sample space of $$\{0..2047\}$$.  

A direct implication of additive homomorphism is that if we use our encryption oracle to generate ciphertexts $$ c_i = E(-(x_i + A)) $$ for every $$ x_i \in \{0..2047\} $$, at least one of these must yield a Paillier decryption of 0 on the server, since for some $$c_i, D(c_x \cdot c_i) = D(E(x + A) \cdot E(-(x + A))) = D(E(0)) = 0$$.  This also nullifies the subsequent RSA encryptions, since 0 is a fixed point under any unpadded RSA operation.  Thus, we have a distinguishing condition that could lead to information leakage!

Returning to `ans`, we're asked to submit 7 lines / lists of numbers with the condition that each list contain an even number of elements.  The lists are then bisected into a left and right half before the aggregated product of the RSA encryptions / Pailler decryptions on our supplied ciphertexts are computed on both, and the results of the encryptions of the left and right halves of each list are printed.

This bisection logic seems especially promising for further building up our distinguisher, since it encodes positional information about the secret.  To give some intuition: suppose we were to naively partition our 2048 relevant ciphertexts into chunks of size 2048 // 7 and submit those across 7 lines--we would expect the server to return 0 on either the first or second encryption on any of the 7 lines returned by the server.  This would let us bound the index to a certain subinterval of $$ \{0..2047\} $$--not quite good enough to return the secret, but certainly directionally correct approach-wise.

Can we do better?

As it turns out, we can, and the idea is remarkably similar to the [1000 wine bottles and 10 prisoners riddle](https://brainstellar.com/puzzles/31). 

We now know that there three possible outcomes concerning the appearance of the 0-ciphertext:

* 0 occurs as the first number of a line
* 0 occurs as the second number of a line
* 0 does not occur in a line

Using these conditions, we can build a trit-based coding scheme.  With 7 total lines, we can encode 3^7 = 2187 possibilites--greater than the 2048 for the secret!  

The general idea proceeds as follows:

#### Encoding

* Initialize a list of rows, each row being [left_half, right_half] = [[], []]
* For every $$ x_i \in \{0..2047\}$$, generate a ciphertext $$ c_i = E(-(x_i + A))$$, derive its ternary representation and index the digits
* For every (index, digit) in the representation:
    * If the digit is 0, exclude $$ c_i $$ from the $$i$$th row
    * If the digit is 1, append $$ c_i $$ to the left half of the $$i$$th row
    * If the digit is 2, append $$ c_i $$ to the right half of the $$i$$th row


#### Decoding

* Read all lines from the server and index them
* Initialize a list $$ D $$ whose elements are the ternary digits of the secret
* For every $$ i, (c_1, c_2) $$ in the line
    * If $$ c_1 $$ and $$ c_2 $$ are nonzero, then set the $$ i $$th digit to 0
    * If $$ c_1 = 0 $$, then set the $$ i $$th digit to 1
    * If $$ c_1 = 2 $$, then set the $$ i $$th digit to 2
* Recover the secret as $$ x = \sum_{i = 0}^6 3^i\cdot D_i $$

The full implementation proceeds.  Note that we sometimes have to pad the left and right halves to ensure each line contains an even number of elements, but the intuition remains unchanged.

```python
import re
from random import randint
from pwn import remote

n_pattern = r"(\d+)"
guess = "guess"
C = 0xD3ADC0DE

class PaillierOracle:
    def __init__(self, n):
        self.n = n
        self.n_sq = self.n * self.n
        self.g = self.n + 1

    def encrypt(self, m):
        m %= self.n
        return (1 + (m * self.n) % self.n_sq) % self.n_sq

def base3_digits(t, k=7):
    out = []
    for _ in range(k):
        out.append(t % 3)
        t //= 3
    return out 

def build_queries(n):
    C = 0xD3ADC0DE
    P = PaillierOracle(n)
    xs = [P.encrypt(-(C + t)) for t in range(2048)]

    lefts  = [[] for _ in range(7)]
    rights = [[] for _ in range(7)]

    for t in range(2048):
        d = base3_digits(t, 7)
        for i in range(7):
            if d[i] == 1:
                lefts[i].append(xs[t])
            elif d[i] == 2:
                rights[i].append(xs[t])
            # d[i]==0 -> omit

    lines = []
    for i in range(7):
        # Pad to ensure even parity
        lefts[i].extend(i for i in range(len(rights[i]) - len(lefts[i])))
        rights[i].extend(i for i in range(len(lefts[i]) - len(rights[i])))

        line = lefts[i] + rights[i]
        assert len(lefts[i]) == len(rights[i])
        assert len(line) % 2 == 0

        lines.append(" ".join(str(v) for v in line))
    return lines

def ternary_to_decimal(outputs):
    trits = []
    for Li, Ri in outputs:
        if Li == 0:
            trits.append(1)
        elif Ri == 0:
            trits.append(2)
        else:
            trits.append(0)
    t = 0
    for i in reversed(range(7)):
        t = t * 3 + trits[i]
    return t

def solve():
    r = remote("0.cloud.chals.io", 32957)
    for i in range(10):
        print("Iteration: ", i)
        _ = r.recvline()
        data = r.recvline()
        n = int(re.findall(n_pattern, data.decode())[0])

        # We should 
        queries = build_queries(n)
        lines = "\n".join(queries)
        print("Completed generation")
        r.sendline(lines.encode())
        chunks = []
        while data := r.recvline().decode():
            if len(data) < 3:
                continue
            print("Got chunk: ", data)
            if guess in data:
                break
            
            split = data.split()
            if not all([s.isnumeric() for s in split]):
                continue

            chunks.append([int(i) for i in split])
        
        decoded = ternary_to_decimal(chunks)
        r.sendline(str(decoded).encode())
        res = r.recvline()
        print(res)
    res = r.recvline()
    print(res)

if __name__ == "__main__":
    solve()
```

Running this passes all 10 rounds and yields the flag:

```
$ python3 solve.py

...

Got chunk:  0 2470416476626287013757437165518574143632344822290863291574556673425633749350696459642434140172602148241095210419398590187744231348458663562116627322196119

Got chunk:  7575219091331457507431158024230936072810218016697824999115221095552714524481381944904490760950446600150609199236884482770856521081701575516810451654553586 0

Got chunk:  Can you guess my secret?

b'Correct!\n'
b'Here you go: FortID{Y0u_R_4_Phr3ak1n6_M1nd_R3ad3r!_orz_orz}\n'
```

## Flag

FortID{Y0u_R_4_Phr3ak1n6_M1nd_R3ad3r!_orz_orz}