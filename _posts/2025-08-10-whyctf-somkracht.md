---
layout: post
title: Somkracht - WhyCTF 2025
date: 2025-08-10 11:12:00-0400
description: Cryptography in practice
tags: cryptography WhyCTF 2025
categories: CTFs
---

Somkracht was a 200 point cryptography challenge on [WhyCTF 2025](https://ctftime.org/event/2680).

## Problem Description

Is this how RSA works? I read something about p and q somewhere.

## Solution

We're given two RSA ciphertexts: 

$$c_1 = m^e \pmod{N}$$

$$c_2 = m^{p + q} \pmod{N}$$

By Euler's theorem, we have for $$m, N$$ coprime (as is the case here), $$m^{\varphi(N)} \equiv 1 \pmod{N}$$.  Then since $$N = pq$$, $$\varphi(N) = N - (p + q) + 1$$, so $$N + 1 \equiv p + q \pmod{\varphi(N)}$$, meaning $$m^{p + q} \equiv m^{N + 1} \pmod{N}$$.  

To recover $$m$$, we verify that $$\gcd(e, N + 1) = 1$$.  By Bézout's identity, there exist integers $$x, y$$ such that $$ex + (N + 1)y = 1$$, and computing these is simple with the extended Euclidean algorithm.  Then 

$$ c_1^x c_2^y = (m^e)^x (m^{N + 1})^y$$

$$ = m^{ex + (N + 1)y} $$

$$ \equiv m \pmod{N} $$ 

This can be done concisely in Sage:

```
import binascii
_, x, y =  xgcd(e, N + 1)
m = (pow(ct1, x) * pow(ct2, y)) % N
print(binascii.unhexlify(hex(m)[2:]))
```

which gives us `flag{31470335203860e47f0c3b1dd50e1da9}`

## Flag

flag{31470335203860e47f0c3b1dd50e1da9}
