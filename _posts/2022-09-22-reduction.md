---
layout: post
title: A neat trick to recover elements in rings with zero divisors
date: 2022-09-21 11:12:00-0400
description: Number Theory
tags: cryptography math
categories: CTFs
---

I recently came across an interesting math problem involving a key exchange protocol over the ring $$\mathbb{Z}/(n)$$ where $$n = pq$$ for $$p$$ and $$q$$ prime.  The protocol involves two parties, Alice and Bob, and proceeds as follows:

* Alice randomly selects $$r_s$$ and $$r_a$$ from $$\mathbb{Z}/(n)$$ with the constraint that $$\gcd(r_a, n) = 1$$.  She forms her secret $$s = r_sp$$ and sends $$P_1 = r_as$$ to Bob.
* Bob randomly selects $$r_b$$ from $$\mathbb{Z}/(n)$$, also with the constraint that $$\gcd(r_b, n) = 1$$.  He sends $$P_2 = r_bA$$ back to Alice.
* Alice sends Bob $$P_3 = r_a^{-1}P_2$$
* Bob obtains Alice's secret by performing $$s = r_b^{-1}P_3$$.

The parameters $$p, q, P_1, P_2, P_3$$ are public, while $$r_s, r_a, r_b$$ are private.

Let's say Alice and Bob ran this protocol and an eavesdropper, Eve, wanted to compromise their private parameters.  Eve might be tempted to multiply $$P_1$$ by $$p^{-1}$$ and thereby obtain $$s$$.  Unfortunately for Eve, this immediately fails since $$\mathbb{Z}/(n)$$ has zero divisors--namely, any element that is a multiple of $$p$$ or $$q$$ will have no inverse!  This also means that any attempts by Eve to multiply $$P_i$$ with $$P_j^{-1}$$ to solve for private parameters will also fail, as all $$P_i$$ have a factor of $$p$$.

However, all is not lost for Eve.  Recall that $$P_1$$ can be expressed as the following congruence: $$P_1 \equiv r_a r_sp \pmod{n}$$.  By definition, $$P_1 = kn + r_sp = k(pq) + r_ar_sp$$.  Eve can then treat $$P_1$$ as an element of $$\mathbb{Z}$$ and compute $$D_1 = P_1/p = kq + r_ar_s$$, which is really just $$r_ar_s \pmod{q}$$.  Eve proceeds identically for $$P_2$$ and $$P_3$$, obtaining $$D_2 \equiv r_ar_br_s \pmod{q}$$ and $$D_3 \equiv r_br_s\pmod{q}$$.  This "reduction" modulo $$q$$ is significant because the ring $$\mathbb{Z}/(q)$$ has no zero divisors, meaning every non-zero element is invertible!

Eve now has the following system:

$$\begin{equation*}
  \left\{
    \begin{aligned}
      & D_1 \equiv r_a r_s \pmod{q}\\
      & D_2 \equiv r_a r_b r_s \pmod{q} \\
      & D_3 \equiv r_b r_s \pmod{q}\\
    \end{aligned}
  \right.
\end{equation*}$$

Eve can solve for $$r_b \pmod{q}$$ by computing $$D_1 D_2^{-1} \pmod{q} = (r_a r_b r_s) (r_a r_s)^{-1} \pmod{q}$$.  Eve also needs to compute $$r_b \pmod{p}$$ in order to piece together $$r_b \pmod{n}$$; to do this, she creates a similar system

$$\begin{equation*}
  \left\{
    \begin{aligned}
      & D_4 \equiv r_a r_s \pmod{p}\\
      & D_5 \equiv r_a r_b r_s \pmod{p} \\
      & D_6 \equiv r_b r_s \pmod{p}\\
    \end{aligned}
  \right.
\end{equation*}$$

and computes $$D_4 D_5^{-1} \pmod{p}$$. Eve can then simplify this system to obtain

$$\begin{equation*}
  \left\{
    \begin{aligned}
      & r_b \pmod{p}\\
      & r_b \pmod{q}\\
    \end{aligned}
  \right.
\end{equation*}$$

She then applies the Chinese remainder theorem to obtain $$r_b \pmod{n}$$.  From here, Eve can trivially recover $$s$$ by performing $$ r_b^{-1}P_3$$.  

There is actually an even quicker approach that Eve can take to recover $$s$$: realize that for $$n = pq$$, $$p(a \pmod{q}) = pa \pmod{n}$$.  This is easy to see by definition of $$ b \equiv (a \pmod{q})$$, which means $$b = kq + a$$.  Therefore $$pb = k(pq) + pa$$, and the result follows.  In this case, Eve knows that $$P_3$$ contains a factor of $$p$$, so she can actually perform $$P_3 (r_b^{-1} \pmod{q}) \pmod{n}$$ to obtain $$s$$.

The below script demonstrates both of Eve's approaches in action:

```python
import random
from math import gcd

q = random_prime(1<<256, proof=False)
p = random_prime(1<<256, proof=False)
n = p * q


# Private parameters
r_s = random.randint(1, n)
r_a = 0
r_b = 0
s = (r_s * p) % n

while gcd(r_a, n) != 1:
    r_a = random.randint(1, n)

while gcd(r_b, n) != 1:
    r_b = random.randint(1, n)

# Public parameters
P_1 = (s * r_a) % n
P_2 = (P_1 * r_b) % n
P_3 = (P_2 * inverse_mod(r_a, n)) % n

# Eve stuff
D_1 = int(P_1 / p)
D_2 = int(P_2 / p)
D_3 = int(P_3 / p)


## Approach 1: Chinese Remainder Theorem

# Compute r_b modulo p and q
rb_mod_p = (D_2 * inverse_mod(D_1, p)) % p
rb_mod_q = (D_2 * inverse_mod(D_1, q)) % q

# Piece together r_b (mod n) via the Chinese remainder theorem
rb_mod_n = crt([rb_mod_p, rb_mod_q], [p, q])

# Compute the secret via r_b^-1 * P_3, which yields s = p * r_s
v = (inverse_mod(rb_mod_n, n) * P_3) % n

## Approach 2: multiply rb_mod_q by P_2, take modulo n

v_2 = (P_3 * inverse_mod(rb_mod_q, q) % n)

assert(v == v_2 == s)
```

