---
layout: post
title: Vaulted (199) - JustCTF 2023
date: 2023-06-05 11:12:00-0400
description: Cryptography in practice
tags: cryptography math justCTF2023
categories: CTFs
---

Vaulted was a cryptography challenge that was worth 199 points at the end of [JustCTF 2023](https://ctftime.org/event/1930/).  

## Problem Description

This secure multisignature application will keep our flag safe. Mind holding on to one of the backup keys?

```
nc vaulted.nc.jctf.pro 1337
```

## Solution

Our goal is to access a secure vault that is protected by an ECDSA multisignature scheme over the elliptic curve secp256k1.  The vault provides us with two important functions:

* `enroll`, which provides us the opportunity to enroll a public key into the vault
* `get_flag`, which lets us obtain the flag by submitting at least 3 distinct (public key, signature) pairs such that each signature for the string `'get_flag'` verifies under each public key and each public key is present in the vault

This can be seen below:

```python
class FlagVault:
    def __init__(self, flag):
        self.flag = flag
        self.pubkeys = []

    def get_keys(self, _data):
        return str([pk.format().hex() for pk in self.pubkeys])

    def enroll(self, data):
        if len(self.pubkeys) > 3:
            raise Exception("Vault public keys are full")

        pk = PublicKey(bytes.fromhex(data['pubkey']))
        self.pubkeys.append(pk)
        return f"Success. There are {len(self.pubkeys)} enrolled"

    def get_flag(self, data):
        # Deduplicate pubkeys
        auths = {bytes.fromhex(pk): bytes.fromhex(s) for (pk, s) in zip(data['pubkeys'], data['signatures'])}

        if len(auths) < 3:
            raise Exception("Too few signatures")

        if not all(PublicKey(pk) in self.pubkeys for pk in auths):
            raise Exception("Public key is not authorized")

        if not all(PublicKey(pk).verify(s, b'get_flag') for pk, s in auths.items()):
            raise Exception("Signature is invalid")

        return self.flag
```

The difficulty here is that the vault is already initialized with three existing public keys:

```python
PUBKEYS = ['025056d8e3ae5269577328cb2210bdaa1cf3f076222fcf7222b5578af846685103', 
            '0266aa51a20e5619620d344f3c65b0150a66670b67c10dac5d619f7c713c13d98f', 
            '0267ccabf3ae6ce4ac1107709f3e8daffb3be71f3e34b8879f08cb63dff32c4fdc']

if __name__ == "__main__":
    vault = FlagVault(FLAG)
    for pubkey in PUBKEYS:
        vault.enroll({'pubkey': pubkey})

    write({'message': WELCOME})
```

We don't know any of the private keys corresponding to these public keys, so it is computationally intractable for us to generate correct signatures.  Furthermore, the deduplication and authorization checks in `get_flag` seemingly prevent us from simply supplying the same (public key, signature) tuple 3 times or supplying public keys that aren't already in the vault.  Thus, it would seem like we are at an impasse.

However, there's actually a crucial vulnerability in the authorization check and `enroll`.  

```python
# Authorization
if not all(PublicKey(pk) in self.pubkeys for pk in auths):
    raise Exception("Public key is not authorized")
```

```python
def enroll(self, data):
    if len(self.pubkeys) > 3:
        raise Exception("Vault public keys are full")

    pk = PublicKey(bytes.fromhex(data['pubkey']))
    self.pubkeys.append(pk)
    return f"Success. There are {len(self.pubkeys)} enrolled"
```

`enroll` and `get_flag`'s authorization check are respectively adding and checking coincurve `PublicKey` objects.  coincurve is actually a wrapper around libsecp256k1, which supports three distinct byte representations for the same public key.

* Compressed: `0x02 || PubKey.X` or `0x03 || PubKey.X`
* Uncompressed: `0x04 || PubKey.X || PubKey.Y`
* Hybrid: `0x06 || PubKey.X || PubKey.Y` or `0x07 || PubKey.X || PubKey.Y`

Where the `||` above denotes concatenation.

Note that in the authorization check, `self.pubkeys` is a list, and using the `in` operator requires that `__eq__` is implemented for the operand. To check for equality of two `PublicKey` objects, coincurve compares their uncompressed byte representations:

```python
def __eq__(self, other) -> bool:
    return self.format(compressed=False) == other.format(compressed=False)

def format(self, compressed: bool = True) -> bytes:
    """
    Format the public key.

    :param compressed: Whether or to use the compressed format.
    :return: The 33 byte formatted public key, or the 65 byte formatted public key if `compressed` is `False`.
    """
    length = 33 if compressed else 65
    serialized = ffi.new('unsigned char [%d]' % length)
    output_len = ffi.new('size_t *', length)

    lib.secp256k1_ec_pubkey_serialize(
        self.context.ctx, serialized, output_len, self.public_key, EC_COMPRESSED if compressed else EC_UNCOMPRESSED
    )

    return bytes(ffi.buffer(serialized, length))
```

Indeed, a `PublicKey` object initialized on an equivalent compressed, uncompressed, and hybrid public key will all be equal to one another.

Thus, we can bypass the deduplication check by generating a public / private keypair, signing `'get_flag'` with the private key, and specifying the compressed, uncompressed, and hybrid representations of our public key along with the signature when calling `get_flag`.  This can be done as follows:

```python
from coincurve import PublicKey
from pwn import *
import json

PUBKEYS = ['025056d8e3ae5269577328cb2210bdaa1cf3f076222fcf7222b5578af846685103', 
            '0266aa51a20e5619620d344f3c65b0150a66670b67c10dac5d619f7c713c13d98f', 
            '0267ccabf3ae6ce4ac1107709f3e8daffb3be71f3e34b8879f08cb63dff32c4fdc',
            '03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7']

PUBKEYS = [PublicKey(bytes.fromhex(x)) for x in PUBKEYS]

# Verifies our solution
def verify_sol(data):
    # Deduplicate pubkeys
    auths = {bytes.fromhex(pk): bytes.fromhex(s) for (pk, s) in zip(data['pubkeys'], data['signatures'])}

    if len(auths) < 3:
        raise Exception("Too few signatures")

    if not all(PublicKey(pk) in PUBKEYS for pk in auths):
        raise Exception("Public key is not authorized")

    if not all(PublicKey(pk).verify(s, b'get_flag') for pk, s in auths.items()):
        raise Exception("Signature is invalid")
    
    return True

if __name__ == "__main__":
    data = {}
    pubkeys = ("03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7","04a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7",
    "07a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7893aba425419bc27a3b6c7e693a24c696f794c2ed877a1593cbee53b037368d7")
    
    init_msg = {"method": "enroll", "pubkey": pubkeys[0]}

    signatures = tuple(["304402204b254a205d0afd7620dd37bacbeadd4a4098cfa7b4f36597470538fb5d8c1836022058ee0cf5587015007b3fd5f55528c0db7c49faac4024c1c8518ed346938cad02"] * 3)

    data["method"] = "get_flag"
    data["pubkeys"] = pubkeys
    data["signatures"] = signatures

    assert verify_sol(data), "L"

    # Socket logic
    r = remote("vaulted.nc.jctf.pro", 1337)
    r.recv(1024)
    r.sendline(bytes(json.dumps(init_msg), "utf8"))
    r.recv(1024)
    r.sendline(bytes(json.dumps(data), "utf8"))
    print(r.recv(1024))
```

```
[+] Opening connection to vaulted.nc.jctf.pro on port 1337: Done
b'{"message": "justCTF{n0nc4n0n1c4l_72037872768289199286663281818929329}"}\n'
[*] Closed connection to vaulted.nc.jctf.pro port 1337
```

## Flag

justCTF{n0nc4n0n1c4l_72037872768289199286663281818929329}
