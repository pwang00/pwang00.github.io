---
layout: post
title: Rustberry (201) - JustCTF 2023
date: 2023-06-05 11:10:00-0400
description: Rust ARMv7+ reversing
tags: reversing justCTF2023
categories: CTFs
---

Rustberry was a reverse engineering challenge that was worth 201 points at the end of [JustCTF 2023](https://ctftime.org/event/1930/).  You can download the original challenge [here.](https://pwang00.github.io/assets/challenges/justctf2023/rev/rustberry.exe)

## Problem Description

I have enough of VMs. This is a simple crackme

Note: flag is in format jctf{[A-Za-z0-9_]+}

```
nc vaulted.nc.jctf.pro 1337
```

## Solution

We're given a binary `rustberry.exe`, which seems to be have been initially written in Rust and compiled for ARMv7+:

```
$ file rustberry.exe 
rustberry.exe: ELF 32-bit LSB pie executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-armhf.so.3, for GNU/Linux 3.2.0, BuildID[sha1]=fe44afa081afc7b0025b39da63c436ebdc7038be, with debug_info, not stripped
```

Typically, the main function of Rust ELFs follows the naming convention `<project_name>::main`, and indeed we find `rustberry::main` in Ghidra's decompiled output.

```c
void main(undefined4 param_1,undefined4 param_2)

{
  code *local_c;
  
  local_c = rustberry::main;
  std::rt::lang_start_internal
            (&local_c,&anon.1360747006cbb19a0f51f675ad6cc70e.0.llvm.6404864161857707856,param_1,
             param_2,0);
  return;
}

...

void rustberry::main(char *param_1)

{
  undefined *puVar1;
  undefined4 *puVar2;
  ...
}
```

Examining it, a few things stand out:

`__s2` is likely a `Vec<u8>` that's storing some kind of key:

```c
__s2 = (undefined4 *)std::alloc::__default_lib_allocator::__rust_alloc(0xac,4);
if (__s2 == (undefined4 *)0x0) {
                /* WARNING: Subroutine does not return */
alloc::alloc::handle_alloc_error(0xac,4);
}
__s2[0x25] = 7;
__s2[0x29] = 0x1c;
__s2[0x2a] = 0xff;
__s2[0x18] = 3;
__s2[0x26] = 0x21;
__s2[0x19] = 0x1a;
__s2[0x1a] = 0x11;
__s2[0x1b] = 0x14;
__s2[0x20] = 0x11;
__s2[0x21] = 0x11;
__s2[0x1d] = 0x13;
__s2[0x1e] = 1;
__s2[0x1f] = 0x20;
__s2[0x13] = 8;
__s2[0x28] = 0xb;
__s2[0x27] = 0xb;
__s2[0x11] = 0xb;
__s2[0x17] = 0xb;
__s2[8] = 0x15;
__s2[9] = 0x33;
__s2[0x22] = 0x18;
__s2[0x10] = 0xf;
__s2[10] = 0x1a;
__s2[0xb] = 9;
__s2[0xc] = 0x14;
__s2[0xd] = 0x12;
__s2[3] = 5;
__s2[0x1c] = 0x22;
__s2[4] = 0x1b;
__s2[5] = 0xd;
__s2[6] = 0x1d;
__s2[0x23] = 0x1a;
__s2[0x15] = 0x1a;
__s2[0xf] = 0x1a;
__s2[7] = 0x1a;
__s2[0x24] = 2;
__s2[0x12] = 0;
__s2[0x14] = 0xd;
__s2[0x16] = 0x1d;
__s2[0xe] = 0x13;
*__s2 = 9;
__s2[1] = 2;
__s2[2] = 0x13;
__dest = (byte *)std::alloc::__default_lib_allocator::__rust_alloc(0x41,1);
```

`__dest` is likely some `Vec<u8>` that's storing the upper and lowercase alphabet and some special characters:

```c
__dest = (byte *)std::alloc::__default_lib_allocator::__rust_alloc(0x41,1);
if (__dest == (byte *)0x0) {
                /* WARNING: Subroutine does not return */
alloc::alloc::handle_alloc_error(0x41,1);
}
memcpy(__dest,
        "abcdefghijklmnopqrstuvwxyz_{}0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZGive me the flag? \nYou\' ve entered \nError: \nIndex out of bounds()/rustc/84c898d65adf2f39a5a98507f1fe0ce10a2b8dbc/ library/core/src/str/pattern.rs"
        ,0x41);
```

`puVar2` is likely the String corresponding to our user input.  Furthermore, there's a main loop that's computing `uVar6 = puVar2[i]`, checking if `puVar2[i] in dest[1]`, and copying `dest.index_of(puVar2[i])` into `__s1[i]`:

```c
    do {
      uVar6 = (uint)*(byte *)((int)puVar2 + uVar9);
      if (uVar6 == *__dest) {
        uVar6 = count_leading_zeroes(0);
        iVar7 = 0;
LAB_0001624c:
        iVar7 = iVar7 + (uVar6 >> 5 ^ 1);
      }
      else {
        if (uVar6 == __dest[1]) {
          uVar6 = count_leading_zeroes(0);
          iVar7 = 1;
          goto LAB_0001624c;
        }

        ...
        if (uVar6 == __dest[0x40]) {
          iVar7 = 0x40;
          uVar6 = count_leading_zeroes(uVar6 - __dest[0x40]);
          goto LAB_0001624c;
        }
      }
      *(int *)(__s1 + uVar9 * 4) = iVar7;
      uVar9 = uVar9 + 1;
    } while (uVar4 != uVar9);
```

There's a comparison that compares `uVar4` to 0x2b = 42, suggesting that `uVar4` is the length of the input.  Furthermore, the comparison checks that the `__s1` and `__s2` are bytewise identical for the first 0xac = 172 characters.  If the check succeeds, then the program will output "You've entered correctly", and otherwise it will output "You've entered incorrectly".

```c
if ((uVar4 != 0x2b) || (iVar7 = bcmp(__s1,__s2,0xac), iVar7 != 0)) goto LAB_000162f4;
local_48 = 9;
local_4c = (undefined4 *)std::alloc::__default_lib_allocator::__rust_alloc(9,1);
if (local_4c == (undefined4 *)0x0) {
                /* WARNING: Subroutine does not return */
    alloc::alloc::handle_alloc_error(9,1);
}

// "correctly"
*(undefined *)(local_4c + 2) = 0x79;
local_4c[1] = 0x6c746365;
uVar8 = 0x72726f63;

...

LAB_000162f4:
    local_48 = 0xb;
    local_4c = (undefined4 *)std::alloc::__default_lib_allocator::__rust_alloc(0xb,1);
    if (local_4c == (undefined4 *)0x0) {
                    /* WARNING: Subroutine does not return */
      alloc::alloc::handle_alloc_error(0xb,1);
    }

    // "incorrectly"
    *(undefined4 *)((int)local_4c + 7) = 0x796c7463;
    local_4c[1] = 0x63657272;
    uVar8 = 0x6f636e69;
```

We therefore need to find a way to supply a string such that after the indices are checked against `__dest` and copied into `__s1`, `__s1` and `__s2` match.  This is actually quite simple since we're already given the correct indices in `__s2`.  We can recover the original string by doing `__dest[__s2[i]]`.

```python
__dest = "abcdefghijklmnopqrstuvwxyz_{}0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZGive me the flag? \nYou' ve entered \nError: \nIndex out of bounds()/rustc/84c898d65adf2f39a5a98507f1fe0ce10a2b8dbc/ library/core/src/str/pattern.rs"
__s2 = [9, 2, 19, 5, 27, 13, 29, 26, 21, 51, 26, 9, 20, 18, 19, 26, 15, 11, 0, 8, 13, 26, 29, 11, 3, 26, 17, 20, 34, 19, 1, 32, 17, 17, 24, 26, 2, 7, 33, 11, 11, 28]
puVar2 = "".join([__dest[i] for i in __s2])

print(puVar2)
```

`jctf{n0_vM_just_plain_0ld_ru5tb3rry_ch4ll}`.

Indeed, after running the binary with this, we confirm that we have the correct flag.

```
$ export LD_LIBRARY_PATH=/usr/arm-linux-gnueabihf/lib/
$ ./rustberry.exe 
Give me the flag? 
jctf{n0_vM_just_plain_0ld_ru5tb3rry_ch4ll}
You've entered correctly
```

### Some additional notes 

We made some assumptions about the purpose of some variables since decompiled code isn't always sensible.  For example, it's not 100% clear that `uVar4` is the length of the input and `puVar2` is the input string.

```c
local_38 = 1;
local_30 = 0;
local_44 = 0;
std::io::stdio::_print(&local_44);
local_54 = 0;
local_58 = (undefined4 *)0x1;
local_5c = 0;
local_50 = std::io::stdio::stdin();
std::io::stdio::Stdin::read_line(&local_44,&local_50,&local_5c);
uVar4 = local_54;
puVar2 = local_58;
```

We can ascertain this via dynamic analysis.  

From looking at the dissassembly, we can see that 

```c
(uint)*(byte *)((int)puVar2 + uVar9);
```

corresponds to 
```c
00015c2c 02 00 db e7     ldrb       r0,[r11,r2]
```

meaning `puVar2` is stored in `r11`.  Furthermore,

```c
if ((uVar4 != 0x2b) || (iVar7 = bcmp(__s1,__s2,0xac), iVar7 != 0)) goto LAB_000162f4
```

corresponds to 

```c
00016268 2b 00 5a e3     cmp        r10,#0x2b
0001626c 20 00 00 1a     bne        LAB_000162f4
00016270 09 00 a0 e1     cpy        r0,r9
00016274 07 10 a0 e1     cpy        r1,r7
00016278 ac 20 a0 e3     mov        r2,#0xac
0001627c 08 f2 ff eb     bl         <EXTERNAL>::bcmp
00016280 00 00 50 e3     cmp        r0,#0x0
00016284 1a 00 00 1a     bne        LAB_000162f4
```

so `uVar4` is stored in `r10`, `__s1` is stored in `r9`, and `__s2` is stored in `r7`.

We can then run the binary via qemu-arm and gdbserver, set relevant breakpoints, and examine the contents of these registers:

```c
$ qemu-arm -g 1234 rustberry.exe 
Give me the flag? 
jctf{n0_vM_just_plain_0ld_ru5tb3rry_ch4ll}

...

gdb-peda$ b *0x40006268
Breakpoint 1 at 0x40006268
gdb-peda$ x/s $r11
0x40056860:     "jctf{n0_vM_just_plain_0ld_ru5tb3rry_ch4ll}\ni\261"
gdb-peda$ p $r10
$13 = 0x2b
gdb-peda$ x/172x $r7
0x40056890:     0x09    0x00    0x00    0x00    0x02    0x00    0x00    0x00
0x40056898:     0x13    0x00    0x00    0x00    0x05    0x00    0x00    0x00
0x400568a0:     0x1b    0x00    0x00    0x00    0x0d    0x00    0x00    0x00
0x400568a8:     0x1d    0x00    0x00    0x00    0x1a    0x00    0x00    0x00
0x400568b0:     0x15    0x00    0x00    0x00    0x33    0x00    0x00    0x00
0x400568b8:     0x1a    0x00    0x00    0x00    0x09    0x00    0x00    0x00
0x400568c0:     0x14    0x00    0x00    0x00    0x12    0x00    0x00    0x00
0x400568c8:     0x13    0x00    0x00    0x00    0x1a    0x00    0x00    0x00
0x400568d0:     0x0f    0x00    0x00    0x00    0x0b    0x00    0x00    0x00
0x400568d8:     0x00    0x00    0x00    0x00    0x08    0x00    0x00    0x00
0x400568e0:     0x0d    0x00    0x00    0x00    0x1a    0x00    0x00    0x00
0x400568e8:     0x1d    0x00    0x00    0x00    0x0b    0x00    0x00    0x00
0x400568f0:     0x03    0x00    0x00    0x00    0x1a    0x00    0x00    0x00
0x400568f8:     0x11    0x00    0x00    0x00    0x14    0x00    0x00    0x00
0x40056900:     0x22    0x00    0x00    0x00    0x13    0x00    0x00    0x00
0x40056908:     0x01    0x00    0x00    0x00    0x20    0x00    0x00    0x00
0x40056910:     0x11    0x00    0x00    0x00    0x11    0x00    0x00    0x00
0x40056918:     0x18    0x00    0x00    0x00    0x1a    0x00    0x00    0x00
0x40056920:     0x02    0x00    0x00    0x00    0x07    0x00    0x00    0x00
0x40056928:     0x21    0x00    0x00    0x00    0x0b    0x00    0x00    0x00
0x40056930:     0x0b    0x00    0x00    0x00    0x1c    0x00    0x00    0x00
0x40056938:     0xff    0x00    0x00    0x00
gdb-peda$ x/172x $r9
0x40056988:     0x09    0x00    0x00    0x00    0x02    0x00    0x00    0x00
0x40056990:     0x13    0x00    0x00    0x00    0x05    0x00    0x00    0x00
0x40056998:     0x1b    0x00    0x00    0x00    0x0d    0x00    0x00    0x00
0x400569a0:     0x1d    0x00    0x00    0x00    0x1a    0x00    0x00    0x00
0x400569a8:     0x15    0x00    0x00    0x00    0x33    0x00    0x00    0x00
0x400569b0:     0x1a    0x00    0x00    0x00    0x09    0x00    0x00    0x00
0x400569b8:     0x14    0x00    0x00    0x00    0x12    0x00    0x00    0x00
0x400569c0:     0x13    0x00    0x00    0x00    0x1a    0x00    0x00    0x00
0x400569c8:     0x0f    0x00    0x00    0x00    0x0b    0x00    0x00    0x00
0x400569d0:     0x00    0x00    0x00    0x00    0x08    0x00    0x00    0x00
0x400569d8:     0x0d    0x00    0x00    0x00    0x1a    0x00    0x00    0x00
0x400569e0:     0x1d    0x00    0x00    0x00    0x0b    0x00    0x00    0x00
0x400569e8:     0x03    0x00    0x00    0x00    0x1a    0x00    0x00    0x00
0x400569f0:     0x11    0x00    0x00    0x00    0x14    0x00    0x00    0x00
0x400569f8:     0x22    0x00    0x00    0x00    0x13    0x00    0x00    0x00
0x40056a00:     0x01    0x00    0x00    0x00    0x20    0x00    0x00    0x00
0x40056a08:     0x11    0x00    0x00    0x00    0x11    0x00    0x00    0x00
0x40056a10:     0x18    0x00    0x00    0x00    0x1a    0x00    0x00    0x00
0x40056a18:     0x02    0x00    0x00    0x00    0x07    0x00    0x00    0x00
0x40056a20:     0x21    0x00    0x00    0x00    0x0b    0x00    0x00    0x00
0x40056a28:     0x0b    0x00    0x00    0x00    0x1c    0x00    0x00    0x00
0x40056a30:     0xff    0x00    0x00    0x00
```

Thus, by supplying the flag, we have that the first 172 bytes pointed to by `r7` and `r9` are identical, meaning `bcmp(__s1, __s2, 0xac)` is satisfied.  We can also observe that `r11` contains the contents of our flag, so `puVar2` does actually store our input.  Finally, `r10` does indeed correspond to the length of the input (0x2b), meaning our assumption about `uVar4` being the length of the input was correct.  


## Flag

jctf{n0_vM_just_plain_0ld_ru5tb3rry_ch4ll}