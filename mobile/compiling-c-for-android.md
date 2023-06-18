---
description: Compile and run C programs on Android to debug pieces of code
---

# Compiling C for Android

Android runs on Unix and is very much capable of running programs compiled with C. The only catch is that it uses some specific architectures which means specific compilers should be used to generate the binary. This can be very useful in viewing the output of a C library like compiled JNI functions for example.&#x20;

Imagine we reverse-engineered a JNI function that uses a seeded random or the filesystem, which we can't easily replicate on a local Linux machine. We could copy [ghidra.md](../reverse-engineering/ghidra.md "mention")'s decompiled code into a simple C program that prints the output like this one:

```c
#include <stdio.h>
#include <stdlib.h>

int iVar1;
char __s[0x21];

int main() {
    srand(0x1ca3);
    long lVar4 = 0;
    do {
        iVar1 = rand();
        __s[lVar4] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"[iVar1 % 0x3e];
        lVar4 = lVar4 + 1;
    } while (lVar4 != 0x20);

    __s[0x20] = '\0';

    printf("Key: %s\n", __s);
}
```

In the original code, this was a variable, but I've added the `printf` to extract this value and read it instead. Running this locally might give different results than if it actually ran on the mobile device, so we need to compile it with a specific Android compiler for the device to understand.&#x20;

From [here](https://stackoverflow.com/a/13259266/10508498), you can compile a program using the Android [Native Development Kit](https://developer.android.com/ndk/downloads). It contains many prebuilt compilers for many different architectures and versions. Simply download and extract the zip linked above and look at the `toolchains/llvm/prebuilt/linux-x86_64/bin` directory to find all the compilers for both C and C++. Here you can choose one of the architectures like `armv7a` or `aarch64` (ARMv8-A), together with the correct Android API version your device uses, see the link below for a translation table:

{% embed url="https://apilevels.com/" %}
Big table of all Android API versions and their corresponding names and numbers
{% endembed %}

{% hint style="warning" %}
Some devices don't use ARM and should use regular `x86_64` instead. In this case, simply use the `x86_64-linux-androidXX-clang` compiler instead
{% endhint %}

Use these binaries like you would any other `gcc` compiler, for example:

```shell-session
$ x86_64-linux-android27-clang program.c -o program
```

Then you can copy this binary over to the device using ADB, and run it:

<pre class="language-shell-session" data-overflow="wrap"><code class="lang-shell-session"><strong>$ adb push ./program /data/local/tmp/program
</strong><strong>$ adb shell
</strong><strong># cd /data/local/tmp/
</strong><strong># file program
</strong>program: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /system/bin/linker64, not stripped
<strong># ./program
</strong>Key: zxzaKk5uLHdoKo9y8osZSnTe5DCdrIX0
</code></pre>
