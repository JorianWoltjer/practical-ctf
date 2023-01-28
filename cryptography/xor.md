---
description: An operation between bits used often in cryptography
---

# XOR

## Description

Understanding XOR is very important in cryptography, because a lot of encryption algorithms use it in some way. XOR stands for eXclusive OR, meaning it's the OR operation but without 1+1 being true. You can see a truth table below:

| **XOR** | **0** | **1** |
| :-----: | :---: | :---: |
|  **0**  |  `0`  |  `1`  |
|  **1**  |  `1`  |  `0`  |

This means that only if the two values are different, the XOR function will return 1. It also means that if one value is 1, the result will be the inverse of the other value. So XORing with 1 is basically flipping a bit.&#x20;

Often you're working with longer strings of bytes that are XORed, but this works the same way, just doing XOR for every bit:

```python
01000010 01111001 01100101 = "Hey"  # Plaintext
01001011 01000101 01011001 = "KEY"  # Key
-------------------------- XOR
00001001 00111100 00111100 = "\t<<"  # Ciphertext
```

The nice thing about XOR is also the fact that encryption and decryption are the exact same operation, because you're just flipping the bits where the key is 1. When decrypting you're just flipping the bits back:

```python
00001001 00111100 00111100 = "\t<<"  # Ciphertext
01001011 01000101 01011001 = "KEY"  # Key
-------------------------- XOR
01000010 01111001 01100101 = "Hey"  # Plaintext
```

But this also means that if you know the ciphertext, and the plaintext you can XOR them both to get the key:

```python
00001001 00111100 00111100 = "\t<<"  # Ciphertext
01000010 01111001 01100101 = "Hey"  # Plaintext
-------------------------- XOR
01001011 01000101 01011001 = "KEY"  # Key
```

Since XOR encryption works bit-by-bit you don't even need to know the whole plaintext to get part of the key. If you know only the first few characters of the plaintext, or in some special positions you can still get the key at those same positions.&#x20;

## Repeating-key XOR

Repeating-key XOR is when a key for XOR is shorter than the plaintext/ciphertext, and needs to be repeated to fill the space.&#x20;

```
Plaintext: Hello, world! And some more text.
Key:       secretsecretsecretsecretsecretsec
```

Using some analytical techniques it's possible to abuse this fact to brute-force the key byte-by-byte by looking at what the plaintext would be after decrypting. You can filter out any non-printable characters for example to narrow-down a lot of results, and there are lots of techniques on finding how normal a text looks. As you can imagine this works better for longer plaintexts, because the key will be repeated more times.&#x20;

There is a useful tool that finds the key length, and brute-forces it automatically:

{% embed url="https://github.com/hellman/xortool" %}
A tool to analyze and brute-force XOR repeating-key encryption
{% endembed %}

```shell
xortool file.bin  # Find lengths
xortool -l 11 -c 20 file.bin  # Length 11 + character \x20 (space) most common
xortool -x -c ' ' file.hex  # File is hex encoded + space character most common
xortool -b -f message.enc  # Brute-force with output filter (charset)
xortool -b -p "CTF{" message.enc  # Brute-force with known plaintext
```

See the Github link above for more examples.
