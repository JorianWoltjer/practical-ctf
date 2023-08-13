---
description: An operation between bits used often in cryptography
---

# XOR

## Description

Understanding XOR is very important in cryptography because a lot of encryption algorithms use it in some way. XOR stands for eXclusive OR, meaning it's the OR operation but without 1+1 being true. You can see a truth table below:

<table data-header-hidden><thead><tr><th width="99" align="center"></th><th width="79" align="center"></th><th width="81" align="center"></th></tr></thead><tbody><tr><td align="center"><strong>XOR</strong></td><td align="center"><strong>0</strong></td><td align="center"><strong>1</strong></td></tr><tr><td align="center"><strong>0</strong></td><td align="center"><code>0</code></td><td align="center"><code>1</code></td></tr><tr><td align="center"><strong>1</strong></td><td align="center"><code>1</code></td><td align="center"><code>0</code></td></tr></tbody></table>

This means that only if the two values are different, the XOR function will return 1. It also means that if one value is 1, the result will be the inverse of the other value. So XORing with 1 is basically flipping a bit.&#x20;

Often you're working with long strings of bytes that are XORed, but this works the same way, just doing XOR for every bit:

```python
01000010 01111001 01100101 = "Hey"  # Plaintext
01001011 01000101 01011001 = "KEY"  # Key
-------------------------- XOR
00001001 00111100 00111100 = "\t<<"  # Ciphertext
```

The nice thing about XOR is also the fact that encryption and decryption are the exact same operation because you're just flipping the bits where the key is 1. When decrypting you're just flipping the bits back:

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

Repeating-key XOR is when a key for XOR is shorter than the plaintext/ciphertext and needs to be repeated to fill the space.&#x20;

```
Plaintext: Hello, world! And some more text.
Key:       secretsecretsecretsecretsecretsec
```

Using some analytical techniques it's possible to abuse this fact to brute-force the key byte-by-byte by looking at what the plaintext would be after decrypting. You can filter out any non-printable characters for example to narrow down a lot of results, and there are lots of techniques fo finding how normal a text looks. As you can imagine this works better for longer plaintexts, because the key will be repeated more times.&#x20;

There is a useful tool that finds the key length, and brute-forces it automatically:

{% embed url="https://github.com/hellman/xortool" %}
A tool to analyze and brute-force XOR repeating-key encryption
{% endembed %}

{% code title="Examples" %}
```shell
xortool file.bin  # Find lengths
xortool -l 11 -c 20 file.bin  # Length 11 + character \x20 (space) most common
xortool -x -c ' ' file.hex  # File is hex encoded + space character most common
xortool -b -f message.enc  # Brute-force with output filter (charset)
xortool -b -p "CTF{" message.enc  # Brute-force with known plaintext
```
{% endcode %}

## Multi-Time Pad (Crib Dragging)

The [One-Time Pad](https://en.wikipedia.org/wiki/One-time\_pad) (OTP) is a well-known **unbreakable** cipher. The important thing though is _One-Time_, and when the key is used multiple times instead, it becomes insecure very quickly.&#x20;

[This answer](https://crypto.stackexchange.com/a/33694) explains the idea behind the "Many-Time Pad" attack. The main takeaway is that if you guess one character at a position correctly, you can get back the secret at that index, and reuse that for other ciphertexts to make better guesses.&#x20;

A simple but useful tool here is the one linked below. You provide two ciphertexts and can guess common strings like " `the` " or "`. The` " or others if you know part of the plaintext. The tool will show what the other plaintext must be at all positions. Try to find a plausible text here, and click Output 1/2 to save it there and continue:

{% embed url="https://toolbox.lotusfa.com/crib_drag/" %}
Try "Crib words" to guess plaintext possibilities and find positions
{% endembed %}

After finding a chunk of plaintext, a useful **interactive tool** is [MTP](https://github.com/CameronLonsdale/MTP) by _CameronLonsdale_. It allows you to write letters in all plaintext guesses at the same time to see if anything makes sense:

<figure><img src="../.gitbook/assets/mtp showcase.gif" alt=""><figcaption><p>Interactively guess letters to expand the plaintext all the way</p></figcaption></figure>
