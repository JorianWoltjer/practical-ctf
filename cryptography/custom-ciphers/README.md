---
description: >-
  "Never roll your own crypto" is a saying for a reason. It's hard to make a
  secure cryptographic algorithm because there are many ways it may be broken
---

# Custom Ciphers

## General Ideas

The first thing you should look at with a custom cipher is what randomness it relies on. You should look at **how many possible keys** there are to brute-force. Sometimes only ASCII values are allowed in the key, meaning you don't have to brute-force all 256 bytes, but only the 32-127 bytes.&#x20;

Also think about if it's possible to brute-force some parts **separately**, instead of all at once. Sometimes you can know when a certain byte in the key is correct, meaning you can brute-force all the bytes one by one.&#x20;

This is the basis of finding vulnerabilities in custom ciphers. It's all about thinking about how you could brute-force the key and tricks to do it more efficiently.&#x20;

In a challenge meant to be solved, it is often fast enough to use a simple language like Python. But it creates lots of overhead and implementations of brute-force in languages like C or Rust will often be way faster.&#x20;

### Meet in the Middle

There is a great [YouTube video](https://www.youtube.com/watch?v=wL3uWO-KLUE) by _polylog_ explaining this technique to solve Rubik's Cubes as an example.&#x20;

<figure><img src="../../.gitbook/assets/image (33).png" alt=""><figcaption><p>An visual example of using the Meet in the Middle attack for Rubik's Cubes (from the video)</p></figcaption></figure>

The goal of a cryptographic algorithm is that it's really hard to brute-force. Sometimes this is done by repeating tasks to make it exponentially harder.&#x20;

Take **DES,** for example, an old encryption standard with a **56-bit** key. Nowadays cracking a 56-bit key is doable on a very powerful computer. We could naively just come up with "**Double DES**", which would just be 2 DES encryptions with 2 different keys. That means you would need 2x56-bit keys meaning 112 bits. This is absolutely not brute-forcible and you might think it is secure.&#x20;

When you only have a ciphertext and you don't know what plaintext it will turn into, you cannot break it as you would indeed need to brute-force all 112 bits at the same time, maybe until some meaningful text comes out. You would need about 5e+33 operations to go through all the keys.&#x20;

But in the case, you have a **plaintext-ciphertext pair**, you can do a lot better. This is because you don't need to start at the ciphertext and brute-force all the way to the plaintext. Instead, you can start brute-force _decrypting_ from the ciphertext **halfway** to the plaintext, and then also brute-force _encrypting_ from the plaintext halfway to the ciphertext. If you store all the middle values from encrypting the plaintext, you can try to find a match when decrypting the ciphertext. A match here means the first 56-bit key is the one from the plaintext, and the second key is the one from the ciphertext. This is known as the **Meet in the Middle** attack.&#x20;

You could use this to cut the exponent in half of something that exponentially gets harder. In this Double DES example above, it would result in brute-forcing two 56-bit keys separately, instead of one 112-bit key. The only catch here is the fact that you would have to store all the halfway points and their keys, meaning it could take up quite a bit of **memory**. But this is often very worth it as the amount of computation is greatly reduced.&#x20;

{% hint style="info" %}
**Note**: Often you'll see in real challenges that the key has some restrictions which make it not as random as completely random bits to brute-force. Since these attacks rely on half of the exponent being doable, which isn't always the case with large-key cryptographic algorithms like AES.&#x20;
{% endhint %}

For an example of this attack in practice, you can see this writeup:

{% embed url="https://jorianwoltjer.com/blog/p/ctf/cyber-santa-is-coming-to-town-2021/meet-me-halfway" %}
Challenge with two weak AES keys to brute-force separately using Meet in the Middle
{% endembed %}

The basic idea of the attack is first brute-forcing one key, then saving all the halfway point together with the key they came from, then brute-forcing the second key and checking when a halfway point matches that from the first key. Then you have both parts of the key.&#x20;
