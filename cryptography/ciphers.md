---
description: >-
  Ways to encrypt text. Often methods used a long time ago to send secret
  messages
---

# Ciphers

## CyberChef

CyberChef is a great tool to stack various text operations. You can do things like URL encode, then Base64, then To Hex, etc. Just put some text in the input, apply operations as a recipe by dragging them from the left, and see the output.&#x20;

{% embed url="https://gchq.github.io/CyberChef/" %}
CyberChef: The Cyber Swiss Army Knife
{% endembed %}

It also has a **Magic** operation that tries lots of operations recursively, until some possible text comes out. [Example](https://gchq.github.io/CyberChef/#recipe=XOR\(%7B'option':'Decimal','string':'42'%7D,'Standard',false\)To\_Base64\('A-Za-z0-9%2B/%3D'\)To\_Hex\('None',0\)Comment\('The%20recipe%20above%20encrypts%20the%20text.%20Click%20the%20%F0%9F%9A%AB%20or%20%E2%8F%B8%EF%B8%8F%20icon%20below%20to%20see%20the%20encrypted%20text%20before%20Magic%20finds%20it.'\)Magic\(3,true,false,'%5E%5B%20-\~%5D%2B$'\)\&input=ZmluZCBtZSB1c2luZyBtYWdpYw)

To test/debug recipes you can use the ![](<../.gitbook/assets/image (21).png>) button to **disable** the operation, and the ![](<../.gitbook/assets/image (28).png>) button to **stop/pause** the recipe before it reaches this operation.&#x20;

## Ciphers

There are lots of different ciphers out there, and often it's a game of recognizing certain features of the ciphertext and then deciding on a cipher to try. Some ciphers have keys, but these can often be brute-forced until some English text comes out, or until it fits a `CTF{.*}` flag format.&#x20;

A good tool to automatically recognize and suggest ciphers is the one from Boxentriq. Lots of ciphers I won't cover here can be found on their site:

{% embed url="https://www.boxentriq.com/code-breaking/cipher-identifier" %}
Tool to automatically detect cipher from ciphertext
{% endembed %}

Another great tool is [dCode](https://www.dcode.fr/en), which you'll find often when searching for tools that can decrypt your cipher. It has lots of tools for even the most exotic of ciphers and can brute-force some parameters automatically. It also has a **Cipher Identifier**:

{% embed url="https://www.dcode.fr/cipher-identifier" %}
Automatic cipher identifier from dcode.fr with 200+ ciphers
{% endembed %}

For non-text cipher that uses **symbols** instead, try looking at their list of _Symbol Ciphers_:

{% embed url="https://www.dcode.fr/symbols-ciphers" %}
List of symbols used in specific cipher, can be used to recognize your ciphertext
{% endembed %}

### ROT13

ROT13 stands for "Rotate by 13", meaning you rotate all the letters by 13. This means the first letter (A) becomes the 14th letter (N). When you reach the end of the alphabet you just wrap around back to the start. The 20th letter in the alphabet (T) becomes `20 + 13 = 33 - 26 = 7` meaning the 7th letter (G).&#x20;

This rotation does not need to be 13, although it's the most common. You can rotate the letters by any amount from 0-26.&#x20;

{% code title="Example" %}
```python
CTF{f4k3_fl4g_f0r_t3st1ng}  # Plaintext
-------------------------- ROT 13
PGS{s4x3_sy4t_s0e_g3fg1at}  # Ciphertext
```
{% endcode %}

[CyberChef](https://gchq.github.io/CyberChef/#recipe=ROT13\(true,true,false,19\)\&input=SkFNe200cjNfbXM0bl9tMHlfYTN6YTF1bn0), [Brute-Force](https://gchq.github.io/CyberChef/#recipe=ROT13\_Brute\_Force\(true,true,false,100,0,true,'CTF%7B'\)\&input=SkFNe200cjNfbXM0bl9tMHlfYTN6YTF1bn0)

### ROT47

Similarly to [#rot13](ciphers.md#rot13 "mention"), ROT47 also rotates characters by some constant amount. But this time the whole printable ASCII character set, meaning 33 (`!`) to 126 (`~`). It rotates through this whole character set and wraps around just like ROT13.&#x20;

This also can have any amount of rotation from 0-94.&#x20;

{% code title="Example" %}
```python
CTF{f4k3_fl4g_f0r_t3st1ng}  # Plaintext
-------------------------- ROT 47
>OAva/f.Zag/bZa+mZo.no,ibx  # Ciphertext
```
{% endcode %}

[CyberChef](https://gchq.github.io/CyberChef/#recipe=ROT47\(52\)\&input=bX5wRzJeN10rMjheMysyWj4rQF0/QFs6M0k), [Brute-Force](https://gchq.github.io/CyberChef/#recipe=ROT47\_Brute\_Force\(100,0,true,'CTF%7B'\)\&input=bX5wRzJeN10rMjheMysyWj4rQF0/QFs6M0k)

### XOR

As explained in detail in [xor.md](xor.md "mention"), it XORs all the bits from a given plaintext or ciphertext, with a key that is often repeating. It can generate any set of bytes, including non-printable characters. This means it's often encoded in something like Base64 or Hex to make sure it can be sent properly. [#repeating-key-xor](xor.md#repeating-key-xor "mention") can be brute-forced, and with a known plaintext you can recover the key.&#x20;

{% code title="Example" %}
```python
01000010 01111001 01100101 = "Hey"  # Plaintext
01001011 01000101 01011001 = "KEY"  # Key
-------------------------- XOR
00001001 00111100 00111100 = "\t<<"  # Ciphertext
```
{% endcode %}

[CyberChef](https://gchq.github.io/CyberChef/#recipe=From\_Hex\('Auto'\)XOR\(%7B'option':'Hex','string':'42'%7D,'Standard',false\)\&input=MDExNjA0MzkyNDc2Mjk3MTFkMjQyZTc2MjUxZDI0NzIzMDFkMzY3MTMxMzY3MzJjMjUzZg), [Brute-Force](https://gchq.github.io/CyberChef/#recipe=From\_Hex\('Auto'\)XOR\_Brute\_Force\(1,100,0,'Standard',false,true,false,'CTF%7B'\)\&input=MDExNjA0MzkyNDc2Mjk3MTFkMjQyZTc2MjUxZDI0NzIzMDFkMzY3MTMxMzY3MzJjMjUzZg)

### ADD

The ADD cipher adds a number to every byte and wraps around when it goes over 255. For every character in the plaintext, it gets the character in the key that is often repeating.&#x20;

```python
4354467b66346b335f666c34675f6630725f74337374316e677d = "CTF{f4k3_fl4g_f0r_t3st1ng}"  # Plaintext
7365637265747365637265747365637265747365637265747365 = "secretsecretsecretsecretse"  # Key
-------------------------- ADD
b6b9a9edcba8de98c2d8d1a8dac4c9a2d7d3e798d6e696e2dae2 = "¶¹©íË¨Þ.ÂØÑ¨ÚÄÉ¢×Óç.Öæ.âÚâ"  # Ciphertext
```

{% code title="Invert a key" %}
```python
def encrypt_key_to_decrypt_key(key):
    return bytes(256 - c for c in key).hex()
```
{% endcode %}

[CyberChef](https://gchq.github.io/CyberChef/#recipe=From\_Hex\('Auto'\)ADD\(%7B'option':'Hex','string':'8d9b9d8e9b8c'%7D\)\&input=YjZiOWE5ZWRjYmE4ZGU5OGMyZDhkMWE4ZGFjNGM5YTJkN2QzZTc5OGQ2ZTY5NmUyZGFlMg)

### Substitution Cipher

A substitution cipher works by replacing certain letters with other letters. The secret here is the alphabet used, meaning what letters map to what other letters. There are some online tools that can use some analytics to find what text/key is the most likely to be correct:

{% embed url="https://planetcalc.com/8047/" %}
Automatic Substitution Cipher cracker
{% endembed %}

If an online tool cannot solve it, you might need to do some manual work. A great tool that can help with this is the following:

{% embed url="https://www.boxentriq.com/code-breaking/cryptogram" %}
Manual Substitution Cipher solver
{% endembed %}

Simply input your ciphertext, and click **Start Manual Solving**. Here you can view your ciphertext, and plaintext so far in the **Text** field. In the **Key** field, you can fill out what letters should correspond to each other. The easiest way is to look at the spacing of your target text if there is any, and guess what some words might be. Then you can slowly fill in other letters and guess more words.&#x20;

When working with English text, you can use the **Word finder** there to put wildcards for letters you don't know and find possible matching words. If your plaintext is likely in another language than English, you might want to look for any other online Wildcard dictionary searchers or create your own from a wordlist in your favorite programming language.&#x20;

Another tool that might help in the case of **short text** or a **different language** than existing tools use, is my own **SubSolver**:

{% embed url="https://github.com/JorianWoltjer/SubSolver" %}
CLI tool to Solve Substitution Ciphers using a wordlist
{% endembed %}

It allows you to provide a wordlist and tries every possible combination of words in that list efficiently to find possible solutions that fit with the repeated letters and spacing in a ciphertext.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ time ./target/release/sub-solver -s "Tcxd dlzhrtm edbe ec tmcpfitd xs ecch rl ifercl"
</strong>[*] Using empty starting key
[*] Using built-in english wordlist
[+] Loaded 13255 unique patterns
[+] Saved dictionary cache
[*] Input string: "Tcxd dlzhrtm edbe ec tmcpfitd xs ecch rl ifercl"
[+] Parsed 9 input words
[+] Pruned impossible words
[*] Starting to find solutions...
?xoetc?la??nh??w?iys???m?g -> some english text to showcase my tool in action
?xoetc?la??nh??w?irs???m?g -> some english text to showcase mr tool in action
?xoetc?la??nh??w?ius???m?g -> some english text to showcase mu tool in action
[+] Finished! (3 solutions)

real    0m0.117s
</code></pre>
