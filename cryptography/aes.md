---
description: >-
  The Advanced Encryption Standard is a common symmetric encryption standard
  with a few different modes of operation
---

# AES

## Python

The [PyCryptodome](https://pypi.org/project/pycryptodome/) library has a lot of useful functions including AES

```shell
pip install pycryptodome
```

AES uses PKCS#7 padding to pad all data into blocks of 16 bytes. You can use the `pad()` and `unpad()` functions from `Crypto.Util.Padding` to do this easily.&#x20;

Here are some common operations you would want to do with AES:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# ECB Encrypt
plaintext = b"Hello, world! (ECB)"
KEY = os.urandom(16)  # 16 bytes
cipher = AES.new(KEY, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
# ECB Decrypt
cipher = AES.new(KEY, AES.MODE_ECB)
plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
print(plaintext)  # b'Hello, world! (ECB)'

# CBC Encrypt
plaintext = b"Hello, world! (CBC)"
KEY = os.urandom(16)  # 16 bytes
IV = os.urandom(16)  # 16 bytes
cipher = AES.new(KEY, AES.MODE_CBC, IV)
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
# CBC Decrypt
cipher = AES.new(KEY, AES.MODE_CBC, IV)
plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
print(plaintext)  # b'Hello, world! (CBC)'
```

## ECB Mode

![Diagram explaining AES ECB mode from Wikipedia](<../.gitbook/assets/image (7) (1).png>)

With AES in ECB mode, all plaintext data is split into blocks of 16 bytes and then encrypted separately. This means that if two blocks of 16 bytes are the same anywhere in the plaintext, we would see two of the same ciphertext blocks as well. This is the main problem of ECB mode that allows for various attacks

### Decrypt suffix (data after plaintext)

Sometimes secret data is appended after the plaintext before encrypting. In an ideal world, you should not be able to extract this data from looking at the encrypted ciphertext without knowing the key. With AES ECB however, this is possible.&#x20;

The only thing you need is a function that takes your plaintext, appends the secret data, encrypts it all, and gives you back the ciphertext.&#x20;

```python
def oracle(plaintext):
    return encrypt(plaintext + "secret")
```

Without knowing the key we can do a trick where we slot the suffix into the last byte of our plaintext. Then after we can brute-force every character it could have been in that position, until we find that that specific encrypted block matches our initial slot.&#x20;

```python
# Initial ("AAAABBBBCCCCDDD")
AAAABBBBCCCCDDDs ecret
# Brute-force ("AAAABBBBCCCCDDD?")
AAAABBBBCCCCDDDa secret
AAAABBBBCCCCDDDb secret
AAAABBBBCCCCDDDc secret
...
AAAABBBBCCCCDDDs secret  # Match
```

Then we know the first character is s, and we can repeat the same thing again by just making more space in our plaintext so the second character of the secret gets slotted into our block. Then during the brute-forcing, we already know the first character and we only need to brute-force the second character again.&#x20;

```python
# Initial ("AAAABBBBCCCCDD")
AAAABBBBCCCCDDse cret
# Brute-force ("AAAABBBBCCCCDDs?")
AAAABBBBCCCCDDsa secret
AAAABBBBCCCCDDsb secret
AAAABBBBCCCCDDsc secret
...
AAAABBBBCCCCDDse secret  # Match
```

The last thing to note for the implementation is when you have leaked the first 16 bytes, and it looks like we don't have any more space to slot our suffix into. In this case, we can just start from the beginning again by inputting 15 characters, and then look at the **second** block. We know the whole plaintext up until that point already so this is essentially the same as before.

```python
# Initial ("AAAABBBBCCCCDDD")
AAAABBBBCCCCDDDa muchlongersecret thanbefore
# Brute-force ("AAAABBBBCCCCDDDamuchlongersecre?")
AAAABBBBCCCCDDDa muchlongersecrea amuchlongersecre tthanbefore
AAAABBBBCCCCDDDa muchlongersecreb amuchlongersecre tthanbefore
AAAABBBBCCCCDDDa muchlongersecrec amuchlongersecre tthanbefore
...
AAAABBBBCCCCDDDa muchlongersecret amuchlongersecre tthanbefore  # Match in 2nd block
```

We can keep going like this and eventually leak the whole secret string. You can find a general implementation of this attack in Python in my Cryptopals solutions:

{% embed url="https://github.com/JorianWoltjer/Cryptopals/blob/master/set2/14.py" %}
Solution to a Cryptopals challenge with a script that exploits this AES ECB oracle
{% endembed %}

## CBC Mode

![Diagram explaining AES CBC mode from Wikipedia](<../.gitbook/assets/image (18).png>)

With AES in CBC mode, all blocks depend on the previous block as seen in the diagram above. This means that the ECB attacks from earlier don't work here. But CBC still has some vulnerabilities when used in the wrong way. The main reason for this is the use of XOR from the previous block.

### Bit-flipping Attack

![Diagram explaining AES CBC mode decryption from Wikipedia](<../.gitbook/assets/image (32).png>)

As seen in the diagram above, the decrypted ciphertext after the AES algorithm also gets XORed with the previous block to get back the original plaintext. If we have control over the ciphertext, we can flip a few bits of it for the receiving system to later XOR the plaintext with. You can see an arrow going from the ciphertext of the previous block, going to the plaintext of the other block.&#x20;

This is what the bit-flipping attack is. When we flip a bit in the previous ciphertext, in the next plaintext these bits will also be flipped. This way we could alter the plaintext to be anything we want and maybe inject data that should not be there.&#x20;

One problem is that when we flip even a single bit of the ciphertext in one block, the whole block decrypts to garbage because AES is very sensitive to changes. This means that we _can_ make a block of the plaintext into anything we want by flipping the bits in the previous block, but at a cost: The previous block will be random garbage. If the application does not have very strict verification on this it can still be a problem.&#x20;

```python
# Encrypt without =
AAAABBBBCCCCDDDD adminztrue -> 8f450a920a32227a19b22039deabf7b9 0f31008a84d45451d3114e9f162bee63
# 6th character "z" needs to become "=". XORing with eachother becomes "G"
# Now the 6th position in the previous block needs to be XORed with "G"
Before: 8f450a920a32227a19b22039deabf7b9 0f31008a84d45451d3114e9f162bee63
After:  8f450a920a75227a19b22039deabf7b9 0f31008a84d45451d3114e9f162bee63
# Sending this to application will decrypt to:
[random garbage] admin=true
```

If the application for example just checks if a certain string is in the plaintext, without you being able to generate a ciphertext containing that string yourself, you can bypass it with this attack.&#x20;

To see an example of this attack see my solution script to the Cryptopals challenge:

{% embed url="https://github.com/JorianWoltjer/Cryptopals/blob/master/set2/16.py" %}
An implementation of the AES CBC bit-flipping attack in Python
{% endembed %}

### Padding Oracle

I'll start off by saying that this attack really takes some time to understand, but after enough time it will all click. I found some good resources online that explain it well, and visually. Here is one of them:

{% embed url="https://samsclass.info/141/proj/p14pad.htm" %}
A site detailing the AES Padding Oracle attack with diagrams
{% endembed %}

To understand the Padding Oracle you first need to understand the [bit-flipping attack](aes.md#bit-flipping-attack) first (see above). This attack builds upon it to eventually be able to decrypt any ciphertext you get.&#x20;

All plaintext that gets encrypted by AES needs to be in chunks of 16 bytes. This means that if your input is not exactly a multiple of 16 bytes, you need to add **padding** until it is the correct length. The default is PKCS#7 padding which simply fills the needed space with bytes representing the length of the padding. So if there are 3 bytes missing, they will be filled with three `\x03` bytes:

```python
# Plaintext:    |                |
AAAABBBBCCCCDDDD EEEEFFFFGGGGH
# Padded:     3 bytes missing ^^^
AAAABBBBCCCCDDDD EEEEFFFFGGGGH\x03\x03\x03
```

When data needs to be unpadded to get back the original data, the code can just look at the last byte of the plaintext, which has the value of how many bytes of padding there are. In this example, the code would see `\x03` and know the last 3 bytes are padding. The code could **validate** the padding by checking to see if all the bytes that should be padding have this `\x03` value. If any of the padding bytes do not have this same value, something must have gone wrong during the padding process at the start. An application can then choose to display some sort of error message saying the padding is invalid.&#x20;

When an application says the padding is invalid, it gives away a tiny bit of information about the ciphertext we put in it. Now we know if the ciphertext has valid padding when decrypted.&#x20;

But here we can abuse the bit-flipping attack to get more information. If you remember we can flip any bits in a block of the plaintext by flipping those bits in the previous block of the ciphertext. This means that we can also flip some padding bits to make them correct or incorrect.&#x20;

Let's say the unknown plaintext does have valid padding, which is often the case. Then you might think that changing the last byte of the padding would only be able to make it invalid. But if we think about how this padding works, a simple `\x01` would also pass as valid padding. This is because the validation just looks at the last byte, and checks if that number of bytes is the same padding. In the case of 1, it would always be valid because it's the only byte of padding needed. So the application would return valid padding if we change the `\x03` at the end to a `\x01`.&#x20;

```
Original:   AAAABBBBCCCCDDDD EEEEFFFFGGGGH\x03\x03\x03
Also valid: AAAABBBBCCCCDDDD EEEEFFFFGGGGH\x03\x03\x01
```

If we just brute-force all 256 possible bytes in the last spot of the plaintext, there will be 2 situations where it has valid padding: When it is the same as the original ciphertext, meaning it's 3, but also when it becomes 1. In a real attack, we wouldn't know the padding was `\x03` bytes, but when we know what two values cause the padding to be valid, we can get the difference between these two brute-forced bytes. This difference will be the same as the difference between their values, `\x03` and `\x01`, but we know the `\x01` would give valid padding beforehand so we can just remove that from the difference and we are left with `\x03`! This way we can learn the last padding byte is `\x03`. To really understand why this happens, look at the decryption diagram above and think about how XOR works there.&#x20;

Now to get more bytes we can repeat this idea. To get the 2nd-to-last byte of the plaintext we can again think about when the padding would be valid for this byte: In the original ciphertext, but also when its value is `\x02` and the last byte is also `\x02`. This would make the padding 2 long and both bytes would be `\x02`, so it would be valid. But in the original plaintext, this last byte was `\x03`, as we just learned, so we would need to change this byte somehow.&#x20;

Luckily we already have the necessary information to do this. We can also bit-flip the last byte to become `\x02` instead of `\x03`, just like in a normal bit-flipping attack. Then we brute-force the second byte until becomes `\x02` in the plaintext and gives a "valid padding" response. This will again be our signal that we're done and then we can again get the difference between the original ciphertext, and this new ciphertext. This difference is the same difference between the `\x03` and `\x02` in the plaintext, so we can again just remove the known `\x02` it should be from the difference to get another `\x03`, but this time in the 2nd-to-last byte.&#x20;

This same idea will keep working even for non-padding bytes, meaning we can leak the real plaintext byte-by-byte and eventually have decrypted the whole thing.&#x20;

You can find an implementation of this attack on my Cryptopals solutions:

{% embed url="https://github.com/JorianWoltjer/Cryptopals/blob/master/set3/17.py" %}
Solution to a Cryptopals challenge with a script that exploits this AES CBC padding oracle
{% endembed %}

## CTR Mode

This mode can turn AES which normally is a block cipher of 16 bytes at a time, into a stream cipher, meaning it can simply generate any amount of random bytes from a key as the seed. This keystream it generates can then be used to XOR with the actual plaintext to encrypt it. Decrypting goes exactly the same: generate the keystream, XOR it with the ciphertext and you get back the plaintext as XOR is symmetric in this way.&#x20;

It generates the keystream by **encrypting a CounTeR with the key**. This counter can simply start at 1, and goes up for every block. This way, you're encrypting some value to generate random-looking output for the keystream.&#x20;

```python
cipher = AES.new(key, AES.MODE_ECB)  # Uses AES-ECB with key
keystream_first  = cipher.encrypt(b'\x00'*15 + '\x01')  # Keystream is generated by encrypting big endian integer
keystream_second = cipher.encrypt(b'\x00'*15 + '\x02')
keystream = b"".join(cipher.encrypt((i).to_bytes(16, 'big')) for i in range(1, 10))  # Generate infinitely
ciphertext = xor(plaintext, keystream)  # XOR is used to encrypt/decrypt
```

### Known Plaintext Attack

Working with XOR you should always think about the possibility of XORing the plaintext and ciphertext together to get the key. If this is possible, you might be able to decrypt other things if the key is repeated. With AES-CTR, this is exactly the case. If your keystream is using a fixed key, and the counter is started at 1 every time, the keystream will always be the same.&#x20;

If you can then obtain a plaintext-ciphertext combination, you can XOR them to get back the keystream used in the middle of encryption. Then use this keystream to decrypt any other data like AES would.&#x20;

```python
from Crypto.Util.Padding import pad
from Crypto.Util import Counter
from Crypto.Cipher import AES
from pwn import xor
import os

KEY = os.urandom(16)

def encrypt_CTR(plaintext):
    counter = Counter.new(128)  # Always the same initially
    cipher = AES.new(KEY, AES.MODE_CTR, counter=counter)
    ct = cipher.encrypt(pad(plaintext, 16))
    return ct

flag = b"CTF{f4k3_fl4g_f0r_t3st1ng}"  # Secret
flag_ct = encrypt_CTR(flag)  # Public
print(f"{flag_ct=}")  # b'\xc2\xd6a\xbc\xf1\x18\x13g\xba\xa3.\x03\xe0L\x8a\xb1[\xc59&\xb0#!\xac\xc5\xb6\x8b\x8f\xc1\x81\xfc\x83'

# Attack

known = b"A"*32
known_ct = encrypt_CTR(known)
print(f"{known_ct=}")  # b'\xc0\xc3f\x86\xd6m9\x15\xa4\x84\x03v\xc6R\xad\xc0h\xdb\x0cT\x82\x16Q\x83\xe3\x8a\xcc\xc8\x86\xc6\xbb\xc4\xe5\xc2"<\x9ae\xcd\x89\xc3\xcf\xcc\x12\xee{gT'

keystream = xor(known_ct, known)
print(f"{keystream=}")  # b"\x81\x82'\xc7\x97,xT\xe5\xc5B7\x87\x13\xec\x81)\x9aM\x15\xc3W\x10\xc2\xa2\xcb\x8d\x89\xc7\x87\xfa\x85\xa4\x83c}\xdb$\x8c\xc8\x82\x8e\x8dS\xaf:&\x15"

plaintext = xor(keystream, flag_ct)
print(f"{plaintext=}")  # b'CTF{f4k3_fl4g_f0r_t3st1ng}\x06\x06\x06\x06\x06\x06fU\x02\xc1*<\x9f\xaf8-\xa3POv\xac\xa4'
```

For more technical details, see the [pycryptodome docs](https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#ctr-mode), or the [cryptopals challenge](https://cryptopals.com/sets/3/challenges/18).&#x20;

### Repeated Key Attack

If you have **multiple ciphertexts** encrypted with the same keystream, and you can score a plaintext ton how plausible it is, you can use a statistical approach to try bytes of the keystream until all ciphertext decrypts to something that looks English for example.&#x20;

This is essentially the same attack as Repeating-key XOR because if the CTR keystream that is generated is the same for all the plaintext, you have a bunch of plaintext with a repeated key. XOR also works on a byte-by-byte basis, so you can try all 256 possible keystream bytes, XOR them with all the ciphertext's first bytes, and see if they look plausible as plaintext. You could check for example if all the characters are in the alphabet, including a few special characters like `" ,.!?"`.&#x20;

Then just repeat this for all the bytes you want. You can find an implementation of this attack on my Cryptopals solutions:

{% embed url="https://github.com/JorianWoltjer/Cryptopals/blob/master/set3/19.py" %}
Solution to a Cryptopals challenge with a script that exploits this AES CTR statistical attack
{% endembed %}
