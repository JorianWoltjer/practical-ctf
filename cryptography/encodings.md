# Encodings

Normally you see text like this, in plain ASCII. But sometimes you want to represent some special characters that have special functions or can't be seen. This is where you could use various encodings to represent the bytes in a different way.&#x20;

ASCII is a simple set of 128 bytes that represent a lot of common characters we recognize, like letters, numbers, and some special characters. In the `0_` and `1_` column you can also find some non-printable characters. That means these characters cannot be seen normally, but have some special meaning. Take `0a` , for example, this is represented in the table as `LF` which stands for Line Feed. This character is actually the newline character for when you press enter while writing text.&#x20;

![A table of the ASCII character set](<../.gitbook/assets/image (1) (1) (1) (1) (1) (1).png>)

You might notice that the "most significant nibble" only goes up to 7. This is because ASCII only has 128 characters, instead of the 256 possible bytes. This means there are 128 more bytes that are not in ASCII but can still exist.&#x20;

### Unicode

Many systems nowadays understand Unicode, an extension of ASCII, and quote a big one at that. There are over 100.000 different symbols defined in the standard, with new ones coming. In all these characters there are some that have special properties when changing case or normalizing.&#x20;

The site below has a searchable table of all known unicode transformations for Uppercase, Lowercase, Normalize NFC, and Normalize NFKC. These can be useful for **bypassing filters**:

{% embed url="https://gosecure.github.io/unicode-pentester-cheatsheet/" %}
Table of unicode transformations in different languages
{% endembed %}

As these symbols take up more than 1 byte, they can also be useful for **overflowing** data. A length check on a string often returns the _number of characters_ instead of the _number of bytes_ in high-level programming languages. By inserting emoji, for example, it is possible to have a length be very small, but the number of bytes much larger:

<pre class="language-python"><code class="lang-python"><strong>>>> len("💻")
</strong>1
<strong>>>> "💻".encode()
</strong>b'\xf0\x9f\x92\xbb'
<strong>>>> len("💻".encode())
</strong>4
</code></pre>

## Hexadecimal

As you can see in the table above, sometimes numbers are represented including the `A-F` characters. This is known as hexadecimal or just "hex" because it allows for 16 values per digit (`0-9` and `A-F`). A common way to say a number is in this hex format is by adding `0x` in front of it, like `0x2a`.&#x20;

Every digit is extended by 6 more characters, meaning it can store more information in fewer digits. The nice thing about hex is the fact that 2 digits can store `16x16=256` values, exactly the amount of possible bytes (`2^8=256`). This makes it really useful to represent bytes with, and that is what it is often used for.&#x20;

As we saw with ASCII, all characters can be assigned a number. We can convert this number to hex to get the hexadecimal representation of the character and keep doing this for all the characters. Eventually, we end up with a big string of hex characters that represent the original string:

```python
# "Hello, world!"
ASCII:   "H   e    l    l    o    ,       w    o    r    l    d    !"
Decimal: [72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33]
Hex:    0x48  65   6c   6c   6f   2c  20  77   6f   72   6c   64   21
# 0x48656c6c6f2c20776f726c6421
```

You can use [#python](encodings.md#python "mention") or [CyberChef](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('None',0\)\&input=SGVsbG8sIHdvcmxkIQ) to easily convert to hex.&#x20;

## Base64

Base64 is another very common way to represent data just like hex. Hex is not very efficient as it always takes up 2 digits per byte. Base64 is better at this by having 64 possible characters to represent any bytes. It is a very useful encoding for representing non-printable characters as printable characters, and works as follows:

First, start by converting your desired bytes to binary (1's and 0's):

```python
"Hello, world!"
[72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33]
01001000 01100101 01101100 01101100 01101111 00101100 00100000 01110111 01101111 01110010 01101100 01100100 00100001
```

Then we take this big stream of binary and split it into chunks of 6 bits:

```python
010010 000110 010101 101100 011011 000110 111100 101100 001000 000111 011101 101111 011100 100110 110001 100100 001000 01
```

You may notice at the very end there are two `01` characters left, not a full 6 bits. We'll just fill these up with 0's.

Then finally we use the Base64 alphabet to convert these 6-bit values back to printable characters, and as a last step you should add `=` characters until the length of the string is a multiple of 3:

![The Base64 alphabet showing decimal, binary and character representations](<../.gitbook/assets/image (9).png>)

```python
12341234123412341234
SGVsbG8sIHdvcmxkIQ==
```

This resulting string is our Base64 string. It will always only contain characters from the Base64 alphabet which makes it easy for systems because they won't have to deal with unexpected characters.

Decoding the string works in the same way but in reverse. First, you would convert the Base64 string back to the binary stream using the base64 alphabet, and then take chunks of 8 from it to get back the original bytes.&#x20;

You can use [#python](encodings.md#python "mention") or [CyberChef](https://gchq.github.io/CyberChef/#recipe=To\_Base64\('A-Za-z0-9%2B/%3D'\)\&input=SGVsbG8sIHdvcmxkIQ) to easily convert to Base64.&#x20;

{% hint style="info" %}
**Note**: Sometimes flags or other secrets are 'hidden' in Base64. You can search through files for a specific string using [grep.md](../forensics/grep.md "mention"), but you can also search in Base64 by first encoding your search string in Base64, and then taking off the last character (because it can change). This will allow you to search for a string in Base64, and you may find encoded flags (see [this writeup](https://jorianwoltjer.com/blog/post/ctf/hacky-holidays-unlock-the-city-2022/pizza-pazzi#the-base64-cheese))
{% endhint %}

### Other bases

Base64 is by far the most common format, but there are a few more similar base encodings. One example is **Base32**, which works the same as Base64 but uses chunks of 5 bits to per output character, so it takes up more space but has a more limited charset. This is useful for systems that don't allow capitalization like DNS domain names sometimes.&#x20;

Another variant is **Base58** which is a little smaller than Base64, removing often misread characters like `I`, `l`, `O` and `0`. It is mostly used in cryptocurrency addresses like Bitcoin but can look very similar to Base64.&#x20;

These other bases are also found in Python and [CyberChef ](https://gchq.github.io/CyberChef/#recipe=To\_Base58\('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'\)\&input=SGVsbG8sIHdvcmxkIQ)recipes, with often some option to specify a custom alphabet yourself because they are not always standardized.&#x20;

## Big Integers

Strings are always stored as bytes on a computer. Let's take the "Hello" string for example:

```python
String: "H  e  l  l  o"
Bytes:   48 65 6c 6c 6f
```

Integers are also just stored as bytes on a computer:

```python
Number: 1337
Bytes:  05 39
```

But what if we read a string as bytes from memory like it was an integer? We would get the Big Endian integer representation.&#x20;

```python
String: "Hello"
Integer: 310939249775
```

This type of encoding is pretty common when working with mathematical cryptosystems like [rsa.md](asymmetric-encryption/rsa.md "mention"), because they work with numbers instead of strings. That way the math works the same and you can just convert it back to a string at the end.&#x20;

You can use hex functions or the PyCryptodome library in [#python](encodings.md#python "mention") to easily convert to this integer notation.&#x20;

## Python

Python has lots of functions to easily convert to and between these different representations. One thing you need to keep in mind when working with Python is the difference between **strings** and **bytestrings**. They will come up very often and it's important to understand what they both allow you to do.&#x20;

### Strings vs Bytestrings

Normal strings are defined just by using `"` or `'` quotes. It is a series of **printable** characters used to store normal text data. But everything in a computer is stored in bytes, so these characters need to be **encoded** to bytes first before they are stored. \
This is where bytestrings come in. They are the encoded variant of a string and are the exact bytes the string is made of. This means you have much easier control over the bytes. These types of strings are defined just like a normal string with quotes, but with a `b` prepended to the quotes.&#x20;

```python
String:      "Hello 👋"
Bytestring: b'Hello \xf0\x9f\x91\x8b'
```

In the example above you can see the unprintable characters that make up the emoji are shown as `\x[hex]`. This representation just means one hexadecimal byte when you see it.&#x20;

To convert between strings and bytestrings you can use the `.encode()` and `.decode()` functions on the objects. And since bytestrings are basically just a list of integers from 0-255 under the hood, you can even use the `bytes()` function to convert a list of integers directly to a bytestring.&#x20;

```python
string = "Hello 👋"  # Normal string
bytestring = string.encode()  # Encode to bytestring
print(bytestring)  # b'Hello \xf0\x9f\x91\x8b'

decoded = bytestring.decode()  # Decode back to normal string
print(decoded)  # Hello 👋

ints = list(bytestring)  # Get the list of integers from the raw bytes
print(ints)  # [72, 101, 108, 108, 111, 32, 240, 159, 145, 139]

ints[0] = 74  # Set the first character to a "J" in ASCII
new_bytestring = bytes(ints)  # Convert the list of integers back to a bytestring
new_string = new_bytestring.decode()
print(new_string)  # "Jello 👋"
```

### Converting encodings

<pre class="language-python"><code class="lang-python"># Convert bytestring to hex
<strong>>>> b"Hello, world!".hex()
</strong>'48656c6c6f2c20776f726c6421'
<strong>>>> bytes.fromhex('48656c6c6f2c20776f726c6421')  # Really useful!!
</strong>b'Hello, world!'

# Convert bytestring to base64
>>> from base64 import b64encode, b64decode
<strong>>>> b64encode(b"Hello, world!")
</strong>b'SGVsbG8sIHdvcmxkIQ=='
<strong>>>> b64decode(b'SGVsbG8sIHdvcmxkIQ==')
</strong>b'Hello, world!'

# Convert bytes to a big integer (long)
>>> from Crypto.Util.number import bytes_to_long, long_to_bytes
<strong>>>> bytes_to_long(b"Hello")
</strong>310939249775
<strong>>>> bytes_to_long(310939249775)
</strong>b'Hello'
# Manual method using hex
<strong>>>> int(b"Hello".hex(), 16)
</strong>310939249775
<strong>>>> bytes.fromhex(hex(310939249775)[2:])
</strong>b'Hello'
</code></pre>

### Useful functions

Some useful functions not mentioned above for various things:

<pre class="language-python"><code class="lang-python"># Add an integer value to a bytestring
>>> b = b"Hello "
<strong>>>> b += bytes([65])  # Add a list of length one
</strong>b'Hello A'
# Get the ASCII value for a character
<strong>>>> ord("J")  # Single character to integer
</strong>74
<strong>>>> chr(74)  # Integer to single character
</strong>"J"
<strong>>>> [ord(c) for c in "Hello"]  # Use list comprehension to convert a whole string
</strong>[72, 101, 108, 108, 111]
# Get the integer value from a character in a bytestring (they act like lists)
>>> b = b"Hello, world!"
<strong>>>> b[0]  # Get an index
</strong>72  # "H"
<strong>>>> for c in b[:5]:  # You can iterate over the bytestring like a list
</strong><strong>...     print(c)
</strong>72   # "H" 
101  # "e"
108  # "l"
108  # "l"
111  # "o"
# Convert an integer to hex
<strong>>>> hex(1337)
</strong>0x539
<strong>>>> 0x539  # Python reads numbers with 0x in front directly as hex
</strong>1337
<strong>>>> int("539", 16)  # Convert hex string to an integer
</strong>1337
</code></pre>

## Recognition

There are a lot of encodings out there, which are very useful for machines, but not often very readable for humans. There are a few tricks though to quickly recognize certain encodings that give away what they are.&#x20;

The first thing to know is that the English letters go from 65 to 122 in **ASCII**. The lowercase letters start at 97 and are the most common, so if you see a list of decimal numbers around **97-122** you can be pretty sure that it is just the ASCII integer representation, and you can decode it from decimal: [CyberChef](https://gchq.github.io/CyberChef/#recipe=From\_Decimal\('Space',false\)\&input=NzIgMTAxIDEwOCAxMDggMTExIDQ0IDMyIDExOSAxMTEgMTE0IDEwOCAxMDAgMzM)

Next, the **hexadecimal** encoding is very similar. It's just the ASCII values but converted to hex, which goes from 0x41 to 0x7a. The lowercase letters start from 0x61 again, so a list of values from **0x61 to 0x7a** is likely to be hex encoded. Hex characters are often represented without any spacing because they always take up 2 bytes of space, so recognizing a lot of 6's and 7's should be what you're looking for. Then you can of course decode again from hex: [CyberChef](https://gchq.github.io/CyberChef/#recipe=From\_Hex\('None'\)\&input=NDg2NTZjNmM2ZjJjMjA3NzZmNzI2YzY0)

Finally, **Base64** has a few indicators. The first and most obvious is the **`=`** **signs** at the end, being the padding that Base64 often needs. Almost no other encoding does this so it's a clear sign of some base encoding. Then the with Base64 character set it often looks like random characters. But because Base64 is basically converting character by character, we can recognize the start of a string like `{"` for **JSON**, which will look like **`eyJ`** or **`eyI`**. Then you know there is a JSON value when you decode it: [CyberChef](https://gchq.github.io/CyberChef/#recipe=From\_Base64\('A-Za-z0-9%2B/%3D',true,false\)\&input=ZXlKclpYa2lPaUFpZG1Gc2RXVWlmUT09)
