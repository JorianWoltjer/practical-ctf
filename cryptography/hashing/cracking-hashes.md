---
description: >-
  The point of hashes are that you can't reverse them, but we can sometimes find
  the original text by brute-forcing
---

# Cracking Hashes

To automatically recognize and crack all kinds of hashes I made a cracking module part of my default tool:

{% embed url="https://github.com/JorianWoltjer/default" %}
My big tool containing a module for cracking hashes
{% endembed %}

## Password Hashes

A secure application should store any passwords using a hashing function. This is because the application does not need to know the exact password you set, only if it is the same one you put in when you created your account. Because of this, the application can store a scrambled password which is the hash and cannot be reversed back into the original password.&#x20;

The only way to try and get back the original text from a hash, is to try lots of possible values for the original text until it matches te hash. But of course you would need to have a list that contains the original text. This is known as brute-forcing or cracking a hash.&#x20;

There are a lot of different hashing functions that all have some differences. The biggest difference for cracking is the speed of the hashing function. The faster you can generate a hash, the faster you can try passwords to see if they generate the same hash. Here are some common hashes with their average speed on my RTX 2060 laptop with [#hashcat](cracking-hashes.md#hashcat "mention"):

<table><thead><tr><th>Hash function</th><th width="199.33333333333331">Speed</th><th>Time per 1.000.000.000</th></tr></thead><tbody><tr><td>Bcrypt ($2*$)</td><td>12 KH/s</td><td>23 hours</td></tr><tr><td>SHA512-crypt ($6$)</td><td>38 KH/s</td><td>7.3 hours</td></tr><tr><td>SHA1</td><td>4 GH/s</td><td>0.25 seconds</td></tr><tr><td>MD5</td><td>7.5 GH/s</td><td>0.133 seconds</td></tr><tr><td>NTLM</td><td>9.5 GH/s</td><td>0.105 seconds</td></tr></tbody></table>

Yes, you read that right. With today's computers, you can generate a billion MD5 or NT hashes in a tenth of a second. That's why it is important to use intentionally slow algorithms like Bcrypt which are a lot harder to brute-force.&#x20;

## Converting hash formats

Different applications and files have different formats to store hashes. Two common tools for cracking hashes are [#john-the-ripper](cracking-hashes.md#john-the-ripper "mention") and [#hashcat](cracking-hashes.md#hashcat "mention"). These tools have different formats for some hashes, so they might need to be converted.&#x20;

Hashcat has made a great list of example hashes to see what they all look like:

{% embed url="https://hashcat.net/wiki/doku.php?id=example_hashes" %}
A list of example hashes with their name and hashcat mode
{% endembed %}

When comparing the two you'll find that john often has a few different possible ways to represent a hash. Sometimes including the filename or username in the hash as well. But with Hashcat the hash often needs to be completely stripped down. Take the PKZIP hash for example:

```
John: test.zip/flag.txt:$pkzip$1*2*2*0*11*5*22dc8822*0*42*0*11*55ee*bfcbf39396ab87b78eb574a02dd5020f23*$/pkzip$:flag.txt:test.zip::test.zip
Hashcat:                $pkzip$1*2*2*0*11*5*22dc8822*0*42*0*11*55ee*bfcbf39396ab87b78eb574a02dd5020f23*$/pkzip$
```

Sometimes you also need to **extract** a hash from a password-protected ZIP file for example. This is where John has a lot of useful tools. In the [`john/run`](https://github.com/openwall/john/tree/bleeding-jumbo/run) directory of your John the Ripper installation, there should be a lot of scripts and programs that allow you to convert certain files to the john format. For `.zip` archives there is the `zip2john` utility:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ zip2john test.zip
</strong>ver 1.0 efh 5455 efh 7875 test.zip/flag.txt PKZIP Encr: 2b chk, TS_chk, cmplen=17, decmplen=5, crc=22DC8822 ts=55EE cs=55ee type=0
test.zip/flag.txt:$pkzip$1*2*2*0*11*5*22dc8822*0*42*0*11*55ee*bfcbf39396ab87b78eb574a02dd5020f23*$/pkzip$:flag.txt:test.zip::test.zip
<strong>$ zip2john test.zip > john.hash
</strong><strong>$ cat john.hash
</strong>test.zip/flag.txt:$pkzip$1*2*2*0*11*5*22dc8822*0*42*0*11*55ee*bfcbf39396ab87b78eb574a02dd5020f23*$/pkzip$:flag.txt:test.zip::test.zip
</code></pre>

There are a lot of files that can be converted to john like this, just find one for the file format you need and convert it using the script.&#x20;

You can also use John to convert the hashes from a file, and then actually crack them with **Hashcat**. As stated above hashcat has a slightly different hash format, but from what I've found it's almost always just splitting the john hash by `:` colons and then taking the second part. That way you're only getting the hash without any other information.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ cat john.hash | awk -F: '{print $2}' > hashcat.hash
</strong><strong>$ cat hashcat.hash
</strong>$pkzip$1*2*2*0*11*5*22dc8822*0*42*0*11*55ee*bfcbf39396ab87b78eb574a02dd5020f23*$/pkzip$
</code></pre>

## [Hashcat](https://hashcat.net/hashcat/)

Hashcat is a hash-cracking tool that is often used professionally because it can use the GPU to get really fast cracking speeds. It also supports a lot of hashes just like John, the only thing is that it's a bit finicky to get working sometimes. But if you have a GPU in your cracking machine I highly suggest using Hashcat for it.&#x20;

{% hint style="info" %}
**Tip**: To give hashcat as many resources as you can, you should try to not use it in a VM like Windows Subsystem Linux for example. To make sure it can use your GPU to the fullest run it in your main operating system
{% endhint %}

As seen in [#converting-hash-formats](cracking-hashes.md#converting-hash-formats "mention"), Hashcat cannot always directly read a hash. You might need to convert it to the right format the way it expects. If it cannot recognize the hash correctly you might get a "No hashes loaded." warning.&#x20;

Hashcat does not automatically recognize hash types, but you need to provide a **hash mode** with `-m [mode]` as an argument. To find the correct number to use for your hash you can look at the [example hashes](https://hashcat.net/wiki/doku.php?id=example\_hashes) or use [Name-That-Hash](https://github.com/HashPals/Name-That-Hash) which has RegExes to automatically recognize the hash and give you the hashcat mode.&#x20;

Hashcat also has a few different **attack** **modes** for how to generate the passwords it tries. This is specified using the `-a [mode]` argument. Here are a few attack modes explained:

{% hint style="warning" %}
**Tip**: Hashcat caches results in order to not crack the same hash twice, and can show the found password again using `--show`. If you ever want to **clear** this cache simply remove the `~/.hashcat/hashcat.potfile` file
{% endhint %}

### [Dictionary attack](https://hashcat.net/wiki/doku.php?id=dictionary\_attack)

To simply go through a wordlist for cracking, you can use attack mode 0 (`-a 0`). Then just provide the path to the wordlist after the file containing the hash:

```shell-session
$ hashcat -m 0 hash.txt -a 0 /list/rockyou.txt
```

### [Combinator attack](https://hashcat.net/wiki/doku.php?id=combinator\_attack)

Similar to the Dictionary attack, you can combine two dictionaries to try all combinations of both lists. This could be useful with first and last names for example. Just use attack mode 1 (`-a 1`) and specify 2 wordlists this time.&#x20;

```shell-session
$ hashcat -m 0 hash.txt -a 1 dict1.txt dict2.txt
```

You can make this attack a lot more powerful using [#rules](cracking-hashes.md#rules "mention") to alter the words in the dictionary before guessing them (using the `-j` and `-k` arguments). This way you can mess with uppercase/lowercase, prefixes, suffixes, and a lot more. For an example using the combinator attack with rules see this writeup:

{% embed url="https://jorianwoltjer.com/blog/post/ctf/hacky-holidays-unlock-the-city-2022/stop-the-heist#3-password-cracking" %}
A writeup using the combinator attack with prefixes and suffixes to crack passwords in a CTF{} format
{% endembed %}

### [Mask attack](https://hashcat.net/wiki/doku.php?id=mask\_attack)

The Mask attack is basically just brute force. You can specify a pattern for the password to be in, and it will try all possible combinations of letters/numbers, etc. Using attack mode 3 (`-a 3`), you can write a pattern like `?l?l?l?l?l?l?l?l` to try all lowercase 8-character passwords. There are a few more built-in character sets:

* `?l` = lowercase alphabet (`abcdefghijklmnopqrstuvwxyz`)
* `?u` = uppercase alphabet (`ABCDEFGHIJKLMNOPQRSTUVWXYZ`)
* `?d` = digits (`0123456789`)
* `?s` = special characters (``«space»!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~``)
* `?a` = all of the above (`?l?u?d?s`)
* `?h` = hex lowercase (`0123456789abcdef`)
* `?H` = hex uppercase (`0123456789ABCDEF`)
* `?b` = bytes (`0x00 - 0xff`)

You can even define your own charsets using the `-1` (one) option and then just use the `?1` anywhere in your pattern:

{% code title="Examples" %}
```python
?l?l?l?l?l?l?l?l   => aaaaaaaa - zzzzzzzz  # 8 lowercase characters
-1 ?l?d ?1?1?1?1?1 => aaaaa - 99999  # Define lowercase and digits as charset
password?d         => password0 - password9  # Can put text in mask
-1 ?l?u ?1?l?l?l?l?l19?d?d => aaaaaa1900 - Zzzzzz1999  # 6 characters, can be uppercase and year
-1 ?dabcdef -2 ?l?u ?1?1?2?2?2?2?2 => 00aaaaa - ffZZZZZ  # multiple custom charsets
-1 efghijklmnop ?1?1?1 => eee - ppp  # custom character set
```
{% endcode %}

```shell-session
$ hashcat -m 0 hash.txt -a 3 -1 ?l?u ?1?l?l?l?l?l19?d?d
```

#### Cracking IP addresses

Sometimes an IP address or things like 4-digit codes are hashed that don't have too many possibilities. These are often easy to crack with mask patterns in hashcat. For IP address there is a [ipv4.hcmask](https://pastebin.com/4HQ6C8gG) mask that you can use to crack an IPv4 address in a few minutes. Digit codes can easily be cracked with multiple `?d` charsets.

### [Rules](https://hashcat.net/wiki/doku.php?id=rule\_based\_attack)

Rules in Hashcat are incredibly powerful. There are so many things you can do with them to create any password list you would want.&#x20;

You can quickly use the `-j` argument to write a single rule in the argument. The `'u'` rule for example just makes the password uppercase. Or use something like `'$1$2$3'` to append characters to the end.&#x20;

To see exactly what passwords a rule generated you can use the `--stdout` flag to just print the generated passwords to the terminal instead of cracking anything:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ cat list.txt
</strong>password
secret
root
<strong>$ hashcat --stdout -a 0 -j 'u$1$2$3' list.txt
</strong>PASSWORD123
SECRET123
ROOT123
</code></pre>

Using actual `.rule` files with the `-r` argument you can even specify multiple rules to create lots of passwords quickly:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ cat case.rule
</strong>l
u
<strong>$ cat 123.rule
</strong>$1
$2
$3
<strong>$ hashcat --stdout -r case.rule -r 123.rule list.txt
</strong>password1
PASSWORD1
password2
PASSWORD2
password3
PASSWORD3
secret1
SECRET1
secret2
SECRET2
secret3
SECRET3
root1
ROOT1
root2
ROOT2
root3
ROOT3
</code></pre>

## [John the Ripper](https://github.com/openwall/john)

John the Ripper is a hash-cracking tool that is easy to use. It automatically recognizes hash types and has lots of tools built in to extract hashes from various password-protected files. It's also quick to get started, as not much setup is required. The only downside compared to hashcat is the fact that it's often a bit slower. This doesn't matter when a hash only takes seconds to crack, but it really matters if you're cracking for multiple hours.&#x20;

PentestMonkey has made a list of example hashes for John the Ripper, and how to crack them. Not all hash types are included but a bit of googling should get you there:

{% embed url="https://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats" %}
A list of example hashes with their name and john mode
{% endembed %}

John is pretty specific with its arguments. For a custom wordlist, make sure to use `-wordlist=` with the `=` sign. If you do not include the `=` sign it will give a weird "invalid UTF-8" error. Here is an example of how you should run john:

<pre class="language-shell-session" data-title="Cracking an MD5 hash"><code class="lang-shell-session"><strong>$ cat hash.txt
</strong>5ebe2294ecd0e0f08eab7690d2a6ee69
<strong>$ john --wordlist=/list/rockyou.txt --format=raw-md5 hash.txt 
</strong>Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
secret           (?)
1g 0:00:00:00 DONE (2022-08-18 22:05) 50.00g/s 19200p/s 19200c/s 19200C/s 123456..michael1
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
</code></pre>

### Cracking shadow hashes

The `/etc/shadow` file on Linux contains the password hashes for all users with a password. Normally of course this would only be readable by root, but sometimes you can exploit a vulnerability to read files as root. You could read this file to get the password hashes, and then crack the hashes on your own machine.&#x20;

To get the usernames and other useful information for John, also get the `/etc/passwd` file. We can then use these files with the `unshadow` tool from the `john/run` directory:

```shell-session
$ ~/john/run/unshadow passwd shadow > hashes.txt
```

Then we get a `hashes.txt` file that `john` can read. Just put in your wordlist of choice, and get cracking!

```shell-session
$ john hashes.txt --wordlist=rockyou.txt
```

When it finds a hash, it will output it to the terminal. But if you ever lose it, `john` saves it for you so you can always use `--show` on the hashes file to see what the password was that it found.&#x20;

```shell-session
$ john --show hashes.txt
```

Finally, you can use `su [username]` to log into the user you cracked, and see if you can escalate more with your new privileges.&#x20;

## Cracking Wifi

Packet captures can capture Wifi WEP/WPA handshakes, which can be cracked offline using a tool like [#hashcat](cracking-hashes.md#hashcat "mention"). When you get a `.pcap` file containing 802.11 encrypted data, you can crack the password to decrypt the packets.

### WPA/WPA2 Handshakes

To extract hashes from a `.pcap` file, you can use [this site](https://hashcat.net/cap2hashcat/) or download `hcxtools` yourself:

```shell-session
$ git clone https://github.com/ZerBea/hcxtools && cd hcxtools
$ make
$ make install
```

Then after it's installed, you can use the `hcxpcapngtool` command to extract the handshakes from the capture. Then use hashcat with mode 22000 or 22001 to crack the password:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ hcxpcapngtool capture.pcap -o capture.hashes
</strong><strong>$ cat capture.hashes
</strong>WPA*02*a462a7029ad5ba30b6af0df391988e45*000c4182b255*000d9382363a*436f6865726572*3e8e967dacd960324cac5b6aa721235bf57b949771c867989f49d04ed47c6933*0203007502010a00100000000000000000cdf405ceb9d889ef3dec42609828fae546b7add7baecbb1a394eac5214b1d386000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac020100000fac040100000fac020000*02
<strong>$ hashcat -m 22000 hash.txt list.txt
</strong>...
a462a7029ad5ba30b6af0df391988e45:000c4182b255:000d9382363a:Coherer:Induction
</code></pre>

After you find the password, you can use Wireshark to decrypt the packets (see [#decrypting](../../forensics/wireshark.md#decrypting "mention"))

### WEP

WEP is an old Wifi encryption standard where every device uses the same key. It also happens to be easily crackable with enough traffic. It requires lots of IVs (Initialization Vectors), which can come from lots of normal traffic, or you can manually send specific packets that would trigger IVs to be generated if you have access to the network (see [this tutorial](https://www.aircrack-ng.org/doku.php?id=simple\_wep\_crack)). When you have a packet capture with enough information, you can use [`aircrack-ng`](https://www.aircrack-ng.org/) to quickly find the key:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ aircrack-ng capture.cap
</strong>...
KEY FOUND! [ 1F:1F:1F:1F:1F ]
</code></pre>

After it completes, you can use the key it found (hex format) to decrypt all the traffic (see [#decrypting](../../forensics/wireshark.md#decrypting "mention"))
