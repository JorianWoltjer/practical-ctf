---
description: >-
  An encryption standard using prime number factorization to encrypt and decrypt
  with an asymmetric keypair
---

# RSA

## Description

{% embed url="https://www.di-mgt.com.au/rsa_alg.html#rsasummary" %}
A big description of the whole RSA algorithm, and equations
{% endembed %}

### Symbols

* `n`: Modulus, part of public key
* `p` and `q`: The prime factors of `n`
* `e`: Exponent, part of public key
* `c`: Ciphertext, result after encrypting
* `d`: Decryption exponent, part of the private key
* `m`: Message, plaintext
* $$ϕ$$ or `phi`: Decryption modulus

### Equations

* $$n=pq$$, where $$p$$ and $$q$$ are distinct primes.
* $$ϕ=(p−1)(q−1)$$
* $$e<n$$ such that $$gcd(e,ϕ)=1$$
* $$d=e^{-1} \bmod ϕ$$
  * $$e*d=1 \bmod ϕ$$​
  * $$d_p=d \bmod p-1$$​
    * $$e*d_p=1 \bmod p-1$$
  * $$d_q=d \bmod q-1$$​
    * $$e*d_q=1 \bmod q-1$$​
* $$c=m^e \bmod n$$, where $$1<m<n$$
* $$m=c^d \bmod n$$

### Python

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime

# Create key
e = 0x10001  # 65537
p = getPrime(2048)  # Private
q = getPrime(2048)  # Private
n = p*q  # Public

# Encrypt
m = bytes_to_long(b"Hello, world!")  # String to number
c = pow(m, e, n)  # base, exponent, mod

# Decrypt
phi = (p-1)*(q-1)
d = pow(e, -1, phi)
m = pow(c, d, n)
print(long_to_bytes(m))  # b"Hello, world!"
```

{% hint style="info" %}
RSA is a mathematical cryptosystem that doesn't support strings straight away. That's why we use the `long_to_bytes()` functions here to convert the strings to [#big-integers](../encodings.md#big-integers "mention") first for the calculations, and then back to a string to display the text
{% endhint %}

## [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)

RsaCtfTool has a lot of attacks built-in for common challenges. See [test.sh](https://github.com/RsaCtfTool/RsaCtfTool/blob/master/test.sh) and the `test()` functions in the [attacks](https://github.com/RsaCtfTool/RsaCtfTool/tree/master/attacks) on their GitHub for lots of examples of what inputs an attack needs

### Common options

* `--private`: Display private key if recovered, should always be included
* `--attack`: Specify the attack modes (default: all)
* `-n N`: Specify the modulus (format: int or 0xhex)
* `-e E`: Specify the public exponent, using commas to separate multiple exponents (format: int or 0xhex)
* `--uncipher UNCIPHER`: Uncipher a ciphertext, using commas to separate multiple ciphers
* `--publickey PUBLICKEY`: public key file. You can use comma-separated or wildcards (`*` or `?`) for multiple keys.

## Attacks

A collection of how to exploit attacks on specific RSA cases

### Private key from Public key

This automatically tries many common vulnerabilities in private key generation to guess it:

<pre class="language-shell-session" data-overflow="wrap"><code class="lang-shell-session"><strong>$ rsactftool --publickey key.pub --private
</strong><strong>$ rsactftool -n 22281454606178185475137713421838422701543711268688600199661211611180627857676287178299712404685904372784253912486518309166107347902668817333387309917713878185701525779283063877318406271407207356695157218976821377797726991423192800200038862274192839464396744870595855658571673885678865944463809042500492800193755481497663544377666279577049151233765472181498228853733312890990468820942647689943230580776756954044828448094549187428360616039917736728741158185566675010288835722749075283482869482557110351806822719324373000017117153101570619871972625144670079798850809870562279085243502354929201076164300122928273223973813 -e 65535 --private
</strong></code></pre>

### Factoring manually

The whole security of RSA comes from the difficulty of finding the private factors `p` and `q` that multiply to the public `n`. With huge numbers generated completely randomly, this task is impossible for today's computers. But for smaller numbers or numbers with specific patterns this task may become doable. The method above tries many patterns of primes, but if the **primes are small** we can try to factor them ourselves.&#x20;

First, a good idea is to check if this hasn't been done already. [FactorDB](http://factordb.com/) has a giant database of already factored numbers, some of which are surprisingly big. It does not contain every computable number though, so sometimes you'll want to do it manually. \
One tool that does this very quickly and efficiently is `yafu` ([install](https://github.com/sherlly/blog/blob/master/Install%20yafu%20under%20linux%20environment.md)):

{% embed url="https://github.com/bbuhrow/yafu" %}
Efficiently compute prime factors of a number on your own machine
{% endembed %}

{% code title="Example" %}
```python
from Crypto.Util.number import getPrime
p, q = getPrime(100), getPrime(100)
print(p, q)  # 1098198514732662644984272774739, 1211043850430579966229909607507
n = p*q
print(n)  # 1329966557818987769720263660823856372773218914702069314365673
```
{% endcode %}

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ yafu 'factor(1329966557818987769720263660823856372773218914702069314365673)'
</strong>...
SIQS elapsed time = 2.0392 seconds.
Total factoring time = 3.1806 seconds

***factors found***

<strong>P31 = 1211043850430579966229909607507
</strong><strong>P31 = 1098198514732662644984272774739
</strong></code></pre>

### Small exponent, short plaintext (root)

With a small exponent, the plaintext (`m`) will not be very large after exponentiation. Then after the modulus `n` is applied only a few iterations of `k` will be done, or even none if $$m^e<n$$. This means that we can just iterate over `k` until we find a perfect integer root.

A good indicator of this is when `c` is significantly smaller than `n`. Here's an example where `e=3`, resulting in the equation we can brute-force:

$$
\begin{align*} 
c &= m^3 \bmod n \\
m^3 &= c + n \times k \\
m &= \sqrt[3]{c + n \times k}
\end{align*}
$$

```python
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes, bytes_to_long
import itertools
from tqdm import tqdm  # Progress bar

c = 151814383524468468373167432525334908713043999048030189233295991599282067478160817156274898218736730237867345576036666946129871354139493863328262790965298305504411851013141605494128623445958233929914932221347146103674366602777710563310909991256780496783556246514908319445504257550991303655041040831073499873433
n = 171354491787393121852494841274865993221545603054645652028289158190712035844082220019865456896490374268177490904077197891514585821726394567609038398139385702804697464419303857917065676758998677864936457552536228524298639887223362539820442671452257441601021229295609980653229431658071360735615596125759082670707
e = 3

for k in tqdm(itertools.count()):
    c_before_mod = c + n*k

    if iroot(c_before_mod, e)[1]:  # If perfect root
        break

plaintext = long_to_bytes(iroot(c_before_mod, e)[0])
print(plaintext)
```

### Chinese Remainder Theorem (CRT)

The attack using the [Chinese Remainder Theorom](https://en.wikipedia.org/wiki/Chinese\_remainder\_theorem) is a more powerful version of the $$m^e<n$$ idea from above. Instead, it works when $$m<n$$, and you have $$e$$ amount of different $$c$$'s and $$n$$'s with the same plaintext. So often when the **message isn't too long** (no padding) and you have **multiple ciphertexts and public keys**, you can use this attack.&#x20;

Let's say that in RSA you use $$e=3$$ (can be any exponent just requires more samples). Then you would need **3** ciphertext and public key examples. The equations for this would look like this:

$$
\left\{ \begin{array}{ll} c_1 = & m^3\mod n_1 \\ c_2 = & m^3\mod n_2 \\ c_3 = & m^3\mod n_3 \\ \end{array} \right.
$$

Then we can use the idea of CRT which says using:

$$
\left\{ \begin{array}{ll} c_1 = & x\mod n_1 \\ c_2 = & x\mod n_2 \\ c_3 = & x\mod n_3 \\ \end{array} \right.
$$

where you know $$c_1, c_2, c_3$$ and $$n_1, n_2, n_3$$, you can find $$x$$ efficiently. In the case of RSA, this would be $$m^3$$, and then we can simply get the cube root to find $$m$$ and we have cracked the message. ([source](https://crypto.stackexchange.com/a/55944))

{% hint style="info" %}
**Note**: The CRT actually gives:

$$x = m^3\mod n_1\times n_2\times n_3$$\
This is why $$m$$ has to be less than $$n$$, otherwise this modulus will have wrapped around and you would have to guess how many times this has been done. If it's barely too large you might be able to brute-force this $$k$$ value, but otherwise, it will take too much computation
{% endhint %}

An example implementation for this attack would be:

```python
from Crypto.Util.number import bytes_to_long, getPrime
from functools import reduce
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes
from tqdm import tqdm

FLAG = b"CTF{f4k3_fl4g_f0r_t3st1ng}"
E = 257

def get_encrypted():
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    
    m = bytes_to_long(FLAG)
    c = pow(m, E, n)

    return c, n, E

# Attack

def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * mul_inv(p, n_i) * p
    return sum % prod

def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1: return 1
    while a > 1:
        q = a // b
        a, b = b, a%b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += b0
    return x1

cs = []
ns = []
for i in tqdm(range(E), desc="Generating"):
    c, n, e = get_encrypted()
    
    cs.append(c)
    ns.append(n)

x = chinese_remainder(ns, cs)
m = iroot(x, E)
print(m)
print(long_to_bytes(m[0]))
```

Here `get_encrypted()` is a simple RSA implementation with a high enough `e=257` that a simple root of the ciphertext won't work. But using the CRT you can get 257 different samples and compute `x`, to finally get `m`.&#x20;

This script runs for about 40 seconds, but for `e=65537` and 1024-bit primes, it would take about 10 hours. The biggest bottleneck here is generating the primes by the "server", as this can take around a second for 1024-bit primes. When we need 65537 samples this really adds up, but in a real-world scenario, 10 hours is very doable.&#x20;

### Coppersmith's Attack

The small exponent attack explained in the earlier [root](rsa.md#small-exponent-short-plaintext) section **only works when the plaintext is short**. That is why there is another attack that requires any of the following information:

* A part of the plaintext ([#stereotyped-messages](rsa.md#stereotyped-messages "mention"))
* High bits of either `p` and `q` primes ([writeup](https://amritabi0s.wordpress.com/2019/03/18/confidence-teaser-ctf-crypto-writeups/))

The technique involves quite a bit of math, being a result of Lattice Reduction (LLL). A great page with some details and resources about the specifics of the Coppersmith's attack is [this GitHub repository by ashutosh1206](https://github.com/ashutosh1206/Crypton/tree/master/RSA-encryption/Attack-Coppersmith).&#x20;

#### Stereotyped Messages

For this type of attack, we need to know a **part of the start** of the plaintext. An example of such a challenge would be the following (also see [this writeup](https://ctftime.org/writeup/10431)):

{% code title="Challenge" %}
```python
from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime

# Plaintext
flag = b"CTF{f4k3_fl4g_f0r_t3st1ng}"  # [REDACTED]
assert len(flag) == 26
m = bytes_to_long(b"This text is known. We'll use it to perform the Coppersmith's attack. Here's the secret flag: " + flag)

# Generate key
e = 3  # Small e
p = getPrime(512)  # Secure random primes
q = getPrime(512)
n = p*q
print(f"{n=}")  # n=100327967615765455066432131459361990250708753607333235195396044112959692871544110349814828608845716258088261033059120367626020028506475238904444366037162531628517305056808743166564074785466919977046747694732610541698197389485408333767339588904126857437470803627457816584759208958972799096606448918221245435269

c = pow(m, e, n)  # Encrypt
print(f"{c=}")  # c=41779631873918536705147834958361623514512917846121113398008031115793138940292445032649979745012468108251030582291719772740281680895336323197312942057440995386864999859489683117696716440779630814117695405320029822373894489891535401454333570161682797618800372458217584598699177209637329147391505835747079254848
```
{% endcode %}

To verify we can use this attack to efficiently recover the plaintext we need to make sure that: $$n^{1/e} > \mathit{difference}$$. Where this difference is between the plaintext and your guess of the plaintext. If you know a significant part of the start of a plaintext this difference will be small enough to satisfy the condition. It also means that the smaller `e` is, the larger the upper bound for the difference, and the less plaintext we need to know. We can do a sanity check in Python like this:

{% code title="Sanity check" %}
```python
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes, bytes_to_long

n = 100327967615765455066432131459361990250708753607333235195396044112959692871544110349814828608845716258088261033059120367626020028506475238904444366037162531628517305056808743166564074785466919977046747694732610541698197389485408333767339588904126857437470803627457816584759208958972799096606448918221245435269
plaintext = bytes_to_long(b"This text is known. We'll use it to perform the Coppersmith's attack. Here's the secret flag: " + b"CTF{f4k3_fl4g_f0r_t3st1ng}")
guess     = bytes_to_long(b"This text is known. We'll use it to perform the Coppersmith's attack. Here's the secret flag: " + b"CTF{XXXXXXXXXXXXXXXXXXXXX}")

upper_bound = int(iroot(n, 3)[0])  # n^(1/e)
assert upper_bound > abs(plaintext-guess)  # True: Attack can be used (4646657599085420719632980191748083535931530837393872023845638304709112678027902981558510765889796299593 > 5185515455561693213705816661216384501404499996708608)
```
{% endcode %}

In this example, the XXX is small enough that we can use this attack to efficiently recover the plaintext. We can use [SageMath](https://www.sagemath.org/) to do some mathematical magic and compute possible differences, which is Coppersmith's attack. We can even try multiple lengths of the unknown text because this attack only takes a few seconds:

{% code title="Attack" %}
```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from tqdm import tqdm

n = 100327967615765455066432131459361990250708753607333235195396044112959692871544110349814828608845716258088261033059120367626020028506475238904444366037162531628517305056808743166564074785466919977046747694732610541698197389485408333767339588904126857437470803627457816584759208958972799096606448918221245435269
c = 41779631873918536705147834958361623514512917846121113398008031115793138940292445032649979745012468108251030582291719772740281680895336323197312942057440995386864999859489683117696716440779630814117695405320029822373894489891535401454333570161682797618800372458217584598699177209637329147391505835747079254848
e = 3

for flag_length in tqdm(range(25, 30), desc="Length"):  # Try different lengths
    unknown = b"\x00"*flag_length  # Unknowns replaced with \x00
    m_guess = bytes_to_long(b"This text is known. We'll use it to perform the Coppersmith's attack. Here's the secret flag: " + unknown)

    # Coppersmith's attack
    P.<x> = PolynomialRing(Zmod(n), implementation='NTL')
    pol = (m_guess + x)^e - c
    roots = pol.small_roots(epsilon=1/30)
    
    for root in roots:  # Find possible differences
        tqdm.write(f"{flag_length}: {long_to_bytes(int(m_guess+root))} ({root})")

# 26: b"This text is known. We'll use it to perform the Coppersmith's attack. Here's the secret flag: CTF{f4k3_fl4g_f0r_t3st1ng}" (108193853725429410694302373498305388100215459547699917544646525)
```
{% endcode %}

### Euclidean Algorithm

The [Euclidean Algorithm](https://en.wikipedia.org/wiki/Euclidean\_algorithm) is originally an algorithm for efficiently computing the Greatest Common Divisor (GCD) for two numbers. If this answer is `1`, it means the numbers don't share any factors, which may be important in some cryptosystems.&#x20;

There is also the Extended Euclidean Algorithm that can do a lot more. It can find two new numbers, that when multiplied with their respective numbers and added, equal the greatest common divisor. This is especially useful when the numbers are coprime, meaning the GCD is equal to 1. Then you can rearrange the equation to have something useful in modular arithmetic. In the example below, $$a$$ and $$b$$ would be the inputs, and the Extended Euclidean Algorithm finds $$s$$ and $$t$$:

$$
\begin{align*} 
as + bt & = \gcd(a, b)\\
as + bt & = 1\\
as & = 1 - bt\\
as & = 1 \mod{b}\\
\end{align*}
$$

This last line is how we get the multiplicative inverse in RSA, used to generate the value of `d`. ​But in custom schemes similar to RSA, this may be exploitable. When working with $$\bmod\text{ }b$$ it may be possible to reduce some arguments to 1 like above.&#x20;

#### Reverse of Modulo Multiplication

Here is an example of using this knowledge to break a flawed cryptosystem. Let's say it uses two random numbers that multiply together, and after the modulus is applied, you get the answer. In this example you have only one of the factors, the modulus, and the result, you want to calculate the other factor that was used.&#x20;

```python
(x * a) % b = c
# We have: x, b, c
# Want to know: a
```

In normal arithmetic without a modulus, this would be easy. Just divide the answer by the factor you know, to get the other one. When in modular arithmetic, this is a bit harder. The answer might have wrapped around to another iteration of the modulus. With big numbers, just brute-forcing this takes way too long. That is where the Extended Euclidean Algorithm comes in. As explained in [this math exchange answer](https://math.stackexchange.com/a/684564), it tells us we can get a number $$s$$ that when multiplied with $$a$$, becomes $$1 \bmod b$$. So in our original equation, we can just multiply by this $$s$$ to get a nice equation for calculating $$x$$ with only variables we know:

$$
\begin{align*}
x * a &= c \mod{b}\\
x * a * s &= c * s \mod{b}\\
x * 1 &= c * s \mod{b}\\
x &= c * s \mod{b}\\
\end{align*}
$$

​So this finally means we have an efficient way of calculating the other factor we wanted. In code, it would look something like this:

```python
from egcd import egcd

# (x * a) % b = c
#  ^

gcd, s, t = egcd(a, b)  # Extended Euclidean Algorithm
assert gcd == 1

x = c * s % b  # Derived equation for x
```

### Redacted Private Key

Sometimes you'll find part of a private key or a partially redacted screenshot for example. In some cases, there is still enough information in the redacted key that we can recover the entire private key. A good example is [this writeup from Cryptohack](https://blog.cryptohack.org/twitter-secrets).&#x20;

Often you'll find the private key in the PEM format:

```
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----
```

This format encodes a few numbers that RSA uses in the following order:

```sql
RSAPrivateKey ::= SEQUENCE {
  version           Version,
  modulus           INTEGER,  -- n
  publicExponent    INTEGER,  -- e
  privateExponent   INTEGER,  -- d
  prime1            INTEGER,  -- p
  prime2            INTEGER,  -- q
  exponent1         INTEGER,  -- d_p = d mod (p-1)
  exponent2         INTEGER,  -- d_q = d mod (q-1)
  coefficient       INTEGER,  -- (inverse of q) mod p
  otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
```

When the key is decoded from Base64, the raw data is split by ASN.1 headers. These differ per private key but are in a simple format. For example `02 82 01 01`:

* `02`: The data type: Integer
* `82`: Meaning the length of the encoded integer value will be stored in the following 2 bytes
* `0101`: The length of the integer value that follows. Taking this value (257) and reading the next 257 from Big Endian results in the number

You can then search the redacted private key for these header values and find parts of the private key. Then after writing down every number you have found, you can try to use the RSA [#equations](rsa.md#equations "mention") to calculate or brute-force unknown values.&#x20;

You might find the $$d_p$$ value and `q`, but no `n` as seen in the writeup linked above. In that case, we know some equations, and we can find `p` having only one unknown:

$$
\begin{align*} 
d_p = d \bmod p-1 \\
e*d_p = 1 \bmod p-1 \\
e*d_p = 1+k_p(p−1) \\
p = \frac{e*d_p-1}{k_p}+1
\end{align*}
$$

Here $$k_p < e$$ meaning we can easily brute-force it until we get a valid `p` that is prime.&#x20;

```python
from Crypto.Util.number import isPrime

e = 65537
q = 0xc28871e8714090e0a33327b88acc57eef2eb6033ac6bc44f31baeac33cbc026c3e8bbe9e0f77c8dbc0b4bfed0273f6621d24bc1effc0b6c06427b89758f6d433a02bf996d42e1e2750738ac3b85b4a187a3bcb4124d62296cb0eecaa5b70fb84a12254b0973797a1e53829ec59f22238eab77b211664fc2fa686893dda43756c895953e573fd52aa9bb41d22306135c81174a001b32f5407d4f72d80c5de2850541de5d55c19c1f817eea994dfa534b6d941ba204b306225a9e06ddb048f4e34507540fb3f03efeb30bdd076cfa22b135c9037c9e18fe4fa70cf61cea8c002e9c85e53c1eaac935042d00697270f05b8a7976846963c933dadd527227e6c45e1
d_p = 0x878f7c1b9b19b1693c1371305f194cd08c770c8f5976b2d8e3cf769a1117080d6e90a10aef9da6eb5b34219b71f4c8e5cde3a9d36945ac507ee6dfe4c146e7458ef83fa065e3036e5fbf15597e97a7ba93a31124d97c177e68e38adc4c45858417abf8034745d6b3782a195e6dd3cf0be14f5d97247900e9aac3b2b5a89f33a3f8f71d27d670401ca185eb9c88644b7985e4d98a7da37bfffdb737e54b6e0de2004d0c8c425fb16380431d7de40540c02346c98991b748ebbc8aac73dd58de6f7ff00a302f4047020b6cd9098f6ba686994f5e043e7181edfc552e18bce42b3a42b63f7ccb7729b74e76a040055d397278cb939240f236d0a2a79757ba7a9f09

for k_p in range(3, e):
    p_mul = d_p * e - 1
    if p_mul % k_p == 0:
        p = (p_mul // k_p) + 1
        if isPrime(p):
            print(f"Possible p: {p}")

# Possible p: 27424620168275816399297809452044477898445869043083928305403190561848181247448557658593857562389973580360112343197758188112451321934751365149355739718827334237004580631677805658180827450425037486862624956571004133160660553447844660253489608830574578247130997606552780186884875956837105323963951273120671578260037968554324775219655391384842262185092080897722729583541520288238199378137937292821948537290086006515948412691425793388343550817692412524057095996025193588558531233775036475712447358021159753894894021532314644572789928387689536798350947404591354707156502434749956591501101436381621117178639848984726819742457
```

Now we have `p` and `q`, and can easily multiply them to get `n`. We can also now calculate `d` from `p` and `q` to get the decryption key.&#x20;

If you get multiple possible values for `p`, you could use some partial numbers in the redacted private key to verify each possible value. If you have some bits of the `n` for example, you could calculate `n` and then verify it with the known bits.&#x20;

### No modulus (`n`)

If exponent `e` is small, the ciphertext might not have wrapped around with the modulus and you can just root it to get the original plaintext. You can verify this by checking if the ciphertext is a perfect root.

```python
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes, bytes_to_long

c = bytes_to_long(bytes.fromhex("04a842294fd232f363404d984a463f265938e591c4be8370c332e9c8f3b4c5216c8691920326b600619525e1e1eee7dd88220e0d5863c20bcbc3406bf0588e73a8b1db198ff84f9b1c91a9eaaa65"))
e = 3

root, is_perfect = iroot(c, e)  # Cube root
assert is_perfect

print(long_to_bytes(root))
```

#### Known plaintext

If you have 2 plaintext-ciphertext pairs, you can recover N with some math:

$$
\begin{align*}
m_1^e &= c_1 \bmod n \\
m_2^e &= c_2 \bmod n \\
&\Downarrow \\
m_1^e - c_1 &= k_1*n \\
m_2^e - c_2 &= k_2*n \\
\end{align*}
$$

Here the last two equations both have `n` multiplied by some different `k`. The product of $$k*n$$ can be easily calculated as the difference between $$m^e$$ and $$c$$, which we know from the plaintext-ciphertext pairs. This means we know two different numbers, which have `n` as a factor. We can use the Greatest Common Divisor (GCD) to calculate this common factor `n`. [Sagemath](https://www.sagemath.org/) has a very fast implementation for the power and GCD:

{% code title="find_n.sage" %}
```python
from Crypto.Util.number import bytes_to_long, long_to_bytes

m1 = bytes_to_long(b"You can't factor the modulus")
c1 = 4249729541274832324831915101850978041491970958978013333892918723306168770472089196478720527554982764987079625218029445015042835412969986610407794962546486526768377464483162272541733624521350257458334912357961557141551376502679112069746250223130120067678503609054343306910481618502449487751467838568736395758064426403381068760701434585433915614901796040740316824283643177505677105619002929103619338876322183416750542848507631412106633630984867562243228659040403724671325236096319784525457674398019860558530212905126133378508676777200538275088387251038714220361173376355185449239483472545370043145325106307606431828449482078191
m2 = bytes_to_long(b"If you don't know the modulus!")
c2 = 13075855845498384344820257559893309320125843093107442572680776872299102248743866420640323500087788163238819301260173322187978140866718036292385520509724506487692001245730298675731681509412177547061396861961413760298064385526657135656283464759479388590822600747903100354135682624356454872283852822117199641700847558605700370117557855396952083088645477966782338316017387406733063346986224014837246404581562813312855644424128648363175792786282857154624788625411070173092512834181678732914231669616670515512774709315620233482515821178277673737845032672993814500177126048019814877397547310166915188341668439101769932492677363463422
e = 65537

n = GCD(pow(m1, e) - c1, pow(m2, e) - c2)
print(f"{n=}")  # 34825223743402829383680359547814183240817664070909938698674658390374124787235739502688056639022131897715513587903467527066065545399622834534513631867145432553730850980331789931667370903396032758515681278057031496814054828419443822343986117760958186984521716807347123949922837482460532728350223473430713058522361175980521908817215812291272284241848086260180382693014713901303747444753828636575351349026883294939561001468099252543181336195746032718177937417431101756313823635150129601855358558635996348271242920308406268552606733676301725088348399264293936151662467456410825402303921583389167882090767423931762347825907802328053
```
{% endcode %}

### 2 keys: Same n, same ciphertext, different e

{% embed url="https://crypto.stackexchange.com/questions/1614/rsa-cracking-the-same-message-is-sent-to-two-different-people-problem/1616#1616" %}
Answer to Cryptography Stack Exchange post explaining solution
{% endembed %}

{% hint style="info" %}
Use the comma (`,`) to separate `-e` and `--uncipher` values
{% endhint %}

<pre class="language-shell-session" data-title="Using RsaCtfTool" data-overflow="wrap"><code class="lang-shell-session"><strong>$ rsactftool -n 121785996773018308653850214729611957957750585856946607620398279656647965006857599756926384863459274369411103073349913717154710735727786240206066327436155758154142877120260776520601315370480059127244029804523614658953301573686851312721445206131147094674807765817210890772194336025491364961932882951123597124291 -e 65537,343223 --uncipher 5050983197907648139720782448847677677343236446273586870502111273113384857588837608900494692102715861436825279596563904392832518247929761994240007673498974877828278590361242528762459283022987952424770766975922016521475963712698089809426428406068793291250622593222599407825968002220906973019105007856539702124,99993713982446651581396992055360571139557381122865583938229634474666415937105325664345678113405954865343401854091338680448775405253508255042453184099961570780032181898606546389573694481401653361757628850127420072609555997892925890632116852740542002226555293049123266123721696951805937683483979653786235824108
</strong>[*] Multikey mode using keys: /tmp/tmpk3mwiuve, /tmp/tmpuaraslbe
Unciphered data :
STR : b'Yeah man, you got the message. The flag is W311D0n3! and this is a padding to have a long text, else it will be easy to decrypt.'
</code></pre>

{% code title="Python implementation" %}
```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
from egcd import egcd

# Same n
n = 121785996773018308653850214729611957957750585856946607620398279656647965006857599756926384863459274369411103073349913717154710735727786240206066327436155758154142877120260776520601315370480059127244029804523614658953301573686851312721445206131147094674807765817210890772194336025491364961932882951123597124291 
e1 = 65537
e2 = 343223

c1 = 5050983197907648139720782448847677677343236446273586870502111273113384857588837608900494692102715861436825279596563904392832518247929761994240007673498974877828278590361242528762459283022987952424770766975922016521475963712698089809426428406068793291250622593222599407825968002220906973019105007856539702124
c2 = 99993713982446651581396992055360571139557381122865583938229634474666415937105325664345678113405954865343401854091338680448775405253508255042453184099961570780032181898606546389573694481401653361757628850127420072609555997892925890632116852740542002226555293049123266123721696951805937683483979653786235824108

gcd, a, b = egcd(e1, e2)
assert gcd == 1, "e1 and e2 are coprime"

m = pow(c1, a, n) * pow(c2, b, n) % n

print(long_to_bytes(m))
```
{% endcode %}

### Multiple keys with common factors

<pre class="language-shell-session" data-overflow="wrap"><code class="lang-shell-session"><strong>$ rsactftool --publickey key1.pub,key2.pub,key3.pub --private --attack common_factors
</strong><strong>$ rsactftool --publickey "key*.pub" --private --attack common_factors
</strong></code></pre>

## Converting keys

Formats of RSA keys can be tricky. Here are a few common ways to convert public/private keys into other useful formats

{% embed url="https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html" %}
Documentation explaining how to work with RSA keys in PyCryptodome
{% endembed %}

### `n` and `e` to any file format

{% code title="Using PyCryptodome" overflow="wrap" %}
```python
>>> from Crypto.PublicKey import RSA
>>> key = RSA.construct((22281454606178185475137713421838422701543711268688600199661211611180627857676287178299712404685904372784253912486518309166107347902668817333387309917713878185701525779283063877318406271407207356695157218976821377797726991423192800200038862274192839464396744870595855658571673885678865944463809042500492800193755481497663544377666279577049151233765472181498228853733312890990468820942647689943230580776756954044828448094549187428360616039917736728741158185566675010288835722749075283482869482557110351806822719324373000017117153101570619871972625144670079798850809870562279085243502354929201076164300122928273223973813, 65535))  # (n, e, d, p, q)
>>> with open("key.pub", "wb") as f:
>>>     f.write(key.export_key("PEM"))  # 'PEM', 'DER' or 'OpenSSH'
```
{% endcode %}

<pre class="language-shell-session" data-title="Using RsaCtfTool" data-overflow="wrap"><code class="lang-shell-session"><strong>$ rsactftool --createpub -n 22281454606178185475137713421838422701543711268688600199661211611180627857676287178299712404685904372784253912486518309166107347902668817333387309917713878185701525779283063877318406271407207356695157218976821377797726991423192800200038862274192839464396744870595855658571673885678865944463809042500492800193755481497663544377666279577049151233765472181498228853733312890990468820942647689943230580776756954044828448094549187428360616039917736728741158185566675010288835722749075283482869482557110351806822719324373000017117153101570619871972625144670079798850809870562279085243502354929201076164300122928273223973813 -e 65535 --private
</strong>-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsIDMbcVpE90iK0Omtkww
8XXNbuuWczKPXJi0+3NXVQHyRITITnVd/EIoPxqYCloxebCowFx5xjnu+Vo+gM5C
KYzbOznGMkYlCj5AmXV1+a6hMErL7+Qsth/12ghUhgMMMjshA+ZRPu6tJ1d7H7Ho
ge3zOPvkHnfNIxIcHQI43GYJURWNQ2Mij+h3CF25P1ictf+/Uijdfa1wk+3PLtTy
jRMcP7IOWdWUloPowu/vCUgKe/Qq0+WINNi/Uf1MaXBTq+4fUTPzXrVBGxQ6DYMj
ysHw9wxgZCYijLeIrJdIL7DPkaYVadv+pzLhKWAsigEdzbVI0mjjDnlc/QoL9g37
tQIDAP//
-----END PUBLIC KEY-----
</code></pre>

### Any file format to `n` and `e`

{% code title="Using PyCryptodome" overflow="wrap" %}
```python
>>> from Crypto.PublicKey import RSA
>>> RSA.importKey(open("key.pub", "rb").read())
RsaKey(n=22281454606178185475137713421838422701543711268688600199661211611180627857676287178299712404685904372784253912486518309166107347902668817333387309917713878185701525779283063877318406271407207356695157218976821377797726991423192800200038862274192839464396744870595855658571673885678865944463809042500492800193755481497663544377666279577049151233765472181498228853733312890990468820942647689943230580776756954044828448094549187428360616039917736728741158185566675010288835722749075283482869482557110351806822719324373000017117153101570619871972625144670079798850809870562279085243502354929201076164300122928273223973813, e=65535)
```
{% endcode %}

<pre class="language-shell-session" data-title="Using RsaCtfTool" data-overflow="wrap"><code class="lang-shell-session"><strong>$ rsactftool --dumpkey --publickey key.pub --private
</strong>Details for key.pub:
n: 22281454606178185475137713421838422701543711268688600199661211611180627857676287178299712404685904372784253912486518309166107347902668817333387309917713878185701525779283063877318406271407207356695157218976821377797726991423192800200038862274192839464396744870595855658571673885678865944463809042500492800193755481497663544377666279577049151233765472181498228853733312890990468820942647689943230580776756954044828448094549187428360616039917736728741158185566675010288835722749075283482869482557110351806822719324373000017117153101570619871972625144670079798850809870562279085243502354929201076164300122928273223973813
e: 65535
</code></pre>
