---
description: >-
  Some examples of signature implementations (often HMAC) that can be cracked
  using hashcat
---

# Cracking Signatures

{% hint style="info" %}
See [#hashcat](cracking-hashes.md#hashcat "mention") for general information on how to use `hashcat`, this page explains some practical usages in relation to signatures which are often used in cookies to authenticate users
{% endhint %}

## JSON Web Token (JWT)

JSON Web Tokens are strings of Base64-encoded data signed using some secret key. This means the client can store and read the data inside of this token, but they cannot change it without knowing the correct signing key. Only the server should be able to generate these tokens for you in a secure scenario.&#x20;

{% embed url="https://jwt.io/" %}
An interactice JWT playground to decode and encode tokens
{% endembed %}

The fact that we know the plaintext data, and everything is stored on the client, means that it is inherently vulnerable to brute-force attacks. We can guess many different signing keys to find when it aligns with the expected signature, which is exactly what we will use hashcat for.&#x20;

There are multiple different algorithms for signing the data, which is always given by the `"alg"` value in the header of the token. Two of the most common are:

* **HS256**: HMAC (with SHA256) using a **password** as a secret
* **RS256**: RSA (with SHA256) using a cryptographic **private key**

RSA is _not_ easily brute-forced without a weak key, or some other special vulnerability in the generated key. Because of this, only the HMAC version is viable for brute-forcing with a password dictionary in hashcat. Luckily, this is a well-known algorithm used in many other places and is implemented in a pretty simple way for JWTs.&#x20;

Let's take the following simple example:

{% code title="JSON Web Token" overflow="wrap" %}
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o
```
{% endcode %}

Hashcat has a special JWT mode (`-m 16500`) that automatically extracts the payload and signature to create a simple HMAC input/output which can run at very high speeds (`~500 MH/s` on my laptop). It even auto-detects this mode for us, meaning we only need to provide the hash and how passwords should be generated:

<pre class="language-shell-session" data-overflow="wrap"><code class="lang-shell-session"><strong>$ hashcat eyJhbGciOiJIUzI1NiIsInR5cC...zWXcXNrz0ogtVhfEd2o /list/rockyou.txt
</strong>
hashcat starting in autodetect mode
16500 | JWT (JSON Web Token) | Network Protocol
...
eyJhbGciOiJIUzI1NiIsInR5cC...zWXcXNrz0ogtVhfEd2o:secret
</code></pre>

Now that we know the password, we can use the [debugger site](https://jwt.io/) to forge any new data. Simply input your original JWT, and set the secret where it says "your-256-bit-secret", which should now make a "Signature Verified" checkmark appear. At this point, you can change any data in the Payload section to forge other users' data, perform deeper injections, or anything else you can imagine.&#x20;

### Custom HMAC

A developer might use a less-known HMAC function to sign their JWTs, which hashcat may not be able to parse for you directly. In these cases, it is a matter of extracting the useful information manually, and then using lower-level hashcat modes to crack the secret.&#x20;

Imagine an **MD5** HMAC for example:

<pre class="language-json" data-title="JSON Web Token"><code class="lang-json"><strong>eyJhbGciOiAiTUQ1X0hNQUMifQ.eyJ1c2VybmFtZSI6ICJqMHIxYW4ifQ.yKcA62pVJ8Pij7SajzE8nw
</strong>
{
  "alg": "MD5_HMAC"
}
...
</code></pre>

An HMAC signature works using some data as the payload, and a key which is the password. In JWT this is implemented in the following way:

```renpy
[hash]_HMAC(
  urlsafe_base64encode(header) + "." +
  urlsafe_base64encode(payload),
  secret
)
```

The `header` and `payload` are both urlsafe-Base64 encoded, and joined together by a `.` period. This is the raw data provided to the HMAC function, together with the `secret` which is often just put in raw, but could in some cases also be Base64 encoded.&#x20;

Inside the JWT, the header and payload are already put in the right format, being the part before the second period (`eyJhbGciOiAiTUQ1X0hNQUMifQ.eyJ1c2VybmFtZSI6ICJqMHIxYW4ifQ`). Then the last part is the signature, meaning the result of the HMAC function. It is Base64 encoded while hashcat expects it as **hex** like a regular hash. This means we just have to convert this last part to hex to get a string it understands:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ echo yKcA62pVJ8Pij7SajzE8nw | base64 -d | xxd -p
</strong>c8a700eb6a5527c3e28fb49a8f313c9f
</code></pre>

Finally, we have all the parts we need, and can write out the hash in the way hashcat expects:

```
<signature>:<data>
c8a700eb6a5527c3e28fb49a8f313c9f:eyJhbGciOiAiTUQ1X0hNQUMifQ.eyJ1c2VybmFtZSI6ICJqMHIxYW4ifQ
```

Then we simply use the raw HMAC-MD5 (`-m 50`) mode in hashcat to crack the secret like before:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ hashcat -m 50 hash2.txt /list/rockyou.txt
</strong>...
c8a700eb6a5527c3e28fb49a8f313c9f:eyJhbGciOiA...IxYW4ifQ:secret
</code></pre>

### Manually Forging

When we have a secret key, we can try to forge new data with it by implementing the algorithm in a simple script. There are many easy libraries that do most of the work already, so it is simply a matter of understanding the required steps. For JWTs:

1. First the `header` and `payload` JSON data is encoded into a string, and are separately Base64 encoded, which are then joined together by `.` period
2. An HMAC signature is made by putting the data from step 1 in the data argument, and the secret in the key argument, selecting the correct hash function (MD5, SHA256, etc.)
3. This resulting signature is Base64 encoded and appended together with a `.` in front to the header and payload value from step 1, which becomes the resulting JWT

Putting this into code, it looks something like this:

{% code title="Python" %}
```renpy
import hmac
from base64 import urlsafe_b64encode
import json

KEY = b"secret"
HASH = "md5"

header = {
  "alg": "MD5_HMAC"
}
payload = {
  "username": "admin"
}

headers_enc = urlsafe_b64encode(json.dumps(header).encode()).decode().strip("=")
payload_enc = urlsafe_b64encode(json.dumps(payload).encode()).decode().strip("=")

data = f"{headers_enc}.{payload_enc}"
signature = urlsafe_b64encode(hmac.new(KEY, data.encode(), digestmod=HASH).digest()).decode().strip("=")

print(f"{data}.{signature}")
# eyJhbGciOiAiTUQ1X0hNQUMifQ.eyJ1c2VybmFtZSI6ICJqMHIxYW4ifQ.yKcA62pVJ8Pij7SajzE8nw
```
{% endcode %}

In this way, you can generate any type of signature for your JWT after cracking it, regardless of if the [online debugger](https://jwt.io/) has it.&#x20;

## Flask Session

{% hint style="info" %}
See the [#brute-force](../../web/web-frameworks/flask.md#brute-force "mention") section for Flask Session Cookies. An all-in-one tool can crack it for you, or use hashcat to do so much faster
{% endhint %}

## `cookie-session` from Express (`session.sig=`)

{% hint style="warning" %}
See [this writeup](https://vihan.org/write-ups/insomnihack-2020/#secretus) for an example using `express-session` instead, which looks like:\
`s:lkdh18zhtZX-vve8gThP8_NEoTkr-OsT.T4zrDEc9N2RbIViBsst5ZlWo1DfWL`

(recognizable by the `s:` prefix)
{% endhint %}

The [`cookie-session`](https://github.com/expressjs/cookie-session) library from the NodeJS Express framework is a common way of managing sessions. Similarly to JWTs and Flask Sessions, it also stores data on the client together with a signature that prevents it from being changed using HMAC. We simply have to adapt the HMAC function to use a different hash and alter the input format.&#x20;

The information is split into the data as `session=` and the signature as `session.sig=`. For example:

```http
Cookie: session=eyJ1c2VybmFtZSI6ICJqMHIxYW4ifQ; session.sig=eORsWVeMDsGGRNp-QK-sbzHp8as
```

From a test [here](https://github.com/pillarjs/cookies/blob/master/test/test.js#L26-L28) we can find that the `cookies` library uses another library named [Keygrip](https://github.com/crypto-utils/keygrip/blob/master/index.js#L21-L28) with the default configuration to generate this signature from data and a key. The implementation is simply another HMAC this time using SHA1, and the data is the cookie data, meaning `"session=eyJ1c2VybmFtZSI6ICJqMHIxYW4ifQ"` with whatever the payload is. Lastly, the signature is encoded in Base64 again, we need to decode and encode it to hex for hashcat to understand:

<pre class="language-python"><code class="lang-python">>>> from base64 import urlsafe_b64decode
<strong>>>> urlsafe_b64decode(b'eORsWVeMDsGGRNp-QK-sbzHp8as' + b"==").hex()
</strong>'78e46c59578c0ec18644da7e40afac6f31e9f1ab'
</code></pre>

Knowing this we can easily create a hashcat hash in this format (note that `session=` may be different depending on your cookie name):

{% code title="hash.txt" %}
```
78e46c59578c0ec18644da7e40afac6f31e9f1ab:session=eyJ1c2VybmFtZSI6ICJqMHIxYW4ifQ
```
{% endcode %}

Finally, we can use the HMAC-SHA1 mode (`-m 150`) to crack it:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ hashcat -m 150 hash.txt /list/rockyou.txt
</strong>...
78e46c59578c0ec18644da7e40afac6f31e9f1ab:session=eyJ1c2VybmFtZSI6ICJqMHIxYW4ifQ:secret
</code></pre>

Now that the secret key is found, we can forge any cookie payload with a valid signature:

```python
import hmac
from base64 import urlsafe_b64encode
from hashlib import sha1
import json

def sign(data, key):
    signature = hmac.new(key, data, sha1)
    signature_enc = urlsafe_b64encode(signature.digest()).rstrip(b"=")
    return signature_enc

SECRET = b"secret"
payload = {"username": "j0r1an"}

data = b'session=' + urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
signature = sign(data, SECRET)

print(data)  # b'session=eyJ1c2VybmFtZSI6ICJqMHIxYW4ifQ'
print(b'session.sig=' + signature)  # b'session.sig=eORsWVeMDsGGRNp-QK-sbzHp8as'
```
