---
description: >-
  A legacy authentication protocol for Active Directory with many flaws and
  dangers
---

# NTLM

### LM vs NT vs NTLM

{% embed url="https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4" %}
Article explaining the mess that is all the different NTLM hashes
{% endembed %}

#### LM-hashes

LM-hashes is the first password storage in Windows, being used in old versions (prior to Windows NT) and were prevalent in Windows 95, 98, and Me. It was disabled by default starting in Windows Vista/Server 2008. \
However, it is still possible to enable them in newer versions [through a GPO setting](https://learn.microsoft.com/en-US/troubleshoot/windows-server/windows-security/prevent-windows-store-lm-hash-password). When dumping the SAM/NTDS database they are shown together with [#nt-hashes](ntlm.md#nt-hashes "mention").

These hashes were very primitive, and generated as follows (see [this answer](https://stackoverflow.com/a/76738476/10508498)):

1. Convert all lowercase to **uppercase**
2. Pad password to exactly 14 characters with NULL characters
3. Split the password into two 7-character chunks
4. Create two DES keys from each 7-character chunk
5. DES-encrypt the string `"KGS!@#$%"` with these two chunks
6. Concatenate the two DES encrypted strings. This is the LM hash \
   (ex. `"hashcat"` -> `299bd128c1101fd6aad3b435b51404ee`)

There are some interesting observations about this hash type. Firstly, only 142 different characters are possible with only 14 bytes to place them in. This is still a lot of possibilities, but it gets better. Because the password is separated into chunks of 7 characters, and we get the raw hash of both sections, we can simply brute-force them **separately**! This is a tremendous speedup that allows cracking _any_ password regardless of strength in a reasonable time.&#x20;

This also means that you cannot use a password of 15+ characters. When this hash is not used, or **empty**, it will be fully padded by 14 `\x00` bytes. One 7-byte chunk generates a hash of `aad3b435b51404ee`, meaning both together are: `aad3b435b51404eeaad3b435b51404ee`. This is a very common string in modern environments as it shows there is either no password or that LM hashes are disabled.&#x20;

#### NT-hashes

Sometimes called **NTLM-hashes**, this is the way passwords are hashed on modern systems to this day. As the successor to [#lm-hashes](ntlm.md#lm-hashes "mention") it has made improvements and is now very similar to other common hashes like MD5. So similar in fact, that it is also about _just as fast_ if not _2x faster_ to crack. The algorithm is not new, but simply an MD4 hash of the little-endian UTF-16 encoded password (ex. `b4b9b02e6f09a9bd760f388b67351e2b`).&#x20;

Technically, the **combination** of an LM hash and NT hash is called the **NTLM hash**, often separated by a colon in hash dumps:

<pre><code>Password: hashcat
<strong>LM hash: 299bd128c1101fd6aad3b435b51404ee
</strong><strong>NT hash: b4b9b02e6f09a9bd760f388b67351e2b
</strong>Dump (LM enabled):
<strong>Administrator:500:299bd128c1101fd6aad3b435b51404ee:b4b9b02e6f09a9bd760f388b67351e2b
</strong>Dump (LM disabled):
<strong>Administrator:500:aad3b435b51404eeaad3b435b51404ee:b4b9b02e6f09a9bd760f388b67351e2b
</strong></code></pre>

#### NetNTLMv1/v2

As shown in the flow below, the NT hash is used for calculating the correct response to a challenge from the server. NetNTLMv1 is a type of **challenge**, which may be captured by an attacker to crack offline. Because this challenge-response includes the NT hash it is possible to let hashcat guess passwords to test if the response matches.&#x20;

<pre class="language-renpy" data-title="NetNTLMv1 algorithm" data-overflow="wrap"><code class="lang-renpy">C = 8-byte server challenge, random
K1 | K2 | K3 = LM/NT-hash | 5-bytes-0
response = DES(K1,C) | DES(K2,C) | DES(K3,C)

<strong>u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c
</strong></code></pre>

<pre class="language-renpy" data-title="NetNTLMv2 algorithm" data-overflow="wrap"><code class="lang-renpy">SC = 8-byte server challenge, random
CC = 8-byte client challenge, random
CC* = (X, time, CC2, domain name)
v2-Hash = HMAC-MD5(NT-Hash, user name, domain name)
LMv2 = HMAC-MD5(v2-Hash, SC, CC)
NTv2 = HMAC-MD5(v2-Hash, SC, CC*)
response = LMv2 | CC | NTv2 | CC*

<strong>admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030
</strong></code></pre>

The main difference between v1 and v2 for an attacker is its speed to crack. Both versions work exactly the same in terms of the protocol, it is only a different algorithm. The NetNTLMv1 challenges (\~18GH/s) can be cracked around 15x faster than NetNTLMv2 challenges (\~1.2GH/s).&#x20;

### Authentication Flow

NetNTLM works using a challenge-response mechanism. The entire process is as follows:

<figure><img src="../../.gitbook/assets/image (1) (2) (3).png" alt=""><figcaption><p>Challenge-response mechanism of NTLM between a Client, Server and Domain Controller</p></figcaption></figure>

1. The client sends an **authentication request** to the server they want to access
2. The server generates a **random** number and sends it as a **challenge** to the client
3. The client combines their **NTLM password hash** with the challenge (and other known data) to generate a response to the challenge and sends it back to the server for verification
4. The server forwards the challenge and the response to the Domain Controller for verification
5. The domain controller uses the challenge to recalculate the response and **compares** it to the original response sent by the client. If they both match, the client is authenticated; otherwise, access is denied. The authentication result is sent back to the server
6. The server forwards the authentication result to the client

Note that the user's password (or hash) is never transmitted through the network for security (or at least, _some_ security).

{% hint style="info" %}
**Note**: The described process applies when using a domain account. If a local account is used, the server can verify the response to the challenge itself without requiring interaction with the domain controller since it has the password hash stored locally on its SAM
{% endhint %}

## Cracking Hashes

After [#receiving-hashes](ntlm.md#receiving-hashes "mention"), you have a hash of a user's password. With a lot of computing power or by looking them up in a database you might be able to recover the password of that user.&#x20;

### Plaintext Passwords

An **NTLM hash** is simply a quick hash over the user's password. This means tools like [#hashcat](../../cryptography/hashing/cracking-hashes.md#hashcat "mention") can brute-force it very quickly (\~32GH/s). Store one or more hashes in a file and use any hashcat mode to attempt to crack it:

```bash
hashcat -m 1000 ntlm.hash /list/rockyou.txt
```

For [#lm-hashes](ntlm.md#lm-hashes "mention"), these can be cracked in **7-byte blocks** due to how they are generated. The passwords are also **case-insensitive** (always uppercase) which drastically reduces the number of characters to try. If we have a password hash that is not empty (`aad3b435b51404ee`) we can split it into chunks and crack it in minutes even with a broad character set:

<pre class="language-shell-session"><code class="lang-shell-session">Password: Sup3r!Str0ng??
LM Hash: 215f2e16e5c68b4e6f5899c6e7963649 -> (215f2e16e5c68b4e, 6f5899c6e7963649)

<strong>$ hashcat -m 3000 215f2e16e5c68b4e -a 3 -1 ?u?d?s ?1?1?1?1?1?1?1
</strong>215f2e16e5c68b4e:SUP3R!S
<strong>$ hashcat -m 3000 6f5899c6e7963649 -a 3 -1 ?u?d?s ?1?1?1?1?1?1?1
</strong>6f5899c6e7963649:TR0NG??

Recovered: SUP3R!STR0NG??
</code></pre>

After which, if we also have the NT hash, we can recover the case-sensitive password by toggling the cases. [The documentation](https://hashcat.net/wiki/doku.php?id=toggle\_attack\_with\_rules) explains how this is possible, and someone made [a tool](https://blog.didierstevens.com/2016/07/16/tool-to-generate-hashcat-toggle-rules/) to generate hashcat rules for toggling the cases for passwords of arbitrary length, but 14 characters is enough in this case.

{% file src="../../.gitbook/assets/toggles14.rule" %}
Rule to toggle capitalization of 14-character passwords in hashcat
{% endfile %}

<pre class="language-shell-session" data-overflow="wrap"><code class="lang-shell-session">NT Hash: 8e4fd6f220fad54eaaacaf8f788cd57c

<strong>$ echo 'SUP3R!STR0NG??' | hashcat -m 1000 8e4fd6f220fad54eaaacaf8f788cd57c -r /list/hashcat/toggles14.rule
</strong>...
8e4fd6f220fad54eaaacaf8f788cd57c:Sup3r!Str0ng??
</code></pre>

#### Lookup Tables

All these hashes have **no salt**, meaning any password attempts will work on any hash. This allows sites like [CrackStation](https://crackstation.net/) to store giant lists of **precomputed** passwords and hashes that it will simply query to find any matches, significantly reducing the difficulty of cracking a hash. \
The only reason you should crack a hash like this manually is if you know it contains a specific pattern hashcat can match, and it is not in a big list like CrackStation.&#x20;

## Pass the Hash

In Active Directory, having the NTLM hash of a user is **just as good** as having their password. This is due to the pass-the-hash attack where all verification uses the hash instead of the password (as seen in the [#authentication-flow](ntlm.md#authentication-flow "mention")). Most offensive tools allow a `-hashes` or `-H` argument to pass the hash and impersonate a user without knowing their password.&#x20;

NTLM Authentication won't send the plain NTLM hashes over the network, ever. It only calculates a challenge-response using it which cannot be reversed, only brute-forced. Using a challenge-response an attacker can still guess passwords and calculate the hash as well as the response offline.&#x20;

### Extracting from Memory

Tools like [Mimikatz](https://github.com/ParrotSec/mimikatz) can do a lot, including extracting secrets like NTLM hashes from **LSASS** (Local Security Authority Subsystem Service) process memory. Because this component handles a lot of Windows security features, its memory contains useful information when it can be dumped.&#x20;

{% embed url="https://tools.thehacker.recipes/mimikatz/modules/lsadump/lsa" %}
Mimikatz `lsadump::lsa` command explained
{% endembed %}

The [#secretsdump.py](../active-directory.md#secretsdump.py "mention") script or [lsassy](https://github.com/Hackndo/lsassy) can do the same, but **remotely** through Python. These often give cached NTLM hashes of different users on a Computer, which you may be able to crack or **re-use elsewhere**.&#x20;

### Receiving Challenges

By forcing a victim to authenticate with **you**, they will ask for a challenge, which you can provide, and then receive a response based on the NTLM hash of that user. Tools exist to set up fake servers that let a user authenticate while capturing their challenge response to crack offline:

{% embed url="https://github.com/SpiderLabs/Responder" %}
A tool to set up many servers for authentication, capturing responses
{% endembed %}

<pre class="language-shell-session"><code class="lang-shell-session"># # Responder requires an interface (eth = ethernet, tun = tunnel/VPN)
<strong>$ ip a
</strong>1: lo: ...
2: eth0: ...
3: tun0: ...
<strong>$ responder -I tun0
</strong>Responder IP      [10.10.10.10]
...
[+] Listening for events...
</code></pre>

## Pass the Challenge (NTLM Relay)

<figure><img src="../../.gitbook/assets/image (2) (2).png" alt=""><figcaption><p>Relaying an NTLM authentication flow to impersonate a user (<a href="https://blog.fox-it.com/2017/05/09/relaying-credentials-everywhere-with-ntlmrelayx/">source</a>)</p></figcaption></figure>

When a server authenticates to **you**, it expects a challenge back for it to solve. An attacker can abuse this by simply requesting a challenge to another service and forwarding this challenge to the client who would be none the wiser. They will calculate the response with their NTLM hash and send it back to the attack, who can then forward it back to the target server, impersonating the user. Now the attacker is authenticated and can do anything on the target server as the victim!

Multiple services accept NTLM authentication in this way, most commonly SMB and LDAP. A tool was developed that can listen for authentication requests, and relay them to a target server like explained. Because the protocol is so simple, this can go cross-service meaning an SMB request could be relayed to LDAP.&#x20;

{% embed url="https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py" %}
Relay NTLM challenges to different services automatically ([more info](https://blog.fox-it.com/2017/05/09/relaying-credentials-everywhere-with-ntlmrelayx/))
{% endembed %}

Letting it listen with `sudo ntlmrelayx.py` a bunch of ports will be opened for connections. Try ways of [#receiving-challenges](ntlm.md#receiving-challenges "mention") and when you do, the tool will automatically relay the authentication to a target specified with `-t IP` (client IP by default).&#x20;

* `-t IP`: SMB
* `-t imap://IP`: IMAP
* `-t ldaps://IP`: LDAP

Another useful option is `-i` which will spawn a listener on every success for interactive tooling like  SMB or LDAP client where you can write commands yourself. \
By default, the tool will perform useful actions like trying to execute files through SMB, or even adding a Domain Admin account if enough privileges are gained.&#x20;
