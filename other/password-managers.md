---
description: >-
  Passwords stored in a central vault, which may have some weaknesses depending
  on your target
---

# Password Managers

## KeePass - Memory Dump

While typing out the master key to unlock a KeePass database, the value of the input box is stored in memory. While it is visually hidden using '●' characters, the last character was briefly visible in memory and stored there ([CVE-2023-3278](https://nvd.nist.gov/vuln/detail/CVE-2023-32784), fixed in [KeePass 2.54](https://keepass.info/news/n230603\_2.54.html) released June 3rd 2023). That makes it possible to find strings like the following in a memory dump:

```
s
●e
●●c
●●●r
●●●●e
●●●●●t
```

Dumps can be created of a vulnerable version using the following command on a Windows machine:

```powershell
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process keepass).id keepass.DMP full
```

Then, use a tool to parse and extract the leaks from the memory dump:

{% embed url="https://github.com/JorianWoltjer/keepass-dump-extractor" %}
Extract passwords hints from a keepass memory dump to generate a wordlist
{% endembed %}

## Bitwarden - PIN Cracking

When the Bitwarden browser extension is installed on a compromised machine, it is often still locked and requires the master password to be entered to decrypt the data. There is an option however to lock the vault with a PIN instead of a password, either _always_ or _only after the master password has been entered once_.

<figure><img src="../.gitbook/assets/image (46).png" alt="" width="186"><figcaption></figcaption></figure>

You can imagine that passwords must be less protected because the only thing required to unlock the vault now is a 4-digit number. It still works offline meaning that the decryption can always be replicated without limits to brute-force the PIN. While Bitwarden tries its best to make it slow to crack such a PIN, there are only 10000 options which can be done in a few minutes even for slow password hashes.

To exploit all possible scenarios confidently and efficiently, I made a multi-threaded brute-forcing tool that takes the hash and configuration options and cracks the Bitwarden PIN. See the `README.md` file for detailed usage instructions:

{% embed url="https://github.com/JorianWoltjer/bitwarden-pin-bruteforce" %}
Bitwarden PIN brute force tool with usage instructions
{% endembed %}
