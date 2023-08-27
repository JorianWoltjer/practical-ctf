---
description: >-
  Network scanning tool with enumeration script to get detailed information
  about TCP/UDP ports, and the underlying system
---

# Nmap

## Description

{% embed url="https://nmap.org/" %}

Nmap's main use case is **finding open TCP ports**, but while doing so, it can do much more.&#x20;

```bash
nmap [options] 10.10.10.10
```

Some useful options include (see `man nmap` and [docs ](https://nmap.org/book/man.html)for more details):

* `-sV`, `-O`: Software versions, OS detection
* `-sC`: Run default safe [scripts](https://nmap.org/book/nse-usage.html)
* `-Pn`, `-n`: Disable ping, disable DNS resolution
* `-sS`, `-T4`: Stealth scan (half connections, but requires `sudo`), faster scanning speed
* `-oN [filename]`: [Output](https://nmap.org/book/man-output.html) to file
* Situational options:
  * `-p [ports]`: Specify comma-separated or ranges of ports (`-p-` = all ports)
  * `-sU`: Scan UDP instead of TCP (slower and often inconsistent)
  * `-vv`: Verbose output while scan is running, seeing open ports before completion
  * `10.10.10.0/24`: Subnets in target field

<pre class="language-bash" data-title="Examples" data-overflow="wrap"><code class="lang-bash"># Scan all TCP ports with all enumeration options, disabling unnecessary features
<strong>sudo nmap -sV -O -sC -Pn -n -sS -T4 -oN nmap.txt -p- -vv 10.10.10.10
</strong># Scan top 100 UDP ports relatively quickly with enumeration
<strong>sudo nmap -Pn -n -sV -sC -O -vv -oN nmap-udp.txt --top-ports 100 -sU --version-intensity 0 -T4 10.10.10.10
</strong></code></pre>

{% hint style="info" %}
**Tip**: While running, there are a few useful [keybinds](https://nmap.org/book/man-runtime-interaction.html) to alter your scan:

* `v`: Increase verbosity
* `[any]`: Print status update
{% endhint %}

{% hint style="warning" %}
**Tip**: Nmap is a binary that _cannot_ simply be copied over to a compromised machine to scan from there, not even when compiled statically. It requires some folders for services and scripts which it cannot find and won't run.&#x20;

The solution is to copy these folders over too, like done in the [`nmap-static-binaries`](https://github.com/opsec-infosec/nmap-static-binaries/tree/master/linux/x86\_64) repository. After transferring this folder you can run `./nmap`
{% endhint %}
