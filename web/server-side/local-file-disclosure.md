---
description: >-
  Gain information by reading files on a web server, also known as Local File
  Inclusion (LFI)
---

# Local File Disclosure

## Description

Webservers often work with files, either serving content from a file structure, letting you upload files, or some other functionality that reads from a dynamic file path. These functionalities can be interesting if user input is not sanitized, potentially allowing the attacker to read files they aren't supposed to, containing sensitive information like credentials, or helping them plan further attacks by gaining tons of information about the underlying system.&#x20;

These vulnerabilities happen when user input finds its way into a path that is read, and then used by the server or returned to the client:

{% code title="Vulnerable example" %}
```php
<?php
file_get_contents("/var/www/html/uploads/" . $_GET['file']);
```
{% endcode %}

Because the attacker can directory control the `?file=` URL parameter, they can use **Directory Traversal** sequences to go up into parent directories and read any file. Look at the following example:

<pre class="language-bash"><code class="lang-bash"><strong># ?file=file.txt
</strong>/var/www/html/uploads/file.txt
<strong># ?file=../etc/passwd
</strong>/var/www/html/uploads/../../../../etc/passwd
-> /var/www/html/../../../etc/passwd
<strong># ?file=../../../../etc/passwd
</strong>/var/www/html/uploads/../../../../etc/passwd
-> /etc/passwd
</code></pre>

By inserting enough `../` sequences, you can traverse to any file on the server. Depending on what is done with the file contents, this can have many different security implications. If it is simply read and returned to you, this is a **Local File Disclosure**, see [#exploits](local-file-disclosure.md#exploits "mention") for tricks to exploit these. \
If this happens in a PHP [`require()`](https://www.php.net/manual/en/function.require.php) function with a `?page=` parameter, for example, the content will be executed as PHP code often allowing RCE! See [#local-file-inclusion](../../languages/php.md#local-file-inclusion "mention") for exploits in this case. \
RCE can also happen if you read the right secrets on a server to forge signatures, for example. See [#werkzeug-debug-mode-rce-console-pin](../../languages/web-frameworks/flask.md#werkzeug-debug-mode-rce-console-pin "mention") for an example of this.

For a large list of input strings that try to bypass various different filters, see the following fuzzing list:

[https://github.com/1N3/IntruderPayloads/blob/master/FuzzLists/traversal.txt](https://github.com/1N3/IntruderPayloads/blob/master/FuzzLists/traversal.txt)

The above includes tricks like when a developer removes all `../` sequences, but fails to do so recursively, allowing you to insert nested sequences that when removed, form another sequence that wasn't there before:

<pre data-title="Bypass: &#x27;../&#x27; are removed"><code><strong>../../../../etc/passwd
</strong>-> etc/passwd
<strong>..././..././..././..././etc/passwd
</strong>-> ../../../../etc/passwd
</code></pre>

{% hint style="info" %}
**Tip**: For Windows-based targets, `\` backslashes may have interesting effects allowing for filter bypasses. See [#slashes-vs](../../windows/exploitation.md#slashes-vs "mention") for details
{% endhint %}

### Absolute Paths

One trick that the fuzzing list above doesn't cover is absolute paths. In some cases, your input might just be the start of a path that is looked up relatively, and if the **first character of your path** is a `/`, it will be treated as an **absolute path**. This means a payload like `/etc/passwd` directly might just work.

Another case where this works is in frameworks that treat joining absolute paths as overwriting the previous paths, which happens surprisingly often. In Python, for example, the default `os.path.join()` function will overwrite any earlier paths with your path if it starts with a `/` slash:

<pre class="language-python" data-title="Python absolute paths"><code class="lang-python">>>> import os
<strong>>>> os.path.join("/var/www/html/uploads", "file.txt")
</strong>'/var/www/html/uploads/file.txt'
<strong>>>> os.path.join("/var/www/html/uploads", "/etc/passwd")
</strong>'/etc/passwd'  # uploads/ is overwritten by our path!

>>> from pathlib import Path
<strong>>>> Path("/var/www/html/uploads") / "file.txt"
</strong>PosixPath('/var/www/html/uploads/file.txt')
<strong>>>> Path("/var/www/html/uploads") / "/etc/passwd"
</strong>PosixPath('/etc/passwd')  # same happens in pathlib
</code></pre>

## Exploits

Enumerate the filesystem by accessing targetted paths to learn about the system and find secrets.

### Enumerating Linux

#### Findings paths using `locatedb`

On some Linux systems, the [`locate`](https://en.wikipedia.org/wiki/Locate_\(Unix\)) command allows the user to search for filenames on the system quickly. This is so fast because a database is kept up to date. This database contains an indexed list of all files on the system that it can quickly search through. It is stored at `/var/cache/locate/locatedb` and has a binary file format.

Some clever people thought of using this file to leak all paths on a server, and then disclose those after! This was first seen in [_d3readfile_](https://hackingstudypad.tistory.com/518), and later explored more in [_Free Chat_](https://github.com/elweth-sec/Writeups/blob/master/GCC-2023/Free_Chat.md). These writeups explain that you can download this file, and then use `locate.findutils` on it to list all the files in plain text:

```bash
locate.findutils -d locatedb '*'
```

If you're lucky, and running as `root`, the read-protected `/var/lib/mlocate/mlocate.db` is a similar file that can be enumerated using `mlocate`. The output of these commands can be incredibly useful for extracting more files as there is no longer a need to guess, you can download all files and fully enumerate the system.&#x20;

#### Basic Enumeration

* `/etc/passwd`: Often used as a proof-of-concept, contains all users on a system and some information about them like their home directory and default shell.
* `/etc/shadow`: Only readable by `root`, containing password hashes for all users. These can be cracked like explained in [#cracking-shadow-hashes](../../cryptography/hashing/cracking-hashes.md#cracking-shadow-hashes "mention").
* `/etc/hosts`: Contains custom IP-to-hostname mappings often seen in larger networks with an internal domain. This can be useful for attacking other systems deeper into the network.
* `/home/$USER/...`: From the list of users, you can check out their home directories to potentially find interesting files stored there. These can have any name like `password.txt`, but common directories include `.ssh/id_rsa`, `.ssh/id_dsa`, or `.ssh/id_ecdsa` for SSH private keys.&#x20;

The `/home` folder often contains an SSH private key file that is only readable by the user but can be used to log into that user remotely. When you are able to read this file, copy it to your attacking machine and use `ssh -i` to authenticate with the private key:

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

Inside the home directories of users, you may also find **history files** containing commands issued by the user that could contain plaintext credentials if they were provided as arguments. These can often give a lot of insight into how admins are managing the system. Some examples:

* `~/.bash_history`: History of all bash commands run by the user in plain text.
* `~/.mysql_history`: History of MySQL console commands run interactively by the user.
* `~/.psql_history`: History of PostgreSQL console commands.

#### Generic `/proc` filesystem

The `/proc` directory on Linux is a goldmine of information because it makes heavy use of Linux's saying _"everything is a file"_. Detailed CPU information and memory statistics are stored here, as well as networking information in `/proc/net/tcp`:

{% code title="/proc/net/tcp" %}
```
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode

   0: 0100007F:0539 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 477410 1 0000000081462e8b 100 0 0 10 0
   1: 00000000:1388 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 471732 1 00000000f0fbd3b7 100 0 0 10 0
```
{% endcode %}

This content has a special machine-readable format where everything is encoded as **hex**. After we decode it, we can find all listening and connected TCP streams to find things like internal servers:

{% code title="Decoder" %}
```python
tcp = open("/proc/net/tcp").read()

def decode_address(address):
    ip, port = address.split(':')
    ip = '.'.join([str(int(ip[i:i+2], 16)) for i in range(0, len(ip), 2)][::-1])
    port = int(port, 16)
    return ip, port

for entry in tcp.splitlines()[2:]:
    entry = entry.split()
    local_ip, local_port = decode_address(entry[1])
    remote_ip, remote_port = decode_address(entry[2])
    print(f"{local_ip}:{local_port}\t-> {remote_ip}:{remote_port}")
```
{% endcode %}

The script above tells us that there is an internal service running on `127.0.0.1:1337`, and an external service on `0.0.0.0:5000`, presumably where we got access from.

#### Processes in `/proc/$PID`

Of course, the procfs can also be used for, well, _processes_. These all have unique Process ID (PID) that is their path in the `/proc` directory. There is one special extra path called `self`, which links to the current process (the one reading the file). This is useful if you want to know information about the process your are currently exploiting without knowing all other PIDs.&#x20;

Luckily, these PIDs are often not that large and a simple brute force starting from 0 and counting upward should find most processes. Interesting things to read here are:

* `/proc/self/environ`: Environment variables delimited by null bytes, may contain secrets
* `/proc/self/cmdline`: CLI arguments to start the process, delimited by null bytes
* `/proc/self/fd/$N`: File Descriptors open for the process, starting at 2 and counting up
* `/proc/self/exe`: Symlink to the process binary, useful if it is custom-compiled
* `/proc/self/maps`: All sections and addresses for bypassing ASLR protection

### Web Server

#### Configuration

Web applications often use a _reverse proxy_ or simply host files through a web server like [Apache2](https://httpd.apache.org/) or [Nginx](https://www.nginx.com/). These have common configuration file locations at the following paths:

{% code title="Apache2" %}
```
/etc/apache2/httpd.conf
/etc/apache2/apache2.conf
/etc/httpd/httpd.conf
/etc/httpd/conf/httpd.conf
```
{% endcode %}

{% code title="Nginx" %}
```
/etc/nginx/nginx.conf
/usr/local/nginx/conf/nginx.conf
/usr/local/etc/nginx/nginx.conf
```
{% endcode %}

When one of these is found, you can use the base directory to find more configuration files with custom settings. For both web servers, the `sites-available/` and `sites-enabled/` directories contain configuration per site. These can include proxy rules or other configurations, but they have a custom name set by the developer. This may require some guesswork, but there is a `default.conf` that may be used. Otherwise, the domain name or application name with some extensions may work.

#### Source Code

When you can read files in an otherwise black box system, finding source code can be very useful to not only discover more complicated vulnerabilities but also potentially find secrets inside of source code like passwords or random tokens. If you find a cookie signing key, for example, you could forge your own cookies to become any user or even exploit deserialization flaws.&#x20;

Common locations for these include:

* `/app`: Often for source code like Python applications, containing files like `main.py` or `app.py`, potentially in a subdirectory called `src/`.
* `/var/www`: Common for static files or PHP, often in a `html/` subdirectory and/or the name of the application or domain as a directory containing the files. This often contains things like `index.html` or `index.php`.
* `/opt`: The directory for optional programs often used to install big applications under their name, like `/opt/MyApp`. These vary a lot in which files you will find, so try different ones like `.py` files, `.php`, `.html`, `.aspx` and `web.config` for ASP.NET apps.
* `/proc/self/cwd`: Links to the **current working directory** of this process. If it was started from the source code directory you may find it directly inside here.
* `../`: Relative URLs from where the path used to point can also help reduce guessing, as you may be able to find source code in a parent directory, or an adjacent `src/` directory.

In any of these locations, you should look for configuration files as well, like `.env` which is a common place for environment variables that often contain secrets for the application. `.htpasswd` is another credential file often used by Apache to protect directories with basic authentication. These files will contain a username and password separated by a `:` colon.&#x20;

{% hint style="info" %}
If a git repository is fully cloned into a web server, you may be able to find a`.git/` folder with all git objects and history. This can be incredibly useful for source code analysis, as well as finding secrets in the history or config files. See [#finding-git-on-websites](../../forensics/git.md#finding-git-on-websites "mention") for details.
{% endhint %}

The hardest part is finding one initial file in a source code directory to go off of. This can be done in an automated way through fuzzing and using targetted extensions with educated guesses of where things might be stored. When one part of the source code is found, it often references other files by their name or path that you can then find relative to it to slowly map out the entire source code.
