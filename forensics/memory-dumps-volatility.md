---
description: >-
  Big dump of the RAM on a system. Use tools like volatility to analyze the
  dumps and get information about what happened
---

# Memory Dumps (Volatility)

When you get a big file (>1 GB) and its `file` type is just `data`, you might have your hands on a memory dump.&#x20;

```shell-session
$ du -h file.dmp
1.0G    file.dmp
$ file file.dmp
file.dmp: data
```

You can often find a lot of interesting strings with the `strings` tool, but there are often way too many strings to find anything useful. That's why we use tools like [#volatility](memory-dumps-volatility.md#volatility "mention") to analyze the data in these dumps and find interesting information like open processes, caches, and much more.&#x20;

You can find an example challenge where the goal was to find 3 pieces of information about some malware that had run in the memory dump:

{% embed url="https://jorianwoltjer.com/blog/post/ctf/cyber-santa-is-coming-to-town-2021/honeypot" %}
Writeup of a Forensics challenge where you had to analyze a memory dump
{% endembed %}

## Volatility

There are 2 versions of volatility. The first is the original [volatility](https://github.com/volatilityfoundation/volatility) which is made for Python 2. In the rest of this page, I'll refer to it as **volatility2**. The second version is [volatility3](https://github.com/volatilityfoundation/volatility3), made for Python 3. It is an improved version of the original, but some features/modules are missing. That's why you often work with both tools combined.&#x20;

You should clone both Github repositories and then run the `vol.py` Python files to use the tools.&#x20;

{% tabs %}
{% tab title="volatility2" %}
```shell
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python2 setup.py install
python2 vol.py —h
```
{% endtab %}

{% tab title="volatility3" %}
```shell
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install
```
{% endtab %}
{% endtabs %}

Both tools have a detailed help page with `-h` that shows all the available modules, and what they do. This page will also cover a few of the most important ones.&#x20;

{% hint style="info" %}
**Tip**: You can create a **symlink** to the vol.py script to easily access the tools from any directory with the `vol2` and `vol3` commands:

```shell
sudo ln -s /path/to/volatility/vol.py /bin/vol2
sudo ln -s /path/to/volatility3/vol.py /bin/vol3
```
{% endhint %}

### Finding the Profile (2 only)

Volatility2 needs a **profile** to do its scans. This just tells the tool what operating system and version the dump was made in, so it can change the way it searches based on that. To find this profile there is a simple `imageinfo` module that analyzes the dump and tells what profile it thinks you should use.&#x20;

```shell-session
$ vol2 -f file.dmp imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86_24000, Win7SP1x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                              ...
           Image date and time : 2021-11-25 19:14:12 UTC+0000
     Image local date and time : 2021-11-25 11:14:12 -0800
```

If it can find a profile, it will show after `Suggested Profile(s)`, and you need to use one of these in all future commands using the `--profile` argument.&#x20;

{% hint style="info" %}
**Note**: You can also use the **`kdbgscan`** module instead of the `imageinfo` module. This module is useful for the `--kdbg` argument that can help some modules function better. It finds KDBG address instead of just a profile, giving even more information to the modules. If you're having trouble with a module like `pslist` you can try running this scan and adding the argument (see [this post](https://andreafortuna.org/2017/06/25/volatility-my-own-cheatsheet-part-1-image-identification/#7edb))
{% endhint %}

### Extra Profiles

By default both volatility Github repositories **only** contain **Windows** profiles. But you might get a memory dump from some Linux or Mac system. Luckily there are extra profiles you can download for these operating systems. Download the profiles below for volatility2 or 3:

{% tabs %}
{% tab title="volatility2" %}
{% embed url="https://github.com/volatilityfoundation/profiles" %}
Github repository containing Linux and Mac profiles for volatility2
{% endembed %}

The Linux profiles need to be placed into the `volatility/plugins/overlays/linux` source directory, and the Mac profiles to `volatility/plugins/overlays/mac`.&#x20;

{% hint style="warning" %}
Do **not** copy all the ZIP files into these directories. It will try to load every single one and make volatility extremely slow. They suggest making educated guesses about what operating system the dump could have come from, and then only importing that individual ZIP file.&#x20;
{% endhint %}
{% endtab %}

{% tab title="volatility3" %}
{% embed url="https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip" %}
ZIP archive containing Linux profiles for volatility3
{% endembed %}

{% embed url="https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip" %}
ZIP archive containing Mac profiles for volatility3
{% endembed %}

Then unzip these into the `volatility3/volatility3/symbols` source directory which should already have a `windows` folder. Then it will automatically use these symbols when running a module.&#x20;
{% endtab %}
{% endtabs %}

## Modules

### Processes

A good quick thing to do is to look at the running processes. From there you can often spot something suspicious to investigate further.&#x20;

{% tabs %}
{% tab title="volatility2" %}
```shell
vol2 -f file.dmp --profile=PROFILE pslist  # Process list
vol2 -f file.dmp --profile=PROFILE pstree  # Process tree
vol2 -f file.dmp --profile=PROFILE psscan  # Process list (slower, but more thorough)
```
{% endtab %}

{% tab title="volatility3" %}
```shell
vol3 -f file.dmp windows.pslist.PsList  # Process list
vol3 -f file.dmp windows.pstree.PsTree  # Process tree
vol3 -f file.dmp windows.psscan.PsScan  # Process list (slower, but more thorough)
```
{% endtab %}
{% endtabs %}

### Dump process

If you find a process that you haven't seen before or looks custom, you can extract the executable from memory and analyze it further as a file. Just provide the `--pid` you find in the process list and dump it into the current directory:

{% tabs %}
{% tab title="volatility2" %}
```bash
vol2 -f file.dmp --profile=PROFILE procdump --pid <pid> --dump-dir=procdump  # Dump .exe from process to current directory
```
{% endtab %}

{% tab title="volatility3" %}
```bash
vol3 -f file.dmp windows.dumpfiles.DumpFiles --pid <pid>  # Dump .exe from process to current directory
```
{% endtab %}
{% endtabs %}

### Command-line

If you found any `cmd.exe` or `powershell.exe` processes, it might be worth checking what arguments they have to see what they are executing:

{% tabs %}
{% tab title="volatility2" %}
```shell
vol2 -f file.dmp --profile=PROFILE cmdline  # Command-line (arguments) for process es
vol2 -f file.dmp --profile=PROFILE consoles  # Command history
```
{% endtab %}

{% tab title="volatility3" %}
```shell
python3 vol.py -f file.dmp windows.cmdline.CmdLine  # Command-line (arguments) for process es
```
{% endtab %}
{% endtabs %}

You might see a PowerShell process with the `-EncodedCommand` or `/e` argument, and a big random string. This is actually a Base64 and UTF16 encoded command that is executed in PowerShell, and you can use a [CyberChef recipe](https://gchq.github.io/CyberChef/#recipe=From\_Base64\('A-Za-z0-9%2B/%3D',true,false\)Decode\_text\('UTF-16LE%20\(1200\)'\)Syntax\_highlighter\('powershell'\)\&input=YVFCbEFIZ0FJQUFvQUNnQWJnQmxBSGNBTFFCdkFHSUFhZ0JsQUdNQWRBQWdBRzRBWlFCMEFDNEFkd0JsQUdJQVl3QnNBR2tBWlFCdUFIUUFLUUF1QUdRQWJ3QjNBRzRBYkFCdkFHRUFaQUJ6QUhRQWNnQnBBRzRBWndBb0FDY0FhQUIwQUhRQWNBQnpBRG9BTHdBdkFIY0FhUUJ1QUdRQWJ3QjNBSE1BYkFCcEFIWUFaUUIxQUhBQVpBQmhBSFFBWlFCeUFDNEFZd0J2QUcwQUx3QjFBSEFBWkFCaEFIUUFaUUF1QUhBQWN3QXhBQ2NBS1FBcEFBPT0) for example to decode the command.&#x20;

### Environment variables

Environment variables sometimes contain secrets or other interesting information, so generally, it's a good idea to look at them. It will give a lot of results for all processes though, so you can filter them to a single process by providing a `--pid`.&#x20;

{% tabs %}
{% tab title="volatility2" %}
```shell
vol2 -f file.dmp --profile=PROFILE envars [--pid <pid>]  # Environment variables from process
vol2 -f file.dmp --profile=LINUX_PROFILE linux_psenv [-p <pid>]  # Linux: Environment variables from process
```
{% endtab %}

{% tab title="volatility3" %}
```shell
vol3 -f file.dmp windows.envars.Envars [--pid <pid>]  # Environment variables from process
```
{% endtab %}
{% endtabs %}

### Network

Very often programs and malware need to communicate with some remote endpoint, and these network connections can also appear in the memory dump:

{% tabs %}
{% tab title="volatility2" %}
```shell
vol2 -f file.dmp --profile=PROFILE netscan  # Get active network connections
vol2 -f file.dmp --profile=PROFILE connections  # XP and 2003 only
vol2 -f file.dmp --profile=PROFILE connscan  # TCP connections 
vol2 -f file.dmp --profile=PROFILE sockscan  # Open sockets
vol2 -f file.dmp --profile=PROFILE sockets  # Scanner for tcp socket objects

vol2 -f file.dmp --profile=LINUX_PROFILE linux_ifconfig
vol2 -f file.dmp --profile=LINUX_PROFILE linux_netstat
vol2 -f file.dmp --profile=LINUX_PROFILE linux_netfilter
vol2 -f file.dmp --profile=LINUX_PROFILE linux_arp  # ARP table
vol2 -f file.dmp --profile=LINUX_PROFILE linux_list_raw  # Processes using promiscuous raw sockets (between processes)
vol2 -f file.dmp --profile=LINUX_PROFILE linux_route_cache
```
{% endtab %}

{% tab title="volatility3" %}
```shell
vol3 -f file.dmp windows.netscan.NetScan  # Get active network connections
```
{% endtab %}
{% endtabs %}

### Registry

The Windows registry is a big list of keys and values. Some programs or malware use it to store settings/data that might be interesting to look at. You can extract the registry hives and specific keys from a memory dump:

{% tabs %}
{% tab title="volatility2" %}
```shell
vol2 -f file.dmp --profile=PROFILE hivelist  # List roots
vol2 -f file.dmp --profile=PROFILE printkey  # List roots and get initial subkeys
vol2 -f file.dmp --profile=PROFILE printkey -K "Software\Microsoft\Windows NT\CurrentVersion"  # Get value from key
vol2 -f file.dmp --profile=PROFILE hivedump  # Dump full hive
```
{% endtab %}

{% tab title="volatility3" %}
```shell
vol3 -f file.dmp windows.registry.printkey.PrintKey  # List roots and get initial subkeys
vol3 -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion"  # Get value from key
```
{% endtab %}
{% endtabs %}

{% hint style="info" %}
**Tip**: Use the `-o` argument in any of these commands to get the information from a specific hive from `hivelist`. It needs the **virtual address** of the hive like `-o 0x9aad6148`. Otherwise, it will use all hives
{% endhint %}

### Filesystem

Files often contain lots of information, especially on Linux where everything is a file. Memory dumps may contain interesting files that you can extract and take a look at. The idea is that you first list files to find interesting ones, and then extract some specific ones you find.&#x20;

{% tabs %}
{% tab title="volatility2" %}
```shell
vol2 -f file.dmp --profile=PROFILE filescan  # All files
vol2 -f file.dmp --profile=PROFILE dumpfiles -n --dump-dir=dumpfiles  # Dump all files
vol2 -f file.dmp --profile=PROFILE dumpfiles -n --dump-dir=dumpfiles -Q <0xPHYSOFFSET>  # Dump file at specific physical address

vol2 -f file.dmp --profile=LINUX_PROFILE linux_enumerate_files  # All files
vol2 -f file.dmp --profile=LINUX_PROFILE linux_find_file -F /path/to/file  # Find inode number of specific fike
vol2 -f file.dmp --profile=LINUX_PROFILE linux_find_file -i <0xINODENUMBER> -O /path/to/dump/file  # Dump specific file
```
{% endtab %}

{% tab title="volatility3" %}
```shell
vol3 -f file.dmp windows.filescan.FileScan  # Any files
vol3 -f file.dmp windows.dumpfiles.DumpFiles --physaddr <0xAAAAA>  # Offset from previous command
```
{% endtab %}
{% endtabs %}

### Miscellaneous

There are some specific things you can take a look at in-memory dumps that don't fit into a specific category. Here are some of them:

#### Internet Explorer history

{% tabs %}
{% tab title="volatility2" %}
```shell
vol2 -f file.dmp --profile=PROFILE iehistory  # Internet Explorer history
```
{% endtab %}
{% endtabs %}

#### Clipboard

{% tabs %}
{% tab title="volatility2" %}
```shell
vol2 -f file.dmp --profile=PROFILE clipboard  # Get clipboard data
```
{% endtab %}
{% endtabs %}

#### Notepad content

{% tabs %}
{% tab title="volatility2" %}
```shell
vol2 -f file.dmp --profile=PROFILE notepad  # List currently displayed notepad text
```
{% endtab %}
{% endtabs %}

#### Screenshot

Surprisingly enough, you can even generate a screenshot of the system from only a memory dump. It can help give an idea of what applications are running in the foreground, and quite literally give a clearer picture of the system.

{% tabs %}
{% tab title="volatility2" %}
```shell
vol2 -f file.dmp --profile=PROFILE screenshot --dump-dir=screenshot  # Dump a few screenshots
```

#### Example:

![Example desktop showing a single window and a taskbar](../.gitbook/assets/session\_2.WinSta0.Default.png)
{% endtab %}
{% endtabs %}

#### Bash history

In Linux, it's possible to read the `.bash_history` file, but often this is disabled. With this module you can still recover the bash history from memory:

{% tabs %}
{% tab title="volatility2" %}
```shell
vol2 -f file.dmp --profile=PROFILE linux_bash  # Bash history
```
{% endtab %}

{% tab title="volatility3" %}
```shell
vol3   -f file.dmp linux.bash.Bash  # Bash history
```
{% endtab %}
{% endtabs %}

#### Dump certificates / SSL keys

{% tabs %}
{% tab title="volatility2" %}
```shell
# Interesting options for this module are: --pid, --name, --ssl
vol2 -f file.dmp --profile=PROFILE dumpcerts --dump-dir=dumpcerts  # Dump certificates
```
{% endtab %}

{% tab title="volatility3" %}
```shell
vol3 -f file.dmp windows.registry.certificates.Certificates  # Dump certificates   
```
{% endtab %}
{% endtabs %}

## Hashes

Similarly to a tool like Mimikatz, volatility can extract hashes and passwords from the memory dump:

{% tabs %}
{% tab title="volatility2" %}
```shell
vol2 -f file.dmp --profile=PROFILE hashdump  # Common windows hashes (SAM+SYSTEM)
vol2 -f file.dmp --profile=PROFILE cachedump  # Domain cache hashes
vol2 -f file.dmp --profile=PROFILE lsadump  # LSA Secrets
```
{% endtab %}

{% tab title="volatility3" %}
```shell
vol3 -f file.dmp windows.hashdump.Hashdump  # Common windows hashes (SAM+SYSTEM)
vol3 -f file.dmp windows.cachedump.Cachedump  # Domain cache hashes
vol3 -f file.dmp windows.lsadump.Lsadump  # LSA Secrets
```
{% endtab %}
{% endtabs %}

Then after you get these hashes, you might be able to do some Pass-The-Hash attack or crack the password (see [cracking-hashes.md](../cryptography/hashing/cracking-hashes.md "mention")). Hashes you get from `hashdump` are NTLM hashes, where the 4th column is the actual hash. You can get the hashes formatted in a file like this:

```shell-session
$ cat hashdump.txt  # From volitality hashdump module
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
$ cat hashdump.txt | awk -F: '{print $4}' > hashes.txt  # Only 4th column
$ hashcat -m 1000 hashes.txt wordlist.txt
fc525c9683e8fe067095ba2ddc971889:Passw0rd!
```
