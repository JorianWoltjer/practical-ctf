---
description: In a NTFS file system, files can have multiple streams with extra data
---

# Alternate Data Streams (ADS)

Normally, the content of a file is stored in the `$Data` stream of a file. But you can create alternate streams on the same file with different content. This can be useful for hiding some data and might be used by malware to make its payloads less obvious. However, if you know what you're looking for these can be very easily found.&#x20;

## PowerShell

The easiest way to find files with alternate data streams is to run a PowerShell command like the following, which will recursively search the current directory for any streams that are not `$Data`.

<pre class="language-powershell"><code class="lang-powershell"><strong>PS F:\> gci -recurse | % { gi $_.FullName -stream * } | where stream -ne ':$Data'
</strong>PSPath        : Microsoft.PowerShell.Core\FileSystem::F:\C\Windows\Tasks\ActiveSyncProvider.dll:hidden.ps1
PSParentPath  : Microsoft.PowerShell.Core\FileSystem::F:\C\Windows\Tasks
PSChildName   : ActiveSyncProvider.dll:hidden.ps1
PSDrive       : F
PSProvider    : Microsoft.PowerShell.Core\FileSystem
PSIsContainer : False
FileName      : F:\C\Windows\Tasks\ActiveSyncProvider.dll
Stream        : hidden.ps1
Length        : 175838
</code></pre>

If you find any interesting names, you can extract their content with another PowerShell command:

<pre class="language-powershell"><code class="lang-powershell"><strong>Get-Item &#x3C;FILE> | Get-Content -Stream &#x3C;STREAM_NAME>
</strong># For example
<strong>Get-Item .\ActiveSyncProvider.dll | Get-Content -Stream hidden.ps1
</strong></code></pre>

If you want to set the content of ADS, you can do so using the `Set-Content` command:

<pre class="language-powershell"><code class="lang-powershell"><strong>Set-Content -Path &#x3C;FILE> -Stream &#x3C;STREAM_NAME> -Value &#x3C;CONTENT>
</strong># For example
<strong>Set-Content -Path .\ActiveSyncProvider.dll -Stream hidden.ps1 -Value '...'
</strong></code></pre>

## Legitimate uses

There is a reason this feature exists, and you may find streams that are not meant to be hidden for malware or secrets. Here are a few real-world uses that you might come across.&#x20;

### Zone.Identifier

This is the most common ADS which comes from **downloading files**. You might have experienced those warnings that Windows Defender gives when you try to run a program you just downloaded from the internet. Windows Defender knows this because every downloaded file will include this `Zone.Identifier` stream which tells it where the file comes from. There are 5 different zones with varying levels of trust:

1. Local Intranet Zone
2. Trusted Sites Zone
3. **Internet Zone**
4. Restricted Sites Zone
5. Local Machine Zone

The most common is **3. Internet Zone** for files downloaded from the internet. The content of this stream might look like this:

```toml
[ZoneTransfer]
ZoneId=3
```
