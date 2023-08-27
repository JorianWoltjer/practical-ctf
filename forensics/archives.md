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

Sometimes `binwalk` can also help with finding files in the ZIP when `unzip` cannot.&#x20;

When you suspect some kind of file trickery you should look at the file format, and find things that are weird about this ZIP file. Password Protection

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

<pre class="language-python" data-title="Python"><code class="lang-python">import zipfile

with zipfile.ZipFile("payload.zip", "w") as zip:
    #          source            name
<strong>    zip.write("passwd", "../../../../etc/passwd")
</strong></code></pre>

The above example will create a ZIP file `payload.zip`, that when extracted by vulnerable, will try to overwrite `/etc/passwd`with the content you choose. This can be useful if `root` executes it for a Privilege Escalation scenario, but more commonly you'll want to get initial access by **overwriting executable files** like PHP shells, templates, dotfiles, or `~/.ssh/authorized_keys` if SSH is enabled (see [#writing-files](../linux/linux-privilege-escalation/#writing-files "mention") for more details).

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
