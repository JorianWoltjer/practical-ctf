---
description: Different kinds of file archives, like ZIP, RAR or TAR
---

# Archives

## Password Protection

Most types of archive files can set a password that encrypts the content until the correct password is given. There are a few tricks to brute-force or even bypass this password protection.&#x20;

### Brute-forcing

I spent a lot of time automating the cracking of password protected archives in my [default](https://github.com/JorianWoltjer/default) tool:

```shell-session
$ default crack archive.zip
```

It will automatically recognize the type of encryption used, and start hashcat or john to crack it using a wordlist.&#x20;

Doing it manually would require you to first get a hash using a tool like `zip2john` included in John the Ripper. Then you crack that hash with hashcat or john if you have the right hash mode.&#x20;

### Read filenames

An interesting little thing about most archive file formats is the fact that when they are encrypted, you can still read the filenames and structure, only the content is encrypted. This can already give a good idea for what kind of files the archive contains.&#x20;

```shell-session
$ unzip -v archive.zip
Archive:  archive.zip
 Length   Method    Size  Cmpr    Date    Time   CRC-32   Name
--------  ------  ------- ---- ---------- ----- --------  ----
      15  Stored       15   0% 1970-01-01 00:00 21c0cb62  file.txt
--------          -------  ---                            -------
      15               15   0%                            1 file
```

As you can see, even the size and a CRC32 are present. This CRC is a checksum of the **unencrypted** file content, so if you can guess the content you can confirm it by taking the CRC. This allows for brute-forcing content of very small files as well. See this tool for an implementation of that:

{% embed url="https://github.com/kmyk/zip-crc-cracker" %}
A Python tool to bruteforce content of very small files in an encrypted ZIP archive
{% endembed %}

### ZIP Known Plaintext Attack

The PKZIP stream cipher is vulnerable to a Known Plaintext attack. This means that if we **know some content** of a file in the encrypted ZIP, we can use it to find the keys used to decrypt the rest.&#x20;

With a faster brute-force attack afterwards it is also possible to recover the original password for further use.&#x20;

The [bkcrack](https://github.com/kimci86/bkcrack) tool has a great implementation of this attack, see the tutorial here on how to use it:

{% embed url="https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md" %}
A tool that uses the known plaintext attack to decrypt ZIP files and recover the password
{% endembed %}

## File format

<figure><img src="../.gitbook/assets/image (27).png" alt=""><figcaption><p>A visual explanation of the ZIP file format by Ange Albertini</p></figcaption></figure>

Sometimes a zip file can be corrupted, either intentionally or unintentionally. You can try to fix it using the `-FF` flag in `zip`:

```shell-session
$ zip -FF archive.zip --out fixed.zip
```

Sometimes `binwalk` can also help with finding files in the ZIP when `unzip` cannot.&#x20;

When you suspect some kind of file trickery you should look at the file format, and find things that are weird about this ZIP file.&#x20;
