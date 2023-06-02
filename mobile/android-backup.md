---
description: Extracting information from an Android Backup (.ab) file
---

# Android Backup

## Reading files in the Backup

To extract and browse files from an Android Backup, use android-backup-extractor (`abe.jar`):

{% embed url="https://github.com/nelenkov/android-backup-extractor/releases" %}
Tool to extract files from an android backup
{% endembed %}

When you have the latest release downloaded, simply start it with java to unpack your `.ab` file into a `.tar` file:

```shell-session
$ java -jar abe.jar unpack backup.ab backup.tar [password]  # Unpack into TAR
$ mkdir backup  # Create final directory
$ tar -xvf backup.tar -C backup  # Extract files from TAR into directory
```

{% hint style="info" %}
The password is only required if the backup is encrypted, in which case you will want to find a password somewhere to extract it.&#x20;
{% endhint %}

{% hint style="warning" %}
If you are having trouble unpacking the .ab file into a .tar file, you can try to manually do it by prepending a few bytes like with the following command:

```bash
( printf "\x1f\x8b\x08\x00\x00\x00\x00\x00"; tail -c +25 backup.ab ) | tar xfvz -
```
{% endhint %}

After this is extracted, you can explore the created folder and see all the files that were stored in the backup.&#x20;

## Cracking Android Password

([source](https://www.pentestpartners.com/security-blog/cracking-android-passwords-a-how-to/))

When you have access to the files on an Android device, you can find a hash of the password/PIN used to unlock the device. Often you will find such a key in the `/data/system/password.key` file. It contains a hex-encoded string which is a combination of the SHA1 hash, as well as the MD5 hash. For example:

{% code title="password.key" %}
```
1136656D5C6718C1DEFC71B431B2CB5652A8AD550E20BDCF52B00002C8DF35C963B71298
```
{% endcode %}

{% hint style="warning" %}
If you cannot find this file, you might have **multiple users**. See [this section](https://www.pentestpartners.com/security-blog/cracking-android-passwords-a-how-to/) on how to extract a password for each user.&#x20;
{% endhint %}

This key is computed like so:

```
SHA1(password + salt) + MD5(password + salt)
```

These can be split by taking the first 40 characters as a SHA1 hash, and the leftover 32 characters as the MD5 hash:

```json
SHA1: 1136656D5C6718C1DEFC71B431B2CB5652A8AD55
MD5:  0E20BDCF52B00002C8DF35C963B71298
```

### Finding the Salt

Then the final thing required is the **salt** for the hash. You can find it by looking for the settings SQLite database. Commonly it is found in the following locations:

<table><thead><tr><th width="204">Version</th><th>Database Location</th></tr></thead><tbody><tr><td>Android <strong>1.0-4.0</strong></td><td><code>/data/data/com.android.providers.settings/databases/settings.db</code></td></tr><tr><td>Android <strong>4.1+</strong></td><td><code>/data/system/locksettings.db</code></td></tr></tbody></table>

You can simply connect to it with the sqlite3 command:

```shell-session
$ sqlite3 locksettings.db
```

Then you can find the password salt by running the following query:

```sql
sqlite> select value from locksettings where name='lockscreen.password_salt';
3582477098377895419
```

This is simply a number, and to get it into the regular salt string, you need to convert it to lowercase hexadecimal notation (without the `0x`):

{% code title="Python" %}
```python
>>> hex(3582477098377895419)[2:]
'31b783f0b0c95dfb'
```
{% endcode %}

### Cracking with Hashcat

Finally, now that we have the hashed password and salt, we can get to actually cracking it. We have two hashes, an MD5 hash, and a SHA1 hash. They are both from the same password and salt, so we can just choose one of the two. Since the MD5 hash is a lot faster to compute, we will use that for cracking.&#x20;

The correct hashcat mode is `-m 10`, as this is `md5($pass.$salt)` seen in the [example hashes](https://hashcat.net/wiki/doku.php?id=example\_hashes). That page also gives us the format hashcat expects from the hash. We will first put the MD5 hash, followed by a `:` colon, and finally the salt value in hex.&#x20;

{% code title="hash.txt" %}
```
0e20bdcf52b00002c8df35c963b71298:31b783f0b0c95dfb
```
{% endcode %}

The `locksettings.db` file can also reveal what kind of password is used, which helps with deciding what pattern to crack. Simply run the following query on the database and see what it means:

```sql
sqlite> select value from locksettings where name='lockscreen.password_type';
131072
```

<table><thead><tr><th width="173" align="right">password_type</th><th>Meaning</th></tr></thead><tbody><tr><td align="right">32768</td><td><code>LowLevelBiometricSecurity</code>: implies technologies that can recognize the identity of an individual to about a 3-digit PIN (i.e. face)</td></tr><tr><td align="right">65536</td><td><code>PatternPassword</code>: any type of password is assigned on the device (i.e. pattern)</td></tr><tr><td align="right">131072</td><td><code>NumericPasswordBasic</code>: numeric password is assigned to the device</td></tr><tr><td align="right">196608</td><td><code>NumericPasswordAdvanced</code>: numeric password with no repeating (4444) or ordered (1234, 4321, 2468, etc.) sequences</td></tr><tr><td align="right">262144</td><td><code>AlphabeticPassword</code>: alphabetic password</td></tr><tr><td align="right">327680</td><td><code>AlphanumericPassword</code>: alphabetic and numeric password</td></tr><tr><td align="right">393216</td><td><code>ComplexPassword</code>: alphabetic, numeric, and special character password</td></tr></tbody></table>

Then finally, you can start hashcat to crack the password, for example:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ hashcat -m 10 hash.txt -a 3 ?d?d?d?d
</strong>0e20bdcf52b00002c8df35c963b71298:31b783f0b0c95dfb:1337
</code></pre>

{% hint style="info" %}
For more details on hashcat options, see [#hashcat](../cryptography/hashing/cracking-hashes.md#hashcat "mention").
{% endhint %}

## WhatsApp Messages

When you have access to the files of a device, you might find that it contains Whatsapp messages stored in a backup. These are often said to be encrypted, but the key to decrypt them is also stored along the same files. You simply have to use a tool to decrypt them, and one such tool is whatsapp-viewer:

{% embed url="https://github.com/andreas-mausch/whatsapp-viewer/releases" %}
A GUI application for decrypting and viewing Whatsapp databases
{% endembed %}

To use this tool, you need a couple of files. Firstly, the key for decrypting the databases. This key can be stored in a couple of different locations, but the simplest way is to just search for a path with "whatsapp" and "key" to find a single file named `key`:

```shell-session
$ find | grep -i whatsapp | grep -i key
./apps/com.whatsapp/f/key
```

Now that we have the key, we can get the database with messages and contacts to decrypt. To find the directory containing the databases, simply search for it again:

```shell-session
$ find -type d | grep -i whatsapp | grep -i databases
./shared/0/WhatsApp/Databases
```

In this directory, you will find a `msgstore.db` file, and optionally a `wa.db` file containing contact information. With these files, you can start WhatsApp Viewer, and depending on the `.crypt` version of your database, you can go to **File** -> **Decrypt .crypt\[N]**. From there select your database and key file, decrypt it, and select an output file location.

This output file is now the SQLite database unencrypted which you can view with `sqlite3`:

<pre class="language-sql"><code class="lang-sql"><strong>$ sqlite3 messages.decrypted.db
</strong><strong>sqlite> .tables
</strong>...
message
...
<strong>sqlite> SELECT * FROM message;
</strong>...
</code></pre>
