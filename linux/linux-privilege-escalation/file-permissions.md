---
description: >-
  Wrong permissions on files may lead to someone doing what they should not be
  allowed to
---

# File Permissions

## Regular Permissions

When running the `ls` command to see files in a directory, you can provide the `-l` flag to list all information about the file as well. Together with `-a` to see all files (including ones starting with a `.` dot), you get a common command to see file permissions and other information:

<figure><img src="../../.gitbook/assets/image (1) (1).png" alt=""><figcaption><p>Using the <code>ls</code> command to see file permissions</p></figcaption></figure>

Here there are different columns with different purposes. The first column shows the permissions for the file or directory, depending on how much you are related to the item. This is about the owner and group of the file. To the right of the permissions, there are 2 names, the **user** and the **group** owner. Different permissions apply to the owner or group of the file than other users on the system.&#x20;

The first yellow letter in the permissions shows the **type**, either `d` for a directory or `-` for a regular file. Then there are 3 pairs of 3 letters.&#x20;

`r` = **r**ead\
`w` = **w**rite\
`x` = e**x**ecute

The first <mark style="color:green;">green</mark> pair shows the **user** permissions. The second <mark style="color:blue;">blue</mark> pair shows the **group** permissions, and finally, the last <mark style="color:red;">red</mark> pair shows **everyone else**'s permissions, that aren't the user or group owner.&#x20;

This allows separate permissions for the owner, group, and everyone else. A `-` dash means the permission that should be in that spot is not given. You could for example make a file readable, but not writable or executable with a `r--` permission.&#x20;

{% hint style="info" %}
**Note**: For _directories_, these `rwx` permissions mean something slightly different:

`r` = **r**ead -> list files inside\
`w` = **w**rite -> create files inside\
`x` = e**x**ecute -> travel inside with `cd`
{% endhint %}

Something not yet covered is the `s` permission that you might see instead of `x`. This is a special permission meaning **s**etuid. When this bit is set, and you can execute it, you will gain the rights of the program **owner** while executing the program. This means if the program has any functionality to read files, for example, you can read files with the rights of the program owner.&#x20;

This sounds dangerous because it is. Only very few programs actually require this, like `sudo` for example to give you higher permissions only if you put in the correct password first. For more information on this see [suid.md](suid.md "mention").

## Chmod

`chmod` is short for "**ch**ange file **mod**e bits", as these permissions are also known as mode bits. This tool allows you to **change** the permissions of a file. The syntax to do so might take some getting used to, but it works as follows.&#x20;

You take the permissions for the 3 pairs and convert them to a binary number representing which permissions you want to give, and the ones you don't. Then convert this binary number to decimal, and you get a string of 3 numbers as follows:

<img src="../../.gitbook/assets/XdX8mLsvKw.png" alt="" data-size="original">

This command above would mean the files is readable, writable, and executable by the owner, not writable by the group, and for everyone is it only executable. There are some more common file permissions you might want to set, for example:

* `600` (`rw- rw- ---`): Only readable or writable by owners of the file
* `777` (`rwx rwx rwx`): Everyone can do anything with the file

### Different syntax

Some more useful syntax you might see is using the `+` symbol in the mode bits, followed by a permission. This is some short syntax to **add** the permission to the bits if it wasn't already there. Without further specification, it will apply the permission to all 3 pairs.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session">rw- rw- r--
<strong>$ chmod +x file  # Add executable permission for everyone
</strong>rwx rwx r-x
$ chmod +s file  # Add setuid permission to user and group owner
rws rws r-x
</code></pre>

You can also specify with the user (`u`), group (`g`) or other users (`o`) what permissions you need exactly without having to think about the binary numbers. Simply prefix one of these letters before the permission to only apply it there.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session">rw- rw- r--
<strong>$ chmod u+x file  # Add executable permission for the user owner
</strong>rwx rw- r--
<strong>$ chmod o+rwx file  # Add all permissions for other users
</strong>rwx rw- rwx
</code></pre>

## Access Control List (ACL)

Sometimes you might see a + symbol after the permissions of an item. This means it has additional, more specific permissions that might be abusable. To view these permissions, use the `getfacl` command:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ getfacl -t file.txt
</strong># # file: tmp/file.txt
USER   root      rwx
user   john      rw-
GROUP  root      rwx
mask             rwx
other            r--
</code></pre>

Here the `-t` argument gives a simpler layout of the results. You can see the USER, GROUP, and other permissions that `ls -l` already gives, as well as the additional permission: `user john rw-`. This is interesting because it means the user `john`, who is not the owner of the file, still has write permissions, while other users can only read.&#x20;

You can find all files with extra ACL permissions with the following recursive command:

```shell-session
$ getfacl -R -s -t / 2>/dev/null
```

In a default system, these permissions are rarely used, so any results may be worth checking out.&#x20;
