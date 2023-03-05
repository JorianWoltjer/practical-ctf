---
description: >-
  Finding information about the target system find vulnerabilities to allow
  privilege escalation
---

# Enumeration

## LinPEAS

A good place to start is to the run [linpeas.sh](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) script on the target that checks all sorts of things. The script is regularly updated so make sure to download a new copy from time to time in order to get the newest techniques.&#x20;

This script will give a ton of output that you can look through. It will also show interesting files to look at. To get a lot of information about the exploitability of something it found, look at the link below the title of the output. For example:

![Example of linpeas.sh output](<../../.gitbook/assets/image (35).png>)

It will highlight very likely Privilege Escalation vectors in ![](<../../.gitbook/assets/image (6) (1).png>), and other interesting things with <mark style="color:red;">**`RED`**</mark>. In the example above, it shows that there is a directory in the PATH variable to which we have write permissions. Normally only administrators (root) would have this permission.&#x20;

## [Pspy](https://github.com/DominicBreuker/pspy)

`pspy` is a tool that can detect the execution of commands on the target system. Without needing root permissions, it can find out what commands the root user or any other user is executing. It also finds command-line arguments for those commands and can be really useful for finding out what is happening in a system.&#x20;

Often there are [cron-jobs.md](cron-jobs.md "mention") running that automatically execute commands or scripts that you might not be able to find yourself. Using `pspy` you can often see these commands execute and think of privilege escalation techniques to exploit these commands.&#x20;

## Finding files

There are lots of files on a default Linux system, and it might be hard to look through all kinds of directories yourself to try and find interesting files. Luckily we can use the `find` command in Linux to search for files with specific properties. Here are a few useful examples:

```shell
find / -user [user]  # Find files owned by specific user
find / -name flag.txt  # Find files named "flag.txt" (allows * wildcards)
find / -type d -name config  # Find all directories named "config"
find / -perm a=x  # Find all files that anyone can execute
```

Sometimes due to permissions these commands can generate a lot of "Permission denied" errors in the output. To hide these errors just add a `2>/dev/null` to the end of the command to redirect errors to nothing.&#x20;

## Interesting directories

Some default directories often contain interesting information to look at. Here are a few:

* `/tmp`: A folder writable to everyone, often used in hacking to place temporary scripts because you should always be allowed to do so
  * `/dev/shm`: Is another similar directory, but a bit less common because it can sometimes be cleared
* `/home`: Contains all the regular users' home directories, which are sometimes readable. There might even be readable SSH keys in their `.ssh` folder or other secrets
* `/opt`: Is a directory only root can write to, but normal users should still be able to read it. This can sometimes contain interesting files that the root user uses or has placed there.&#x20;
* `/var/log`: Contains various log files from apache, nginx, or other applications

## Other tricks

* `sudo -l`: If no password is required, linpeas.sh will automatically find this. Otherwise, if you know the password of the user you are running as, make sure to check this with their password. See [sudo.md](sudo.md "mention") for exploitation of any entries you find
* `ps aux`: See all running processes and information about them
  * `ps axjf`: See processes in a tree structure
* Look at the `.bash_history` (or similar) history files inside of users' home directories. These may contain sensitive command-line arguments with passwords or other secrets
* `env`: To see all current environment variables
