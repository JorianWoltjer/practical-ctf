---
description: Finding commands that are / can be executed with elevated privileges
---

# Command Triggers

## Automated (Cron Jobs)

Cron Jobs are a default way to execute commands or scripts in regular intervals. You can make scripts run every 2 minutes, every hour, every 3rd day of the month, etc. They execute commands as certain users, so if we as a low-privileged user can _change_ some behavior of these commands to get us as shell as that other user, we escalate privileges.

Cron table files (crontabs) store the configuration for cron jobs. The system-wide crontab is located at `/etc/crontab` which is often readable by all users:

<pre class="language-bash" data-title="/etc/crontab"><code class="lang-bash">SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / &#x26;&#x26; run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / &#x26;&#x26; run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / &#x26;&#x26; run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / &#x26;&#x26; run-parts --report /etc/cron.monthly )
# Custom
<strong>* * * * * root overwrite.sh
</strong><strong>* * * * * root /usr/local/bin/compress.sh
</strong></code></pre>

{% hint style="warning" %}
Know that you can't always find the source for cron jobs, as they may be hidden in unreadable files by your user. Tools like [#pspy](enumeration.md#pspy "mention") can show starting process in realtime in such cases to hypothesize about Cron Jobs
{% endhint %}

Here the top 4 jobs are pretty standard. Using the `run-parts` command they just say to run the scripts inside `/etc/cron.hourly`, `/etc/cron.daily`, `/etc/cron.weekly` and `/etc/cron.monthly`. They also say exactly when it will run, indicated by the first 5 values. The `/etc/cron.daily` directory for example runs every day at 6:25 AM.

In the example above, there are also two `overwrite.sh` and `compress.sh` scripts, which run **every minute** (indicated by the `* * * * *`, [here's a tool](https://crontab.guru/)). These are often interesting because they run very often, allowing us lots of chances to mess with them.&#x20;

{% hint style="info" %}
**Tip**: Use the `date` command to see the exact current time. Cron jobs execute at the 0-second mark so you'll know exactly when your payload should have executed.&#x20;

You can even use `watch -n 1 date` to get a date output that updates every second, so you can count down to exactly when it executes
{% endhint %}

These rules often trigger scripts, which are very valuable to read and understand when possible. More configurations like the [#usdpath](command-exploitation.md#usdpath "mention") variable are interesting to check, but most exploitation comes from the commands that are executed, and how you can influence them. For example, by overwriting the scripts directly with sufficient permissions, or writing malicious files that it uses.&#x20;

## Sudo

Using this command you get a list of commands you can execute as other users:

```bash
sudo -l
```

If you get any error message like these, it means you probably cannot use this technique for this user:

> Sorry, user \<username> may not run sudo on \<machine>.
>
> \<username> is not in the sudoers file. This incident will be reported.

In the _best-case_ scenario, you can run any command (even `sudo /bin/bash`) as root (without a password):

<pre class="language-bash"><code class="lang-bash">Matching Defaults entries:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User &#x3C;username> may run the following commands:
<strong>    (ALL) NOPASSWD: ALL
</strong></code></pre>

Another more common example is that you can only execute a certain program or the `NOPASSWD` tag is not set meaning you do need to enter the _current user's_ password:

<pre class="language-shell-session"><code class="lang-shell-session">User may run the following commands:
<strong>    (ALL : ALL) /usr/bin/find
</strong>
<strong>$ sudo find
</strong>Password: 
</code></pre>

Another common syntax to recognize is _which other user_ you execute the command as, as this is not always `root`:

<pre class="language-shell-session"><code class="lang-shell-session">User may run the following commands:
<strong>    (administrator) /usr/bin/cat
</strong>
<strong>$ sudo -u administrator cat
</strong></code></pre>

### `env_keep`

Sometimes the program itself is not exploitable, but there is an `env_keep` option. This option allows you to keep environment variables while executing the program, that normally get cleared.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ sudo -l
</strong>Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

User user may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/apache2
</code></pre>

Normally no environment variables are set at all (`env_reset` is doing this). All names added via `env_keep+=` can be set in your shell session, and will be kept when you run `sudo`. \
If it were `!env_reset` instead, all variables would be kept. This is even more exploitable as many ways exist to use environment variables for unintended behavior (see [#environment-variables](command-exploitation.md#environment-variables "mention")).

## SetUID

Set User ID (SUID) binaries are programs that when executed by anyone, will perform actions with the **permissions of the owner** of the program. All programs are files, and the SUID bit on a program is just a permission like read/write/execute that you might be familiar with. The SUID bit can be seen as an `s` character where there would normally be an `x` for executable permissions:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ ls -la /usr/bin/sudo
</strong>-rwsr-xr-x 2 root root 168136 Jan  5  2016 /usr/bin/sudo
   ^  ^       ^     ^
SUID  SGID   user group
</code></pre>

When this `s` permission is set by the owner, it means that for anyone executing this program, it will be like the owner of the program ran it. If the file owner is root for example, then you would be executing the program as root. This sounds very dangerous because it is.&#x20;

{% hint style="info" %}
Note: The Set Group ID (SGID) bit is very similar. When executed by anyone, it just sets the permissions to those of the **group** owner of the file. The second name in the `ls` output is the group, so you can see what permissions you would be getting
{% endhint %}

As a defender, you need to be absolutely sure that the program that is executing cannot do things other users shouldn't be able to do, like reading files, writing files, or executing arbitrary commands. Programs like `sudo` in the example above are secured by asking for a password and checking permissions very carefully. But this is also why a vulnerability in sudo or any other SUID program is a big deal.&#x20;

To find all files on the system having the SUID or SGID bit set, you can use a `find` command:

```shell
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2>/dev/null
```

An important note is that executing these programs **keeps the environment variables** that you set. This opens up a whole load of new inputs the binary does something with. The [#usdld\_preload-and-usdld\_library\_path](command-exploitation.md#usdld\_preload-and-usdld\_library\_path "mention") variables are _filtered_, but the [#usdpath](command-exploitation.md#usdpath "mention") variable is _kept_! If developers aren't careful to use absolute paths, this resolution can be overwritten by an attacker.

{% hint style="warning" %}
**Note**: _Shell scripts do not use the SUID bit_, these only matter on ELF executables. This was a decision made because SUID binaries should be as secure as possible ([more info](https://unix.stackexchange.com/a/2910))
{% endhint %}
