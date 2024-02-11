---
description: Finding your attack surface and testing credentials
---

# Scanning/Spraying

While working on the engagement, you will often keep finding new information that you should keep track of. Here is a logical way of structuring the information you find like IPs, usernames, and passwords. The rest of the commands in this section will use these files in the examples:

* `ips.txt`: All valid IP addresses that you can reach. For example, whenever you find a new internal network, you can add more IPs to this list.
* `users.txt`: Every valid username or domain user. Many tools accept such a list for trying some action on every user.
* `emails.txt`: Similar to the `users.txt` file, but with an `@domain.tld` suffix to be used in tools requiring the domain per user, or for sending mass-phishing emails.&#x20;
* `passwords.txt`: Every password you find from any source. If a password has a matching username, make sure it is put on the same line as in `users.txt`, this way some tools like [NetExec](https://github.com/Pennyw0rth/NetExec) can use `--no-bruteforce` to try usernames with their corresponding password only.

It may also be useful to export certain environment variables to use in commands, in order to make them more generic. Variables like `$DC` (domain controller) or `$DOMAIN` (domain of the Active Directory) will be used in commands in the following sections. Set these in Linux using `export`:

```bash
export DC=10.10.10.10
export DOMAIN=domain.tld
```

## Anonymous logins

Some protocols with some settings in Windows allow for a special "guest" user to log in without requiring real credentials. These types of authentication often grant you very low privileges, but they may be enough to do something interesting, or at least learn more about the environment.&#x20;

Here are some commands that test for the existence of these types of binds:

```bash
# SMB (port 139,445)
smbclient -L //$IP -U %         # Empty username and password
smbclient -L //$IP -U " "%" "   # Space as username and password
smbclient -L //$IP -U guest%    # 'guest' username and empty password
# LDAP (port 389,636)
ldapsearch -h $IP 389 -x -s base -b '' "(objectClass=*)" "*" +
```

<pre class="language-shell-session"><code class="lang-shell-session"># # FTP (port 21)
<strong>$ ftp $IP
</strong>220 Rebex FTP Server ready.
<strong>Name ($IP:user): anonymous
</strong>331 Password required for 'anonymous'.
<strong>Password: anonymous@domain.com
</strong>230 User 'anonymous' logged in.
> 
</code></pre>

## Scanning & Networking

See [nmap.md](../web/enumeration/nmap.md "mention") for a guide on scanning IP addresses for open ports. On Windows, here is a very minimal scan that can be applied to large ranges or slow connections:

{% code overflow="wrap" %}
```bash
nmap -sT -n -Pn -sV -sC -vv --open -p21,22,25,53,80,88,135,139,389,443,445,464,636,1433,2222,3000,3268,3269,3306,3389,5000,5985,8000,8080 -iL ips.txt -oN nmap/external.txt
```
{% endcode %}

When having gotten access to some machine, it may be inside some internal network not visible from the outside. Check this using `ipconfig`:

```powershell
ipconfig /all
```

To be able to access other machines in this newly discovered network from your own attacking machine, a useful tool is [#ligolo-ng](../linux/linux-privilege-escalation/networking.md#ligolo-ng "mention"), which can tunnel the traffic like a VPN.

## Spraying

### Enumerating usernames

#### Kerberos user enumeration

When all you have is access to the domain controller, but no valid credentials yet, you can use Kerberos (port 88) to test if a given username is valid. The following tool does this using a wordlist:

{% embed url="https://github.com/ropnop/kerbrute" %}
Perform various brute-force attacks like user enumeration through the Kerberos protocol
{% endembed %}

```bash
kerbrute userenum --dc $DC -d $DOMAIN /list/names.txt
```

As a wordlist, [`kerberos_enum_userlists`](https://github.com/attackdebris/kerberos\_enum\_userlists) has some lists in the 'a.smith' and 'asmith' format as this is common for organizations. Another list for only the most common (ordered) **first names** is here:

{% file src="../.gitbook/assets/names.txt" %}
List of 6781 english first names ordered so the most common are first
{% endfile %}

#### LDAP query

When you have valid domain credentials, a simpler option than brute-force is to simply query LDAP (port 389) on the domain controller, to make sure you have all existing users:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ nxc ldap $DC -u $USERNAME -p $PASSWORD --users
</strong>...
LDAP    $DC     389    DC01       Administrator     Built-in account for administering the computer/domain
LDAP    $DC     389    DC01       Guest             Built-in account for guest access to the computer/domain
LDAP    $DC     389    DC01       krbtgt            Key Distribution Center Service Account
LDAP    $DC     389    DC01       user1
LDAP    $DC     389    DC01       user2
LDAP    $DC     389    DC01       user3
</code></pre>

{% hint style="info" %}
**Tip**: If you get a "\[Errno -2] Name or service not known" message, it cannot resolve the domain name. Make sure you add any hosts like `dc01.$DOMAIN` to your `/etc/hosts` file.
{% endhint %}

LDAP contains much more domain information, not just usernames. [#bloodhound](active-directory-privilege-escalation.md#bloodhound "mention") can do this.

### Spray passwords

To try one (or a few) passwords on many users, there are different protocols you can use. In the end they all query the same data, but some protocols might be unavailable due to various reasons. The most common is SMB (port 139,445), which is mainly used for sharing files over the network, but also different mechanisms like printers or some internal communication.

Important to note is that Active Directory has **rate limiting** in the form of **blocking accounts** after too many failed login attempts. In the following example, after 5 failed attempts on the account, it will be blocked for 30 minutes. Only after that period will you be able to try again.

<pre class="language-powershell"><code class="lang-powershell">PS C:\> net accounts
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          42
Minimum password length:                              7
Length of password history maintained:                24
<strong>Lockout threshold:                                    5
</strong><strong>Lockout duration (minutes):                           30
</strong><strong>Lockout observation window (minutes):                 30
</strong>Computer role:                                        WORKSTATION
</code></pre>

You can see this behavior in action in the following example:

<pre class="language-shell-session" data-title="Account Lockout Example"><code class="lang-shell-session"><strong>$ nxc smb $IP -u $USERNAME -p /list/rockyou.txt
</strong>SMB   $IP   445    DC01     [-] $DOMAIN\$USERNAME:123456    STATUS_LOGON_FAILURE
SMB   $IP   445    DC01     [-] $DOMAIN\$USERNAME:12345     STATUS_LOGON_FAILURE
SMB   $IP   445    DC01     [-] $DOMAIN\$USERNAME:123456789 STATUS_LOGON_FAILURE
SMB   $IP   445    DC01     [-] $DOMAIN\$USERNAME:password  STATUS_LOGON_FAILURE
SMB   $IP   445    DC01     [-] $DOMAIN\$USERNAME:iloveyou  STATUS_LOGON_FAILURE
<strong>SMB   $IP   445    DC01     [-] $DOMAIN\$USERNAME:princess  STATUS_ACCOUNT_LOCKED_OUT
</strong><strong>SMB   $IP   445    DC01     [-] $DOMAIN\$USERNAME:1234567   STATUS_ACCOUNT_LOCKED_OUT
</strong></code></pre>

The tool used here is [NetExec](https://github.com/Pennyw0rth/NetExec), a _fork of_ [_CrackMapExec_](https://github.com/byt3bl33d3r/CrackMapExec) after it has been archived. This tool is very useful for spraying various protocols with credentials, and then performing actions with found logins.

{% embed url="https://github.com/Pennyw0rth/NetExec" %}
Tool for interacting with Active Directory protocols
{% endembed %}

To spray a password for all users you have, simply provide a domain-joined IP with SMB open, and use the `-u` and `-p` options from which it will try all combinations:

```bash
# SMB (port 139,445)
nxc smb $IP -u users.txt -p $PASSWORD
nxc smb $IP -u users.txt -p passwords.txt
# LDAP (port 389,636)
nxc ldap $IP -u users.txt -p $PASSWORD
nxc ldap $IP -u users.txt -p passwords.txt
...
```

### Brute Forcing

In [#spray-passwords](scanning-spraying.md#spray-passwords "mention") you read how most Windows protocols have a lockout policy. RDP and SSH however don't have this by default and may allow long brute-force attacks that can guess more complex passwords. The best tool for this job is `hydra`:

{% embed url="https://github.com/vanhauser-thc/thc-hydra" %}
Brute Forcing tool for many protocols and built for speed at scale
{% endembed %}

Similar to NetExec, it implements various protocols. But this tool is specially built for brute force attacks at a large scale. It does not have further exploitation capabilities, only finding credentials.&#x20;

For the username, password, and IP you can choose either a static value, or try everything from a list.&#x20;

{% code title="Templates (SSH)" %}
```bash
hydra -l $USERNAME -p $PASSWORD -M ips.txt ssh  # Try password on all IPs (SSH)
hydra -l $USERNAME -P /list/passwords.txt ssh://$IP  # Guess password for one user
hydra -L /list/usernames.txt -p $PASSWORD ssh://$IP  # Guess username for a password
hydra -L /list/usernames.txt -P /list/passwords.txt ssh://$IP  # Guess user and pass
hydra -C /list/credentials.txt -M ips.txt ssh  # Try specific credentials on all IPs
```
{% endcode %}

To brute force RDP, or another supported protocol, simply replace `ssh` with `rdp`:

```bash
hydra -l $USERNAME -p $PASSWORD -M ips.txt rdp  # Try password on all IPs (RDP)
```

Another common task is trying common credentials on website login pages. If the login page looks like a common piece of software, your first step should be **looking up the "default credentials"** in a search engine. Otherwise, some of the credentials below are common defaults:

```
admin:admin
admin:password
admin:root
root:root
root:password
root:admin
guest:guest
user:password
```

{% hint style="info" %}
**Tip**: If you know any usernames, also try a `[username]:[username]` combination, there is a decent chance that their password will be the same as their username.
{% endhint %}

When these don't work, or you can't find any, you can try to brute force it a little. Hydra also has built-in options for this for simple HTTP forms, but for more complex flows try out [ffuf](https://github.com/ffuf/ffuf) (details in[#find-content](../web/enumeration/#find-content "mention")). When things are simple, like a Basic Auth prompt, hydra suffices:

<figure><img src="../.gitbook/assets/image (12) (1).png" alt="" width="375"><figcaption><p>Example website Basic Auth login prompt</p></figcaption></figure>

This type of prompt comes from the following response header:

```http
WWW-Authenticate: Basic realm="..."
```

When you fill out this form the browser gives you, you will send the following header with all future requests to that origin. This contains your username and password in base64 separated by a colon (`:`). For example, this decodes to `username:password`:

```http
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
```

Hydra can automatically encode and send data like this if you provide the `http-get` option:

{% code title="Brute Force Basic Auth" %}
```bash
hydra -l admin -P /list/passwords.txt $IP http-get /path/to/login
```
{% endcode %}

Finally, the last thing it can do with websites is automatically submit POST forms. When a custom login page is made this is by far the most common way of authenticating, which has custom parameters and URLs that will verify the credentials. To automate such a login a little bit of analysis is required to find out how a form is built, easily done by intercepting the request in a proxy like [Burp Suite](https://portswigger.net/burp).&#x20;

<pre class="language-http" data-title="Example POST login"><code class="lang-http"><strong>POST /login.php HTTP/1.1
</strong>Host: example.com
Content-Length: 27
...
Content-Type: application/x-www-form-urlencoded
Connection: close

<strong>username=user&#x26;password=pass
</strong></code></pre>

Things to look out for here are the path, and the body itself with your input in it. These can all be put into hydra in a sort of template format, where it will fill in the username and password every time. The response to this request is also good to take note of, like "Login failed". Hydra can use this to determine if a login is successful or not. For example:

{% code overflow="wrap" %}
```bash
hydra -l admin -P /list/passwords.txt $IP http-post-form "/login.php:username=^USER^&password=^PASS^:Login failed"
```
{% endcode %}

You'll notice the big string at the end that separates the path, the body with `^USER^` and `^PASS^` template variables, and lastly a failed login response to look for.&#x20;

### Enumerating access

When you have found credentials, they may have access to various different places with different permissions. Try using `nxc` to spray them as shown above while looking at the amount of access. For SMB, for example, you can list the shares you may access on each server with READ or WRITE perms:

```bash
nxc smb ips.txt -u $USERNAME -p $PASSWORD --shares
```
