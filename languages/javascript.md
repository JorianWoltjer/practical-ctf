---
description: >-
  A very popular language used to create interactivity on the web, and on the
  backend using NodeJS
---

# JavaScript

{% content-ref url="../web/web-frameworks/nodejs.md" %}
[nodejs.md](../web/web-frameworks/nodejs.md)
{% endcontent-ref %}

## Common Issues

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

The second argument to `replace()` functions determine what should be put in place of the matched part. It might come as a surprise that when this section is user-controlled input, there are some special character sequences that are not taken literally. The following sequences insert a special piece of text instead ([source](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global\_Objects/String/replace#specifying\_a\_string\_as\_the\_replacement)):

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

* `\x41` = `'A'`: Hex escape, shortest! ([CyberChef](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('None',0\)Find\_/\_Replace\(%7B'option':'Regex','string':'..'%7D,'%5C%5Cx$%26',true,false,true,false\)\&input=YWxlcnQoKQ))
* `\u0041` = `'A'`: Unicode escape, non-ASCII characters too! ([CyberChef](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('None',0\)Find\_/\_Replace\(%7B'option':'Regex','string':'..'%7D,'%5C%5Cu00$%26',true,false,true,false\)\&input=YWxlcnQoKQ))
* `\101` = `'A'`: Octal escapes, numeric-only payload! ([CyberChef](https://gchq.github.io/CyberChef/#recipe=To\_Octal\('Space'\)Find\_/\_Replace\(%7B'option':'Regex','string':'.\*'%7D,'%20$%26',false,false,true,true\)Find\_/\_Replace\(%7B'option':'Regex','string':'%20\(%5C%5Cd%2B\)'%7D,'%5C%5C%5C%5C$1',true,false,true,false\)\&input=YWxlcnQoKQ))

Other than these generic escapes, there are a few special characters that get their own escapes:

<table><thead><tr><th width="134" align="right">Syntax</th><th>Meaning</th></tr></thead><tbody><tr><td align="right"><code>\\</code></td><td>Backslash</td></tr><tr><td align="right"><code>\'</code></td><td>Single quote</td></tr><tr><td align="right"><code>\"</code></td><td>Double quote</td></tr><tr><td align="right"><code>\`</code></td><td>Backtick</td></tr><tr><td align="right">(0x0a) <code>\n</code></td><td>New Line</td></tr><tr><td align="right">(0x0d) <code>\r</code></td><td>Carriage Return</td></tr><tr><td align="right">(0x09) <code>\t</code></td><td>Horizontal Tab</td></tr><tr><td align="right">(0x0b) <code>\v</code></td><td>Vertical Tab</td></tr><tr><td align="right">(0x08) <code>\b</code></td><td>Backspace</td></tr><tr><td align="right">(0x0c) <code>\f</code></td><td>Form Feed</td></tr></tbody></table>

When inside [template literals](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template\_literals) (using `` ` `` backticks), you can use `${}` expressions to evaluate inline JavaScript code which may contain any code you want to run, or evaluate to any string you need.&#x20;

```javascript
`${alert()}`
`${String.fromCharCode(97,110,121,116,104,105,110,103)}` -> 'anything'
```

{% hint style="info" %}
Unrelated to strings, you can also use these templates as "[tagged templates](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Template\_literals#tagged\_templates)" to call functions without parentheses:

```javascript
alert``
```
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

### Comments

A few different and uncommon ways of creating comments in JavaScript:

```javascript
alert()//Regular comment

alert()/*multiline
comment*/alert()

alert()<!--HTML comment

#!shebang comment (start of line only)

-->HTML comment (start of line only)
```
