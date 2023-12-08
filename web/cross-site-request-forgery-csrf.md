---
description: >-
  Submitting data-altering requests blindly from your domain on the client-side.
  Cookies are automatically sent, often requiring CSRF tokens as protection
---

# Cross-Site Request Forgery (CSRF)

## Description

Websites need to be able to access their own sensitive content, while malicious websites should not be able to access that same data from another site. To make this possible, _browsers_ implement some **same-origin** and **same-site** policies. These either allow or deny an action based on the **origins** of the request. As you can read in the table below, _same-site_ is generally more allowing than _same-origin_:

<table><thead><tr><th width="244">Request from</th><th width="216">Request to</th><th>Same-site?</th><th>Same-origin?</th></tr></thead><tbody><tr><td><code>example.com</code></td><td><code>example.com</code></td><td><mark style="color:green;"><strong>Yes</strong></mark></td><td><mark style="color:green;"><strong>Yes</strong></mark></td></tr><tr><td><code>app.example.com</code></td><td><code>other.example.com</code></td><td><mark style="color:green;"><strong>Yes</strong></mark></td><td><mark style="color:red;"><strong>No</strong></mark>: mismatched domain name</td></tr><tr><td><code>example.com</code></td><td><code>example.com:8080</code></td><td><mark style="color:green;"><strong>Yes</strong></mark></td><td><mark style="color:red;"><strong>No</strong></mark>: mismatched port</td></tr><tr><td><code>example.com</code></td><td><code>example.co.uk</code></td><td><mark style="color:red;"><strong>No</strong></mark>: mismatched eTLD</td><td><mark style="color:red;"><strong>No</strong></mark>: mismatched domain name</td></tr><tr><td><code>https://example.com</code></td><td><code>http://example.com</code></td><td><mark style="color:red;"><strong>No</strong></mark>: mismatched scheme</td><td><mark style="color:red;"><strong>No</strong></mark>: mismatched scheme</td></tr></tbody></table>

One feature that uses the **same-origin** policy is [Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS). This prevents an attacker from requesting a page from a website on a user's behalf and being able to read the response content. If this were not the case, any website could steal secrets from any other website by simply requesting them. \
This policy ensures certain response headers are explicitly set to allow this cross-origin resource sharing.&#x20;

A different feature that uses the **same-site** policy is **Cookies**. On many websites cookies are everything that authenticates the user. If a request includes the session cookie of a user, they are allowed to perform actions on their account. Simple as that.\
To make sure malicious websites cannot simply recreate a `<form>` and send it automatically to change a password, for example, these requests are checked to be _same-site_ (see table above). If the origins are not same-site the cookies will not be sent.&#x20;

In the early web days, this `SameSite` did not exist for cookies. Nowadays it is an attribute on cookies that may be `None` (no protections), `Lax` (default, some protections) or `Strict` (most protections). This value is important to know as it decides what kind of cross-site requests will be authenticated. The table above shows that at least **any subdomain on any port** will **bypass** same-site protections because it is considered same-site. This means that any [cross-site-scripting-xss.md](cross-site-scripting-xss.md "mention") vulnerability on such a website may lead to you being able to make authenticated requests!

However, the reality is slightly more complicated. Because these rules are so lax, most sites implement their own protection: **CSRF Tokens**. These are extra fields on a form that are randomly generated, but attached to the user's session. Whenever a form is submitted, the extra CSRF token field is validated to match the session and only then will it be considered authenticated. \
A malicious site won't know this randomly generated token and therefore cannot make a fake request that includes it. This is assuming however that 1. This token is _implemented_, 2. This token is _generated securely_, and 3. This token is _unique per user_. ([learn more](https://portswigger.net/web-security/csrf/bypassing-token-validation))

### Examples

To get a more practical idea of these protections, here are some examples of what is and isn't allowed in modern browsers. Firstly, some practical examples of how an attacker's site can send POST data to another site if it is misconfigured:

{% code title="Using <form>" overflow="wrap" %}
```html
<form id=form action="https://example.com/reset_password" method="POST" enctype="application/x-www-form-urlencoded">
    <input type="text" name="password" value="hacked">
</form>
<script>form.submit();</script>
```
{% endcode %}

{% code title="Using fetch()" %}
```html
<script>
    fetch('https://example.com/reset_password', {
        method: 'POST',
        mode: 'no-cors',  // Prevent preflight request
        credentials: 'include',  // Include cookies if allowed
        headers: {  // Parse body as form submission
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: 'password=hacked',
    })
</script>
```
{% endcode %}

Here both methods can achieve the same requests, only with the `fetch()` method you can completely control the body data while using a `<form>` this is done for you depending on the `Content-Type`. \
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

#### Strict

As mentioned earlier, the SameSite protection only prevents cross-_site_ requests. If you can create a fake form or have javascript execution on a sibling domain or different port, this bypasses the restriction.&#x20;

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

{% code title="CSRF URL" %}
```python
https://example.com/post?postId=../reset_password%3Fpassword%3Dhacked
```
{% endcode %}

#### Lax (default)

This default SameSite value is by far the most common. It sits in the middle of `None` and `Strict` as it allows some specific behaviors to send cookies, but not others:

1. A top-level redirect using the `Location:` response header or `location=` in JavaScript. \
   Only for GET requests
2. Restrictions are only applied after 2 minutes from setting the cookie. This means that in the small window of time, any POST CSRF is possible as if it were `None`

You may be able to abuse this behavior if you find a state-changing GET request, or can trick the server into thinking it is a POST request with with backends like _Symfony_ that have an extra \
`?_method=` parameter that can be set to `POST` in a regular GET request:

```python
https://example.com/reset_password?_method=POST&password=hacked
```

The other time-based behavior has a small chance of a victim just having logged in being exploitable. This is pretty unlikely, but a more powerful way to use this is if the site allows **resetting the cookie**. When it is set again by opening a new tab from your site, for example, the timer is also reset and a CSRF is possible.&#x20;

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
            // After it has been reset, CSRF within the 2-minute window
            form.submit();
        }, 5000);
    }
</script>
```

#### None

With this SameSite attribute, the cookie is treated as before SameSite was implemented. This means any techniques like the `<form>` or `fetch()` will work and send cookies with any request method. In such cases, you should check if any CSRF tokens are required; if not, there's a good chance you can make any victim send any state-changing request when they visit your site.&#x20;
