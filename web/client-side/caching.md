---
description: Remember static content to resolve less requests by the backend
---

# Caching

## # Related Pages

{% content-ref url="../server-side/reverse-proxies.md" %}
[reverse-proxies.md](../server-side/reverse-proxies.md)
{% endcontent-ref %}

## Concepts

To save on bandwidth and respond faster, large websites often implement a caching proxy in front of their regular servers that have a simple task: remember static content and handle requests that don't need the backend. While sounding simple, it comes with a lot of questions, like what needs to be cached and to who?

<figure><img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption><p>Responses being cached after one user requests it (<a href="https://portswigger.net/web-security/web-cache-deception#web-caches">source</a>)</p></figcaption></figure>

There are a few concepts that all caches share, and are useful to understand. First of all, **Cache Rules**. These are the decisions the caching proxy makes to figure out _if_ a request/response needs to be cached for future requests. Some dynamic APIs should never be cached, so you'll often see these target static resources like JS/CSS or images.

Then there are **Cache Keys** being the normalized versions of requests that find which requests should return equivalent responses, without actually asking the backend. These often include the path, query parameters, and potentially some headers. If two requests with the same cache key come in, the 1st will be resolved and the 2nd will be instantly returned from the cache of the 1st response.

### Is something cached?

By sending the same requests to an endpoint multiple times, there are some different ways to detect the effects of caching:

* Sometimes the response contains specific headers such as `X-Cache-Status: MISS` (meaning it wasn't stored before, but is now) or `CF-Cache-Status: HIT` (meaning it was stored and now returned from the cache). `BYPASS` often means it wasn't cached and instead requested from the backend.
* If the backend is noticeably _slow_, you may be able to measure when a resource responds quicker than normal because it's coming directly from the caching server.
* If you can _edit_ the underlying resource (such as a profile image), request it, change your image and then quickly request it again to check if the change had an effect, or if it takes some more time because it is still cached.

While testing, it is common to use **cache busters** to explicitly _not_ cache something, or cache it only with a specific identifier to avoid messing with real users. You can put the same random string into both of your testing requests, guaranteeing that it won't have been cached before by other users but maybe it will be now that you've requested it. This is often done with a `?cb=$RANDOM` query parameter.

## Browser Cache

### Disk Cache

Browsers will cache certain responses in the disk or memory cache. While testing, make sure to uncheck the <img src="../../.gitbook/assets/Disable cache.png" alt="" data-size="line"> box in the _Network_ tab of your DevTools. To clear this cache, the easiest way is to clear it globally via `chrome://settings/clearBrowserData` (Chrome) or `about:preferences#privacy` (Firefox).

In the table of requests, you'll see <img src="../../.gitbook/assets/image (62).png" alt="" data-size="line"> in place of the _Size_ column if the response came from the cache. You may also see 304 Not Modified status codes for responses that are cached, but revalidated to ensure they haven't changed. Top-level navigations will always revalidate the cache, but `fetch()`es or loading resources can be retrieved directly from the cache with no request to the server.

The [`Cache-Control`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cache-Control) header decides if and for how long a response will be cached, and how it is revalidated. The `Vary` header adds the specified request headers to the cache key. If no such headers are given, the browser will cache the response by default but revalidate it every time it is used (with the `If-Modified-Since` or `If-None-Match` header). If you need to get the cached version of a response for some reason without revalidating first, `fetch()` has a [`cache`](https://developer.mozilla.org/en-US/docs/Web/API/Request/cache) option that you can set to `force-cache`. This is used in [#origin-with-credentials-cache](cross-site-request-forgery-csrf.md#origin-with-credentials-cache "mention").

One edge case is [**Service Workers**](https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API/Using_Service_Workers) which need to be registered with a specific JavaScript URL. These skip the cache by default, but using the `{ updateViaCache: 'all' }` option you can enable it. This may allow you to poison the cache client-side and then load a service worker from there for persistent XSS. See [writeups to this challenge](https://bugology.intigriti.io/intigriti-monthly-challenges/0325) for more details.

Another use for disk cache is the fact that the HTML will always stay the same, while **JavaScript code is re-executed**. If this fetches a payload dynamically, it can allow you to run a payload multiple times on one static DOM, even if during regular navigations it would be different every time. This could be useful in limited CSS Injection scenarios. See [this writeup](https://gist.github.com/arkark/5787676037003362131f30ca7c753627) for an example, and [#poisoning-top-level-navigation-with-fetch](caching.md#poisoning-top-level-navigation-with-fetch "mention") for how to perform a top-level navigation to a disk cached resource _without revalidating_.\
It may also be used for retrieving an earlier response with XSS that the user navigated away from, and cannot get back to due to corruption or a different cookie etc. [bi0sCTF 2024 - Image Gallery 1](https://blog.bi0s.in/2024/03/06/Web/ImageGallery1-bi0sCTF2024/#Image-gallery-1) is an example of this.

To protect against attacks involving caches such as XS-Leaks or Client-Side Cache Poisoning/Deception, they are separated by _eTLD+1_ as specified in [Cache Partitioning](https://developer.chrome.com/blog/http-cache-partitioning#how_will_cache_partitioning_affect_chromes_http_cache). This means subdomains will share a cache, but a separate attacker's domain will not.

### Back/forward (bfcache)

While the disk cache helps with speed, the browser's <img src="../../.gitbook/assets/image (64).png" alt="" data-size="line"> (Back and Forward) buttons should ideally keep the _state_ of the webpage as well. This is what the Back/forward cache (or "bfcache") does, remembering pages you navigate through and their JavaScript heap. You can trigger this programmatically with [`history.back()`](https://developer.mozilla.org/en-US/docs/Web/API/History/back) or the more generic [`history.go(n)`](https://developer.mozilla.org/en-US/docs/Web/API/History/go).

{% embed url="https://web.dev/articles/bfcache" %}
Explaining the usefulness of bfcache and technical details/edge cases
{% endembed %}

To check if a page was loaded through bfcache, keep an eye on the _Applications_ -> _Back/forward cache_ section. While navigating this will either show "Not served from back/forward cache" (with a reason if you pressed the Back button) or "Successfully served from back/forward cache" when it was successful.

<figure><img src="../../.gitbook/assets/image (63).png" alt=""><figcaption><p>After pressing back, it successfully loaded from bfcache</p></figcaption></figure>

Restoring from this cache means all JavaScript and DOM state (also input values) will remain the same, allowing an attacker to attack this data with a `localStorage` XSS or anything that will be reloaded. In some more complex attacks it can be useful to be able to _clear_ the bfcache, which is possible by simply overflowing the maximum of 6 navigations, and then going back with `history.go(-n)` to your target page. The following writeup explains this idea with great interactive visuals:

{% embed url="https://adragos.ro/dice-ctf-2025-quals/#websafestnote" %}
Explaining Local Storage HTML-Injection abuse using bfcache clearing
{% endembed %}

#### Cache uncacheable resources

The browser wants to cache as many resources as possible, but it can't always be certain that a resource hasn't been changed. There are many interconnected rules that decide this heuristically, see the following article for a detailed summary of what response headers matter:

{% embed url="https://blog.huli.tw/2017/08/27/en/http-cache/" %}
Explanation of the various browser cache heuristics
{% endembed %}

Some resources like ones without any special response headers, may be cached without an _age_. This would normally mean they are always first revalidated with headers like `If-Modified-Since` (from `Last-Modified`) and `If-None-Match` (from `Etag`), before being returned. You can recognize this by the **304 Not Modified** status code.

It will always be revalidated, which takes time. If for any reason you need to request to be instantaneous, such as in a Race Condition, bfcache can help out. The following writeup explains this idea:

{% embed url="https://blog.vitorfalcao.com/posts/intigriti-0525-writeup/#taming-the-bfcache" %}
Caching a slow `fetch()` request with bfcache falling back on disk cache
{% endembed %}

Essentially, you can open your target in a window, it's resources will be loaded uncached. Then, navigate it to a page returning `<script>history.back()</script>`. This quickly goes back to the original URL, and tries to use bfcache. It's not eligible because a window reference exists, but trying its best to quickly craft the page, it falls back on _disk cache_. Even stale resources can be loaded straight from cache now, no revalidation happens!

As shown in the writeup, this can be very useful in abusing gadgets that rely on the DOM.\
If your target is iframeable the same attack flow works, without needing a click for `window.open()`:

{% code title="Using window.open()" %}
```html
<script>
  onclick = () => {
    w = window.open("https://target.com/page-with-resources-you-want-loaded-quickly");
  
    const blob = new Blob(["<script>history.back()<\/script>"], { type: "text/html" })
    setTimeout(() => {
      w.location = URL.createObjectURL(blob);
    }, 3500);
  }
</script>
```
{% endcode %}

{% code title="Using <iframe>" %}
```html
<iframe src="https://target.com/page-with-resources-you-want-loaded-quickly"></iframe>
<script>
  const blob = new Blob(["<script>history.back()<\/script>"], { type: "text/html" });
  setTimeout(() => {
    frames[0].location = URL.createObjectURL(blob);
  }, 3500);
</script>
```
{% endcode %}

If you want to avoid the interaction required for `window.open()` and an iframe isn't possible, you may still be able to use a [`<meta http-equiv=refresh>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta#setting_a_page_redirect) tag to get the target back to your site, and then go back. It will normally trigger bfcache but if you want to avoid it and fall back to Disk Cache as in this example, another condition is its maximum of 6 entries. going as that with `history.go(-7)` after a bunch of extra redirects will bypass it.\
[Check this page for a description of all possible error reasons](https://developer.mozilla.org/en-US/docs/Web/API/Performance_API/Monitoring_bfcache_blocking_reasons#blocking_reasons) that you may be able to trigger.

#### Poisoning top-level navigation with `fetch()`

I previously stated that a top-level navigation will always first revalidate, and then either get the page from cache if it hasn't changed or get the new one. This is not entirely true, as there is actually another way to load a URL top-level, that is via bfcache. When pressing the back button (or triggering it via JavaScript), the nest page may be loaded from either one of three steps:

1. If it is stored in the Back/forward cache, return it directly from there
2. If it is stored in the disk cache, return it directly from there
3. Send a request to the server and return that response

It's hard to influence 1, but 2 can be poisoned by a `fetch()` call to store a cache entry on a URL with some special headers. If the response to this fetch is of type `text/html` and contains an XSS payload, the top-level navigation from the cache may trigger it even though the navigation shouldn't normally be able to send special extra headers or a request method such as `PUT`, `DELETE` or `PATCH`.

To skip option 1, there are some rules that make bfcache disallowed, like if the [window has an `opener`](https://web.dev/articles/bfcache?hl=en#avoid-window-opener). This can be achieved by first getting on an attacker's page, and then opening the URL you will later restore from cache. Then navigate to the URL that will poison the cache, and finally execute `history.back()`. Because it still has an opener reference to the attacker's page, the bfcache won't be used, but the disk cache from the fetch will.

{% code title="back.html" %}
```html
<script>
  const n = parseInt(new URLSearchParams(location.search).get("n"));
  history.go(-n);
</script>
```
{% endcode %}

<pre class="language-javascript"><code class="lang-javascript">const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  // Put URL into history, may error for now
<strong>  w = window.open("https://example.com/page/to/be/poisoned");
</strong>  await sleep(1000);

  // Use a fetch() with special headers etc. to poison the above URL
<strong>  w.location = "https://example.com/poisoner?payload=&#x3C;script>...";
</strong>  await sleep(1000);
    
  // We can't call history.back() directly on a cross-origin window,
  // so navigate to our origin which will do history.go(-2)
<strong>  w.location = "/back.html?n=2"
</strong>})();
</code></pre>

For examples of this check out the writeups of [SECCON 2022 - spanote](https://blog.arkark.dev/2022/11/18/seccon-en/#web-spanote) and the [Intigriti March 2023 XSS Challenge](https://mizu.re/post/intigriti-march-2023-xss-challenge#-disk-cache-to-the-moon).

### Iframe reparenting

{% embed url="https://blog.huli.tw/2024/09/07/en/idek-ctf-2024-iframe/" %}
Detailed explanation of a challenge involving _iframe reparenting_ and similar concepts
{% endembed %}

[#back-forward-bfcache](caching.md#back-forward-bfcache "mention") talked about windows and tabs navigating through history, but iframes can do this too. Surprisingly, these are also stored as global history entries just like regular navigations. This means that if you click a link inside an iframe, and then one in its parent, going back once will send back the parent still has its 2nd content.

<figure><img src="../../.gitbook/assets/iframe-reparenting.gif" alt=""><figcaption><p>Showcase of iframe keeping its content after going back (<a href="https://r.jtw.sh/poc.html?body=%3Ch1%3EParent%3C%2Fh1%3E%0D%0A%3Cdiv%3E%0D%0A%09%3Ciframe%0D%0A%09%09src%3D%22https%3A%2F%2Fr.jtw.sh%2Fpoc.html%3Fbody%3D%253Ch1%253EFirst%253C%252Fh1%253E%250D%250A%253Ca%2Bhref%253D%2522https%253A%252F%252Fr.jtw.sh%252Fpoc.html%253Fbody%253D%25253Ch2%25253ESecond%25253C%25252Fh2%25253E%2522%253EGo%2Bto%2Bsecond%253C%252Fa%253E%22%3E%3C%2Fiframe%3E%0D%0A%3C%2Fdiv%3E%0D%0A%3Ca+href%3D%22https%3A%2F%2Fr.jtw.sh%2Fpoc.html%3Fbody%3DNow%2Btry%2Bgoing%2Bback%22%3ENavigate+away%3C%2Fa%3E">source</a>)</p></figcaption></figure>

Now familiar with the bfcache, this behavior may not be surprising to you. It keeps the entire page's state, including iframe content so it can restore it when you go back.

The strange part, however, is that **this demo still works** if you have a reference to the page and **bfcache fails**, so it falls back to [#disk-cache](caching.md#disk-cache "mention"). Somehow the browser knows during the first back press to put the 2nd iframe content into the HTML retrieved from disk. This is known as _iframe reparenting_. The browser stored the position and content of each iframe so it knows where to place it in which navigation, trying its best to act the same as in non top-level navigations.

This causes problems when **JavaScript has altered the HTML** stored in disk cache, because when going back, this state isn't kept while the iframes still need to get their potentially navigated content. If the JavaScript added a `sandbox` attribute to the iframe, for example, this isn't kept when going back while a future `src` may be set.\
The following example showcases how this can go wrong, by loading an untrusted page in a sandbox that's applied after the fact:

<pre class="language-html" data-title="https://target.com"><code class="lang-html">&#x3C;body>
<strong>  &#x3C;iframe id="iframe" src="/?b=Initial content">&#x3C;/iframe>
</strong>&#x3C;/body>
&#x3C;script>
  setTimeout(() => {
<strong>    iframe.sandbox = "";  // Should be safe with fully-enabled sandbox
</strong><strong>    iframe.src = '/xss.html?b=&#x3C;script>alert(origin)&#x3C;\/script>';
</strong>  }, 2000);
&#x3C;/script>
</code></pre>

An attacker can get a reference to the above HTML, and after 2 seconds have passed the iframe's history entry has been added while the initial HTML is only stored in Disk Cache. Then the attacker navigates the window to a `history.back()` page, it loads the initial HTML with the updated XSS iframe content. This causes the XSS to be triggered:

{% code title="Attack" %}
```html
<iframe	src="https://target.com"></iframe>
<script>
  const blob = new Blob(["<script>history.back()<\/script>"], { type: "text/html" });
  setTimeout(() => {
    frames[0].location = URL.createObjectURL(blob);
  }, 3000);
</script>
```
{% endcode %}

Even if _cache is disabled_, the iframe reparenting feature _still works_. This feature works by remembering the order of iframes and their content. So if the original page had 1 iframe, and we navigate away then come back, and the newly returned response still has 1 iframe anywhere, the browser will attach the stored iframe content into that found iframe. Even if the rest of the page has changed.

Below is an example that shows going back and forth with a **changing** top-level page will keep the iframe's history as expected. While navigated away, you can even alter the PHP source code to move the iframe somewhere else on the page, and the moment you go back the browser will still be able to find it and put the "Second" content in it.

{% code title="Example" %}
```php
<?php
header("Cache-Control: no-store");  // Disable Disk Cache
?>
<script>
  window.addEventListener('unload', function() {});  // Disable bfcache
</script>
<h1>Parent</h1>
<p><?= random_int(0, 1000);  /* Notice the page content change */ ?></p>
<div>
  <iframe src="https://r.jtw.sh/poc.html?body=%3Ch1%3EFirst%3C%2Fh1%3E%0D%0A%3Ca+href%3D%22https%3A%2F%2Fr.jtw.sh%2Fpoc.html%3Fbody%3D%253Ch2%253ESecond%253C%252Fh2%253E%22%3EGo+to+second%3C%2Fa%3E"></iframe>
</div>
<a href="https://r.jtw.sh/poc.html?body=Now+try+going+back">Navigate away</a>
```
{% endcode %}

#### Policy containers

The `sandbox` attribute restricts the iframe, but is an attribute outside of the sandbox. For that reason it's not remembered during the navigation. Other security features like the [content-security-policy-csp.md](cross-site-scripting-xss/content-security-policy-csp.md "mention") or [`Referrer-Policy:`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy) are actually remembered _with_ the iframe's content, known as the [_policy container_](https://html.spec.whatwg.org/multipage/browsers.html#policy-container).

What this means for us is that the CSP which was active while the history entry was saved is the one that is restored. Even if the top-level HTML page has changed in the meantime. This can happen with [`<iframe srcdoc>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/iframe#srcdoc) because it _inherits the CSP_ of its parent, no other type of iframe does this. After going back, the CSP may have changed on the top-level page, but the iframe will still restore its one from earlier that it inherited.

Check out [the original writeup](https://blog.huli.tw/2024/09/07/en/idek-ctf-2024-iframe/#putting-it-all-together) to learn how these facts could be combined by altering an HTML injection payload with/without a sandbox to achieve XSS in a special scenario.

## Cache Poisoning

When two requests normalize to the same cache key, they should always result in the same response. With tricky parsing and rules, however, this can sometimes not be the case. Take any request that a regular user's browser makes while browsing the website, such as a resource or page. If an attacker can make a request with the same cache key and cause a different response than expected to be cached, it can be disastrous for the user as it often makes the feature/application unusable.

That is the gist of Cache Poisoning, altering a request to return another cacheable response that users will encounter. It is explained in more detail with examples and labs below:

{% embed url="https://portswigger.net/web-security/web-cache-poisoning" %}
Learn about Cache Poisoning and practice interactive labs
{% endembed %}

The most important part in exploiting this is knowing the **cache key**. If you can alter your request enough to cause a different response while keeping the same cache key, it will be vulnerable. Note that your alternative response must still be cacheable, this is where cache rules come in. If it causes a 400 Bad Request or 404 response, it often will be denied from the cache and requested the 2nd time anyway. You must have a successful but different response.

This is often achieved with extra _request headers_. Some of these headers will cause the application to act differently, maybe return a redirect or a different response format. Specifically, NextJS has been [haunted](https://zhero-web-sec.github.io/research-and-things/nextjs-and-cache-poisoning-a-quest-for-the-black-hole#section-1) [by](https://zhero-web-sec.github.io/research-and-things/nextjs-and-cache-poisoning-a-quest-for-the-black-hole#section-2) [this](https://zhero-web-sec.github.io/research-and-things/nextjs-and-cache-poisoning-a-quest-for-the-black-hole#section-3) [many](https://zhero-web-sec.github.io/research-and-things/nextjs-cache-and-chains-the-stale-elixir) [times](https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware).&#x20;

When working with source code, it is best to look for request attributes that cause conditions to happen, often about returning a different kind of response (eg. the `Accept:` header). In a blackbox scenario fuzzing may be a better option, trying weird variations of the request while keeping track of if it's still being cached under the same key or not.

Sometimes a very lax cache key can miss things like query parameters that are important for controlling a backend response. Another sneaky method is using the `#` in a request. While these are not normally sent over HTTP, they can be and the backend server may deal with it in a strange way:

```http
GET /static/main.js#/../../uploads/attacker.js HTTP/1.1
```

The above's cache key may be truncated to `/static/main.js`, while the backend interprets the path traversal and returns the uploaded malicious JavaScript file.

## Cache Deception

If cache is shared between users, private data should not end up in the cache. In Cache Deception, an attacker prepares a URL that a victim will visit to get cache some of their personal data with their authentication. The attacker can then request the same URL to get back the cached response _without_ authentication.

{% embed url="https://portswigger.net/web-security/web-cache-deception" %}
Learn about Cache Deception and practice interactive labs
{% endembed %}

Routes like `/api/profile` are normally ruled out from the cache, while files under `/static` or with the `.js` extension will always be cached. If you can confuse the URL parsers of the caching proxy and backend such that it thinks your URL matches the cache rules, while it returns private user data, you have Cache Deception!

Nginx will resolve even encoded path traversals, so one example exploit would be sending the victim to:

[https://example.com/static/..%2Fapi%2Fprofile](https://example.com/static/..%2Fapi%2Fprofile)

The caching proxy like Cloudflare may be configured to cache every path starting with `/static/`, while Nginx passes the decoded and resolved `/api/profile` to the backend, returning the currently logged-in user's private data. This will now be cached, and when the attacker visits the above URL shortly after the victim, they will receive their victims response.

For file extensions, it is common to try and find a character that truncates the path, such as `;.js` in Tomcat or `%00.js` when strings are null-terminated. If the path is matched including the query string, simply adding the extension after a question mark like `?.js` will do. When it is normalized an encoded one may do the trick(`%3F.js`).\
You may be able to see the pattern here, simply fuzz all potential characters and their encoded forms to try and find delimiters. Then exploit it as follows:

[https://example.com/api/profile;.js](https://example.com/api/profile;.js)

In some PHP configurations, it is also common to rewrite every suffix path of a `.php` file to the same endpoint, for example:

[https://example.com/api/profile.php/anything.js](https://example.com/api/profile.php/anything.js)

All of these tricks require the cache key to not include any unpredictable data, such as the session cookie. The cache needs to be shared between users so that an unauthenticated attacker can retrieve the stolen data.
