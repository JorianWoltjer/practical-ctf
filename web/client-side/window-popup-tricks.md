---
description: >-
  Abusing browser functionality to do interesting things with popups and
  interactions
---

# Window Popup Tricks

## APIs

Before trying to understand how we can abuse popup windows, we should understand the functions we can call from JavaScript. The main one is [`window.open(url, target, windowFeatures)`](https://developer.mozilla.org/en-US/docs/Web/API/Window/open) which opens a new window, either a tab or a popup. The destiction is made by the 3rd `windowFeatures` argument which is a string containing some `key=value,` options. \
Specifying the `popup` key here will force a popup, but specifying any position or size will do so as well:

```javascript
window.open("https://example.com", "", "");  // Open new tab
window.open("https://example.com", "", "popup");  // Open popup
window.open("https://example.com", "", "width=200,height=200");  // Open small popup
window.open("https://example.com", "", "width=200,height=200,top=100,left=200"); // Open positioned popup
```

If you just add the above to a `<script>` tag without any extra code, you will get a warning like the following in most browsers by default:

<figure><img src="../../.gitbook/assets/image (56).png" alt=""><figcaption><p>Popup blocker preventing window from spawning</p></figcaption></figure>

The browser's built-in popup blocker prevents our window from spawning. Any `window.open()` calls require ["Transient activation"](https://developer.mozilla.org/en-US/docs/Glossary/Transient_activation) or just an **interaction**. The documentation explains what events trigger it and what APIs are affected by this protection. In short, we need the user to click somewhere, and inside the event handler for that click, open our popup:

```html
<script>
  // Set event handler (`window.addEventListener("click", () => {})` also works)
  onclick = () => {
    window.open("https://example.com", "", "popup"); // Open popup
  }
</script>
```

This successfully triggers the popup. In Chromium, the `onkeydown`, `onkeyup` and `onkeypress` events also work, while on Firefox only `onkeyup` works. This popup will open the given URL in a **top-level context**, sending with it any `SameSite=Lax` cookies, making attacks that require cookies more often possible.

{% hint style="success" %}
**Tip**: _Headless browsers_ (`--headless`) lack this "popup blocker", so in automated environments you will often be able to start as many popups as you want, whenever you want.
{% endhint %}

### Window References

We could also have saved the return value from `window.open()`, giving us a **window reference**. When the popup is cross-origin with the main page, we are very limited in what can be accessed on the window, but not fully out of options. See the following example:

<pre class="language-html"><code class="lang-html">&#x3C;script>
  let w;
  onclick = () => {
    w = window.open("https://example.com", "", "popup"); // Open popup
    console.log(w);
    
<strong>    setTimeout(() => {
</strong><strong>      w.location = "https://example.com/2"  // Change the URL of the popup
</strong><strong>    }, 1000);
</strong>  }
&#x3C;/script>
</code></pre>

Using the window reference, we can change the `.location` property to redirect the target page at any moment. For more complicated sequences, we could even redirect it to a URL same-origin with the main window, call some APIs that are only available for such windows, and then redirect it to the target page.

The popup will itself have a reference back to the main page as well. The [`window.opener`](https://developer.mozilla.org/en-US/docs/Web/API/Window/opener) variable holds a reference to the page that opened this window, so in our case the main page. The target page can also use this variable to detect when it is being displayed in a popup and act accordingly. In rare scenarios, you might want to prevent this detection and altered behavior. \
Luckily, it is very easy to revoke access to the `opener` variable, simply using the `noopener` window feature (ironically, introduced to enhance security):

```html
<script>
  onclick = async () => {
    // example.com will see `opener` as 'null' now, 
    // instead of a reference back to the main page
    window.open("https://example.com", '', 'popup,noopener')
  }
</script>
```

### Moving and Resizing

With a window reference, a _same-origin_ popup has [`.moveTo()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/moveTo) and [`.moveBy()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/moveBy) methods to move the window around, as well as [`.resizeTo()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/resizeTo) and [`resizeBy()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/resizeBy) methods to change its bounds. These can be called at any time to change what area a window covers, no matter if it's focused:

<pre class="language-javascript"><code class="lang-javascript">let w;
onclick = () => {
  w = window.open(origin, "", "width=200,height=200,top=100,left=200");
  
  setTimeout(() => {
<strong>    // Move 100px to the right
</strong><strong>    w.moveBy(100, 0);
</strong><strong>    // Increase height by 200px
</strong><strong>    w.resizeBy(0, 200);
</strong>  }, 1000);
}
</code></pre>

Note that these methods are only available on same-origin popups, check the DevTools Console for errors if you try to change the URL from `origin` to some random other website. We can, however, move the window right at the start before the real page loads:

<pre class="language-javascript"><code class="lang-javascript">let w;
onclick = () => {
  w = window.open("https://example.com", "", "width=200,height=200,top=100,left=200");
<strong>  w.resizeBy(0, 200);  // Works
</strong>  
  setTimeout(() => {
<strong>    w.resizeBy(0, -200);  // Doesn't work
</strong>  }, 1000);
}
</code></pre>

### `window.name` ("target")

Another surprisingly useful feature of windows is the `target` (2nd) argument. This sets the [`window.name`](https://developer.mozilla.org/en-US/docs/Web/API/Window/name) property for the window. One interesting behavior that this causes is that if there already exists a window with **the same name**, it is **re-used** instead of creating a new one. As normal with a popup, focus will be given to the new popup, but with this trick the new popup may be an existing window with the same name.

Below is an example:

```javascript
let w;
let i = 0;
onclick = () => {
  switch (i++) {
    case 0:
      // 1st, open a new popup named "some-name"
      w = window.open("https://example.com", "some-name", "width=200,height=200,top=100,left=200");
      break;
    case 1:
      // 2nd, re-use the first popup to open this next page, gaining focus again
      w2 = window.open("https://example.com/2", "some-name");
      break;
  }
}
```

{% hint style="info" %}
**Tip**: After the 2nd click, the popup window will be redirected to `/2`, reloading that page. If you just want to get another window reference and/or focus the popup window, you can open the location to the same URL with a `#` appended to it. Alternatively, you can also set it to an invalid URL like `invalid://`.&#x20;

Either option will _not_ reload the page, and only focus the window with that existing name this will be useful in the attacks described later.
{% endhint %}

By clicking twice on the main page, it first opens a popup with a specific name, and when this name is set the same for the second click, the same existing popup is used and only its location is changed. One scenario where this is useful is to put focus _back on the main page_ by specifying it's `window.name` in a `window.open()` call from the popup itself:

```html
<script>
  // Set main window's name to "main"
  window.name = "main";
  
  let w;
  onclick = () => {
    const blob = new Blob([`
        <script>
          onclick = () => {
            // Open main location again with a '#' appended, re-using the "main" name
            // Note that the same URL with a hash will not reload the page
            window.open("${location}#", "main")
          }
        <\/script>
      `], {
      type: "text/html",
    });
    
    // Create window to blob with HTML content
    w = window.open(URL.createObjectURL(blob), "some-name", "width=200,height=200,top=100,left=200");
  }
</script>
```

Clicking on the main page and then inside the popup will put focus back on the main window, while the popup remains in the background.

### Hash fragments and IDs

URLs have a `#` hash fragment part that is sometimes accessed by JavaScript through `location.hash`, or used by the browser automatically to scroll to a certain element. When you click on the header above this paragraph, for example, `#hash-fragments-and-ids` is appended to the URL. When you copy and paste this URL into a new window, you will automatically scroll down to this header element.

This works because the header has an `id="hash-fragments-and-ids"` attribute which the browser looks for when you pass it as a hash fragment in the URL. Instead of manually typing a URL, other sites can also redirect or popup to a URL with a hash fragment.

Scrolling to a specific element is not the only this does, `<input>` or `<button>` elements will be automatically **focused**. See the following example:

{% code title="Target (example.com)" %}
```html
<input id="some-button" type="submit" value="Submit">
```
{% endcode %}

{% code title="Attack" %}
```html
<script>
  onclick = () => {
    // Automatically focus input on opening the popup
    window.open("https://example.com/#some-button", "", "popup")
  }
</script>
```
{% endcode %}

This can be automated by changing the `.location` attribute of a window reference. When you change the URL to the same path and query with a different hash fragment, it is _not reloaded_ and will focus/scroll to the new element the hash points to. Here's an example that cycles through a few:

{% code title="Target (example.com)" %}
```html
<button id="1">1</button>
<button id="2">2</button>
<button id="3">3</button>
```
{% endcode %}

{% code title="Attack" %}
```html
<script>
  const target = "https://example.com";

  function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  let w;
  onclick = async () => {
    w = window.open(target, "", "popup");
    // Cycle through buttons without reloading by changing the hash fragment only
    await sleep(1000);
    while (true) {
      w.location = target + "#1"
      await sleep(500);
      w.location = target + "#2"
      await sleep(500);
      w.location = target + "#3"
     await sleep(500);
    }
  }
</script>
```
{% endcode %}

## Exploits

In this part, we learn how to abuse the above tricks in bigger exploit chains to make good proof of concepts that don't require much user interaction and are pretty convincing.

### Holding Space

One powerful instruction to give a user is to hold space. As with holding any key, after a short second, the key will be repeatedly pressed while it is held. The same goes for the spacebar. The benefit of the spacebar is that it also serves as a way of pressing a button while it is focused. It allows for easy navigation without the mouse, but we can abuse it to perform unexpected interactions with a target page.&#x20;

{% embed url="https://www.paulosyibelo.com/2024/02/cross-window-forgery-web-attack-vector.html" %}
Article explaining an example attack of pressing a button with the spacebar
{% endembed %}

The idea is as follows:

1. Instruct the user to hold space on our attacker's page, like a "Verifying connection" screen or game
2. Open a popup to the target page with the ID of a sensitive button in the hash fragment
3. The user, still holding space, will now focus the sensitive button on the target page and quickly make the space press hit the button. The main page can then close the popup again to prevent the victim from noticing

{% hint style="warning" %}
**Note**: The attack described above **does not work** on Firefox, **only** on Chromium-based browsers. Firefox does not see `onkeydown` as an interaction worthy of opening a popup, disallowing holding space from calling `window.open()`.
{% endhint %}

### Keyboard Popunder

The idea in [#holding-space](window-popup-tricks.md#holding-space "mention") works, but requires the target page to load in full view of the victim, making them more likely to release space and fail the exploit. Instead, if we were able to load the target page in the background and then re-focus it when it is completely loaded, there should be no time for the victim to notice. This is an attack I described in depth in the following blog post:

{% embed url="https://jorianwoltjer.com/blog/p/hacking/pressing-buttons-with-popups" %}
Explaining practical attacks by holding space with popups
{% endembed %}

While so-called "popunders" should no longer be possible in modern browsers, we can emulate them while the user is typing. While holding space spacebar, the `onkeydown` event is actually sent repeatedly similar to holding down any letter will write that letter repeatedly after a small second. This gives us effectively infinite user interactions and "user activation", so we can call the `window.open()` function without having to worry about the popup blocker.

By opening a popup `onkeydown` with a page under our control (eg. an inline [`Blob`](https://developer.mozilla.org/en-US/docs/Web/API/Blob)) that itself also has an `onkeydown` sending the focus back to the main page, it only shows up for a split second before being hidden again. This is effectively a popunder!

After this routine, we can redirect the popup in the background to the target page with the sensitive button and an `id=` attribute. After it loads, and while the user is still holding space, we quickly focus the popup so that the user instantly presses the button without it having to load/wait.

Some example proof of concepts for different cases have been shared here, which you should be able to slightly alter for your target:

{% embed url="https://github.com/JorianWoltjer/popup-research" %}
Experiments and proof of concepts for real-world targets
{% endembed %}
