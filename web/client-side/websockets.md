# WebSockets

## # Related Pages

> Bypassing reverse proxies using [#websocket-and-h2c-smuggling](../server-side/reverse-proxies.md#websocket-and-h2c-smuggling "mention")

## Description

[WebSockets](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API) allow two-way communication over a single connection where both the server and client can send messages whenever they like. It is functionally similar to a raw TCP connection sending data to and between, but is wrapped in WebSocket _frames_ and used by the browser.

### Protocol

Creating a WebSocket connection starts with an HTTP request. In the browser, you call the [`WebSocket()`](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/WebSocket) constructor and a request like the following is sent:

{% code title="Request" %}
```http
GET /some/ws HTTP/1.1
Host: example.com
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: ut/YSNzdtIkvnTCSQtTx9g==
```
{% endcode %}

The server has a websocket handler for `/some/ws`, so it responds with a `Sec-WebSocket-Accept:` header derived from the request's `Sec-WebSocket-Key:` ([source](https://en.wikipedia.org/wiki/WebSocket#Opening_handshake)). The status code will be 101 "Switching Protocols", and the TCP connection stays open.

{% code title="Response" %}
```http
HTTP/1.1 101 Switching Protocols
Connection: upgrade
Upgrade: websocket
Sec-WebSocket-Accept: /fCJAu1M5mY53eHwube2Xl1leKM=
```
{% endcode %}

After this handshake, any party can send websocket frames that the other will decode and handle accordingly. On the wire this is a binary protocol, and looks something like this:

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption><p>Wireshark capture of WebSocket frame with "Hello, world!" text payload</p></figcaption></figure>

Messages have a few different types:

* **Text data frame**: Simple UTF-8 strings as message content
* **Binary data frame**: Raw bytes as message content
* **Ping/Pong**: Used to keep the connection alive and avoid timeouts
* **Close**: The party sending a close frame cannot send more frames after doing so. _The other may still send frames_, but most often it will automatically send a closing handshake response to end the connection from both sides.

Implementations with WebSockets often work completely differently than regular HTTP endpoints, which may cause them to have less validation or more dangerous behaviour. Be sure to test for the **standard type of vulnerabilities within fields** of a WebSocket message.

### SocketIO

A common wrapper around WebSockets in the wild is [SocketIO](https://socket.io/). This has backwards compatability support by falling back on streaming HTTP responses if WebSockets fail for any reason, and has built some more features like session/room management that are common for web applications.

At the highest level, there are [namespaces](https://socket.io/docs/v4/namespaces/) that can be seen as completely different connections to different applications. Almost always, this is implicitly the main namespace (`/`). A namespace contains [rooms](https://socket.io/docs/v4/rooms/) which can be seen as types of [events](https://socket.io/docs/v4/emitting-events/).

Only the server can put you into a room, you cannot decide this for yourself. This is often used for authorization, after completing some verification. This puts you into a private room with other connected clients where sensitive information may be shared.

### Snippets

#### WebSocket Server

{% code title="Dependencies" %}
```sh
npm install ws
```
{% endcode %}

<pre class="language-javascript" data-title="server.js"><code class="lang-javascript">const WebSocket = require('ws');

const ws = new WebSocket.Server({ port: 8080 });

ws.on('connection', conn => {
  console.log('Client connected.');

<strong>  conn.on('message', message => {
</strong><strong>    console.log(`Received from client: ${message}`);
</strong><strong>    conn.send(`Server received: ${message}`);
</strong><strong>  });
</strong>
  conn.on('close', () => {
    console.log('Client disconnected.');
  });

  conn.send('Welcome to the WebSocket server!');
});

console.log('WebSocket server is running on ws://localhost:1337');
</code></pre>

#### WebSocket Client - JavaScript

{% embed url="https://developer.mozilla.org/en-US/docs/Web/API/WebSocket" %}
Documentation for JavaScript `WebSocket` Client API
{% endembed %}

<pre class="language-javascript" data-title="client.js"><code class="lang-javascript">const socket = new WebSocket("ws://localhost:1337");

socket.addEventListener("open", (event) => {
<strong>  socket.send("Hello Server!");
</strong>});

<strong>socket.addEventListener("message", (event) => {
</strong>  console.log("Message from server ", event.data);
});
</code></pre>

<details>

<summary><code>WebSocketClient.js</code></summary>

```javascript
class WebSocketClient {
  constructor(url) {
    this.socket = new WebSocket(url);
    this._messageQueue = [];
    this._pendingResolvers = [];

    this.socket.addEventListener('message', (event) => {
      const message = event.data;
      if (this._pendingResolvers.length > 0) {
        this._pendingResolvers.shift()(message);
      } else {
        this._messageQueue.push(message);
      }
    });
  }

  send(message) {
    if (this.socket.readyState === WebSocket.OPEN) {
      this.socket.send(message);
    } else {
      throw new Error("WebSocket is not open");
    }
  }

  recv() {
    return new Promise((resolve) => {
      if (this._messageQueue.length > 0) {
        resolve(this._messageQueue.shift());
      } else {
        this._pendingResolvers.push(resolve);
      }
    });
  }

  close() {
    if (this.socket.readyState === WebSocket.OPEN) {
      this.socket.close();
    } else {
      throw new Error("WebSocket is already closed or not opened");
    }
  }
}
```

</details>

```javascript
ws = new WebSocketClient('ws://localhost:8080')
console.log("Received:", await ws.recv())
ws.send("Hello, from JavaScript!")
console.log("Received:", await ws.recv())
ws.close()
```

#### WebSocket Client - Python

{% code title="Dependencies" %}
```sh
pip install websocket-client
```
{% endcode %}

<details>

<summary><code>WebSocketClient.py</code></summary>

```python
import websocket
import threading
import queue


class WebSocketClient:
    def __init__(self, url):
        self.url = url
        self.ws = websocket.WebSocketApp(
            url,
            on_open=self._on_open,
            on_message=self._on_message,
            on_close=self._on_close,
            on_error=self._on_error
        )
        self.recv_queue = queue.Queue()
        self.connected_event = threading.Event()
        self.thread = threading.Thread(target=self.ws.run_forever)
        self.thread.daemon = True

    def _on_open(self, ws):
        self.connected_event.set()

    def _on_message(self, ws, message):
        self.recv_queue.put(message)

    def _on_close(self, ws, code, msg):
        print(f"WebSocket closed: {code} - {msg}")

    def _on_error(self, ws, error):
        print(f"WebSocket error: {error}")

    def send(self, message):
        if isinstance(message, bytes):
            self.ws.send(message, websocket.ABNF.OPCODE_BINARY)
        else:
            self.ws.send(message)

    def recv(self, timeout=5):
        try:
            return self.recv_queue.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError("No message received in time.")

    def close(self):
        self.ws.close()
        self.thread.join(timeout=1)

    def __enter__(self):
        self.thread.start()
        if not self.connected_event.wait(timeout=5):
            raise TimeoutError("Could not connect to WebSocket server.")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
```

</details>

```python
with WebSocketClient("ws://localhost:1337") as ws:
    print(f"Received: {ws.recv()!r}")
    ws.send("Hello from Python!")
    print(f"Received: {ws.recv()!r}")
```

***

#### SocketIO Server

{% embed url="https://socket.io/docs/v4/server-api/" %}
Documentation for `Socket.IO` library's API methods
{% endembed %}

{% code title="Dependencies" %}
```sh
npm install socket.io express
```
{% endcode %}

{% code title="server-socketio.js" %}
```javascript
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

io.on('connection', (socket) => {
  console.log('Client connected');
  
  // Emitting events
  socket.emit('event1', 'This is sent to the connecting socket only');
  io.emit('event2', 'This is sent to all connected sockets');
  socket.broadcast.emit('event3', 'This is sent to all sockets except the sender');
  
  // Rooms
  socket.join('room1');
  io.to('room1').emit('roomEvent', 'Message to room1');
  
  // Listening for events
  socket.on('clientEvent', (data) => {
    console.log('Received from client:', data);
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

const PORT = 1337;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
```
{% endcode %}

#### SocketIO Client - JavaScript

{% embed url="https://socket.io/docs/v4/client-api/" %}
Documentation for `Socket.IO-Client` library's API methods
{% endembed %}

<pre class="language-html" data-title="Importing (Browser)"><code class="lang-html"><strong>&#x3C;script src="https://cdn.socket.io/4.8.1/socket.io.js">&#x3C;/script>
</strong>&#x3C;script>
  ...
&#x3C;/script>
&#x3C;!-- or -->
<strong>&#x3C;script type="module">
</strong><strong>  import { io } from "https://cdn.socket.io/4.8.1/socket.io.esm.min.js";
</strong>  ...
&#x3C;/script>
</code></pre>

{% code title="Dependencies (NodeJS)" %}
```sh
npm install socket.io-client
```
{% endcode %}

{% code title="Importing (NodeJS)" %}
```javascript
import { io } from "socket.io-client";
// or
const { io } = require("socket.io-client");
```
{% endcode %}

<pre class="language-javascript"><code class="lang-javascript"><strong>const socket = io("http://localhost:1337");
</strong>
function recv(socket, event) {
    return new Promise((resolve) => {
        function handler(data) {
            socket.off(event, handler);
            resolve(data);
        }
        socket.on(event, handler);
    });
}

socket.on('connect', async () => {
    console.log('Connected to server');

<strong>    socket.on('someEvent', (data) => {
</strong>        console.log('Received from server:', data);
    });

<strong>    const listener = recv(socket, 'response');
</strong><strong>    socket.emit('clientEvent', 'Hello from client');
</strong>    const response = await listener;
    console.log('Response received:', response);

    socket.close();
});
socket.on('disconnect', () => {
    console.log('Disconnected from server');
});

</code></pre>

#### SocketIO Client - Python

{% embed url="https://python-socketio.readthedocs.io/en/latest/client.html" %}
Documentation for `python-socketio` client library
{% endembed %}

{% code title="Dependencies" %}
```sh
pip install "python-socketio[client]"
```
{% endcode %}

<pre class="language-python"><code class="lang-python">import socketio

with socketio.SimpleClient() as socket:
<strong>    socket.connect('http://localhost:1337')
</strong>    
<strong>    socket.emit('my message', {'foo': 'bar'})
</strong><strong>    event = socket.receive()
</strong>    print(f'received event: "{event[0]}" with arguments {event[1:]}')
    
<strong>    @socket.event
</strong><strong>    def message(data):
</strong><strong>        print('I received a message!')
</strong>    
    @socket.on('my message')
    def on_message(data):
        print('I received a message!')
</code></pre>

## Cross-Site WebSocket Hijacking

{% embed url="https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking" %}
Explanation of the CSWSH technique with labs
{% endembed %}

WebSocket connections can also be made cross-site, and if these are automatically authenticated by cookies, you can get into a dangerous scenario where an attacker's site can not only **send**, but **also receive messages**. This is because [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS) doesn't apply to WebSockets, you are always able to read incoming messages cross-origin.

Important for this to have any security impact is if the [#same-site](cross-site-request-forgery-csrf.md#same-site "mention") rules allow any site to send authentication cookies with requests. Because WebSockets are background requests, the `SameSite=` attribute needs to be `None` for Chromium, or unset for Firefox.\
Note that if you can gain control over a same-site origin like a subdomain or different port with XSS, you can even get `SameSite=Strict` cookies to be sent.

### Protections

Some common protections include:

* Checking the `Origin:` header matches a trusted value. Make sure this is no vulnerable prefix/suffix matching, or that dots in a regex match any character.
* Requiring the authentication token to be sent as a websocket message, not automatically in a cookie during the handshake. The attacker cannot then abuse any authentication because it needs to happen manually.
