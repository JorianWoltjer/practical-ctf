---
description: >-
  A protocol for PLCs to store values in coils, inputs, and registers at
  addresses
---

# Modbus - TCP/502

## Description

{% embed url="https://en.wikipedia.org/wiki/Modbus" %}
Detailed description of the modbus protocol
{% endembed %}

Modbus is a communication protocol commonly used in Programmable Logic Controllers (PLCs). There are a few different versions, but the most common are **Modbus RTU and TCP**:

* **Modbus RTU** (Remote Terminal Unit): Used in slow serial communication, and makes use of a compact, binary representation of the data for protocol communication
* **Modbus ASCII**: Similar to RTU, but only using printable ASCII characters for protocol communication, meaning it is less efficient
* **Modbus TCP**: Used on a network, over TCP port 502. When hacking remotely this is by far the most common. See [#modbus](../forensics/wireshark.md#modbus "mention") for analyzing **Wireshark** captures of this data
* **Modbus RTU/IP**: A variant of Modbus TCP that differs in that a checksum is included in the payload, as with Modbus RTU

You can see a Modbus server as a small piece of memory, being able to store values at addresses in different sizes. The client asks the server for values or tells it to write a value somewhere. The following table shows all the different types of values:

<table><thead><tr><th width="189">Type</th><th width="153">Access</th><th width="194">Size</th><th>Addresses</th></tr></thead><tbody><tr><td>Coil</td><td><mark style="color:red;">Read-write</mark></td><td>1 bit (0-1)</td><td>00001 – 09999</td></tr><tr><td>Discrete input</td><td><mark style="color:blue;">Read-only</mark></td><td>1 bit (0-1)</td><td>10001 – 19999</td></tr><tr><td>Input register</td><td><mark style="color:blue;">Read-only</mark></td><td>16 bits (0-65535)</td><td>30001 – 39999</td></tr><tr><td>Holding register</td><td><mark style="color:red;">Read-write</mark></td><td>16 bits (0-65535)</td><td>40001 – 49999</td></tr></tbody></table>

These coils, inputs, and registers can all have arbitrary meanings, like configuration values, status outputs, or ASCII-encoded strings. The addresses are pretty limited, so it is generally useful to dump all the data and then guess what it means locally, and possibly by testing the effects of changing values.&#x20;

## Interaction

Using a tool like `modbus-cli` you can interact with a modbus server easily from the CLI:

{% embed url="https://github.com/tallakt/modbus-cli" %}
Modbus command line utility for reading, writing, and dumping
{% endembed %}

[This writeup](https://jpdias.me/infosec/iot/2019/11/30/bsides-lx-cisco.html) is a good reference as an example of reading data, understanding it, and then changing it using the tool above. First, we try reading from the different registers, which we can even do in bulk for large ranges at a time. Be careful with this however because if your requested range falls out of the range the server holds it will give an `InvalidAddress` error message. Here we try reading the first 5 values from the Holding registers:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ modbus read 10.10.10.10 400001 5
</strong>1
1
1
1
1
</code></pre>

Do dump the entire space, simply keep increasing this amount until you get an error. From here it is a matter of understanding what the data means. The _NahamConCTF 2023 -_ [_Where's my Water_](https://ctftime.org/task/25632) challenge for example contained the following values:

```
...
111
119
95
101
110
97
98
108
101
100
58
102
97
108
115
101
17
17
17
...
```

These values are all in the 50-60 and 90-110 range which is likely an ASCII string padded with `17`s. We can decode it using [CyberChef](https://gchq.github.io/CyberChef/#recipe=From\_Decimal\('Line%20feed',false\)\&input=MTExCjExOQo5NQoxMDEKMTEwCjk3Cjk4CjEwOAoxMDEKMTAwCjU4CjExNgoxMTQKMTE3CjEwMQ) to `"ow_enabled:false"`. We could try to change this `false` to `true` to see what happens, and then write it back to the Modbus server at the correct offset ([CyberChef](https://gchq.github.io/CyberChef/#recipe=To\_Decimal\('Space',false\)\&input=b3dfZW5hYmxlZDp0cnVl)):

```shell-session
$ modbus write 10.10.10.10 400020 116 114 117 101 17
```

This was the solution to the challenge, because when the server now reads the Modbus data it finds our altered `"ow_enabled:true"` string instead.&#x20;

Using the tool above you can even write special data types like signed integers or floating point numbers by providing a `--int` or `--float` parameter:

<table><thead><tr><th>Type</th><th width="93">Size</th><th width="182">Formatted Address</th><th width="115">Address</th><th>Parameter</th></tr></thead><tbody><tr><td>word (default, unsigned)</td><td>16 bits</td><td>%MW100</td><td>400101</td><td><code>--word</code></td></tr><tr><td>integer (signed)</td><td>16 bits</td><td>%MW100</td><td>400101</td><td><code>--int</code></td></tr><tr><td>floating point</td><td>32 bits</td><td>%MF100</td><td>400101</td><td><code>--float</code></td></tr><tr><td>double word</td><td>32 bits</td><td>%MD100</td><td>400101</td><td><code>--dword</code></td></tr><tr><td>boolean (coils)</td><td>1 bit</td><td>%M100</td><td>101</td><td>N/A</td></tr></tbody></table>
