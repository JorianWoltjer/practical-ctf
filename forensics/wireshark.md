---
description: A popular tool to analyze and extract data from network packet captures
---

# Wireshark

## Description

{% embed url="https://www.wireshark.org/" %}
Link to the official Wireshark website
{% endembed %}

Wireshark is a GUI tool to analyze network packet captures. You can open `.pcap` or `.pcapng` files in the program and use filters to find specific packets. You can also use it to capture packets yourself from a certain interface, which could be really useful for debugging networking-related issues. It allows you to see exactly what packets are being sent.&#x20;

You can capture packets in Linux using `tcpdump`:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ sudo tcpdump -w capture.pcap  # Use Ctrl+C to stop
</strong>tcpdump: listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
^C
42 packet received by filter
<strong>$ file capture.pcap
</strong>pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 262144)
</code></pre>

When in Wireshark, you see a list of all the packets on the top and detailed information about the contents of a packet on the bottom. Click on a packet at the top to analyze it at the bottom.&#x20;

In the list of packets, the **Info** columns can be really useful. To quickly see what a packet is about, you can read a summary in that column.&#x20;

To practice analyzing specific protocols, you can use some [example captures](https://wiki.wireshark.org/SampleCaptures) that Wireshark gives to see how it works yourself.&#x20;

## TShark

[`tshark`](https://www.wireshark.org/docs/man-pages/tshark.html) is a command-line version of Wireshark that can make it easy to extract data from a capture. Often you're working in Wireshark, and then use TShark to get specific data that needs to be scripted.&#x20;

The output of TShark can easily be used by other tools to analyze further.&#x20;

### Options

* `-r`: File to read packets from (`.pcap`)
* `-Y [filter]`: [#filters](wireshark.md#filters "mention") to apply
* `-T fields`: Display only selected fields
* `-e [field]`: Field name to display (can be specified multiple times)
* `-E separator=,`: Separate fields with a comma
* `-E quote=d`: Surround fields with double-quotes

This field name can be found in Wireshark. Simply find a packet with the information you want to extract, select it by clicking on it, and then look on the bottom bar. It will show the field name in between the `()` brackets. You can also directly copy it by right-clicking, and going to **Copy** -> **Field Name.**&#x20;

<figure><img src="../.gitbook/assets/image (19) (1).png" alt=""><figcaption><p>Screenshot showing field name of DNS query name as an example</p></figcaption></figure>

{% code title="Examples" %}
```shell-session
# # Filter 'dns' and display query names
$ tshark -r capture.pcap -Y 'dns' -T fields -e dns.qry.name
# # Show Modbus registers as [number]:[value]
$ tshark -r modbus.pcapng -Y 'modbus.regnum16' -T fields -E separator=: -e modbus.regnum16 -e modbus.regval_uint16
```
{% endcode %}

## Statistics

When you get a packet capture, it might only contain a few packets that you can look at yourself. But more often, you get a capture over a larger timeframe with lots of packets and different protocols. That is where you can use the statistics tools built into Wireshark to get a general idea of the capture.&#x20;

All of this happens in the **Statistics** menu on the top bar:

![](<../.gitbook/assets/image (37).png>)

One useful option is **Protocol Hierarchy**. It shows a list of all the protocols it finds in the capture, and how often they come up. In the following example, you can see NTP, DNS, TLS, and HTTP. You can also see that almost all packets are plain TCP:

![An example screenshot of the Protocol Hierarchy in Wireshark, showing NTP, DNS, TLS and HTTP](<../.gitbook/assets/image (11) (2).png>)

Two other useful options are **Conversations** and **Endpoints**. First, the conversations show the communication between two endpoints, showing the number of packets, and much more detailed information. This is useful to find interesting conversations if you know an IP address for example. These endpoints are the from and to addresses of these conversations and show what parties were involved in the capture.&#x20;

![](<../.gitbook/assets/image (3) (1).png>) <- Conversations

![](<../.gitbook/assets/image (43).png>) <- Endpoints

All of these menus can help give an initial idea of the capture, to get an idea of what to look at next.&#x20;

## Display Filters

Captures often contain a lot of packets, and of various types. That is why there is a display filter in Wireshark that you can use to only **match** certain types of packets. Just type the filter into the search bar to only see packets that match it:

<figure><img src="../.gitbook/assets/image (15).png" alt=""><figcaption><p>Example of a display filter that only displays HTTP traffic</p></figcaption></figure>

You can find all the documentation about the syntax of these filters on the [Official Wireshark Wiki](https://wiki.wireshark.org/DisplayFilters) page. Most of the time you start with a protocol, and add `.` dots to get more specific.

Boolean operations like `==` (equals), `!=` (not equals), `&&` (and), `||` (or) work as well, allowing you to combine multiple filters together.&#x20;

These filters are also really useful for looking at specific protocols, like for [#http](wireshark.md#http "mention") you can use just `http`, or for [#modbus](wireshark.md#modbus "mention") you can use `modbus`.&#x20;

{% code title="Examples" %}
```python
tcp.port == 4444  # Match TCP port
ip.addr != 10.10.10.10  # Filter out source or destination IP address
eth.addr == 00:00:5e:00:53:00  # Filter Ethernet MAC address
http  # Filter only http traffic
http.host contains "example"  # Filter HTTP host header containing string
pkt_comment  # Filter on Wireshark comments in the capture
```
{% endcode %}

{% hint style="info" %}
**Tip**: Wireshark allows you to add **comments** to captures, which may contain interesting information. Search for comments using the `pkt_comment` filter, then you'll see the comments in the details of the packet (lime green)
{% endhint %}

### Edge cases

Without knowing all the names of filters, you can also easily filter some properties by right-clicking on it in the packet details and selecting **Apply as Filer**. Then you can choose to include/exclude this specific value.&#x20;

<figure><img src="../.gitbook/assets/image (23).png" alt=""><figcaption><p>Screenshot of the right-click menu in Wireshark to apply Wikipedia host as filter</p></figcaption></figure>

One last thing you might run into is the fact that you can't filter the **Protocol** or **Info** columns in the list of packets. This can be useful to quickly search in the Info column, and there is a Plugin for Wireshark that adds this called [filtcols](https://wiki.wireshark.org/Lua/Examples/filtcols). Just install it and then you can use `filtcols.protocol` and `filtcols.info` as strings in the display filter.&#x20;

{% code title="Examples" %}
```python
filtcols.protocol == "802.11"  # Filter for 802.11 Wifi protocol
filtcols.info contains "SSID"  # Filter Info column containing the string "SSID"
```
{% endcode %}

## Protocols

There are lots of protocols that Wireshark automatically recognizes and gives information about. You can also extract information from some protocols, which is often a bit more work. Here are some common protocols and what you can do with them.&#x20;

### TCP Stream

Filter: `tcp`

Lots of protocols use TCP as a base, and some protocols aren't recognized by Wireshark. That is why it's so useful to be able to look at TCP and find out exactly what the packet contains.&#x20;

TCP works in streams. As packets often have a maximum size of about 1500 bytes, these streams have to be split into different packets. When having a packet **selected**, Wireshark can combine the packets together by following the stream, using the **Analyze** -> **Follow** -> **TCP Stream** menu (Ctrl+Shift+Alt+T). By default this will show the data as ASCII (readable text), but you can change it with the "Show data as" dropdown on the bottom.

<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption><p>Example of following TCP Stream, with "Show data as" menu open</p></figcaption></figure>

This view can give a quick idea of what readable text is contained in the packets. You can also cycle through all the streams in the whole capture using the ![](<../.gitbook/assets/image (16).png>) number on the right. If there aren't too many TCP streams, this can quickly show you the contents of the packets and what readable text they contain. Protocols like HTTP or SMTP work completely in readable text, so they should be very easily findable with this technique.&#x20;

This same Follow Stream option is very useful for extracting the raw packet data into some other place. Using the "Show data as **Raw**" option, you'll see the hex values of the data bytes, which you can decode from hex later to get the raw bytes.&#x20;

### HTTP

Filter: `http`

HTTP is the communication that websites use. Normally encryption by HTTPS makes this not readable in a packet capture, but when the packets can be decrypted they turn into HTTP. It is built on TCP, meaning you can use the **Follow TCP Stream** menu to read the data going back and forth.&#x20;

The basics of HTTP are pretty simple. A client sends a request to a server, which then sends back a response.&#x20;

#### Request

{% code title="Example request" %}
```http
POST /login.php HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 31

username=admin&password=hunter2
```
{% endcode %}

The first word in a request is the **method**. Commonly this includes `GET`, `POST`, `HEAD`, `DELETE`, `PUT` and `PATCH`. The `GET` method is used to simply get some content, and `POST` for sending data to the server that should do some action.&#x20;

Then comes the **path**. This is the URL that is requested from the host. In some GET requests, this can also contain URL parameters like `?id=1`.&#x20;

Then there are some headers, notably the `Host` header which specifies what website the request was sent to. The User-Agent also gives some information about what browser/program made the request.&#x20;

`POST` requests often have a body with some content that is sent to the server. These are separated by `&` characters, and the key-value pairs are separated by an `=` equals sign.&#x20;

#### Response

{% code title="Example response" %}
```http
HTTP/1.1 200 OK
Content-Length: 26
Content-Type: text/html; charset=UTF-8
Set-Cookie: PHPSESSID=1576xwtmlrhunx7f3cpbkq5xinyqn773

<html>Hello, world!</html>
```
{% endcode %}

The response gives the content that is displayed back in the browser. It first shows a [status code](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status) that tells the browser some information, like if there was an error, or what kind of response it is.&#x20;

Then come the response **headers**. One notable header is the `Content-Type`, this says what format the response is in. For websites, this is often HTML. But other things like JSON or files can be specified here. The `Set-Cookie` header can also set the `Cookie` header for the next request. This is often used for authentication.&#x20;

Lastly, there is the response data. In some cases, this is not directly readable because of some compression (seen by lots of `.` dots instead of readable text). In this case, you can show the data as **Raw** and decode it from hex, to then decompress it with whatever method it was compressed (the `Content-Type` header can help with this).&#x20;

#### Downloading Files

HTTP can also be used to download files from websites. These can also be found while looking through the HTTP packets, but you can also let Wireshark look for HTTP downloads and export them as files to analyze yourself. You can get a list of Objects by going to **File** -> **Export Objects** -> **HTTP**. In this list, you can select any file that looks interesting or **Save All**.&#x20;

![](<../.gitbook/assets/image (22).png>)

### DNS

Filter: `dns`

[Broken link](broken-reference "mention") is very commonly found in packet captures, because almost everything uses domain names nowadays. DNS can give away some information about what domains were visited if you have encrypted HTTPS traffic for example.&#x20;

#### Data Exfiltration

DNS can also be used by attackers to **exfiltrate** data. Sometimes HTTP or other ways of sending data are detected or not available, which is why you can use DNS to send small bits of information. Domain names can be a total of 253 characters long, and the parts between the `.` dots are only 63 characters each. An attacker can set up NS records on their domain so that any `*.attacker.com` domain is asked to a server of the attacker. This way the attacker can let the client make a DNS request to for example `secret.attacker.com` to leak the string "secret" to the attacker via DNS.&#x20;

This is often done using Base32, an encoding that encodes any bytes to a longer string of 32 characters. This encoded string is then placed in front of an attacker's domain so that they get the encoded string exfiltrated over DNS, which they can later decode.&#x20;

To filter and find all domain names you can use the [#tshark](wireshark.md#tshark "mention") command-line program. With `-r` you can specify a file, then a display filter with `-Y`, and finally with `-T fields` and `-e` you can select specific fields to display:

```shell-session
$ tshark -r capture.pcap -Y 'dns' -T fields -e dns.qry.name > names.txt
```

Then you have all the DNS requests that were done in the capture. You can manually filter out the requests that look like DNS exfiltration ([grep.md](grep.md "mention") can help). And then decode them from Base32 to get the data (or whatever encoding/encryption the malware used).&#x20;

{% code title="Example" %}
```shell-session
$ sed -n '1~2!p' names.txt  # Remove every other line, if every request is doubled
$ sed s/.example.com//g names.txt  # Remove rest of name at the end
$ base32 -d names.txt  # Decode from base32
$ xxd -r -p names.txt  # Decode from hex
```
{% endcode %}

#### Request Data

An attacker may also want to send commands/code to the victim to execute. It is also possible to request data via DNS, as this is the point of DNS. Some records like TXT records can contain larger chunks of text to be requested. TXT records aren't often seen in normal packet captures, so you should definitely look at them when they are in the capture.&#x20;

Similarly to the [#data-exfiltration](wireshark.md#data-exfiltration "mention"), we can use [#tshark](wireshark.md#tshark "mention") to extract all the TXT records from the capture. This time with the `dns.txt` field:

```shell-session
$ tshark -r capture.pcap -Y 'dns' -T fields -e dns.txt
```

### USB Keystrokes

Wireshark can also capture communication of USB devices. A USB keyboard for example sends lots of `URB_INTERRUPT in` packets (see image).&#x20;

<figure><img src="../.gitbook/assets/image (24).png" alt=""><figcaption><p>Wireshark screenshot showing USB keystroke packets</p></figcaption></figure>

You can extract the raw data using [#tshark](wireshark.md#tshark "mention"):

{% code overflow="wrap" %}
```shell-session
$ tshark -r capture.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
```
{% endcode %}

Then you have the data in `keystrokes.txt`, and you can use a tool like [ctf-usb-keyboard-parser](https://github.com/carlospolop-forks/ctf-usb-keyboard-parser) to decode the keystrokes to text.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ git clone https://github.com/carlospolop-forks/ctf-usb-keyboard-parser.git
</strong><strong>$ ./ctf-usb-keyboard-parser/usbkeyboard.py keystrokes.txt
</strong>Hekk⌫⌫llo, world!
</code></pre>

{% hint style="info" %}
**Note**: In the @carlospolop fork of this script backspaces are shown as `⌫`, but in the original, they actually remove the previous character. It might be useful to see the data that was removed with backspace so I suggest using the @carlospolop fork as linked above
{% endhint %}

### Modbus

Filter: `modbus`

[Modbus](https://en.wikipedia.org/wiki/Modbus) is a protocol that has a few different versions. There is Modbus RTU (Remote Terminal Unit) which is used in serial communication. There is also the ASCII variant that also works on serial, and finally, Modbus TCP which goes over TCP (default: port 502). It is commonly used in industrial electronics to read and write simple values. You may find traffic like this in a network capture allowing you to see exactly what data is queried and returned. There are a few different data types it uses:

| Object type      | Access     | Size    | Address Space |
| ---------------- | ---------- | ------- | ------------- |
| Coil             | Read-write | 1 bit   | 00001 – 09999 |
| Discrete input   | Read-only  | 1 bit   | 10001 – 19999 |
| Input register   | Read-only  | 16 bits | 30001 – 39999 |
| Holding register | Read-write | 16 bits | 40001 – 49999 |

These registers can contain numbers from 0-65535, and can be queried (function codes 3 & 4). The response may contain interesting values to look at. You can use [#tshark](wireshark.md#tshark "mention") to extract the **holding register** numbers and values (change `func_code` to `4` for input registers):

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ tshark -r modbus.pcapng -Y 'modbus.func_code==3 &#x26;&#x26; modbus.regnum16' -T fields -E separator=: -e modbus.regnum16 -e modbus.regval_uint16
</strong>100:72
101:101
102:108
103:108
104:111
</code></pre>

These can sometimes contain strings encoded in decimal, be sure to try and decode them in a [CyberChef recipe](https://gchq.github.io/CyberChef/#recipe=Find\_/\_Replace\(%7B'option':'Regex','string':'%5C%5Cd%2B:\(%5C%5Cd%2B\)'%7D,'$1',true,false,true,false\)From\_Decimal\('Line%20feed',false\)\&input=MTAwOjcyCjEwMToxMDEKMTAyOjEwOAoxMDM6MTA4CjEwNDoxMTE).&#x20;

### SSL/TLS

{% embed url="https://wiki.wireshark.org/TLS" %}
Official Wireshark documentation on Decrypting SSL/TLS
{% endembed %}

HTTPS traffic is encrypted using Transport Layer Security (TLS). This means a normal packet capture cannot read the data being sent.&#x20;

To decrypt this data you require a key. This can be the RSA private key of the website, starting with `-----BEGIN PRIVATE KEY-----`, or using per-session key log files ((Pre)-Master Secret).

#### RSA Keys

To decrypt data when you have the key go to **Edit** -> **Preferences** -> **Protocols** -> **TLS** and click **Edit** by the RSA keys list. Here you can click the ![](<../.gitbook/assets/image (29) (1).png>) icon to add an entry containing the IP address and port of the target website (you can find this in the SSL/TLS packets), and the protocol, which will be `http` for HTTPS. Finally the path to the file containing the RSA key.&#x20;

When you now click OK you will see the decrypted traffic like HTTP requests in your list of packets (filter `http`). The raw data will still be the encrypted SSL/TLS data, so instead of following the TCP stream just look at the packet details on the bottom when selecting a packet.&#x20;

#### (Pre)-Master Secret

The `SSLKEYLOGFILE` environment variable can be set to a filename where browsers will log all the SSL keys used. You may find this file somewhere allowing you to use it to decrypt all the traffic made from that browser. The contents of the file should look something like this:

{% code title="Example SSL key log" %}
```log
CLIENT_RANDOM 52362c10a2665e323a2adb4b9da0c10d4a8823719272f8b4c97af24f92784812 9F9A0F19A02BDDBE1A05926597D622CCA06D2AF416A28AD9C03163B87FF1B0C67824BBDB595B32D8027DB566EC04FB25
CLIENT_RANDOM 52362c1012cf23628256e745e903cea696e9f62a60ba0ae8311d70dea5e41949 9F9A0F19A02BDDBE1A05926597D622CCA06D2AF416A28AD9C03163B87FF1B0C67824BBDB595B32D8027DB566EC04FB25
CLIENT_RANDOM 6e9015fda12c6fae63ef1ddf06be63aa65ed23349f74e703764e5100282d3382 81940A0057008819B3B139B4C9F5328F8AEEECB844CB2A4F31C841722510D757BA870A089A89FEC788A0E42E61F30BD1
CLIENT_RANDOM 3b5cffc32014f2cf0f8bee7d33c1ac3020d54115862a3aaedcf3e5557caf9218 2F94FD5BE4DD0473BBEC947189729C887A32A2815F185D813C5B354510570E0B8A9673646594906504A3C8575B5F43C8
```
{% endcode %}

Putting this in Wireshark goes similar to the RSA keys, just go to **Edit** -> **Preferences** -> **Protocols** -> **TLS** and select the (Pre)-Master-Secret log filename. When you click on OK the packets will be decrypted again and you can view the real data.&#x20;

## Wifi (802.11)

{% embed url="https://wiki.wireshark.org/HowToDecrypt802.11" %}
Wireshark tutorial on how to decrypt 802.11 traffic
{% endembed %}

You can capture Wifi traffic all around you using a network card that supports **monitoring mode**. When a Wifi network requires a password to connect to, all the traffic is encrypted. In Wireshark, this encrypted data looks like packets with the protocol 802.11, and "Data" in the info column. You'll be able to see what MAC addresses the communication is between, but not what the data is.&#x20;

{% code title="Filter" %}
```python
wlan && filtcols.info contains "Data"
```
{% endcode %}

To decrypt this data you need the key/password of the Wifi network. There are a few different types of encryption for Wifi:

* **WEP**: A hexadecimal key used for all traffic. The first standard, and pretty easy to crack with brute force (example: `a1:b2:c3:d4:e5`)
* **WPA/WPA2**: A password/SSID combination, with a different encryption key for each connected device (example: `MyPassword:MySSID`)
* **WPA-PSK**: WPA with a Pre-Shared Key. 64 bytes in hex (example: `01020304...61626364`)

### Decrypting

When you have found a WEP key (eg. by cracking it), you can instantly decrypt all the traffic from anyone.&#x20;

But a WPA key is unique for all connected devices. To be able to decrypt WPA traffic, you need the EAPOL handshake for that device. This handshake is done when you authenticate with the network, so every time you connect. If you're lucky the capture contains the moment when the device connects meaning you have this EAPOL handshake. It consists of 4 parts, and all 4 need to be included to decrypt the traffic. You can filter for `eapol` to find if you have parts 1-4:

<figure><img src="../.gitbook/assets/image (25).png" alt=""><figcaption><p>Screenshot of all 4 parts of EAPOL handshake in Wireshark</p></figcaption></figure>

To then actually decrypt the traffic using the network key/password, go to **Edit** -> **Preferences** -> **Protocols** -> **IEEE 802.11** and click **Edit** by the Decryption keys. Here you can click the ![](<../.gitbook/assets/image (14).png>) icon to add a key.&#x20;

First choose the **Key type**, and then put the key into the Key field in the hex format for WEP, or the `MyPassword:MySSID` format for WPA (you can find the SSID with the `wlan.ssid` filter). Finally, click OK when your password is set.&#x20;

| Key type    | Key (example)                                                      |
| ----------- | ------------------------------------------------------------------ |
| **wep**     | `0102030405060708090a0b0c0d`                                       |
| **wpa-pwd** | `MyPassword:MySSID`                                                |
| **wpa-pwd** | `MyPassword`                                                       |
| **wpa-psk** | `a66e97b9a1008a97285c7ec2b95082bed3541d3dd01165b0128f7f3c18563797` |

You should now see some encrypted traffic turn into normal traffic, like TCP and UDP. To be sure you can use the `filtcols.protocol != "802.11"` filter to only show normal traffic.&#x20;
