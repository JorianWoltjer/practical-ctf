---
description: >-
  Finding flaws of the logic in an application. Instead of complex injections,
  break the regular flow or perform unexpected actions
---

# Business Logic Errors

Business Logic is the logic a business _should_ enforce. These aren't protections like preventing injection, but instead focus on processes like a webshop checkout. Here it is important that the value a customer pays is equal to the value of their order. When this is not the case, it becomes an Error and may be exploitable.

### Manipulating Sequences

Many applications work with sequences of actions you expect a user to do, like a _login sequence_ with multiple factors. If given a User Interface like a website, it might be expected that they can only follow the pages they are given by the server. But by intercepting traffic with a proxy like Burp Suite, an attacker can manipulate the &**order of requests** in unexpected ways in hopes of fooling the server.

These behaviors might not have been tested on the application, leading to weird behavior at best and security vulnerabilities at worst. There are a few ways in which you can mess with the order:

* **Skip** to future actions: See if you can bypass checks and skip to a future state, by completing the sequence once and on your next attempt referencing the first sequence
* **Go back** to previous actions: When having completed one step, go back to one you already completed, which might confuse the server and send a different response
* **Repeat** previous actions: Sending a request multiple times can have similar effects to going back to a previous step. It's an interesting behavior that might confuse the server

#### Client In Control

Apart from the order, more errors can arise from giving the **client too much control**. If they send the total price in a request to the server, an attacker can simply lower the price to get free items. This trend goes further than just webshop checkouts and is important for any data sent to the server, as an attacker can change all of it.

In Burp Suite you can check the **Proxy History** tab to **view all requests** and parameters you have control over, but don't forget hidden parameters that aren't sent yet, but the server does accept.

For a flexible application, a developer might create an endpoint that changes user settings, allowing you to send a request that merges your current settings with the ones you send it. Giving too much control like this can quickly result in **Mass Assignment** vulnerabilities where you could maybe add a `&role=admin` parameter to also change that attribute, which the developer might not have expected. JSON or XML endpoints are very common for this, as just a merge of the attributes is easy to implement but can have unexpected security implications.

Lastly, some parameters may refer to objects using an ID of sorts, like a User ID. When this ID is controlled by the client, an attacker might change it to reference another user or object, called **Insecure Direct Object Reference (IDOR)**. It's very easy to make the mistake of forgetting an authorization check for such requests, making this simple vulnerability surprisingly common.\
It can easily be tested by creating _2 accounts_, and interchanging IDs between the two in certain requests to test if you can interact with one account on another.

### Integer Overflow

Computers use bits and bytes to store numbers, and many languages define "integers" and other variable types with a **number of bits**. This means not all existing numbers are representable, just the ones that fit into that number of bits.

You might question what would happen if you have the _highest_ possible number in an integer, and add 1 to it. This depends on the programming language, but in C for example it will **overflow** to the _lowest_ possible number.

{% code title="C" %}
```c
int a = 2147483647;
printf("Before: %d\n", a);  // 2147483647
a += 1;
printf("After:  %d\n", a);  // -2147483648
```
{% endcode %}

This possible behavior could be exploited if an application expects a value only to go up, but when you make it high enough, it will become negative. This could be catastrophic for a webshop checkout for example.

There are _signed_ and _unsigned_ numbers, and types like `short`, `int` or `long` that all have different bit sizes, with different limits. Here is a table of all the ranges for common types:

<table><thead><tr><th width="213">Type</th><th width="65">Bits</th><th width="236">Max</th><th>Min (Max+1)</th></tr></thead><tbody><tr><td><code>short</code></td><td>16</td><td><code>32767</code></td><td><code>-32768</code></td></tr><tr><td><code>unsigned short</code></td><td>16</td><td><code>65535</code></td><td><code>0</code></td></tr><tr><td><code>int</code></td><td>32</td><td><code>2147483647</code></td><td><code>-2147483648</code></td></tr><tr><td><code>unsigned int</code></td><td>32</td><td><code>4294967295</code></td><td><code>0</code></td></tr><tr><td><code>long</code></td><td>64</td><td><code>9223372036854775807</code></td><td><code>-9223372036854775808</code></td></tr><tr><td><code>unsigned long</code></td><td>64</td><td><code>18446744073709551615</code></td><td><code>0</code></td></tr></tbody></table>

{% hint style="info" %}
**Note**: While most languages act like this, Python is special as it dynamically resizes integers to be of an arbitrary bit length, avoiding this problem.
{% endhint %}

Instead of making the number so large it exceeds the maximum, it might also be possible to instead decrease it so it exceeds the _minimum_ instead. For unsigned numbers this is as simple as supplying a **negative number** which will wrap around to a giant positive number causing weird behaviours if two processes use a differrent number interpretation.&#x20;

Negative numbers in general can cause all kinds of unexpected results due to calculations, as many inputs accept them but don't think about how the application would actually handle them without testing. The same goes for any invalid input like `AAAA` as a number which can cause weird results in an untested application.&#x20;

### Rounding Errors

When rounding numbers like 0.3333... to 0.3, some precision is lost. If rounding happens irregularly between two processes, this lost information can benefit an attacker if they are able to abuse it.

Money for example is often rounded to 2 decimal places, like $1.23. If you could send someone $0.004 however, the system for subtracting from your balance and the system for adding balance to the recipient must be the same! Otherwise, small amounts of money might appear out of nowhere which an attacker can abuse by doing so repeatedly.

#### Floating Point Numbers

Floating point numbers work in a similar way, as they have a limited amount of bits to store very large and very small numbers. Some very small numbers have to be rounded to the nearest floating point, and some very large numbers have to as well.

This can already become apparent with numbers like `100000042.0f` in Java, which is stored as `1.0000004E8` (`E8` = with 8 zeros). You can see the `2` digit was lost as floats are not precise enough.

{% hint style="info" %}
**Note**: A `double` instead of a `float` has double the number of bits (32 -> 64), which allows for much more precision and would store this example correctly
{% endhint %}

Thinking about the money example again, if an attacker was able to send $1000000**44**.00 as an example, it would be rounded to the nearest $1000000**48**.00 instead, creating $4 out of thin air.
