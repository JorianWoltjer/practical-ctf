# SQL Injection

## SQLMap

{% embed url="https://book.hacktricks.xyz/pentesting-web/sql-injection/sqlmap" %}

You can run a raw request through `sqlmap` with cookies and POST to find any injection:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ sqlmap -r r.txt --batch
</strong></code></pre>

* `--level=5` tests more inputs, like HTTP headers
* `--risk=3` tests more injection payloads

### XSS/SQLi through SQL Injection

{% embed url="https://jorianwoltjer.com/blog/post/hacking/intigriti-xss-challenge/intigriti-july-xss-challenge-0722" %}
Writeup showing XSS through a Second-Order injection
{% endembed %}

Use UNION SELECT statements to alter the returned content on the site, with an XSS payload for example

{% hint style="info" %}
Also try 'Second-Order' injection, by doing another injection inside of your `UNION` content if not all values can be altered (see writeup)
{% endhint %}

### Filter Bypass

* Quotes (`'` & `"`): Use `0x6a307231616e` instead of `"j0r1an"` ([CyberChef](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('None',0\)Find\_/\_Replace\(%7B'option':'Regex','string':'.\*'%7D,'0x$%26',false,false,false,false\)\&input=ajByMWFu))
