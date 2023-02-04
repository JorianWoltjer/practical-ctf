---
description: 'Open Source INTelligence: Abusing public information'
---

# OSINT

## Account Finder

When you have a username of someone and want to find more information about that username, you can try to search for that username on different social media platforms. There are also a few tools that do this for you on a lot of websites quickly.&#x20;

A popular CLI tool is [sherlock](https://github.com/sherlock-project/sherlock), where you can simply provide a username and see all the accounts that were found:

```shell-session
$ sherlock USERNAME [USERNAMES ...]
```

Another tool I have found to be very useful is the following site:

{% embed url="https://whatsmyname.app/" %}
Username lookup site that requests over 500 sites in a few seconds
{% endembed %}

The above web tool also shows some Google search results, as a bonus. These can be useful in finding more details about a username, and what it is associated with.&#x20;

## Certificate Transparency

Certificate Transparency (CT) can be a useful tool as it provides a publicly accessible log of all issued SSL certificates for websites, including information about the **domain names** associated with the certificate. Some databases collect these logs and make them able to be queried, like [crt.sh](https://crt.sh/) or Censys:

{% embed url="https://search.censys.io/certificates" %}
The Certificate Transparency search page from Censys that allows complex queries
{% endembed %}

### Subdomains

Very often when setting up a new subdomain the owner will have to register a new certificate for it. This action is logged by the CT and can be looked up on websites such as [crt.sh](https://crt.sh/). Simply put in a query with a % like in SQL as follows to get all the subdomains of a certain root domain:

{% code title="gitbook.com subdomains" %}
```sql
%.gitbook.com
```
{% endcode %}

{% hint style="warning" %}
Note that these queries can take some time, as there is a lot of data to query through. Just be a little patient with these services.&#x20;
{% endhint %}

### Wildcards

The Censys search tool linked above is really powerful. You only need to create a free account and then you can use Elasticsearch syntax to query all kinds of information about the certificates. Most often you're querying the domain name, and want to use the `parsed.names` keyword. After the colon, you can specify a string, maybe including wildcards, or even a regular expression:

{% code title="Includes "verysecret"" %}
```regex
parsed.names:/.*verysecret.*/
```
{% endcode %}

With these [regular-expressions-regex.md](../../languages/regular-expressions-regex.md "mention"), you can query pretty much anything you want. You can also try to search for multiple strings with anything in between, and make sure "very" is the start of a word:

```regex
parsed.names:/.*\Wvery.*secret.*/
```
