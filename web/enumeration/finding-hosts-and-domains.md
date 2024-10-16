---
description: Find domain names and hosts relating to a company
---

# Finding Hosts & Domains

{% hint style="info" %}
Note that using these techniques you might find lots of root domains, not all of which might be in scope of the program. Before testing a website you should verify if you are allowed to test it.
{% endhint %}

### IP Ranges

Most decently big companies have claimed IP ranges for their services. These regions are specified and sent to everyone to make sure they don't get taken by another company. This means that we can look up a company name, and find all the IP ranges they claimed.&#x20;

Using [bgp.he.net](https://bgp.he.net/) we can search for a company name and find results:

![BGP search for GitHub showing IP ranges](<../../.gitbook/assets/image (4) (1).png>)

### Reverse Lookup from ASN using [`amass`](https://github.com/OWASP/Amass)

In the search for IP ranges in the previous part, you might also find the Autonomous System number (found in the result column as 'AS####'). This number is very useful as it defines a single company that owns multiple IP ranges. \
If you can find this number for your target, you can use `amass intel` to **reverse lookup** these IPs and find all domain names in this range:

```bash
amass intel -asn 36459 | tee domains.txt
```

## Finding Subdomains

There are lots of techniques to find subdomains, from finding links in HTML/JavaScript, to scraping them from public sources, or even brute force. Here are a few common techniques.

### Linked (spidering)

Sometimes subdomains get used and loaded when visiting a website of the target. You could manually look through the requests, and click around on the websites to find unique subdomains that get used. But this is a lot of work, that can be automated.&#x20;

With the [`gospider`](https://github.com/jaeles-project/gospider) tool we can visit a URL and grab all links from the HTML and Javascript files. There is even a **depth** option (`-d`) to recursively search for more pages on the results:

```bash
gospider -s https://gitbook.com --subs -d 2
```

This will give results in the format:

> \[robots] - https://gitbook.com/webinar\
> \[robots] - https://gitbook.com/webinars/\
> \[url] - \[code-200] - https://www.gitbook.com/\
> \[subdomains] - http://www.gitbook.com\
> \[subdomains] - https://www.gitbook.com\
> \[subdomains] - http://docs.gitbook.com\
> \[subdomains] - https://docs.gitbook.com\
> \[subdomains] - http://blog.gitbook.com

As you can see there is the `[subdomains]` category that contains URLs to all unique subdomains it found (only with `--subs`). We can grab these results with some Regular Expressions to add to our clean subdomains list. [This regex](https://regexr.com/6g2ch) looks for any lines starting with `[subdomains]` and takes only the domain name (without protocol):

```regex
\[subdomains\] - https?:\/\/(.+(\..+)+)
```

If we combine these two, we can find all subdomains in a list, crawled recursively from URLs:

<pre class="language-shell-session" data-overflow="wrap"><code class="lang-shell-session"><strong>$ gospider -s https://gitbook.com --subs -d 2 cat subs.txt | grep -F '[subdomains]' | cut -d'/' -f3 | sort -u | tee linked-subdomains.txt
</strong>www.gitbook.com
docs.gitbook.com
blog.gitbook.com
</code></pre>

### Scraping

There are many more ways to find subdomains that other scanners have found. There are databases full of subdomains that you can query, but going by them one by one every time is very time-consuming.&#x20;

Luckily there is an awesome tool called `subfinder` that aims to automate this process, with many different open-source techniques. Doing a simple `-d` for the domain, and `-o` for the output file, you can quickly get a big list of subdomains.

```bash
subfinder -d gitbook.com -o scraped-subdomains.txt
```

{% embed url="https://github.com/projectdiscovery/subfinder" %}
Automatically scrape many collections of subdomains
{% endembed %}

#### [Certificate Transparency](osint.md#certificate-transparency)

#### Google Search

Google indexes many websites in its search feature. We can use the powerful query options to find subdomains as well as URLs. We'll start off by searching for just the target domain ([link](https://www.google.com/search?q=site%3Agitbook.com)):

> **site:gitbook.com**

This already gives a few subdomains in the results:

```
docs.gitbook.com
jobs.gitbook.com
developer.gitbook.com
policies.gitbook.com
www.gitbook.com
```

Apart from these, the rest of the results are mostly the same. Luckily, Google Search has a feature to exclude these from the results, ensuring we only get new results! We make a new query ([link](https://www.google.com/search?q=site%3Agitbook.com+-site%3Adocs.gitbook.com+-site%3Ajobs.gitbook.com+-site%3Adeveloper.gitbook.com+-site%3Apolicies.gitbook.com+-site%3Awww.gitbook.com)):

> site:gitbook.com **-site:docs.gitbook.com -site:jobs.gitbook.com -site:developer.gitbook.com -site:policies.gitbook.com -site:www.gitbook.com**

It looks for more results and excludes the previous domains. Now we get some more obscure ones:

```
changelog.gitbook.com
app.gitbook.com
enterprise-registry.gitbook.com
legacy.gitbook.com
```

We can keep going and add these to our exclusions, to get even more new results. Do this until nothing is found anymore. You'll be surprised by how many subdomains you can find just using a simple search engine.&#x20;

### Brute Force

The fastest way to try many different possible subdomains is to have lots of DNS resolvers we can ask at once. This way we distribute the requests to many different hosts and we can go much faster than just asking one all the time.&#x20;

First, we'll need a list of public DNS resolvers. Luckily there is a handy list publicly available here:

{% embed url="https://public-dns.info/nameservers.txt" %}
List of public online DNS resolvers
{% endembed %}

A problem with this list though, is the fact that these servers can be _DNS cache poisoned_. This means the domain names might be wrong and give false positives. But there is a tool called [`dnsvalidator`](https://github.com/vortexau/dnsvalidator) that can validate all resolvers on this list, and filter out any cache poisoned ones. Simply run the tool like this to get a list of verified resolvers:

```bash
dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 20 -o resolvers.txt
```

{% hint style="warning" %}
**Note**: `dnsvalidator` might take a while to do its job. You can increase the number of threads but this also increases the risk of getting detected for attacking the DNS infrastructure and getting blocked. I suggest not going above 100 threads
{% endhint %}

Now that we have a bunch of resolvers, we can give [`puredns`](https://github.com/d3mondev/puredns) a list of names to test on the domain. Assetnote has a big list that contains almost 10 million possible subdomain names.&#x20;

{% embed url="https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt" %}
Wordlist of many possible subdomains
{% endembed %}

With a bunch of resolvers, this big number of subdomains can be scanned surprisingly quickly. Using `puredns bruteforce` we can pass in the wordlist and all the resolvers:

{% code overflow="wrap" %}
```bash
puredns bruteforce best-dns-wordlist.txt gitbook.com -r resolvers.txt -w brute-subdomains.txt
```
{% endcode %}

## Confirming Status

All of these domains we found might not actually have any content on them though (false positives). We could manually check all these domains, but that would take a while. The [`httpx`](https://github.com/projectdiscovery/httpx) tool can automate this process and quickly find all online domains after sending a simple request. It accepts a list of URLs or domains as input, which most tools can do:

```bash
subfinder -d gitbook.com -silent | httpx -silent | tee online-subdomains.txt
```
