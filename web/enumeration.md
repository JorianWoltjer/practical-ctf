---
description: The first things to do when you see a website
---

# Enumeration

## Find back-end

{% embed url="https://www.wappalyzer.com/" %}
Use the Wappalyzer extension to detect the back-end techlogies
{% endembed %}

## Fuzz content

There is a `ffuf` module in my [default ](https://github.com/JorianWoltjer/default)tool:

```shell-session
$ default ffuf content http://example.com/
$ default ffuf param http://example.com/page
$ default ffuf vhost example.com
```

Check out [FFUF.me](http://ffuf.me/) for a great tutorial on how to use various options in [ffuf](https://github.com/ffuf/ffuf):

{% embed url="http://ffuf.me/" %}
A site with practice exercises on fuzzing with ffuf
{% endembed %}
