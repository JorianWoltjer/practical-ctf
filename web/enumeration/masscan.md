---
description: >-
  Use masscan to asynchronously scan for open ports at incredible speeds, then
  later analyze the results with other tools
---

# Masscan

{% embed url="https://github.com/robertdavidgraham/masscan" %}
Asynchronous high-speed TCP port scanner
{% endembed %}

### Find open ports

The options masscan uses are very similar to nmap. It accepts a subnet or individual host as a target, and using the `-p` syntax you can provide a list, range or all ports using `-p-`. Then the output formats like `-oX` for XML or `-oJ` for JSON are useful when parsing the results with other tools afterwards.&#x20;

{% code title="Example" %}
```bash
sudo masscan 192.168.1.0/24 -p- --rate 100000 -oX out.xml
```
{% endcode %}

### Convert output to nmap format

Because masscan uses its own version of the XML output format, some tools won't work with this kind of output. To convert the masscan XML to nmap XML, we need to do two things:

1. Optionally: change the ownership from the output file from root to our current user
2. Remove the comment line `<!-- masscan v1.0 scan -->`

```bash
sudo chown $USER:$(id -gn) $1
sed -i '/<!-- masscan v1.0 scan -->/d' $1
```
