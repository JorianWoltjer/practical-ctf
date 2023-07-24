---
description: >-
  Manage and organize a directory of resources including Users, Groups, and
  Computers with policies
---

# Active Directory

## Description

Windows Active Directory (AD) is meant to be a _directory of resources_. It mainly holds **Users**, **Groups**, and **Computers** allowing administrators to write policies for managing the network.&#x20;

The system has gotten so big and complex that it's _hard_ to find a secure environment. The biggest problem is sticking to backward compatibility, meaning old and insecure protocols should still be supported in the newest version, so that any two versions can work together. This causes many different versions to stay active while administrators forget about them.&#x20;

Some of the main protocols found in AD are:

* **LDAP** (Lightweight Directory Access Protocol): The "database" of AD, where resources are stored and queried
* **DNS** (Domain Name System): Resolving domain names to IP addresses in the internal network
* **SMB** (Server Message Block): Used for different things, mainly file sharing and printer access
* **NTLM** & **Kerberos** Authentication: First came NTLM, which after many security patches, was thrown out over Kerberos. In most ADs, however, this old protocol is still used in places, or it can be forced by an attacker. See [windows-authentication](windows-authentication/ "mention") for more information

## General Attacks

Pentesting Active Directory is a game of privilege escalation. First, often some credentials or code execution is found as an entry point, and then you move throughout the network by accessing files, exploiting more services or simply abusing privileges. This is then repeated until the Domain Admin account is reached which gives full access to do anything on the domain.&#x20;

Using `nmap` to find open ports, you can try to find any **initial access** for you to escalate from.&#x20;

To be efficient, you will often use tooling in order to perform enumeration and attacks. A list of useful tools with a small description for each one can be found here:

{% embed url="https://wadcoms.github.io/" %}
GTFOBins-style cheatsheet of AD tools for different attacks
{% endembed %}

[Impacket](https://github.com/fortra/impacket) is a Python library implementing many protocols used by Active Directory. Its [`examples/`](https://github.com/fortra/impacket/tree/master/examples) directory houses many useful scripts for attacking a domain with different techniques, and some useful utilities. To learn what each script does, check out the work-in-progress list here:

{% embed url="https://tools.thehacker.recipes/impacket/examples" %}
List of all impacket examples with explanations, arguments, and examples
{% endembed %}

### BloodHound

{% embed url="https://github.com/BloodHoundAD/BloodHound" %}
Explore and analyze Active Directory using graphs, nodes and paths
{% endembed %}

BloodHound is a visual tool allowing you to explore and analyze big Active Directory networks by finding paths to higher privileges. To set it up, there are 3 components:

1. A [Neo4J](https://github.com/neo4j/neo4j) database to store data in the form of graphs, which BloodHound will analyze
2. BloodHound client to analyze the graph and find privilege escalation paths
3. Raw AD information like users, groups, and privileges. This is used to find paths in

#### Neo4J Database

You can follow the [installation instructions](https://neo4j.com/docs/operations-manual/current/installation/linux/) to install the `neo4j` binary, which you can start at any time using:

```bash
sudo neo4j console
```

This will start a database server on [http://localhost:7474/](http://localhost:7474/) where you need to change the password for the **first time**. Default credentials are `neo4j`:`neo4j`, and when you log in, you are asked to set a new one. After doing so you can connect to it with BloodHound as explained below.&#x20;

#### BloodHound client

Download the latest release from [GitHub](https://github.com/BloodHoundAD/BloodHound/releases) and simply start the program. It will open a GUI application where you are required to log in with the Neo4J credentials you set, after which you will see a blank canvas.&#x20;

On the right are a few buttons, and to upload data for it to analyze choose![](<../.gitbook/assets/image (1) (6).png>)**Upload Data**. Here you can select multiple files we will generate in the next section.&#x20;

#### Ingesting data

Fetching the data from AD is done with an "ingestor". The official one is [SharpHound](https://github.com/BloodHoundAD/SharpHound) which you run as a domain-joined user to enumerate everything:

{% embed url="https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound.html#basic-usage" %}
Official data collector for BloodHound as a Windows binary ran as the compromised user
{% endembed %}

Possibly an easier way however is using the Python tool which can be run from anywhere and supports multiple ways of authentication:

{% embed url="https://github.com/fox-it/BloodHound.py" %}
Unofficial ingestor made in Python requiring credentials as arguments
{% endembed %}

<pre class="language-shell-session"><code class="lang-shell-session">$ mkdir bloodhound &#x26;&#x26; cd bloodhound
<strong>$ bloodhound.py -c all -d $DOMAIN -u $USER -p $PASSWORD -dc $DOMAIN_CONTROLLER
</strong>...
$ ls
computers.json   domains.json  groups.json  users.json
containers.json  gpos.json     ous.json
</code></pre>

You should select all these files in BloodHound when uploading data, giving it as much information as possible.&#x20;

#### Usage

When fully set up you can use BloodHound to visually find relations to users, computers, and groups, as well as letting it automatically find privilege escalation paths.&#x20;

You can search for any node using the **Search for a node** bar top-left. One common thing you might do is mark compromised users as "Owned" in the right-click menu which can help other analysis tools. \
Reading information about the node is also useful, especially if **Reachable High-Value Targets** is higher than 0. This means a path exists to abuse privileges to escalate to a high-value target like **Domain Admin** (click on it to view).&#x20;

The **Analysis** tab performs queries on the collection as a whole and can find dangerous privileges or otherwise interesting resources like **Kerberastable Accounts**. \
The **Shortest Paths** can show visual representations of interesting paths that might give ideas.

Any edge can be right-clicked to **view Help** which explains _how_ the path is exploitable with examples. This allows quick and easy following of a path to abuse your way to Domain Admin or any other end goal.&#x20;

## Dump Information

Active Directory and Windows store a lot of information, including sensitive secrets like passwords, hashes, tokens, or tickets. When enough access is gained, these secrets can be extracted to escalate further into the network due to re-use, or simply protocol security risks.&#x20;

### [Mimikatz](https://github.com/ParrotSec/mimikatz)

This tool is a big collection of commands that should be run **on the target** itself as an executable. Its most common use case is extracting in-memory credentials from the computer to use in further attacks, like cracking or passing them. \
The `sekurlsa::logonpasswords` command does exactly this, finding different plaintext credentials, NTLM hashes, or Kerberos tickets from logged-on users. \
Some other commands **require** `privilege::debug` to be run before in order to activate Debug privileges. The `sekurlsa::pth` command stands for "Pass The Hash", allowing you to spawn a process as another user only knowing their NTLM hash.&#x20;

{% embed url="https://tools.thehacker.recipes/mimikatz/modules" %}
Documentation of all different useful modules and command in Mimikatz
{% endembed %}

### [`secretsdump.py`](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)

Remotely dump all kinds of secrets on the target computer, from NTLM hashes to SAM and LSA. While this finds and dumps a lot, it won't find everything (read more in [this article](https://medium.com/@benichmt1/secretsdump-demystified-bfd0f933dd9b)). The classic [#mimikatz](active-directory.md#mimikatz "mention") also extracts credentials from Windows Credential Manager and other tokens, and the browser's saved passwords are not stolen either. It is still however a quick and easy way to escalate further on a network when you have initial access.&#x20;

```bash
python3 secretsdump.py DOMAIN/USER:PASSWORD@IP
```

{% hint style="info" %}
Like many other tools, an **NTLM hash** or Kerberos ticket is enough to impersonate the victim without having to know their plaintext password. See [#pass-the-hash](windows-authentication/ntlm.md#pass-the-hash "mention") for ideas
{% endhint %}

### [`ldapdomaindump.py`](https://github.com/dirkjanm/ldapdomaindump)

A simple tool that uses LDAP access to dump as much information about the domain as possible. This can help craft more attack ideas and get you an idea of what users, groups, and permissions exist. This writes HTML, JSON, and grepable files with the results in your current directory. Especially the HTML files give a nice table with links to view your results.

```bash
ldapdomaindump -u 'DOMAIN\USER' -p PASSWORD IP
```

{% hint style="success" %}
**Note**: This tool might _not require authentication_ to be used, as LDAP could be configured for unauthenticated access. Use the `-u` option empty to use an anonymous session
{% endhint %}
