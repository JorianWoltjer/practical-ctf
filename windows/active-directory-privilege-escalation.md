---
description: >-
  Traverse the Active Directory permissions to escalate your privileges and
  access more
---

# Active Directory Privilege Escalation

## Description

Windows Active Directory (AD) is meant to be a _directory of resources_. It mainly holds **Users**, **Groups**, and **Computers** allowing administrators to write policies for managing the network.&#x20;

The system has gotten so big and complex that it's _hard_ to find a secure environment. The biggest problem is sticking to backward compatibility, meaning old and insecure protocols should still be supported in the newest version, so that any two versions can work together. This causes many different versions to stay active while administrators forget about them.&#x20;

Some of the main protocols found in AD are:

* **LDAP** (Lightweight Directory Access Protocol): The "database" of AD, where resources are stored and queried
* **DNS** (Domain Name System): Resolving domain names to IP addresses in the internal network
* **SMB** (Server Message Block): Used for different things, mainly file sharing and printer access
* **NTLM** & **Kerberos** Authentication: First came NTLM, which after many security patches, was thrown out over Kerberos. In most ADs, however, this old protocol is still used in places, or it can be forced by an attacker. See [windows-authentication](windows-authentication/ "mention") for more information

Pentesting _Active Directory_ is a game of privilege escalation. First, often some credentials or code execution is found as an entry point, and then you move throughout the network by accessing files, exploiting more services or simply abusing privileges. This is then repeated until the Domain Admin account is reached which gives full access to do anything on the domain.&#x20;

## Commands

Using `nmap` to find open ports, you can try to find any **initial access** for you to escalate from.&#x20;

To be efficient, you will often use tooling in order to perform enumeration and attacks. A list of useful tools with a small description for each one can be found here:

{% embed url="https://wadcoms.github.io/" %}
GTFOBins-style cheatsheet of AD tools for different attacks
{% endembed %}

[Impacket](https://github.com/fortra/impacket) is a Python library implementing many protocols used by Active Directory. Its [`examples/`](https://github.com/fortra/impacket/tree/master/examples) directory houses many useful scripts for attacking a domain with different techniques, and some useful utilities. To learn what each script does, check out the work-in-progress list here:

{% embed url="https://tools.thehacker.recipes/impacket/examples" %}
List of all impacket examples with explanations, arguments, and examples
{% endembed %}

### [`ldapdomaindump.py`](https://github.com/dirkjanm/ldapdomaindump)

A simple tool that uses LDAP access to dump as much information about the domain as possible. This can help craft more attack ideas and get you an idea of what users, groups, and permissions exist. This writes HTML, JSON, and grepable files with the results in your current directory. Especially the HTML files give a nice table with links to view your results.

```bash
ldapdomaindump -u '$DOMAIN\$USERNAME' -p $PASSWORD $IP
```

{% hint style="success" %}
**Note**: This tool _might not require authentication_ to be used, as LDAP could be misconfigured for unauthenticated access. Use the `-u` option empty to use an anonymous session
{% endhint %}

## BloodHound

{% embed url="https://github.com/BloodHoundAD/BloodHound" %}
Explore and analyze Active Directory using graphs, nodes and paths
{% endembed %}

BloodHound is a visual tool that allows you to explore and analyze big Active Directory networks by finding paths to higher privileges. To set it up, there are 3 components:

1. A [Neo4J](https://github.com/neo4j/neo4j) database to store data in the form of graphs, which BloodHound will analyze
2. BloodHound client to analyze the graph and find privilege escalation paths
3. Raw AD information like users, groups, and privileges. This is used to find paths in

These can be easily started with a Docker container:

```bash
curl -L https://ghst.ly/getbhce | BLOODHOUND_PORT=3000 docker compose -f - up
```

After having started up, you should find a login page on [http://localhost:3000/ui/login](http://localhost:3000/ui/login). In the docker logs, you will find an "Initial Password Set To:" the first time, with a random string that is the password for the `admin` user you should log in as. After successfully logging in, it will ask you to change the password to another strong random string, and then you are greeted with the welcome screen.&#x20;

In the [File Ingest](http://localhost:8080/ui/administration/file-ingest) page, you can press **Upload Files** and drag in collected data from [#ingesting-data](active-directory-privilege-escalation.md#ingesting-data "mention").

### LEGACY: Manual Setup

#### Neo4J Database

You can follow the [installation instructions](https://neo4j.com/docs/operations-manual/current/installation/linux/) to install the `neo4j` binary, which you can start at any time using:

```bash
sudo neo4j console
```

This will start a database server on [http://localhost:7474/](http://localhost:7474/) where you need to change the password for the **first time**. Default credentials are `neo4j`:`neo4j`, and when you log in, you are asked to set a new one. After doing so you can connect to it with BloodHound as explained below.&#x20;

#### BloodHound client

Download the latest release from [GitHub](https://github.com/BloodHoundAD/BloodHound/releases) and simply start the program. It will open a GUI application where you are required to log in with the Neo4J credentials you set, after which you will see a blank canvas.&#x20;

On the right are a few buttons, and to upload data for it to analyze choose![](<../.gitbook/assets/image (1) (6).png>)**Upload Data**. Here you can select multiple files we will generate in the next section.&#x20;

### Ingesting data

Fetching the data from AD is done with an "ingestor". The official one is [SharpHound](https://github.com/BloodHoundAD/SharpHound) which you run as a domain-joined user to enumerate everything they can access:

{% embed url="https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound.html#basic-usage" %}
Official data collector for BloodHound as a Windows binary ran as the compromised user
{% endembed %}

Possibly an easier way however is using the Python tool which can be run from anywhere and supports multiple ways of authentication:

{% embed url="https://github.com/fox-it/BloodHound.py" %}
Unofficial ingestor made in Python requiring credentials as arguments
{% endembed %}

<pre class="language-shell-session"><code class="lang-shell-session">$ mkdir bloodhound &#x26;&#x26; cd bloodhound
<strong>$ bloodhound.py -c all -d $DOMAIN -u $USERNAME -p $PASSWORD -dc $DC
</strong>...
$ ls
computers.json   domains.json  groups.json  users.json
containers.json  gpos.json     ous.json
</code></pre>

You should select all these files in BloodHound when uploading data, giving it as much information as possible. Then visiting the main page again your can start to analyze the data and their connections.

### Usage

Check out the following awesome post that shows the basic usage of BloodHound CE:

{% embed url="https://www.incendium.rocks/new-bloodhound-ce#31401b0515554132bca264706d554080" %}
