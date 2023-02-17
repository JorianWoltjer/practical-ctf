---
description: The Microsoft Azure cloud, and how to attack certain parts of it
---

# Microsoft Azure

This page was made after [an online workshop](https://www.youtube.com/watch?v=9rKitQ4iYAo) while solving [a vulnerable testing environment](https://github.com/SecuraBV/brokenbydesign-azure).&#x20;

{% hint style="info" %}
**Note**: If you want to try and complete these challenges without spoiling yourself, do not look at the GitHub source code, as this will show all the flags and solutions. Simply [start on the website](https://www.brokenazure.cloud/).&#x20;
{% endhint %}

## Storage Blobs

When you find a `*.blob.core.windows.net` URL, this is a domain used for Cloud storage on Azure. You might find it used to host files somewhere, like images. But these storages can contain anything from passwords to source code. Sometimes these sensitive "Blobs" can be accessed without any authentication.&#x20;

To get started, try the Microsoft Azure Storage Explorer:

{% embed url="https://azure.microsoft.com/en-us/products/storage/storage-explorer" %}
A tool to connect to various Azure storage resources
{% endembed %}

Inside the program, you can connect to the resource with the **Connect to Azure resources** button on the **Get Started** menu. From here, you can choose **Blob container** for when the windows domain contains `blob`**.**&#x20;

Next, it asks how you want to authenticate. If you have credentials, of course, you can try them here. But otherwise, you can try connecting **Anonymously** to see if they allow anyone to view the resources.&#x20;

Finally, input the **Blob container URL** you found initially. This URL needs to contain the company's own subdomain and the first directory of the path to the resource. For example:

> https://\[somecompany].blob.core.windows.net/\[somecontainer]

After this is filled in, you can connect to the storage and see a list of all the files it contains in a table. You can also download the whole storage in one go by clicking the ![](<../.gitbook/assets/image (20).png>) arrow next to **Download**, and choosing **Download All...**

## Service Principal Login

You might find an App ID and Tenant ID, together with either a password or a certificate. In the case of a certificate, make sure that it includes both the `CERTIFICATE` and `PRIVATE KEY` part, appended to each other ([see documentation](https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli#sign-in-with-a-service-principal)).

```shell-session
$ az login --service-principal --username appID --tenant tenantID --password PASSWORD
$ az login --service-principal --username appID --tenant tenantID --password /path/to/cert
```

{% hint style="info" %}
**Tip**: If you get a "No subscriptions found for..." error, don't hesitate to try it again with the `--allow-no-subscriptions` flag. This error means the login was successful, just that there are no subscriptions (which is often what you want, but there are still things to see). \
A real failed authentication will give a more detailed error specifically saying what part of the authentication went wrong.&#x20;
{% endhint %}

{% code title="Successful Example" %}
```json
[
  {
    "cloudName": "AzureCloud",
    "id": "fbfc9b1b-93dc-45bb-9a2c-8fedfc8d06cc",
    "isDefault": true,
    "name": "N/A(tenant level account)",
    "state": "Enabled",
    "tenantId": "56e1b965-a1eb-436c-b453-da31f68e4ced",
    "user": {
      "name": "76d3c680-08f2-4471-9f60-606c6d83c845",
      "type": "servicePrincipal"
    }
  }
]
```
{% endcode %}

## CLI Enumeration

When logged in with `az login` in any way, you can start to enumerate what is on the Azure environment. The most complete guide is the tool itself, using `az --help`, and passing the `--help` argument on various subcommands.&#x20;

### No subscriptions -> `az ad`

If you required the `--allow-no-subscriptions` flag to even successfully log in, there is not much you can enumerate, but still some things. For example, the Active Directory (AD) environment contains users, applications, and other useful things.&#x20;

```shell-session
$ az ad app list
$ az ad user list
```

Especially the `user list` can be useful, as not only do you get names, email addresses, and other information. But sometimes passwords or other sensitive information is put in fields they're not supped to be in, which are public for everyone to read.&#x20;

## Azure Portal

When you have credentials such as an email address and password, you can log into [portal.azure.com](https://portal.azure.com/). In this GUI you can explore many things that might have been given too much access.&#x20;

### Function Apps source code

In the **Function App** section, you may find exposed pieces of code that are running on Azure. To view their source code, which can contain secrets, click on one and go to **Functions**. There you can find all the functions, where you can again click on one to view it in detail. From here, click **Code + Test** to look at the source code, and in the dropdown, you can select any file you want to read (![](<../.gitbook/assets/image (11).png>)).

## Microsoft SQL

If you find database credentials, or a connection string containing them like the following:

{% code title="MS SQL Connection String" overflow="wrap" %}
```
Server=tcp:[someserver].database.windows.net,1433;Initial Catalog=[database];Persist Security Info=False;User ID=[username];Password=[password];MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;
```
{% endcode %}

You can connect to the database using these credentials, and enumerate what is in them, or even change things if you have access. Use [mssql-cli](https://github.com/dbcli/mssql-cli) for a command-line tool, or [Microsoft SQL Server Management Studio](https://learn.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-ver16) for a GUI tool that automatically enumerates the tables and databases.&#x20;

```shell-session
$ mssql-cli -S [someserver].database.windows.net -d [database] -U [username] -P [password]
```

{% hint style="info" %}
**Tip**: If you don't know the name of the database to initially connect to, try connecting without the `-d` argument and running the `\ld` command to list all databases.&#x20;
{% endhint %}

## VPN Access

If you have access to a VPN that gets you access into the internal Azure network, you can directly access internal ports of machines that might expose sensitive information, or allow other attacks now that they are accessible.&#x20;

In Azure, you can look for **Virtual Networks** in the search bar to find a list of VPNs, and then selecting one and viewing **Connected Devices** will list all devices and their IP addresses. For a big network, this can save some time in scanning the network to quickly find all devices.&#x20;
