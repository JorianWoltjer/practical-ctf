---
description: A query language for repositories of code
---

# CodeQL

## Setup

Follow the Getting Started documentation to install the precompiled binary:

{% embed url="https://docs.github.com/en/code-security/codeql-cli/using-the-codeql-cli/getting-started-with-the-codeql-cli" %}
Getting Started with installing the CodeQL CLI and some other useful tools
{% endembed %}

Also, try downloading a [precompiled pack of queries](https://docs.github.com/en/code-security/codeql-cli/using-the-codeql-cli/getting-started-with-the-codeql-cli#4-verify-your-codeql-cli-setup) with common security issues:

{% code title="Example" %}
```shell-session
$ codeql pack download codeql/python-queries
```
{% endcode %}

## Creating a database

{% embed url="https://docs.github.com/en/code-security/codeql-cli/using-the-codeql-cli/creating-codeql-databases" %}
Create a CodeQL database from a repository to analyze later with queries
{% endembed %}

Create a database with the following command, inside the root folder of the project you are trying to analyze. `<database>` will be the output directory, and `<language-identifier>` is one of the supported languages that the project is written in.&#x20;

```shell-session
$ codeql database create <database> --language=<language-identifier>
```

{% code title="Example" %}
```shell-session
$ codeql database create my-project --language=python
```
{% endcode %}

## Analyzing a database

{% embed url="https://docs.github.com/en/code-security/codeql-cli/using-the-codeql-cli/analyzing-databases-with-the-codeql-cli" %}
Use queries to analyze a CodeQL database
{% endembed %}

When you have created a database, use the `analyze` command to run queries on a database. `<format>` can be one of the possible multiple formats, like `csv` or `sarif-latest`.

```shell-session
$ codeql database analyze <database> --format=<format> --output <output-file>
```

{% code title="Example" %}
```shell-session
$ codeql database analyze my-project --format=sarif-latest --output my-project.sarif
```
{% endcode %}

You can view a CSV file with any spreadsheet program, but the most useful format is [`.sarif`](https://docs.github.com/en/code-security/codeql-cli/codeql-cli-reference/sarif-output). To view the findings and locations in the code you can use the [Sarif Viewer VSCode extension](https://github.com/microsoft/sarif-vscode-extension).&#x20;

## TODO: Creating your own queries
