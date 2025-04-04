---
description: A query language for repositories of code
---

# CodeQL

## Setup

Follow the Getting Started documentation to install the precompiled binary:

{% embed url="https://docs.github.com/en/code-security/codeql-cli/using-the-codeql-cli/getting-started-with-the-codeql-cli" %}
Getting Started with installing the CodeQL CLI and some other useful tools
{% endembed %}

On the releases page, you should download the "CodeQL Bundle" from any of the assets, likely [`codeql-bundle-linux64.tar.gz`](https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz).&#x20;

In case you need more queries for different languages not already included in the bundle, try downloading a [precompiled pack of queries](https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/setting-up-the-codeql-cli#testing-the-codeql-cli-configuration) per language:

{% code title="Example" %}
```bash
codeql pack download codeql/python-queries
```
{% endcode %}

## Creating a database

{% embed url="https://docs.github.com/en/code-security/codeql-cli/using-the-codeql-cli/creating-codeql-databases" %}
Create a CodeQL database from a repository to analyze later with queries
{% endembed %}

Create a database with the following command, inside the root folder of the project you are trying to analyze. `<database>` will be the output directory, and `<language-identifier>` is one of the supported languages that the project is written in.&#x20;

```bash
codeql database create <database> --language=<language-identifier>
```

{% code title="Example" %}
```bash
codeql database create .codeql --language=python
```
{% endcode %}

{% hint style="info" %}
**Tip**: For some compiled languages like `java`, the autobuilder may not be able to build your source code to index it. You can choose for `--build-mode=none` to disable building the project and just look at the source files.
{% endhint %}

## Analyzing a database

{% embed url="https://docs.github.com/en/code-security/codeql-cli/using-the-codeql-cli/analyzing-databases-with-the-codeql-cli" %}
Use queries to analyze a CodeQL database
{% endembed %}

When you have created a database, use the `analyze` command to run queries on a database. `<format>` can be one of the possible multiple formats, like `csv` or `sarif-latest`.

```bash
codeql database analyze <database> --format=<format> --output <output-file>
```

{% code title="Example" %}
```bash
codeql database analyze .codeql --format=sarif-latest --output codeql.sarif
```
{% endcode %}

You can view a CSV file with any spreadsheet program, but the most useful format is [`.sarif`](https://docs.github.com/en/code-security/codeql-cli/codeql-cli-reference/sarif-output). To view the findings and locations in the code you can use the [Sarif Viewer VSCode extension](https://github.com/microsoft/sarif-vscode-extension).

{% embed url="https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer" %}
Download **SARIF Viewer** extension by Microsoft DevLabs
{% endembed %}
