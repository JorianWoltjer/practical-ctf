# NodeJS

## Code Execution

```javascript
require("child_process").exec("id", (err, out) => console.log(out))
```

## Template Injection (SSTI)

Similar to [sqlmap](https://github.com/sqlmapproject/sqlmap), there is [tplmap](https://github.com/epinna/tplmap) which aims to automate template injections by testing various templating engines. Here is a simple example:

```shell-session
$ python2 tplmap.py -u http://localhost:3000/?name=john
```

The tool also allows you to exploit the injection using arguments such as `--os-shell`. \
See the `--help` page for more useful arguments.&#x20;

## Dependencies (package.json)

In every NodeJS project there is a `package.json` file which contains a lot of metadata information about the project, such as where the main file is, some description, and the dependencies. These are external pieces of code with a version number attached that are used throughout the project.&#x20;

A possible problem is when these dependencies aren't regularly updated, and vulnerabilities might be found in those dependencies and be fixed in later versions. If the code keeps using the older version it may become vulnerable because of those dependencies.&#x20;

A simple way to check for known vulnerabilities is by uploading the `package.json` file to Snyk checker:

{% embed url="https://snyk.io/advisor/check/npm" %}
Upload your package.json file and see all the vulnerabilities in old dependencies
{% endembed %}

For attackers, this can give an idea of what vulnerabilities there might be. Of course not all vulnerbilities this checker finds are actually exploitable, but you should find what parts/functions of the vulnerable code are used to see if it is.&#x20;
