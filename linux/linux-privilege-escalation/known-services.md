---
description: >-
  Some common services run every once in a while but can allow for privilege
  escalation if set up incorrectly or are outdated
---

# Known Services

## Git hooks

When you find a `.git` directory, you can find a lot of history in files by looking at the different commits and branches (see more in [git.md](../../forensics/git.md "mention")). But there is also a feature called Hooks that allow you to run code when a certain action happens with the repository. With a `git commit` is executed, for example, the `pre-commit` hook gets triggered. If you can write these hooks you can let whoever runs the `git commit` execute arbitrary commands.&#x20;

You can find these hooks in the `.git/hooks` directory. If you are able to write a `pre-commit` file here, you can put any executable file in its place and it will be run on commit:

{% code title=".git/hooks/pre-commit" %}
```bash
#!/bin/bash

cp /bin/bash /tmp/bash; chmod +xs /tmp/bash
```
{% endcode %}

Then just make sure the file is actually executable with `chmod`:

```shell-session
$ chmod +x pre-commit
```

{% hint style="info" %}
For more command injection in git configuration files, see[#attacking-git-commands](../../forensics/git.md#attacking-git-commands "mention")
{% endhint %}
