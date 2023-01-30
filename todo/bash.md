---
description: Useful commands and bash tricks
---

# Bash

\[TODO: redirection, command substitution, wildcards, env variables in front of commands, etc.]

* [ ] redirection
* [ ] command substitution
* [ ] wildcards (\*,?,\[])
  * [ ] .files are ignored
* [ ] env variables in front of commands
* [ ] more

### Special characters

{% embed url="https://www.physics.udel.edu/~watson/scen103/ascii.html" %}

```shell-session
$ echo -e "\x03"  # Ctrl+C
```

### Send STDIN to TTY

{% embed url="https://unix.stackexchange.com/questions/48103/construct-a-command-by-putting-a-string-into-a-tty/48221" %}

{% code title="tty.pl" %}
```perl
require "sys/ioctl.ph";
ioctl(STDOUT, &TIOCSTI, $_) for split "", <STDIN>;
```
{% endcode %}

```shell-session
$ ps auxt | grep pts
user     658  0.0  0.0  10496  5488 pts/0    Ss+  17:17   0:00 -bash
$ echo 'id' | sudo perl tty.pl > /dev/pts/0
```
