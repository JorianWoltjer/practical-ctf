---
description: Useful commands/syntax and bash tricks
---

# Bash

## Description

Bash is the command line that almost all Linux machines use, or at least are built on top of. It has a lot of special syntaxes to customize how a command is run, and what the arguments are.&#x20;

### `bash` vs `sh`

`bash` is an improved version of `sh`, with a lot of features like command substitution, redirection and much more syntax.&#x20;

Sometimes you may find yourself in an `sh` shell, and want to upgrade to `bash`. In an interactive shell, you can simply run `/bin/bash`, and otherwise use `/bin/bash -c 'command'`. In this string, you can put any bash syntax and make sure it is run with bash, instead of sh.&#x20;

### Chaining Commands

One very powerful feature of bash is its ability to chain multiple commands together.&#x20;

You can simply execute multiple after each other commands in one line by separating them with a `;` semicolon:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ echo a; echo b
</strong>a
b
</code></pre>

This becomes more powerful when introducing conditions. Programs all return an exit code, which is supposed to be 0 on success, and anything else on failure. Using the `&&` syntax you can run the second command only if the first was successful.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ base64 file.txt &#x26;&#x26; echo "Success!"
</strong>SGVsbG8sIHdvcmxkIQo=
Success!
<strong>$ base64 wrong.txt &#x26;&#x26; echo "Success!"
</strong>base64: wrong.txt: No such file or directory
</code></pre>

The opposite of this is the `||` syntax. It only runs if the first command was _u&#x6E;_&#x73;uccessful.&#x20;

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ base64 file.txt || echo "Error!"
</strong>SGVsbG8sIHdvcmxkIQo=
<strong>$ base64 wrong.txt || echo "Error!"
</strong>base64: wrong.txt: No such file or directory
Error!
</code></pre>

The most powerful operator in bash is the `|` pipe operator. It allows you to chain commands together, by putting the first command's STDOUT into the second command's STDIN. Many tools support input from STDIN in some way to allow this chaining of commands:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ seq 1 5 | sed s/3/THREE/
</strong>1
2
THREE
4
5
# # Some commands that expect a filename argument, accept '-' to read from STDIN
<strong>$ seq 1 10 | ffuf -u http://example.com/FUZZ -w -
</strong></code></pre>

### Wildcards

Sometimes you want to perform some action on multiple files with a certain pattern. If you want to run a command on every file in a certain directory, for example, wildcards are a really useful option. Here is an example:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ ls
</strong>first  second  third
<strong>$ file first second third
</strong>first:  empty
second: ASCII text
third:  PNG image data, 800 x 600, 8-bit/color RGBA, non-interlaced
<strong>$ file *
</strong>first:  empty
second: ASCII text
third:  PNG image data, 800 x 600, 8-bit/color RGBA, non-interlaced
</code></pre>

A wildcard simply **replaces the pattern with all files matching the pattern**, separated by spaces. There are a few different characters that are wildcards, and have different functions:

* `*`: Matches any text of any length (example: `*.txt` matches any file ending with ".txt")
* `?`: Matches any single character (example: `????.txt` matches a 4-character .txt file)
* `[]`: Match any single character in a set (example: `[a-n].txt` matches any single letter file in the first half of the alphabet ending with ".txt")

{% hint style="warning" %}
**Note 1**: By default, these wildcard patterns will **ignore** any file starting with a `.` dot. These are so-called dotfiles that are meant to be more hidden.&#x20;

**Note 2**: The files that are matched may contain special characters like a `-` dash, which when substituted in a command may become unintended arguments for the command. See the [#wildcards-argument-injection](linux-privilege-escalation/command-exploitation.md#wildcards-argument-injection "mention") section for more information about the _exploitation_ of this fact.&#x20;
{% endhint %}

### Environment Variables

Environment variables are like temporary variables you can set to influence commands. You can then substitute references to these variables with their value, or let some program read the variable itself.&#x20;

You can export a variable in the current session using the `export` command:

```shell-session
$ export SOMETHING="text"
```

Then you can refer to that variable later in a future command:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ echo "$SOMETHING"
</strong>text
<strong>$ echo "before${SOMETHING}after"
</strong>beforetextafter
# # You can also use `env` to see all current variables
<strong>$ env | grep SOMETHING
</strong>SOMETHING=text
</code></pre>

If you want to set a variable for a single command once, and not for the whole session, you can simply prepend the export syntax to the command:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ SOMETHING="text" env | grep SOMETHING
</strong>SOMETHING=text
</code></pre>

### Command Substitution

There are a few different ways to execute commands, and put the output of those commands into arguments of another command. This is known as command substitution, as it is replaced with its output.&#x20;

To simply replace an argument with the literal output of a command, you can surround it with ` `` ` backticks, or the equivalent `$()`:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ echo `seq 1 10`
</strong>1 2 3 4 5 6 7 8 9 10
<strong>$ echo $(seq 1 10)
</strong>1 2 3 4 5 6 7 8 9 10
</code></pre>

Another less common syntax is using `<()`. This replaces the argument with a temporary **path** to the output. It is very useful for commands that expect a filename as an argument, like so:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ echo &#x3C;(seq 1 5) &#x3C;(seq 6 10)
</strong>/dev/fd/63 /dev/fd/62
<strong>$ cat &#x3C;(seq 1 5) &#x3C;(seq 6 10)
</strong>1
2
3
4
5
6
7
8
9
10
</code></pre>

### Output Redirection

Using some special characters, you can pass the output of a command or file, to other commands or files. The most common is `>`, which writes the output of its left, to a file named on the right:

```shell-session
$ echo "Hello, world!" > file.txt
# # If no command is specified, an empty file is created
$ > new.txt
```

{% hint style="warning" %}
**Warning**: This will replace the file's contents if it already exists. To append data to the output file, you can use `>>`:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ echo "new line" >> file.txt
</strong><strong>$ cat file.txt
</strong>Hello, world
new line
</code></pre>
{% endhint %}

### Input Redirection (Advanced)

A less common way to read a file as STDIN to a command is by using `<`. It is equivalent to piping `cat [file] |` to the command.&#x20;

```shell-session
$ ./program < input.txt
```

Another useful trick to specify a string on the command line, to pass as STDIN to a command is using `<<<`:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ base64 &#x3C;&#x3C;&#x3C; 'Hello, world!'
</strong>SGVsbG8sIHdvcmxkIQo=
<strong>$ echo 'Hello, world!' | base64  # Equivalent
</strong>SGVsbG8sIHdvcmxkIQo=
</code></pre>

You can find all details you'll ever need in the manual here, which explains some **interesting tricks**:

{% embed url="https://www.gnu.org/software/bash/manual/html_node/Redirections.html" %}
Official manual for bash input/output redirection
{% endembed %}

One is that you can specify a specific file descriptor of where the file should be opened in the program. This may be useful in restricted binary exploitation scenarios, where you need to have a certain file or directory open at a specific file descriptor:

{% code title="[n]<file" %}
```shell-session
$ ./program 3< /path/to/file    # Open file at FD 3
$ ./program 3< /path/to/dir/    # Open directory at FD 3
```
{% endcode %}

A more generally useful piece of syntax is the `&>` characters, which redirect **both** STDOUT and STDERR together into a file:

```shell-session
$ ./program &> output.txt
# # === equivalent to ===
$ ./program >output.txt 2>&1
```

### Escape Characters

{% embed url="https://www.physics.udel.edu/~watson/scen103/ascii.html" %}
An ASCII table with control characters
{% endembed %}

Use `echo -e` to escape certain untypable characters, like Ctrl+C, or [ansi-escape-codes.md](../other/ansi-escape-codes.md "mention"):

```shell-session
$ echo -e "\x03"  # Ctrl+C
```

## Filter Bypass

If you are trying to bypass some command injection filter, there are a few lesser-known pieces of bash syntax that the author of the filter may not have thought of.&#x20;

Try some [#command-substitution](bash.md#command-substitution "mention"), and here is another really weird trick to not require **spaces**:

```shell-session
$ {cat,/etc/passwd}

$ cat${IFS}/etc/passwd
# # If { or } not allowed:
$ cat$IFS/etc/passwd
# # If you require a normal character after the variable:
$ cat$IFS'file.txt'
$ cat$IFS"file.txt"
```

When _letters_ aren't allowed, variables and wildcards are very powerful. This command for example translates to `bash < [every file in the directory]` which might error out some contents of the files if they are not valid bash:

```bash
${0/-/} <*
```

{% hint style="info" %}
For some more advanced usage of these variable substitutions, see [this reference](https://tldp.org/LDP/abs/html/parameter-substitution.html)
{% endhint %}

## Related

{% content-ref url="hacking-linux-boxes.md" %}
[hacking-linux-boxes.md](hacking-linux-boxes.md)
{% endcontent-ref %}

[#attacking-bash-scripts](linux-privilege-escalation/command-exploitation.md#attacking-bash-scripts "mention")
