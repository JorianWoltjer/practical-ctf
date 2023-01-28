---
description: Search for text inside of files
---

# Grep

## Description

Grep is a really useful tool for quickly finding what you're looking for. If you know a file somewhere has some content, or just want to find all files with a certain pattern in them, Grep is the perfect tool for the job. It's written in C and highly optimized, meaning you can quickly search through lots of files.&#x20;

```shell-session
$ grep [OPTIONS...] PATTERNS [FILES...]
```

* `OPTIONS` can be any flags to change the way the search works, or matches are displayed
* `PATTERNS` are a string containing one or more patterns to search for, separated by newline characters (`\n`). To put a newline character in an argument you can use the `$'first\nsecond'` syntax
* `FILES` are the files to search through for the `PATTERNS`. If not specified, it will read from standard input (piping into grep). If in recursive mode with -r, it will default to the current directory but can be any directory

<pre class="language-shell-session" data-title="Simple example"><code class="lang-shell-session"><strong>$ grep something file.txt
</strong>And here is something.
</code></pre>

{% hint style="info" %}
See all documentation about the options with `man grep`
{% endhint %}

### Options

The are a few common and really useful options to know in Grep:

* `-r`: **R**ecursively search a directory (default: current)
* `-v`: In**v**ert search, matching lines where no match
* `-i`: Search case-**i**nsensitive (uppercase/lowercase doesn't matter)
* `-n`: Print the line **n**umber of the match in the file
* `-o`: **O**nly output match (no text around)
* `-a`: Show **a**ll matches (also binary files)
* `-b`: Show **b**yte-offset of matches
* `-l`: **L**ist files that match instead of showing the match
* Simple [regular-expressions-regex.md](../languages/regular-expressions-regex.md "mention") are enabled by default in `PATTERNS`
  * `-F`: Treat `PATTERNS` as **f**ixed strings, not regular expressions
  * `-P`: Use **p**erl-compatible regular expressions (PCRE) including all advanced RegEx features

Some options are also available by using egrep (`-E`), fgrep (`-F`) and rgrep (`-r`) to quickly set the options without having to add the flag.&#x20;

### Examples

```shell-session
# # Select files and output
$ grep -r "something"  # Search recursively in current directory for "something"
$ grep -v "something" file.txt  # Find all lines in file that don't match "something"
$ grep "something" *.txt  # Search "something" in all .txt files (current directory only)
$ grep -r "something" --include "*.txt"  # Recursivly search "something" in .txt files
$ grep -ab "something" file.bin  # Show all (binary) matches and byte-offset
$ grep -r -l "something"  # List filenames that match "something" recursively
$ grep -B2 -A5 "something" file.txt  # Show 2 lines before, and 5 lines after match

# # Patterns
$ grep -r -i "something"  # Search case-insensitively for "something"
$ grep "CTF{.*}" file.txt  # Search for flag format in file
$ grep -P "\x73\x6f\x6d\x65\x74\x68\x69\x6e\x67" file.txt  # Search for hex bytes in file
$ xxd -p file.txt | grep "aabbccdd"  # Search for hex bytes using xxd
$ grep $'first\nsecond' file.txt  # Search for multiple patterns in one file
```
