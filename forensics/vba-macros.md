---
description: >-
  Visual Basic for Applications is a programming language used to create macro
  scripts for Microsoft office apps
---

# VBA Macros

VBA Macros are often used for malware as they provide an easy way to execute code by only opening a seemingly harmless Word/Excel document. Not all documents are macro-enabled, only the following are ([source](https://en.wikipedia.org/wiki/List\_of\_Microsoft\_Office\_filename\_extensions)):

* `.docm`: Word macro-enabled document
* `.dotm`: Word macro-enabled template
* `.xlm`:   Legacy Excel macro
* `.xlsm`: Excel macro-enabled workbook
* `.xltm`: Excel macro-enabled template
* `.xla`:   Excel add-in that can contain macros
* `.xlam`: Excel macro-enabled add-in
* `.ppam`: PowerPoint 2007 add-in with macros enabled
* `.pptm`: PowerPoint macro-enabled presentation
* `.potm`: PowerPoint macro-enabled template
* `.ppsm`: PowerPoint macro-enabled slideshow
* `.sldm`: PowerPoint macro-enabled slide

## OleVBA

[OleVBA](https://github.com/decalage2/oletools/wiki/olevba) is a tool to detect and analyze VBA Macros. It can find suspicious pieces of code and decode strings to allow you to reverse engineer what the code is doing.&#x20;

You can get the source code of a macro-enabled document using the following command:

```shell-session
$ olevba document.docm
```

This will output a few different things. It will show the VBA code of all the macro files inside, and an analysis of suspicious strings and things like `AutoExec` that can activate macros when you open the document. This source code is what you'll most likely want to be looking at, but often it is very obfuscated as malware detection is getting better and better.&#x20;

### Deobfuscating

The `--reveal` option can decode a few encodings to make the code more readable in some cases:

```shell-session
$ olevba invitation.docm --reveal > reveal.txt  # Decode using olevba
$ sed -i -E "s/b'([^'\\\\]*(\\\\.[^'\\\\]*)*)'/\1/g" reveal.txt  # Replace b'' strings in output
```

For the rest, it's mostly a process of putting the code in a file, and analyzing it by hand with a nice code editor

{% hint style="info" %}
**Tip:** Use the [XVBA VSCode extension](https://marketplace.visualstudio.com/items?itemName=local-smart.excel-live-server) to easily navigate and highlight the code
{% endhint %}

A few pieces of syntax you'll likely come across are the following:

* `Sub main() ... End Sub`: This is a Subroutine, basically a function that is meant to be run by the user. Often these kinds of functions are what trigger the rest, so this is a good place to start
* `Function do_something(arg1 As String) As String ... End Function`: Obviously, this is a function, but it's also important to notice the `As String` types. This shows the types of the argument and the function return type. A value is returned from a function by setting a variable in the function to the name of the function, so this function could **return** using `do_something = ...` in the function body.&#x20;
* `Dim some_var As String`: Define a variable with a type

### Dynamic analysis

It might be quite some work to manually evaluate the code in your head while reading it, so another option is to just run some smaller pieces of code while logging various outputs. This can save a lot of time, when some larger malicious code is built from string operations for example. It would be really easy to just run the code that builds the malicious code and then analyze that further.&#x20;

You can make a simple macro to run by opening a blank document in **Word**, going to the **Developer** tab (if you don't see this [try enabling it here](https://support.microsoft.com/en-us/office/show-the-developer-tab-in-word-e356706f-1891-4bb8-8d72-f57a51146792)), and choosing **Visual Basic**. From there you can **Insert** -> **Module** and a window should pop up for you to write code in. You should start with a `Sub` where you can write your code, and when you want to try running the code press the green  ![](<../.gitbook/assets/image (13).png>) button or just press F5.&#x20;

Here's a simple example that should pop up some text:

```vba
Sub main()
    MsgBox "Hello, world!"
End Sub
```

Often you'll want to use this to see the return values of functions, so one simple way is to just call a function, and save the result to a file, as VBA does not have a simple console to log things in. The code would look something like this:

```vba
Sub main()
    Dim result As String
    result = mystery()
    Open "result.txt" For Output As #1
    Print #1, result
    Close #1
End Sub

Function mystery() As String
    mystery = "this is returned"
End Function
```

When saving a file like this, you need to have saved the document you're working on somewhere. Then all paths in the macros will be relative to that saved file, so you should find `result.txt` next to the saved document.&#x20;

When saving the file you need to explicitly say it is a document with macros enabled, or else it won't save the macros with the document. Do this simply by selecting **Word Macro-Enabled Document (\*.docm)** in **Save as type**.&#x20;

Afterward, you should be able to quickly run your macro with F5 and check the output in `result.txt`.&#x20;
