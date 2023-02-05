---
description: Reverse Engineering executable files compiled with .NET
---

# Reversing .NET

[.NET](https://dotnet.microsoft.com/en-us/) is a framework to build executable programs, mainly used for Windows and GUI programs. You write code in C# and compile programs into executable binaries.&#x20;

For Reverse Engineering, there are a few tools that allow you to examine these compiled binaries, and try to decompile code back into C#.&#x20;

## dnSpy

{% embed url="https://github.com/dnSpy/dnSpy" %}
.NET debugger, decompiler and editor
{% endembed %}

DNSpy is one of the most powerful tools, as it allows you to go into very low levels of how the .NET binary is made up. It also can be used to dynamically **debug** a program by running it and settings breakpoints.&#x20;

To get started, simply open the 32-bit or 64-bit version depending on the bits of the executable you want to decompile. Then drag in the file on the left panel, and you can explore all its contents.&#x20;

{% hint style="warning" %}
You might only see `PE`, followed by some headers and sections, without any decompiled C# code. In this case, dnSpy does not understand the executable and cannot decompile it, but using [#ilspy](reversing-.net.md#ilspy "mention") you might still be able to do so
{% endhint %}

dnSpy is mostly used for interactive debugging. When you have the code in front of you, you can click to the left of any line to set a breakpoint there. When you then press the ![](<../.gitbook/assets/image (3) (2).png>) button you can run the program and stop at any breakpoints you set to examine the current state. Then on the bottom panel, you should see **Locals**, and **Call Stack** to view variables and functions currently in use.&#x20;

You can also use the **C# Interactive** panel to quickly execute C# code in order to evaluate strange expressions for example.&#x20;

## ILSpy

{% embed url="https://github.com/icsharpcode/ILSpy" %}
.NET decompiler supporting many formats
{% endembed %}

ILSpy is a completely separate tool from dnSpy, while it looks pretty similar. Its main purpose is decompiling the executable into C# code, and then reading and understanding the code for yourself. It also allows you to read strings and objects that are compiled with the executable.&#x20;

To get started, simply drag an executable file into the left panel, and it will load everything that is needed. Then you can click on the `+` icons to expand all different parts.&#x20;

The `{ }` icon before a name means that it contains **code**, so these might be interesting for understanding what actions the program takes.&#x20;

Another useful part is the **Metadata**. This contains various lists including the **String Heap** and **UserString Heap**. These lists may contain strings the program uses, such as secret keys, commands, or other code. They may prove to be very useful and are worth the time to check out. \
Note that there are more kinds of heaps in this list, with different types of data.

