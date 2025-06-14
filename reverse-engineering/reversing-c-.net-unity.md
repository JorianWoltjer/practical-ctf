---
description: Reverse Engineering executable files compiled with C# .NET (including Unity)
---

# Reversing C# - .NET / Unity

[.NET](https://dotnet.microsoft.com/en-us/) is a framework to build executable programs, mainly used for Windows and GUI programs. You write code in C# and compile programs into executable binaries.&#x20;

For Reverse Engineering, there are a few tools that allow you to examine these compiled binaries, and try to decompile code back into C#.&#x20;

The [Unity game engine](https://unity.com/) also uses this framework to run its games, and the tools explained here can be very useful in Reverse Engineering them. If the game is not protected against this, you can easily open the game's `_Data/Managed/Assembly-CSharp.dll` file which contains the main logic of the program, with all its classes and methods.&#x20;

## dnSpy

{% embed url="https://github.com/dnSpy/dnSpy" %}
.NET debugger, decompiler and editor
{% endembed %}

DNSpy is one of the most powerful tools, as it allows you to go into very low levels of how the .NET binary is made up. It also can be used to dynamically **debug** a program by running it and settings breakpoints.&#x20;

To get started, simply open the 32-bit or 64-bit version depending on the bits of the executable you want to decompile. Then drag in the file on the left panel, and you can explore all its contents.&#x20;

{% hint style="warning" %}
You might only see `PE`, followed by some headers and sections, without any decompiled C# code. In this case, dnSpy does not understand the executable and cannot decompile it, but using [#ilspy](reversing-c-.net-unity.md#ilspy "mention") you might still be able to do so
{% endhint %}

dnSpy is mostly used for interactive debugging. When you have the code in front of you, you can click to the left of any line to set a breakpoint there. When you then press the ![](<../.gitbook/assets/image (3) (2).png>) button you can run the program and stop at any breakpoints you set to examine the current state. Then on the bottom panel, you should see **Locals**, and **Call Stack** to view variables and functions currently in use.&#x20;

You can also use the **C# Interactive** panel to quickly execute C# code in order to evaluate strange expressions for example.&#x20;

### Patching Code

One of dnSpy's greatest powers comes from the ability to change (patch) classes and methods in order to make the code do whatever you want. If there is some `if` statement password check you want to get through, just patch it to be always true! Or the client telling you you can only jump on the ground, remove the check and fly away!

While having an Assembly loaded, you can right-click any class or method and choose **Edit Class** or **Edit Method** to open up a new window. In it, you can rewrite the code however you want. Remove code, add new `using` imports, whatever is needed to make your idea work. Then, after the object is edited how you would like, you can **Compile** which will validate the code, and then use **File -> Save Module** to export the code back to an Assembly (`.dll`).&#x20;

This opens up many possibilities as developers may not expect you to be able to change a program this easily. In `MonoBehaviour` (Unity) classes, specifically there are a few interesting methods that are worth knowing to understand the code better, and to decide a good spot for any extra code you write. \
First the `Start()` method every class has. This method is unsurprisingly called at the **start** of its lifetime, meaning when it is first spawned in. It often contains setup or otherwise one-time code and may be useful if you just want to run some piece of code you wrote to perform a specific action. For example, using the `LoadScene()` function to load in a specific scene you want to look at. You could write a piece of code like this:

<pre class="language-csharp"><code class="lang-csharp"><strong>using UnityEngine.SceneManagement;  // Import required
</strong>
public class SomeScript : MonoBehaviour
{
    private void Start()
    {
<strong>        SceneManager.LoadScene(42);  // Load the level42 asset (from ..._Data)
</strong>    }
}
</code></pre>

Another useful method is `Update()`, which is called on **every frame** to update the scene. Many objects have this method to keep values up to date or a player controller that detects keypresses and controls your movement. These are often useful if you want to _change_ what the code does, as the biggest functionality is often found in these methods. Think of removing checks, adding extra functionality, or anything else.&#x20;

## ILSpy

{% embed url="https://github.com/icsharpcode/ILSpy" %}
.NET decompiler supporting many different formats
{% endembed %}

ILSpy is a completely separate tool from dnSpy, while it looks pretty similar. Its main purpose is decompiling the executable into C# code, and then reading and understanding the code for yourself. It also allows you to read strings and objects that are compiled with the executable.&#x20;

To get started, simply drag an executable file into the left panel, and it will load everything that is needed. Then you can click on the `+` icons to expand all different parts.&#x20;

The `{ }` icon before a name means that it contains **code**, so these might be interesting for understanding what actions the program takes.&#x20;

Another useful part is the **Metadata**. This contains various lists including the **String Heap** and **UserString Heap**. These lists may contain strings the program uses, such as secret keys, commands, or other code. They may prove to be very useful and are worth the time to check out. \
Note that there are more kinds of heaps in this list, with different types of data.

## JetBrains dotPeek

{% embed url="https://www.jetbrains.com/decompiler/" %}
Official dotPeek download page
{% endembed %}

JetBrains primarily make software and tools for programmers to use, in many different programming languages. They also have a **free** .NET Decompiler and Assembly Browser, as linked above.&#x20;

On the base, it does the same as any .NET decompiler, as it will show you the code and allow you to browse through it. But it also has a powerful analysis engine to find usages of functions or variables in other parts of the code.&#x20;

One thing most .NET decompilers miss is the ability to search through the source code as if you had the source files, to find specific keywords or anything else. dotPeek allows you to **export the decompilation as a project**, where you get the full decompiled source and can search though it in any way you want. To do this, simply import an assembly and right-click on its name in the **Assembly Explorer** and choose **Export to Project**:

<figure><img src="../.gitbook/assets/image (7) (2).png" alt=""><figcaption><p><strong>Assembly Explorer</strong> -> <strong>Export to Project</strong></p></figcaption></figure>

Choose a directory to write the source files to, and when it is finished you can find the `.cs` files together with some configuration files it could recover.&#x20;
