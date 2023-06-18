---
description: Decompiling and understanding unknown APKs, using dynamic and static testing
---

# Reversing APKs

## Decompiling

For Android apps, there are a few different common formats. A pretty common way is apps coded in Java, where compiling is turning that source code into **Java bytecode**. After this, the Java code along with the resources it needs is **converted** into a Dalvik Executable (DEX) file. You can see this DEX format as the machine code, and another language called **Smali** is basically **assembly**: the human-readable version of machine code while staying pretty low level.&#x20;

When you want to do static analysis on an APK file, you will first need to **decompile** it to make any sense of the code. There are a few useful tools for this, and the first one is [apktool](https://ibotpeaches.github.io/Apktool/). It is a general-purpose tool for unpacking and rebuilding APKs that gets almost everything from the APK. The main use is turning an **APK** file into **Smali** code, meaning the readable assembly:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ apktool d -f -r app.apk -o app/  # Decompile to smali and assets
</strong>I: Using Apktool 2.4.0-dirty on app.apk
I: Copying raw resources...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
</code></pre>

Other folders/files you might need could be ignored by `apktool`, so it is always a good idea to unpack the APK itself, as **it is just a special ZIP file**. We can simply `unzip` the file to get all the raw content:

```shell-session
$ unzip app.apk -d app/
```

### Java

Reading Smali code is like reading raw assembly, but often this is not what the app was written in, so there is another process to actually decompile an APK into a JAR file. This tool for this is named [dex2jar](https://github.com/pxb1988/dex2jar/releases), and we will use it on the `.apk` file:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ d2j-dex2jar.sh -f app.apk -o app.jar  # Extract JAR from APK
</strong>dex2jar app.apk -> app.jar
</code></pre>

When we have a JAR file, the next step is to unpack and **decompile** that into `.java` source files. A simple tool that does this for all files in a JAR is [procyon](https://github.com/ststeiger/procyon). Simply run it on the `.jar` file created earlier and specify an output directory:

```shell-session
$ procyon app.jar -o app.java/  # Decompile JAR into .java files
```

This can take a while for a big application, but after it is finished you can open the directory it created with a Code Editor like IntelliJ and read all the Java source files.&#x20;

### React Native

Sometimes the decompiled Java code simply does not make any sense, or you see lots of references to "React". When this is the case, it could be that the application was not written in Java, but in a JavaScript framework like React Native. Luckily, there are also tools for decompiling the bundle this creates into semi-readable JavaScript code.

To check if you are dealing with React Native, check for a `assets/index.android.bundle` file in your **unzipped** APK. If that exists, you can use [react-native-decompiler](https://www.npmjs.com/package/react-native-decompiler) to decompile it into multiple JavaScript files.&#x20;

```shell-session
$ npx react-native-decompiler -i app.zip/assets/index.android.bundle -o app.js/
```

Because this bundle is heavily packed, there is a lot of code that serves no use to us, and names are mostly lost. But the best bet is to simply take a quick glance at all the files to see if you recognize anything. **Searching for strings** is also very useful if you know some strings when you start the app in an emulator.&#x20;

{% hint style="info" %}
**Tip**: You might see a lot of `require('./[number]')` code, this simply means it imports a module from the file named `[number].js`.
{% endhint %}

### C# with .NET

Another possibility is C# with .NET as the language the app was written in. You can detect this by finding an `assemblies/` folder in the **unzipped** APK. This folder will contain many `.dll` files, but these files are compressed and not easily readable yet. To decompress the assemblies and allow other tools to work with them use [xamarin-decompress](https://github.com/NickstaDB/xamarin-decompress/blob/main/xamarin-decompress.py):

```shell-session
$ xamarin-decompress.py app.zip/assemblies
```

This will turn `.dll` files into `.decompressed.dll` files in the same directory, which can be easily Reverse Engineered using tools like [dnSpy](https://github.com/dnSpy/dnSpy). For more information on reversing from here on out see [reversing-c-.net-unity.md](../../reverse-engineering/reversing-c-.net-unity.md "mention"). It can decompile these files to almost perfect C# source code.&#x20;

### Automatic tool

Quickly decompiling an APK file can be quite a hassle, which is originally why I made my `default apk` tool that can do all the things shown above, but automatically by detecting the existence of certain files. I run it every time I come across an APK file I want to Reverse Engineer:

{% embed url="https://github.com/JorianWoltjer/default/blob/master/default/commands/apk.py" %}
A CLI tool to automate certain common CTF-related tasks, including APK decompiling
{% endembed %}

For an example of how this tool works and what it does, see this video:

{% embed url="https://asciinema.org/a/hEDUJNUkZideirH6Z2VcE3WKF?autoplay=1" %}
An example showing unpacking, detecting and decompiling an APK file into C# `.dll` files
{% endembed %}

## App Resources

In the code, you might find hex numbers similar to `0x7f100213`. These numbers refer to resources of the app, stored with it in the APK.&#x20;

When you have your APK project open in Android Studio, simply make sure you have the `.apk` file open from the left side, and you can see a list of files in the middle. Click on the `resources.arsc` file and it will show you all the Resource Types and contents in a table. Here you can find what resource matches the hex address you found earlier to find what content it points to.&#x20;

Most of the **strings** and some other categories will be visible here, but you also might find just a path starting with `res/`. This means the value can be found in the `res/` directory inside of the APK, which is also visible in Android Studio right above the `resources.arsc` file. \
To view the real contents simply select the file in there, or to get the raw data outside Android Studio use the local `res/` folder in the unzipped APK.&#x20;
