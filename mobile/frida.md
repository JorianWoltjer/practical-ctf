---
description: A JavaScript tool to interact with running Android applications through code
---

# Frida

## Installation

Frida has two parts, a _server_ and a _client_. The server runs on the device, and clients connect to it.

{% hint style="warning" %}
**Warning**: Using the latest Android API versions can be unstable because Frida may not support them. I've personally noticed **version 34** working well, and later versions causing segfaults.
{% endhint %}

For a lot of features, the server binary from the [Releases](https://github.com/frida/frida/releases) is required. It's a large list so _Show all assets_ and search for `frida-server-*-android-x86_64.xz` or any other architecture depending on your device (check `adb shell getprop ro.product.cpu.abi`).\
Then push the extracted file to your device inside some temporary directory and run it:

```bash
adb push frida-server-*-android-x86_64 /data/local/tmp/frida-server
adb shell chmod +x /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server
```

{% hint style="info" %}
Make sure your device is **rooted** before attempting to run `frida-server`, otherwise, you will receive the following error:

<pre class="language-shell-session" data-overflow="wrap"><code class="lang-shell-session">$ adb shell /data/local/tmp/frida-server
<strong>Unable to load SELinux policy from the kernel: Failed to open file ?/sys/fs/selinux/policy?: Permission denied
</strong></code></pre>

Simply use [#adb](setup.md#adb "mention") to get a root shell and try again:

```bash
adb root
```
{% endhint %}

Now, on your host system you should install the client CLI in the form of a Python library:

```bash
pip install frida
```

Commands like `frida`, `frida-ps` and `frida-trace` should now become available in your shell.

## Tracing

The `-U` flag should be added to **all commands** because it will use the Android bridge, otherwise you will act on your host system. The simplest command is listing processes with [`frida-ps`](https://frida.re/docs/frida-ps/):

<pre class="language-shell-session" data-title="List Processes"><code class="lang-shell-session"><strong>$ frida-ps -Ua
</strong> PID  Name         Identifier                             
----  -----------  ---------------------------------------
<strong>5852  Chrome       com.android.chrome
</strong>1861  Google       com.google.android.googlequicksearchbox
1861  Google       com.google.android.googlequicksearchbox
1694  Messages     com.google.android.apps.messaging
1053  SIM Toolkit  com.android.stk
1056  Settings     com.android.settings
</code></pre>

You can choose any application _Identifier_ and pass it via `-N` to attach `frida-trace` to it (server must be running):

{% code title="Trace specific application" %}
```bash
frida-trace -U -N com.android.chrome
```
{% endcode %}

If the target application is the one in the foreground, you'll be easier off using just `-F` to automatically select it:

{% code title="Trace foreground app" %}
```bash
frida-trace -U -F
```
{% endcode %}

Both start a localhost server on a random port which you can visit in your browser. The UI isn't very intuitive, but there's only a few useful features you will use.

### Logging calls

What this tool is really made for is logging calls to functions or methods while the application is running by inserting _hooks_. You can add one using the <img src="../.gitbook/assets/image (74).png" alt="" data-size="line"> button and choose a type on the right dropdown. For example, if you have an application with some method in a class defined in Java that you want to investigate, choose _Java Method_. The syntax template tells you to input `[Module!]Function`, this accepts wildcards, so to target a method named `decrypt` in _any class_ use `*!decrypt` (it should give auto-completion results to choose from).

From the command-line you can also quickly set up a default hook like this (`-j` = Java Methods, `-i` for native functions):

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ frida-trace -U -F -j '*!decrypt'
</strong>Instrumenting...
MainActivity.decrypt: Auto-generated handler at "C:\...\decrypt.js"
Started tracing 1 function. Web UI available at http://localhost:2762/
</code></pre>

This will generate a simple handler similar to the following that logs all _arguments_ and the _return value_:

{% code title="decrypt.js" %}
```javascript
defineHandler({
  onEnter(log, args, state) {
    log(`MainActivity.decrypt(${args.map(JSON.stringify).join(', ')})`);
  },

  onLeave(log, retval, state) {
    if (retval !== undefined) {
      log(`<= ${JSON.stringify(retval)}`);
    }
  }
});
```
{% endcode %}

Press <img src="../.gitbook/assets/image (73).png" alt="Deploy" data-size="line"> to run the code (from then on, Ctrl+S reloads your changes). This should log all future calls to the method in question:

{% code title="Log" %}
```log
69887 ms  MainActivity.decrypt("test")
69901 ms  <= false
```
{% endcode %}

{% hint style="info" %}
You write all logic using the [JavaScript API](https://frida.re/docs/javascript-api/) which has a subset of JavaScript's language features.
{% endhint %}

### Native Functions

Native functions are defined in `.so` binaries in the `lib/` folder, you should use binary [Broken link](/broken/pages/Ot6uSZX7dTuO8LYuSyDt "mention") tools to analyze them. Then, you may find custom functions or even library functions of interest which you want to log the arguments/memory of. While possible to do manually in GDB, the easiest way is by setting a hook with Frida:

```bash
frida-trace -U -F -i '*!memcpy'
```

This sets a _very generic_ hook for every time `memcpy()` is called, likely creating way too much spam from random invocations. To focus on a specific place in the code you find, you can look at the _return address_ of the call when you intercept it, and then decide wether or not to log it.

Inside your decompiler/disassembler, look at the **call** to your function of interest, and note down the **address of the next instruction**. This will be the return address we're looking for while inside the call. In the following code this would be `0x12de1`, for example:

<figure><img src="../.gitbook/assets/image (75).png" alt=""><figcaption></figcaption></figure>

We will define a hook for `*!memcpy` and check if `this.returnAddress` ends with the same 3 hex digits (because address space shifting happens in increments of `0x1000`). Only if this is true, is the call likely what we need. In the case for this `memcpy()` call, we can read the manpage to learn that its first argument should be the destination, the second argument the source and the third argument the number of bytes to copy.

Because the `args` array will only contain pointers for native code, we can alter it to read the given amount of bytes from the source pointer as a string and print it, to see what string will be copied to the destination.

{% code title="memcpy.js" %}
```javascript
defineHandler({
  onEnter(log, args, state) {
    if (this.returnAddress.and(0xfff).equals(0x00012de1 & 0xfff)) {
      const dst = args[0];
      const src = args[1];
      const size = args[2].toInt32();
      const src_str = src.readUtf8String(size);

      log(`memcpy(${dst}, ${JSON.stringify(src_str)}, ${size})`);
    }
  },
});
```
{% endcode %}

{% code title="Log" %}
```log
238365 ms  memcpy(0x743cd947ab90, "super secret password", 21)
```
{% endcode %}

## Scripts

Instead of analyzing an application that is already running, scripts allow you to automate any JavaScript code from the **start** of an application. You can **run** a saved script as follows:

```bash
frida -U -f com.example.app -l script.js
```

{% hint style="info" %}
`-U` means connect to USB device (ADB)

`-f` means start app with this name

`-l` means run this script on launch
{% endhint %}

Alternatively, you can also do the same from Python:

<details>

<summary>Python Script Template</summary>

{% code title="Requirements" %}
```bash
pip install frida
```
{% endcode %}

<pre class="language-python" data-title="Python"><code class="lang-python">import frida
import frida_tools
import os

APP = "com.example.app"

# Put any JavaScript in the string below
script = """
<strong>...
</strong>"""

def main():
    try:
        device = frida.get_usb_device()
        pid = device.spawn([APP])
        session = device.attach(pid)
        script_instance = session.create_script(script)
        script_instance.load()
        device.resume(pid)
        print(f"Script injected into {APP}.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
    input("Press Enter to exit...")  # Keep the script running until user input
</code></pre>

</details>

From here, the functionality is very similar to [#tracing](frida.md#tracing "mention"). But instead of logging values, this is more useful for altering the functionality of apps. You can overwrite functions and call them however you want, very powerful for quickly testing something and retrying without having to set up the trace all over again.

{% hint style="success" %}
**Tip**: Inside of the script shell (`->` ) you can run `%reload` to re-run your script if you changed it without restarting the app. This can be useful for quick iteration where hooking as quickly as possible doesn't matter.
{% endhint %}

### SSL Pinning

Some applications, for the sake of security, implement extra checks to try and prevent them from being reverse engineered. One of these checks is to see if any unexpected certificates are used for the HTTPS communication, like configured in [#install-certificate-authority-https](http-s-proxy-for-android.md#install-certificate-authority-https "mention"). Luckily, all of this detection happens on-device, so we can _change_ the application's behavior slightly to bypass such checks and debug normally.

Download and run the following script and your app will likely magically be HTTPS-interceptable again. It implements function overrides for many built-in ways to verify certificates.

{% embed url="https://codeshare.frida.re/@ahrixia/root-detection-and-ssl-pinning-bypass/" %}
Frida Root Detection and SSL Pinning Bypass script by @ahrixia
{% endembed %}

### Calling Java functions

One of the most basic but useful features is calling Java functions and methods from within a script. This can be to automate something that's hard to recreate outside of the app.

Firstly, [`Java.perform()`](https://frida.re/docs/javascript-api/#java-perform) is called to hook into the JVM. It takes a function as its first argument which now has access to Java classes with [`Java.use()`](https://frida.re/docs/javascript-api/#java-use).\
You can instantiate classes by calling `.$new()` on them with any arguments, then call methods. For static classes you can immediately call them on the class object itself. Even if they're `private`!

{% code title="Example" %}
```javascript
Java.perform(function () {
  var MathUtils = Java.use("com.google.android.material.math.MathUtils");
  // Calling a static function
  console.log(MathUtils.dist(0, 0, 1, 1));  // 1.41421...

  var Dimension = Java.use("androidx.constraintlayout.core.state.Dimension");
  // Constructing an object, then calling a method
  var dimension = Dimension.$new();
  console.log(dimension.getValue());
});
```
{% endcode %}

### Overwriting Java functions

Another useful idea is overwriting existing functions that then get called by the app. This is done by assigning their `.implementation` property to a custom function that takes the same arguments as the regular method/function. Then returning a value here would also return it in the Java-world.

Below is an example that in addition to the above uses `overload()` to find the specific `onCreate` method that uses a `Bundle` argument. It does so on the `MainActivity` class of the app, essentially overwriting its initializer. You can call the regular method again with `this.onCreate(bundle)`.\
The use of this specific snippet is hooking the `MainActivity.onCreate` method when it's complete so that you can call any other methods on it afterward via `this`.

{% code title="Get MainActivity instance" %}
```javascript
Java.perform(function () {
  // Get MainActivity class
  var MainActivity = Java.use("com.example.app.MainActivity");
  // Overwrite the `.onCreate(Bundle)` method
  MainActivity.onCreate.overload("android.os.Bundle").implementation = function (bundle) {
    console.log("onCreate called");
    this.onCreate(bundle);  // Call original function

    // From here on, `this` refers to the `MainActivity` instance
    console.log(this.win());
  }
});
```
{% endcode %}

And another one to overwrite a return value:

```javascript
MainActivity.check.implementation = function (input) {
    console.log("Input:", input);
    return true;  // Always return true instead of performing a "check"
}
```
