---
description: >-
  After decompiling the code, you can change code and build the app again to
  patch the APK, and make it do different things
---

# Patching APKs

## Decompiling

Patching APKs works by changing the Smali code. To get this code, use [apktool](https://ibotpeaches.github.io/Apktool/) to decompile it:

```shell-session
$ apktool d -f -r app.apk -o app/
```

After that has finished, you will find a `smali/` folder in the output folder of the above command. This contains all the Smali code which is a human-readable assembly for Android. You can open this in your favorite editor to change any of the instructions or values. \
For example, you may find a number responsible for the required score, that you can change to a lower number to bypass some checks.&#x20;

## Rebuilding

It is often difficult to make big changes to the Smali code, but you can pretty easily change number values or strings in the `.smali` files. After making the changes you want, you can turn it back into an APK file to run in Android Studio.&#x20;

To build this after making the changes in your `smali/` folder, go to the top directory again, and use apktool to build the APK:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ apktool b -f app/
</strong>I: Using Apktool 2.4.0-dirty
I: Smaling smali folder into classes.dex...
I: Copying raw resources...
I: Copying libs... (/lib)
I: Copying libs... (/kotlin)
I: Building apk file...
I: Copying unknown files/dir...
I: Built apk...
</code></pre>

Now you will find an APK file in `app/dist/app.apk` with your changes. However, to actually be able to run it on an Android device, you first need to **sign** it.&#x20;

## Signing

To verify the integrity of apps, they must be signed by someone before being able to run on the device. This includes emulated devices, so we need to first sign the patched APK before trying to run it in Android Studio.&#x20;

The first thing you need to do before signing is to align the APK file. This can be done with the [zipalign](https://developer.android.com/studio/command-line/zipalign) tool:

```shell-session
$ zipalign -f 4 app/dist/app.apk app/dist/app-aligned.apk
```

After which, you can actually get to the signing. For this, we can use the [apksigner](https://developer.android.com/studio/command-line/apksigner) tool made for this. It needs a few files first, like a **keystore** to read the certificate from. If you do not have a keystore key, which you likely won't if this is the first time you are signing an APK, you can create one with the following command using [keytool](https://docs.oracle.com/javase/8/docs/technotes/tools/unix/keytool.html):

{% code overflow="wrap" %}
```shell-session
$ keytool -genkey -noprompt -dname 'CN=, OU=, O=, L=, S=, C=' -keystore apk.keystore -alias 'apk' -keyalg RSA -storepass 'password' -keypass 'password'
```
{% endcode %}

This specific command will create a keystore with the following attributes (which can be anything) that we'll need later:

* Alias: `apk`
* Passwords: `password`

After this has been created, use `apksigner` command to use this keystore, and sign the aligned APK:

<pre class="language-shell-session" data-overflow="wrap"><code class="lang-shell-session"><strong>$ apksigner sign -out app/dist/app-signed.apk --ks-key-alias 'apk' --ks apk.keystore --key-pass 'pass:password' --ks-pass 'pass:password' -v app/dist/app-aligned.apk
</strong>Signed
</code></pre>

Finally, the fully signed APK should be stored in `app/dist/app-signed.apk`. You can verify this using `apksigner verify`:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ apksigner verify -v app/dist/app-signed.apk
</strong>Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): false
Verified using v3 scheme (APK Signature Scheme v3): true
Number of signers: 1
</code></pre>

This `.apk` file can now successfully be imported into Android Studio, and emulated on a device to run your patched application.&#x20;
