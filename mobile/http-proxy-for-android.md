---
description: Intercept traffic going from and to an emulated Android device with Burp Suite
---

# HTTP Proxy for Android

When you have an Android emulator set up in Android Studio, you can change some settings to be able to intercept traffic in a Proxy like Burp Suite. This can be really useful when you want to view or test web functionality that an app uses, as this might reveal interesting vulnerabilities because developers might not expect the app to be reverse-engineered in this way.&#x20;

## Setup

All information is taken from [this article by secabit](https://secabit.medium.com/how-to-configure-burp-proxy-with-an-android-emulator-31b483237053).&#x20;

### Export CA Certificate

The first step is to get a certificate file from Burp Suite, to be able to intercept encrypted HTTPS traffic as well.&#x20;

Open Burp Suite, and go to **Proxy** -> **Options**. From there click the **Import / export CA certificate** button, and choose for exporting a **Certificate in DER format**. You should save it with the name: `cacert.der`.&#x20;

### Convert the Certificate

Here we change the format of the certificate to one that Android expects. Simply run the following command:

```shell-session
$ openssl x509 -inform DER -in cacert.der -out cacert.pem
```

This will create a `cacert.pem` file, from which we will need the issuer hash value. We can get this with a simple command like this:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1
</strong>9a5ba575
</code></pre>

Your hash may be different, but you simply have to append `.0` to it to get the correct filename:

```shell-session
$ mv cacert.pem 9a5ba575.0
```

### Install the Certificate on Android

{% hint style="warning" %}
Make sure to use an **API version < 29** (Android 10) to avoid issues with permissions on the `/system` folder
{% endhint %}

In this step, we need to move the certificate from our machine to the Android device. To do this, we need to set a `-writable-system` flag on the device. On Android Studio the location of the `enumator` tool is one of the following:

* Windows: `%LOCALAPPDATA%\Android\sdk\emulator\emulator.exe`
* Linux: `/usr/share/android-sdk/emulator/emulator`\
  ``    or:   `~/Android/Sdk/emulator/emulator`

Use this tool to set this flag on your device:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ emulator -list-avds
</strong>PixelXL27
<strong>$ emulator -avd PixelXL27 -writable-system
</strong></code></pre>

This will start the phone, with a writable system directory. Now we can place the created certificate there with [#adb](setup.md#adb "mention"):

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ adb root  # Start ADB daemon as root
</strong>restarting adbd as root
<strong>$ adb remount  # Remount /system to update read-only to writable
</strong>remount succeeded
</code></pre>

Now that the `/system` folder it writable, we will put the certificate in the `/system/etc/security/cacerts` folder:

```shell-session
$ adb push 9a5ba575.0 /system/etc/security/cacerts  # Copy the file onto the device
$ adb shell "chmod 664 /system/etc/security/cacerts/9a5ba575.0"  # Set the correct permissions
```

Finally, reboot the device to apply the changes:

```shell-session
$ adb reboot
```

To verify if this worked, you can start the device again in Android Studio and look at **Settings** -> **Security** -> **Trusted Credentials** which should show PortSwigger now:

![](<../.gitbook/assets/image (44) (1).png>)

### Connecting to the Proxy

Now that this is set up, you can visit the settings of the device by clicking the ![](<../.gitbook/assets/image (8).png>) three dots and visiting **Settings** -> **Proxy**. Here you can set a **Manual proxy configuration** to the hostname and port of your proxy:

<figure><img src="../.gitbook/assets/image (1) (2).png" alt=""><figcaption><p>Set the Host name and Port number to the correct values where Burp Suite is listening</p></figcaption></figure>

Finally, you can make any traffic on your emulated device and it should show up in the Burp Suite HTTP history, as well as being able to intercept and change traffic.&#x20;

{% hint style="info" %}
If your Burp Suite proxy is not on localhost, you will need to set a different Host name and also edit the Proxy Listener from its Options menu. For **Bind to address** choose **All interfaces** to allow connections from anywhere. \
In this case, also make sure that your firewall is not blocking the listening port.&#x20;
{% endhint %}
