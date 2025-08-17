---
description: Intercept traffic going from and to an emulated Android device with Burp Suite
---

# HTTP(S) Proxy for Android

When you have an Android emulator set up in Android Studio, you can change some settings to be able to intercept traffic in a Proxy like Burp Suite. This can be really useful when you want to view or test web functionality that an app uses, as this might reveal interesting vulnerabilities because developers might not expect the app to be reverse-engineered in this way.

One tool we'll use throughout this process is [#adb](setup.md#adb "mention"). Make sure you're inside Android Studio to be able to use it, or find its absolute path.

## Configure the Proxy

Every time you start your device and want to intercept its traffic, you should set up the proxy configuration so that all traffic gets sent through your Burp Suite instance.

Below are 2 methods of doing this, either through the CLI (easiest) or through the GUI.

### ADB

To make connecting to your local IP easy, we will set up a reverse port forward from the device's 8080 to your 8080. This way, we can target `127.0.0.1` on the device in the future, and this will send it over to your host system for Burp Suite to intercept.

```bash
adb reverse tcp:8080 tcp:8080
```

Next, The following two commands configure the device to send _all_ traffic through this port.

```bash
adb shell settings put global http_proxy 127.0.0.1:8080
adb shell settings put global https_proxy 127.0.0.1:8080
```

Of course, you should have [Burp Suite](https://portswigger.net/burp) running on your host system at this point and can see HTTP requests coming in, although HTTPS websites will likely still cause certificate errors. See [#install-certificate-authority-https](http-s-proxy-for-android.md#install-certificate-authority-https "mention") for a guide on how to fix this.

### GUI

In case you want to rather configure the proxy via the GUI, you can use the `emulator`'s display to do so. First start your device with the following command (use `emulator -list-avds` to get the names):

```
emulator -avd Pixel_6_Pro_API_34
```

On the right you should see a bar of options and ![](<../.gitbook/assets/image (8) (2).png>) three dots for more options. Click it and visit **Settings** -> **Proxy**. Here you can set a **Manual proxy configuration** to the IP address and port of your proxy. You will likely need to configure an external address because localhost points to the device itself, not your host.

<figure><img src="../.gitbook/assets/image (1) (2) (2).png" alt=""><figcaption><p>Set the Host name and Port number to the correct values where Burp Suite is listening</p></figcaption></figure>

You can now easily test if it works by opening the Chrome app and visiting http(s) websites like [http://example.com/](http://example.com/) and [https://example.com/](https://example.com/).

{% hint style="warning" %}
**Tip**: If your Burp Suite proxy is not on localhost (127.0.0.1), you will need to set a different Host name and also edit the Proxy Listener from its Options menu. For **Bind to address** choose **All interfaces** to allow connections from anywhere. \
In this case, also make sure that your firewall is not blocking the listening port.&#x20;
{% endhint %}

## Install Certificate Authority (HTTPS)

To get rid of certificate errors caused by Burp Suite intercepting HTTPS requests, you must tell the Android device to trust its custom certificate authority.

This describes 2 methods which should both work, but one may be easier than the other depending on your setup. If possible, start with the manual approach because it should work on all types of devices.

### Manual via Settings

With the [#configure-the-proxy](http-s-proxy-for-android.md#configure-the-proxy "mention") steps taken, you should be able to visit [http://burp](http://burp/) on your device and end up on Burp Suite's configuration page.

<figure><img src="../.gitbook/assets/image.png" alt="" width="290"><figcaption><p>Downloading certificate file on device</p></figcaption></figure>

Click the _CA Certificate_ button on the top right and download it to some location on the device.\
Then, go into your settings and look for "Certificate", you should find some option to install a CA certificate as in the screenshot below.

<figure><img src="../.gitbook/assets/image (1).png" alt="" width="291"><figcaption><p>Searching for "certificate" in Settings</p></figcaption></figure>

On this Android version, you have to press _Install Anyway_ to start selecting a certificate file from your _Downloads_. Choose the `cacert.der` file from Burp Suite.\
If everything went successfully, you should receive a small message saying "CA certificate installed".

You can now visit HTTPS websites in your browser, and then should be visible in Burp Suite without any certificate errors. Some apps however will still be able to detect the tampering with certificates and possibly not allow you to use them, this is where [#ssl-pinning](http-s-proxy-for-android.md#ssl-pinning "mention") comes in.

### CLI via ADB

{% embed url="https://secabit.medium.com/how-to-configure-burp-proxy-with-an-android-emulator-31b483237053" %}
Tutorial on installing a certificate manually on the device's filesystem
{% endembed %}

You should first download the certificate from Burp Suite via its GUI. Go to **Proxy** -> **Options**, then click the **Import/export CA certificate** button, and choose for exporting a **Certificate in DER format**. You should save it with the name: `cacert.der`.

Next, we need to convert it to the PEM format that Android expects:

```bash
openssl x509 -inform DER -in cacert.der -out cacert.pem
```

We need to also give it a correct name consisting of the "issuer hash", which can be found like this:

<pre class="language-bash"><code class="lang-bash"><strong>openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1
</strong>9a5ba575
</code></pre>

Your hash may be different, but you simply have to append `.0` to it to get your final filename:

```bash
mv cacert.pem 9a5ba575.0
```

{% hint style="warning" %}
This part was tested in **API version <= 28** (Android 10) to avoid issues with permissions on the `/system` folder. Your success may vary.
{% endhint %}

We need to move the certificate from our host to the Android device. To do this, we need to set a `-writable-system` flag on the device with the `emulator` tool. Check out [#adb](setup.md#adb "mention") for more information about how to access this binary.

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ emulator -list-avds
</strong>PixelXL27
<strong>$ emulator -avd PixelXL27 -writable-system
</strong></code></pre>

Next we need to mount the directory as writable so that we can copy files into it:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ adb root  # Start ADB daemon as root
</strong>restarting adbd as root
<strong>$ adb remount  # Remount /system to update read-only to writable
</strong>remount succeeded
</code></pre>

Finally, `push` the file into `/system/etc/security/cacerts` and give it the correct permissions (664):

```bash
adb push 9a5ba575.0 /system/etc/security/cacerts  # Copy the file onto the device
adb shell "chmod 664 /system/etc/security/cacerts/9a5ba575.0"  # Set the correct permissions
```

Then reboot the device to apply the changes (permanently):

```bash
adb reboot
```

To verify if this worked, you can start the device again in Android Studio and look at **Settings** -> **Security** -> **Trusted Credentials** which should show "PortSwigger" now:

![](<../.gitbook/assets/image (44).png>)
