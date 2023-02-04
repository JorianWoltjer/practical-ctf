---
description: Setting up an Android testing environment
---

# Setup

## Android Studio

When you get an APK file, this is an Android app. But luckily, you don't necessarily need a physical Android device to test it on, we can use an emulator on a computer!

It starts by installing an emulator. The most popular one and the one I will be using throughout this page is the free Android Studio:

{% embed url="https://developer.android.com/studio" %}
A big and powerful program for developing and testing Android apps
{% endembed %}

## Virtual Devices

When Android Studio is installed, you should create an Android Virtual Device. From the "Welcome" menu you can go to **Configure** -> **AVD Manager**. Otherwise, go to **Tools** -> **AVD Manager**. In this table, you can see all your virtual devices. If you do not have one yet, you should create one with the **Create Virtual Device** button in the bottom-left corner.&#x20;

In the Configuration menu that pops up, you can select any hardware you would like the device to mimic. Most of the difference is just the screen resolution, but one important note is that you should **not use** ![](../.gitbook/assets/image.png) Play Store devices, as this will restrict some settings we'll do later on.&#x20;

On the next screen, you can select a System Image. This is important for apps, as some APKs only support certain Android versions. I recommend at least one device with Android 8.1 (API 27) because it is fairly new, and still allows you to Proxy traffic later on. \
In some cases, the app will require a higher version though, so then you can simply create a new device with a higher API to run the app on.&#x20;

After the device is created, you will be able to use it in the future to run emulated apps on.&#x20;

## Tools

Some must-have tools to make analyzing APK files easier.&#x20;

### APKTool

{% embed url="https://ibotpeaches.github.io/Apktool/" %}
A decompiing and building tool for reverse engineering APKs
{% endembed %}

### ADB

**A**ndroid **D**e**b**ugger (ADB) is a tool that comes with Android Studio, which allows you to get more from the emulated device, such as a shell to explore the file system or change certain settings. After installing Android Studio, it may be found in the following locations:

* Windows: `%LOCALAPPDATA%\Android\sdk\platform-tools\adb.exe`
* Linux: `/usr/share/android-sdk/platform-tools/adb`\
  ``    or:   `~/Android/Sdk/platform-tools/adb`
