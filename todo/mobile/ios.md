---
description: Reverse Engineering iOS applications in .app format
---

# iOS

iOS apps are not as easily reverse-engineered as most Android apps, because they are compiled into a binary. When you run the `file` command on the binary, you should see Mach-O which confirms this is an iOS application:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ file app
</strong>app: Mach-O 64-bit x86_64 executable, flags:&#x3C;NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>
</code></pre>

## Decompiling

To reverse engineer this binary, it is basically the same procedure as reversing any other ELF binary for example. You can use a decompiler to get some insight into the code structure, and what functions are called.&#x20;

There is a lot of source code from built-in Apple functions, so **searching for function names** is often a good idea to understand what it is doing, instead of guessing or reversing by hand. For example, the `CCCrypt()` function has the following arguments ([source](https://opensource.apple.com/source/CommonCrypto/CommonCrypto-36064/CommonCrypto/CommonCryptor.h)):

```c
CCCryptorStatus CCCrypt(
	CCOperation op,			/* kCCEncrypt, etc. */
	CCAlgorithm alg,		/* kCCAlgorithmAES128, etc. */
	CCOptions options,		/* kCCOptionPKCS7Padding, etc. */
	const void *key,
	size_t keyLength,
	const void *iv,			/* optional initialization vector */
	const void *dataIn,		/* optional per op and alg */
	size_t dataInLength,
	void *dataOut,			/* data RETURNED here */
	size_t dataOutAvailable,
	size_t *dataOutMoved);
```

In addition to this, `enum`s are also useful to know, as the numbers in the decompiled code might not explain what it really means:

```c
/*!
	@enum		CCOptions
	@abstract	Options flags, passed to CCCryptorCreate().
	
	@constant	kCCOptionPKCS7Padding	Perform PKCS7 padding. 
	@constant	kCCOptionECBMode	Electronic Code Book Mode (default is CBC)
*/
enum {
	/* options for block ciphers */
	kCCOptionPKCS7Padding	= 0x0001,
	kCCOptionECBMode	= 0x0002
};
```

## `.plist` files

you might find `.plist` files in the `.app` directory. These files are in a special format but can be parsed by tools such as `plistutil` into XML files:

```shell-session
$ file app.plist 
app.plist: Apple binary property list
$ plistutil -i app.plist
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
        <dict>
                <key>secret</key>
                <string>ExampleSecret</string>
                <key>id</key>
                <string>42</string>
                <key>title</key>
                <string>Some Title</string>
        </dict>
</array>
</plist>
```

## Resources

For another more practical guide and example, see this article:

{% embed url="https://github.com/OWASP/owasp-mastg/blob/master/Document/0x06c-Reverse-Engineering-and-Tampering.md" %}
A walkthrough of various tasks in iOS reverse engineering
{% endembed %}
