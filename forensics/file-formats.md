---
description: What to do with a file you don't understand
---

# File formats

## Understanding common file formats

If you want to understand how a file format works, you should look at documentation online about it. Often these formats are not ASCII readable so you'll want to use a hex editor, such as `xxd`, `hexedit` or [hexyl](https://github.com/sharkdp/hexyl).&#x20;

A big collection of file format made by Ange Albertini is the following (just scroll though until you find your format):

{% embed url="https://github.com/corkami/pics/blob/master/binary/README.md" %}
A big collection of drawings of file formats to understand them quickly
{% endembed %}

## Binwalk

Sometimes when data tries to be hidden inside of another file, it is just pasted right into the host file. Meaning that the bytes of the secret file are just somewhere in the other file. Using [binwalk](https://github.com/ReFirmLabs/binwalk) you can check for known file signatures in a file to see if it embeds something. \
Using the following command you can also recursively extract all of these into a `.extracted` folder:

```shell-session
$ binwalk -eM file.bin
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             TRX firmware header, little endian, image size: 37883904 bytes, CRC32: 0x95C5DF32, flags: 0x1, version: 1, header size: 28 bytes, loader offset: 0x1C, linux kernel offset: 0x0, rootfs offset: 0x0
28            0x1C            uImage header, header size: 64 bytes, header CRC: 0x780C2742, created: 2018-10-10 02:12:20, image size: 2150281 bytes, Data Address: 0x8000, Entry Point: 0x8000, data CRC: 0xA097CFEA, OS: Linux, CPU: ARM, image type: OS Kernel Image, compression type: none, image name: "DD-WRT"
92            0x5C            Linux kernel ARM boot executable zImage (little-endian)
2460          0x99C           device tree image (dtb)
23432         0x5B88          xz compressed data
23776         0x5CE0          xz compressed data
2117484       0x204F6C        device tree image (dtb)
3145756       0x30001C        UBI erase count header, version: 1, EC: 0x0, VID header offset: 0x800, data offset: 0x1000

$ binwalk --dd='.*' file.bin  # Another way to extract all file signatures
```

{% hint style="warning" %}
A common false positive with PNGs is `Zlib compressed data`. This is because PNG uses Zlib for compression in its own file format, so it is recognized by binwalk. But very often this compressed data just covers the entire file
{% endhint %}

You can also use binwalk to understand an unknown file better, by looking at the **entropy** for example. Entropy is how random a certain sequence of bytes is. Simple ASCII text is pretty predicable and stays within about the same range, so the entropy would be low. But for completely random/encrypted bytes the entropy should be really high, close to 1. You can get a graph of the entropy of the file using the `-E` flag:

```shell-session
$ binwalk -E file.bin
```

<figure><img src="../.gitbook/assets/image (42).png" alt=""><figcaption><p>An example of a firmware image showing various amounts of entropy (<a href="https://allabouttesting.org/short-tutorial-firmware-analysis-tool-binwalk/">source</a>)</p></figcaption></figure>

This can give a good idea about what parts of a file you could look at.&#x20;

## PNG

Image files like PNG can have a lot of hidden info. It's a relatively complex file format with a lot of room for secrets.&#x20;

A quick check you can do to see if it is a completely valid PNG file is using [pngcheck](http://www.libpng.org/pub/png/apps/pngcheck.html):

```shell-session
$ pngcheck -h
Test PNG, JNG or MNG image files for corruption, and print size/type info.

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

$ pngcheck image.png
OK: image.png (1920x1080, 32-bit RGB+alpha, non-interlaced, 96.6%).
```

PNG files consist of **chunks** of bytes that tell something about the image. The most common one is `IDAT` which contains the pixel data of the image. An image always ends with `IEND` and 4 checksum bytes (every chunk has the checksum).&#x20;

You might see custom chunks being used to embed data, or data appended to the end, after `IEND`.&#x20;
