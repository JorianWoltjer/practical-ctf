---
description: A cheatsheet on various color codes and syntax
---

# Color Codes

## ANSI Escape Code

Terminals use so-called "ASNI escape sequences" to format text, including colors. They are special sequences of characters that when printed, will alter the text that comes after it.&#x20;

These codes always start with an ESC character, `\x1b` in ASCII. Then for **colors**, you use a `[`, followed by some special code, and finally an `m` character. This special code in between determines what color is displayed.

* `30`-`37` (normal) & `90`-`97` (bright): Foreground color
* `40`-`47` (normal) & `100`-`107` (bright): Background color
* `0`: Reset

See the following table for a list of all these colors:

{% embed url="https://en.wikipedia.org/wiki/ANSI_escape_code#3-bit_and_4-bit" %}
3-bit and 4-bit color codes
{% endembed %}

To use a color like this, put it in the ESC code syntax with the correct number. You can also provide a foreground number as well as a background number, by separating them with a `;` semicolon (order doesn't matter). Here are a few examples:

* ![](<../.gitbook/assets/image (7).png>): `\x1b[31mRed` (31 = Foreground red)
* ![](<../.gitbook/assets/image (4).png>): `\x1b[44mBlue` (44 = Background blue)
* ![](../.gitbook/assets/image.png): `\x1b[42;30mGreen` (42 = Background green, 30 = Foreground black)
* ![](<../.gitbook/assets/image (29).png>): `\x1b[31mred \x1b[0mreset` (0 = Reset)

As seen in the ![](<../.gitbook/assets/image (29).png>)example, you can specify multiple color codes and it will switch as soon as the color code happens.&#x20;

### Programming

To use these color codes in any program or script, you just have to print the right characters to the terminal. One difficulty might be the unreadable ESC character, previously represented as `\x1b`. This character cannot be typed with a keyboard like normal characters and must be scaped in Hex, Unicode, or whatever your language best supports.&#x20;

{% code title="Bash" %}
```shell-session
$ echo -e '\x1b[31mRed\x1b[0m'
```
{% endcode %}

{% code title="Python" %}
```python
print("\x1b[31mRed\x1b[0m")
```
{% endcode %}

{% hint style="info" %}
**Tip**: If you want to use colors in Python, use the [colorama](https://pypi.org/project/colorama/) library. It provides clear names for each color to make the code much more readable.&#x20;
{% endhint %}

## Minecraft

![](<../.gitbook/assets/image (1).png>)   [https://minecraft.fandom.com/wiki/Formatting\_codes](https://minecraft.fandom.com/wiki/Formatting\_codes)

### Normal text

In the chat, color codes are created using the `§` paragraph sign, followed by a number/letter. In the colors above, you can see that bright red is the letter `c` for example. This means that if you want a red message with this color, you need to prefix it with `§c` similar to ANSI escape codes. So `§cred` would produce red text saying "red".

`§r` is useful for resetting the color back to normal after some colored text.&#x20;

### Unicode escape

For JSON text like server's MOTDs, you need to escape the [`§`](https://www.fileformat.info/info/unicode/char/00a7/index.htm) paragraph sign with Unicode, like `\u00a7`. Then you can use the color numbers/letters again, so `\u00a7cred` would produce red text saying "red".&#x20;
