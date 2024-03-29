---
description: A few cheatsheet-like things about the Assembly language
---

# Assembly

## Registers

Generally, `r`-prefixed registers are 64-bit, `e`-prefixed registers are 32-bit, non-prefixed registers are 16-bit, and `l`-suffixed registers are 8-bit. For `r8-15` see the special cases below ([source](https://stackoverflow.com/a/20637866/10508498)):

<table><thead><tr><th width="203">64-bit register</th><th width="192">Lower 32 bits</th><th width="190">Lower 16 bits</th><th>Lower 8 bits</th></tr></thead><tbody><tr><td><code>rax</code></td><td><code>eax</code></td><td><code>ax</code></td><td><code>al</code></td></tr><tr><td><code>rbx</code></td><td><code>ebx</code></td><td><code>bx</code></td><td><code>bl</code></td></tr><tr><td><code>rcx</code></td><td><code>ecx</code></td><td><code>cx</code></td><td><code>cl</code></td></tr><tr><td><code>rdx</code></td><td><code>edx</code></td><td><code>dx</code></td><td><code>dl</code></td></tr><tr><td><code>rsi</code></td><td><code>esi</code></td><td><code>si</code></td><td><code>sil</code></td></tr><tr><td><code>rdi</code></td><td><code>edi</code></td><td><code>di</code></td><td><code>dil</code></td></tr><tr><td><code>rbp</code></td><td><code>ebp</code></td><td><code>bp</code></td><td><code>bpl</code></td></tr><tr><td><code>rsp</code></td><td><code>esp</code></td><td><code>sp</code></td><td><code>spl</code></td></tr><tr><td><code>r8</code></td><td><code>r8d</code></td><td><code>r8w</code></td><td><code>r8b</code> (<code>r8l</code>)</td></tr><tr><td><code>r9</code></td><td><code>r9d</code></td><td><code>r9w</code></td><td><code>r9b</code> (<code>r9l</code>)</td></tr><tr><td><code>r10</code></td><td><code>r10d</code></td><td><code>r10w</code></td><td><code>r10b</code> (<code>r10l</code>)</td></tr><tr><td><code>r11</code></td><td><code>r11d</code></td><td><code>r11w</code></td><td><code>r11b</code> (<code>r11l</code>)</td></tr><tr><td><code>r12</code></td><td><code>r12d</code></td><td><code>r12w</code></td><td><code>r12b</code> (<code>r12l</code>)</td></tr><tr><td><code>r13</code></td><td><code>r13d</code></td><td><code>r13w</code></td><td><code>r13b</code> (<code>r13l</code>)</td></tr><tr><td><code>r14</code></td><td><code>r14d</code></td><td><code>r14w</code></td><td><code>r14b</code> (<code>r14l</code>)</td></tr><tr><td><code>r15</code></td><td><code>r15d</code></td><td><code>r15w</code></td><td><code>r15b</code> (<code>r15l</code>)</td></tr></tbody></table>

See [shellcode.md](../binary-exploitation/shellcode.md "mention") for writing malicious Assembly code and some examples of compiling
