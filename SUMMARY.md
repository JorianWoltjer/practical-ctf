# Table of contents

* [🚩 Home - Practical CTF](README.md)

## 🌐 Web

* [Enumeration](web/enumeration/README.md)
  * [Finding Hosts & Domains](web/enumeration/finding-hosts-and-domains.md)
  * [Masscan](web/enumeration/masscan.md)
  * [Nmap](web/enumeration/nmap.md)
  * [OSINT](web/enumeration/osint.md)
* [Client-Side](web/client-side/README.md)
  * [Cross-Site Scripting (XSS)](web/client-side/cross-site-scripting-xss/README.md)
    * [HTML Injection](web/client-side/cross-site-scripting-xss/html-injection.md)
    * [Content-Security-Policy (CSP)](web/client-side/cross-site-scripting-xss/content-security-policy-csp.md)
    * [postMessage Exploitation](web/client-side/cross-site-scripting-xss/postmessage-exploitation.md)
  * [CSS Injection](web/client-side/css-injection.md)
  * [Cross-Site Request Forgery (CSRF)](web/client-side/cross-site-request-forgery-csrf.md)
  * [XS-Leaks](https://xsleaks.dev/)
  * [Client-Side Path Traversal (CSPT)](web/client-side/client-side-path-traversal-cspt.md)
  * [CRLF / Header Injection](web/client-side/crlf-header-injection.md)
  * [Window Popup Tricks](web/client-side/window-popup-tricks.md)
  * [WebSockets](web/client-side/websockets.md)
  * [Caching](web/client-side/caching.md)
  * [Headless Browsers](web/client-side/headless-browsers.md)
* [Server-Side](web/server-side/README.md)
  * [SQL Injection](web/server-side/sql-injection.md)
  * [NoSQL Injection](web/server-side/nosql-injection.md)
  * [GraphQL](web/server-side/graphql.md)
  * [XML External Entities (XXE)](web/server-side/xml-external-entities-xxe.md)
  * [HTTP Request Smuggling](web/server-side/http-request-smuggling.md)
  * [Local File Disclosure](web/server-side/local-file-disclosure.md)
  * [Arbitrary File Write](web/server-side/arbitrary-file-write.md)
  * [Reverse Proxies](web/server-side/reverse-proxies.md)
  * [ImageMagick](web/server-side/imagemagick.md)
* [Frameworks](web/frameworks/README.md)
  * [Flask](web/frameworks/flask.md)
  * [Ruby on Rails](web/frameworks/ruby-on-rails.md)
  * [NodeJS](web/frameworks/nodejs.md)
  * [Bun](web/frameworks/bun.md)
  * [WordPress](web/frameworks/wordpress.md)
  * [Angular](web/frameworks/angular.md)

## 🔣 Cryptography

* [Encodings](cryptography/encodings.md)
* [Ciphers](cryptography/ciphers.md)
* [AES](cryptography/aes.md)
* [Asymmetric Encryption](cryptography/asymmetric-encryption/README.md)
  * [RSA](cryptography/asymmetric-encryption/rsa.md)
  * [Diffie-Hellman](cryptography/asymmetric-encryption/diffie-hellman.md)
  * [PGP / GPG](cryptography/asymmetric-encryption/pgp-gpg.md)
* [Pseudo-Random Number Generators (PRNG)](cryptography/pseudo-random-number-generators-prng.md)
* [Hashing](cryptography/hashing/README.md)
  * [Cracking Hashes](cryptography/hashing/cracking-hashes.md)
  * [Cracking Signatures](cryptography/hashing/cracking-signatures.md)
* [XOR](cryptography/xor.md)
* [Custom Ciphers](cryptography/custom-ciphers/README.md)
  * [Z3 Solver](cryptography/custom-ciphers/z3-solver.md)
* [Timing Attacks](cryptography/timing-attacks.md)
* [Blockchain](cryptography/blockchain/README.md)
  * [Smart Contracts](cryptography/blockchain/smart-contracts.md)
  * [Bitcoin addresses](cryptography/blockchain/bitcoin-addresses.md)

## 🔎 Forensics

* [Wireshark](forensics/wireshark.md)
* [File Formats](forensics/file-formats.md)
* [Archives](forensics/archives.md)
* [Memory Dumps (Volatility)](forensics/memory-dumps-volatility.md)
* [VBA Macros](forensics/vba-macros.md)
* [Grep](forensics/grep.md)
* [Git](forensics/git.md)
* [File Recovery](forensics/file-recovery.md)

## ⚙️ Reverse Engineering

* [Ghidra](reverse-engineering/ghidra.md)
* [Angr Solver](reverse-engineering/angr-solver.md)
* [Reversing C# - .NET / Unity](reverse-engineering/reversing-c-.net-unity.md)
* [PowerShell](reverse-engineering/powershell.md)

## 📟 Binary Exploitation

* [ir0nstone's Binary Exploitation Notes](https://ir0nstone.gitbook.io/notes/)
* [Reverse Engineering for Pwn](binary-exploitation/reverse-engineering-for-pwn.md)
* [PwnTools](binary-exploitation/pwntools.md)
* [ret2win](binary-exploitation/ret2win.md)
* [ret2libc](binary-exploitation/ret2libc.md)
* [Shellcode](binary-exploitation/shellcode.md)
* [Stack Canaries](binary-exploitation/stack-canaries.md)
* [Return-Oriented Programming (ROP)](binary-exploitation/return-oriented-programming-rop/README.md)
  * [SigReturn-Oriented Programming (SROP)](binary-exploitation/return-oriented-programming-rop/sigreturn-oriented-programming-srop.md)
  * [ret2dlresolve](binary-exploitation/return-oriented-programming-rop/ret2dlresolve.md)
* [Sandboxes (chroot, seccomp & namespaces)](binary-exploitation/sandboxes-chroot-seccomp-and-namespaces.md)
* [Race Conditions](binary-exploitation/race-conditions.md)

## 📲 Mobile

* [Setup](mobile/setup.md)
* [Reversing APKs](todo/mobile/reversing-apks.md)
* [Patching APKs](mobile/patching-apks.md)
* [HTTP(S) Proxy for Android](mobile/http-s-proxy-for-android.md)
* [Frida](mobile/frida.md)
* [Android Backup](mobile/android-backup.md)
* [Compiling C for Android](mobile/compiling-c-for-android.md)
* [iOS](todo/mobile/ios.md)

## 🌎 Languages

* [Python](languages/python.md)
* [JavaScript](languages/javascript/README.md)
  * [Prototype Pollution](languages/javascript/prototype-pollution.md)
* [PHP](languages/php.md)
* [Java](languages/java.md)
* [C#](languages/c.md)
* [Assembly](languages/assembly.md)
* [Markdown](languages/markdown.md)
* [LaTeX](languages/latex.md)
* [JSON](languages/json.md)
* [YAML](languages/yaml.md)
* [CodeQL](languages/codeql.md)
* [NASL (Nessus Plugins)](languages/nasl-nessus-plugins.md)
* [Regular Expressions (RegEx)](languages/regular-expressions-regex.md)

## 🤖 Networking

* [Modbus - TCP/502](networking/modbus-tcp-502.md)
* [Redis/Valkey - TCP/6379](networking/redis-valkey-tcp-6379.md)

## 🐧 Linux

* [Shells](linux/hacking-linux-boxes.md)
* [Bash](linux/bash.md)
* [Linux Privilege Escalation](linux/linux-privilege-escalation/README.md)
  * [Enumeration](linux/linux-privilege-escalation/enumeration.md)
  * [Networking](linux/linux-privilege-escalation/networking.md)
  * [Command Triggers](linux/linux-privilege-escalation/command-triggers.md)
  * [Command Exploitation](linux/linux-privilege-escalation/command-exploitation.md)
  * [Outdated Versions](linux/linux-privilege-escalation/outdated-versions.md)
  * [Network File Sharing (NFS)](linux/linux-privilege-escalation/network-file-sharing-nfs.md)
  * [Docker](linux/linux-privilege-escalation/docker.md)
  * [Filesystem Permissions](linux/linux-privilege-escalation/filesystem-permissions.md)
* [Analyzing Processes](linux/analyzing-processes.md)

## 🪟 Windows

* [The Hacker Recipes - AD](https://www.thehacker.recipes/)
* [Scanning/Spraying](windows/scanning-spraying.md)
* [Exploitation](windows/exploitation.md)
* [Local Enumeration](windows/local-enumeration.md)
* [Local Privilege Escalation](windows/local-privilege-escalation.md)
* [Windows Authentication](windows/windows-authentication/README.md)
  * [Kerberos](windows/windows-authentication/kerberos.md)
  * [NTLM](windows/windows-authentication/ntlm.md)
* [Lateral Movement](windows/lateral-movement.md)
* [Active Directory Privilege Escalation](windows/active-directory-privilege-escalation.md)
* [Persistence](windows/persistence.md)
* [Antivirus Evasion](windows/antivirus-evasion.md)
* [Metasploit](windows/metasploit.md)
* [Alternate Data Streams (ADS)](windows/alternate-data-streams-ads.md)

## ☁️ Cloud

* [Kubernetes](cloud/kubernetes.md)
* [Microsoft Azure](cloud/microsoft-azure.md)

## ❔ Other

* [Business Logic Errors](other/business-logic-errors.md)
* [Password Managers](other/password-managers.md)
* [ANSI Escape Codes](other/ansi-escape-codes.md)
* [WSL Tips](other/wsl-tips.md)
