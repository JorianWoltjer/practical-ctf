# Table of contents

* [🚩 Home - Practical CTF](README.md)

## 🌐 Web

* [Enumeration](web/enumeration/README.md)
  * [Finding Hosts & Domains](web/enumeration/finding-hosts-and-domains.md)
  * [Masscan](web/enumeration/masscan.md)
  * [Nmap](web/enumeration/nmap.md)
* [Cross-Site Scripting (XSS)](web/cross-site-scripting-xss.md)
* [Cross-Site Request Forgery (CSRF)](web/cross-site-request-forgery-csrf.md)
* [XS-Leaks](https://xsleaks.dev/)
* [SQL Injection](web/sql-injection.md)
* [NoSQL Injection](web/nosql-injection.md)
* [Header / CRLF Injection](web/header-crlf-injection.md)
* [HTTP Request Smuggling](web/http-request-smuggling.md)
* [Local File Disclosure](web/local-file-disclosure.md)
* [Chrome Remote DevTools](web/chrome-remote-devtools.md)
* [XML External Entities (XXE)](web/xml-external-entities-xxe.md)
* [ImageMagick](web/imagemagick.md)

## 🔣 Cryptography

* [Encodings](cryptography/encodings.md)
* [Ciphers](cryptography/ciphers.md)
* [Custom Ciphers](cryptography/custom-ciphers/README.md)
  * [Z3 Solver](cryptography/custom-ciphers/z3-solver.md)
* [XOR](cryptography/xor.md)
* [Asymmetric Encryption](cryptography/asymmetric-encryption/README.md)
  * [RSA](cryptography/asymmetric-encryption/rsa.md)
  * [Diffie-Hellman](cryptography/asymmetric-encryption/diffie-hellman.md)
  * [PGP / GPG](cryptography/asymmetric-encryption/pgp-gpg.md)
* [AES](cryptography/aes.md)
* [Hashing](cryptography/hashing/README.md)
  * [Cracking Hashes](cryptography/hashing/cracking-hashes.md)
  * [Cracking Signatures](cryptography/hashing/cracking-signatures.md)
* [Pseudo-Random Number Generators (PRNG)](cryptography/pseudo-random-number-generators-prng.md)
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
* [Android Backup](mobile/android-backup.md)
* [Compiling C for Android](mobile/compiling-c-for-android.md)
* [iOS](todo/mobile/ios.md)

## 🌎 Languages

* [Web Frameworks](languages/web-frameworks/README.md)
  * [Flask](languages/web-frameworks/flask.md)
  * [Ruby on Rails](languages/web-frameworks/ruby-on-rails.md)
  * [NodeJS](languages/web-frameworks/nodejs.md)
  * [WordPress](languages/web-frameworks/wordpress.md)
* [PHP](languages/php.md)
* [Python](languages/python.md)
* [JavaScript](languages/javascript.md)
* [Java](languages/java.md)
* [Assembly](languages/assembly.md)
* [Markdown](languages/markdown.md)
* [LaTeX](languages/latex.md)
* [JSON](languages/json.md)
* [YAML](languages/yaml.md)
* [CodeQL](languages/codeql.md)
* [Regular Expressions (RegEx)](languages/regular-expressions-regex.md)

## 🤖 Networking

* [Modbus - TCP/502](networking/modbus-tcp-502.md)
* [Redis - TCP/6379](networking/redis-tcp-6379.md)

## 🐧 Linux

* [Shells](linux/hacking-linux-boxes.md)
* [Bash](linux/bash.md)
* [Linux Privilege Escalation](linux/linux-privilege-escalation/README.md)
  * [Enumeration](linux/linux-privilege-escalation/enumeration.md)
  * [Networking](linux/linux-privilege-escalation/networking.md)
  * [Command Triggers](linux/linux-privilege-escalation/command-triggers.md)
  * [Command Exploitation](linux/linux-privilege-escalation/command-exploitation.md)
  * [Network File Sharing (NFS)](linux/linux-privilege-escalation/network-file-sharing-nfs.md)
  * [Outdated Versions](linux/linux-privilege-escalation/outdated-versions.md)
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
* [OSINT](other/osint/README.md)
* [Password Managers](other/password-managers.md)
* [WSL Guide](other/wsl-guide.md)
* [ANSI Escape Codes](other/ansi-escape-codes.md)

## 🔨 \[TODO]

* [iframes](todo/iframes/README.md)
  * [postMessage()](todo/iframes/postmessage.md)
  * [Clickjacking](todo/iframes/clickjacking.md)
* [Java Reverse Engineering](todo/java-reverse-engineering.md)
* [Format Strings](todo/format-strings.md)
* [Windows Privilege Escalation](todo/windows-privilege-escalation.md)
* [Amazon AWS](todo/amazon-aws.md)
