---
description: Recovering content of deleted files
---

# File Recovery

Find disks using `mount` and looking for `sd[a-z]`:

```shell-session
$ mount
/dev/sdb on / type ext4 (rw,relatime,discard,errors=remount-ro,data=ordered)
...
```

Then grep for any known text:

```shell-session
$ sudo grep -a -C 200 -F 'Insert text here' /dev/sdb | tee /tmp/recover
```

This will output a lot of garbage as well, so you can then filter on ASCII lines only:

```shell-session
$ grep --color=never -aoP '^[[:ascii:]]*$' /tmp/recover
```
