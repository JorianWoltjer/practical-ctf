# Capabilities

A different way administrators can give more privileges to a program is through capabilities. Especially the `cap_setuid` is very interesting because similar to the [suid.md](suid.md "mention") bit, it executes a program as another user.&#x20;

## Finding capabilities

To get all your capabilities as a user, use the `getcap` command. It will give a lot of errors, so just redirect them to `null` to get a clean output. Note that this command can take a bit because it looks through the whole system. &#x20;

```shell
getcap -r / 2>/dev/null
```

To only get `setuid` capabilities you can filter it with `grep`:

```bash
getcap -r / 2>/dev/null | grep cap_setuid
```

## Exploiting capabilities

After finding binaries with special capabilities, you can look them up on [GTFOBins](https://gtfobins.github.io/#+capabilities) to see if they are exploitable:

{% embed url="https://gtfobins.github.io/#+capabilities" %}
GTFOBins, a searchable list of exploitable binaries
{% endembed %}

Then just use a command you find there to get higher privileges.&#x20;

Since the `cap_setuid` capability is basically the same as the [suid.md](suid.md "mention") bit, you can use the same ideas from there.&#x20;
