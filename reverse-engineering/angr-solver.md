---
description: A binary analysis tool in Python to automatically find paths to code
---

# Angr Solver

[Angr](https://github.com/angr/angr) is really useful for quickly solving some Reverse Engineering challenges. The most useful function allows you to define an address in a Linux binary, and it will run the binary with different inputs to slowly make progress toward that goal.&#x20;

For a CTF challenge, you could point the goal to be after some if statements that you would otherwise have to reverse engineer. Then Angr will find a valid input that gets to the code after the if statements, solving the challenge for you.&#x20;

{% embed url="https://flagbot.ch/material/#lesson-5-constraint-solving-and-symbolic-execution-13-april-2020" %}
A presentation about Z3 and Angr that shows practical code
{% endembed %}

## Template

This template lets Angr do the magic to solve it automatically without much effort, but for more advanced examples see [their documentation](https://docs.angr.io/examples).&#x20;

```python
import angr

# Change this binary
project = angr.Project("./binary", auto_load_libs=False)

@project.hook(0x401337)  # Change this address to your target
def print_flag(state):
    print("Valid input:", state.posix.dumps(0))
    project.terminate_execution()

project.execute()
```

### Examples

When you can and can't use Angr is something you just need to get a feel for, by trying it sometimes and seeing if it works. In most cases, you're looking for some check on an input you're giving, and finding how to get past that if statement is a tedious process. Here are some examples of decompiled code where Angr could be used:

{% code title="Example 1" %}
```c
undefined8 main(void) {
  uint uVar1;
  int local_10;
  int local_c;
  
  printf("Enter the flag: ");
  __isoc99_scanf(&DAT_00102015,buf);
  for (local_c = 0; local_c < 0x1d; local_c = local_c + 1) {
    uVar1 = (uint)(local_c >> 0x1f) >> 0x1e;
    buf[local_c] = buf[local_c] ^
                   *(byte *)((long)&magic + (long)(int)((local_c + uVar1 & 3) - uVar1));
  }
  local_10 = 0;
  while( true ) {
    if (0x1c < local_10) {  // Hard if statement (computation in the for() loop above)
      puts("Correct flag!");
      // <--- TARGET Angr right here
      // Ghidra shows 0x00101231, and starts by default at 0x00100000, meaning
      // we're only 0x1231 into the binary. When Angr runs a program with PIE enabled,
      // it starts at 0x00400000. So the final address we target is 0x00401231
      return 0;
    }
    if (buf[local_10] != flag[local_10]) break;
    local_10 = local_10 + 1;
  }
  puts("Wrong flag!");
  return 0;
}
```
{% endcode %}

{% code title="Example 2" %}
```c
undefined8 validatePassword(byte *param_1) {
  size_t sVar1;
  undefined8 uVar2;
  
  sVar1 = strlen((char *)param_1);
  // Hard if statement:
  if ((((((sVar1 == 0x21) && (*param_1 == (byte)(param_1[6] * '\x02' - 0x1d))) &&
        (param_1[1] == (byte)(param_1[0x13] + 5))) &&
       (((param_1[2] == (byte)(((char)param_1[8] >> 1) + 0x13U) &&
         (param_1[3] == (byte)(param_1[0xf] + 0x35))) &&
        ((param_1[4] == (byte)(param_1[3] + 0xbc) &&
         ((param_1[5] == (byte)(param_1[0x11] + 0x28) && (param_1[6] == (char)param_1[0x16] >> 1))))
        )))) && (param_1[7] == (param_1[0xb] ^ param_1[0x15]))) &&
     (((((((param_1[8] == (param_1[5] ^ 7) && (param_1[9] == (byte)(param_1[0xe] - 0x21))) &&
          (param_1[10] == (byte)(param_1[0x1e] + 7))) &&
         ((param_1[0xb] == (byte)(param_1[0x10] * '\x02') &&
          (param_1[0xc] == (byte)(param_1[0x1d] + param_1[9]))))) && (param_1[0xd] == 0x31)) &&
       ((((param_1[0xe] == (byte)(param_1[0x1d] * '\x02' + 3) && (param_1[0xf] == (*param_1 ^ 5)))
         && (((param_1[0x10] == (byte)(((char)param_1[0x12] >> 1) * '\x02') &&
              (((param_1[0x11] == (param_1[0x14] ^ 0x40) && (param_1[0x12] == (param_1[0x17] ^ 10)))
               && (param_1[0x13] == (byte)(param_1[7] - 2))))) &&
             (((param_1[0x14] == (param_1[10] ^ param_1[0x1c]) &&
               (param_1[0x15] == (char)param_1[0x19] >> 1)) &&
              (param_1[0x16] == (byte)((param_1[0x1f] | 0x61) - 2))))))) &&
        ((param_1[0x17] == 0x39 && (param_1[0x18] == (byte)(param_1[0x12] * '\x02'))))))) &&
      (((param_1[0x19] == (byte)(param_1[0x10] + param_1[0x1a]) &&
        (((param_1[0x1a] == (byte)((char)param_1[0xb] / '\x02' + 7U) &&
          (param_1[0x1b] == (byte)((param_1[4] + 0x7b) * '\x02'))) &&
         (param_1[0x1c] == (byte)(param_1[1] - 0x13))))) &&
       (((param_1[0x1d] == (byte)(param_1[0x20] + 0xb3) &&
         (param_1[0x1e] == (byte)(param_1[0x1f] - param_1[0x10]))) &&
        ((param_1[0x1f] == (byte)(param_1[0xd] * '\x02' + 1) &&
         (param_1[0x20] == (byte)(param_1[4] + param_1[0xf]))))))))))) {
    uVar2 = 1;  // <--- TARGET Angr here, right after the if statement when
                // validatePassword() returns 1
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}
```
{% endcode %}

{% file src="../.gitbook/assets/solve_with_angr.py" %}
Another example of the [CrackThePassword](https://ctftime.org/task/23067) challenge solved with Angr
{% endfile %}

One more writeup of a reversing challenge that was easily solved using Angr:

{% embed url="https://jorianwoltjer.com/blog/post/ctf/cyber-apocalypse-2023/cave-system" %}
