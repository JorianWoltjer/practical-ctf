---
description: The Z3 Theorem Prover can automatically solve puzzles in Python
---

# Z3 Solver

## Description

The Z3 Theorem Prover is a Python library that can automatically solve puzzles you give it in code.&#x20;

```shell
pip install z3-solver
```

The idea is that you define Z3 variables and perform certain operations on them. Then you can add constraints to the solver and lets it fulfill those constraints. To learn using Z3 I highly suggest looking up some random puzzles and trying to solve them with Z3. There are lots of useful functions in Z3 to try out.&#x20;

One example Z3 would be good at is math equations. It can for example solve a quadratic equation like $$6x² + 11x - 35 = 0$$:

```python
from z3 import *

s = Solver()

# Define variables
x = Real('x')

# Define operations (an equation in this case)
y = 6*x**2 + 11*x - 35

# Define constraints
s.add(y == 0)
# s.add(6*x**2 + 11*x - 35 == 0)  # Also works

if s.check() == sat:  # If satisfiable
    print(s.model())  # [x = 5/3]
```

{% hint style="info" %}
Note that the operations and constraints don't need to be in a specific order. You can call `s.add()` any time to add a constraint with the current variables
{% endhint %}

{% embed url="https://z3prover.github.io/api/html/z3.z3.html" %}
Official documentation for the Python module
{% endembed %}

By default, Z3 will only try to find one solution, but you can also let it find all the solutions by just adding a constraint to say that it can't use that same solution again, and then letting it solve again:

```python
while s.check() == sat:  # While satisfiable
    m = s.model()
    print(m)  # [x = 5/3], [x = -7/2]
    s.add(x != m[x])  # Exclude this solution
```

### Variable types

* `Int(name)`: An integer value, without fractions
* `Real(name)`: A real number, with fractions
* `Bool(name)`: A boolean value, True or False
* `BitVec(name, bits)`: "Bit Vector", a collection of bits forming a number. Useful for working with bytes/integers that wrap around

{% hint style="info" %}
Almost all variable types can also be defined as multiple at once by appending an `s` to the function name. For example:

`Bools('a b c d e')`
{% endhint %}

### Functions

* `And(*args)`: All conditions in this function must be met
* `Or(*args)`: Any condition in this function must be met
* `Not(a)`: Condition inverts
* `Xor(a, b)`: Performs the Exclusive OR operation on the two values. Only one of the two can be true.&#x20;
* `LShR(n, b)`: Logical right shift (`abcd` -> `0abc`)\
  The normal `>>` operator does `abcd` -> `aabc` instead. For clarity about all these shifts see [StackOverflow](https://stackoverflow.com/a/44695162/10508498)
* `Distinct(*args)`: All values need to be different from each other

{% hint style="info" %}
The rest of the operations should be available just using the normal arithmetic operators in python, like `+`, `-`, `*`, `/` or `**`. \
Also the bitwise operators: `<<`, `>>`, `&`, `|`\
And finally, the comparison operators: `==`, `!=`, `<`, `>`, `<=`, `>=`
{% endhint %}

## Logic gates

Logic gates are used everywhere in computers. One common problem is finding out what input leads to a given output. You could try to reverse this by hand by going through the circuit backward but this is often very tedious. Luckily Z3 can do this for us.

It has support for `Bool` values that are either ON or OFF, just like a regular logic circuit. Then we can use functions like `And`, `Or`, `Not` and `Xor` to recreate the circuit in Z3, and finally, add the last output to the solver as a constraint. This way Z3 will find a value for all the input booleans that make the output true. See an example of a script that does this for the Google Beginners CTF:

{% embed url="https://github.com/JorianWoltjer/z3-scripts/blob/master/google_beginners_ctf_logic.py" %}
An example of solving a logic gate in Z3 for the Google Beginners CTF
{% endembed %}

## Solving cryptographic functions

Some bad implementations of cryptographic functions may have vulnerabilities that allow you to leak data. It might be hard to find these vulnerabilities yourself by looking at the code, so sometimes you can implement the algorithm in Z3 for it to check if it can be broken somehow.&#x20;

See the [#javascript-math.random](random-number-generators.md#javascript-math.random "mention") RNG for an example script where Z3 was used to find the random state after getting 5 random values as input, allowing you to predict future numbers.&#x20;
