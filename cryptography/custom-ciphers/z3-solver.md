---
description: The Z3 Theorem Prover can automatically solve puzzles in Python
---

# Z3 Solver

## Description

The Z3 Theorem Prover is a Python library that can automatically solve puzzles you give it in code.&#x20;

```shell-session
$ pip install z3-solver
```

The idea is that you define Z3 variables and perform certain operations on them. Then you can add constraints to the solver and lets it fulfill those constraints. To learn using Z3 I highly suggest looking up some random puzzles and trying to solve them with Z3. There are lots of useful functions in Z3 to try out.&#x20;

One example Z3 would be good at is math equations. It can for example solve a quadratic equation like $$6x² + 11x - 35 = 0$$:

<pre class="language-python"><code class="lang-python">from z3 import *

s = Solver()

# Define variables
<strong>x = Real('x')
</strong>
# Define operations (an equation in this case)
<strong>y = 6*x**2 + 11*x - 35
</strong>
# Define constraints
<strong>s.add(y == 0)
</strong># s.add(6*x**2 + 11*x - 35 == 0)  # Also works

if s.check() == sat:  # If satisfiable
    print(s.model())  # [x = 5/3]
</code></pre>

{% hint style="info" %}
Note that the operations and constraints don't need to be in a specific order. You can call `s.add()` any time to add a constraint with the current variables
{% endhint %}

{% embed url="https://z3prover.github.io/api/html/z3.z3.html" %}
Official documentation for the Python module
{% endembed %}

{% embed url="https://ericpony.github.io/z3py-tutorial/guide-examples.htm" %}
Guide on using Z3 for practical problems
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
* `BitVec(name, bits)`: "Bit Vector", a collection of bits forming a number. Useful for working with bytes/integers that wrap around. See [#bitwise-operations](z3-solver.md#bitwise-operations "mention") for details

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

### Logic gates

Logic gates are used everywhere in computers. One common problem is finding out what input leads to a given output. You could try to reverse this by hand by going through the circuit backwards but this is often very tedious. Luckily Z3 can do this for us.

It has support for `Bool` values that are either ON or OFF, just like a regular logic circuit. Then we can use functions like `And`, `Or`, `Not` and `Xor` to recreate the circuit in Z3, and finally, add the last output to the solver as a constraint. This way Z3 will find a value for all the input booleans that make the output true. See an example of a script that does this for the Google Beginners CTF:

{% embed url="https://github.com/JorianWoltjer/z3-scripts/blob/master/google_beginners_ctf_logic.py" %}
An example of solving a logic gate in Z3 for the Google Beginners CTF
{% endembed %}

### Bitwise Operations

When reverse engineering a low-level cryptographic algorithm you're often looking at bitwise operations like shifts, XORs and multiplication or addition which wrap. This is difficult to do cleanly in plain Python, but Z3 can help us out with the `BitVec` and `BitVecVal` constructors to create variables that behave like n-bit numbers, allowing easy bitwise operations and solving.

With signed and unsigned numbers and varying bits, this can be a bit tricky to get right. Most operators work as you would expect:

* `+`, `-`: Add and subtract as unsigned numbers, wrapping on overflow
* `&`, `|`, `^`: AND, OR and XOR operations on each bit of both numbers
* `~`: Invert all bits of one number
* `*`: Multiply, works like _adding_ multiple times

With `BitVec`'s, there are a few edge cases, however. Namely, some operators perform **signed** versions by default. This means the first bit of the number represents the sign of the decimal number, and is not always the desired behaviour. This is an especially large pitfall for the `>>` shift right operator which you might expect to shift right and fill bits on the left with 0's, but instead, it will be filled with the sign (first) bit!

Not only `>>` is a victim of this, but also other operators like `/` divide and `%` modulus. Even comparison operators like `<` and `>` do a signed comparison by default. Luckily, there are built-in replacements that do the _unsigned_ version instead. For `>>`, for example, there is `LShR()`. Here are some examples of performing specific bitwise operations to explain their differences:

<table><thead><tr><th width="221">Operation</th><th width="403">Description</th><th>Example</th></tr></thead><tbody><tr><td><code>x &#x3C;&#x3C; 1</code></td><td>Shift all bits to the <strong>left</strong>, discarding the leftmost and filling empty bits <strong>with 0's</strong></td><td><code>11110001</code><br><code>11100010</code></td></tr><tr><td><code>x >> 1</code></td><td>Shift all bits to the <strong>right</strong>, discarding the rightmost and filling empty bits <strong>with the sign bit</strong> (leftmost)</td><td><code>10001111</code><br><code>11000111</code></td></tr><tr><td><code>LShR(x, 1)</code></td><td>Shift all bits to the <strong>right</strong>, discarding the rightmost and filling empty bits <strong>with 0's</strong></td><td><p><code>10001111</code></p><p><code>01000111</code></p></td></tr><tr><td><code>RotateLeft(x, 1)</code></td><td>Shift all bits to the <strong>left</strong>, and <strong>wrap</strong> the leftmost bit back to the right</td><td><p><code>11100111</code></p><p><code>11001111</code></p></td></tr><tr><td><code>RotateRight(x, 1)</code></td><td>Shift all bits to the <strong>right</strong>, and <strong>wrap</strong> the rightmost bit back to the left</td><td><p><code>11100111</code></p><p><code>11110011</code></p></td></tr><tr><td><code>x / 2</code></td><td>Divide signed number, keeping the sign bit</td><td><code>10110000</code><br><code>11011000</code></td></tr><tr><td><code>UDiv(x, 2)</code></td><td>Divide unsigned number</td><td><code>10110000</code><br><code>01011000</code></td></tr></tbody></table>

All these operations can be used on `BitVec` (variable) and `BitVecVal` (constant) numbers. If you want to be able to follow how a constant changes and to make sure it follows n-bit operations, wrap it with `BitVecVal`. This tells Z3 about the number and all operations will behave as explained above.&#x20;

{% code title="Example" %}
```python
from z3 import *

s = Solver()

# 16-bit numbers
var = BitVec('var', 16)
const = BitVecVal(1000, 16)

const *= 2000
s.add(var == const)

if s.check() == sat:
    var = s.model()[var].as_long()
    print(var)  # 33920, not 2_000_000
```
{% endcode %}

## Solving cryptographic functions

Some bad implementations of cryptographic functions may have vulnerabilities that allow you to leak data. It might be hard to find these vulnerabilities yourself by looking at the code, so sometimes you can implement the algorithm in Z3 to check if it can be broken somehow.&#x20;

See the [#javascript-math.random-xorshift128](../pseudo-random-number-generators-prng.md#javascript-math.random-xorshift128 "mention") RNG for an example script where Z3 was used to find the random state after getting 5 random values as input, allowing you to predict future numbers.&#x20;

## Snippets

Some small but useful pieces of Z3 code that are common across scripts.&#x20;

<pre class="language-python" data-title="Get all flags"><code class="lang-python"># Define 20 characters as bytes
<strong>flag = [BitVec(f"flag_{i}", 8) for i in range(20)]
</strong>
# Restrict to printable ASCII
<strong>for character in flag:
</strong><strong>    s.add(character >= 0x20, character &#x3C; 0x7e)
</strong>
[...constraints...]

# Find all solutions, and print as string
<strong>while s.check() == sat:
</strong><strong>    m = s.model()
</strong><strong>    result = bytes([m[flag[i]].as_long() for i in range(len(flag))])
</strong><strong>    print(result)
</strong><strong>
</strong><strong>    s.add(Or([flag[i] != m[flag[i]] for i in range(len(flag))]))
</strong></code></pre>

For more practical examples, see this repository:

{% embed url="https://github.com/JorianWoltjer/z3-scripts" %}

## CrossHair: RegEx and more

{% embed url="https://github.com/pschanely/CrossHair" %}
Analyze python code flow using an SMT solver to verify statements in tests
{% endembed %}

This testing framework is intended to prove statements you make in a Python docstring. It will use Z3 to try and find **counterexamples** for edge cases. These are useful to create functions that behave as expected, but also useful as a security researcher to **find edge cases**.&#x20;

It is similar to the use of Z3 to solve statements, but much more flexible as it can directly integrate with the Python source code without having to be rewritten, which may change logic in the process. You can use it by defining `pre:` conditions it should expect, and `post:` conditions for it to disprove. You can play around with it on the [live demo](https://crosshair-web.org/), here is an example (`_` = return):

<pre class="language-python"><code class="lang-python">def make_bigger(n: int) -> int:
    '''
<strong>    post: _ > n
</strong>    '''
    return 2 * n + 10
</code></pre>

> error: false when calling `make_bigger(-10)` (which returns `-10`)

Here it finds the edge case where `n` is negative enough that the multiplication outweighs the addition, making the implied effect of always returning a larger value false. We could fix the code, or add a `pre: n >= 0` line before the `post:` to tell CrossHair that the input value should never be negative during analysis.&#x20;

The tool can be installed and run easily from the command line:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ python3 -m pip install crosshair-tool
</strong>...
<strong>$ crosshair check main.py
</strong>error: false when calling make_bigger(-10) (which returns -10)
</code></pre>

{% hint style="warning" %}
The `check` command has a fairly small default timeout per condition, but it can be **increased** by setting the `--per_condition_timeout` argument:

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ crosshair check test.py --per_condition_timeout 999999
</strong></code></pre>
{% endhint %}

Another useful feature for finding **differences** in functions is the [`diffbehavior`](https://crosshair.readthedocs.io/en/latest/diff\_behavior.html) tool. It takes two functions and compares the behavior of the two. Here, a refactor made an unrecognized response return `None` instead of `False`:

```python
def version1(s: str) -> bool:
    if s in ('y', 'yes'):
        return True
    return False

def version2(s: str) -> bool:
    if s in ('y', 'yes'):
        return True
    if s in ('n', 'no'):
        return False
```

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ crosshair diffbehavior test.version1 test.version2
</strong>Given: (s='z\x00\x00'),
  test.version1 : returns False
  test.version2 : returns None
</code></pre>

Also, see [`cover`](https://crosshair.readthedocs.io/en/latest/cover.html) for a tool that can automatically generate **test cases for all code paths**!

### Regular Expressions

One of the biggest improvements on Z3 is the fact that it understands regular expressions and that it can solve statements involving them to look for edge cases or **bypasses**.&#x20;

If we have a regular expression for which we want to find _any_ _valid string_, we can simply tell CrossHair there is none and it will try to find a counterexample:

```python
def simple_regex(s: str) -> bool:
    """
    post: not _  # We say: return value will always be False
    """
    return re.fullmatch(r"a(b|c)d{2,4}", s)
```

> error: false when calling `simple_regex('abdd')` (which returns `<...>`)

For a more complex example, it can find multiple conditions at once. Think of a first condition as passing through the checks and a second condition as being exploitable.&#x20;

```python
def intersect(s: str) -> bool:
    """
    post: not _
    """
    return re.fullmatch(r"a(b|c)d{2,4}", s) and \
           re.fullmatch(r"a(c|d)d{4,10}", s)  # Extra condition
```

> error: false when calling `intersect('acdddd')` (which returns `<...>`)

### Examples

Some examples of _security research_ use cases to find edge cases and bypasses.

First, an RFC-compliant regex that shows it's possible to inject `<` characters when surrounding the name with `"` **quotes**:

{% code title="Email address XSS" %}
```python
# Source: RFC-compliant - https://stackoverflow.com/a/201378/10508498
def is_email(s: str):
    """
    We tell it it's impossible for this regex to let through a "<"
    post: not (_ and "<" in s)
    """
    return bool(re.fullmatch(r"""(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])""", s))
```
{% endcode %}

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ crosshair check main.py --per_condition_timeout 999999
</strong>error: false when calling is_email('"&#x3C;"@0.0') (which returns True)
</code></pre>

Another shorter example where the **IPv6 address** allows any special characters:

{% code title="2nd email address XSS" %}
```python
# Source: short-hand version - https://stackabuse.com/validate-email-addresses-with-regular-expressions-in-javascript/
def test(s: str) -> bool:
    """
    post: not (_ and "<" in s)
    """

    return bool(re.fullmatch(r"([!#-'*+/-9=?A-Z^-~-]+(\.[!#-'*+/-9=?A-Z^-~-]+)*|\"(\[\]!#-[^-~ \t]|(\\[\t -~]))+\")@([!#-'*+/-9=?A-Z^-~-]+(\.[!#-'*+/-9=?A-Z^-~-]+)*|\[[\t -Z^-~]*])", s))
```
{% endcode %}

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ crosshair check main.py --per_condition_timeout 999999
</strong>error: false when calling is_email('?@[&#x3C;]') (which returns True)
</code></pre>

When using **multi-line** regexes, it finds it is possible to bypass a `$` restriction with a newline:

```python
def multiline(s: str) -> bool:
    """
    pre: s
    post: not (_ and "<" in s)
    """
    return bool(re.match("^a(b|c)d$", s, re.MULTILINE))
```

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ crosshair check main.py --per_condition_timeout 999999
</strong>error: false when calling multiline('abd\n&#x3C;') (which returns True)
</code></pre>

Taken from a real **CTF challenge** where the password was given as a regular expression that should be matched. Only one string would be able to match, and it would be the password. This tool can solve it without having to do any reverse engineering!

```python
def challenge(s: str) -> bool:
    """
    post: not _
    """
    return bool(re.match("(?:(?=[^\u6e0d-\u8ffb])[\x66]){0}?(?:(?=[^\u2f60-\u4bb9])[\x66]){0}?(?:(?=[^\ufcb8-\ufcc1])[\x75]){0}?(?:(?=[^\u7f87-\u99aa])[\x61]){0}?(?:(?=[^\u05c7-\ubcf7])[\x49]){1}?(?:(?=[^\ufa88-\ufc28])[\x65]){0}?(?:(?=[^\u9a98-\uc554])[\x76]){0}?(?:(?=[^\uf84d-\ufdd6])[\x70]){0}?(?:(?=[^\uf5e0-\uf711])[\x6e]){0}?(?:(?=[^\ufa45-\ufbeb])[\x61]){1}?(?:(?=[^\uf0ca-\uf28f])[\x73]){0}?(?:(?=[^\ue189-\uf7cb])[\x7a]){0}?(?:(?=[^\u2998-\u7c8b])[\x70]){0}?(?:(?=[^\u5fa8-\ufbb6])[\x6c]){0}?(?:(?=[^\ufef9-\uffa6])[\x4d]){1}?(?:(?=[^\ub312-\ueb5f])[\x6d]){0}?(?:(?=[^\u32bc-\ue435])[\x6d]){0}?(?:(?=[^\u45b2-\u736c])[\x6e]){0}?(?:(?=[^\u372d-\u96b1])[\x71]){0}?(?:(?=[^\ubeac-\uca7e])[\x74]){0}?(?:(?=[^\u9207-\ua598])[\x61]){1}?(?:(?=[^\ua32a-\uc32e])[\x63]){0}?(?:(?=[^\u10e2-\ufc58])[\x66]){0}?(?:(?=[^\ua3ff-\uc711])[\x7a]){0}?(?:(?=[^\u32b6-\u5fca])[\x77]){0}?(?:(?=[^\u3942-\ue7d8])[\x6d]){0}?(?:(?=[^\ud2dc-\uf3d7])[\x4d]){1}?(?:(?=[^\u7881-\ub2aa])[\x71]){0}?(?:(?=[^\u3173-\ub6b8])[\x74]){0}?(?:(?=[^\ua582-\ue3e7])[\x63]){0}?(?:(?=[^\u1f30-\u4a71])[\x7a]){0}?(?:(?=[^\ue799-\uf0ce])[\x65]){0}?(?:(?=[^\u6618-\u96f4])[\x64]){0}?(?:(?=[^\uc2dd-\uc3d3])[\x71]){0}?(?:(?=[^\ud05b-\ue4fc])[\x65]){0}?(?:(?=[^\udf4b-\ueec5])[\x61]){1}?(?:(?=[^\ue2aa-\uf6f6])[\x72]){0}?(?:(?=[^\u4da9-\uc4d6])[\x6e]){0}?(?:(?=[^\u7e7b-\ubb07])[\x69]){0}?(?:(?=[^\uc718-\uff10])[\x6d]){0}?(?:(?=[^\u6c84-\uac27])[\x6c]){1}?(?:(?=[^\ua4a0-\uf819])[\x66]){0}?(?:(?=[^\ue594-\uee75])[\x63]){0}?(?:(?=[^\uf8ca-\ufb79])[\x66]){0}?(?:(?=[^\u51a2-\u5817])[\x7a]){0}?(?:(?=[^\ucfd8-\uea6a])[\x6f]){0}?(?:(?=[^\u3118-\ud5d2])[\x6d]){0}?(?:(?=[^\uec3e-\ufdfd])[\x6f]){0}?(?:(?=[^\u0fb9-\u8106])[\x4c]){1}?(?:(?=[^\ud516-\udca6])[\x6f]){0}?(?:(?=[^\u24a3-\u8174])[\x6a]){0}?(?:(?=[^\u6110-\ueacf])[\x6b]){0}?(?:(?=[^\uf3be-\uf70f])[\x63]){0}?(?:(?=[^\u863c-\uedd6])[\x6b]){0}?(?:(?=[^\u1918-\ued3b])[\x70]){0}?(?:(?=[^\uccde-\udf61])[\x7a]){0}?(?:(?=[^\ub02e-\ue007])[\x61]){1}?(?:(?=[^\ue823-\uf2b1])[\x72]){0}?(?:(?=[^\u3493-\ub3d4])[\x74]){0}?(?:(?=[^\ue507-\ufc8a])[\x70]){0}?(?:(?=[^\ue249-\uf8b6])[\x72]){0}?(?:(?=[^\u9eb1-\ue0ed])[\x6e]){0}?(?:(?=[^\u8a39-\uefa3])[\x72]){1}?(?:(?=[^\u998b-\u9d4d])[\x74]){0}?(?:(?=[^\uf87c-\ufcd2])[\x72]){0}?(?:(?=[^\u4054-\u5fc4])[\x67]){0}?(?:(?=[^\ufbc4-\ufe79])[\x62]){0}?(?:(?=[^\uf57f-\uf6a1])[\x6c]){0}?(?:(?=[^\u5030-\u64bc])[\x6c]){0}?(?:(?=[^\u2371-\u4ee7])[\x44]){1}?(?:(?=[^\ud132-\ue943])[\x71]){0}?(?:(?=[^\ubef9-\uea29])[\x79]){0}?(?:(?=[^\ub7fa-\ubfa1])[\x69]){0}?(?:(?=[^\u71ce-\u8b83])[\x70]){0}?(?:(?=[^\u691a-\u7279])[\x6a]){0}?(?:(?=[^\u9d53-\ub24b])[\x21]){1}?(?:(?=[^\ud30d-\uf213])[\x72]){0}?(?:(?=[^\u40c2-\udd0b])[\x78]){0}?(?:(?=[^\u94a0-\ud814])[\x6a]){0}?(?:(?=[^\u3fe0-\u91c7])[\x66]){0}?(?:(?=[^\u61db-\ud519])[\x62]){0}?", s))
```

<pre class="language-shell-session"><code class="lang-shell-session"><strong>$ crosshair check main.py --per_condition_timeout 999999
</strong>error: false when calling challenge('IaMaMalLarD!') (which returns True)
</code></pre>
